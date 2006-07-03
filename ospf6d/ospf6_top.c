/*
 * Copyright (C) 2003 Yasuhiro Ohara
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNU Zebra; see the file COPYING.  If not, write to the 
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330, 
 * Boston, MA 02111-1307, USA.  
 */

#include <zebra.h>

#include "log.h"
#include "memory.h"
#include "vty.h"
#include "linklist.h"
#include "prefix.h"
#include "table.h"
#include "thread.h"
#include "command.h"

#include "ospf6_proto.h"
#include "ospf6_message.h"
#include "ospf6_lsa.h"
#include "ospf6_lsdb.h"
#include "ospf6_route.h"
#ifndef SIM
#include "ospf6_zebra.h"
#endif //SIM

#include "ospf6_top.h"
#include "ospf6_area.h"
#include "ospf6_interface.h"
#include "ospf6_neighbor.h"

#include "ospf6_flood.h"
#include "ospf6_asbr.h"
#include "ospf6_abr.h"
#include "ospf6_intra.h"
#include "ospf6d.h"
#ifdef SIM
#include "sim.h"
#include "ospf6_sim_printing.h"
#endif //SIM
#ifdef OSPF6_MANET_MPR_FLOOD
#include "ospf6_mpr.h"
#endif //OSPF6_MANET_MPR_FLOOD

/* global ospf6d variable */
#ifdef SIM //Global SIM
struct ospf6 *ospf6 = NULL;
#else
struct ospf6 *ospf6;
#endif //SIM

void
ospf6_top_lsdb_hook_add (struct ospf6_lsa *lsa)
{
  switch (ntohs (lsa->header->type))
    {
      case OSPF6_LSTYPE_AS_EXTERNAL:
        ospf6_asbr_lsa_add (lsa);
        break;

      default:
        break;
    }
}

void
ospf6_top_lsdb_hook_remove (struct ospf6_lsa *lsa)
{
  switch (ntohs (lsa->header->type))
    {
      case OSPF6_LSTYPE_AS_EXTERNAL:
        ospf6_asbr_lsa_remove (lsa);
        break;

      default:
        break;
    }
}

void
ospf6_top_route_hook_add (struct ospf6_route *route)
{
  ospf6_abr_originate_summary (route);
#ifndef SIM
  ospf6_zebra_route_update_add (route);
#endif //SIM
}

void
ospf6_top_route_hook_remove (struct ospf6_route *route)
{
  ospf6_abr_originate_summary (route);
#ifndef SIM
  ospf6_zebra_route_update_remove (route);
#endif //SIM
}

void
ospf6_top_brouter_hook_add (struct ospf6_route *route)
{
  ospf6_abr_examin_brouter (ADV_ROUTER_IN_PREFIX (&route->prefix));
  ospf6_asbr_lsentry_add (route);
  ospf6_abr_originate_summary (route);
}

void
ospf6_top_brouter_hook_remove (struct ospf6_route *route)
{
  ospf6_abr_examin_brouter (ADV_ROUTER_IN_PREFIX (&route->prefix));
  ospf6_asbr_lsentry_remove (route);
  ospf6_abr_originate_summary (route);
}

struct ospf6 *
ospf6_create ()
{
  struct ospf6 *o;

  o = (struct ospf6 *) XMALLOC (MTYPE_OSPF6_TOP, sizeof (struct ospf6));
  memset (o, 0, sizeof (struct ospf6));

  /* initialize */
#ifdef SIM
  gettimeofday_sim (&o->starttime, (struct timezone *) NULL);
#else
  gettimeofday (&o->starttime, (struct timezone *) NULL);
#endif //SIM
  o->area_list = list_new ();
  o->area_list->cmp = ospf6_area_cmp;
  o->lsdb = ospf6_lsdb_create (o);
  o->lsdb_self = ospf6_lsdb_create (o);
  o->lsdb->hook_add = ospf6_top_lsdb_hook_add;
  o->lsdb->hook_remove = ospf6_top_lsdb_hook_remove;

#ifdef OSPF6_CONFIG
 o->minLSInterval = MIN_LS_INTERVAL;
 o->minLSArrival = MIN_LS_ARRIVAL;
#endif //OSPF6_CONFIG

  o->route_table = ospf6_route_table_create ();
#ifndef SIM
  o->route_table->hook_add = ospf6_top_route_hook_add;
  o->route_table->hook_remove = ospf6_top_route_hook_remove;
#endif //SIM

  o->brouter_table = ospf6_route_table_create ();
  o->brouter_table->hook_add = ospf6_top_brouter_hook_add;
  o->brouter_table->hook_remove = ospf6_top_brouter_hook_remove;

  o->external_table = ospf6_route_table_create ();
  o->external_id_table = route_table_init ();

  return o;
}

void
ospf6_delete (struct ospf6 *o)
{
  struct listnode *i;
  struct ospf6_area *oa;

#ifdef SIM
  if (!o)
    return;
  struct listnode *j, *k;
  struct ospf6_interface *oi;
  struct ospf6_neighbor *on;
  double lifetime, delta_2way, delta_full;
  for (i = listhead (o->area_list); i; nextnode (i))
  {
    oa = (struct ospf6_area *) getdata (i);
    for (j = listhead (oa->if_list); j; nextnode (j))
    {
      oi = (struct ospf6_interface *) getdata (j);
#ifdef OSPF6_MANET_MPR_FLOOD
      if (oi->type == OSPF6_IFTYPE_MANETRELIABLE)
      {
        struct ospf6_relay_selector *relay_sel;
        k = listhead(oi->relay_sel_list);
        while(k)
        {
          relay_sel = (struct ospf6_relay_selector *) getdata(k);
          nextnode(k);
          ospf6_relay_selector_delete(oi, relay_sel);
          relay_sel = NULL;
        }
      }
#endif //OSPF6_MANET_MPR_FLOOD
#ifdef SIM_ETRACE_STAT
      delta_2way = elapsed_time(&oi->neigh_2way_change_time);
      delta_full = elapsed_time(&oi->neigh_full_change_time);
      for (k = listhead (oi->neighbor_list); k; nextnode (k))
      {
        on = (struct ospf6_neighbor *) getdata (k);
        if (on->state < OSPF6_NEIGHBOR_TWOWAY)
          continue;
        lifetime = elapsed_time(&on->creation_time);

        update_statistics(OSPF6_CHANGE_OF_NUM_NEIGHS, 1);
        update_statistics(OSPF6_DURATION_OF_NUM_NEIGHS, (double)delta_2way);
        update_statistics(OSPF6_NUM_NEIGH_TIMES_DURATION_OF_NUM_NEIGHS,
                          (double) (oi->num_2way_neigh * delta_2way));
        update_statistics(OSPF6_NEIGH_LIFETIME,lifetime);
        update_statistics(OSPF6_NEIGH_DEATHS,1);

        if (on->state == OSPF6_NEIGHBOR_FULL)
        {
          update_statistics(OSPF6_CHANGE_OF_NUM_ADJ,1);
          update_statistics(OSPF6_DURATION_OF_NUM_ADJ,(double)delta_full);
          update_statistics(OSPF6_NUM_ADJ_TIMES_DURATION_OF_NUM_ADJ,
                            (double) (oi->num_full_neigh-- * delta_full));
          delta_full = 0;
        }
        TraceEvent_sim(1,"num_nbr %d for %f msec delnbr %s for %f msec",
          oi->num_2way_neigh--, delta_2way, ip2str(on->router_id),lifetime);
        delta_2way = 0;
      }
#endif //SIM_ETRACE_STAT
    }
  }
#endif //SIM_ETRAC


#ifdef BUGFIX
 //deleting oa was causing the loop through list to point to NULL
 i = listhead(o->area_list);
 while(i)
 {
  oa = (struct ospf6_area *) getdata (i);
  nextnode(i);
  ospf6_area_delete (oa);
 }
#else
  for (i = listhead (o->area_list); i; nextnode (i))
    {
      oa = (struct ospf6_area *) getdata (i);
      ospf6_area_delete (oa);
    }
#endif //BUGFIX

  ospf6_lsdb_delete (o->lsdb);
  ospf6_lsdb_delete (o->lsdb_self);

  ospf6_route_table_delete (o->route_table);
  ospf6_route_table_delete (o->brouter_table);

  ospf6_route_table_delete (o->external_table);
  route_table_finish (o->external_id_table);

  XFREE (MTYPE_OSPF6_TOP, o);
}

void
ospf6_enable (struct ospf6 *o)
{
  struct listnode *i;
  struct ospf6_area *oa;

  if (CHECK_FLAG (o->flag, OSPF6_DISABLED))
    {
      UNSET_FLAG (o->flag, OSPF6_DISABLED);
      for (i = listhead (o->area_list); i; nextnode (i))
        {
          oa = (struct ospf6_area *) getdata (i);
          ospf6_area_enable (oa);
        }
    }
}

void
ospf6_disable (struct ospf6 *o)
{
  struct listnode *i;
  struct ospf6_area *oa;

  if (! CHECK_FLAG (o->flag, OSPF6_DISABLED))
    {
      SET_FLAG (o->flag, OSPF6_DISABLED);
      for (i = listhead (o->area_list); i; nextnode (i))
        {
          oa = (struct ospf6_area *) getdata (i);
          ospf6_area_disable (oa);
        }

      ospf6_lsdb_remove_all (o->lsdb);
      ospf6_route_remove_all (o->route_table);
      ospf6_route_remove_all (o->brouter_table);
    }
}

int
ospf6_maxage_remover (struct thread *thread)
{
  struct ospf6 *o = (struct ospf6 *) THREAD_ARG (thread);
  struct ospf6_area *oa;
  struct ospf6_interface *oi;
  struct ospf6_neighbor *on;
  struct listnode *i, *j, *k;

  o->maxage_remover = (struct thread *) NULL;

  for (i = listhead (o->area_list); i; nextnode (i))
    {
      oa = (struct ospf6_area *) getdata (i);
      for (j = listhead (oa->if_list); j; nextnode (j))
        {
          oi = (struct ospf6_interface *) getdata (j);
          for (k = listhead (oi->neighbor_list); k; nextnode (k))
            {
              on = (struct ospf6_neighbor *) getdata (k);
              if (on->state != OSPF6_NEIGHBOR_EXCHANGE &&
                  on->state != OSPF6_NEIGHBOR_LOADING)
                continue;

              return 0;
            }
        }
    }

  for (i = listhead (o->area_list); i; nextnode (i))
    {
      oa = (struct ospf6_area *) getdata (i);
      for (j = listhead (oa->if_list); j; nextnode (j))
        {
          oi = (struct ospf6_interface *) getdata (j);
          OSPF6_LSDB_MAXAGE_REMOVER (oi->lsdb);
        }
      OSPF6_LSDB_MAXAGE_REMOVER (oa->lsdb);
    }
  OSPF6_LSDB_MAXAGE_REMOVER (o->lsdb);

  return 0;
}

void
ospf6_maxage_remove (struct ospf6 *o)
{
  if (o && ! o->maxage_remover)
    o->maxage_remover = thread_add_event (master, ospf6_maxage_remover, o, 0);
}

#ifdef OSPF6_CONFIG
DEFUN (ospf6_router_minlsinterval,
       ospf6_router_minlsinterval_cmd,
       "router minls-interval <0-65535>",
       ROUTER_STR
       "minimum time to originate an LSA\n"
       SECONDS_STR)
{
  struct ospf6 *o;

  o = (struct ospf6 *) vty->index;
  o->minLSInterval = strtol (argv[0], NULL, 10);
  
  return CMD_SUCCESS;
}
DEFUN (ospf6_router_minlsarrival,
       ospf6_router_minlsarrival_cmd,
       "router minls-arrival <0-65535>",
       ROUTER_STR
    "minimum time to receive an LSA\n"
       SECONDS_STR)
{
  struct ospf6 *o;

  o = (struct ospf6 *) vty->index;

 o->minLSArrival = strtol (argv[0], NULL, 10);

  return CMD_SUCCESS;
}
#endif //OSPF6_CONFIG

#ifdef SIM_ETRACE_STAT
/* change Router_ID commands. */
DEFUN (ospf6_router_stat,
       ospf6_router_stat_cmd,
       "router statistics start-time <0-4294967296>",
       ROUTER_STR
    "statistics\n"
    "time to start collecting statistics\n"
       SECONDS_STR)
{
  struct ospf6 *o;

  o = (struct ospf6 *) vty->index;

 o->start_stat_time = strtol (argv[0], NULL, 10);

  return CMD_SUCCESS;
}
#endif //SIM_ETRACE_STAT

/* start ospf6 */
DEFUN (router_ospf6,
       router_ospf6_cmd,
       "router ospf6",
       ROUTER_STR
       OSPF6_STR)
{
  if (ospf6 == NULL)
    ospf6 = ospf6_create ();
  if (CHECK_FLAG (ospf6->flag, OSPF6_DISABLED))
    ospf6_enable (ospf6);

  /* set current ospf point. */
  vty->node = OSPF6_NODE;
  vty->index = ospf6;

  return CMD_SUCCESS;
}

/* stop ospf6 */
DEFUN (no_router_ospf6,
       no_router_ospf6_cmd,
       "no router ospf6",
       NO_STR
       OSPF6_ROUTER_STR)
{
  if (ospf6 == NULL || CHECK_FLAG (ospf6->flag, OSPF6_DISABLED))
    vty_out (vty, "OSPFv3 is not running%s", VNL);
  else
    ospf6_disable (ospf6);

  /* return to config node . */
  vty->node = CONFIG_NODE;
  vty->index = NULL;

  return CMD_SUCCESS;
}

/* change Router_ID commands. */
DEFUN (ospf6_router_id,
       ospf6_router_id_cmd,
       "router-id A.B.C.D",
       "Configure OSPF Router-ID\n"
       V4NOTATION_STR)
{
  int ret;
  u_int32_t router_id;
  struct ospf6 *o;

  o = (struct ospf6 *) vty->index;

  ret = inet_pton (AF_INET, argv[0], &router_id);
  if (ret == 0)
    {
      vty_out (vty, "malformed OSPF Router-ID: %s%s", argv[0], VNL);
      return CMD_SUCCESS;
    }

  o->router_id_static = router_id;
  if (o->router_id  == 0)
    o->router_id  = router_id;

  return CMD_SUCCESS;
}

DEFUN (ospf6_interface_area,
       ospf6_interface_area_cmd,
       "interface IFNAME area A.B.C.D",
       "Enable routing on an IPv6 interface\n"
       IFNAME_STR
       "Specify the OSPF6 area ID\n"
       "OSPF6 area ID in IPv4 address notation\n"
      )
{
  struct ospf6 *o;
  struct ospf6_area *oa;
  struct ospf6_interface *oi;
  struct interface *ifp;
  u_int32_t area_id;

  o = (struct ospf6 *) vty->index;

  /* find/create ospf6 interface */
  ifp = if_get_by_name (argv[0]);
  oi = (struct ospf6_interface *) ifp->info;
  if (oi == NULL)
    oi = ospf6_interface_create (ifp);
  if (oi->area)
    {
      vty_out (vty, "%s already attached to Area %s%s",
               oi->interface->name, oi->area->name, VNL);
      return CMD_SUCCESS;
    }

  /* parse Area-ID */
  if (inet_pton (AF_INET, argv[1], &area_id) != 1)
    {
      vty_out (vty, "Invalid Area-ID: %s%s", argv[1], VNL);
      return CMD_SUCCESS;
    }

  /* find/create ospf6 area */
  oa = ospf6_area_lookup (area_id, o);
  if (oa == NULL)
    oa = ospf6_area_create (area_id, o);

  /* attach interface to area */
  listnode_add (oa->if_list, oi); /* sort ?? */
  oi->area = oa;

  SET_FLAG (oa->flag, OSPF6_AREA_ENABLE);

  /* start up */
  thread_add_event (master, interface_up, oi, 0);

  /* If the router is ABR, originate summary routes */
  if (ospf6_is_router_abr (o))
    ospf6_abr_enable_area (oa);

  return CMD_SUCCESS;
}

DEFUN (no_ospf6_interface_area,
       no_ospf6_interface_area_cmd,
       "no interface IFNAME area A.B.C.D",
       NO_STR
       "Disable routing on an IPv6 interface\n"
       IFNAME_STR
       "Specify the OSPF6 area ID\n"
       "OSPF6 area ID in IPv4 address notation\n"
       )
{
  struct ospf6 *o;
  struct ospf6_interface *oi;
  struct ospf6_area *oa;
  struct interface *ifp;
  u_int32_t area_id;

  o = (struct ospf6 *) vty->index;

  ifp = if_lookup_by_name (argv[0]);
  if (ifp == NULL)
    {
      vty_out (vty, "No such interface %s%s", argv[0], VNL);
      return CMD_SUCCESS;
    }

  oi = (struct ospf6_interface *) ifp->info;
  if (oi == NULL)
    {
      vty_out (vty, "Interface %s not enabled%s", ifp->name, VNL);
      return CMD_SUCCESS;
    }

  /* parse Area-ID */
  if (inet_pton (AF_INET, argv[1], &area_id) != 1)
    {
      vty_out (vty, "Invalid Area-ID: %s%s", argv[1], VNL);
      return CMD_SUCCESS;
    }

  if (oi->area->area_id != area_id)
    {
      vty_out (vty, "Wrong Area-ID: %s is attached to area %s%s",
               oi->interface->name, oi->area->name, VNL);
      return CMD_SUCCESS;
    }

  thread_execute (master, interface_down, oi, 0);

  oa = oi->area;
  listnode_delete (oi->area->if_list, oi);
  oi->area = (struct ospf6_area *) NULL;

  /* Withdraw inter-area routes from this area, if necessary */
  if (oa->if_list->count == 0)
    {
      UNSET_FLAG (oa->flag, OSPF6_AREA_ENABLE);
      ospf6_abr_disable_area (oa);
    }

  return CMD_SUCCESS;
}

void
ospf6_show (struct vty *vty, struct ospf6 *o)
{
  struct listnode *n;
  struct ospf6_area *oa;
  char router_id[16], duration[32];
  struct timeval now, running;

  /* process id, router id */
  inet_ntop (AF_INET, &o->router_id, router_id, sizeof (router_id));
  vty_out (vty, " OSPFv3 Routing Process (0) with Router-ID %s%s",
           router_id, VNL);

  /* running time */
#ifdef SIM
  gettimeofday_sim (&now, (struct timezone *)NULL);
#else
  gettimeofday (&now, (struct timezone *)NULL);
#endif //SIM
  timersub (&now, &o->starttime, &running);
  timerstring (&running, duration, sizeof (duration));
  vty_out (vty, " Running %s%s", duration, VNL);

  /* Redistribute configuration */
  /* XXX */

  /* LSAs */
  vty_out (vty, " Number of AS scoped LSAs is %u%s",
           o->lsdb->count, VNL);

  /* Areas */
  vty_out (vty, " Number of areas in this router is %u%s",
           listcount (o->area_list), VNL);
  for (n = listhead (o->area_list); n; nextnode (n))
    {
      oa = (struct ospf6_area *) getdata (n);
      ospf6_area_show (vty, oa);
    }
}

/* show top level structures */
DEFUN (show_ipv6_ospf6,
       show_ipv6_ospf6_cmd,
       "show ipv6 ospf6",
       SHOW_STR
       IP6_STR
       OSPF6_STR)
{
  OSPF6_CMD_CHECK_RUNNING ();

  ospf6_show (vty, ospf6);
  return CMD_SUCCESS;
}

DEFUN (show_ipv6_ospf6_route,
       show_ipv6_ospf6_route_cmd,
       "show ipv6 ospf6 route",
       SHOW_STR
       IP6_STR
       OSPF6_STR
       ROUTE_STR
       )
{
  ospf6_route_table_show (vty, argc, argv, ospf6->route_table);
  return CMD_SUCCESS;
}

ALIAS (show_ipv6_ospf6_route,
       show_ipv6_ospf6_route_detail_cmd,
       "show ipv6 ospf6 route (X:X::X:X|X:X::X:X/M|detail|summary)",
       SHOW_STR
       IP6_STR
       OSPF6_STR
       ROUTE_STR
       "Specify IPv6 address\n"
       "Specify IPv6 prefix\n"
       "Detailed information\n"
       "Summary of route table\n"
       );

DEFUN (show_ipv6_ospf6_route_match,
       show_ipv6_ospf6_route_match_cmd,
       "show ipv6 ospf6 route X:X::X:X/M match",
       SHOW_STR
       IP6_STR
       OSPF6_STR
       ROUTE_STR
       "Specify IPv6 prefix\n"
       "Display routes which match the specified route\n"
       )
{
  const char *sargv[CMD_ARGC_MAX];
  int i, sargc;

  /* copy argv to sargv and then append "match" */
  for (i = 0; i < argc; i++)
    sargv[i] = argv[i];
  sargc = argc;
  sargv[sargc++] = "match";
  sargv[sargc] = NULL;

  ospf6_route_table_show (vty, sargc, sargv, ospf6->route_table);
  return CMD_SUCCESS;
}

DEFUN (show_ipv6_ospf6_route_match_detail,
       show_ipv6_ospf6_route_match_detail_cmd,
       "show ipv6 ospf6 route X:X::X:X/M match detail",
       SHOW_STR
       IP6_STR
       OSPF6_STR
       ROUTE_STR
       "Specify IPv6 prefix\n"
       "Display routes which match the specified route\n"
       "Detailed information\n"
       )
{
  const char *sargv[CMD_ARGC_MAX];
  int i, sargc;

  /* copy argv to sargv and then append "match" and "detail" */
  for (i = 0; i < argc; i++)
    sargv[i] = argv[i];
  sargc = argc;
  sargv[sargc++] = "match";
  sargv[sargc++] = "detail";
  sargv[sargc] = NULL;

  ospf6_route_table_show (vty, sargc, sargv, ospf6->route_table);
  return CMD_SUCCESS;
}

ALIAS (show_ipv6_ospf6_route,
       show_ipv6_ospf6_route_type_cmd,
       "show ipv6 ospf6 route (intra-area|inter-area|external-1|external-2)",
       SHOW_STR
       IP6_STR
       OSPF6_STR
       ROUTE_STR
       "Dispaly Intra-Area routes\n"
       "Dispaly Inter-Area routes\n"
       "Dispaly Type-1 External routes\n"
       "Dispaly Type-2 External routes\n"
       );

DEFUN (show_ipv6_ospf6_route_type_detail,
       show_ipv6_ospf6_route_type_detail_cmd,
       "show ipv6 ospf6 route (intra-area|inter-area|external-1|external-2) detail",
       SHOW_STR
       IP6_STR
       OSPF6_STR
       ROUTE_STR
       "Dispaly Intra-Area routes\n"
       "Dispaly Inter-Area routes\n"
       "Dispaly Type-1 External routes\n"
       "Dispaly Type-2 External routes\n"
       "Detailed information\n"
       )
{
  const char *sargv[CMD_ARGC_MAX];
  int i, sargc;

  /* copy argv to sargv and then append "detail" */
  for (i = 0; i < argc; i++)
    sargv[i] = argv[i];
  sargc = argc;
  sargv[sargc++] = "detail";
  sargv[sargc] = NULL;

  ospf6_route_table_show (vty, sargc, sargv, ospf6->route_table);
  return CMD_SUCCESS;
}

/* OSPF configuration write function. */
int
config_write_ospf6 (struct vty *vty)
{
  char router_id[16];
  struct listnode *j, *k;
  struct ospf6_area *oa;
  struct ospf6_interface *oi;

  /* OSPFv6 configuration. */
  if (ospf6 == NULL)
    return CMD_SUCCESS;
  if (CHECK_FLAG (ospf6->flag, OSPF6_DISABLED))
    return CMD_SUCCESS;

  inet_ntop (AF_INET, &ospf6->router_id_static, router_id, sizeof (router_id));
  vty_out (vty, "router ospf6%s", VNL);
  if (ospf6->router_id_static != 0)
    vty_out (vty, " router-id %s%s", router_id, VNL);

  ospf6_redistribute_config_write (vty);
  ospf6_area_config_write (vty);

  for (j = listhead (ospf6->area_list); j; nextnode (j))
    {
      oa = (struct ospf6_area *) getdata (j);
      for (k = listhead (oa->if_list); k; nextnode (k))
        {
          oi = (struct ospf6_interface *) getdata (k);
          vty_out (vty, " interface %s area %s%s",
                   oi->interface->name, oa->name, VNL);
        }
    }
  vty_out (vty, "!%s", VNL);
  return 0;
}

/* OSPF6 node structure. */
struct cmd_node ospf6_node =
{
  OSPF6_NODE,
  "%s(config-ospf6)# ",
  1 /* VTYSH */
};

/* Install ospf related commands. */
void
ospf6_top_init ()
{
  /* Install ospf6 top node. */
  install_node (&ospf6_node, config_write_ospf6);

  install_element (VIEW_NODE, &show_ipv6_ospf6_cmd);
  install_element (ENABLE_NODE, &show_ipv6_ospf6_cmd);
  install_element (CONFIG_NODE, &router_ospf6_cmd);

  install_element (VIEW_NODE, &show_ipv6_ospf6_route_cmd);
  install_element (VIEW_NODE, &show_ipv6_ospf6_route_detail_cmd);
  install_element (VIEW_NODE, &show_ipv6_ospf6_route_match_cmd);
  install_element (VIEW_NODE, &show_ipv6_ospf6_route_match_detail_cmd);
  install_element (VIEW_NODE, &show_ipv6_ospf6_route_type_cmd);
  install_element (VIEW_NODE, &show_ipv6_ospf6_route_type_detail_cmd);
  install_element (ENABLE_NODE, &show_ipv6_ospf6_route_cmd);
  install_element (ENABLE_NODE, &show_ipv6_ospf6_route_detail_cmd);
  install_element (ENABLE_NODE, &show_ipv6_ospf6_route_match_cmd);
  install_element (ENABLE_NODE, &show_ipv6_ospf6_route_match_detail_cmd);
  install_element (ENABLE_NODE, &show_ipv6_ospf6_route_type_cmd);
  install_element (ENABLE_NODE, &show_ipv6_ospf6_route_type_detail_cmd);

  install_default (OSPF6_NODE);
  install_element (OSPF6_NODE, &ospf6_router_id_cmd);
  install_element (OSPF6_NODE, &ospf6_interface_area_cmd);
  install_element (OSPF6_NODE, &no_ospf6_interface_area_cmd);
  install_element (OSPF6_NODE, &no_router_ospf6_cmd);
#ifdef SIM_ETRACE_STAT
  install_element (OSPF6_NODE, &ospf6_router_stat_cmd);
#endif //SIM_ETRACE_STAT
#ifdef OSPF6_CONFIG
  install_element (OSPF6_NODE, &ospf6_router_minlsinterval_cmd);
  install_element (OSPF6_NODE, &ospf6_router_minlsarrival_cmd);
#endif //OSPF6_CONFIG
}

#ifdef OSPF6_MANET
void ospf6_pushback_lsa_add(struct ospf6_lsa *lsa,
                              struct ospf6_neighbor *on)
{
  struct listnode *n;
  struct ospf6_pushback_neighbor *opbn = NULL;
 
  if (on->ospf6_if->type != OSPF6_IFTYPE_MANETRELIABLE)
    return;

  ospf6_refresh_lsa_pushback_list(lsa);

  //create the pushback list and schedule expiration
  if (lsa->pushBackTimer == NULL)
  {
#ifdef OSPF6_MANET_MPR_FLOOD
    if (on->ospf6_if->flooding == OSPF6_FLOOD_MPR_SDCDS)
    {
      lsa->pushBackTimer =
        thread_add_timer_msec (master, ospf6_pushback_expiration, lsa,
          on->ospf6_if->pushBackInterval + pushback_jitter(on->ospf6_if));
    }
#endif //OSPF6_MANET_MPR_FLOOD

#ifdef OSPF6_MANET_MDR_FLOOD
    if (on->ospf6_if->flooding == OSPF6_FLOOD_MDR_SICDS)
    { 
      lsa->pushBackTimer =
        thread_add_timer_msec (master, ospf6_pushback_expiration, lsa,
          on->ospf6_if->BackupWaitInterval + pushback_jitter(on->ospf6_if));
    }
#endif //OSPF6_MANET_MDR_FLOOD
    if (!on->ospf6_if->flooding == OSPF6_FLOOD_MDR_SICDS ||
        !on->ospf6_if->flooding == OSPF6_FLOOD_MPR_SDCDS)
    {
      printf("Interface flooding %d should not call ospf6_pushback_lsa_add()\n",
             on->ospf6_if->flooding);
      exit(0);
    }
    lsa->pushback_neighbor_list = list_new();
  }

  //Is this neighbor already on the push back list?
  for (n = listhead(lsa->pushback_neighbor_list); n; nextnode(n))
  {
    opbn = (struct ospf6_pushback_neighbor *) getdata(n);
    if (on->router_id == opbn->router_id &&
        on->ospf6_if->interface->ifindex == opbn->ifindex)
      return; //already in the list
  }

  //put the pushback neighbor on the pushback list
  opbn = (struct ospf6_pushback_neighbor *) 
          malloc(sizeof(struct ospf6_pushback_neighbor));
  opbn->router_id = on->router_id;
  opbn->ifindex = on->ospf6_if->interface->ifindex;
  listnode_add(lsa->pushback_neighbor_list, opbn);
}

void ospf6_pushback_lsa_neighbor_delete(struct ospf6_lsa *lsa,
                                       struct ospf6_neighbor *on)
{
  struct listnode *n;
  struct ospf6_pushback_neighbor *opbn;

  //Find pushback neighbor, if found remove
  for (n = listhead(lsa->pushback_neighbor_list); n; nextnode(n))
  {
    opbn = (struct ospf6_pushback_neighbor *) getdata(n);
    if (on->router_id == opbn->router_id &&
        on->ospf6_if->interface->ifindex == opbn->ifindex)
    {
      listnode_delete(lsa->pushback_neighbor_list, opbn);
      free(opbn);
      break;
    }
  }
  //clean out old neighbors and cancel pushback thread if pushback
  //no more pushback neighbors
  ospf6_refresh_lsa_pushback_list(lsa);
}

void ospf6_pushback_lsa_delete(struct ospf6_lsa *lsa)
{
 struct listnode *n;
 struct ospf6_pushback_neighbor *opbn;

 //cancel pushback thread
 THREAD_OFF(lsa->pushBackTimer);
 lsa->pushBackTimer = NULL;

 //clean up pushback neighbor list
 if (lsa->pushback_neighbor_list)
 {
  n = listhead(lsa->pushback_neighbor_list);
  while(n)
  {
   opbn = (struct ospf6_pushback_neighbor *) getdata(n);
   nextnode(n);
   free(opbn);
  }
  list_delete(lsa->pushback_neighbor_list);
  lsa->pushback_neighbor_list = NULL;
 }
}

// Section 3.4.8-2.2
 //Does "from" neighbor's neighbors cover all the pushback neighbors
boolean ospf6_pushback_check_coverage(struct ospf6_lsa *lsa,
                                    struct ospf6_neighbor *from)
{
  struct listnode *n;
  boolean cover = true;
  struct ospf6_pushback_neighbor *opbn;
  struct ospf6_lsa *r_lsa;
  char *start, *end, *current;
  struct ospf6_router_lsa *router_lsa;
  struct ospf6_router_lsdesc *router_lsd;

  ospf6_refresh_lsa_pushback_list(lsa);
#ifdef SIM
  ospf6_print_pushback_list_sim(lsa);
#endif //SIM

  if (!lsa->pushback_neighbor_list)
    return cover;  //from neighbor covers because no pushback neighbors exist

  //find router lsa for "from" neighbor
  r_lsa = ospf6_lsdb_lookup(htons(OSPF6_LSTYPE_ROUTER), htonl(0),
                          from->router_id, from->ospf6_if->area->lsdb);
  if (!r_lsa)
    return cover;
  router_lsa = (struct ospf6_router_lsa *)
               ((char *) r_lsa->header + sizeof (struct ospf6_lsa_header));
  start = (char *) router_lsa + sizeof (struct ospf6_router_lsa);
  end = (char *) r_lsa->header + ntohs (r_lsa->header->length);

  //loop over pushback neighbor list
  n = listhead(lsa->pushback_neighbor_list);
  while(n)
  {
    opbn = (struct ospf6_pushback_neighbor *) getdata(n);
    nextnode(n);
    cover = false;
    //loop over neighbors in router lsa
    for (current=start; current + sizeof (struct ospf6_router_lsdesc) <= end;
         current += sizeof (struct ospf6_router_lsdesc))
    {
      router_lsd = (struct ospf6_router_lsdesc *) current;
      if (ntohl(router_lsd->interface_id) != from->ifindex)
        continue;  //link must be on MANET subnet
      if (router_lsd->neighbor_router_id == opbn->router_id)
      {  //from's neighbor covers this pushback neighbor
        cover = true;
        break;
      }
    }
    if (!cover)
      return cover;
  }
  return cover;
}

int ospf6_pushback_expiration (struct thread *thread)
{
  struct ospf6_lsa *lsa = (struct ospf6_lsa *) THREAD_ARG (thread);
  struct listnode *n, *i;
  struct list *eligible_interfaces;
  struct ospf6_pushback_neighbor *opbn;
  struct ospf6_neighbor *on;
  struct ospf6_interface *oi;

  lsa->pushBackTimer = NULL;
  ospf6_refresh_lsa_pushback_list(lsa);
  if (!lsa->pushback_neighbor_list)
    return 0;

  eligible_interfaces = list_new ();
  n = listhead(lsa->pushback_neighbor_list);
  while(n)
  {
    opbn = (struct ospf6_pushback_neighbor *) getdata(n);
    nextnode(n);

    //neighbor should exist because pushback list was just refreshed
    oi = ospf6_interface_lookup_by_ifindex(opbn->ifindex);
    on = ospf6_neighbor_lookup (opbn->router_id, oi);
    assert(on);

    if (!listnode_lookup(eligible_interfaces, oi))
      listnode_add (eligible_interfaces, oi);

    ospf6_pushback_lsa_neighbor_delete(lsa,on);

#ifdef OSPF6_MANET_MDR_FLOOD
    if (oi->flooding == OSPF6_FLOOD_MDR_SICDS)
    {
      //if LSA is on ack list, this will count as an implict ack
      //remove LSA from ack list (MANET always on interface ack list)
      struct ospf6_lsa *ack_lsa;
      struct ospf6_lsa *rxmt_lsa;

      // Reset rxmt time if LSA is in retrans list.
      rxmt_lsa = ospf6_lsdb_lookup (lsa->header->type, lsa->header->id,
                                   lsa->header->adv_router, on->retrans_list);
      if (rxmt_lsa)
        set_time(&rxmt_lsa->rxmt_time);

      //if LSA is on ack list, this will count as an implict ack
      //remove LSA from ack list (MANET always on interface ack list)
      ack_lsa = ospf6_lsdb_lookup (lsa->header->type, lsa->header->id,
                                   lsa->header->adv_router, oi->lsack_list);

      if (ack_lsa)
        ospf6_lsdb_remove (ack_lsa, oi->lsack_list);

      continue;
    }
#endif //OSPF6_MANET_MDR_FLOOD

    if (IS_OSPF6_DEBUG_FLOODING)
      zlog_info ("  Add copy of %s to retrans-list of %s",
                 lsa->name, on->name);
    ospf6_increment_retrans_count (lsa);
    set_time(&lsa->rxmt_time);
    ospf6_lsdb_add (ospf6_lsa_copy (lsa), on->retrans_list);
#ifdef OSPF6_DELAYED_FLOOD
    on->thread_send_lsupdate =
    ospf6_send_lsupdate_delayed_msec(master, ospf6_lsupdate_send_neighbor,
                                     on, on->ospf6_if->rxmt_interval*1000, 
                                     on->thread_send_lsupdate);
#else
    if (on->thread_send_lsupdate == NULL)
      on->thread_send_lsupdate = 
        thread_add_timer (master, ospf6_lsupdate_send_neighbor,
                          on, on->ospf6_if->rxmt_interval);
#endif //OSPF6_DELAYED_FLOOD
  }

  for (i = listhead(eligible_interfaces); i; nextnode(i))
  {
    oi = (struct ospf6_interface *) getdata(i);
    if (IS_OSPF6_DEBUG_FLOODING)
      zlog_info ("  Add copy of %s to lsupdate_list of %s",
                 lsa->name, oi->interface->name);
#ifdef SIM_ETRACE_STAT
    char id[16], adv_router[16];
    inet_ntop (AF_INET, &lsa->header->id, id, sizeof (id));
    inet_ntop (AF_INET, &lsa->header->adv_router, adv_router,
               sizeof (adv_router));
    TraceEvent_sim(2,"Schedule Pushback Flood LSA %s -id %s -advrt %s -age %d -seq %lu -len %d",
                   ospf6_lstype_name(lsa->header->type), id, adv_router,
                   ntohs(age_mask(lsa->header)), ntohl(lsa->header->seqnum),
                   ntohs(lsa->header->length));
    update_statistics(OSPF6_LSA_FLOOD_NONRELAY,1);
#endif //SIM_ETRACE_STAT
  
  ospf6_lsdb_add (ospf6_lsa_copy (lsa), oi->lsupdate_list);
#ifdef OSPF6_DELAYED_FLOOD
  //XXX BOEING LSAs after this are gone from the perspective of pushback
  //with delay equal to 1msec no coalescing takes place
  //with a higher delay pushBackInterval is effectively increased
  oi->thread_send_lsupdate = 
    ospf6_send_lsupdate_delayed_msec(master, ospf6_lsupdate_send_interface,
                                     oi, 1, oi->thread_send_lsupdate);
#else
    if (oi->thread_send_lsupdate == NULL)
      oi->thread_send_lsupdate =
        thread_add_event (master, ospf6_lsupdate_send_interface, oi, 0);
#endif //OSPF6_DELAYED_FLOOD
  }
  list_delete (eligible_interfaces);
  return 0;
}

void
ospf6_refresh_lsa_pushback_list(struct ospf6_lsa *lsa)
{
  struct listnode *n;
  struct ospf6_neighbor *on;
  struct ospf6_interface *oi;
  struct ospf6_pushback_neighbor *opbn;

  //The neighbor state of pushback neighbors could have changed
  //remove those pushback neighbors in a state below EXCHANGE

  if (!lsa->pushback_neighbor_list)
    return;

  n = listhead(lsa->pushback_neighbor_list);
  while(n)
  {
    opbn = (struct ospf6_pushback_neighbor *) getdata(n);
    nextnode(n);
    oi = ospf6_interface_lookup_by_ifindex(opbn->ifindex);
    on = ospf6_neighbor_lookup(opbn->router_id, oi);

    //For SICDS, delete neighbors that are below TWOWAY.
    if (oi->flooding == OSPF6_FLOOD_MDR_SICDS)
    {
      if (!on || on->state < OSPF6_NEIGHBOR_TWOWAY)
      { //pushback neighbor fell below state TWOWAY
        listnode_delete(lsa->pushback_neighbor_list, opbn);
        free(opbn);
      }
    }
    else if (!on || on->state < OSPF6_NEIGHBOR_EXCHANGE)
    { //pushback neighbor fell below state EXCHANGE
      listnode_delete(lsa->pushback_neighbor_list, opbn);
      free(opbn);
    }
  }
  //there are no pushback neigbors left, cancel the pushback timer
  if (lsa->pushback_neighbor_list->count == 0)
  {
    ospf6_pushback_lsa_delete(lsa);
  }
}

//return pushback jitter in msec
long pushback_jitter(struct ospf6_interface *oi)
{
  long jitter = 0;
  int rand_;

#ifdef SIM
  rand_= rand_sim();
#else
  rand_ = rand();
#endif //SIM

#ifdef OSPF6_MANET_MPR_FLOOD
  if (oi->flooding == OSPF6_FLOOD_MPR_SDCDS)
    jitter = (long) ((double)rand_/RAND_MAX*oi->pushBackInterval);
#endif //OSPF6_MANET_MPR_FLOOD

#ifdef OSPF6_MANET_MDR_FLOOD
  if (oi->flooding == OSPF6_FLOOD_MDR_SICDS)
    jitter = (long) ((double)rand_/RAND_MAX*oi->BackupWaitInterval);
#endif //OSPF6_MANET_MDR_FLOOD

  if (!oi->flooding == OSPF6_FLOOD_MDR_SICDS ||
      !oi->flooding == OSPF6_FLOOD_MPR_SDCDS)
  {
    printf("Interface flooding %d should not call pushback_jitter()\n",
           oi->flooding);
    exit(0);
  }
  return jitter;
}
#endif //OSPF6_MANET

#ifdef SIM_ETRACE_STAT
void update_statistics(int element, double add)
{
  if (!collect_stats_sim(ospf6))
    return;
  ospf6->statistics[element] += add;
}
#endif //SIM_ETRACE_STAT
