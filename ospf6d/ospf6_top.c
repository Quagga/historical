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

/*
 * Copyright (C) 2005 6WIND  
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
#include "ospf6_zebra.h"

#include "ospf6_top.h"
#include "ospf6_area.h"
#include "ospf6_interface.h"
#include "ospf6_neighbor.h"

#include "ospf6_flood.h"
#include "ospf6_asbr.h"
#include "ospf6_abr.h"
#include "ospf6_intra.h"
#include "ospf6d.h"

/* global ospf6d variable */
struct ospf6 *ospf6;

extern struct in_addr router_id_zebra;

void
ospf6_router_id_update (struct ospf6 *ospf6)
{
  u_int32_t router_id;
  char buf_debug1[BUFSIZ], buf_debug2[BUFSIZ];

  if (IS_OSPF6_DEBUG_ZEBRA (RECV))
    zlog_debug ("Router-ID[OLD:%s]: Update", inet_ntop (AF_INET, &ospf6->router_id, buf_debug1, BUFSIZ));

  if (ospf6->router_id_static != 0)
    router_id = ospf6->router_id_static;
  else
    router_id = router_id_zebra.s_addr;

  ospf6->router_id = router_id;

  if (IS_OSPF6_DEBUG_ZEBRA (RECV))
    zlog_debug ("Router-ID[NEW:%s]: Update", inet_ntop (AF_INET, &ospf6->router_id, buf_debug2, BUFSIZ));
}

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
  ospf6_zebra_route_update_add (route);
}

void
ospf6_top_route_hook_remove (struct ospf6_route *route)
{
  ospf6_abr_originate_summary (route);
  ospf6_zebra_route_update_remove (route);
}

void
ospf6_top_brouter_hook_add (struct ospf6_route *route)
{
  struct ospf6_area *oa;
  struct listnode *node;

  ospf6_abr_examin_brouter (ADV_ROUTER_IN_PREFIX (&route->prefix));
  ospf6_asbr_lsentry_add (route);
  ospf6_abr_originate_summary (route);
  for (ALL_LIST_ELEMENTS_RO (ospf6->area_list, node, oa))
    ospf6_abr_nssa_translator_state_update (oa);
}

void
ospf6_top_brouter_hook_remove (struct ospf6_route *route)
{
  struct ospf6_area *oa;
  struct listnode *node;

  ospf6_abr_examin_brouter (ADV_ROUTER_IN_PREFIX (&route->prefix));
  ospf6_asbr_lsentry_remove (route);
  ospf6_abr_originate_summary (route);
  for (ALL_LIST_ELEMENTS_RO (ospf6->area_list, node, oa))
    ospf6_abr_nssa_translator_state_update (oa);
}

struct ospf6 *
ospf6_create ()
{
  struct ospf6 *o;

  o = XMALLOC (MTYPE_OSPF6_TOP, sizeof (struct ospf6));
  memset (o, 0, sizeof (struct ospf6));

  /* initialize */
  gettimeofday (&o->starttime, (struct timezone *) NULL);
  o->area_list = list_new ();
  o->interfaces = list_new ();
  o->area_list->cmp = ospf6_area_cmp;
  o->lsdb = ospf6_lsdb_create (o);
  o->lsdb_self = ospf6_lsdb_create (o);
  o->lsdb->hook_add = ospf6_top_lsdb_hook_add;
  o->lsdb->hook_remove = ospf6_top_lsdb_hook_remove;

  o->route_table = ospf6_route_table_create ();
  o->route_table->hook_add = ospf6_top_route_hook_add;
  o->route_table->hook_remove = ospf6_top_route_hook_remove;

  o->brouter_table = ospf6_route_table_create ();
  o->brouter_table->hook_add = ospf6_top_brouter_hook_add;
  o->brouter_table->hook_remove = ospf6_top_brouter_hook_remove;

  o->external_table = ospf6_route_table_create ();
  o->external_id_table = route_table_init ();

  o->stale_table = ospf6_route_table_create ();

  o->ref_bandwidth = OSPF6_DEFAULT_REF_BANDWIDTH;

  o->maximum_prefix = 0;
  o->max_prefix_threshold = OSPF6_MAXIMUM_PREFIX_THRESHOLD_DEFAULT;
  o->max_prefix_warning_only = 0;
 
  return o;
}

void
ospf6_delete (struct ospf6 *o)
{
  struct listnode *node, *nnode;
  struct ospf6_area *oa;
  struct ospf6_ifgroup *ifgroup;

  if (!o)
    return;

  for (ALL_LIST_ELEMENTS (o->interfaces, node, nnode, ifgroup))
    {
      list_delete_node(o->interfaces, node);
      ospf6_ifgroup_free(o, ifgroup);
    }

  for (ALL_LIST_ELEMENTS (o->area_list, node, nnode, oa))
    ospf6_area_delete (oa);

  list_delete(o->area_list);
  list_delete(o->interfaces);

  ospf6_lsdb_delete (o->lsdb);
  ospf6_lsdb_delete (o->lsdb_self);

  ospf6_route_table_delete (o->route_table);
  ospf6_route_table_delete (o->brouter_table);

  ospf6_route_table_delete (o->external_table);
  route_table_finish (o->external_id_table);

  ospf6_route_table_delete (o->stale_table);

  THREAD_OFF(o->dio.dio_timer);
  THREAD_OFF(o->maxage_remover);

  XFREE (MTYPE_OSPF6_TOP, o);
}

void
ospf6_enable (struct ospf6 *o)
{
  struct listnode *node, *nnode;
  struct ospf6_area *oa;

  if (CHECK_FLAG (o->flag, OSPF6_DISABLED))
    {
      UNSET_FLAG (o->flag, OSPF6_DISABLED);
      for (ALL_LIST_ELEMENTS (o->area_list, node, nnode, oa))
        ospf6_area_enable (oa);
    }
}

void
ospf6_disable (struct ospf6 *o)
{
  struct listnode *node, *nnode;
  struct ospf6_area *oa;

  if (! CHECK_FLAG (o->flag, OSPF6_DISABLED))
    {
      SET_FLAG (o->flag, OSPF6_DISABLED);
      
      for (ALL_LIST_ELEMENTS (o->area_list, node, nnode, oa))
        ospf6_area_disable (oa);

      ospf6_lsdb_remove_all (o->lsdb);
      ospf6_route_remove_all (o->route_table);
      ospf6_route_remove_all (o->brouter_table);
      ospf6_route_remove_all (o->stale_table);
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

  for (ALL_LIST_ELEMENTS_RO (o->area_list, i, oa))
    {
      for (ALL_LIST_ELEMENTS_RO (oa->if_list, j, oi))
        {
          for (ALL_LIST_ELEMENTS_RO (oi->neighbor_list, k, on))
            {
              if (on->state != OSPF6_NEIGHBOR_EXCHANGE &&
                  on->state != OSPF6_NEIGHBOR_LOADING)
                continue;

              return 0;
            }
        }
    }

  for (ALL_LIST_ELEMENTS_RO (o->area_list, i, oa))
    {
      for (ALL_LIST_ELEMENTS_RO (oa->if_list, j, oi))
        OSPF6_LSDB_MAXAGE_REMOVER (oi->lsdb);
      
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

  ospf6_router_id_update (ospf6);

  return CMD_SUCCESS;
}

DEFUN (ospf6_interface_passive,
       ospf6_interface_passive_cmd,
       "interface passive",
       "Enable routing on an IPv6 interface\n"
       "Make all the interface as passive\n")
{
  struct ospf6_interface *oi;
  struct ospf6_area *oa;
  struct listnode *node_a;
  struct listnode *node_i;
  struct listnode *node, *nnode;
  struct ospf6_neighbor *on;

  for (ALL_LIST_ELEMENTS_RO (ospf6->area_list, node_a, oa))
    {
      for (ALL_LIST_ELEMENTS_RO (oa->if_list, node_i, oi))
        {
          SET_FLAG (oi->flag, OSPF6_INTERFACE_PASSIVE);
          THREAD_OFF (oi->thread_send_hello);

          for (ALL_LIST_ELEMENTS (oi->neighbor_list, node, nnode, on))
            {
              THREAD_OFF (on->inactivity_timer);
              thread_execute (master, inactivity_timer, on, 0);
            }
        }
   }

  return CMD_SUCCESS;
}

DEFUN (no_ospf6_interface_passive,
       no_ospf6_interface_passive_cmd,
       "no interface passive",
       "Enable routing on an IPv6 interface\n"
       "Make all the interface as active\n")
{
  struct ospf6_interface *oi;
  struct ospf6_area *oa;
  struct listnode *node_a;
  struct listnode *node_i;

  for (ALL_LIST_ELEMENTS_RO (ospf6->area_list, node_a, oa))
    {
      for (ALL_LIST_ELEMENTS_RO (oa->if_list, node_i, oi))
        {
          UNSET_FLAG (oi->flag, OSPF6_INTERFACE_PASSIVE);
          THREAD_OFF (oi->thread_send_hello);
          oi->thread_send_hello =
            thread_add_event (master, ospf6_hello_send, oi, 0);
        }
   }

  return CMD_SUCCESS;
}

/* stop ospf6 */
DEFUN (no_router_ospf6,
       no_router_ospf6_cmd,
       "no router ospf6",
       NO_STR
       OSPF6_ROUTER_STR
       OSPF6_STR)
{
  if (ospf6 == NULL || CHECK_FLAG (ospf6->flag, OSPF6_DISABLED))
    vty_out (vty, " OSPFv3 is not running%s", VNL);
  else
  {
    ospf6_disable (ospf6);
    ospf6_delete(ospf6); /* XFREE ospf6, table, like ospf6_create() */
    ospf6 = NULL;
  }

  /* return to config node . */
  vty->node = CONFIG_NODE;
  vty->index = NULL;

  return CMD_SUCCESS;
}

/* change Router_ID commands. */
DEFUN (ospf6_router_id,
       ospf6_router_id_cmd,
       "ospf6 router-id A.B.C.D",
       OSPF6_STR
       "Configure OSPF6 Router-ID\n"
       V4NOTATION_STR)
{
  int ret;
  u_int32_t router_id;
  struct ospf6 *o;

  o = (struct ospf6 *) vty->index;

  ret = inet_pton (AF_INET, argv[0], &router_id);
  if (ret == 0)
    {
      vty_out (vty, "malformed OSPF6 Router-ID: %s%s", argv[0], VNL);
      return CMD_SUCCESS;
    }

  o->router_id_static = router_id;
  o->router_id  = router_id;

  return CMD_SUCCESS;
}

DEFUN (no_ospf6_router_id,
       no_ospf6_router_id_cmd,
       "no ospf6 router-id",
       NO_STR
       "OSPF6 specific commands\n"
       "Configure OSPF6 Router-ID\n")
{
  struct ospf6 *o = (struct ospf6 *) vty->index;
  u_int32_t router_id;

 if (argc == 1)
   {
     if (inet_pton (AF_INET, argv[0], &router_id) == 0)
       {
         vty_out (vty, "malformed OSPF6 Router-ID: %s%s", argv[0], VNL);
	 return CMD_WARNING;
       }
     if (o->router_id_static != router_id)
       {
         vty_out (vty, "%s is not the configured router-id%s", argv[0], VNL);
         return CMD_WARNING;
       }
   }

  o->router_id_static = 0; /* XXX */
  ospf6_router_id_update (o);

  if (IS_OSPF6_DEBUG_ZEBRA (RECV))
    zlog_info ("CONFIG: remove router-id");

  return CMD_SUCCESS;
}

ALIAS (no_ospf6_router_id,
       no_ospf6_router_id_val_cmd,
       "no ospf6 router-id A.B.C.D",
       NO_STR
       "OSPF6 specific commands\n"
       "Configure OSPF6 Router-ID\n"
       V4NOTATION_STR)

int
ospf6_str2area_id (const char *name,  u_int32_t *area_id, int *ai_format)
{
  char *endptr = NULL;

  /*match "A.B.C.D"*/
  if (strchr (name, '.') != NULL)
     {
        if (inet_pton (AF_INET, name, area_id) <= 0)
                return -1;
      
        if (ai_format)
                *ai_format = OSPF6_AREA_ID_FORMAT_ADDRESS;
     }
  /*match "<0-4294967295>"*/
  else
     {
        *area_id = htonl (strtoul (name, &endptr, 10));

        if (ai_format)
                *ai_format = OSPF6_AREA_ID_FORMAT_DECIMAL;

        if (*endptr != '\0' || (*area_id == ULONG_MAX && errno == ERANGE))
                return -1;
     }
   return 0;
}

DEFUN (ospf6_auto_cost_reference_bandwidth,
       ospf6_auto_cost_reference_bandwidth_cmd,
       "auto-cost reference-bandwidth <1-4294967>",
       "Calculate OSPF6 interface cost according to bandwidth\n"
       "Use reference bandwidth method to assign OSPF6 interface cost\n"
       "The reference bandwidth in terms of Mbits per second\n")
{
  struct ospf6 *o = vty->index;
  u_int32_t refbw;

  refbw = strtol (argv[0], NULL, 10);
  if (refbw < 1 || refbw > 4294967)
    {
      vty_out (vty, "reference-bandwidth value is invalid%s", VNL);
      return CMD_WARNING;
    }

  if ((refbw * 1000) == o->ref_bandwidth)
    return CMD_SUCCESS;

  /* If reference bandwidth is changed. */
  o->ref_bandwidth = refbw * 1000;
  vty_out (vty, " OSPF6: Reference bandwidth is changed.%s", VNL);
  vty_out (vty, "        Please ensure reference bandwidth is consistent across all routers%s", VNL);

  ospf6_interface_recalculate_cost ();

  return CMD_SUCCESS;
}

DEFUN (no_ospf6_auto_cost_reference_bandwidth,
       no_ospf6_auto_cost_reference_bandwidth_val_cmd,
       "no auto-cost reference-bandwidth <1-4294967>",
       NO_STR
       "Calculate OSPF6 interface cost according to bandwidth\n"
       "Use reference bandwidth method to assign OSPF6 interface cost\n"
       "Configured reference bandwidth in terms of Mbits per second\n")
{
  struct ospf6 *o = vty->index;

  if (argc && (o->ref_bandwidth != strtol (argv[0], NULL, 10) * 1000))
    {
      vty_out (vty, "%s is not the configured reference-bandwidth value%s", argv[0], VNL);
      return CMD_WARNING;
    }

  if (o->ref_bandwidth == OSPF6_DEFAULT_REF_BANDWIDTH)
    return CMD_SUCCESS;

  o->ref_bandwidth = OSPF6_DEFAULT_REF_BANDWIDTH;
  vty_out (vty, " OSPF6: Reference bandwidth is changed.%s", VNL);
  vty_out (vty, "        Please ensure reference bandwidth is consistent across all routers%s", VNL);

  ospf6_interface_recalculate_cost ();

  return CMD_SUCCESS;
}

ALIAS (no_ospf6_auto_cost_reference_bandwidth,
       no_ospf6_auto_cost_reference_bandwidth_cmd,
       "no auto-cost reference-bandwidth",
       NO_STR
       "Calculate OSPF6 interface cost according to bandwidth\n"
       "Use reference bandwidth method to assign OSPF6 interface cost\n"
      )

#define AREA2STR(a) inet_ntoa(*(struct in_addr*)&(a))

/*
 * WARNING:
 *    if several interface statements overlap (e.g. ctu0 and ctu*)
 *    then the area ID must be the same, otherwise the result
 *    is unpredictable
 */
DEFUN (ospf6_interface_area,
       ospf6_interface_area_cmd,
       "interface IFNAME area (A.B.C.D|<0-4294967295>)",
       "Enable routing on an IPv6 interface\n"
       IFNAME_STR
       "Specify the OSPF6 area ID\n"
       OSPF6_AREA_ID_STR)
{
  struct ospf6 *o;
  struct ospf6_area *oa;
  u_int32_t area_id;
  int ai_format;
  struct listnode *node;
  struct ospf6_ifgroup *ifgroup;

  o = (struct ospf6 *) vty->index;

  /* add interface name pattern into ospf6 interface list */
  for (ALL_LIST_ELEMENTS_RO(o->interfaces, node, ifgroup))
    {
      /* OSPF already enabled on this interface name pattern */
      if (strcmp(ifgroup->ifname, argv[0]) == 0)
        {
          vty_out (vty, "%s already attached to Area %s%s",
                 ifgroup->ifname, AREA2STR(ifgroup->area_id), VNL);

          return CMD_WARNING;
        }
    }

  /* parse Area-ID */
  if (ospf6_str2area_id (argv[1], &area_id, &ai_format) < 0)
    {
      vty_out (vty, "Invalid Area-ID: %s%s", argv[1], VNL);
      return CMD_WARNING;
    }

  ifgroup = ospf6_ifgroup_new(argv[0], area_id, ai_format);
  listnode_add(o->interfaces, ifgroup);

  /* find/create ospf6 area */
  oa = ospf6_area_lookup (area_id, o);
  if (oa == NULL)
    oa = ospf6_area_create (area_id, ai_format, o);

  /* Now enable ospf6 on all interfaces matching this ifname pattern */
  ospf6_interface_run(o, argv[0], oa);

  return CMD_SUCCESS;
}

DEFUN (no_ospf6_interface_area,
       no_ospf6_interface_area_cmd,
       "no interface IFNAME area (A.B.C.D|<0-4294967295>)",
       NO_STR
       "Disable routing on an IPv6 interface\n"
       IFNAME_STR
       "Specify the OSPF6 area ID\n"
       OSPF6_AREA_ID_STR)
{
  struct ospf6 *o;
  u_int32_t area_id;
  int ai_format;
  struct listnode * node;
  struct ospf6_ifgroup *ifgroup;

  o = (struct ospf6 *) vty->index;

  for (ALL_LIST_ELEMENTS_RO(o->interfaces, node, ifgroup))
    {
      if (strcmp(ifgroup->ifname, argv[0]) == 0)
        break;
    }

  if (node == NULL)
    {
      vty_out (vty, "No such interface %s%s", argv[0], VNL);
      return CMD_WARNING;
    }

  /* parse Area-ID */
  if (ospf6_str2area_id (argv[1], &area_id, &ai_format) < 0)
    {
      vty_out (vty, "Invalid Area-ID: %s%s", argv[1], VNL);
      return CMD_WARNING;
    }

  if (ifgroup->area_id != area_id)
    {
      vty_out (vty, "Wrong Area-ID: %s is attached to area %s%s",
               ifgroup->ifname, AREA2STR(ifgroup->area_id), VNL);
      return CMD_WARNING;
    }

  list_delete_node(o->interfaces, node);

  ospf6_ifgroup_free(o, ifgroup);

  ospf6_if_update (o);

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
  gettimeofday (&now, (struct timezone *)NULL);
  timersub (&now, &o->starttime, &running);
  timerstring (&running, duration, sizeof (duration));
  vty_out (vty, " Running %s%s", duration, VNL);

  /* Redistribute configuration */
  vty_out (vty, " Redistribute Configuration%s", VNL);
  if (o->maximum_prefix)
  {
    vty_out (vty, "     Maximum Prefixes: %u%s", o->maximum_prefix, VNL);
    vty_out (vty, "     Threshold: %d%%%s", o->max_prefix_threshold, VNL);
    if (o->max_prefix_warning_only)
      vty_out (vty, "     Warning-Only: Enable%s", VNL);
    else
      vty_out (vty, "     Warning-Only: Disable%s", VNL);
  }
  else
  vty_out (vty, "     Maximum-Prefix is not configured%s", VNL);

  /* LSAs */
  vty_out (vty, " Number of AS scoped LSAs is %u%s",
           o->lsdb->count, VNL);

  /* LSAs */
  vty_out (vty, " Number of AS scoped LSAs is %u%s",
           o->lsdb->count, VNL);

  /* Areas */
  vty_out (vty, " Number of areas in this router is %u%s",
           listcount (o->area_list), VNL);

  for (ALL_LIST_ELEMENTS_RO (o->area_list, n, oa))
    ospf6_area_show (vty, oa);
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
       )

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
       "Display Intra-Area routes\n"
       "Display Inter-Area routes\n"
       "Display Type-1 External routes\n"
       "Display Type-2 External routes\n"
       )

DEFUN (show_ipv6_ospf6_route_type_detail,
       show_ipv6_ospf6_route_type_detail_cmd,
       "show ipv6 ospf6 route (intra-area|inter-area|external-1|external-2) detail",
       SHOW_STR
       IP6_STR
       OSPF6_STR
       ROUTE_STR
       "Display Intra-Area routes\n"
       "Display Inter-Area routes\n"
       "Display Type-1 External routes\n"
       "Display Type-2 External routes\n"
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
  struct listnode *j;
  struct ospf6_ifgroup *ifgroup;

  /* OSPFv6 configuration. */
  if (ospf6 == NULL)
    return CMD_SUCCESS;
  if (CHECK_FLAG (ospf6->flag, OSPF6_DISABLED))
    return CMD_SUCCESS;

  inet_ntop (AF_INET, &ospf6->router_id_static, router_id, sizeof (router_id));
  vty_out (vty, "router ospf6%s", VNL);
  if (ospf6->router_id_static != 0)
    vty_out (vty, " ospf6 router-id %s%s", router_id, VNL);

  ospf6_redistribute_config_write (vty);
  ospf6_area_config_write (vty);
  ospf6_config_write_dio (vty);

  /* auto-cost reference-bandwidth configuration.  */
  if (ospf6->ref_bandwidth != OSPF6_DEFAULT_REF_BANDWIDTH)
    vty_out (vty, " auto-cost reference-bandwidth %d%s",
             ospf6->ref_bandwidth / 1000, VNL);

  for (ALL_LIST_ELEMENTS_RO (ospf6->interfaces, j, ifgroup))
    {
      if (ifgroup->format == OSPF6_AREA_ID_FORMAT_DECIMAL)
            vty_out (vty, " interface %s area %u%s",
                   ifgroup->ifname, (u_int32_t)ntohl(ifgroup->area_id), VNL);
      else
            vty_out (vty, " interface %s area %s%s",
                   ifgroup->ifname, AREA2STR(ifgroup->area_id), VNL);
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
  install_element (CONFIG_NODE, &no_router_ospf6_cmd);

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
  install_element (OSPF6_NODE, &no_ospf6_router_id_cmd);
  install_element (OSPF6_NODE, &no_ospf6_router_id_val_cmd);
  install_element (OSPF6_NODE, &ospf6_interface_area_cmd);
  install_element (OSPF6_NODE, &ospf6_interface_passive_cmd);
  install_element (OSPF6_NODE, &no_ospf6_interface_passive_cmd);
  install_element (OSPF6_NODE, &no_ospf6_interface_area_cmd);
  install_element (OSPF6_NODE, &ospf6_auto_cost_reference_bandwidth_cmd);
  install_element (OSPF6_NODE, &no_ospf6_auto_cost_reference_bandwidth_cmd);
  install_element (OSPF6_NODE, &no_ospf6_auto_cost_reference_bandwidth_val_cmd);
}


