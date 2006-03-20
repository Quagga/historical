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
#include "linklist.h"
#include "thread.h"
#include "vty.h"
#include "command.h"
#include "if.h"
#include "prefix.h"
#include "table.h"
#include "plist.h"

#include "ospf6_proto.h"
#include "ospf6_lsa.h"
#include "ospf6_lsdb.h"
#include "ospf6_route.h"
#include "ospf6_spf.h"
#include "ospf6_top.h"
#include "ospf6_area.h"
#include "ospf6_interface.h"
#include "ospf6_intra.h"
#include "ospf6_abr.h"
#include "ospf6d.h"
#include "ospf6_asbr.h"

int
ospf6_area_stub_cmd_handler (struct vty *vty, const char *argv[], 
                             int stub, int nosum);

int
ospf6_area_cmp (void *va, void *vb)
{
  struct ospf6_area *oa = (struct ospf6_area *) va;
  struct ospf6_area *ob = (struct ospf6_area *) vb;
  return (ntohl (oa->area_id) < ntohl (ob->area_id) ? -1 : 1);
}

/* schedule routing table recalculation */
void
ospf6_area_lsdb_hook_add (struct ospf6_lsa *lsa)
{
  switch (ntohs (lsa->header->type))
    {
    case OSPF6_LSTYPE_ROUTER:
    case OSPF6_LSTYPE_NETWORK:
      if (IS_OSPF6_DEBUG_EXAMIN_TYPE (lsa->header->type))
        {
          zlog_debug ("Examin %s", lsa->name);
          zlog_debug ("Schedule SPF Calculation for %s",
		      OSPF6_AREA (lsa->lsdb->data)->name);
        }
      ospf6_spf_schedule (OSPF6_AREA (lsa->lsdb->data));
      break;

    case OSPF6_LSTYPE_INTRA_PREFIX:
      ospf6_intra_prefix_lsa_add (lsa);
      ospf6_declare_vlinks_up (OSPF6_AREA (lsa->lsdb->data));
      break;

    case OSPF6_LSTYPE_INTER_PREFIX:
    case OSPF6_LSTYPE_INTER_ROUTER:
      ospf6_abr_examin_summary (lsa, (struct ospf6_area *) lsa->lsdb->data);
      break;

    case OSPF6_LSTYPE_TYPE_7:
      ospf6_abr_translate_type7_lsa_to_type5 (lsa);
      ospf6_asbr_lsa_add (lsa);
      break;

    default:
      break;
    }
}

void
ospf6_area_lsdb_hook_remove (struct ospf6_lsa *lsa)
{
  switch (ntohs (lsa->header->type))
    {
    case OSPF6_LSTYPE_ROUTER:
    case OSPF6_LSTYPE_NETWORK:
      if (IS_OSPF6_DEBUG_EXAMIN_TYPE (lsa->header->type))
        {
          zlog_debug ("LSA disappearing: %s", lsa->name);
          zlog_debug ("Schedule SPF Calculation for %s",
                     OSPF6_AREA (lsa->lsdb->data)->name);
        }
      ospf6_spf_schedule (OSPF6_AREA (lsa->lsdb->data));
      break;

    case OSPF6_LSTYPE_INTRA_PREFIX:
      ospf6_intra_prefix_lsa_remove (lsa);
      break;

    case OSPF6_LSTYPE_INTER_PREFIX:
    case OSPF6_LSTYPE_INTER_ROUTER:
      ospf6_abr_examin_summary (lsa, (struct ospf6_area *) lsa->lsdb->data);
      break;

    case OSPF6_LSTYPE_TYPE_7:
      ospf6_abr_flush_translated_type7_by_lsa (lsa);
      ospf6_asbr_lsa_remove (lsa);
      break;

    default:
      break;
    }
}

void
ospf6_area_route_hook_add (struct ospf6_route *route)
{
  struct ospf6_route *copy = ospf6_route_copy (route);
  ospf6_route_add (copy, ospf6->route_table);
}

void
ospf6_area_route_hook_remove (struct ospf6_route *route)
{
  struct ospf6_route *copy;

  copy = ospf6_route_lookup_identical (route, ospf6->route_table);
  if (copy)
    ospf6_route_remove (copy, ospf6->route_table);
}

/* Make new area structure */
struct ospf6_area *
ospf6_area_create (u_int32_t area_id, int ai_format, struct ospf6 *o)
{
  struct ospf6_area *oa;
  struct ospf6_route *route;

  oa = XCALLOC (MTYPE_OSPF6_AREA, sizeof (struct ospf6_area));

  inet_ntop (AF_INET, &area_id, oa->name, sizeof (oa->name));
  oa->area_id = area_id;
  oa->ai_format = ai_format;
  oa->if_list = list_new ();
  oa->default_cost = 1;

  oa->default_metric_type = EXTERNAL_METRIC_TYPE_1;
  oa->NSSATranslatorRole = NSSA_TRANSLATOR_ROLE_CANDIDATE;
  oa->NSSATranslatorStabilityInterval = 
    DEFAULT_NSSA_TRANSLATOR_STABILITY_INTERVAL;
  oa->NSSATranslatorState = NSSA_TRANSLATOR_STATE_DISABLED;
  oa->thread_nssa_trans_state_disable = NULL;
  oa->nssa_no_propagate = 0;
  oa->nssa_no_redistribution = 0;
  oa->translated_rt_table = ospf6_route_table_create ();

  oa->vlink_list = list_new ();
  oa->full_vls = 0;
  oa->stub_lsa_count = 0;
  oa->lsdb = ospf6_lsdb_create (oa);
  oa->lsdb->hook_add = ospf6_area_lsdb_hook_add;
  oa->lsdb->hook_remove = ospf6_area_lsdb_hook_remove;
  oa->lsdb_self = ospf6_lsdb_create (oa);

  oa->spf_table = ospf6_route_table_create ();
  oa->route_table = ospf6_route_table_create ();
  oa->route_table->hook_add = ospf6_area_route_hook_add;
  oa->route_table->hook_remove = ospf6_area_route_hook_remove;

  oa->range_table = ospf6_route_table_create ();
  oa->summary_prefix = ospf6_route_table_create ();
  oa->summary_router = ospf6_route_table_create ();

  /* set default options */
  OSPF6_OPT_SET (oa->options, OSPF6_OPT_V6);
  OSPF6_OPT_SET (oa->options, OSPF6_OPT_E);
  OSPF6_OPT_SET (oa->options, OSPF6_OPT_R);

  oa->ospf6 = o;
  listnode_add_sort (o->area_list, oa);

  /* import other areas' routes as inter-area routes */
  for (route = ospf6_route_head (o->route_table); route;
       route = ospf6_route_next (route))
    ospf6_abr_originate_summary_to_area (route, oa);

  return oa;
}

void
ospf6_area_delete (struct ospf6_area *oa)
{
  struct listnode *n, *nnode;
  struct ospf6_interface *oi;

  THREAD_OFF (oa->thread_nssa_trans_state_disable);

  /* ospf6 interface list */
  for (ALL_LIST_ELEMENTS (oa->if_list, n, nnode, oi))
    {
      /* synchronous call to interface down handler */
      thread_execute (master, interface_down, oi, 0);
      ospf6_interface_delete (oi);
    }

  ospf6_lsdb_delete (oa->lsdb);
  ospf6_lsdb_delete (oa->lsdb_self);

  ospf6_route_table_delete (oa->translated_rt_table);
  ospf6_route_table_delete (oa->range_table);
  ospf6_route_table_delete (oa->summary_prefix);
  ospf6_route_table_delete (oa->summary_router);

  list_delete (oa->if_list);
  list_delete (oa->vlink_list);

  ospf6_spf_table_finish (oa->spf_table);
  ospf6_route_table_delete (oa->spf_table);
  ospf6_route_table_delete (oa->route_table);

#if 0
  ospf6_spftree_delete (oa->spf_tree);
  ospf6_route_table_delete (oa->topology_table);
#endif /*0*/

  THREAD_OFF (oa->thread_spf_calculation);
  THREAD_OFF (oa->thread_route_calculation);

  /* cancel all thread events referencing oa */
  thread_cancel_event(master, oa);

  listnode_delete (oa->ospf6->area_list, oa);
  oa->ospf6 = NULL;

  /* free area */
  XFREE (MTYPE_OSPF6_AREA, oa);
}

struct ospf6_area *
ospf6_area_lookup (u_int32_t area_id, struct ospf6 *ospf6)
{
  struct ospf6_area *oa;
  struct listnode *n;

  for (ALL_LIST_ELEMENTS_RO (ospf6->area_list, n, oa))
    if (oa->area_id == area_id)
      return oa;

  return (struct ospf6_area *) NULL;
}

struct ospf6_area *
ospf6_area_get (u_int32_t area_id, int ai_format, struct ospf6 *o)
{
  struct ospf6_area *oa;
  oa = ospf6_area_lookup (area_id, o);
  if (oa == NULL)
    oa = ospf6_area_create (area_id, ai_format, o);
  return oa;
}

void
ospf6_area_enable (struct ospf6_area *oa)
{
  struct listnode *node, *nnode;
  struct ospf6_interface *oi;

  SET_FLAG (oa->flag, OSPF6_AREA_ENABLE);

  for (ALL_LIST_ELEMENTS (oa->if_list, node, nnode, oi))
    ospf6_interface_enable (oi);
}

void
ospf6_area_disable (struct ospf6_area *oa)
{
  struct listnode *node, *nnode;
  struct ospf6_interface *oi;

  UNSET_FLAG (oa->flag, OSPF6_AREA_ENABLE);

  for (ALL_LIST_ELEMENTS (oa->if_list, node, nnode, oi))
    ospf6_interface_disable (oi);
}


void
ospf6_area_show (struct vty *vty, struct ospf6_area *oa)
{
  struct listnode *i;
  struct ospf6_interface *oi;

  vty_out (vty, " Area %s%s", oa->name, VNL);
  vty_out (vty, "     Number of Area scoped LSAs is %u%s",
           oa->lsdb->count, VNL);
  if (PREFIX_NAME_IN(oa))
    vty_out (vty, "     Area %s filter in%s", oa->name, VNL);
  if (PREFIX_NAME_OUT(oa))
    vty_out (vty, "     Area %s filter out%s", oa->name, VNL);


  vty_out (vty, "     Interface attached to this area:");
  for (ALL_LIST_ELEMENTS_RO (oa->if_list, i, oi))
    vty_out (vty, " %s", oi->interface->name);
  
  if( IS_AREA_NSSA (oa))
    {
      vty_out (vty, "%s", VNL);
      if (oa->NSSATranslatorState == NSSA_TRANSLATOR_STATE_DISABLED)
        vty_out (vty, "     NSSA Translator state is DISBALED %s", VNL);
      else
        vty_out (vty, "     NSSA Translator state is ENABLED %s", VNL);

      if(oa->thread_nssa_trans_state_disable)
        vty_out (vty, "     NSSA Translator Stability Timer Running %s", VNL);
    }

  vty_out (vty, "%s", VNL);
}


#define OSPF6_CMD_AREA_GET(str, oa)                        \
{                                                          \
  u_int32_t area_id = 0;                                  \
  int ai_format;                                          \
  if (ospf6_str2area_id (str, &area_id, &ai_format) < 0)\
    {                                                      \
      vty_out (vty, "Malformed Area-ID: %s%s", str, VNL);  \
      return CMD_SUCCESS;                                  \
    }                                                      \
  oa = ospf6_area_get (area_id, ai_format, ospf6);                    \
}

DEFUN (area_range,
       area_range_cmd,
       "area (A.B.C.D|<0-4294967295>) range X:X::X:X/M",
       "OSPF area parameters\n"
       OSPF6_AREA_ID_STR
       "Configured address range\n"
       "Specify IPv6 prefix\n"
       )
{
  int ret;
  struct ospf6_area *oa;
  struct prefix prefix;
  struct ospf6_route *range;

  OSPF6_CMD_AREA_GET (argv[0], oa);
  argc--;
  argv++;

  ret = str2prefix (argv[0], &prefix);
  if (ret != 1 || prefix.family != AF_INET6)
    {
      vty_out (vty, "Malformed argument: %s%s", argv[0], VNL);
      return CMD_SUCCESS;
    }
  argc--;
  argv++;

  range = ospf6_route_lookup (&prefix, oa->range_table);
  if (range == NULL)
    {
      range = ospf6_route_create ();
      range->type = OSPF6_DEST_TYPE_RANGE;
      range->path.area_id = oa->area_id;
      range->prefix = prefix;
    }

  if (argc)
    {
      if (! strcmp (argv[0], "not-advertise"))
        SET_FLAG (range->flag, OSPF6_ROUTE_DO_NOT_ADVERTISE);
      else if (! strcmp (argv[0], "advertise"))
        UNSET_FLAG (range->flag, OSPF6_ROUTE_DO_NOT_ADVERTISE);
    }

  ospf6_route_add (range, oa->range_table);
  return CMD_SUCCESS;
}

ALIAS (area_range,
       area_range_advertise_cmd,
       "area (A.B.C.D|<0-4294967295>) range X:X::X:X/M (advertise|not-advertise)",
       "OSPF area parameters\n"
       OSPF6_AREA_ID_STR
       "Configured address range\n"
       "Specify IPv6 prefix\n"
       "Advertising options\n"
       "Non-advertising options\n"
       )

DEFUN (no_area_range,
       no_area_range_cmd,
       "no area (A.B.C.D|<0-4294967295>) range X:X::X:X/M",
       NO_STR
       "OSPF area parameters\n"
       OSPF6_AREA_ID_STR
       "Configured address range\n"
       "Specify IPv6 prefix\n"
       )
{
  int ret;
  struct ospf6_area *oa;
  struct prefix prefix;
  struct ospf6_route *range;

  OSPF6_CMD_AREA_GET (argv[0], oa);
  argc--;
  argv++;

  ret = str2prefix (argv[0], &prefix);
  if (ret != 1 || prefix.family != AF_INET6)
    {
      vty_out (vty, "Malformed argument: %s%s", argv[0], VNL);
      return CMD_SUCCESS;
    }

  range = ospf6_route_lookup (&prefix, oa->range_table);
  if (range == NULL)
    {
      vty_out (vty, "Range %s does not exists.%s", argv[0], VNL);
      return CMD_SUCCESS;
    }

  ospf6_route_remove (range, oa->range_table);
  return CMD_SUCCESS;
}

int
ospf6_area_vlink_count (struct ospf6_area *area)
{
  struct ospf6_vl_data *vl_data;
  struct listnode *node;
  int count = 0;

  for (ALL_LIST_ELEMENTS_RO (area->vlink_list, node, vl_data))
    if (IPV4_ADDR_SAME (&vl_data->vl_area_id, &area->area_id))
      count++;

  return count;
}

struct ospf6_vl_data *
get_valid_vl_data (struct ospf6_area *area)
{
  struct ospf6_vl_data *vl_data;
  struct listnode *node;

  for (ALL_LIST_ELEMENTS_RO (area->vlink_list, node, vl_data))
    return vl_data; 

  return NULL; 
}

void
ospf6_vl_set_timers (struct ospf6_vl_data *vl_data, 
                     struct ospf6_vl_config_data *vl_config)
{
  struct ospf6_interface *oi = vl_data->vl_oi;

  if (vl_config->hello_interval)
    oi->hello_interval = vl_config->hello_interval;

  if (vl_config->retransmit_interval)
    oi->rxmt_interval = vl_config->retransmit_interval;

  if (vl_config->transmit_delay)
    oi->transdelay = vl_config->transmit_delay;

  if (vl_config->dead_interval)
    oi->dead_interval = vl_config->dead_interval;

  return;
}

static int
ospf6_vl_set (struct ospf6 *ospf6, struct ospf6_area *area, 
              struct ospf6_vl_config_data *vl_config)
{
  struct ospf6_vl_data *vl_data = NULL;
  struct vty *vty = vl_config->vty;

  if (vl_config->area_id == BACKBONE_AREA_ID)
    {
      vty_out (vty, "Virtual-link cannot be configured over Backbone%s", VNL);
      return CMD_WARNING;
    }

  if (IS_AREA_STUB (area))
    {
      vty_out (vty, "Virtual Link cannnot be configured over stub area%s", VNL);
      return CMD_WARNING;
    }

  vl_data = ospf6_vl_lookup (area, vl_config->vl_peer);

  if (! vl_data)
    {
      vl_data = ospf6_vl_data_new (area, vl_config->vl_peer);
      /* Create a new virtual interface */ 
      if (! ospf6_vl_new (ospf6, vl_data, vl_config->ai_format))
        {
          vty_out (vty, "Virtual interface creation failed%s", VNL);
          XFREE (MTYPE_OSPF_VL_DATA, vl_data);
          return CMD_WARNING;
        }

      listnode_add (area->vlink_list, vl_data);
      ospf6_declare_vlinks_up (area);
    }

  /* Set timers */
  ospf6_vl_set_timers (vl_data, vl_config);

  return CMD_SUCCESS;
}

struct ospf6_area *
ospf6_area_process_vl_cmd (const char *name, const char *rid, 
                           struct ospf6_vl_config_data *vl_config, 
                           struct vty *vty)
{
  struct ospf6_area *area = NULL;

  memset (vl_config, 0, sizeof (struct ospf6_vl_config_data));
  vl_config->vty = vty;

  /* Validate the command Area ID */
  if (ospf6_str2area_id (name, &vl_config->area_id, &vl_config->ai_format) < 0)
    {
      vty_out (vty, "Invalid Area-ID: %s%s", name, VNL);
      return NULL;
    }

  /* Validate the command Router ID */
  if (inet_pton (AF_INET, rid, &vl_config->vl_peer) != 1)
    {
      vty_out (vty, "Invalid Router-ID: %s%s", rid, VNL);
      return NULL;
    }

  area = ospf6_area_lookup (vl_config->area_id, ospf6);
  if (! area)
    vty_out (vty, "Area %s does not exist%s", name, VNL);

  return area;
}

DEFUN (area_vlink,
       area_vlink_cmd,
       "area (A.B.C.D|<0-4294967295>) virtual-link A.B.C.D",
       VLINK_HELPSTR_IPADDR)
{
  struct ospf6_area *area = NULL;
  struct ospf6_vl_config_data vl_config;
  int i;

  area = ospf6_area_process_vl_cmd (argv[0], argv[1], &vl_config, vty);
  if (! area)
    return CMD_SUCCESS;

  /* Check if this router is an ABR */
  if (! ospf6_is_router_abr (ospf6))
    {
      vty_out (vty, "This router is not an ABR: %s%s", argv[1], VNL);
      return CMD_SUCCESS;
    }

  /* Create Virtual Link with default timers */
  if (argc == 2)
    return  ospf6_vl_set(ospf6, area, &vl_config);

  /* set timers */
  for (i=2; i < argc; i++)
    {
      switch (argv[i][0])
        {

        case 'h':
          /* Hello interval */
          vl_config.hello_interval = strtol (argv[++i], NULL, 10);
          break;

        case 'r':
          /* Retransmit Interval */
          vl_config.retransmit_interval = strtol (argv[++i], NULL, 10);
          break;

        case 't':
          /* Transmit Delay */
          vl_config.transmit_delay = strtol (argv[++i], NULL, 10);
          break;

        case 'd':
          /* Dead Interval */
          vl_config.dead_interval = strtol (argv[++i], NULL, 10);
          break;
        }
    }

  /* Action configuration */
  return ospf6_vl_set (ospf6, area, &vl_config);
}

DEFUN (no_area_vlink,
       no_area_vlink_cmd,
       "no area (A.B.C.D|<0-4294967295>) virtual-link A.B.C.D",
       NO_STR
       VLINK_HELPSTR_IPADDR)
{
  struct ospf6_area *area = NULL;
  struct ospf6_vl_config_data vl_config;
  struct ospf6_vl_data *vl_data;
  int i;

  area = ospf6_area_process_vl_cmd (argv[0], argv[1], &vl_config, vty);

  if (! area)
    {
      vty_out (vty, "Area %s does not exist%s", argv[0], VNL);
      return CMD_SUCCESS;
    }

  vl_data = ospf6_vl_lookup (area, vl_config.vl_peer);
  
  if (vl_data == NULL)
    {
      vty_out (vty, "This Virtual-Link does not exist%s", VNL);
      return CMD_SUCCESS;
    }

  if (argc ==2)
    {
      ospf6_vl_delete (area, vl_data);
      return CMD_SUCCESS;
    }

  /* Deal with timer parameters */
  for (i=2; i < argc; i++)
    {
      switch (argv[i][0])
        {

        case 'h':
          /* Hello interval */
          vl_config.hello_interval = DEFAULT_HELLO_INTERVAL;
          break;

        case 'r':
          /* Retransmit Interval */
          vl_config.retransmit_interval = DEFAULT_RETRANSMIT_INTERVAL;
          break;

        case 't':
          /* Transmit Delay */
          vl_config.transmit_delay = DEFAULT_TRANSMISSION_DELAY;
          break;

        case 'd':
          /* Dead Interval */
          vl_config.dead_interval = DEFAULT_DEAD_INTERVAL;
          break;
        }
    }
  return ospf6_vl_set (ospf6, area, &vl_config);
}

ALIAS (area_vlink,
       area_vlink_param1_cmd,
       "area (A.B.C.D|<0-4294967295>) virtual-link A.B.C.D (hello-interval|retransmit-interval|transmit-delay|dead-interval) <1-65535>",
       VLINK_HELPSTR_IPADDR
       VLINK_HELPSTR_TIME_PARAM)

ALIAS (no_area_vlink,
       no_area_vlink_param1_cmd,
       "no area (A.B.C.D|<0-4294967295>) virtual-link A.B.C.D (hello-interval|retransmit-interval|transmit-delay|dead-interval)",
       NO_STR
       VLINK_HELPSTR_IPADDR
       VLINK_HELPSTR_TIME_PARAM_NOSECS)

ALIAS (area_vlink,
       area_vlink_param2_cmd,
       "area (A.B.C.D|<0-4294967295>) virtual-link A.B.C.D (hello-interval|retransmit-interval|transmit-delay|dead-interval) <1-65535> (hello-interval|retransmit-interval|transmit-delay|dead-interval) <1-65535>",
       VLINK_HELPSTR_IPADDR
       VLINK_HELPSTR_TIME_PARAM
       VLINK_HELPSTR_TIME_PARAM)

ALIAS (no_area_vlink,
       no_area_vlink_param2_cmd,
       "no area (A.B.C.D|<0-4294967295>) virtual-link A.B.C.D (hello-interval|retransmit-interval|transmit-delay|dead-interval) (hello-interval|retransmit-interval|transmit-delay|dead-interval)",
       NO_STR
       VLINK_HELPSTR_IPADDR
       VLINK_HELPSTR_TIME_PARAM_NOSECS
       VLINK_HELPSTR_TIME_PARAM_NOSECS)

ALIAS (area_vlink,
       area_vlink_param3_cmd,
       "area (A.B.C.D|<0-4294967295>) virtual-link A.B.C.D (hello-interval|retransmit-interval|transmit-delay|dead-interval) <1-65535> (hello-interval|retransmit-interval|transmit-delay|dead-interval) <1-65535> (hello-interval|retransmit-interval|transmit-delay|dead-interval) <1-65535>",
       VLINK_HELPSTR_IPADDR
       VLINK_HELPSTR_TIME_PARAM
       VLINK_HELPSTR_TIME_PARAM
       VLINK_HELPSTR_TIME_PARAM)

ALIAS (no_area_vlink,
       no_area_vlink_param3_cmd,
       "no area (A.B.C.D|<0-4294967295>) virtual-link A.B.C.D (hello-interval|retransmit-interval|transmit-delay|dead-interval) (hello-interval|retransmit-interval|transmit-delay|dead-interval) (hello-interval|retransmit-interval|transmit-delay|dead-interval)",
       NO_STR
       VLINK_HELPSTR_IPADDR
       VLINK_HELPSTR_TIME_PARAM_NOSECS
       VLINK_HELPSTR_TIME_PARAM_NOSECS
       VLINK_HELPSTR_TIME_PARAM_NOSECS)

ALIAS (area_vlink,
       area_vlink_param4_cmd,
       "area (A.B.C.D|<0-4294967295>) virtual-link A.B.C.D (hello-interval|retransmit-interval|transmit-delay|dead-interval) <1-65535> (hello-interval|retransmit-interval|transmit-delay|dead-interval) <1-65535> (hello-interval|retransmit-interval|transmit-delay|dead-interval) <1-65535> (hello-interval|retransmit-interval|transmit-delay|dead-interval) <1-65535>",
       VLINK_HELPSTR_IPADDR
       VLINK_HELPSTR_TIME_PARAM
       VLINK_HELPSTR_TIME_PARAM
       VLINK_HELPSTR_TIME_PARAM
       VLINK_HELPSTR_TIME_PARAM)

ALIAS (no_area_vlink,
       no_area_vlink_param4_cmd,
       "no area (A.B.C.D|<0-4294967295>) virtual-link A.B.C.D (hello-interval|retransmit-interval|transmit-delay|dead-interval) (hello-interval|retransmit-interval|transmit-delay|dead-interval) (hello-interval|retransmit-interval|transmit-delay|dead-interval) (hello-interval|retransmit-interval|transmit-delay|dead-interval)",
       NO_STR
       VLINK_HELPSTR_IPADDR
       VLINK_HELPSTR_TIME_PARAM_NOSECS
       VLINK_HELPSTR_TIME_PARAM_NOSECS
       VLINK_HELPSTR_TIME_PARAM_NOSECS
       VLINK_HELPSTR_TIME_PARAM_NOSECS)

void
ospf6_area_config_write (struct vty *vty)
{
  struct listnode *node, *vl_node;
  struct ospf6_area *oa;
  struct ospf6_route *range;
  struct ospf6_vl_data *vl_data;
  char buf[128], buf_rid[16];

  for (ALL_LIST_ELEMENTS_RO (ospf6->area_list, node, oa))
    {
      for (range = ospf6_route_head (oa->range_table); range;
           range = ospf6_route_next (range))
        {
          prefix2str (&range->prefix, buf, sizeof (buf));
	  if (oa->ai_format == OSPF6_AREA_ID_FORMAT_DECIMAL)
	    vty_out (vty, " area %lu range %s%s", (unsigned long int) ntohl (oa->area_id), buf, VNL);
	  else
            vty_out (vty, " area %s range %s%s", oa->name, buf, VNL);
        }

      if (IS_AREA_STUB (oa))
        {
          if (IS_AREA_NO_SUMMARY (oa))
            vty_out (vty, " area %s stub no-summary%s", oa->name, VNL);
	  else
            vty_out (vty, " area %s stub%s", oa->name, VNL);
        }

      if (IS_AREA_NSSA (oa))
        {
          if (oa->NSSATranslatorRole == NSSA_TRANSLATOR_ROLE_NEVER)
            vty_out (vty, " area %s nssa translate-never", oa->name);
          else if (oa->NSSATranslatorRole == NSSA_TRANSLATOR_ROLE_ALWAYS)
            vty_out (vty, " area %s nssa translate-always", oa->name);
          else
            vty_out (vty, " area %s nssa", oa->name);

          if (IS_AREA_NO_SUMMARY (oa))
            vty_out (vty, " no-summary%s", VNL);
	  else
            vty_out (vty, "%s", VNL);

          if (oa->default_metric_type != EXTERNAL_METRIC_TYPE_1)
            vty_out (vty, " area %s nssa default-metric-type %d%s",
                     oa->name, oa->default_metric_type , VNL);

          if (oa->nssa_no_propagate != 0)
            vty_out (vty, " area %s nssa no-propagate%s", oa->name, VNL);

          if (oa->nssa_no_redistribution != 0)
            vty_out (vty, " area %s nssa no-redistribution%s", oa->name, VNL);

          if (oa->NSSATranslatorStabilityInterval !=
              DEFAULT_NSSA_TRANSLATOR_STABILITY_INTERVAL)
            vty_out (vty, " area %s nssa translator-stability-interval %u%s",
                     oa->name, oa->NSSATranslatorStabilityInterval, VNL);
        }

      if (oa->plist_in.name)
        vty_out (vty, " area %s filter-list prefix %s in%s",oa->name,oa->plist_in.name,VNL);
      if (oa->plist_out.name)
        vty_out (vty, " area %s filter-list prefix %s out%s",oa->name,oa->plist_out.name,VNL);
      vty_out (vty, "%s", VTY_NEWLINE);

      if (oa->default_cost != 1)
        vty_out (vty, " area %s default-cost %u%s", oa->name,
                 oa->default_cost, VNL);

      if (ospf6_area_vlink_count(oa))
        {
          for (ALL_LIST_ELEMENTS_RO (oa->vlink_list, vl_node, vl_data))
            {
              inet_ntop(AF_INET, &vl_data->vl_peer, buf_rid, sizeof (buf_rid));
              vty_out (vty, " area %s virtual-link %s%s", oa->name, buf_rid,VNL);
            }
        }
    }
}

DEFUN (show_ipv6_ospf6_spf_tree,
       show_ipv6_ospf6_spf_tree_cmd,
       "show ipv6 ospf6 spf tree",
       SHOW_STR
       IP6_STR
       OSPF6_STR
       "Shortest Path First caculation\n"
       "Show SPF tree\n")
{
  struct listnode *node;
  struct ospf6_area *oa;
  struct ospf6_vertex *root;
  struct ospf6_route *route;
  struct prefix prefix;

  ospf6_linkstate_prefix (ospf6->router_id, htonl (0), &prefix);

  for (ALL_LIST_ELEMENTS_RO (ospf6->area_list, node, oa))
    {
      route = ospf6_route_lookup (&prefix, oa->spf_table);
      if (route == NULL)
        {
          vty_out (vty, "LS entry for root not found in area %s%s",
                   oa->name, VNL);
          continue;
        }
      root = (struct ospf6_vertex *) route->route_option;
      ospf6_spf_display_subtree (vty, "", 0, root);
    }

  return CMD_SUCCESS;
}

DEFUN (show_ipv6_ospf6_area_spf_tree,
       show_ipv6_ospf6_area_spf_tree_cmd,
       "show ipv6 ospf6 area (A.B.C.D|<0-4294967295>) spf tree",
       SHOW_STR
       IP6_STR
       OSPF6_STR
       OSPF6_AREA_STR
       OSPF6_AREA_ID_STR
       "Shortest Path First caculation\n"
       "Show SPF tree\n")
{
  u_int32_t area_id;
  struct ospf6_area *oa;
  struct ospf6_vertex *root;
  struct ospf6_route *route;
  struct prefix prefix;
  int ai_format;

  ospf6_linkstate_prefix (ospf6->router_id, htonl (0), &prefix);

  if (ospf6_str2area_id (argv[0], &area_id, &ai_format) < 0)
    {
      vty_out (vty, "Malformed Area-ID: %s%s", argv[0], VNL);
      return CMD_SUCCESS;
    }
  oa = ospf6_area_lookup (area_id, ospf6);
  if (oa == NULL)
    {
      vty_out (vty, "No such Area: %s%s", argv[0], VNL);
      return CMD_SUCCESS;
    }

  route = ospf6_route_lookup (&prefix, oa->spf_table);
  if (route == NULL)
    {
      if (oa->ai_format == OSPF6_AREA_ID_FORMAT_DECIMAL)
        vty_out (vty, "LS entry for root not found in area %lu%s",
               (unsigned long int) ntohl (oa->area_id), VNL);
      else
        vty_out (vty, "LS entry for root not found in area %s%s",
               oa->name, VNL);
      return CMD_SUCCESS;
    }
  root = (struct ospf6_vertex *) route->route_option;
  ospf6_spf_display_subtree (vty, "", 0, root);

  return CMD_SUCCESS;
}

DEFUN (show_ipv6_ospf6_simulate_spf_tree_root,
       show_ipv6_ospf6_simulate_spf_tree_root_cmd,
       "show ipv6 ospf6 simulate spf-tree A.B.C.D area (A.B.C.D|<0-4294967295>)",
       SHOW_STR
       IP6_STR
       OSPF6_STR
       "Shortest Path First caculation\n"
       "Show SPF tree\n"
       "Specify root's router-id to calculate another router's SPF tree\n"
       "OSPF area parameters\n"
       OSPF6_AREA_ID_STR)
{
  u_int32_t area_id;
  int ai_format;
  struct ospf6_area *oa;
  struct ospf6_vertex *root;
  struct ospf6_route *route;
  struct prefix prefix;
  u_int32_t router_id;
  struct ospf6_route_table *spf_table;
  unsigned char tmp_debug_ospf6_spf = 0;

  inet_pton (AF_INET, argv[0], &router_id);
  ospf6_linkstate_prefix (router_id, htonl (0), &prefix);

  if (ospf6_str2area_id (argv[1], &area_id, &ai_format) < 0)
    {
      vty_out (vty, "Malformed Area-ID: %s%s", argv[1], VNL);
      return CMD_SUCCESS;
    }
  oa = ospf6_area_lookup (area_id, ospf6);
  if (oa == NULL)
    {
      vty_out (vty, "No such Area: %s%s", argv[1], VNL);
      return CMD_SUCCESS;
    }

  tmp_debug_ospf6_spf = conf_debug_ospf6_spf;
  conf_debug_ospf6_spf = 0;

  spf_table = ospf6_route_table_create ();
  ospf6_spf_calculation (router_id, spf_table, oa);

  conf_debug_ospf6_spf = tmp_debug_ospf6_spf;

  route = ospf6_route_lookup (&prefix, spf_table);
  if (route == NULL)
    {
      ospf6_spf_table_finish (spf_table);
      ospf6_route_table_delete (spf_table);
      return CMD_SUCCESS;
    }
  root = (struct ospf6_vertex *) route->route_option;
  ospf6_spf_display_subtree (vty, "", 0, root);

  ospf6_spf_table_finish (spf_table);
  ospf6_route_table_delete (spf_table);

  return CMD_SUCCESS;
}


int
ospf6_area_nssa_cmd_handler (struct vty *vty, int argc, const char *argv[], 
                             int nssa, int nosum)
{
  struct ospf6_area *oa;
  struct listnode *k;
  struct ospf6_interface *oi;

  OSPF6_CMD_AREA_GET (argv[0], oa);

  if (IS_AREA_BACKBONE (oa))
    {
        vty_out(vty,"You can't configure nssa to backbone%s",VNL);
	return CMD_WARNING;
    }

  if (ospf6_area_vlink_count (oa))
    {
        vty_out(vty,"Area can't be nssa as it contains virtual link%s",VNL);
	return CMD_WARNING;
    }

  /* if area is stub, disable it */
  if (IS_AREA_STUB (oa))
    ospf6_area_stub_cmd_handler (vty, argv, 0, 0);

  if (ospf6_is_router_abr (oa->ospf6))
    ospf6_abr_disable_area (oa); 

  ospf6_abr_nssa_translator_state_disable_now (oa);

  for (ALL_LIST_ELEMENTS_RO (oa->if_list, k, oi))
    thread_add_event (master, interface_down, oi, 0);

  if (nssa)
    {
      SET_FLAG (oa->flag, OSPF6_AREA_NSSA);
      OSPF6_OPT_CLEAR (oa->options, OSPF6_OPT_E);
      OSPF6_OPT_SET (oa->options, OSPF6_OPT_N);

      if (argc > 1)
        {
          if (strncmp (argv[1], "translate-c", 11) == 0)
            oa->NSSATranslatorRole = NSSA_TRANSLATOR_ROLE_CANDIDATE;
          else if (strncmp (argv[1], "translate-n", 11) == 0)
            oa->NSSATranslatorRole = NSSA_TRANSLATOR_ROLE_NEVER;
          else if (strncmp (argv[1], "translate-a", 11) == 0)
            oa->NSSATranslatorRole = NSSA_TRANSLATOR_ROLE_ALWAYS;
        }
      else
        oa->NSSATranslatorRole = NSSA_TRANSLATOR_ROLE_CANDIDATE;

      if (nosum)
        SET_FLAG (oa->flag, OSPF6_AREA_NO_SUMMARY);
      else
        UNSET_FLAG (oa->flag, OSPF6_AREA_NO_SUMMARY);
    }
  else
    {
      UNSET_FLAG (oa->flag, OSPF6_AREA_NSSA);
      OSPF6_OPT_SET (oa->options, OSPF6_OPT_E);
      OSPF6_OPT_CLEAR (oa->options, OSPF6_OPT_N);
      UNSET_FLAG (oa->flag, OSPF6_AREA_NO_SUMMARY);
    }

  ospf6_abr_nssa_translator_state_update (oa);

  for (ALL_LIST_ELEMENTS_RO (oa->if_list, k, oi))
    thread_add_event (master, interface_up, oi, 0);

  if (ospf6_is_router_abr (oa->ospf6))
    ospf6_abr_enable_area (oa); 

  return CMD_SUCCESS;
}

DEFUN (area_nssa_translate_no_summary,
       area_nssa_translate_no_summary_cmd,
       "area (A.B.C.D|<0-4294967295>) nssa (translate-candidate|translate-never|translate-always) no-summary",
       "OSPF area parameters\n"
       OSPF6_AREA_ID_STR 
       "Configure OSPF area as nssa\n"
       "Configure NSSA-ABR for translate election (default)\n"
       "Configure NSSA-ABR to never translate\n"
       "Configure NSSA-ABR to always translate\n"
       "Do not inject inter-area routes into nssa\n")
{
   return ospf6_area_nssa_cmd_handler (vty, argc, argv, 1, 1);
}

DEFUN (area_nssa_translate,
       area_nssa_translate_cmd,
       "area (A.B.C.D|<0-4294967295>) nssa (translate-candidate|translate-never|translate-always)",
       "OSPF area parameters\n"
       OSPF6_AREA_ID_STR
       "Configure OSPF area as nssa\n"
       "Configure NSSA-ABR for translate election (default)\n"
       "Configure NSSA-ABR to never translate\n"
       "Configure NSSA-ABR to always translate\n")
{
  return ospf6_area_nssa_cmd_handler (vty, argc, argv, 1, 0);
}

DEFUN (area_nssa,
       area_nssa_cmd,
       "area (A.B.C.D|<0-4294967295>) nssa",
       "OSPF area parameters\n"
       OSPF6_AREA_ID_STR
       "Configure OSPF area as nssa\n")
{
  return ospf6_area_nssa_cmd_handler (vty, argc, argv, 1, 0);
}

DEFUN (area_nssa_no_summary,
       area_nssa_no_summary_cmd,
       "area (A.B.C.D|<0-4294967295>) nssa no-summary",
       "OSPF area parameters\n"
       OSPF6_AREA_ID_STR
       "Configure OSPF area as nssa\n"
       "Do not inject inter-area routes into nssa\n")
{
  return ospf6_area_nssa_cmd_handler (vty, argc, argv, 1, 1);
}

DEFUN (area_nssa_translator_stability_interval,
       area_nssa_translator_stability_interval_cmd,
       "area (A.B.C.D|<0-4294967295>) nssa translator-stability-interval <0-65535>",
       "OSPF area parameters\n"
       OSPF6_AREA_ID_STR
       "Configure OSPF area as nssa\n"
       "Set the NSSA Translator Stability Interval\n"
       "Time the translator will continue to translate, after translator status is lost\n")
{
  struct ospf6_area *oa;
  u_int16_t interval;

  VTY_GET_INTEGER_RANGE ("nssa translator stability interval",
                          interval, argv[1], 0, 65535);
  ospf6_area_nssa_cmd_handler (vty, argc, argv, 1, 0);
  OSPF6_CMD_AREA_GET (argv[0], oa);

  oa->NSSATranslatorStabilityInterval = interval;

  return CMD_SUCCESS;
}

DEFUN (no_area_nssa_translator_stability_interval,
       no_area_nssa_translator_stability_interval_cmd,
       "no area (A.B.C.D|<0-4294967295>) nssa translator-stability-interval",
       NO_STR
       "OSPF area parameters\n"
       OSPF6_AREA_ID_STR
       "Configure OSPF area as nssa\n"
       "Set the NSSA Translator Stability Interval\n")
{
  struct ospf6_area *oa;

  OSPF6_CMD_AREA_GET (argv[0], oa);

  oa->NSSATranslatorStabilityInterval =
    DEFAULT_NSSA_TRANSLATOR_STABILITY_INTERVAL;

  return CMD_SUCCESS;
}

DEFUN (area_nssa_no_propagate,
       area_nssa_no_propagate_cmd,
       "area (A.B.C.D|<0-4294967295>) nssa no-propagate",
       "OSPF area parameters\n"
       OSPF6_AREA_ID_STR
       "Configure OSPF area as nssa\n"
       "Do not set P-bit in originated Type-7 LSAs\n")
{
  struct ospf6_area *oa;

  ospf6_area_nssa_cmd_handler (vty, argc, argv, 1, 0);
  OSPF6_CMD_AREA_GET (argv[0], oa);
  oa->nssa_no_propagate = 1;

  return CMD_SUCCESS;
}

DEFUN (no_area_nssa_no_propagate,
       no_area_nssa_no_propagate_cmd,
       "no area (A.B.C.D|<0-4294967295>) nssa no-propagate",
       NO_STR
       "OSPF area parameters\n"
       OSPF6_AREA_ID_STR
       "Configure OSPF area as nssa\n"
       "Do not set P-bit in originated Type-7 LSAs\n")
{
  struct ospf6_area *oa;

  OSPF6_CMD_AREA_GET (argv[0], oa);

  oa->nssa_no_propagate = 0;

  return CMD_SUCCESS;
}


DEFUN (area_nssa_no_redistribution,
       area_nssa_no_redistribution_cmd,
       "area (A.B.C.D|<0-4294967295>) nssa no-redistribution",
       "OSPF area parameters\n"
       OSPF6_AREA_ID_STR
       "Configure OSPF area as nssa\n"
       "Do not inject external routes into nssa\n")
{
  struct ospf6_area *oa;

  ospf6_area_nssa_cmd_handler (vty, argc, argv, 1, 0);
  OSPF6_CMD_AREA_GET (argv[0], oa);
  oa->nssa_no_redistribution = 1;

  return CMD_SUCCESS;
}

DEFUN (no_area_nssa_no_redistribution,
       no_area_nssa_no_redistribution_cmd,
       "no area (A.B.C.D|<0-4294967295>) nssa no-redistribution",
       NO_STR
       "OSPF area parameters\n"
       OSPF6_AREA_ID_STR
       "Configure OSPF area as nssa\n"
       "Do not inject external routes into nssa\n")
{
  struct ospf6_area *oa;

  OSPF6_CMD_AREA_GET (argv[0], oa);

  oa->nssa_no_redistribution = 0;

  return CMD_SUCCESS;
}

DEFUN (no_area_nssa,
       no_area_nssa_cmd,
       "no area (A.B.C.D|<0-4294967295>) nssa",
       NO_STR
       "OSPF area parameters\n"
       OSPF6_AREA_ID_STR
       "Configure OSPF area as nssa\n")
{
  return ospf6_area_nssa_cmd_handler (vty, argc, argv, 0, 0);
}

DEFUN (no_area_nssa_no_summary,
       no_area_nssa_no_summary_cmd,
       "no area (A.B.C.D|<0-4294967295>) nssa no-summary",
       NO_STR
       "OSPF area parameters\n"
       OSPF6_AREA_ID_STR
       "Configure OSPF area as nssa\n"
       "Do not inject inter-area routes into nssa\n")
{
  return ospf6_area_nssa_cmd_handler (vty, argc, argv, 1, 0);
}

DEFUN (area_nssa_default_metric_type,
       area_nssa_default_metric_type_cmd,
       "area (A.B.C.D|<0-4294967295>) nssa default-metric-type (1|2)",
       "OSPF area parameters\n"
       OSPF6_AREA_ID_STR
       "Configure OSPF area as nssa\n"
       "Set the type7-default metric-type of a nssa area\n"
       "Set OSPF6 External Type 1 metrics\n"
       "Set OSPF6 External Type 2 metrics\n"
       )
{
  struct ospf6_area *oa;
  u_int8_t metric_type;

  VTY_GET_INTEGER_RANGE ("nssa default metric-type", metric_type, argv[1], 1, 2);

  OSPF6_CMD_AREA_GET (argv[0], oa);
 
  if (metric_type != oa->default_metric_type) 
    {
      oa->default_metric_type = metric_type;
      if (ospf6_is_router_abr (oa->ospf6))
        {
          if (IS_AREA_NSSA (oa) && !IS_AREA_NO_SUMMARY (oa))
            ospf6_abr_default_type_7_org_or_clear (oa, TYPE7_ORIGINATE);
        }
    }

  return CMD_SUCCESS;
}

DEFUN (no_area_nssa_default_metric_type,
       no_area_nssa_default_metric_type_cmd,
       "no area (A.B.C.D|<0-4294967295>) nssa default-metric-type (1|2)",
       NO_STR
       "OSPF area parameters\n"
       OSPF6_AREA_ID_STR
       "Configure OSPF area as nssa\n"
       "Set the type7-default metric-type of a nssa area\n"
       "Set OSPF6 External Type 1 metrics\n"
       "Set OSPF6 External Type 2 metrics\n"
       )
{
  struct ospf6_area *oa;
  u_int8_t metric_type;

  VTY_GET_INTEGER_RANGE ("nssa default metric-type", metric_type, argv[1], 1, 2);

  OSPF6_CMD_AREA_GET (argv[0], oa);
 
  if (metric_type == oa->default_metric_type) 
    {
      oa->default_metric_type = 1;
      if (ospf6_is_router_abr (oa->ospf6))
        {
          if (IS_AREA_NSSA (oa) && !IS_AREA_NO_SUMMARY (oa))
            ospf6_abr_default_type_7_org_or_clear (oa, TYPE7_ORIGINATE);
        }
    }

  return CMD_SUCCESS;
}

int
ospf6_area_stub_cmd_handler (struct vty *vty, const char *argv[], 
                             int stub, int nosum)
{
  struct ospf6_area *oa;
  struct listnode *k;
  struct ospf6_interface *oi;

  OSPF6_CMD_AREA_GET (argv[0], oa);

  if (IS_AREA_BACKBONE (oa))
    {
        vty_out(vty,"You can't configure stub to backbone%s",VNL);
	return CMD_WARNING;
    }

  if (ospf6_area_vlink_count (oa))
    {
        vty_out(vty,"Area can't be stub as it contains virtual link%s",VNL);
	return CMD_WARNING;
    }

  /* if area is nssa, disable it */
  if (IS_AREA_NSSA (oa))
    ospf6_area_nssa_cmd_handler (vty, 0, argv, 0, 0);

  if (ospf6_is_router_abr (oa->ospf6))
    ospf6_abr_disable_area (oa); 

  for (ALL_LIST_ELEMENTS_RO (oa->if_list, k, oi))
    thread_add_event (master, interface_down, oi, 0);

  if (stub)
    {
      SET_FLAG (oa->flag, OSPF6_AREA_STUB);
      OSPF6_OPT_CLEAR (oa->options, OSPF6_OPT_E);
      OSPF6_OPT_CLEAR (oa->options, OSPF6_OPT_N);

      if (nosum)
        SET_FLAG (oa->flag, OSPF6_AREA_NO_SUMMARY);
      else
        UNSET_FLAG (oa->flag, OSPF6_AREA_NO_SUMMARY);
    }
  else
    {
      UNSET_FLAG (oa->flag, OSPF6_AREA_STUB);
      OSPF6_OPT_SET (oa->options, OSPF6_OPT_E);
      OSPF6_OPT_CLEAR (oa->options, OSPF6_OPT_N);
      UNSET_FLAG (oa->flag, OSPF6_AREA_NO_SUMMARY);
    }

  for (ALL_LIST_ELEMENTS_RO (oa->if_list, k, oi))
    thread_add_event (master, interface_up, oi, 0);

  if (ospf6_is_router_abr (oa->ospf6))
    ospf6_abr_enable_area (oa); 

  return CMD_SUCCESS;
}

DEFUN (area_stub,
       area_stub_cmd,
       "area (A.B.C.D|<0-4294967295>) stub",
       "OSPF area parameters\n"
       OSPF6_AREA_ID_STR
       "Configure OSPF area as stub\n"
       )
{
  return ospf6_area_stub_cmd_handler (vty, argv, 1, 0);
}

DEFUN (area_stub_no_summary,
       area_stub_no_summary_cmd,
       "area (A.B.C.D|<0-4294967295>) stub no-summary",
       "OSPF area parameters\n"
       OSPF6_AREA_ID_STR
       "Configure OSPF area as stub\n"
       "Do not inject inter-area routes into stub\n"
       )
{
  return ospf6_area_stub_cmd_handler (vty, argv, 1, 1);
}


DEFUN (no_area_stub,
       no_area_stub_cmd,
       "no area (A.B.C.D|<0-4294967295>) stub",
       NO_STR
       "OSPF area parameters\n"
       OSPF6_AREA_ID_STR
       "Configure OSPF area as stub\n"
       )
{
  return ospf6_area_stub_cmd_handler (vty, argv, 0, 0);
}

DEFUN (no_area_stub_no_summary,
       no_area_stub_no_summary_cmd,
       "no area (A.B.C.D|<0-4294967295>) stub no-summary",
       NO_STR
       "OSPF area parameters\n"
       OSPF6_AREA_ID_STR
       "Configure OSPF area as stub\n"
       "Do not inject inter-area routes into stub\n"
       )
{
  return ospf6_area_stub_cmd_handler (vty, argv, 1, 0);
}

DEFUN (area_default_cost,
       area_default_cost_cmd,
       "area (A.B.C.D|<0-4294967295>) default-cost <0-16777215>",
       "OSPF area parameters\n"
       OSPF6_AREA_ID_STR
       "Set the summary-default cost of a NSSA or stub area\n"
       "Stub's or NSSA's advertised default summary cost\n"
       )
{
  struct ospf6_area *oa;
  u_int32_t cost;

  VTY_GET_INTEGER_RANGE ("default cost", cost, argv[1], 0, 16777215);

  OSPF6_CMD_AREA_GET (argv[0], oa);
 
  if (cost != oa->default_cost) 
    {
      oa->default_cost = cost;
      if (ospf6_is_router_abr (oa->ospf6))
        {
          if (IS_AREA_STUB (oa) || (IS_AREA_NSSA (oa) &&
              IS_AREA_NO_SUMMARY (oa)))
            ospf6_abr_originate_default_summary_to_area (oa);
          else if (IS_AREA_NSSA (oa))
            ospf6_abr_default_type_7_org_or_clear (oa, TYPE7_ORIGINATE);
        }
    }

  return CMD_SUCCESS;
}

DEFUN (no_area_default_cost,
       no_area_default_cost_cmd,
       "no area (A.B.C.D|<0-4294967295>) default-cost <0-16777215>",
       NO_STR
       "OSPF area parameters\n"
       OSPF6_AREA_ID_STR
       "Set the summary-default cost of a NSSA or stub area\n"
       "Stub's or NSSA's advertised default summary cost\n"
       )
{
  struct ospf6_area *oa;
  u_int32_t cost;

  VTY_GET_INTEGER_RANGE ("default cost", cost, argv[1], 0, 16777215);

  OSPF6_CMD_AREA_GET (argv[0], oa);

  if (cost == oa->default_cost) 
    {
      oa->default_cost = 1;
      if (ospf6_is_router_abr (oa->ospf6))
        {
          if (IS_AREA_STUB (oa) || (IS_AREA_NSSA (oa) &&
              IS_AREA_NO_SUMMARY (oa)))
            ospf6_abr_originate_default_summary_to_area (oa);
          else if (IS_AREA_NSSA (oa))
            ospf6_abr_default_type_7_org_or_clear (oa, TYPE7_ORIGINATE);
        }
    }

  return CMD_SUCCESS;
}
 
DEFUN (area_filter_list,
       area_filter_list_cmd,
       "area (A.B.C.D|<0-4294967295>) filter-list prefix WORD (in|out)",
       "OSPF area parameters\n"
       "OSPF area ID in IP address format\n"
       "OSPF area ID as a decimal value\n"
       "Filter networks between OSPF areas\n"
       "Filter prefixes between OSPF areas\n"
       "Name of an IP prefix-list\n"
       "Filter networks sent to this area\n"
       "Filter networks sent from this area\n")
{
  struct ospf6 *ospf6 = vty->index;
  struct ospf6_area *area;
  struct prefix_list *plist;
  struct ospf6_area *oa = NULL;
  struct listnode *node, *nnode;

  OSPF6_CMD_AREA_GET (argv[0], area);

  plist = prefix_list_lookup (AFI_IP6, argv[1]);

  if(plist == NULL)
   return CMD_SUCCESS;

  if (strncmp (argv[2], "in", 2) == 0)
    {
      ospf6_abr_disable_area (area);

      if (PREFIX_NAME_IN (area))
        free (PREFIX_NAME_IN (area));

      PREFIX_NAME_IN (area) = strdup (argv[1]);

      ospf6_abr_enable_area (area);

    }
  else
    {
      for (ALL_LIST_ELEMENTS (ospf6->area_list, node, nnode, oa))
         {
           if (area->area_id != oa->area_id)
             ospf6_abr_disable_area (oa);
         }

      if (PREFIX_NAME_OUT (area))
        free (PREFIX_NAME_OUT (area));

      PREFIX_NAME_OUT (area) = strdup (argv[1]);

      for (ALL_LIST_ELEMENTS (ospf6->area_list, node, nnode, oa))
         {
           if (area->area_id != oa->area_id)
             ospf6_abr_enable_area (oa);
         }

    }

  return CMD_SUCCESS;
}

DEFUN (no_area_filter_list,
       no_area_filter_list_cmd,
       "no area (A.B.C.D|<0-4294967295>) filter-list prefix WORD (in|out)",
       NO_STR
       "OSPF area parameters\n"
       "OSPF area ID in IP address format\n"
       "OSPF area ID as a decimal value\n"
       "Filter networks between OSPF areas\n"
       "Filter prefixes between OSPF areas\n"
       "Name of an IP prefix-list\n"
       "Filter networks sent to this area\n"
       "Filter networks sent from this area\n")
{
  struct ospf6 *ospf6 = vty->index;
  struct ospf6_area *area,*oa=NULL;
  struct prefix_list *plist;
  struct listnode *node, *nnode;

  OSPF6_CMD_AREA_GET (argv[0], area);
  plist = prefix_list_lookup (AFI_IP6, argv[1]);

  if(plist == NULL)
   return CMD_SUCCESS;

  if (strncmp (argv[2], "in", 2) == 0)
    {
      ospf6_abr_disable_area (area);

      if (PREFIX_NAME_IN (area))
        if (strcmp (PREFIX_NAME_IN (area), argv[1]) != 0)
          return CMD_SUCCESS;

      if (PREFIX_NAME_IN (area))
        free (PREFIX_NAME_IN (area));

      PREFIX_NAME_IN (area) = NULL;

      ospf6_abr_enable_area (area);

    }
  else
    {
      for (ALL_LIST_ELEMENTS (ospf6->area_list, node, nnode, oa))
         {
           if (area->area_id != oa->area_id)
             ospf6_abr_disable_area (oa);
         }

      if (PREFIX_NAME_OUT (area))
        if (strcmp (PREFIX_NAME_OUT (area), argv[1]) != 0)
          return CMD_SUCCESS;

      if (PREFIX_NAME_OUT (area))
        free (PREFIX_NAME_OUT (area));

      PREFIX_NAME_OUT (area) = NULL;

      for (ALL_LIST_ELEMENTS (ospf6->area_list, node, nnode, oa))
         {
           if (area->area_id != oa->area_id)
             ospf6_abr_enable_area (oa);
         }

    }

  return CMD_SUCCESS;
}

void
ospf6_area_init ()
{
  install_element (VIEW_NODE, &show_ipv6_ospf6_spf_tree_cmd);
  install_element (VIEW_NODE, &show_ipv6_ospf6_area_spf_tree_cmd);
  install_element (VIEW_NODE, &show_ipv6_ospf6_simulate_spf_tree_root_cmd);

  install_element (ENABLE_NODE, &show_ipv6_ospf6_spf_tree_cmd);
  install_element (ENABLE_NODE, &show_ipv6_ospf6_area_spf_tree_cmd);
  install_element (ENABLE_NODE, &show_ipv6_ospf6_simulate_spf_tree_root_cmd);

  install_element (OSPF6_NODE, &area_range_cmd);
  install_element (OSPF6_NODE, &area_range_advertise_cmd);
  install_element (OSPF6_NODE, &no_area_range_cmd);

  /* "area stub" commands */
  install_element (OSPF6_NODE, &area_stub_cmd);
  install_element (OSPF6_NODE, &area_stub_no_summary_cmd);
  install_element (OSPF6_NODE, &no_area_stub_cmd);
  install_element (OSPF6_NODE, &no_area_stub_no_summary_cmd);
  install_element (OSPF6_NODE, &area_default_cost_cmd);
  install_element (OSPF6_NODE, &no_area_default_cost_cmd);

  /* "area nssa" commands */
  install_element (OSPF6_NODE, &area_nssa_cmd);
  install_element (OSPF6_NODE, &area_nssa_translate_no_summary_cmd);
  install_element (OSPF6_NODE, &area_nssa_translate_cmd);
  install_element (OSPF6_NODE, &area_nssa_no_summary_cmd);
  install_element (OSPF6_NODE, &area_nssa_no_propagate_cmd);
  install_element (OSPF6_NODE, &no_area_nssa_no_propagate_cmd);
  install_element (OSPF6_NODE, &area_nssa_no_redistribution_cmd);
  install_element (OSPF6_NODE, &no_area_nssa_no_redistribution_cmd);
  install_element (OSPF6_NODE, &no_area_nssa_cmd);
  install_element (OSPF6_NODE, &no_area_nssa_no_summary_cmd);
  install_element (OSPF6_NODE, &area_nssa_default_metric_type_cmd);
  install_element (OSPF6_NODE, &no_area_nssa_default_metric_type_cmd);
  install_element (OSPF6_NODE, &area_nssa_translator_stability_interval_cmd);

  /* filter-list commands */
  install_element (OSPF6_NODE, &area_filter_list_cmd);
  install_element (OSPF6_NODE, &no_area_filter_list_cmd);

  install_element (OSPF6_NODE, &no_area_nssa_translator_stability_interval_cmd);
  
  /* virtual link commands */
  install_element (OSPF6_NODE, &area_vlink_cmd);

  install_element (OSPF6_NODE, &area_vlink_param1_cmd);
  install_element (OSPF6_NODE, &area_vlink_param2_cmd);
  install_element (OSPF6_NODE, &area_vlink_param3_cmd);
  install_element (OSPF6_NODE, &area_vlink_param4_cmd);

  install_element (OSPF6_NODE, &no_area_vlink_cmd);

  install_element (OSPF6_NODE, &no_area_vlink_param1_cmd);
  install_element (OSPF6_NODE, &no_area_vlink_param2_cmd);
  install_element (OSPF6_NODE, &no_area_vlink_param3_cmd);
  install_element (OSPF6_NODE, &no_area_vlink_param4_cmd);
}


