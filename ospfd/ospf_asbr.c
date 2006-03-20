/*
 * OSPF AS Boundary Router functions.
 * Copyright (C) 1999, 2000 Kunihiro Ishiguro, Toshiaki Takada
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
 * along with GNU Zebra; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#include <zebra.h>

#include "thread.h"
#include "memory.h"
#include "linklist.h"
#include "prefix.h"
#include "if.h"
#include "table.h"
#include "vty.h"
#include "filter.h"
#include "log.h"

#include "ospfd/ospfd.h"
#include "ospfd/ospf_interface.h"
#include "ospfd/ospf_asbr.h"
#include "ospfd/ospf_lsa.h"
#include "ospfd/ospf_lsdb.h"
#include "ospfd/ospf_neighbor.h"
#include "ospfd/ospf_spf.h"
#include "ospfd/ospf_flood.h"
#include "ospfd/ospf_route.h"
#include "ospfd/ospf_zebra.h"
#include "ospfd/ospf_dump.h"


/* Remove external route. */
void
ospf_external_route_remove (struct ospf *ospf, struct prefix_ipv4 *p)
{
  struct route_node *rn;
  struct ospf_route *or;

  rn = route_node_lookup (ospf->old_external_route, (struct prefix *) p);
  if (rn)
    if ((or = rn->info))
      {
	zlog_info ("Route[%s/%d]: external path deleted",
		   inet_ntoa (p->prefix), p->prefixlen);

	/* Remove route from zebra. */
        if (or->type == OSPF_DESTINATION_NETWORK)
	  ospf_zebra_delete ((struct prefix_ipv4 *) &rn->p, or);

	ospf_route_free (or);
	rn->info = NULL;

	route_unlock_node (rn);
	route_unlock_node (rn);
	return;
      }

  zlog_info ("Route[%s/%d]: no such external path",
	     inet_ntoa (p->prefix), p->prefixlen);
}

/* Lookup external route. */
struct ospf_route *
ospf_external_route_lookup (struct ospf *ospf,
			    struct prefix_ipv4 *p)
{
  struct route_node *rn;

  rn = route_node_lookup (ospf->old_external_route, (struct prefix *) p);
  if (rn)
    {
      route_unlock_node (rn);
      if (rn->info)
	return rn->info;
    }

  zlog_warn ("Route[%s/%d]: lookup, no such prefix",
	     inet_ntoa (p->prefix), p->prefixlen);

  return NULL;
}


/* Add an External info for AS-external-LSA. */
struct external_info *
ospf_external_info_new (u_char type)
{
  struct external_info *new;

  new = (struct external_info *)
    XMALLOC (MTYPE_OSPF_EXTERNAL_INFO, sizeof (struct external_info));
  memset (new, 0, sizeof (struct external_info));
  new->type = type;

  ospf_reset_route_map_set_values (&new->route_map_set);
  return new;
}

void
ospf_external_info_free (struct external_info *ei)
{
  XFREE (MTYPE_OSPF_EXTERNAL_INFO, ei);
}

void
ospf_reset_route_map_set_values (struct route_map_set_values *values)
{
  values->metric = -1;
  values->metric_type = -1;
}

int
ospf_route_map_set_compare (struct route_map_set_values *values1,
			    struct route_map_set_values *values2)
{
  return values1->metric == values2->metric &&
    values1->metric_type == values2->metric_type;
}

/* Add an External info for AS-external-LSA. */
struct external_info *
ospf_external_info_add (u_char type, struct prefix_ipv4 p,
			unsigned int ifindex, struct in_addr nexthop)
{
  struct external_info *new;
  struct route_node *rn;
  struct ospf *ospf;

  /* Initialize route table. */
  if (EXTERNAL_INFO (type) == NULL)
    EXTERNAL_INFO (type) = route_table_init ();

  rn = route_node_get (EXTERNAL_INFO (type), (struct prefix *) &p);
  /* If old info exists, -- discard new one or overwrite with new one? */
  if (rn)
    if (rn->info)
      {
	route_unlock_node (rn);
	zlog_warn ("Redistribute[%s]: %s/%d already exists, discard.",
		   LOOKUP (ospf_redistributed_proto, type),
		   inet_ntoa (p.prefix), p.prefixlen);
	/* XFREE (MTYPE_OSPF_TMP, rn->info); */
	return rn->info;
      }
  
  ospf = ospf_lookup ();
  /* Check to limit redistribution */
  if (ospf_limit_redistribution (p))
    {
      zlog_warn ("can't redistribute more than maximum prefix routes %u",
                                                    ospf->maximum_prefix);
      return NULL;
    }
 
  /* Increment the count for added external routes (default routes are ignored) */
  if (! is_prefix_default (&p)) 
    ospf->redstr_count ++;
 
  /* Create new External info instance. */
  new = ospf_external_info_new (type);
  new->p = p;
  new->ifindex = ifindex;
  new->nexthop = nexthop;
  new->tag = 0;

  rn->info = new;

  if (IS_DEBUG_OSPF (lsa, LSA_GENERATE))
    zlog_debug ("Redistribute[%s]: %s/%d external info created.",
	       LOOKUP (ospf_redistributed_proto, type),
	       inet_ntoa (p.prefix), p.prefixlen);
  return new;
}

void
ospf_external_info_delete (u_char type, struct prefix_ipv4 p)
{
  struct route_node *rn;
  struct ospf *ospf;

  rn = route_node_lookup (EXTERNAL_INFO (type), (struct prefix *) &p);
  if (rn)
    {
      ospf_external_info_free (rn->info);
      rn->info = NULL;
      route_unlock_node (rn);
      route_unlock_node (rn);
    }
  ospf = ospf_lookup ();
  /* Decrement the count for deleted external routes (default route is ignored) */
  if (! is_prefix_default (&p))
    ospf->redstr_count --;  
}

struct external_info *
ospf_external_info_lookup (u_char type, struct prefix_ipv4 *p)
{
  struct route_node *rn;
  rn = route_node_lookup (EXTERNAL_INFO (type), (struct prefix *) p);
  if (rn)
    {
      route_unlock_node (rn);
      if (rn->info)
	return rn->info;
    }

  return NULL;
}

struct ospf_lsa *
ospf_external_info_find_lsa (struct ospf *ospf,
			     struct prefix_ipv4 *p)
{
  struct ospf_lsa *lsa;
  struct as_external_lsa *al;
  struct in_addr mask, id;

  lsa = ospf_lsdb_lookup_by_id (ospf->lsdb, OSPF_AS_EXTERNAL_LSA,
				p->prefix, ospf->router_id);

  if (!lsa)
    return NULL;

  al = (struct as_external_lsa *) lsa->data;

  masklen2ip (p->prefixlen, &mask);

  if (mask.s_addr != al->mask.s_addr)
    {
      id.s_addr = p->prefix.s_addr | (~mask.s_addr);
      lsa = ospf_lsdb_lookup_by_id (ospf->lsdb, OSPF_AS_EXTERNAL_LSA,
				   id, ospf->router_id);
      if (!lsa)
	return NULL;
    }

  return lsa;
}


/* Update ASBR status. */
void
ospf_asbr_status_update (struct ospf *ospf, u_char status)
{
  zlog_info ("ASBR[Status:%d]: Update", status);

  /* ASBR on. */
  if (status)
    {
      /* Already ASBR. */
      if (IS_OSPF_ASBR (ospf))
	{
	  zlog_info ("ASBR[Status:%d]: Already ASBR", status);
	  return;
	}
      SET_FLAG (ospf->flags, OSPF_FLAG_ASBR);
    }
  else
    {
      /* Already non ASBR. */
      if (! IS_OSPF_ASBR (ospf))
	{
	  zlog_info ("ASBR[Status:%d]: Already non ASBR", status);
	  return;
	}
      UNSET_FLAG (ospf->flags, OSPF_FLAG_ASBR);
    }

  /* Transition from/to status ASBR, schedule timer. */
  ospf_spf_calculate_schedule (ospf);
  OSPF_TIMER_ON (ospf->t_router_lsa_update,
		 ospf_router_lsa_update_timer, OSPF_LSA_UPDATE_DELAY);
}

void
ospf_redistribute_withdraw (u_char type)
{
  struct ospf *ospf;
  struct route_node *rn;
  struct external_info *ei;

  ospf = ospf_lookup ();

  /* Delete external info for specified type. */
  if (EXTERNAL_INFO (type))
    for (rn = route_top (EXTERNAL_INFO (type)); rn; rn = route_next (rn))
      if ((ei = rn->info))
	if (ospf_external_info_find_lsa (ospf, &ei->p))
	  {
	    if (is_prefix_default (&ei->p) &&
		ospf->default_originate != DEFAULT_ORIGINATE_NONE)
	      continue;
	    ospf_external_lsa_flush (ospf, type, &ei->p, ei->ifindex, ei->nexthop);
	    ospf_external_info_delete (type, ei->p);
	  }
}

void
ospf_log_warnings_cli (struct ospf *ospf)
{
  u_int32_t prefix_threshold;
  
  /* Get the threshold limit for maximum-prefix */
  prefix_threshold = (ospf->maximum_prefix * ospf->max_prefix_threshold)/100;

  /* Log warning message when threshold is already reached */
  if (ospf->redstr_count >= prefix_threshold)
    zlog_warn ("WARNING : redistributed prefixes reached the threshold value %u",
                                                               prefix_threshold);
  
  /* Log warning message when maximum-prefix is already reached */
  if (ospf->redstr_count >= ospf->maximum_prefix)
    zlog_warn ("WARNING : redistributed prefixes reached the maximum-prefix value %u",
                                                                 ospf->maximum_prefix);
}

void
ospf_redistribute_max_prefix_set (const char *num_str, const char *threshold_str, int warning)
{
  struct ospf *ospf;
  ospf = ospf_lookup ();

  /* set the prefix limit */
  ospf->maximum_prefix = strtol (num_str, NULL, 10);

  /* set the threshold or deafault value (75%) is considered */
  if (threshold_str)
    ospf->max_prefix_threshold = strtol (threshold_str, NULL, 10);

  /* warning-only enable/disable */
  ospf->max_prefix_warning_only = warning;
  
  /* if already some prefixes are redistributed,check to log warnings */
  if (ospf->redstr_count)
    ospf_log_warnings_cli (ospf);
}

void
ospf_redistribute_max_prefix_unset ()
{
  struct ospf *ospf;
  ospf = ospf_lookup ();

  /* Unset the prefix limit */
  ospf->maximum_prefix = 0;
  /* Reset the threshold to default */
  ospf->max_prefix_threshold = OSPF_MAXIMUM_PREFIX_THRESHOLD_DEFAULT;
  /* Unset Warning-Only */
  ospf->max_prefix_warning_only = 0;
}

int
ospf_limit_redistribution (struct prefix_ipv4 p)
{
  struct ospf *ospf;
  u_int32_t prefix_threshold;
 
  ospf = ospf_lookup ();
 
  /* If the max-prefix is not set, redistribute all the prefixes */
  if (!ospf->maximum_prefix)
    return 0;
  
  /* Don't limit default routes (prefixes) */
  if (is_prefix_default (&p))
    return 0;

  /* Get the threshold limit for maximum-prefix */
  prefix_threshold = (ospf->maximum_prefix * ospf->max_prefix_threshold)/100;
  
  /* Log warning message when threshold is reached */
  if ((ospf->redstr_count + 1) == prefix_threshold)
    zlog_warn ("WARNING : redistributed prefixes reached the threshold value %u",
                                                               prefix_threshold);
  
  /* Log warning message when maximum-prefix is reached */
  if ((ospf->redstr_count + 1) == ospf->maximum_prefix)
    zlog_warn ("WARNING : redistributed prefixes reached the maximum-prefix value %u",
                                                                 ospf->maximum_prefix);
  
  /* If Warning-only is set, redistribute all the prefixes */
  if (ospf->max_prefix_warning_only)
    return 0;

  /* Other wise, redistribute only the maximum-prefix no.of routes */
  if (ospf->redstr_count >= ospf->maximum_prefix)
    return 1;

  return 0;
}

