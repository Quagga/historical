/*
 * Area Border Router function.
 * Copyright (C) 2004 Yasuhiro Ohara
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
#include "prefix.h"
#include "table.h"
#include "vty.h"
#include "plist.h"
#include "linklist.h"
#include "command.h"
#include "thread.h"

#include "ospf6_proto.h"
#include "ospf6_route.h"
#include "ospf6_lsa.h"
#include "ospf6_route.h"
#include "ospf6_lsdb.h"
#include "ospf6_message.h"

#include "ospf6_top.h"
#include "ospf6_area.h"
#include "ospf6_interface.h"
#include "ospf6_neighbor.h"

#include "ospf6_flood.h"
#include "ospf6_intra.h"
#include "ospf6_abr.h"
#include "ospf6_asbr.h"
#include "ospf6d.h"

unsigned char conf_debug_ospf6_abr;

static void
ospf6_abr_clear_summary (struct ospf6_route *summary, 
                         struct ospf6_route_table *summary_table, 
                         struct ospf6_lsa *lsa)
{
  if (summary)
    ospf6_route_remove (summary, summary_table);
  if (lsa)
    ospf6_lsa_purge (lsa);
}

int
ospf6_is_router_abr (struct ospf6 *o)
{
  struct listnode *node;
  struct ospf6_area *oa;
  int area_count = 0;

  for (ALL_LIST_ELEMENTS_RO (o->area_list, node, oa))
    if (IS_AREA_ENABLED (oa))
      area_count++;

  if (area_count > 1)
    return 1;
  return 0;
}

int
ospf6_is_router_nssa_abr (struct ospf6 *o)
{
  struct listnode *node;
  struct ospf6_area *oa;

  if (ospf6_is_router_abr (o))
    {
      for (ALL_LIST_ELEMENTS_RO (o->area_list, node, oa))
        if (IS_AREA_ENABLED (oa) && IS_AREA_NSSA (oa))
          return 1;
    }
  return 0;
}

void
ospf6_abr_default_type_7_org_or_clear (struct ospf6_area *area,
                                       u_int8_t org_or_clear)
{
  struct ospf6_route *route;
  struct ospf6_lsa *lsa;
  static u_char active = 0;
  static u_int32_t id = 0;

  if (org_or_clear == TYPE7_CLEAR)
    {
      if (! active)
        return;
      struct ospf6_lsa *old_lsa;
      old_lsa = ospf6_lsdb_lookup (htons (OSPF6_LSTYPE_TYPE_7), id,
                                   area->ospf6->router_id, area->lsdb);
      if (old_lsa) 
        ospf6_lsa_purge (old_lsa);
      active = 0;
      return;
    }

  route = ospf6_route_create ();

  route->type = OSPF6_DEST_TYPE_NETWORK;
  route->prefix.family = AF_INET6;
  route->prefix.prefixlen = 0;
  inet_pton (AF_INET6, IPV6_ADDR_ANY, &route->prefix.u.prefix6);
  route->path.origin.type = htons (OSPF6_LSTYPE_TYPE_7);
  route->path.origin.adv_router = ospf6->router_id;
  route->path.area_id = area->area_id;
  if (area->default_metric_type == 1)
    route->path.type = OSPF6_PATH_TYPE_EXTERNAL1;
  else
    route->path.type = OSPF6_PATH_TYPE_EXTERNAL2;
  route->path.cost = area->default_cost;
  route->path.metric_type = area->default_metric_type;
  route->nexthop[0].ifindex = IFINDEX_INTERNAL;

  if(active == 1)
    {
      struct ospf6_lsa *old_lsa;
      old_lsa = ospf6_lsdb_lookup (htons (OSPF6_LSTYPE_TYPE_7), id,
                                   area->ospf6->router_id, area->lsdb);
      if (old_lsa) 
        {
          struct ospf6_route *old_ro;
          old_ro = ospf6_route_create ();
          ospf6_asbr_route_from_external_lsa (old_lsa, old_ro);
          if (! ospf6_route_path_type_cost_cmp (route, old_ro))
            {
              /* if no change */
              ospf6_route_delete (route);
              ospf6_route_delete (old_ro);
              return;
            }
          ospf6_lsa_purge (old_lsa);
          ospf6_route_delete (old_ro);
        }
    }

  route->path.origin.id = ospf6->external_id++; 
  id = route->path.origin.id;
  active = 1;

  lsa = ospf6_external_lsa_create (route);
  ospf6_lsa_originate_area (lsa, area);

  ospf6_route_delete (route);
}

int
ospf6_abr_plist_in_check (struct ospf6_area *area,struct prefix *p)
{
  struct prefix_list *plist;

  if (PREFIX_NAME_IN (area))
    {
      plist = prefix_list_lookup (AFI_IP6, PREFIX_NAME_IN (area));
      if (plist)
        if (prefix_list_apply (plist, p) != PREFIX_PERMIT)
          return 0;
    }
  return 1;
}
int
ospf6_abr_plist_out_check (struct ospf6_area *area, struct prefix *p)
{
  struct prefix_list *plist;

  if (PREFIX_NAME_OUT (area))
    {
      plist= prefix_list_lookup (AFI_IP6, PREFIX_NAME_OUT (area));
      if (plist)
        if (prefix_list_apply (plist, p) != PREFIX_PERMIT)
          return 0;
    }
  return 1;
}

void
ospf6_abr_enable_area (struct ospf6_area *area)
{
  struct ospf6_area *oa;
  struct ospf6_route *ro, *route;
  struct listnode *node, *nnode;

  for (ALL_LIST_ELEMENTS (area->ospf6->area_list, node, nnode, oa))
    {
      /* update B bit for each area */
      OSPF6_ROUTER_LSA_SCHEDULE (oa);

      /* install other area's configured address range */
      if (oa != area)
        {
          for (ro = ospf6_route_head (oa->range_table); ro;
               ro = ospf6_route_next (ro))
            {
              UNSET_FLAG (ro->flag, OSPF6_ROUTE_ACTIVE_RANGE);

              for (route = ospf6_route_match_head (&ro->prefix, ospf6->route_table);
                    route; route = ospf6_route_match_next (&ro->prefix, route))
                  {
                    if (!ospf6_abr_plist_out_check (oa, &route->prefix))
                      {
                        if (IS_OSPF6_DEBUG_EXAMIN (INTER_PREFIX))
                          zlog_debug ("ospf6_abr_enable_area(): rnage denied by out filter-list");
                        continue;
                      }
                      else
                        SET_FLAG (ro->flag, OSPF6_ROUTE_ACTIVE_RANGE);
                  }

              if (CHECK_FLAG (ro->flag, OSPF6_ROUTE_ACTIVE_RANGE))
                ospf6_abr_originate_summary_to_area (ro, area);
            }
        }
    }

  /* install calculated routes to border routers */
  for (ro = ospf6_route_head (area->ospf6->brouter_table); ro;
       ro = ospf6_route_next (ro))
    ospf6_abr_originate_summary_to_area (ro, area);

  /* install calculated routes to network (may be rejected by ranges) */
  for (ro = ospf6_route_head (area->ospf6->route_table); ro;
       ro = ospf6_route_next (ro))
    ospf6_abr_originate_summary_to_area (ro, area);

  if (IS_AREA_STUB (area) || (IS_AREA_NSSA (area) &&
      IS_AREA_NO_SUMMARY (area)))
    ospf6_abr_originate_default_summary_to_area (area);
  else if (IS_AREA_NSSA (area))
    ospf6_abr_default_type_7_org_or_clear (area, TYPE7_ORIGINATE);
}

void
ospf6_abr_disable_area (struct ospf6_area *area)
{
  struct ospf6_area *oa;
  struct ospf6_route *ro;
  struct ospf6_lsa *old;
  struct listnode *node, *nnode;

  /* Withdraw all summary prefixes previously originated */
  for (ro = ospf6_route_head (area->summary_prefix); ro;
       ro = ospf6_route_next (ro))
    {
      old = ospf6_lsdb_lookup (ro->path.origin.type, ro->path.origin.id,
                               area->ospf6->router_id, area->lsdb);
      ospf6_abr_clear_summary (ro, area->summary_prefix, old);
    }

  /* Withdraw all summary router-routes previously originated */
  for (ro = ospf6_route_head (area->summary_router); ro;
       ro = ospf6_route_next (ro))
    {
      old = ospf6_lsdb_lookup (ro->path.origin.type, ro->path.origin.id,
                               area->ospf6->router_id, area->lsdb);
      ospf6_abr_clear_summary (ro, area->summary_router, old);
    }

  if (IS_AREA_STUB (area) || (IS_AREA_NSSA (area) &&
      IS_AREA_NO_SUMMARY (area)))
    ospf6_abr_clear_default_summary_to_area (area);
  else if (IS_AREA_NSSA (area))
    ospf6_abr_default_type_7_org_or_clear (area, TYPE7_CLEAR);

  /* Schedule Router-LSA for each area (ABR status may change) */
  for (ALL_LIST_ELEMENTS (area->ospf6->area_list, node, nnode, oa))
      /* update B bit for each area */
      OSPF6_ROUTER_LSA_SCHEDULE (oa);
}

int
default_summary_prefix_cmp(const struct prefix *p1)
{
  struct prefix p2; 
 
  p2.family = AF_INET6;
  p2.prefixlen = 0;
  inet_pton (AF_INET6, IPV6_ADDR_ANY, &p2.u.prefix6);
  return (prefix_cmp(p1,&p2));
}

/* RFC 2328 12.4.3. Summary-LSAs */
void
ospf6_abr_originate_summary_to_area (struct ospf6_route *route,
                                     struct ospf6_area *area)
{
  struct ospf6_lsa *lsa, *old = NULL;
  struct ospf6_interface *oi;
  struct ospf6_route *summary, *range = NULL;
  struct ospf6_area *route_area;
  char buffer[OSPF6_MAX_LSASIZE];
  struct ospf6_lsa_header *lsa_header;
  caddr_t p;
  struct ospf6_inter_prefix_lsa *prefix_lsa;
  struct ospf6_inter_router_lsa *router_lsa;
  struct ospf6_route_table *summary_table = NULL;
  u_int16_t type;
  char buf[64];
  int is_debug = 0;

  /* Applying in filter for area */
  if ((route->path.type == OSPF6_PATH_TYPE_INTRA || route->type == OSPF6_DEST_TYPE_RANGE)
      && (!ospf6_abr_plist_in_check (area, &route->prefix)))
    {
      if (IS_OSPF6_DEBUG_EXAMIN (INTER_PREFIX))
        zlog_debug ("ospf_abr_originate_summary_to_area(): denied by in filter-list");
      return;
    }

  /* Applying out filter for area */
  if (route->type == OSPF6_DEST_TYPE_NETWORK)
    {
      route_area = ospf6_area_lookup (route->path.area_id, ospf6);

      if (!ospf6_abr_plist_out_check (route_area, &route->prefix))
        {
          if (IS_OSPF6_DEBUG_EXAMIN (INTER_PREFIX))
            zlog_debug ("ospf6_abr_originate_summary_to_area(): denied by out filter-list");
          return;
        }
     }

  if (route->type == OSPF6_DEST_TYPE_ROUTER)
    {
      if (IS_OSPF6_DEBUG_ABR || IS_OSPF6_DEBUG_ORIGINATE (INTER_ROUTER))
        {
          is_debug++;
          inet_ntop (AF_INET, &(ADV_ROUTER_IN_PREFIX (&route->prefix)),
                     buf, sizeof (buf));
          zlog_debug ("Originating summary in area %s for ASBR %s",
		      area->name, buf);
        }
      summary_table = area->summary_router;
    }
  else
    {
      if (IS_OSPF6_DEBUG_ABR || IS_OSPF6_DEBUG_ORIGINATE (INTER_PREFIX))
        {
          is_debug++;
          prefix2str (&route->prefix, buf, sizeof (buf));
          zlog_debug ("Originating summary in area %s for %s",
		      area->name, buf);
        }
      summary_table = area->summary_prefix;
    }

  summary = ospf6_route_lookup (&route->prefix, summary_table);
  if (summary)
    old = ospf6_lsdb_lookup (summary->path.origin.type,
                             summary->path.origin.id,
                             area->ospf6->router_id, area->lsdb);

  /* if this route has just been removed, remove corresponding LSA */
  if (CHECK_FLAG (route->flag, OSPF6_ROUTE_REMOVE))
    {
      if (is_debug)
        zlog_debug ("The route has just removed, purge previous LSA");

      ospf6_abr_clear_summary (summary, summary_table, old);
      return;
    }

  /* Only destination type network, range or ASBR are considered */
  if (route->type != OSPF6_DEST_TYPE_NETWORK &&
      route->type != OSPF6_DEST_TYPE_RANGE &&
      (route->type != OSPF6_DEST_TYPE_ROUTER ||
       ! CHECK_FLAG (route->path.router_bits, OSPF6_ROUTER_BIT_E)))
    {
      if (is_debug)
        zlog_debug ("Route type is none of network, range nor ASBR, withdraw");

      ospf6_abr_clear_summary (summary, summary_table, old);
      return;
    }

  /* AS External routes are never considered */
  if (route->path.type == OSPF6_PATH_TYPE_EXTERNAL1 ||
      route->path.type == OSPF6_PATH_TYPE_EXTERNAL2)
    {
      if (is_debug)
        zlog_debug ("Path type is external, withdraw");

      ospf6_abr_clear_summary (summary, summary_table, old);
      return;
    }

  /* do not generate if the path's area is the same as target area */
  if (route->path.area_id == area->area_id)
    {
      if (is_debug)
        zlog_debug ("The route is in the area itself, ignore");

      ospf6_abr_clear_summary (summary, summary_table, old);
      return;
    }

  /* do not generate if the nexthops belongs to the target area */
  if (route->nexthop[0].ifindex != IFINDEX_INTERNAL)
    {
      oi = ospf6_interface_lookup_by_ifindex (route->nexthop[0].ifindex);
      if (oi && oi->area && oi->area == area)
        {
          if (is_debug)
            zlog_debug ("The route's nexthop is in the same area, ignore");

          ospf6_abr_clear_summary (summary, summary_table, old);
          return;
       }
    }

  /* do not generate if the route cost is greater or equal to LSInfinity */
  if (route->path.cost >= LS_INFINITY)
    {
      if (is_debug)
        zlog_debug ("The cost exceeds LSInfinity, withdraw");

      ospf6_abr_clear_summary (summary, summary_table, old);
      return;
    }

  /* if this is a route to ASBR */
  if (route->type == OSPF6_DEST_TYPE_ROUTER)
    {
      /* Only the prefered best path is considered */
      if (! CHECK_FLAG (route->flag, OSPF6_ROUTE_BEST))
        {
          if (is_debug)
            zlog_debug ("This is the secondary path to the ASBR, ignore");

          ospf6_abr_clear_summary (summary, summary_table, old);
          return;
        }

      /* Do not generate if the area is stub or nssa */
      if (IS_AREA_STUB_OR_NSSA (area))
        {
          if (is_debug)
            zlog_debug ("This is stub/nssa area, ignore");

          ospf6_abr_clear_summary (summary, summary_table, old);
          return;
        }
      struct ospf6_area *oa;
      oa = ospf6_area_lookup (route->path.area_id, ospf6);
      if (IS_AREA_NSSA (oa))
        {
          if (is_debug)
            zlog_debug ("This is nssa ASBR, ignore");

          ospf6_abr_clear_summary (summary, summary_table, old);
          return;
        }
    }

  /* if this is an intra-area route, this may be suppressed by aggregation */
  if (route->type == OSPF6_DEST_TYPE_NETWORK &&
      route->path.type == OSPF6_PATH_TYPE_INTRA)
    {
      /* search for configured address range for the route's area */
      route_area = ospf6_area_lookup (route->path.area_id, area->ospf6);
      assert (route_area);
      range = ospf6_route_lookup_bestmatch (&route->prefix,
                                            route_area->range_table);

      /* ranges are ignored when originate backbone routes to transit area.
         Otherwise, if ranges are configured, the route is suppressed. */
      if (range && ! CHECK_FLAG (range->flag, OSPF6_ROUTE_REMOVE) &&
          (route->path.area_id != BACKBONE_AREA_ID ||
           ! IS_AREA_TRANSIT (area)))
        {
          if (is_debug)
            {
              prefix2str (&range->prefix, buf, sizeof (buf));
              zlog_debug ("Suppressed by range %s of area %s",
                         buf, route_area->name);
            }

          ospf6_abr_clear_summary (summary, summary_table, old);
          return;
        }
    }

  /* If this is a configured address range */
  if (route->type == OSPF6_DEST_TYPE_RANGE)
    {
      /* If DoNotAdvertise is set */
      if (CHECK_FLAG (route->flag, OSPF6_ROUTE_DO_NOT_ADVERTISE))
        {
          if (is_debug)
            zlog_debug ("This is the range with DoNotAdvertise set. ignore");

          ospf6_abr_clear_summary (summary, summary_table, old);
          return;
        }

      /* Whether the route have active longer prefix */
      if (! CHECK_FLAG (route->flag, OSPF6_ROUTE_ACTIVE_RANGE))
        {
          if (is_debug)
            zlog_debug ("The range is not active. withdraw");

          ospf6_abr_clear_summary (summary, summary_table, old);
          return;
        }
    }
  /* if the area is totally stub and if its not default route, ignore*/
  if (IS_AREA_NO_SUMMARY (area)) 
    {
      if (!(route->type == OSPF6_DEST_TYPE_NETWORK && 
         default_summary_prefix_cmp (&route->prefix) == 0))
        {
          if (is_debug)
            zlog_debug ("This is stub or nssa area no summary, ignore");

          ospf6_abr_clear_summary (summary, summary_table, old);
          return;
        }
    }

  /* Inter-area prefix should not be advertised to backbone - section 12.4.3, 2328 */
  if (route->path.type == OSPF6_PATH_TYPE_INTER && 
      area->area_id == BACKBONE_AREA_ID)
    {
      if (is_debug)
        zlog_debug ("Inter-area prefix should not be adv to backbone, withdraw");

      ospf6_abr_clear_summary (summary, summary_table, old);
      return;
    }

  /* the route is going to be originated. store it in area's summary_table */
  if (summary == NULL)
    {
      summary = ospf6_route_copy (route);
      if (route->type == OSPF6_DEST_TYPE_NETWORK ||
          route->type == OSPF6_DEST_TYPE_RANGE)
        summary->path.origin.type = htons (OSPF6_LSTYPE_INTER_PREFIX);
      else
        summary->path.origin.type = htons (OSPF6_LSTYPE_INTER_ROUTER);
      summary->path.origin.adv_router = area->ospf6->router_id;
      summary->path.origin.id =
        ospf6_new_ls_id (summary->path.origin.type,
                         summary->path.origin.adv_router, area->lsdb);
      summary = ospf6_route_add (summary, summary_table);
    }
  else
    {
      summary->type = route->type;
      gettimeofday (&summary->changed, NULL);
    }

  summary->path.router_bits = route->path.router_bits;
  summary->path.options[0] = route->path.options[0];
  summary->path.options[1] = route->path.options[1];
  summary->path.options[2] = route->path.options[2];
  summary->path.prefix_options = route->path.prefix_options;
  summary->path.area_id = area->area_id;
  summary->path.type = OSPF6_PATH_TYPE_INTER;
  summary->path.cost = route->path.cost;
  summary->nexthop[0] = route->nexthop[0];

  /* prepare buffer */
  memset (buffer, 0, sizeof (buffer));
  lsa_header = (struct ospf6_lsa_header *) buffer;

  if (route->type == OSPF6_DEST_TYPE_ROUTER)
    {
      router_lsa = (struct ospf6_inter_router_lsa *)
        ((caddr_t) lsa_header + sizeof (struct ospf6_lsa_header));
      p = (caddr_t) router_lsa + sizeof (struct ospf6_inter_router_lsa);

      /* Fill Inter-Area-Router-LSA */
      router_lsa->options[0] = route->path.options[0];
      router_lsa->options[1] = route->path.options[1];
      router_lsa->options[2] = route->path.options[2];
      OSPF6_ABR_SUMMARY_METRIC_SET (router_lsa, route->path.cost);
      router_lsa->router_id = ADV_ROUTER_IN_PREFIX (&route->prefix);
      type = htons (OSPF6_LSTYPE_INTER_ROUTER);
    }
  else
    {
      prefix_lsa = (struct ospf6_inter_prefix_lsa *)
        ((caddr_t) lsa_header + sizeof (struct ospf6_lsa_header));
      p = (caddr_t) prefix_lsa + sizeof (struct ospf6_inter_prefix_lsa);

      /* Fill Inter-Area-Prefix-LSA */
      OSPF6_ABR_SUMMARY_METRIC_SET (prefix_lsa, route->path.cost);
      prefix_lsa->prefix.prefix_length = route->prefix.prefixlen;
      prefix_lsa->prefix.prefix_options = route->path.prefix_options;

      /* set Prefix */
      memcpy (p, &route->prefix.u.prefix6,
              OSPF6_PREFIX_SPACE (route->prefix.prefixlen));
      ospf6_prefix_apply_mask (&prefix_lsa->prefix);
      p += OSPF6_PREFIX_SPACE (route->prefix.prefixlen);
      type = htons (OSPF6_LSTYPE_INTER_PREFIX);
    }

  /* Fill LSA Header */
  lsa_header->age = 0;
  lsa_header->type = type;
  lsa_header->id = summary->path.origin.id;
  lsa_header->adv_router = area->ospf6->router_id;
  lsa_header->seqnum =
    ospf6_new_ls_seqnum (lsa_header->type, lsa_header->id,
                         lsa_header->adv_router, area->lsdb);
  lsa_header->length = htons ((caddr_t) p - (caddr_t) lsa_header);

  /* LSA checksum */
  ospf6_lsa_checksum (lsa_header);

  /* create LSA */
  lsa = ospf6_lsa_create (lsa_header);

  /* Originate */
  ospf6_lsa_originate_area (lsa, area);
}

void
ospf6_abr_originate_default_summary_to_area (struct ospf6_area *area)
{
  struct ospf6_route *route;

  route = ospf6_route_create ();

  route->type = OSPF6_DEST_TYPE_NETWORK;
  route->prefix.family = AF_INET6;
  route->prefix.prefixlen = 0;
  inet_pton (AF_INET6, IPV6_ADDR_ANY, &route->prefix.u.prefix6);
  route->path.cost = area->default_cost;
  route->nexthop[0].ifindex = IFINDEX_INTERNAL;

  ospf6_abr_originate_summary_to_area (route,area);

  ospf6_route_delete (route);
}

void
ospf6_abr_clear_default_summary_to_area (struct ospf6_area *area)
{
  struct prefix prefix;
  struct ospf6_route *summary;
  struct ospf6_lsa *old = NULL;

  prefix.family = AF_INET6;
  prefix.prefixlen = 0;
  inet_pton (AF_INET6, IPV6_ADDR_ANY, &prefix.u.prefix6);

  summary = ospf6_route_lookup (&prefix, area->summary_prefix);
  if (summary)
    old = ospf6_lsdb_lookup (summary->path.origin.type,
                             summary->path.origin.id,
                             area->ospf6->router_id, area->lsdb);

  ospf6_abr_clear_summary (summary, area->summary_prefix, old);
}

u_char
ospf6_abr_reachable_nssa_translators (struct ospf6_area *oa,
                                      u_char purpose)
{
  struct ospf6_route *ro, *as_asbr_ro;
  u_int32_t adv_router, best;
  struct prefix as_asbr_id;

  best = oa->ospf6->router_id;
  for (ro = ospf6_route_head (ospf6->brouter_table); ro;
       ro = ospf6_route_next (ro))
    {
      adv_router = ospf6_linkstate_prefix_adv_router (&ro->prefix);

      if (adv_router == oa->ospf6->router_id)
        continue;

      if (! CHECK_FLAG (ro->path.router_bits, OSPF6_ROUTER_BIT_B))
        continue;

      /* check border router reachable over nssa */
      if (ro->path.area_id != oa->area_id)
        continue;

      /* check border router reachable over AS's trasit topology */
      ospf6_linkstate_prefix (adv_router, 0, &as_asbr_id);
      for (as_asbr_ro = ospf6_route_match_head (&as_asbr_id,
           ospf6->brouter_table); as_asbr_ro;
           as_asbr_ro = ospf6_route_match_next (&as_asbr_id, as_asbr_ro))
        {
          struct ospf6_area *as_asbr_oa;
          as_asbr_oa = ospf6_area_lookup (as_asbr_ro->path.area_id, ospf6);

          if (! IS_AREA_STUB_OR_NSSA (as_asbr_oa) && 
              (CHECK_FLAG (as_asbr_ro->path.router_bits, OSPF6_ROUTER_BIT_E)))
            break;
        }

      if (as_asbr_ro == NULL)
        continue;

      ospf6_route_unlock (as_asbr_ro);

      if (purpose == NSSA_CANDIDATE_ELECTION)
        {
          if (CHECK_FLAG (ro->path.router_bits, OSPF6_ROUTER_BIT_NT))
            {
              ospf6_route_unlock (ro);
              return NSSA_TRANSLATOR_STATE_DISABLED;
            }
        }
      else /* NSSA_CHECK_TRANSLATORS */
        {
          if (! CHECK_FLAG (ro->path.router_bits, OSPF6_ROUTER_BIT_NT))
            continue;
        }

      if (ntohl (adv_router) > ntohl (best))
        best = adv_router;
    }

  if (best == oa->ospf6->router_id)
    return NSSA_TRANSLATOR_STATE_ENABLED;

  return NSSA_TRANSLATOR_STATE_DISABLED;
}

u_int8_t
ospf6_type5_capable_area_lookup (void)
{
  struct listnode *node;
  struct ospf6_area *oa;

  for (ALL_LIST_ELEMENTS_RO (ospf6->area_list, node, oa))
    {
      if (IS_AREA_STUB_OR_NSSA (oa))
        continue;
      /* found 1 external routing capable area */
      return 1;
    }
  return 0;
}

/* return 1 if the external route originated by this router is more
   preferred than the parameter route else return 0 */
u_int8_t
ospf6_abr_existing_local_type5_more_preferred (struct ospf6_route *route)
{
  struct ospf6_route *match;

  match = ospf6_route_lookup (&route->prefix, ospf6->external_table);

  if (! match) 
    return 0;

  if (! IN6_ARE_ADDR_EQUAL (&match->nexthop[0].address,
                            &route->nexthop[0].address))
   return 0; 

  if (ospf6_route_path_type_cost_cmp (match, route) < 0)
    return 1;

  return 0;
}

u_int8_t
ospf6_abr_already_translated_and_no_change (struct ospf6_route *route)
{
  struct ospf6_route *match;
  int changed = 0;
  struct ospf6_lsa *lsa;
  struct ospf6_area *oa;

  oa = ospf6_area_lookup (route->path.area_id, ospf6);
  match = ospf6_route_lookup (&route->prefix, oa->translated_rt_table);

  if (! match) 
    return 0;

  changed = ospf6_route_path_type_cost_cmp (match, route);
  if (!IN6_ARE_ADDR_EQUAL (&match->nexthop[0].address,
                           &route->nexthop[0].address))
    changed = 1;

  /* already translated route has not changed */
  if (! changed) 
    return 1;

  /* already translated route has changed, so purge the old one */
  lsa = ospf6_lsdb_lookup (match->path.origin.type, match->path.origin.id,
                           oa->ospf6->router_id, ospf6->lsdb);
  ospf6_route_remove (match, oa->translated_rt_table);
  if (lsa)
    ospf6_lsa_purge (lsa);

  return 0;
}

void
ospf6_abr_translate_type7_route_to_type5 (struct ospf6_route *route)
{
  struct ospf6_area *oa;
  struct ospf6_lsa *lsa;

  oa = ospf6_area_lookup (route->path.area_id, ospf6);

  if (oa->NSSATranslatorState != NSSA_TRANSLATOR_STATE_ENABLED)
    return;

  /* if no type5 capable area found, then dont translate */
  if (! ospf6_type5_capable_area_lookup ())
    return;

  /* check if there are any nssa translators which are reachable
  over nssa and as ASBRs over as-transit topology having
  higher router id */
  if (ospf6_abr_reachable_nssa_translators (oa,
      NSSA_CHECK_TRANSLATORS) == NSSA_TRANSLATOR_STATE_DISABLED)
    return;

  /* if this route is already translated and if the route
  information is not changed then dont translate it again.
  if this route is already translated and if the route
  information like path cost/type fwd addr has changed
  then purge the old translated entry and originate new one */
  if (ospf6_abr_already_translated_and_no_change (route))
    return;

  if (ospf6_abr_existing_local_type5_more_preferred (route))
    return;

  route->path.origin.id = ospf6->external_id++; 
  route->path.origin.type = htons (OSPF6_LSTYPE_AS_EXTERNAL);
  route->path.origin.adv_router = ospf6->router_id;
  ospf6_route_add (ospf6_route_copy (route), oa->translated_rt_table);
  lsa = ospf6_external_lsa_create (route);
  SET_FLAG (lsa->flag, OSPF6_LSA_TRANSLATED);
  ospf6_lsa_originate_process (lsa, ospf6);
}

void
ospf6_abr_flush_translated_type7_by_prefix (struct ospf6_area *oa,
                                            struct prefix *t7_prefix)
{
  struct ospf6_route *ro;
  struct ospf6_lsa *lsa;

  ro = ospf6_route_lookup (t7_prefix, oa->translated_rt_table);

  if (! ro) 
    return;

  lsa = ospf6_lsdb_lookup (ro->path.origin.type, ro->path.origin.id,
                           oa->ospf6->router_id, ospf6->lsdb);
  ospf6_route_remove (ro, oa->translated_rt_table);
  if (lsa)
    ospf6_lsa_purge (lsa);
}

/* when type 7 is deleted, delete type 5 */
void
ospf6_abr_flush_translated_type7_by_lsa (struct ospf6_lsa *lsa)
{
  struct prefix t7_prefix;
  struct ospf6_as_external_lsa *external;
  struct ospf6_area *oa;

  if (lsa->header->adv_router == ospf6->router_id)
    return;

  external = (struct ospf6_as_external_lsa *)
    OSPF6_LSA_HEADER_END (lsa->header);

  t7_prefix.family = AF_INET6;
  t7_prefix.prefixlen = external->prefix.prefix_length;
  ospf6_prefix_in6_addr (&t7_prefix.u.prefix6, &external->prefix);

  oa = OSPF6_AREA (lsa->lsdb->data);
  ospf6_abr_flush_translated_type7_by_prefix (oa, &t7_prefix);
}

/* when type 7 is added, generate type 5 if atleast
   one ext routing capable area found */
void
ospf6_abr_translate_type7_lsa_to_type5 (struct ospf6_lsa *lsa)
{
  struct ospf6_area *oa;
  struct ospf6_as_external_lsa *external;
  struct ospf6_route *range = NULL;
  struct ospf6_route *route;

  if (lsa->header->adv_router == ospf6->router_id)
    return;

  external = (struct ospf6_as_external_lsa *)
    OSPF6_LSA_HEADER_END (lsa->header);

  if (! CHECK_FLAG (external->prefix.prefix_options, OSPF6_PREFIX_OPTION_P))
    {
      /* if this non translatable lsa has been translated
         earlier then flush it */
      ospf6_abr_flush_translated_type7_by_lsa (lsa);
      return;
    }

  route = ospf6_route_create ();

  ospf6_asbr_route_from_external_lsa (lsa, route);

  oa = OSPF6_AREA (lsa->lsdb->data);

  range = ospf6_route_lookup_bestmatch (&route->prefix, oa->range_table);
  if (! range)
    {
      route->path.area_id = oa->area_id;
      UNSET_FLAG (route->path.prefix_options, OSPF6_PREFIX_OPTION_P);
      ospf6_abr_translate_type7_route_to_type5 (route);
    }
  ospf6_route_delete (route);
}

void
ospf6_abr_nssa_translator_state_enable (struct ospf6_area *oa)
{ 
  struct ospf6_lsa *lsa;
  struct ospf6_route *ro;

  oa->NSSATranslatorState = NSSA_TRANSLATOR_STATE_ENABLED;
  /* update Nt bit for the area */
  OSPF6_ROUTER_LSA_SCHEDULE (oa);

  for (ro = ospf6_route_head (oa->range_table); ro;
       ro = ospf6_route_next (ro))
    {
      if (CHECK_FLAG (ro->flag, OSPF6_ROUTE_ACTIVE_RANGE) &&
          (ro->path.type == OSPF6_PATH_TYPE_EXTERNAL1 ||
          ro->path.type == OSPF6_PATH_TYPE_EXTERNAL2))
        ospf6_abr_translate_type7_route_to_type5 (ro);
    }

  /* for each type7 lsa in area translate to type5 */
  for (lsa = ospf6_lsdb_type_head (htons (OSPF6_LSTYPE_TYPE_7),
       oa->lsdb); lsa;
       lsa = ospf6_lsdb_type_next (htons (OSPF6_LSTYPE_TYPE_7), lsa))
    {
      if (! OSPF6_LSA_IS_MAXAGE (lsa))
        ospf6_abr_translate_type7_lsa_to_type5 (lsa);
    }
}

void
ospf6_abr_withdraw_translated_lsa (struct ospf6_area *oa)
{
  struct ospf6_lsa *lsa;

  for (lsa = ospf6_lsdb_type_head (htons (OSPF6_LSTYPE_TYPE_7),
       oa->lsdb); lsa;
       lsa = ospf6_lsdb_type_next (htons (OSPF6_LSTYPE_TYPE_7), lsa))
    ospf6_abr_flush_translated_type7_by_lsa (lsa);
}

void
ospf6_abr_withdraw_translated_range (struct ospf6_area *oa)
{
  struct ospf6_route *ro;

  for (ro = ospf6_route_head (oa->range_table); ro;
       ro = ospf6_route_next (ro))
    {
      if (CHECK_FLAG (ro->flag, OSPF6_ROUTE_ACTIVE_RANGE) &&
          (ro->path.type == OSPF6_PATH_TYPE_EXTERNAL1 ||
          ro->path.type == OSPF6_PATH_TYPE_EXTERNAL2))
        ospf6_abr_flush_translated_type7_by_prefix (oa, &ro->prefix);
    }
}

/* disable the nssa translator when the stability interval expires */ 
int
ospf6_abr_nssa_translator_state_disable (struct thread *thread)
{
  struct ospf6_area *oa;

  oa = (struct ospf6_area *) THREAD_ARG (thread);
  assert (oa);

  oa->NSSATranslatorState = NSSA_TRANSLATOR_STATE_DISABLED;

  /*  update Nt bit for the area */
  OSPF6_ROUTER_LSA_SCHEDULE (oa);

  /* flush type 5 aggregates of type 7 */
  ospf6_abr_withdraw_translated_range (oa);

  oa->thread_nssa_trans_state_disable = NULL;

  return 0;
}

/* disable the nssa translator immediately without waiting for
   stability interval */
void
ospf6_abr_nssa_translator_state_disable_now (struct ospf6_area *oa)
{
  THREAD_OFF (oa->thread_nssa_trans_state_disable);
  thread_execute (master, ospf6_abr_nssa_translator_state_disable,
                  oa, 0);

  ospf6_abr_withdraw_translated_lsa (oa);
  ospf6_route_remove_all (oa->translated_rt_table);
}

void
ospf6_abr_nssa_translator_state_update (struct ospf6_area *oa)
{
  u_char new_state;

  if (! IS_AREA_NSSA (oa))
    return;

  new_state = NSSA_TRANSLATOR_STATE_DISABLED;

  if (ospf6_is_router_abr (ospf6))
  {
    switch (oa->NSSATranslatorRole)
      {
        case NSSA_TRANSLATOR_ROLE_ALWAYS:
          new_state = NSSA_TRANSLATOR_STATE_ENABLED;
          break;
        case NSSA_TRANSLATOR_ROLE_CANDIDATE:
          new_state = ospf6_abr_reachable_nssa_translators (oa,
                        NSSA_CANDIDATE_ELECTION);
          break;
      }
  }

  if (new_state == NSSA_TRANSLATOR_STATE_ENABLED)
    THREAD_OFF (oa->thread_nssa_trans_state_disable);

  if (oa->NSSATranslatorState == new_state)
    return;

  switch (new_state)
    {
      case NSSA_TRANSLATOR_STATE_ENABLED:
        ospf6_abr_nssa_translator_state_enable (oa);
        break;

      case NSSA_TRANSLATOR_STATE_DISABLED:
	if (oa->thread_nssa_trans_state_disable == NULL)
          oa->thread_nssa_trans_state_disable = thread_add_timer (master,
            ospf6_abr_nssa_translator_state_disable, oa,
            oa->NSSATranslatorStabilityInterval);
        break;
    }
}


void
ospf6_abr_range_type7_aggregate_update (struct ospf6_route *range)
{
  u_int32_t cost1 = 0;
  u_int32_t cost2 = 0;
  u_int32_t cost = 0;
  u_char type = OSPF6_PATH_TYPE_NONE;
  struct ospf6_route *ro;
  struct ospf6_lsa *lsa;
  struct ospf6_as_external_lsa *external;
  struct prefix prefix;

  if (CHECK_FLAG (range->flag, OSPF6_ROUTE_DO_NOT_ADVERTISE))
    return;

  /* update range's cost and active flag */
  for (ro = ospf6_route_match_head (&range->prefix, ospf6->route_table);
       ro; ro = ospf6_route_match_next (&range->prefix, ro))
    {
      if (CHECK_FLAG (ro->flag, OSPF6_ROUTE_REMOVE))
        continue;

      if (ro->path.origin.type != htons (OSPF6_LSTYPE_TYPE_7))
        continue;

      if (ro->path.area_id != range->path.area_id)
        continue;

      if (! CHECK_FLAG (ro->path.prefix_options, OSPF6_PREFIX_OPTION_P))
        continue;

      if (IN6_IS_ADDR_UNSPECIFIED (&ro->nexthop[0].address))
        continue;

      type = type | ro->path.type;
      if (ro->path.type == OSPF6_PATH_TYPE_EXTERNAL1) 
        cost1 = MAX (cost1, ro->path.cost);
      else
        cost2 = MAX (cost2, ro->path.cost_e2);
    }

  /* check locally sourced type5 lsas */
  for (lsa = ospf6_lsdb_type_router_head (htons (OSPF6_LSTYPE_AS_EXTERNAL),
       ospf6->router_id, ospf6->lsdb); lsa; lsa = ospf6_lsdb_type_router_next
       (htons (OSPF6_LSTYPE_AS_EXTERNAL), ospf6->router_id, lsa))
    {

      external = (struct ospf6_as_external_lsa *)
        OSPF6_LSA_HEADER_END (lsa->header);

      prefix.family = AF_INET6;
      prefix.prefixlen = external->prefix.prefix_length;
      ospf6_prefix_in6_addr (&prefix.u.prefix6, &external->prefix);

      if (CHECK_FLAG (lsa->flag, OSPF6_LSA_TRANSLATED))
        continue;

      if (! prefix_match (&range->prefix, &prefix))
        continue;

      if (CHECK_FLAG (external->bits_metric, OSPF6_ASBR_BIT_E))
        {
          cost2 = MAX (cost2, OSPF6_ASBR_METRIC (external));
          type = type | OSPF6_PATH_TYPE_EXTERNAL2;
        }
      else
        {
          cost1 = MAX (cost1, OSPF6_ASBR_METRIC (external));
          type = type | OSPF6_PATH_TYPE_EXTERNAL1;
        }
    }

  if (type != OSPF6_PATH_TYPE_NONE)
    {
      if (type == OSPF6_PATH_TYPE_EXTERNAL1)
        cost = cost1;
      else
        {
          type = OSPF6_PATH_TYPE_EXTERNAL2;
          cost = cost2 + 1;
        }
    }

  if (range->path.type != type ||
      (range->path.type == OSPF6_PATH_TYPE_EXTERNAL1 &&
      range->path.cost != cost)||
      (range->path.type == OSPF6_PATH_TYPE_EXTERNAL2 &&
      range->path.cost_e2 != cost))
    {
      range->path.type = type;
      range->path.cost = 0;
      range->path.cost_e2 = 0;
      if (range->path.type == OSPF6_PATH_TYPE_EXTERNAL2)
        {
          range->path.metric_type = EXTERNAL_METRIC_TYPE_2;
          range->path.cost_e2 = cost;
          range->path.cost = cost;
        }
      else if (range->path.type == OSPF6_PATH_TYPE_EXTERNAL1)
        {
          range->path.metric_type = EXTERNAL_METRIC_TYPE_1;
          range->path.cost = cost;
        }

      if ((range->path.type != OSPF6_PATH_TYPE_NONE && cost))
        {
          SET_FLAG (range->flag, OSPF6_ROUTE_ACTIVE_RANGE);
          ospf6_abr_translate_type7_route_to_type5 (range);
        }
      else
        {
          UNSET_FLAG (range->flag, OSPF6_ROUTE_ACTIVE_RANGE);
          struct ospf6_area *oa;
          oa = ospf6_area_lookup (range->path.area_id, ospf6);
          ospf6_abr_flush_translated_type7_by_prefix (oa, &range->prefix);
        }
    }
}

u_int8_t
ospf6_abr_range_update (struct ospf6_route *range, struct ospf6_route *route)
{
  struct ospf6_area *oa;

  u_int32_t cost = 0;
  struct ospf6_route *ro;

  assert (range->type == OSPF6_DEST_TYPE_RANGE);

  if (route->path.origin.type == htons (OSPF6_LSTYPE_TYPE_7))
  {
    ospf6_abr_range_type7_aggregate_update (range);
    return 0;
  }

  /* update range's cost and active flag */
  for (ro = ospf6_route_match_head (&range->prefix, ospf6->route_table);
       ro; ro = ospf6_route_match_next (&range->prefix, ro))
    {
      if (ro->path.type == OSPF6_PATH_TYPE_EXTERNAL1 ||
          ro->path.type == OSPF6_PATH_TYPE_EXTERNAL2)
        continue;
      if (ro->path.area_id == range->path.area_id &&
          ! CHECK_FLAG (ro->flag, OSPF6_ROUTE_REMOVE))
        cost = MAX (cost, ro->path.cost);
    }

  if (range->path.cost != cost)
    {
      range->path.cost = cost;

      if (range->path.cost)
        {
          SET_FLAG (range->flag, OSPF6_ROUTE_ACTIVE_RANGE);
          oa = ospf6_area_lookup (route->path.area_id, ospf6);

          if (!ospf6_abr_plist_out_check (oa, &route->prefix))
            {
              if (IS_OSPF6_DEBUG_EXAMIN (INTER_PREFIX))
                zlog_debug ("ospf6_abr_range_update(): range denied by out filter-list");
              return 0;
            }
        }
      else
        UNSET_FLAG (range->flag, OSPF6_ROUTE_ACTIVE_RANGE);
      return 1; 
    }

  return 0;
}

void
ospf6_abr_originate_summary (struct ospf6_route *route)
{
  struct listnode *node, *nnode;
  struct ospf6_area *oa;
  struct ospf6_route *range = NULL;
  struct ospf6_route *summary = route;

  if (route->type == OSPF6_DEST_TYPE_NETWORK)
    {
      oa = ospf6_area_lookup (route->path.area_id, ospf6);
      range = ospf6_route_lookup_bestmatch (&route->prefix, oa->range_table);
      if (range)
        {
          if(ospf6_abr_range_update (range, route))
            summary = range;
          else
            return;
        }
    }

  for (ALL_LIST_ELEMENTS (ospf6->area_list, node, nnode, oa))
    ospf6_abr_originate_summary_to_area (summary, oa);
}

/* RFC 2328 16.2. Calculating the inter-area routes */
void
ospf6_abr_examin_summary (struct ospf6_lsa *lsa, struct ospf6_area *oa)
{
  struct prefix prefix, abr_prefix;
  struct ospf6_route_table *table = NULL;
  struct ospf6_route *range, *route, *old = NULL;
  struct ospf6_route *abr_entry;
  u_char type = 0;
  char options[3] = {0, 0, 0};
  u_int8_t prefix_options = 0;
  u_int32_t cost = 0;
  u_char router_bits = 0;
  int i;
  char buf[64];
  int is_debug = 0;

  if (lsa->header->type == htons (OSPF6_LSTYPE_INTER_PREFIX))
    {
      struct ospf6_inter_prefix_lsa *prefix_lsa;

      if (IS_OSPF6_DEBUG_EXAMIN (INTER_PREFIX))
        {
          is_debug++;
          zlog_debug ("Examin %s in area %s", lsa->name, oa->name);
        }

      prefix_lsa = (struct ospf6_inter_prefix_lsa *)
        OSPF6_LSA_HEADER_END (lsa->header);
      prefix.family = AF_INET6;
      prefix.prefixlen = prefix_lsa->prefix.prefix_length;
      ospf6_prefix_in6_addr (&prefix.u.prefix6, &prefix_lsa->prefix);
      prefix2str (&prefix, buf, sizeof (buf));
      table = oa->ospf6->route_table;
      type = OSPF6_DEST_TYPE_NETWORK;
      prefix_options = prefix_lsa->prefix.prefix_options;
      cost = OSPF6_ABR_SUMMARY_METRIC (prefix_lsa);
    }
  else if (lsa->header->type == htons (OSPF6_LSTYPE_INTER_ROUTER))
    {
      struct ospf6_inter_router_lsa *router_lsa;

      if (IS_OSPF6_DEBUG_EXAMIN (INTER_ROUTER))
        {
          is_debug++;
          zlog_debug ("Examin %s in area %s", lsa->name, oa->name);
        }

      router_lsa = (struct ospf6_inter_router_lsa *)
        OSPF6_LSA_HEADER_END (lsa->header);
      ospf6_linkstate_prefix (router_lsa->router_id, htonl (0), &prefix);
      inet_ntop (AF_INET, &router_lsa->router_id, buf, sizeof (buf));
      table = oa->ospf6->brouter_table;
      type = OSPF6_DEST_TYPE_ROUTER;
      options[0] = router_lsa->options[0];
      options[1] = router_lsa->options[1];
      options[2] = router_lsa->options[2];
      cost = OSPF6_ABR_SUMMARY_METRIC (router_lsa);
      SET_FLAG (router_bits, OSPF6_ROUTER_BIT_E);
    }
  else
    assert (0);

  /* Find existing route */
  route = ospf6_route_lookup (&prefix, table);
  if (route)
    ospf6_route_lock (route);
  while (route && ospf6_route_is_prefix (&prefix, route))
    {
      if (route->path.area_id == oa->area_id &&
          route->path.origin.type == lsa->header->type &&
          route->path.origin.id == lsa->header->id &&
          route->path.origin.adv_router == lsa->header->adv_router)
        old = route;
      route = ospf6_route_next (route);
    }
    if (route)
      ospf6_route_unlock (route);

  /* (1) if cost == LSInfinity or if the LSA is MaxAge */
  if (cost == LS_INFINITY)
    {
      if (is_debug)
        zlog_debug ("cost is LS_INFINITY, ignore");
      if (old)
        ospf6_route_remove (old, table);
      return;
    }
  if (OSPF6_LSA_IS_MAXAGE (lsa))
    {
      if (is_debug)
        zlog_debug ("LSA is MaxAge, ignore");
      if (old)
        ospf6_route_remove (old, table);
      return;
    }

  /* (2) if the LSA is self-originated, ignore */
  if (lsa->header->adv_router == oa->ospf6->router_id)
    {
      if (is_debug)
        zlog_debug ("LSA is self-originated, ignore");
      if (old)
        ospf6_route_remove (old, table);
      return;
    }

  /* (3) if the prefix is equal to an active configured address range */
  if (lsa->header->type == htons (OSPF6_LSTYPE_INTER_PREFIX))
    {
      range = ospf6_route_lookup (&prefix, oa->range_table);
      if (range)
        {
          if (is_debug)
            zlog_debug ("Prefix is equal to address range, ignore");
          if (old)
            ospf6_route_remove (old, table);
          return;
        }
    }
  /* ignore summary default from a stub area */
  if (ospf6_is_router_abr (oa->ospf6) && 
      IS_AREA_STUB_OR_NSSA (oa) && 
      default_summary_prefix_cmp (&prefix) == 0)
    {
      if (old)
        ospf6_route_remove (old, table);
      return;
    }

  /* (4) if the routing table entry for the ABR does not exist */
  ospf6_linkstate_prefix (lsa->header->adv_router, htonl (0), &abr_prefix);
  abr_entry = ospf6_route_lookup (&abr_prefix, oa->ospf6->brouter_table);
  if (abr_entry == NULL || abr_entry->path.area_id != oa->area_id ||
      CHECK_FLAG (abr_entry->flag, OSPF6_ROUTE_REMOVE) ||
      ! CHECK_FLAG (abr_entry->path.router_bits, OSPF6_ROUTER_BIT_B))
    {
      if (is_debug)
        zlog_debug ("ABR router entry does not exist, ignore");
      if (old)
        ospf6_route_remove (old, table);
      return;
    }

  /* (5),(6),(7) the path preference is handled by the sorting
     in the routing table. Always install the path by substituting
     old route (if any). */
  if (old)
    route = ospf6_route_copy (old);
  else
    route = ospf6_route_create ();

  route->type = type;
  route->prefix = prefix;
  route->path.origin.type = lsa->header->type;
  route->path.origin.id = lsa->header->id;
  route->path.origin.adv_router = lsa->header->adv_router;
  route->path.router_bits = router_bits;
  route->path.options[0] = options[0];
  route->path.options[1] = options[1];
  route->path.options[2] = options[2];
  route->path.prefix_options = prefix_options;
  route->path.area_id = oa->area_id;
  route->path.type = OSPF6_PATH_TYPE_INTER;
  route->path.cost = abr_entry->path.cost + cost;
  for (i = 0; i < OSPF6_MULTI_PATH_LIMIT; i++)
    route->nexthop[i] = abr_entry->nexthop[i];

  if (is_debug)
    zlog_debug ("Install route: %s", buf);
  ospf6_route_add (route, table);
}

void
ospf6_abr_examin_brouter (u_int32_t router_id)
{
  struct ospf6_lsa *lsa;
  struct ospf6_area *oa;
  struct listnode *node, *nnode;
  u_int16_t type;

  for (ALL_LIST_ELEMENTS (ospf6->area_list, node, nnode, oa))
    {
      type = htons (OSPF6_LSTYPE_INTER_ROUTER);
      for (lsa = ospf6_lsdb_type_router_head (type, router_id, oa->lsdb); lsa;
           lsa = ospf6_lsdb_type_router_next (type, router_id, lsa))
        ospf6_abr_examin_summary (lsa, oa);

      type = htons (OSPF6_LSTYPE_INTER_PREFIX);
      for (lsa = ospf6_lsdb_type_router_head (type, router_id, oa->lsdb); lsa;
           lsa = ospf6_lsdb_type_router_next (type, router_id, lsa))
        ospf6_abr_examin_summary (lsa, oa);
    }
}


/* Display functions */
int
ospf6_inter_area_prefix_lsa_show (struct vty *vty, struct ospf6_lsa *lsa)
{
  struct ospf6_inter_prefix_lsa *prefix_lsa;
  struct in6_addr in6;
  char buf[64];

  prefix_lsa = (struct ospf6_inter_prefix_lsa *)
    OSPF6_LSA_HEADER_END (lsa->header);

  vty_out (vty, "     Metric: %lu%s",
           (u_long) OSPF6_ABR_SUMMARY_METRIC (prefix_lsa), VNL);

  ospf6_prefix_options_printbuf (prefix_lsa->prefix.prefix_options,
                                 buf, sizeof (buf));
  vty_out (vty, "     Prefix Options: %s%s", buf, VNL);

  ospf6_prefix_in6_addr (&in6, &prefix_lsa->prefix);
  inet_ntop (AF_INET6, &in6, buf, sizeof (buf));
  vty_out (vty, "     Prefix: %s/%d%s", buf,
           prefix_lsa->prefix.prefix_length, VNL);

  return 0;
}

int
ospf6_inter_area_router_lsa_show (struct vty *vty, struct ospf6_lsa *lsa)
{
  struct ospf6_inter_router_lsa *router_lsa;
  char buf[64];

  router_lsa = (struct ospf6_inter_router_lsa *)
    OSPF6_LSA_HEADER_END (lsa->header);

  ospf6_options_printbuf (router_lsa->options, buf, sizeof (buf));
  vty_out (vty, "     Options: %s%s", buf, VNL);
  vty_out (vty, "     Metric: %lu%s",
           (u_long) OSPF6_ABR_SUMMARY_METRIC (router_lsa), VNL);
  inet_ntop (AF_INET, &router_lsa->router_id, buf, sizeof (buf));
  vty_out (vty, "     Destination Router ID: %s%s", buf, VNL);

  return 0;
}

/* Debug commands */
DEFUN (debug_ospf6_abr,
       debug_ospf6_abr_cmd,
       "debug ospf6 abr",
       DEBUG_STR
       OSPF6_STR
       "Debug OSPFv3 ABR function\n"
      )
{
  OSPF6_DEBUG_ABR_ON ();
  return CMD_SUCCESS;
}

DEFUN (no_debug_ospf6_abr,
       no_debug_ospf6_abr_cmd,
       "no debug ospf6 abr",
       NO_STR
       DEBUG_STR
       OSPF6_STR
       "Debug OSPFv3 ABR function\n"
      )
{
  OSPF6_DEBUG_ABR_OFF ();
  return CMD_SUCCESS;
}

int
config_write_ospf6_debug_abr (struct vty *vty)
{
  if (IS_OSPF6_DEBUG_ABR)
    vty_out (vty, "debug ospf6 abr%s", VNL);
  return 0;
}

void
install_element_ospf6_debug_abr ()
{
  install_element (ENABLE_NODE, &debug_ospf6_abr_cmd);
  install_element (ENABLE_NODE, &no_debug_ospf6_abr_cmd);
  install_element (CONFIG_NODE, &debug_ospf6_abr_cmd);
  install_element (CONFIG_NODE, &no_debug_ospf6_abr_cmd);
}

struct ospf6_lsa_handler inter_prefix_handler =
{
  OSPF6_LSTYPE_INTER_PREFIX,
  "Inter-Prefix",
  ospf6_inter_area_prefix_lsa_show
};

struct ospf6_lsa_handler inter_router_handler =
{
  OSPF6_LSTYPE_INTER_ROUTER,
  "Inter-Router",
  ospf6_inter_area_router_lsa_show
};

void
ospf6_abr_init ()
{
  ospf6_install_lsa_handler (&inter_prefix_handler);
  ospf6_install_lsa_handler (&inter_router_handler);
}


