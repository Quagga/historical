/*
 * IS-IS Rout(e)ing protocol               - isis_route.c
 * Copyright (C) 2001,2002   Sampo Saaristo
 *                           Tampere University of Technology      
 *                           Institute of Communications Engineering
 *
 *                                         based on ../ospf6d/ospf6_route.[ch]
 *                                         by Yasuhiro Ohara
 *
 * This program is free software; you can redistribute it and/or modify it 
 * under the terms of the GNU General Public Licenseas published by the Free 
 * Software Foundation; either version 2 of the License, or (at your option) 
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,but WITHOUT 
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or 
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for 
 * more details.

 * You should have received a copy of the GNU General Public License along 
 * with this program; if not, write to the Free Software Foundation, Inc., 
 * 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

/*
 * Copyright (C) 2006 6WIND
 */

#include <stdlib.h>
#include <stdio.h>
#include <zebra.h>

#include "thread.h"
#include "linklist.h"
#include "vty.h"
#include "log.h"
#include "memory.h"
#include "prefix.h"
#include "hash.h"
#include "if.h"
#include "table.h"

#include "isis_constants.h"
#include "isis_common.h"
#include "dict.h"
#include "isisd.h"
#include "isis_misc.h"
#include "isis_adjacency.h"
#include "isis_circuit.h"
#include "isis_tlv.h"
#include "isis_pdu.h"
#include "isis_lsp.h"
#include "isis_spf.h"
#include "isis_route.h"
#include "isis_zebra.h"

extern struct isis *isis;
extern struct thread_master *master;

static struct isis_nexthop *
isis_nexthop_create (struct in_addr *ip, unsigned int ifindex)
{
  struct listnode *node;
  struct isis_nexthop *nexthop;

  for (ALL_LIST_ELEMENTS_RO (isis->nexthops, node, nexthop))
    {
      if (nexthop->ifindex != ifindex)
	continue;
      if (ip && memcmp (&nexthop->ip, ip, sizeof (struct in_addr)) != 0)
	continue;

      nexthop->lock++;
      return nexthop;
    }

  nexthop = XMALLOC (MTYPE_ISIS_NEXTHOP, sizeof (struct isis_nexthop));
  if (!nexthop)
    {
      zlog_err ("ISIS-Rte: isis_nexthop_create: out of memory!");
    }

  memset (nexthop, 0, sizeof (struct isis_nexthop));
  nexthop->ifindex = ifindex;
  memcpy (&nexthop->ip, ip, sizeof (struct in_addr));
  listnode_add (isis->nexthops, nexthop);
  nexthop->lock++;

  return nexthop;
}

static void
isis_nexthop_delete (struct isis_nexthop *nexthop)
{
  nexthop->lock--;
  if (nexthop->lock == 0)
    {
      listnode_delete (isis->nexthops, nexthop);
      XFREE (MTYPE_ISIS_NEXTHOP, nexthop);
    }

  return;
}

static int
nexthoplookup (struct list *nexthops, struct in_addr *ip,
	       unsigned int ifindex)
{
  struct listnode *node;
  struct isis_nexthop *nh;

  for (ALL_LIST_ELEMENTS_RO (nexthops, node, nh))
    {
      if (!(memcmp (ip, &nh->ip, sizeof (struct in_addr))) &&
	  ifindex == nh->ifindex)
	return 1;
    }

  return 0;
}

static void
nexthop_print (struct isis_nexthop *nh)
{
  u_char buf[BUFSIZ];

  inet_ntop (AF_INET, &nh->ip, (char *) buf, BUFSIZ);

  zlog_debug ("\nwith adjuncencies:  %s %u", buf, nh->ifindex);
}

#if 0
static void
nexthops_print (struct list *nhs)
{
  struct listnode *node;
  struct isis_nexthop *nh;

  for (ALL_LIST_ELEMENTS_RO (nhs, node, nh))
    nexthop_print (nh);
}
#endif

#ifdef HAVE_IPV6
static struct isis_nexthop6 *
isis_nexthop6_new (struct in6_addr *ip6, unsigned int ifindex)
{

  struct isis_nexthop6 *nexthop6;

  nexthop6 = XMALLOC (MTYPE_ISIS_NEXTHOP6, sizeof (struct isis_nexthop6));
  if (!nexthop6)
    {
      zlog_err ("ISIS-Rte: isis_nexthop_create6: out of memory!");
    }

  memset (nexthop6, 0, sizeof (struct isis_nexthop6));
  nexthop6->ifindex = ifindex;
  memcpy (&nexthop6->ip6, ip6, sizeof (struct in6_addr));
  nexthop6->lock++;

  return nexthop6;
}

static struct isis_nexthop6 *
isis_nexthop6_create (struct in6_addr *ip6, unsigned int ifindex)
{
  struct listnode *node;
  struct isis_nexthop6 *nexthop6;

  for (ALL_LIST_ELEMENTS_RO (isis->nexthops6, node, nexthop6))
    {
      if (nexthop6->ifindex != ifindex)
	continue;
      if (ip6 && memcmp (&nexthop6->ip6, ip6, sizeof (struct in6_addr)) != 0)
	continue;

      nexthop6->lock++;
      return nexthop6;
    }

  nexthop6 = isis_nexthop6_new (ip6, ifindex);

  return nexthop6;
}

static void
isis_nexthop6_delete (struct isis_nexthop6 *nexthop6)
{

  nexthop6->lock--;
  if (nexthop6->lock == 0)
    {
      listnode_delete (isis->nexthops6, nexthop6);
      XFREE (MTYPE_ISIS_NEXTHOP6, nexthop6);
    }

  return;
}

static int
nexthop6lookup (struct list *nexthops6, struct in6_addr *ip6,
		unsigned int ifindex)
{
  struct listnode *node;
  struct isis_nexthop6 *nh6;

  for (ALL_LIST_ELEMENTS_RO (nexthops6, node, nh6))
    {
      if (!(memcmp (ip6, &nh6->ip6, sizeof (struct in6_addr))) &&
	  ifindex == nh6->ifindex)
	return 1;
    }

  return 0;
}

#ifdef EXTREME_DEBUG
#if 0
static void
nexthop6_print (struct isis_nexthop6 *nh6)
{
  u_char buf[BUFSIZ];

  inet_ntop (AF_INET6, &nh6->ip6, (char *) buf, BUFSIZ);

  zlog_debug ("      %s %u", buf, nh6->ifindex);
}
#endif

#if 0
static void
nexthops6_print (struct list *nhs6)
{
  struct listnode *node;
  struct isis_nexthop6 *nh6;

  for (ALL_LIST_ELEMENTS_RO (nhs6, node, nh6))
    nexthop6_print (nh6);
}
#endif
#endif /* EXTREME_DEBUG */
#endif /* HAVE_IPV6 */

static void
adjinfo2nexthop (struct list *nexthops, struct isis_adjacency *adj)
{
  struct isis_nexthop *nh;
  struct listnode *node, *nnode;
  struct in_addr *ipv4_addr;

  if (adj->ipv4_addrs == NULL)
    return;


  for (ALL_LIST_ELEMENTS (adj->ipv4_addrs, node, nnode, ipv4_addr))
    {
      if (!nexthoplookup (nexthops, ipv4_addr,
			  adj->circuit->interface->ifindex))
	{
	  nh = isis_nexthop_create (ipv4_addr,
				    adj->circuit->interface->ifindex);
          nexthop_print( nh );
	  listnode_add (nexthops, nh);
	}
    }
}

#ifdef HAVE_IPV6
static void
adjinfo2nexthop6 (struct list *nexthops6, struct isis_adjacency *adj)
{
  struct listnode *node, *nnode;
  struct in6_addr *ipv6_addr;
  struct isis_nexthop6 *nh6;

  if (!adj->ipv6_addrs)
    return;

  for (ALL_LIST_ELEMENTS (adj->ipv6_addrs, node, nnode, ipv6_addr))
    {
      if (!nexthop6lookup (nexthops6, ipv6_addr,
			   adj->circuit->interface->ifindex))
	{
	  nh6 = isis_nexthop6_create (ipv6_addr,
				      adj->circuit->interface->ifindex);
	  listnode_add (nexthops6, nh6);
	}
    }
}
#endif /* HAVE_IPV6 */

static struct isis_route_info *
isis_route_info_new (uint32_t cost, uint32_t depth, u_char family,
		     struct list *adjacencies,int level)
{
  struct isis_route_info *rinfo;
  struct isis_adjacency *adj;
  struct listnode *node, *nnode;

  rinfo = XMALLOC (MTYPE_ISIS_ROUTE_INFO, sizeof (struct isis_route_info));
  if (!rinfo)
    {
      zlog_err ("ISIS-Rte: isis_route_info_new: out of memory!");
      return NULL;
    }
  memset (rinfo, 0, sizeof (struct isis_route_info));

  if (family == AF_INET)
    {
      rinfo->nexthops = list_new ();
      for (ALL_LIST_ELEMENTS (adjacencies, node, nnode, adj))
        adjinfo2nexthop (rinfo->nexthops, adj);
    }
#ifdef HAVE_IPV6
  if (family == AF_INET6)
    {
      rinfo->nexthops6 = list_new ();
      for (ALL_LIST_ELEMENTS (adjacencies, node, nnode, adj))
        adjinfo2nexthop6 (rinfo->nexthops6, adj);
    }

#endif /* HAVE_IPV6 */

  rinfo->cost = cost;
  rinfo->depth = depth;
  rinfo->route_type=level;

  return rinfo;
}

static void
isis_route_info_delete (struct isis_route_info *route_info)
{
  if (route_info->nexthops)
    {
      route_info->nexthops->del = (void (*)(void *)) isis_nexthop_delete;
      list_delete (route_info->nexthops);
    }

#ifdef HAVE_IPV6
  if (route_info->nexthops6)
    {
      route_info->nexthops6->del = (void (*)(void *)) isis_nexthop6_delete;
      list_delete (route_info->nexthops6);
    }
#endif /* HAVE_IPV6 */

  XFREE (MTYPE_ISIS_ROUTE_INFO, route_info);
}

static int
isis_route_info_same_attrib (struct isis_route_info *new,
			     struct isis_route_info *old)
{
  if (new->cost != old->cost)
    return 0;
  if (new->depth != old->depth)
    return 0;

  return 1;
}

static int
isis_route_info_same (struct isis_route_info *new,
		      struct isis_route_info *old, u_char family)
{
  struct listnode *node, *nnode;
  struct isis_nexthop *nexthop;
#ifdef HAVE_IPV6
  struct isis_nexthop6 *nexthop6;
#endif /* HAVE_IPV6 */
  if (!isis_route_info_same_attrib (new, old))
    return 0;


  if (family == AF_INET)
    {
      for (ALL_LIST_ELEMENTS (new->nexthops, node, nnode, nexthop))
        if (nexthoplookup (old->nexthops, &nexthop->ip, nexthop->ifindex) 
              == 0)
          return 0;

      for (ALL_LIST_ELEMENTS (old->nexthops, node, nnode, nexthop))
        if (nexthoplookup (new->nexthops, &nexthop->ip, nexthop->ifindex) 
             == 0)
          return 0;
    }
#ifdef HAVE_IPV6
  else if (family == AF_INET6)
    {
      for (ALL_LIST_ELEMENTS (new->nexthops6, node, nnode, nexthop6))
        if (nexthop6lookup (old->nexthops6, &nexthop6->ip6,
                            nexthop6->ifindex) == 0)
          return 0;

      for (ALL_LIST_ELEMENTS (old->nexthops6, node, nnode, nexthop6))
        if (nexthop6lookup (new->nexthops6, &nexthop6->ip6,
                            nexthop6->ifindex) == 0)
          return 0;
    }
#endif /* HAVE_IPV6 */

  if( new->route_type != old->route_type )
    return 0;

  return 1;
}

#if 0
static void
isis_nexthops_merge (struct list *new, struct list *old)
{
  struct listnode *node, *nnode;
  struct isis_nexthop *nexthop;
  

  for (ALL_LIST_ELEMENTS (new, node, nnode, nexthop))
    {
      if (nexthoplookup (old, &nexthop->ip, nexthop->ifindex))
	continue;
      listnode_add (old, nexthop);
      nexthop->lock++;
    }
}
#endif

#ifdef HAVE_IPV6
#if 0
static void
isis_nexthops6_merge (struct list *new, struct list *old)
{
  struct listnode *node, *nnode;
  struct isis_nexthop6 *nexthop6;

  for (ALL_LIST_ELEMENTS (new, node, nnode, nexthop6))
    {
      if (nexthop6lookup (old, &nexthop6->ip6, nexthop6->ifindex))
	continue;
      listnode_add (old, nexthop6);
      nexthop6->lock++;
    }
}
#endif
#endif /* HAVE_IPV6 */

#if 0
static void
isis_route_info_merge (struct isis_route_info *new,
		       struct isis_route_info *old, u_char family)
{
  if (family == AF_INET)
    isis_nexthops_merge (new->nexthops, old->nexthops);
#ifdef HAVE_IPV6
  else if (family == AF_INET6)
    isis_nexthops6_merge (new->nexthops6, old->nexthops6);
#endif /* HAVE_IPV6 */

  return;
}
#endif

#if 0
static int
isis_route_info_prefer_new (struct isis_route_info *new,
			    struct isis_route_info *old)
{
  if (!CHECK_FLAG (old->flag, ISIS_ROUTE_FLAG_ACTIVE))
    return 1;

  if (new->cost < old->cost)
    return 1;

  return 0;
}
#endif

struct isis_route_info *
isis_route_create (struct prefix *prefix, u_int32_t cost, u_int32_t depth,
		   struct list *adjacencies, struct isis_area *area,int level)
{
  struct route_node *route_node;
  struct isis_route_info *rinfo_new, *rinfo_old, *route_info = NULL;
  u_char buff[BUFSIZ];
  u_char family;

  family = prefix->family;
  /* for debugs */
  prefix2str (prefix, (char *) buff, BUFSIZ);

  rinfo_new = isis_route_info_new (cost, depth, family, adjacencies,level);
  if (!rinfo_new)
    {
      zlog_err ("ISIS-Rte (%s): isis_route_create: out of memory!",
		area->area_tag);
      return NULL;
    }

  if (family == AF_INET)
    route_node = route_node_get (area->route_table, prefix);
#ifdef HAVE_IPV6
  else if (family == AF_INET6)
    route_node = route_node_get (area->route_table6, prefix);
#endif /* HAVE_IPV6 */
  else
    return NULL;
  rinfo_old = route_node->info;
  if (!rinfo_old)
    {
      if (isis->debugs & DEBUG_RTE_EVENTS)
	zlog_debug ("ISIS-Rte (%s) route created: %s", area->area_tag, buff);
      SET_FLAG (rinfo_new->flag, ISIS_ROUTE_FLAG_ACTIVE);
      route_node->info = rinfo_new;
      return rinfo_new;
    }

  if (isis->debugs & DEBUG_RTE_EVENTS)
    zlog_debug ("ISIS-Rte (%s) route already exists check for type attribute match : %s", area->area_tag,
	       buff);
   
  if (isis_route_info_same (rinfo_new, rinfo_old, family))
    {
      if (isis->debugs & DEBUG_RTE_EVENTS)
	zlog_debug ("ISIS-Rte (%s) route unchanged: %s", area->area_tag, buff);
        isis_route_info_delete (rinfo_new);
        route_info = rinfo_old;
    }
  else
    {
         /* just replace the old route with new route by checking the route_type.
	    Here route validation for ECMP is not needed because of SPF output is providing 
            best path route */
            
        if( !((rinfo_old->route_type == IS_LEVEL_1) && (rinfo_new->route_type == IS_LEVEL_2)) )
          {
              isis_route_info_delete (rinfo_old);
              route_info = rinfo_new;
              zlog_debug ("ISIS-Rte (%s) route changed: %s", area->area_tag, buff);
           }
         else
           {
                isis_route_info_delete (rinfo_new);
                route_info = rinfo_old;
                zlog_debug ("ISIS-Rte (%s) route unchanged: %s", area->area_tag, buff);
           }
                 
     }

    SET_FLAG (route_info->flag, ISIS_ROUTE_FLAG_ACTIVE);
    route_node->info = route_info;

  return route_info;
}

static void
isis_route_delete (struct prefix *prefix, struct route_table *table)
{
  struct route_node *rode;
  struct isis_route_info *rinfo;
  char buff[BUFSIZ];

  /* for log */
  prefix2str (prefix, buff, BUFSIZ);


  rode = route_node_get (table, prefix);
  rinfo = rode->info;

  if (rinfo == NULL)
    {
      if (isis->debugs & DEBUG_RTE_EVENTS)
	zlog_debug ("ISIS-Rte: tried to delete non-existant route %s", buff);
      return;
    }

  if (CHECK_FLAG (rinfo->flag, ISIS_ROUTE_FLAG_ZEBRA_SYNC))
    {
      UNSET_FLAG (rinfo->flag, ISIS_ROUTE_FLAG_ACTIVE);
      if (isis->debugs & DEBUG_RTE_EVENTS)
	zlog_debug ("ISIS-Rte: route delete  %s", buff);
      isis_zebra_route_update (prefix, rinfo);
    }
  isis_route_info_delete (rinfo);
  rode->info = NULL;

  return;
}

int
isis_route_validate (struct thread *thread)
{
  struct isis_area *area;
  struct route_table *table;
  struct route_node *rode;
  struct isis_route_info *rinfo;
  u_char buff[BUFSIZ];
#ifdef HAVE_IPV6
  int v6done = 0;
#endif
  area = THREAD_ARG (thread);
  table = area->route_table;
#ifdef HAVE_IPV6
again:
#endif
  for (rode = route_top (table); rode; rode = route_next (rode))
    {
      if (rode->info == NULL)
	continue;
      rinfo = rode->info;

      if (isis->debugs & DEBUG_RTE_EVENTS)
	{
	  prefix2str (&rode->p, (char *) buff, BUFSIZ);
	  zlog_debug ("ISIS-Rte (%s): route validate: %s %s %s",
		      area->area_tag,
		      (CHECK_FLAG (rinfo->flag, ISIS_ROUTE_FLAG_ZEBRA_SYNC) ?
		      "sync'ed" : "nosync"),
		      (CHECK_FLAG (rinfo->flag, ISIS_ROUTE_FLAG_ACTIVE) ?
		      "active" : "inactive"), buff);
	}

      isis_zebra_route_update (&rode->p, rinfo);
      if (!CHECK_FLAG (rinfo->flag, ISIS_ROUTE_FLAG_ACTIVE))
	isis_route_delete (&rode->p, area->route_table);
    }
#ifdef HAVE_IPV6
  if (v6done)
    return ISIS_OK;
  table = area->route_table6;
  v6done = 1;
  goto again;
#endif

  return ISIS_OK;
}
