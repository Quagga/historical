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

#include "memory.h"
#include "if.h"
#include "log.h"
#include "command.h"
#include "thread.h"
#include "prefix.h"
#include "plist.h"

#include "ospf6_lsa.h"
#include "ospf6_lsdb.h"
#include "ospf6_network.h"
#include "ospf6_message.h"
#include "ospf6_route.h"
#include "ospf6_top.h"
#include "ospf6_area.h"
#include "ospf6_interface.h"
#include "ospf6_neighbor.h"
#include "ospf6_intra.h"
#include "ospf6_spf.h"
#include "ospf6_proto.h"
#include "ospf6_abr.h"
#include "ospf6d.h"

unsigned char conf_debug_ospf6_interface = 0;

const char *ospf6_interface_state_str[] =
{
  "None",
  "Down",
  "Loopback",
  "Waiting",
  "PointToPoint",
  "DROther",
  "BDR",
  "DR",
  NULL
};

struct ospf6_ifgroup *
ospf6_ifgroup_new (const char *ifname, u_int32_t area_id, int format)
{
  struct ospf6_ifgroup *new;
  new = XCALLOC (MTYPE_OSPF6_IF, sizeof (struct ospf6_ifgroup));

  new->ifname = XSTRDUP (MTYPE_OSPF6_IF, ifname);
  new->area_id = area_id;
  new->format = format;
  
  return new;
}

void
ospf6_ifgroup_free (struct ospf6 *o, struct ospf6_ifgroup *ifgroup)
{
  XFREE (MTYPE_OSPF6_IF, ifgroup->ifname);
  XFREE (MTYPE_OSPF6_IF, ifgroup);
}

/*
 * check whether ifname matches pattern
 * pattern last char set to * means "any number"
 *
 * e.g.: pattern "eth0" only matches "eth0"
 *       pattern "eth*" matches "eth0", "eth1", "eth25"
 *                      but does not match "ether2" or "eth"
 */
int
ospf6_ifgroup_match(const char *pattern, const char *ifname)
{
  int patternlen;

  patternlen = strlen(pattern);

  if (patternlen && pattern[patternlen - 1] == '*')
    {
      const char *p;

      if (strlen(ifname) < patternlen)
        return 0;
      if (strncmp(pattern, ifname, patternlen - 1) != 0)
        return 0;
      for (p = &ifname[patternlen-1]; *p; p++)
        if (!isdigit(*p))
          return 0;
    }
  else
    return (strcmp(pattern, ifname) == 0);

  return 1;
}


struct ospf6_interface *
ospf6_interface_lookup_by_ifindex (int ifindex)
{
  struct ospf6_interface *oi;
  struct interface *ifp;

  ifp = if_lookup_by_index (ifindex);
  if (ifp == NULL)
    return (struct ospf6_interface *) NULL;

  oi = (struct ospf6_interface *) ifp->info;
  return oi;
}

/* schedule routing table recalculation */
void
ospf6_interface_lsdb_hook (struct ospf6_lsa *lsa)
{
  switch (ntohs (lsa->header->type))
    {
      case OSPF6_LSTYPE_LINK:
        if (OSPF6_INTERFACE (lsa->lsdb->data)->state == OSPF6_INTERFACE_DR)
          OSPF6_INTRA_PREFIX_LSA_SCHEDULE_TRANSIT (OSPF6_INTERFACE (lsa->lsdb->data));
        ospf6_spf_schedule (OSPF6_INTERFACE (lsa->lsdb->data)->area);
        break;

      default:
        break;
    }
}

/* Create new ospf6 interface structure */
struct ospf6_interface *
ospf6_interface_create (struct interface *ifp)
{
  struct ospf6_interface *oi;
  unsigned int iobuflen;

  oi = (struct ospf6_interface *)
    XMALLOC (MTYPE_OSPF6_IF, sizeof (struct ospf6_interface));

  if (oi)
    memset (oi, 0, sizeof (struct ospf6_interface));
  else
    {
      zlog_err ("Can't malloc ospf6_interface for ifindex %d", ifp->ifindex);
      return (struct ospf6_interface *) NULL;
    }

  oi->area = (struct ospf6_area *) NULL;
  oi->neighbor_list = list_new ();
  oi->neighbor_list->cmp = ospf6_neighbor_cmp;
  oi->linklocal_addr = (struct in6_addr *) NULL;
  oi->global_addr = (struct in6_addr *) NULL;

  oi->instance_id = DEFAULT_INSTANCE_ID;
  oi->transdelay = DEFAULT_TRANSMISSION_DELAY;
  oi->priority = DEFAULT_PRIORITY;
  oi->hello_interval = DEFAULT_HELLO_INTERVAL;
  oi->dead_interval = DEFAULT_DEAD_INTERVAL;
  oi->rxmt_interval = DEFAULT_RETRANSMIT_INTERVAL;

  oi->cost_flag = OSPF6_INTERFACE_COST_AUTO;
  oi->state = OSPF6_INTERFACE_DOWN;
  oi->flag = 0;

  /* Try to adjust I/O buffer size with IfMtu */
  oi->ifmtu = ifp->mtu6;
  oi->static_mtu = 0;
  oi->mtu_ignore = 1;

  iobuflen = ospf6_iobuf_size (ifp->mtu6);
  if (oi->ifmtu > iobuflen)
    {
      if (IS_OSPF6_DEBUG_INTERFACE)
        zlog_debug ("Interface %s: IfMtu is adjusted to I/O buffer size: %d.",
		    ifp->name, iobuflen);
      oi->ifmtu = iobuflen;
    }

  oi->lsupdate_list = ospf6_lsdb_create (oi);
  oi->lsack_list = ospf6_lsdb_create (oi);
  oi->lsdb = ospf6_lsdb_create (oi);
  oi->lsdb->hook_add = ospf6_interface_lsdb_hook;
  oi->lsdb->hook_remove = ospf6_interface_lsdb_hook;
  oi->lsdb_self = ospf6_lsdb_create (oi);

  oi->route_connected = ospf6_route_table_create ();

  /* link both */
  oi->interface = ifp;
  ifp->info = oi;

  oi->cost = ospf6_interface_get_cost (oi);

  return oi;
}

void
ospf6_interface_delete (struct ospf6_interface *oi)
{
  struct listnode *node, *nnode;
  struct ospf6_neighbor *on;

  for (ALL_LIST_ELEMENTS (oi->neighbor_list, node, nnode, on))
      ospf6_neighbor_delete (on);
  
  list_delete (oi->neighbor_list);

  THREAD_OFF (oi->thread_send_hello);
  THREAD_OFF (oi->thread_send_lsupdate);
  THREAD_OFF (oi->thread_send_lsack);
  THREAD_OFF (oi->thread_wait_timer);

  /* cancel all events referencing oi */
  thread_cancel_event (master, oi);

  ospf6_lsdb_remove_all (oi->lsdb);
  ospf6_lsdb_remove_all (oi->lsupdate_list);
  ospf6_lsdb_remove_all (oi->lsack_list);

  ospf6_lsdb_delete (oi->lsdb);
  ospf6_lsdb_delete (oi->lsdb_self);

  ospf6_lsdb_delete (oi->lsupdate_list);
  ospf6_lsdb_delete (oi->lsack_list);

  ospf6_route_table_delete (oi->route_connected);

  /* cut link */
  oi->interface->info = NULL;

  /* plist_name */
  if (oi->plist_name)
    XFREE (MTYPE_PREFIX_LIST_STR, oi->plist_name);

  XFREE (MTYPE_OSPF6_IF, oi);
}

void
ospf6_interface_enable (struct ospf6_interface *oi)
{
  UNSET_FLAG (oi->flag, OSPF6_INTERFACE_DISABLE);

  THREAD_OFF(oi->thread_send_hello);
  oi->thread_send_hello =
    thread_add_event (master, ospf6_hello_send, oi, 0);
}

void
ospf6_interface_disable (struct ospf6_interface *oi)
{
  struct listnode *node, *nnode;
  struct ospf6_neighbor *on;

  SET_FLAG (oi->flag, OSPF6_INTERFACE_DISABLE);

  for (ALL_LIST_ELEMENTS (oi->neighbor_list, node, nnode, on))
      ospf6_neighbor_delete (on);

  list_delete_all_node (oi->neighbor_list);

  ospf6_lsdb_remove_all (oi->lsdb);
  ospf6_lsdb_remove_all (oi->lsupdate_list);
  ospf6_lsdb_remove_all (oi->lsack_list);

  THREAD_OFF (oi->thread_send_hello);
  THREAD_OFF (oi->thread_send_lsupdate);
  THREAD_OFF (oi->thread_send_lsack);
}

/*
 * Return link local address to use  
 * If a link local address is already in use and still configured on the
 * interface, then continue using it, else use another one.
 * Return NULL if no link local address is available.
 */
static struct in6_addr *
ospf6_interface_get_linklocal_address (struct interface *ifp)
{
  struct listnode *n;
  struct connected *c;
  struct in6_addr *l = (struct in6_addr *) NULL;
  struct ospf6_interface *oi;

  oi = (struct ospf6_interface *) ifp->info;
  if (! oi)
    return NULL;

  /* for each connected address */
  for (ALL_LIST_ELEMENTS_RO (ifp->connected, n, c))
    {
      /* if family not AF_INET6, ignore */
      if (c->address->family != AF_INET6)
        continue;

      /* linklocal scope check */
      if (IN6_IS_ADDR_LINKLOCAL (&c->address->u.prefix6))
        {
          /* is this the link local address currently in use? */
          if (oi->linklocal_addr && (memcmp(oi->linklocal_addr, &c->address->u.prefix6,
                      sizeof (struct in6_addr)) == 0))
              return(oi->linklocal_addr);
          /* no, mark it as a candidate */
          else
            {
              if (l == NULL)
                l = &c->address->u.prefix6;
            }
        }

    }
  if (l) {
    zlog_warn("Changing link local address used on %s interface",
      ifp->name);
        memcpy(&oi->lladdr_copy, l, sizeof (struct in6_addr));
    return(&oi->lladdr_copy);
  }

  return NULL;
 
}

/* Get global address */
static struct in6_addr *
ospf6_interface_get_global_address (struct interface *ifp)
{
  struct listnode *n;
  struct connected *c;
  struct in6_addr *s = (struct in6_addr *) NULL;

  /* for each connected address */
  for (ALL_LIST_ELEMENTS_RO (ifp->connected, n, c))
    {
      /* if family not AF_INET6, ignore */
      if (c->address->family != AF_INET6)
        continue;

      /* global scope check */
      if (IN6_IS_ADDR_GLOBAL (&c->address->u.prefix6))
        s = &c->address->u.prefix6;
    }
  return s;
}

void
ospf6_add_if_to_area(struct ospf6 *o, struct interface *ifp,
                     struct ospf6_area *oa)
{
  struct ospf6_interface *oi;
  int    abr_previously;

  oi = (struct ospf6_interface *) ifp->info;
  if (oi == NULL)
      oi = ospf6_interface_create (ifp);

  /* attach interface to area */
  listnode_add (oa->if_list, oi); /* sort ?? */
  oi->area = oa;

  abr_previously = ospf6_is_router_abr (o);
  SET_FLAG (oa->flag, OSPF6_AREA_ENABLE);

  /* start up */
  thread_add_event (master, interface_up, oi, 0);

  /* If the router is ABR, originate summary routes */
  if (ospf6_is_router_abr (o))
    {
      if (!abr_previously)
        {
          struct ospf6_area *oa_temp;
          struct listnode *node;

          for (ALL_LIST_ELEMENTS_RO (o->area_list, node, oa_temp))
            {
              ospf6_abr_nssa_translator_state_update (oa_temp);
              ospf6_abr_enable_area (oa_temp);
            }
        }
      else
        ospf6_abr_enable_area (oa);
    }
}

void
ospf6_interface_if_add (struct ospf6 *o, struct interface *ifp)
{
  struct ospf6_interface *oi;
  unsigned int iobuflen;
  struct listnode *node;
  struct ospf6_ifgroup *ifgroup;
  struct ospf6_area *oa;

  oi = (struct ospf6_interface *) ifp->info;
  if (oi && oi->area)
    return;

   /* wait OSPFv3 to initialize */
   if (o == NULL)
     return;

   for (ALL_LIST_ELEMENTS_RO (o->interfaces, node, ifgroup))
      {
        if (ospf6_ifgroup_match(ifgroup->ifname, ifp->name))
            break;
      }

  if (node == NULL)
    return;

  oa = ospf6_area_get(ifgroup->area_id, ifgroup->format, o);

  ospf6_add_if_to_area(o, ifp, oa);

  oi = (struct ospf6_interface *)ifp->info;

  /* Try to adjust I/O buffer size with IfMtu */
  if (oi->ifmtu == 0)
    oi->ifmtu = ifp->mtu6;
  iobuflen = ospf6_iobuf_size (ifp->mtu6);
  if (oi->ifmtu > iobuflen)
    {
      if (IS_OSPF6_DEBUG_INTERFACE)
        zlog_debug ("Interface %s: IfMtu is adjusted to I/O buffer size: %d.",
		    ifp->name, iobuflen);
      oi->ifmtu = iobuflen;
    }

  /* interface start */
  if (oi->area)
    thread_add_event (master, interface_up, oi, 0);
}

void
ospf6_interface_if_del (struct ospf6 *o, struct interface *ifp)
{
  struct ospf6_interface *oi;

  oi = (struct ospf6_interface *) ifp->info;
  if (oi == NULL)
    return;

  /* interface stop */
  if (oi->area)
    thread_execute (master, interface_down, oi, 0);

  listnode_delete (oi->area->if_list, oi);
  oi->area = (struct ospf6_area *) NULL;

  ospf6_interface_delete (oi);
}

void
ospf6_interface_state_update (struct interface *ifp)
{
  struct ospf6_interface *oi;

  oi = (struct ospf6_interface *) ifp->info;
  if (oi == NULL)
    return;
  if (oi->area == NULL)
    return;

  if (ifp->flags & OSPF6_IF_UP)
    thread_add_event (master, interface_up, oi, 0);
  else
    thread_add_event (master, interface_down, oi, 0);

  return;
}

void
ospf6_interface_connected_route_update (struct interface *ifp)
{
  struct ospf6_interface *oi;
  struct ospf6_route *route, *ro, *ro_area;
  struct connected *c;
  struct listnode *node, *nnode;

  oi = (struct ospf6_interface *) ifp->info;
  if (oi == NULL)
    return;

  /* if area is null, do not make connected-route list */
  if (oi->area == NULL)
    return;
  
  if (oi->nw_type == OSPF6_NWTYPE_VIRTUALLINK)
      oi->linklocal_addr = (struct in6_addr *) NULL;
  else
    {
      /* reset linklocal & global addresses */
      oi->linklocal_addr = ospf6_interface_get_linklocal_address (ifp);
      oi->global_addr = ospf6_interface_get_global_address (ifp);

      if (IS_OSPF6_DEBUG_INTERFACE)
        {
          if (! oi->linklocal_addr)
            zlog_debug ("OSPF6 Interface Linklocal address is NULL");
          if (! oi->global_addr)
            zlog_debug ("OSPF6 Interface Global address is NULL");
        }
    }

  /* update "route to advertise" interface route table */
  for (ro = ospf6_route_head (oi->route_connected); ro; 
      ro = ospf6_route_next (ro))
    {
      if ((ro_area = ospf6_route_match_head(&ro->prefix, oi->area->route_table)) != NULL)
        {
          ospf6_route_remove (ro_area, oi->area->route_table);
          ospf6_route_unlock(ro_area);
        }

      ospf6_route_remove (ro, oi->route_connected);
    }

  for (ALL_LIST_ELEMENTS (oi->interface->connected, node, nnode, c))
    {
      if (c->address->family != AF_INET6)
        continue;

      CONTINUE_IF_ADDRESS_LINKLOCAL (IS_OSPF6_DEBUG_INTERFACE, c->address);
      CONTINUE_IF_ADDRESS_UNSPECIFIED (IS_OSPF6_DEBUG_INTERFACE, c->address);
      CONTINUE_IF_ADDRESS_LOOPBACK (IS_OSPF6_DEBUG_INTERFACE, c->address);
      CONTINUE_IF_ADDRESS_V4COMPAT (IS_OSPF6_DEBUG_INTERFACE, c->address);
      CONTINUE_IF_ADDRESS_V4MAPPED (IS_OSPF6_DEBUG_INTERFACE, c->address);

      /* apply filter */
      if (oi->plist_name)
        {
          struct prefix_list *plist;
          enum prefix_list_type ret;
          char buf[128];

          prefix2str (c->address, buf, sizeof (buf));
          plist = prefix_list_lookup (AFI_IP6, oi->plist_name);
          ret = prefix_list_apply (plist, (void *) c->address);
          if (ret == PREFIX_DENY)
            {
              if (IS_OSPF6_DEBUG_INTERFACE)
                zlog_debug ("%s on %s filtered by prefix-list %s ",
			    buf, oi->interface->name, oi->plist_name);
              continue;
            }
        }

      route = ospf6_route_create ();
      memcpy (&route->prefix, c->address, sizeof (struct prefix));
      apply_mask (&route->prefix);
      route->type = OSPF6_DEST_TYPE_NETWORK;
      route->path.area_id = oi->area->area_id;
      route->path.type = OSPF6_PATH_TYPE_INTRA;
      route->path.cost = oi->cost;
      route->nexthop[0].ifindex = oi->interface->ifindex;
      inet_pton (AF_INET6, "::1", &route->nexthop[0].address);
      ospf6_route_add (ospf6_route_copy(route), oi->route_connected);
      ospf6_route_add (route, oi->area->route_table);
    }

  /* create new Link-LSA */
  /* RFC2740 section 3.4.3.6-Link-LSA should not be originated for Vlinks */
  if (oi->nw_type != OSPF6_NWTYPE_VIRTUALLINK)
    OSPF6_LINK_LSA_SCHEDULE (oi);

  OSPF6_INTRA_PREFIX_LSA_SCHEDULE_TRANSIT (oi);
  OSPF6_INTRA_PREFIX_LSA_SCHEDULE_STUB (oi->area);
}


void
ospf6_interface_stale_add (struct ospf6_interface *oi, struct ospf6_route *route,
                           struct ospf6_stale *os)
{
  struct ospf6_route *stale = os->stale;
  int i; /* multipath index */

  for (i = 0; i < OSPF6_MULTI_PATH_LIMIT; i++)
    ospf6_nexthop_copy (&route->nexthop[i], &os->nexthop[0][i]);

  /* This means prev state is none, so no stale entry is expected */
  if (os->nh_count[1] > 0)
    {
      stale = ospf6_route_copy (route);

      if (os->flag == OSPF6_STALE_INTERFACE)
        {
          /* old interface cost is stored for cost recalculation */
          stale->path.origin.id = oi->cost - os->cost;

          /* interface route cost is set to 0 in stale */
          stale->path.cost = route->path.cost + os->cost - oi->cost;
        }
      else
        stale->path.origin.id = 0;

      for (i = 0; i < OSPF6_MULTI_PATH_LIMIT; i++)
        ospf6_nexthop_copy (&stale->nexthop[i], &os->nexthop[1][i]);

      ospf6_route_add (stale, ospf6->stale_table);
    }
}


void
ospf6_interface_stale_update (struct ospf6_interface *oi, 
                              struct ospf6_route *route, struct ospf6_stale *os)
{
  struct ospf6_route *stale = os->stale;
  u_int32_t cost = 0;
  int i, j; /* multipath index */

  if (os->flag == OSPF6_STALE_INTERFACE)
    cost += oi->cost;

  if (stale)
    {
      cost += stale->path.cost;

      if (cost == route->path.cost)
        {
          for (i = 0; ospf6_nexthop_is_set (&stale->nexthop[i]) &&
               i < OSPF6_MULTI_PATH_LIMIT; i++)
            ospf6_nexthop_copy (&route->nexthop[i], &stale->nexthop[i]);

          if (os->nh_count[0] > 0)
            {
              for (j = 0; i < OSPF6_MULTI_PATH_LIMIT; i++, j++)
                ospf6_nexthop_copy (&route->nexthop[i], &os->nexthop[0][j]);
            }

          ospf6_route_remove (stale, ospf6->stale_table);
        }
      else if (cost < route->path.cost)
        {
          for (i = 0; i < OSPF6_MULTI_PATH_LIMIT; i++)
            ospf6_nexthop_copy (&route->nexthop[i], &stale->nexthop[i]);

          if (os->nh_count[0] > 0)
            {
              for (i = 0; i < OSPF6_MULTI_PATH_LIMIT; i++)
                ospf6_nexthop_copy (&stale->nexthop[i], &os->nexthop[0][i]);

              /* Flag indicating current state of stale, 
                 state will change after swapping */
              if (os->flag == OSPF6_STALE_NON_INTERFACE)
                {
                  /* interface cost is set to 0 in stale */
                  stale->path.cost = route->path.cost - oi->cost;

                  /* old interface cost is stored for cost recalculation */
                  stale->path.origin.id = oi->cost - os->cost;
                }
              else
                {
                  stale->path.cost = route->path.cost;
                  stale->path.origin.id = 0;
                }
            }

          route->path.cost = cost;
        }
    }
}


/* Cost state machine, present state can be cost increase / decrease, previous 
  state can be cost decrease / increase */
void
ospf6_interface_route_table_update (struct ospf6_interface *oi, long int cost_diff)
{
  struct ospf6_route *route, *stale;
  struct ospf6_stale os;
  struct ospf6_nexthop nh_si[OSPF6_MULTI_PATH_LIMIT]; /* nexthop same interface */
  struct ospf6_nexthop nh_di[OSPF6_MULTI_PATH_LIMIT]; /* nexthop diff interface */
  int si, di, i; /* multipath index */

  if (ospf6 == NULL)
    return;

  for (route = ospf6_route_head (ospf6->route_table); route;
       route = ospf6_route_next (route))
    {
      /* loopback routes are upated in connected route update */
      if (IN6_IS_ADDR_LOOPBACK (&route->nexthop[0].address))
        continue;

      for (i = 0, si = 0; i < OSPF6_MULTI_PATH_LIMIT; i++)
        ospf6_nexthop_clear (&nh_si[i]);
      for (i = 0, di = 0; i < OSPF6_MULTI_PATH_LIMIT; i++)
        ospf6_nexthop_clear (&nh_di[i]);

      stale = ospf6_route_match_head(&route->prefix, ospf6->stale_table);
      os.stale = stale;

      for (i = 0; i < OSPF6_MULTI_PATH_LIMIT; i++)
        {
          if (ospf6_nexthop_is_set (&route->nexthop[i]))
            {
              if (route->nexthop[i].ifindex == oi->interface->ifindex)
                {
                  ospf6_nexthop_copy (&nh_si[si], &route->nexthop[i]);
                  si++;
                }
              else
                {
                  ospf6_nexthop_copy (&nh_di[di], &route->nexthop[i]);
                  di++;
                }

              continue;
            }
          /* This means prev state is either increase or none */
          else if ( (cost_diff > 0) && (di > 0))
            {
              os.nexthop[0] = (struct ospf6_nexthop *)&nh_di;
              os.nexthop[1] = (struct ospf6_nexthop *)&nh_si;
              os.nh_count[1] = si;
              os.cost = cost_diff; 
              os.flag = OSPF6_STALE_INTERFACE;

              /* stale will contain interface routes, 
                 route contains non-interface routes */
              ospf6_interface_stale_add (oi, route, &os);
            }
          else if ( (cost_diff > 0) && (di == 0))
            {
              /* stale contains non-interface routes, 
                 route contains interface routes */
              route->path.cost += cost_diff;

              os.nexthop[0] = (struct ospf6_nexthop *)&nh_si;
              os.nh_count[0] = si;
              os.cost = cost_diff; 
              os.flag = OSPF6_STALE_NON_INTERFACE;

              ospf6_interface_stale_update (oi, route, &os);
            }
          /* This means prev state is either decrease or none */
          else if ( (cost_diff < 0) && (si > 0))
            {
              os.nexthop[0] = (struct ospf6_nexthop *)&nh_si;
              os.nexthop[1] = (struct ospf6_nexthop *)&nh_di;
              os.nh_count[1] = di;
              os.flag = OSPF6_STALE_NON_INTERFACE;

              /* stale will contain non-interface routes, 
                 route contains interface routes */
              ospf6_interface_stale_add (oi, route, &os);
              route->path.cost += cost_diff;
            }
          else if ( (cost_diff < 0) && (si == 0))
            {
              /* stale contains interface routes, 
                 route contains non-interface routes */

              os.nexthop[0] = (struct ospf6_nexthop *)&nh_di;
              os.nh_count[0] = di;
              os.flag = OSPF6_STALE_INTERFACE;

              ospf6_interface_stale_update (oi, route, &os);
            }

          break;
        }
    }

  /* remove unwanted stale entries, if present */
  stale = route = NULL;
  for (stale = ospf6_route_head (ospf6->stale_table); stale;
       stale = ospf6_route_next (stale))
    {
      if ( (route = ospf6_route_match_head(&stale->prefix, ospf6->route_table)) == NULL)
        ospf6_route_remove (stale, ospf6->stale_table);
    }
}

/* For ECMP only. When an interface is down, remove nexthops belonging to that 
   interface */
void
ospf6_interface_ecmp_nexthop_flush (struct ospf6_interface *oi, 
                                    struct ospf6_route_table *route_table)
{
  struct ospf6_route *route;
  struct ospf6_nexthop nexthop[OSPF6_MULTI_PATH_LIMIT];
  int i, j;

  for (route = ospf6_route_head (route_table); route;
       route = ospf6_route_next (route))
    {
      for (i = 0; i < OSPF6_MULTI_PATH_LIMIT; i++)
        ospf6_nexthop_clear (&nexthop[i]);

      for (i = 0, j = 0; ospf6_nexthop_is_set (&route->nexthop[i]) &&
           i < OSPF6_MULTI_PATH_LIMIT; i++)
        {
          if (route->nexthop[i].ifindex != oi->interface->ifindex)
            {
              ospf6_nexthop_copy (&nexthop[j], &route->nexthop[i]);
              j++;
            }
        }

      /* if the route is not ECMP route then do not flush */
      if (i == 1)
        continue;

      for (i = 0; i < OSPF6_MULTI_PATH_LIMIT; i++)
        ospf6_nexthop_copy (&route->nexthop[i], &nexthop[i]);

    }
}

static void
ospf6_interface_state_change (u_char next_state, struct ospf6_interface *oi)
{
  u_char prev_state;

  prev_state = oi->state;
  oi->state = next_state;

  if (prev_state == next_state)
    return;

  /* log */
  if (IS_OSPF6_DEBUG_INTERFACE)
    {
      zlog_debug ("Interface state change %s: %s -> %s", oi->interface->name,
		  ospf6_interface_state_str[prev_state],
		  ospf6_interface_state_str[next_state]);
    }

  if ((prev_state == OSPF6_INTERFACE_DR ||
       prev_state == OSPF6_INTERFACE_BDR) &&
      (next_state != OSPF6_INTERFACE_DR &&
       next_state != OSPF6_INTERFACE_BDR))
    ospf6_leave_alldrouters (oi->interface->ifindex);
  if ((prev_state != OSPF6_INTERFACE_DR &&
       prev_state != OSPF6_INTERFACE_BDR) &&
      (next_state == OSPF6_INTERFACE_DR ||
       next_state == OSPF6_INTERFACE_BDR))
    ospf6_join_alldrouters (oi->interface->ifindex);

  OSPF6_ROUTER_LSA_SCHEDULE (oi->area);
  if (next_state == OSPF6_INTERFACE_DOWN)
    {
      OSPF6_NETWORK_LSA_EXECUTE (oi);
      OSPF6_INTRA_PREFIX_LSA_EXECUTE_TRANSIT (oi);
      OSPF6_INTRA_PREFIX_LSA_SCHEDULE_STUB (oi->area);
    }
  else if (prev_state == OSPF6_INTERFACE_DR ||
           next_state == OSPF6_INTERFACE_DR)
    {
      OSPF6_NETWORK_LSA_SCHEDULE (oi);
      OSPF6_INTRA_PREFIX_LSA_SCHEDULE_TRANSIT (oi);
      OSPF6_INTRA_PREFIX_LSA_SCHEDULE_STUB (oi->area);
    }
}

u_int32_t
ospf6_interface_get_cost (struct ospf6_interface *oi)
{
  u_int32_t cost = oi->cost;
  u_int32_t bw, refbw;

  /* A specifed ipv6 ospf6 cost overrides a calculated one.
   * Calculate cost using zebra processes interface bandwidth field. */
  if (oi->cost_flag == OSPF6_INTERFACE_COST_AUTO)
    {
      bw = oi->interface->bandwidth ? oi->interface->bandwidth : OSPF6_DEFAULT_BANDWIDTH;

      if (ospf6)
        refbw = ospf6->ref_bandwidth;
      else
        refbw = OSPF6_DEFAULT_REF_BANDWIDTH;

      cost = (u_int32_t) ((double)refbw / (double)bw + (double)0.5);
      if (cost < 1)
        cost = 1;
      else if (cost > 65535)
        cost = 65535;
    }

  return cost;
}

/* update interface cost, route costs, and trigger lsa hooks */
void
ospf6_interface_update_cost (struct ospf6_interface *oi, u_int32_t newcost)
{
  long int cost_diff = newcost - oi->cost;

  if (cost_diff == 0)
    return;

  oi->cost = newcost;

  /* update cost held in route_connected list in ospf6_interface */
  ospf6_interface_connected_route_update (oi->interface);
  ospf6_interface_route_table_update (oi, cost_diff);

  /* execute LSA hooks */
  if (oi->area)
    {
      OSPF6_LINK_LSA_SCHEDULE (oi);
      OSPF6_ROUTER_LSA_SCHEDULE (oi->area);
      OSPF6_NETWORK_LSA_SCHEDULE (oi);
      OSPF6_INTRA_PREFIX_LSA_SCHEDULE_TRANSIT (oi);
      OSPF6_INTRA_PREFIX_LSA_SCHEDULE_STUB (oi->area);
    }
}

void
ospf6_interface_recalculate_cost ()
{
  struct ospf6_area *oa;
  struct ospf6_interface *oi;
  struct listnode *na, *ni;
  u_int32_t newcost;

  for (ALL_LIST_ELEMENTS_RO (ospf6->area_list, na, oa))
    for (ALL_LIST_ELEMENTS_RO (oa->if_list, ni, oi))
      {
        newcost = ospf6_interface_get_cost (oi);
        ospf6_interface_update_cost (oi, newcost);
      }
}



/* DR Election, RFC2328 section 9.4 */

#define IS_ELIGIBLE(n) \
  ((n)->state >= OSPF6_NEIGHBOR_TWOWAY && (n)->priority != 0)

static struct ospf6_neighbor *
better_bdrouter (struct ospf6_neighbor *a, struct ospf6_neighbor *b)
{
  if ((a == NULL || ! IS_ELIGIBLE (a) || a->drouter == a->router_id) &&
      (b == NULL || ! IS_ELIGIBLE (b) || b->drouter == b->router_id))
    return NULL;
  else if (a == NULL || ! IS_ELIGIBLE (a) || a->drouter == a->router_id)
    return b;
  else if (b == NULL || ! IS_ELIGIBLE (b) || b->drouter == b->router_id)
    return a;

  if (a->bdrouter == a->router_id && b->bdrouter != b->router_id)
    return a;
  if (a->bdrouter != a->router_id && b->bdrouter == b->router_id)
    return b;

  if (a->priority > b->priority)
    return a;
  if (a->priority < b->priority)
    return b;

  if (ntohl (a->router_id) > ntohl (b->router_id))
    return a;
  if (ntohl (a->router_id) < ntohl (b->router_id))
    return b;

  zlog_warn ("Router-ID duplicate ?");
  return a;
}

static struct ospf6_neighbor *
better_drouter (struct ospf6_neighbor *a, struct ospf6_neighbor *b)
{
  if ((a == NULL || ! IS_ELIGIBLE (a) || a->drouter != a->router_id) &&
      (b == NULL || ! IS_ELIGIBLE (b) || b->drouter != b->router_id))
    return NULL;
  else if (a == NULL || ! IS_ELIGIBLE (a) || a->drouter != a->router_id)
    return b;
  else if (b == NULL || ! IS_ELIGIBLE (b) || b->drouter != b->router_id)
    return a;

  if (a->drouter == a->router_id && b->drouter != b->router_id)
    return a;
  if (a->drouter != a->router_id && b->drouter == b->router_id)
    return b;

  if (a->priority > b->priority)
    return a;
  if (a->priority < b->priority)
    return b;

  if (ntohl (a->router_id) > ntohl (b->router_id))
    return a;
  if (ntohl (a->router_id) < ntohl (b->router_id))
    return b;

  zlog_warn ("Router-ID duplicate ?");
  return a;
}

static u_char
dr_election (struct ospf6_interface *oi)
{
  struct listnode *node, *nnode;
  struct ospf6_neighbor *on, *drouter, *bdrouter, myself;
  struct ospf6_neighbor *best_drouter, *best_bdrouter;
  u_char next_state = 0;

  drouter = bdrouter = NULL;
  best_drouter = best_bdrouter = NULL;

  /* pseudo neighbor myself, including noting current DR/BDR (1) */
  memset (&myself, 0, sizeof (myself));
  inet_ntop (AF_INET, &oi->area->ospf6->router_id, myself.name,
             sizeof (myself.name));
  myself.state = OSPF6_NEIGHBOR_TWOWAY;
  myself.drouter = oi->drouter;
  myself.bdrouter = oi->bdrouter;
  myself.priority = oi->priority;
  myself.router_id = oi->area->ospf6->router_id;

  /* Electing BDR (2) */
  for (ALL_LIST_ELEMENTS (oi->neighbor_list, node, nnode, on))
    bdrouter = better_bdrouter (bdrouter, on);
  
  best_bdrouter = bdrouter;
  bdrouter = better_bdrouter (best_bdrouter, &myself);

  /* Electing DR (3) */
  for (ALL_LIST_ELEMENTS (oi->neighbor_list, node, nnode, on))
    drouter = better_drouter (drouter, on);

  best_drouter = drouter;
  drouter = better_drouter (best_drouter, &myself);
  if (drouter == NULL)
    drouter = bdrouter;

  /* the router itself is newly/no longer DR/BDR (4) */
  if ((drouter == &myself && myself.drouter != myself.router_id) ||
      (drouter != &myself && myself.drouter == myself.router_id) ||
      (bdrouter == &myself && myself.bdrouter != myself.router_id) ||
      (bdrouter != &myself && myself.bdrouter == myself.router_id))
    {
      myself.drouter = (drouter ? drouter->router_id : htonl (0));
      myself.bdrouter = (bdrouter ? bdrouter->router_id : htonl (0));

      /* compatible to Electing BDR (2) */
      bdrouter = better_bdrouter (best_bdrouter, &myself);

      /* compatible to Electing DR (3) */
      drouter = better_drouter (best_drouter, &myself);
      if (drouter == NULL)
        drouter = bdrouter;
    }

  /* Set interface state accordingly (5) */
  if (drouter && drouter == &myself)
    next_state = OSPF6_INTERFACE_DR;
  else if (bdrouter && bdrouter == &myself)
    next_state = OSPF6_INTERFACE_BDR;
  else
    next_state = OSPF6_INTERFACE_DROTHER;

  /* If NBMA, schedule Start for each neighbor having priority of 0 (6) */
  /* XXX */

  /* If DR or BDR change, invoke AdjOK? for each neighbor (7) */
  /* RFC 2328 section 12.4. Originating LSAs (3) will be handled
     accordingly after AdjOK */
  if (oi->drouter != (drouter ? drouter->router_id : htonl (0)) ||
      oi->bdrouter != (bdrouter ? bdrouter->router_id : htonl (0)))
    {
      if (IS_OSPF6_DEBUG_INTERFACE)
        zlog_debug ("DR Election on %s: DR: %s BDR: %s", oi->interface->name,
		    (drouter ? drouter->name : "0.0.0.0"),
		    (bdrouter ? bdrouter->name : "0.0.0.0"));

      for (ALL_LIST_ELEMENTS_RO (oi->neighbor_list, node, on))
        {
          if (on->state < OSPF6_NEIGHBOR_TWOWAY)
            continue;
          /* Schedule AdjOK. */
          thread_add_event (master, adj_ok, on, 0);
        }
    }

  oi->drouter = (drouter ? drouter->router_id : htonl (0));
  oi->bdrouter = (bdrouter ? bdrouter->router_id : htonl (0));
  return next_state;
}

static u_int vlink_count = 0;

/* virtual link functions */

int
ospf6_vl_new (struct ospf6 *ospf6, struct ospf6_vl_data *vl_data, int format)
{
  struct interface * vi;
  char ifname[INTERFACE_NAMSIZ + 1];

  if (IS_OSPF6_DEBUG_INTERFACE)
    zlog_debug ("ospf6_vl_new : Start");
  if (vlink_count == OSPF6_VL_MAX_COUNT)
    {
      if (IS_OSPF6_DEBUG_INTERFACE)
        zlog_debug ("ospf6_vl_new : Alarm - "
                    "cannot create more than OSPF6_MAX_VL_COUNT virtual links");
      return 0;
    }

  if (IS_OSPF6_DEBUG_INTERFACE)
    zlog_debug ("ospf6_vl_new : creating pseudo zebra interface");

  snprintf (ifname, sizeof(ifname), "VLINK%d", vlink_count);
  vi = if_create (ifname, strnlen(ifname, sizeof(ifname)));

  vl_data->vl_oi = ospf6_interface_create (vi);
  if (vl_data->vl_oi == NULL)
    {
      if (IS_OSPF6_DEBUG_INTERFACE)
        zlog_debug ("ospf6_vl_new : Alarm - OSPF6 int structure is not created");
      return 0;
    }
  /* Back pointer to vl_data */
  vl_data->vl_oi->vl_data = vl_data;
  vl_data->vl_oi->ifmtu = OSPF6_VL_MTU;
  vl_data->vl_oi->nw_type = OSPF6_NWTYPE_VIRTUALLINK;

  vlink_count++;
  
  if (IS_OSPF6_DEBUG_INTERFACE)
    {
      zlog_debug ("ospf6_vl_new : Created name: %s",ifname);
      zlog_debug ("ospf6_vl_new : set if-name to %s",vi->name);
    }

  vl_data->vl_oi->area = ospf6_area_get (BACKBONE_AREA_ID, format,ospf6);

  if (IS_OSPF6_DEBUG_INTERFACE)
    zlog_debug ("ospf6_vl_new : set associated area to the backbone");

  listnode_add (vl_data->vl_oi->area->if_list, vl_data->vl_oi);

  if (IS_OSPF6_DEBUG_INTERFACE)
    zlog_debug ("ospf6_vl_new : Stop");

  return 1;
}

void 
ospf6_vl_down_check (struct ospf6_area *area, u_int32_t rid)
{
  struct listnode *node;
  struct ospf6_vl_data *vl_data;
 
  for (ALL_LIST_ELEMENTS_RO (area->vlink_list, node, vl_data))
    {
      if ( (IPV4_ADDR_SAME (&vl_data->vl_peer, &rid)) && 
            CHECK_FLAG (vl_data->flags, OSPF6_VL_FLAG_APPROVED))
        {
          UNSET_FLAG (vl_data->flags, OSPF6_VL_FLAG_APPROVED); 
          ospf6_vl_shutdown (vl_data);
        }
    }
}


void
ospf6_vl_up_check (struct ospf6_area *area, u_int32_t rid, int nexthop_ifindex, 
                   u_int32_t cost)
{
  struct listnode *node;
  struct ospf6_vl_data *vl_data;
  struct ospf6_interface *oi;
  struct ospf6 *ospf6 = area->ospf6;
  struct ospf6_area *backbone;
  char buf_aid[16],buf_rid[16];

  if (IS_OSPF6_DEBUG_INTERFACE)
    {
      zlog_debug ("ospf6_vl_up_check : Start");
      inet_ntop(AF_INET, &rid, buf_rid, sizeof (buf_rid));
      zlog_debug ("ospf6_vl_up_check : Router ID is %s", buf_rid);
      inet_ntop(AF_INET, &area->area_id, buf_aid, sizeof (buf_aid));
      zlog_debug ("ospf6_vl_up_check : Area is %s", buf_aid);
    }

  for (ALL_LIST_ELEMENTS_RO (area->vlink_list, node, vl_data))
    {
      if (IS_OSPF6_DEBUG_INTERFACE)
        {
          zlog_debug ("ospf6_vl_up_check : considering VL, name: %s", 
                      vl_data->vl_oi->interface->name);
          memset(buf_aid, 0, sizeof (buf_aid));
          inet_ntop(AF_INET, &vl_data->vl_area_id, buf_aid, sizeof (buf_aid));
          memset(buf_rid, 0, sizeof (buf_rid));
          inet_ntop(AF_INET, &vl_data->vl_peer, buf_rid, sizeof (buf_rid));
          zlog_debug ("ospf6_vl_up_check : VL area: %s, peer ID: %s", buf_aid, buf_rid);
        }

      if (IPV4_ADDR_SAME (&vl_data->vl_peer, &rid))
        {
          oi = vl_data->vl_oi;
          SET_FLAG (vl_data->flags, OSPF6_VL_FLAG_APPROVED);

          if (IS_OSPF6_DEBUG_INTERFACE)
            zlog_debug ("ospf6_vl_up_check : this VL matched - new");

          if (oi->state == OSPF6_INTERFACE_DOWN)
            {
              /* Get the global address for virtual link */
              oi->global_addr = ospf6_get_vlink_addr (nexthop_ifindex);
              if ( (oi->global_addr == NULL) || 
                    ! IN6_IS_ADDR_GLOBAL (oi->global_addr))
                {
                  if (IS_OSPF6_DEBUG_INTERFACE)
                    zlog_debug ("ospf6_vl_up_check : Global address is "
                                "not assigned, VLINK can't be up");
                  return;
                }         
              /* Include global address for VLINK */
              OSPF6_INTRA_PREFIX_LSA_SCHEDULE_STUB (area);
              
              /* Get the destination address for virtual link */
              vl_data->peer_addr = 
                ospf6_get_vlink_dst_addr (htons (OSPF6_LSTYPE_INTRA_PREFIX), 
                                          vl_data->vl_peer, area->lsdb);   
              if ( (vl_data->peer_addr == NULL) || 
                    ! IN6_IS_ADDR_GLOBAL (vl_data->peer_addr))
                {
                  if (IS_OSPF6_DEBUG_INTERFACE)
                    zlog_debug ("ospf6_vl_up_check : Destination address is "
                                "not reachable, VLINK can't be up");
                  return;
                }

              if (IS_OSPF6_DEBUG_INTERFACE)
                zlog_debug ("ospf6_vl_up_check : VL is down, waking it up - new");
              SET_FLAG (oi->interface->flags, IFF_UP);
              if (if_is_up (oi->interface))
                thread_add_event (master,interface_up, oi, 0);
              else
                thread_add_event (master,interface_down, oi, 0);
            }
           
          if (oi->cost != cost)
            {
              oi->cost = cost; 
              if (IS_OSPF6_DEBUG_INTERFACE)
                zlog_debug ("ospf6_vl_up_check : VL cost change, originating "
                            "router lsa for backbone");

              backbone = ospf6_area_lookup(BACKBONE_AREA_ID, ospf6);
              
              /* If the cost of the VLINK changed, originate a router lsa 
                 to the backbone */
              if (backbone != NULL)
                OSPF6_ROUTER_LSA_SCHEDULE(backbone);
              else if (IS_OSPF6_DEBUG_INTERFACE)
                zlog_debug ("ospf6_vl_up_check : VL cost change, no backbone!");
            }
        }
    }
}

/* Check the border router table and declare if any VLINK has to be up */
void ospf6_declare_vlinks_up (struct ospf6_area *oa)
{
  struct ospf6_route *broute;
  struct ospf6 *ospf6 = oa->ospf6;
 
  /* Unapprove all the VLINKs in this area */
  ospf6_vl_unapprove (oa);
 
  for (broute = ospf6_route_head (ospf6->brouter_table); broute;
       broute = ospf6_route_next (broute))
   {
     if ( (broute->type == OSPF6_DEST_TYPE_ROUTER) && 
          (broute->path.area_id == oa->area_id))
       { 
         ospf6_vl_up_check (oa, broute->path.origin.adv_router, 
                            broute->nexthop[0].ifindex, broute->path.cost);
         /* If V-bit is set,make the area as transit */
         if (CHECK_FLAG (broute->path.router_bits, OSPF6_ROUTER_BIT_V))
           SET_FLAG ((oa)->flag, OSPF6_AREA_TRANSIT);
       } 
   }
  
  /* Shut down all the unapproved VLINKs in this area */
  ospf6_vl_shut_unapproved (oa);
  
  return;
}

/* Get the address for virtual link */
struct in6_addr *
ospf6_get_vlink_addr (int ifindex)
{
  struct in6_addr *vl_src_addr = (struct in6_addr *)NULL;
  struct ospf6_interface *eth_oi;

  eth_oi = ospf6_interface_lookup_by_ifindex (ifindex);
  vl_src_addr = eth_oi->global_addr;

  return vl_src_addr;
}

/* Calculate the destination address (other end point's global address) for VLINK */
struct in6_addr *
ospf6_get_vlink_dst_addr (u_int16_t type, u_int32_t adv_router, 
                          struct ospf6_lsdb *lsdb)
{
  struct ospf6_lsa * lsa;
  struct ospf6_intra_prefix_lsa *intra_prefix_lsa;
  int prefixnum;
  struct ospf6_prefix *prefix;
  struct in6_addr *vl_peer_addr;
  char *start, *end, *current;
  int la_bit=0;
  char buf[128];

  lsa = ospf6_lsdb_type_router_head (type, adv_router, lsdb);
  while (lsa)
    {
      /* If the advertising router matches get the prefix */
      if (lsa->header->adv_router == adv_router)
        {
          intra_prefix_lsa = (struct ospf6_intra_prefix_lsa *)((caddr_t) 
                             lsa->header + sizeof (struct ospf6_lsa_header));

          prefixnum = ntohs (intra_prefix_lsa->prefix_num);

          start = (char *) intra_prefix_lsa + sizeof (struct ospf6_intra_prefix_lsa);
          end = (char *) lsa->header + ntohs (lsa->header->length);

          for (current = start; current < end; current += OSPF6_PREFIX_SIZE (prefix))
            {
              prefix = (struct ospf6_prefix *) current;
              if (prefix->prefix_length == 0 || 
                  current + OSPF6_PREFIX_SIZE (prefix) > end)
                break;

              la_bit = (CHECK_FLAG (prefix->prefix_options, 
                        OSPF6_PREFIX_OPTION_LA) ? 1 : 0);

              if (la_bit == 0)
                continue;

              /* If LA-bit is set then get the address */
              vl_peer_addr = (struct in6_addr *)malloc(sizeof(struct in6_addr));
              memset (vl_peer_addr,0, sizeof (struct in6_addr *));
              memcpy (vl_peer_addr, OSPF6_PREFIX_BODY (prefix), 
                      OSPF6_PREFIX_SPACE (prefix->prefix_length));

              inet_ntop (AF_INET6, vl_peer_addr, buf, sizeof (buf));
             
              if (IS_OSPF6_DEBUG_INTERFACE)
                zlog_debug ("ospf6_get_vlink_dst_addr : vl_peer_addr: %s",buf);
              return vl_peer_addr;
            }

        }
      lsa = ospf6_lsdb_type_router_next (type, adv_router, lsa);
    }
  
  return NULL;
}

void
ospf6_vl_unapprove (struct ospf6_area *area)         
{
  struct listnode *node;
  struct ospf6_vl_data *vl_data;

  for (ALL_LIST_ELEMENTS_RO (area->vlink_list, node, vl_data))
    UNSET_FLAG (vl_data->flags, OSPF6_VL_FLAG_APPROVED);
}

void
ospf6_vl_shut_unapproved (struct ospf6_area *area)   
{
  struct listnode *node;
  struct ospf6_vl_data *vl_data;

  for (ALL_LIST_ELEMENTS_RO (area->vlink_list, node, vl_data))
    if (! CHECK_FLAG (vl_data->flags, OSPF6_VL_FLAG_APPROVED))
      ospf6_vl_shutdown (vl_data);
}

void
ospf6_vl_shutdown (struct ospf6_vl_data *vl_data)
{
  struct ospf6_interface *oi;

  if ((oi = vl_data->vl_oi) == NULL)
    return;

  if (CHECK_FLAG (oi->interface->flags, IFF_UP))
    {
      oi->global_addr = (struct in6_addr *) NULL;
      vl_data->peer_addr = (struct in6_addr *) NULL;
      UNSET_FLAG (oi->interface->flags, IFF_UP);
      thread_execute (master, interface_down, oi, 0);
    }
   return;
}

void
ospf6_vl_data_free (struct ospf6_vl_data *vl_data)
{
  XFREE (MTYPE_OSPF_VL_DATA, vl_data);
}

void
ospf6_vl_delete (struct ospf6_area *area, struct ospf6_vl_data *vl_data)
{
  struct interface *ifp;

  if (! vl_data->vl_oi)
    return;

  ifp = vl_data->vl_oi->interface;

  vl_data->vl_oi->global_addr = (struct in6_addr *) NULL;
  vl_data->peer_addr = (struct in6_addr *) NULL;

  ospf6_interface_if_del (ospf6, ifp);
  if_delete (ifp);

  listnode_delete (area->vlink_list, vl_data);
  ospf6_vl_data_free (vl_data);
  vlink_count--;
}

struct ospf6_vl_data *
ospf6_vl_lookup (struct ospf6_area *area, u_int32_t vl_peer)
{
  struct ospf6_vl_data *vl_data;
  struct listnode *node;

  for (ALL_LIST_ELEMENTS_RO (area->vlink_list, node, vl_data))
    if (IPV4_ADDR_SAME (&vl_data->vl_peer, &vl_peer))
      return vl_data;

  return NULL;
}

struct ospf6_vl_data *
ospf6_vl_data_new (struct ospf6_area *area, u_int32_t vl_peer)
{
  struct ospf6_vl_data *vl_data;

  vl_data = XMALLOC (MTYPE_OSPF_VL_DATA, sizeof (struct ospf6_vl_data));
  memset (vl_data, 0, sizeof (struct ospf6_vl_data));

  vl_data->vl_peer = vl_peer;
  vl_data->vl_area_id = area->area_id;

  return vl_data;
}

int
if_is_virtual_link (struct interface *ifp)
{
  struct ospf6_interface *voi;
  if (ifp->info != NULL)
    {
      voi = (struct ospf6_interface *)ifp->info;
      if (voi->nw_type == OSPF6_NWTYPE_VIRTUALLINK) 
        return 1;
      else
        return 0;  
    }
  return 0;
}



/* Interface State Machine */
int
interface_up (struct thread *thread)
{
  struct ospf6_interface *oi;

  oi = (struct ospf6_interface *) THREAD_ARG (thread);
  assert (oi && oi->interface);

  if (IS_OSPF6_DEBUG_INTERFACE)
    zlog_debug ("Interface Event %s: [InterfaceUp]",
		oi->interface->name);

  /* check physical interface is up */
  if (! if_is_up (oi->interface))
    {
      if (IS_OSPF6_DEBUG_INTERFACE)
        zlog_debug ("Interface %s is down, can't execute [InterfaceUp]",
		    oi->interface->name);
      return 0;
    }

  /* if already enabled, do nothing */
  if (oi->state > OSPF6_INTERFACE_DOWN)
    {
      if (IS_OSPF6_DEBUG_INTERFACE)
        zlog_debug ("Interface %s already enabled",
		    oi->interface->name);
      return 0;
    }

  /* Join AllSPFRouters */
  /* For VLINK no need to join all spf routers.
     The OSPF packets have to go unicast on VLINK */
  if(oi->nw_type != OSPF6_NWTYPE_VIRTUALLINK)
    ospf6_join_allspfrouters (oi->interface->ifindex);

  /* Update interface route */
  ospf6_interface_connected_route_update (oi->interface);

  /* Schedule Hello */
  if (! CHECK_FLAG (oi->flag, OSPF6_INTERFACE_PASSIVE)) {
    THREAD_OFF(oi->thread_send_hello);
    oi->thread_send_hello =
      thread_add_event (master, ospf6_hello_send, oi, 0);
  }

  /* decide next interface state */
  if (if_is_pointopoint (oi->interface) || (oi->nw_type == OSPF6_NWTYPE_VIRTUALLINK))
    ospf6_interface_state_change (OSPF6_INTERFACE_POINTTOPOINT, oi);
  else if (oi->priority == 0)
    ospf6_interface_state_change (OSPF6_INTERFACE_DROTHER, oi);
  else
    {
      ospf6_interface_state_change (OSPF6_INTERFACE_WAITING, oi);
      THREAD_OFF(oi->thread_wait_timer);
      oi->thread_wait_timer =
        thread_add_timer (master, wait_timer, oi, oi->dead_interval);
    }

  return 0;
}

int
wait_timer (struct thread *thread)
{
  struct ospf6_interface *oi;

  oi = (struct ospf6_interface *) THREAD_ARG (thread);
  assert (oi && oi->interface);

  if (IS_OSPF6_DEBUG_INTERFACE)
    zlog_debug ("Interface Event %s: [WaitTimer]",
		oi->interface->name);

  oi->thread_wait_timer = NULL;

  if (oi->state == OSPF6_INTERFACE_WAITING)
    ospf6_interface_state_change (dr_election (oi), oi);

  return 0;
}

int
backup_seen (struct thread *thread)
{
  struct ospf6_interface *oi;

  oi = (struct ospf6_interface *) THREAD_ARG (thread);
  assert (oi && oi->interface);

  if (IS_OSPF6_DEBUG_INTERFACE)
    zlog_debug ("Interface Event %s: [BackupSeen]",
		oi->interface->name);

  if (oi->state == OSPF6_INTERFACE_WAITING)
    ospf6_interface_state_change (dr_election (oi), oi);

  return 0;
}

int
neighbor_change (struct thread *thread)
{
  struct ospf6_interface *oi;

  oi = (struct ospf6_interface *) THREAD_ARG (thread);
  assert (oi && oi->interface);

  if (IS_OSPF6_DEBUG_INTERFACE)
    zlog_debug ("Interface Event %s: [NeighborChange]",
		oi->interface->name);

  if (oi->state == OSPF6_INTERFACE_DROTHER ||
      oi->state == OSPF6_INTERFACE_BDR ||
      oi->state == OSPF6_INTERFACE_DR)
    ospf6_interface_state_change (dr_election (oi), oi);

  return 0;
}

int
loopind (struct thread *thread)
{
  struct ospf6_interface *oi;

  oi = (struct ospf6_interface *) THREAD_ARG (thread);
  assert (oi && oi->interface);

  if (IS_OSPF6_DEBUG_INTERFACE)
    zlog_debug ("Interface Event %s: [LoopInd]",
		oi->interface->name);

  /* XXX not yet */

  return 0;
}

int
interface_down (struct thread *thread)
{
  struct ospf6_interface *oi;
  struct listnode *node, *nnode;
  struct ospf6_neighbor *on;

  oi = (struct ospf6_interface *) THREAD_ARG (thread);
  assert (oi && oi->interface);

  if (IS_OSPF6_DEBUG_INTERFACE)
    zlog_debug ("Interface Event %s: [InterfaceDown]",
		oi->interface->name);

  /* Leave AllSPFRouters */
  if ((oi->nw_type != OSPF6_NWTYPE_VIRTUALLINK) && (oi->state > OSPF6_INTERFACE_DOWN))
    ospf6_leave_allspfrouters (oi->interface->ifindex);

  ospf6_interface_state_change (OSPF6_INTERFACE_DOWN, oi);

  for (ALL_LIST_ELEMENTS (oi->neighbor_list, node, nnode, on))
    ospf6_neighbor_delete (on);
  
  list_delete_all_node (oi->neighbor_list);

  return 0;
}


/* show specified interface structure */
int
ospf6_interface_show (struct vty *vty, struct interface *ifp)
{
  struct ospf6_interface *oi;
  struct connected *c;
  struct prefix *p;
  struct listnode *i;
  char strbuf[64], drouter[32], bdrouter[32];
  const char *updown[3] = {"down", "up", NULL};
  const char *type;
  struct timeval res, now;
  char duration[32];
  struct ospf6_lsa *lsa;
  char vl_addr[64];

  /* check physical interface type */
  if (if_is_loopback (ifp))
    type = "LOOPBACK";
  else if (if_is_broadcast (ifp))
    type = "BROADCAST";
  else if (if_is_pointopoint (ifp))
    type = "POINTOPOINT";
  else if (if_is_virtual_link (ifp))
    type = "VIRTUAL_LINK";
  else 
    type = "UNKNOWN";

  vty_out (vty, "%s is %s, type %s%s",
           ifp->name, updown[if_is_up (ifp)], type,
	   VNL);
  vty_out (vty, "  Interface ID: %d%s", ifp->ifindex, VNL);

  if (ifp->info == NULL)
    {
      vty_out (vty, "   OSPF not enabled on this interface%s", VNL);
      return 0;
    }
  else
    oi = (struct ospf6_interface *) ifp->info;

  vty_out (vty, "  Internet Address:%s", VNL);

  if (oi->nw_type == OSPF6_NWTYPE_VIRTUALLINK)
   {
     if (oi->global_addr)
       {
         inet_ntop (AF_INET6, oi->global_addr, vl_addr, sizeof(vl_addr));
         vty_out (vty, "    inet6: %s%s", vl_addr, VNL);
       }
     else
       vty_out (vty, "    inet6: 0%s", VNL);
   }

  for (ALL_LIST_ELEMENTS_RO (ifp->connected, i, c))
    {
      p = c->address;
      prefix2str (p, strbuf, sizeof (strbuf));
      switch (p->family)
        {
        case AF_INET:
          vty_out (vty, "    inet : %s%s", strbuf,
		   VNL);
          break;
        case AF_INET6:
          vty_out (vty, "    inet6: %s%s", strbuf,
		   VNL);
          break;
        default:
          vty_out (vty, "    ???  : %s%s", strbuf,
		   VNL);
          break;
        }
    }

  vty_out (vty, "  MTU system:%u, static:%u, advertised:%u%s",
                ifp->mtu, oi->static_mtu, OSPF6_MTU(oi), VTY_NEWLINE);
  vty_out (vty, "  MTU mismatch detection:%s%s",
                oi->mtu_ignore ? "disabled" : "enabled", VTY_NEWLINE);

  if (oi->area)
    {
      vty_out (vty, "  Instance ID %d, Interface MTU %d (autodetect: %d)%s",
	       oi->instance_id, oi->ifmtu, ifp->mtu6, VNL);

      if(oi->area->ai_format == OSPF6_AREA_ID_FORMAT_DECIMAL)
        vty_out (vty, "  Area ID %lu, Cost %hu%s", (unsigned long int) ntohl (oi->area->area_id), oi->cost,
	       VNL);
      else
        vty_out (vty, "  Area ID %s, Cost %hu%s", oi->area->name, oi->cost,
	       VNL);
    }
  else
    vty_out (vty, "  Not Attached to Area%s", VNL);

  vty_out (vty, "  State %s, Transmit Delay %d sec, Priority %d%s",
           ospf6_interface_state_str[oi->state],
           oi->transdelay, oi->priority,
	   VNL);

  if (CHECK_FLAG (oi->flag, OSPF6_INTERFACE_PASSIVE))
    vty_out (vty, "  Interface is Passive%s", VNL);
  else
    {
      vty_out (vty, "  Timer intervals configured:%s", VNL);
      vty_out (vty, "   Hello %d, Dead %d, Retransmit %d%s",
               oi->hello_interval, oi->dead_interval, oi->rxmt_interval,
	       VNL);

      if (oi->nw_type != OSPF6_NWTYPE_VIRTUALLINK)
        {
          inet_ntop (AF_INET, &oi->drouter, drouter, sizeof (drouter));
          inet_ntop (AF_INET, &oi->bdrouter, bdrouter, sizeof (bdrouter));
          vty_out (vty, "  DR: %s BDR: %s%s", drouter, bdrouter, VNL);
        }

      vty_out (vty, "  Number of I/F scoped LSAs is %u%s",
               oi->lsdb->count, VNL);

      gettimeofday (&now, (struct timezone *) NULL);

      timerclear (&res);
      if (oi->thread_send_lsupdate)
        timersub (&oi->thread_send_lsupdate->u.sands, &now, &res);
      timerstring (&res, duration, sizeof (duration));
      vty_out (vty, "    %d Pending LSAs for LSUpdate in Time %s [thread %s]%s",
               oi->lsupdate_list->count, duration,
               (oi->thread_send_lsupdate ? "on" : "off"),
               VNL);
      for (lsa = ospf6_lsdb_head (oi->lsupdate_list); lsa;
           lsa = ospf6_lsdb_next (lsa))
        vty_out (vty, "      %s%s", lsa->name, VNL);

      timerclear (&res);
      if (oi->thread_send_lsack)
        timersub (&oi->thread_send_lsack->u.sands, &now, &res);
      timerstring (&res, duration, sizeof (duration));
      vty_out (vty, "    %d Pending LSAs for LSAck in Time %s [thread %s]%s",
               oi->lsack_list->count, duration,
               (oi->thread_send_lsack ? "on" : "off"),
               VNL);
      for (lsa = ospf6_lsdb_head (oi->lsack_list); lsa;
           lsa = ospf6_lsdb_next (lsa))
        vty_out (vty, "      %s%s", lsa->name, VNL);
    }

  return 0;
}

/* show interface */
DEFUN (show_ipv6_ospf6_interface,
       show_ipv6_ospf6_interface_ifname_cmd,
       "show ipv6 ospf6 interface IFNAME",
       SHOW_STR
       IP6_STR
       OSPF6_STR
       INTERFACE_STR
       IFNAME_STR
       )
{
  struct interface *ifp;
  struct listnode *i;

  if (argc)
    {
      ifp = if_lookup_by_name (argv[0]);
      if (ifp == NULL)
        {
          vty_out (vty, "No such Interface: %s%s", argv[0],
                   VNL);
          return CMD_WARNING;
        }
      ospf6_interface_show (vty, ifp);
    }
  else
    {
      for (ALL_LIST_ELEMENTS_RO (iflist, i, ifp))
        ospf6_interface_show (vty, ifp);
    }

  return CMD_SUCCESS;
}

ALIAS (show_ipv6_ospf6_interface,
       show_ipv6_ospf6_interface_cmd,
       "show ipv6 ospf6 interface",
       SHOW_STR
       IP6_STR
       OSPF6_STR
       INTERFACE_STR
       )

DEFUN (show_ipv6_ospf6_interface_ifname_prefix,
       show_ipv6_ospf6_interface_ifname_prefix_cmd,
       "show ipv6 ospf6 interface IFNAME prefix",
       SHOW_STR
       IP6_STR
       OSPF6_STR
       INTERFACE_STR
       IFNAME_STR
       "Display connected prefixes to advertise\n"
       )
{
  struct interface *ifp;
  struct ospf6_interface *oi;

  ifp = if_lookup_by_name (argv[0]);
  if (ifp == NULL)
    {
      vty_out (vty, "No such Interface: %s%s", argv[0], VNL);
      return CMD_WARNING;
    }

  oi = ifp->info;
  if (oi == NULL)
    {
      vty_out (vty, "OSPFv3 is not enabled on %s%s", argv[0], VNL);
      return CMD_WARNING;
    }

  argc--;
  argv++;
  ospf6_route_table_show (vty, argc, argv, oi->route_connected);

  return CMD_SUCCESS;
}

ALIAS (show_ipv6_ospf6_interface_ifname_prefix,
       show_ipv6_ospf6_interface_ifname_prefix_detail_cmd,
       "show ipv6 ospf6 interface IFNAME prefix (X:X::X:X|X:X::X:X/M|detail)",
       SHOW_STR
       IP6_STR
       OSPF6_STR
       INTERFACE_STR
       IFNAME_STR
       "Display connected prefixes to advertise\n"
       OSPF6_ROUTE_ADDRESS_STR
       OSPF6_ROUTE_PREFIX_STR
       "Display details of the prefixes\n"
       )

ALIAS (show_ipv6_ospf6_interface_ifname_prefix,
       show_ipv6_ospf6_interface_ifname_prefix_match_cmd,
       "show ipv6 ospf6 interface IFNAME prefix X:X::X:X/M (match|detail)",
       SHOW_STR
       IP6_STR
       OSPF6_STR
       INTERFACE_STR
       IFNAME_STR
       "Display connected prefixes to advertise\n"
       OSPF6_ROUTE_PREFIX_STR
       OSPF6_ROUTE_MATCH_STR
       "Display details of the prefixes\n"
       )

DEFUN (show_ipv6_ospf6_interface_prefix,
       show_ipv6_ospf6_interface_prefix_cmd,
       "show ipv6 ospf6 interface prefix",
       SHOW_STR
       IP6_STR
       OSPF6_STR
       INTERFACE_STR
       "Display connected prefixes to advertise\n"
       )
{
  struct listnode *i;
  struct ospf6_interface *oi;
  struct interface *ifp;

  for (ALL_LIST_ELEMENTS_RO (iflist, i, ifp))
    {
      oi = (struct ospf6_interface *) ifp->info;
      if (oi == NULL)
        continue;

      ospf6_route_table_show (vty, argc, argv, oi->route_connected);
    }

  return CMD_SUCCESS;
}

ALIAS (show_ipv6_ospf6_interface_prefix,
       show_ipv6_ospf6_interface_prefix_detail_cmd,
       "show ipv6 ospf6 interface prefix (X:X::X:X|X:X::X:X/M|detail)",
       SHOW_STR
       IP6_STR
       OSPF6_STR
       INTERFACE_STR
       "Display connected prefixes to advertise\n"
       OSPF6_ROUTE_ADDRESS_STR
       OSPF6_ROUTE_PREFIX_STR
       "Display details of the prefixes\n"
       )

ALIAS (show_ipv6_ospf6_interface_prefix,
       show_ipv6_ospf6_interface_prefix_match_cmd,
       "show ipv6 ospf6 interface prefix X:X::X:X/M (match|detail)",
       SHOW_STR
       IP6_STR
       OSPF6_STR
       INTERFACE_STR
       "Display connected prefixes to advertise\n"
       OSPF6_ROUTE_PREFIX_STR
       OSPF6_ROUTE_MATCH_STR
       "Display details of the prefixes\n"
       )


/* interface variable set command */
DEFUN (ipv6_ospf6_ifmtu,
       ipv6_ospf6_ifmtu_cmd,
       "ipv6 ospf6 ifmtu <1-65535>",
       IP6_STR
       OSPF6_STR
       "Interface MTU\n"
       "OSPFv3 Interface MTU\n"
       )
{
  struct ospf6_interface *oi;
  struct interface *ifp;
  unsigned int ifmtu, iobuflen;
  struct listnode *node, *nnode;
  struct ospf6_neighbor *on;

  ifp = (struct interface *) vty->index;
  assert (ifp);

  oi = (struct ospf6_interface *) ifp->info;
  if (oi == NULL)
    oi = ospf6_interface_create (ifp);
  assert (oi);

  ifmtu = strtol (argv[0], NULL, 10);

  if (oi->ifmtu == ifmtu)
    return CMD_SUCCESS;

  if (ifp->mtu6 != 0 && ifp->mtu6 < ifmtu)
    {
      vty_out (vty, "%s's ospf6 ifmtu cannot go beyond physical mtu (%d)%s",
               ifp->name, ifp->mtu6, VNL);
      return CMD_WARNING;
    }

  if (oi->ifmtu < ifmtu)
    {
      iobuflen = ospf6_iobuf_size (ifmtu);
      if (iobuflen < ifmtu)
        {
          vty_out (vty, "%s's ifmtu is adjusted to I/O buffer size (%d).%s",
                   ifp->name, iobuflen, VNL);
          oi->ifmtu = iobuflen;
        }
      else
        oi->ifmtu = ifmtu;
    }
  else
    oi->ifmtu = ifmtu;

  /* re-establish adjacencies */
  for (ALL_LIST_ELEMENTS (oi->neighbor_list, node, nnode, on))
    {
      THREAD_OFF (on->inactivity_timer);
      thread_execute (master, inactivity_timer, on, 0);
    }

  return CMD_SUCCESS;
}

DEFUN (no_ipv6_ospf6_ifmtu,
       no_ipv6_ospf6_ifmtu_cmd,
       "no ipv6 ospf6 ifmtu",
       NO_STR
       IP6_STR
       OSPF6_STR
       "Interface MTU\n"
       )
{
  struct ospf6_interface *oi;
  struct interface *ifp;
  unsigned int iobuflen;
  struct listnode *node, *nnode;
  struct ospf6_neighbor *on;

  ifp = (struct interface *) vty->index;
  assert (ifp);

  oi = (struct ospf6_interface *) ifp->info;
  if (oi == NULL)
    oi = ospf6_interface_create (ifp);
  assert (oi);

  if (oi->ifmtu < ifp->mtu)
    {
      iobuflen = ospf6_iobuf_size (ifp->mtu);
      if (iobuflen < ifp->mtu)
        {
          vty_out (vty, "%s's ifmtu is adjusted to I/O buffer size (%d).%s",
                   ifp->name, iobuflen, VNL);
          oi->ifmtu = iobuflen;
        }
      else
        oi->ifmtu = ifp->mtu;
    }
  else
    oi->ifmtu = ifp->mtu;

  /* re-establish adjacencies */
  for (ALL_LIST_ELEMENTS (oi->neighbor_list, node, nnode, on))
    {
      THREAD_OFF (on->inactivity_timer);
      thread_execute (master, inactivity_timer, on, 0);
    }

  return CMD_SUCCESS;
}

/* interface variable set command */
DEFUN (ipv6_ospf6_mtu,
       ipv6_ospf6_mtu_cmd,
       "ipv6 ospf6 mtu MTU",
       IP6_STR
       OSPF6_STR
       "MTU advertised by OSPF\n"
       "<1-65535> Interface MTU\n"
       )
{
  struct ospf6_interface *oi;
  struct interface *ifp;
  u_int32_t mtu;

  ifp = (struct interface *) vty->index;
  assert (ifp);
  oi = (struct ospf6_interface *) ifp->info;
  if (!oi)
    oi = ospf6_interface_create (ifp);
  assert (oi);

  mtu = strtol (argv[0], NULL, 10);

  /* MTU range is <1-65535>. */
  if (mtu < 1 || mtu > 65535)
    {
      vty_out (vty, "MTU is invalid%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  oi->static_mtu = mtu;

  if (oi->area)
    ospf6_interface_state_change (dr_election (oi), oi);

  return CMD_SUCCESS;
}

/* interface variable set command */
DEFUN (no_ipv6_ospf6_mtu,
       no_ipv6_ospf6_mtu_cmd,
       "no ipv6 ospf6 mtu",
       NO_STR
       IP6_STR
       OSPF6_STR
       "Interface mtu\n"
       )
{
  struct ospf6_interface *oi;
  struct interface *ifp;

  ifp = (struct interface *) vty->index;
  assert (ifp);
  oi = (struct ospf6_interface *) ifp->info;
  if (!oi)
    oi = ospf6_interface_create (ifp);
  assert (oi);

  oi->static_mtu = 0;

  if (oi->area)
    ospf6_interface_state_change (dr_election (oi), oi);

  return CMD_SUCCESS;
}

/* interface variable set command */
DEFUN (ipv6_ospf6_mtu_ignore,
       ipv6_ospf6_mtu_ignore_cmd,
       "ipv6 ospf6 mtu-ignore",
       IP6_STR
       OSPF6_STR
       "Disable mtu mismatch detection\n"
       )
{
  struct ospf6_interface *oi;
  struct interface *ifp;

  ifp = (struct interface *) vty->index;
  assert (ifp);
  oi = (struct ospf6_interface *) ifp->info;
  if (!oi)
    oi = ospf6_interface_create (ifp);
  assert (oi);

  oi->mtu_ignore = 1;

  if (oi->area)
    ospf6_interface_state_change (dr_election (oi), oi);

  return CMD_SUCCESS;
}

/* interface variable set command */
DEFUN (no_ipv6_ospf6_mtu_ignore,
       no_ipv6_ospf6_mtu_ignore_cmd,
       "no ipv6 ospf6 mtu-ignore",
       NO_STR
       IP6_STR
       OSPF6_STR
       "Disable mtu mismatch detection\n"
       )
{
  struct ospf6_interface *oi;
  struct interface *ifp;

  ifp = (struct interface *) vty->index;
  assert (ifp);
  oi = (struct ospf6_interface *) ifp->info;
  if (!oi)
    oi = ospf6_interface_create (ifp);
  assert (oi);

  oi->mtu_ignore = 0;

  if (oi->area)
    ospf6_interface_state_change (dr_election (oi), oi);

  return CMD_SUCCESS;
}

/* interface variable unset command */
ALIAS (no_ipv6_ospf6_mtu,
       no_ipv6_ospf6_mtu_mtu_cmd,
       "no ipv6 ospf6 mtu MTU",
       NO_STR
       IP6_STR
       OSPF6_STR
       "Interface mtu\n"
       "<0-65535> mtu\n"
       )

DEFUN (ipv6_ospf6_cost,
       ipv6_ospf6_cost_cmd,
       "ipv6 ospf6 cost <1-65535>",
       IP6_STR
       OSPF6_STR
       "Interface cost\n"
       "Outgoing metric of this interface\n"
       )
{
  struct ospf6_interface *oi;
  struct interface *ifp;
  unsigned long int lcost;

  ifp = (struct interface *) vty->index;
  assert (ifp);

  oi = (struct ospf6_interface *) ifp->info;
  if (oi == NULL)
    oi = ospf6_interface_create (ifp);
  assert (oi);

  lcost = strtol (argv[0], NULL, 10);

  if (lcost > UINT32_MAX)
    {
      vty_out (vty, "Cost %ld is out of range%s", lcost, VNL);
      return CMD_WARNING;
    }
  
  /* Cost should not configured for a VLINK */
  if (oi->nw_type == OSPF6_NWTYPE_VIRTUALLINK)
    {
      vty_out (vty, "Cost cann't be configured for Virtual Links%s", VNL);
      return CMD_WARNING;
    }

  oi->cost_flag = OSPF6_INTERFACE_COST_CONFIGURED;

  ospf6_interface_update_cost (oi, lcost);

  return CMD_SUCCESS;
}

DEFUN (no_ipv6_ospf6_cost,
       no_ipv6_ospf6_cost_val_cmd,
       "no ipv6 ospf6 cost <1-65535>",
       NO_STR
       IP6_STR
       OSPF6_STR
       "Interface cost\n"
       "Configured interface cost\n"
       )
{
  struct ospf6_interface *oi;
  struct interface *ifp;
  u_int32_t newcost;

  ifp = (struct interface *) vty->index;
  assert (ifp);

  oi = (struct ospf6_interface *) ifp->info;
  if (oi == NULL)
    return CMD_SUCCESS;

  if (argc && (oi->cost != strtol (argv[0], NULL, 10)))
    {
      vty_out (vty, "%s is not the configured cost%s", argv[0], VNL);
      return CMD_WARNING;
    }

  oi->cost_flag = OSPF6_INTERFACE_COST_AUTO;

  newcost = ospf6_interface_get_cost (oi);
  ospf6_interface_update_cost (oi, newcost);

  return CMD_SUCCESS;
}

ALIAS (no_ipv6_ospf6_cost,
       no_ipv6_ospf6_cost_cmd,
       "no ipv6 ospf6 cost",
       NO_STR
       IP6_STR
       OSPF6_STR
       "Interface cost\n"
       )


DEFUN (ipv6_ospf6_hellointerval,
       ipv6_ospf6_hellointerval_cmd,
       "ipv6 ospf6 hello-interval <1-65535>",
       IP6_STR
       OSPF6_STR
       "Interval time of Hello packets\n"
       SECONDS_STR
       )
{
  struct ospf6_interface *oi;
  struct interface *ifp;

  ifp = (struct interface *) vty->index;
  assert (ifp);

  oi = (struct ospf6_interface *) ifp->info;
  if (oi == NULL)
    oi = ospf6_interface_create (ifp);
  assert (oi);

  oi->hello_interval = strtol (argv[0], NULL, 10);
  return CMD_SUCCESS;
}

DEFUN (no_ipv6_ospf6_hellointerval,
       no_ipv6_ospf6_hellointerval_cmd,
       "no ipv6 ospf6 hello-interval <1-65535>",
       NO_STR
       IP6_STR
       OSPF6_STR
       "Interval time of Hello packets\n"
       SECONDS_STR )
{
  struct ospf6_interface *oi;
  struct interface *ifp;

  ifp = (struct interface *) vty->index;
  assert (ifp);

  oi = (struct ospf6_interface *) ifp->info;
  if (oi == NULL)
    return CMD_SUCCESS;

  if (oi->hello_interval != strtol (argv[0], NULL, 10))
    {
      vty_out (vty, "%s is not the configured hello-interval%s", argv[0], VNL);
      return CMD_WARNING;
    }

  oi->hello_interval = DEFAULT_HELLO_INTERVAL; 
  return CMD_SUCCESS;
}

/* interface variable set command */
DEFUN (ipv6_ospf6_deadinterval,
       ipv6_ospf6_deadinterval_cmd,
       "ipv6 ospf6 dead-interval <1-65535>",
       IP6_STR
       OSPF6_STR
       "Interval time after which a neighbor is declared down\n"
       SECONDS_STR
       )
{
  struct ospf6_interface *oi;
  struct interface *ifp;

  ifp = (struct interface *) vty->index;
  assert (ifp);

  oi = (struct ospf6_interface *) ifp->info;
  if (oi == NULL)
    oi = ospf6_interface_create (ifp);
  assert (oi);

  oi->dead_interval = strtol (argv[0], NULL, 10);
  return CMD_SUCCESS;
}

DEFUN (no_ipv6_ospf6_deadinterval,
       no_ipv6_ospf6_deadinterval_cmd,
       "no ipv6 ospf6 dead-interval <1-65535>",
       NO_STR
       IP6_STR
       OSPF6_STR
       "Interval time after which a neighbor is declared down\n"
       SECONDS_STR)
{
  struct ospf6_interface *oi;
  struct interface *ifp;

  ifp = (struct interface *) vty->index;
  assert (ifp);

  oi = (struct ospf6_interface *) ifp->info;
  if (oi == NULL)
    return CMD_SUCCESS;

  if (oi->dead_interval != strtol (argv[0], NULL, 10))
    {
      vty_out (vty, "%s is not the configured dead-interval%s", argv[0], VNL);
      return CMD_WARNING;
    }

  oi->dead_interval = 40;
  return CMD_SUCCESS;
}

/* interface variable set command */
DEFUN (ipv6_ospf6_transmitdelay,
       ipv6_ospf6_transmitdelay_cmd,
       "ipv6 ospf6 transmit-delay <1-3600>",
       IP6_STR
       OSPF6_STR
       "Transmit delay of this interface\n"
       "<1-3600> Delay\n" 
       )
{
  struct ospf6_interface *oi;
  struct interface *ifp;

  ifp = (struct interface *) vty->index;
  assert (ifp);

  oi = (struct ospf6_interface *) ifp->info;
  if (oi == NULL)
    oi = ospf6_interface_create (ifp);
  assert (oi);

  oi->transdelay = strtol (argv[0], NULL, 10);
  return CMD_SUCCESS;
}

DEFUN (no_ipv6_ospf6_transmitdelay,
       no_ipv6_ospf6_transmitdelay_cmd,
       "no ipv6 ospf6 transmit-delay <1-3600>",
       NO_STR
       IP6_STR
       OSPF6_STR
       "Transmit delay of this interface\n"
       "<1-3600> Delay\n")
{
  struct ospf6_interface *oi;
  struct interface *ifp;

  ifp = (struct interface *) vty->index;
  assert (ifp);

  oi = (struct ospf6_interface *) ifp->info;
  if (oi == NULL)
    return CMD_SUCCESS;

  if (oi->transdelay != strtol (argv[0], NULL, 10))
    {
      vty_out (vty, "%s is not the configured transmit-delay%s", argv[0], VNL);
      return CMD_WARNING;
    }

  oi->transdelay = 1;
  return CMD_SUCCESS;
}

/* interface variable set command */
DEFUN (ipv6_ospf6_retransmitinterval,
       ipv6_ospf6_retransmitinterval_cmd,
       "ipv6 ospf6 retransmit-interval <1-65535>",
       IP6_STR
       OSPF6_STR
       "Time between retransmitting lost link state advertisements\n"
       SECONDS_STR
       )
{
  struct ospf6_interface *oi;
  struct interface *ifp;

  ifp = (struct interface *) vty->index;
  assert (ifp);

  oi = (struct ospf6_interface *) ifp->info;
  if (oi == NULL)
    oi = ospf6_interface_create (ifp);
  assert (oi);

  oi->rxmt_interval = strtol (argv[0], NULL, 10);
  return CMD_SUCCESS;
}

DEFUN (no_ipv6_ospf6_retransmitinterval,
       no_ipv6_ospf6_retransmitinterval_cmd,
       "no ipv6 ospf6 retransmit-interval <1-65535>",
       NO_STR
       IP6_STR
       OSPF6_STR
       "Time between retransmitting lost link state advertisements\n"
       SECONDS_STR)
{
  struct ospf6_interface *oi;
  struct interface *ifp;

  ifp = (struct interface *) vty->index;
  assert (ifp);

  oi = (struct ospf6_interface *) ifp->info;
  if (oi == NULL)
    return CMD_SUCCESS;

  if (oi->rxmt_interval != strtol (argv[0], NULL, 10))
    {
      vty_out (vty, "%s is not the configured retransmit-interval%s", argv[0], VNL);
      return CMD_WARNING;
    }

  oi->rxmt_interval = 5;
  return CMD_SUCCESS;
}

/* interface variable set command */
DEFUN (ipv6_ospf6_priority,
       ipv6_ospf6_priority_cmd,
       "ipv6 ospf6 priority <0-255>",
       IP6_STR
       OSPF6_STR
       "Router priority\n"
       "Priority value\n"
       )
{
  struct ospf6_interface *oi;
  struct interface *ifp;

  ifp = (struct interface *) vty->index;
  assert (ifp);

  oi = (struct ospf6_interface *) ifp->info;
  if (oi == NULL)
    oi = ospf6_interface_create (ifp);
  assert (oi);

  oi->priority = strtol (argv[0], NULL, 10);

  if (oi->area)
    ospf6_interface_state_change (dr_election (oi), oi);

  return CMD_SUCCESS;
}

DEFUN (no_ipv6_ospf6_priority,
       no_ipv6_ospf6_priority_cmd,
       "no ipv6 ospf6 priority <0-255>",
       NO_STR
       IP6_STR
       OSPF6_STR
       "Router priority\n"
       "Priority value\n")
{
  struct ospf6_interface *oi;
  struct interface *ifp;

  ifp = (struct interface *) vty->index;
  assert (ifp);

  oi = (struct ospf6_interface *) ifp->info;
  if (oi == NULL)
    return CMD_SUCCESS;

  if (oi->priority != strtol (argv[0], NULL, 10))
    {
      vty_out (vty, "%s is not the configured priority%s", argv[0], VNL);
      return CMD_WARNING;
    }

  oi->priority = 1;

  if (oi->area)
    ospf6_interface_state_change (dr_election (oi), oi);

  return CMD_SUCCESS;
}

DEFUN (ipv6_ospf6_instance,
       ipv6_ospf6_instance_cmd,
       "ipv6 ospf6 instance-id <0-255>",
       IP6_STR
       OSPF6_STR
       "Instance ID for this interface\n"
       "Instance ID value\n"
       )
{
  struct ospf6_interface *oi;
  struct interface *ifp;

  ifp = (struct interface *)vty->index;
  assert (ifp);

  oi = (struct ospf6_interface *)ifp->info;
  if (oi == NULL)
    oi = ospf6_interface_create (ifp);
  assert (oi);

  oi->instance_id = strtol (argv[0], NULL, 10);
  return CMD_SUCCESS;
}

DEFUN (ipv6_ospf6_passive,
       ipv6_ospf6_passive_cmd,
       "ipv6 ospf6 passive",
       IP6_STR
       OSPF6_STR
       "passive interface, No adjacency will be formed on this interface\n"
       )
{
  struct ospf6_interface *oi;
  struct interface *ifp;
  struct listnode *node, *nnode;
  struct ospf6_neighbor *on;

  ifp = (struct interface *) vty->index;
  assert (ifp);

  oi = (struct ospf6_interface *) ifp->info;
  if (oi == NULL)
    oi = ospf6_interface_create (ifp);
  assert (oi);

  SET_FLAG (oi->flag, OSPF6_INTERFACE_PASSIVE);
  THREAD_OFF (oi->thread_send_hello);

  for (ALL_LIST_ELEMENTS (oi->neighbor_list, node, nnode, on))
    {
      THREAD_OFF (on->inactivity_timer);
      thread_execute (master, inactivity_timer, on, 0);
    }

  return CMD_SUCCESS;
}

DEFUN (no_ipv6_ospf6_passive,
       no_ipv6_ospf6_passive_cmd,
       "no ipv6 ospf6 passive",
       NO_STR
       IP6_STR
       OSPF6_STR
       "passive interface: No Adjacency will be formed on this I/F\n"
       )
{
  struct ospf6_interface *oi;
  struct interface *ifp;

  ifp = (struct interface *) vty->index;
  assert (ifp);

  oi = (struct ospf6_interface *) ifp->info;
  if (oi == NULL)
    oi = ospf6_interface_create (ifp);
  assert (oi);

  UNSET_FLAG (oi->flag, OSPF6_INTERFACE_PASSIVE);
  THREAD_OFF (oi->thread_send_hello);
  oi->thread_send_hello =
    thread_add_event (master, ospf6_hello_send, oi, 0);

  return CMD_SUCCESS;
}

DEFUN (ipv6_ospf6_advertise_prefix_list,
       ipv6_ospf6_advertise_prefix_list_cmd,
       "ipv6 ospf6 advertise prefix-list WORD",
       IP6_STR
       OSPF6_STR
       "Advertising options\n"
       "Filter prefix using prefix-list\n"
       "Prefix list name\n"
       )
{
  struct ospf6_interface *oi;
  struct interface *ifp;

  ifp = (struct interface *) vty->index;
  assert (ifp);

  oi = (struct ospf6_interface *) ifp->info;
  if (oi == NULL)
    oi = ospf6_interface_create (ifp);
  assert (oi);

  if (oi->plist_name)
    XFREE (MTYPE_PREFIX_LIST_STR, oi->plist_name);
  oi->plist_name = XSTRDUP (MTYPE_PREFIX_LIST_STR, argv[0]);

  ospf6_interface_connected_route_update (oi->interface);
  OSPF6_LINK_LSA_SCHEDULE (oi);
  if (oi->state == OSPF6_INTERFACE_DR)
    {
      OSPF6_NETWORK_LSA_SCHEDULE (oi);
      OSPF6_INTRA_PREFIX_LSA_SCHEDULE_TRANSIT (oi);
    }
  OSPF6_INTRA_PREFIX_LSA_SCHEDULE_STUB (oi->area);

  return CMD_SUCCESS;
}

DEFUN (no_ipv6_ospf6_advertise_prefix_list,
       no_ipv6_ospf6_advertise_prefix_list_cmd,
       "no ipv6 ospf6 advertise prefix-list",
       NO_STR
       IP6_STR
       OSPF6_STR
       "Advertising options\n"
       "Filter prefix using prefix-list\n"
       )
{
  struct ospf6_interface *oi;
  struct interface *ifp;

  ifp = (struct interface *) vty->index;
  assert (ifp);

  oi = (struct ospf6_interface *) ifp->info;
  if (oi == NULL)
    oi = ospf6_interface_create (ifp);
  assert (oi);

  if (oi->plist_name)
    {
      XFREE (MTYPE_PREFIX_LIST_STR, oi->plist_name);
      oi->plist_name = NULL;
    }

  ospf6_interface_connected_route_update (oi->interface);
  OSPF6_LINK_LSA_SCHEDULE (oi);
  if (oi->state == OSPF6_INTERFACE_DR)
    {
      OSPF6_NETWORK_LSA_SCHEDULE (oi);
      OSPF6_INTRA_PREFIX_LSA_SCHEDULE_TRANSIT (oi);
    }
  OSPF6_INTRA_PREFIX_LSA_SCHEDULE_STUB (oi->area);

  return CMD_SUCCESS;
}

int
config_write_ospf6_interface (struct vty *vty)
{
  struct listnode *i;
  struct ospf6_interface *oi;
  struct interface *ifp;

  for (ALL_LIST_ELEMENTS_RO (iflist, i, ifp))
    {
      oi = (struct ospf6_interface *) ifp->info;
      if (oi == NULL)
        continue;

      /* Display only the non default settings.
       * The default settings are defined into 
       * ospf6_interface_create()
       */
      if ( (oi->cost == 1) &&
           (oi->hello_interval == DEFAULT_HELLO_INTERVAL) &&
	   (oi->static_mtu == 0) &&
	   (oi->mtu_ignore != 0) &&
	   (oi->dead_interval == DEFAULT_DEAD_INTERVAL) &&
	   (oi->rxmt_interval == DEFAULT_RETRANSMIT_INTERVAL) &&
	   (oi->priority == DEFAULT_PRIORITY) &&
	   (oi->transdelay == DEFAULT_TRANSMISSION_DELAY) &&
	   (oi->instance_id == DEFAULT_INSTANCE_ID) &&
	   !CHECK_FLAG (oi->flag, OSPF6_INTERFACE_PASSIVE ) )
	continue;

      vty_out (vty, "interface %s%s",
               oi->interface->name, VNL);

      if (ifp->desc)
        vty_out (vty, " description %s%s", ifp->desc, VNL);

      if (ifp->mtu6 != oi->ifmtu)
        vty_out (vty, " ipv6 ospf6 ifmtu %d%s", oi->ifmtu, VNL);

      if (oi->cost != 1 && oi->cost_flag == OSPF6_INTERFACE_COST_CONFIGURED)
        vty_out (vty, " ipv6 ospf6 cost %d%s", oi->cost, VNL);

      if (oi->static_mtu != 0)
      vty_out (vty, " ipv6 ospf6 mtu %u%s",
               oi->static_mtu, VNL);

      if (oi->mtu_ignore == 0)
      vty_out (vty, " no ipv6 ospf6 mtu-ignore%s",
               VNL);

      if (oi->hello_interval != DEFAULT_HELLO_INTERVAL)
      vty_out (vty, " ipv6 ospf6 hello-interval %d%s",
               oi->hello_interval, VNL);

      if (oi->dead_interval != DEFAULT_DEAD_INTERVAL)
      vty_out (vty, " ipv6 ospf6 dead-interval %d%s",
               oi->dead_interval, VNL);

      if (oi->rxmt_interval != DEFAULT_RETRANSMIT_INTERVAL)
      vty_out (vty, " ipv6 ospf6 retransmit-interval %d%s",
               oi->rxmt_interval, VNL);

      if (oi->priority != DEFAULT_PRIORITY)
      vty_out (vty, " ipv6 ospf6 priority %d%s",
               oi->priority, VNL);

      if (oi->transdelay != DEFAULT_TRANSMISSION_DELAY)
      vty_out (vty, " ipv6 ospf6 transmit-delay %d%s",
               oi->transdelay, VNL);

      if (oi->instance_id != DEFAULT_INSTANCE_ID)
      vty_out (vty, " ipv6 ospf6 instance-id %d%s",
               oi->instance_id, VNL);

      if (oi->plist_name)
        vty_out (vty, " ipv6 ospf6 advertise prefix-list %s%s",
                 oi->plist_name, VNL);

      if (CHECK_FLAG (oi->flag, OSPF6_INTERFACE_PASSIVE))
        vty_out (vty, " ipv6 ospf6 passive%s", VNL);

      vty_out (vty, "!%s", VNL);
    }
  return 0;
}

struct cmd_node interface_node =
{
  INTERFACE_NODE,
  "%s(config-if)# ",
  vtysh: 1
};

void
ospf6_interface_init ()
{
  /* Install interface node. */
  install_node (&interface_node, config_write_ospf6_interface);

  install_element (VIEW_NODE, &show_ipv6_ospf6_interface_cmd);
  install_element (VIEW_NODE, &show_ipv6_ospf6_interface_prefix_cmd);
  install_element (VIEW_NODE, &show_ipv6_ospf6_interface_prefix_detail_cmd);
  install_element (VIEW_NODE, &show_ipv6_ospf6_interface_prefix_match_cmd);
  install_element (VIEW_NODE, &show_ipv6_ospf6_interface_ifname_cmd);
  install_element (VIEW_NODE, &show_ipv6_ospf6_interface_ifname_prefix_cmd);
  install_element (VIEW_NODE, &show_ipv6_ospf6_interface_ifname_prefix_detail_cmd);
  install_element (VIEW_NODE, &show_ipv6_ospf6_interface_ifname_prefix_match_cmd);
  install_element (ENABLE_NODE, &show_ipv6_ospf6_interface_cmd);
  install_element (ENABLE_NODE, &show_ipv6_ospf6_interface_prefix_cmd);
  install_element (ENABLE_NODE, &show_ipv6_ospf6_interface_prefix_detail_cmd);
  install_element (ENABLE_NODE, &show_ipv6_ospf6_interface_prefix_match_cmd);
  install_element (ENABLE_NODE, &show_ipv6_ospf6_interface_ifname_cmd);
  install_element (ENABLE_NODE, &show_ipv6_ospf6_interface_ifname_prefix_cmd);
  install_element (ENABLE_NODE, &show_ipv6_ospf6_interface_ifname_prefix_detail_cmd);
  install_element (ENABLE_NODE, &show_ipv6_ospf6_interface_ifname_prefix_match_cmd);

  install_element (CONFIG_NODE, &interface_cmd);
  install_default (INTERFACE_NODE);
  install_element (INTERFACE_NODE, &interface_desc_cmd);
  install_element (INTERFACE_NODE, &no_interface_desc_cmd);
  install_element (INTERFACE_NODE, &ipv6_ospf6_cost_cmd);
  install_element (INTERFACE_NODE, &no_ipv6_ospf6_cost_cmd);
  install_element (INTERFACE_NODE, &no_ipv6_ospf6_cost_val_cmd);
  install_element (INTERFACE_NODE, &ipv6_ospf6_ifmtu_cmd);
  install_element (INTERFACE_NODE, &no_ipv6_ospf6_ifmtu_cmd);
  install_element (INTERFACE_NODE, &ipv6_ospf6_deadinterval_cmd);
  install_element (INTERFACE_NODE, &no_ipv6_ospf6_deadinterval_cmd);
  install_element (INTERFACE_NODE, &ipv6_ospf6_hellointerval_cmd);
  install_element (INTERFACE_NODE, &no_ipv6_ospf6_hellointerval_cmd);
  install_element (INTERFACE_NODE, &ipv6_ospf6_priority_cmd);
  install_element (INTERFACE_NODE, &no_ipv6_ospf6_priority_cmd);
  install_element (INTERFACE_NODE, &ipv6_ospf6_mtu_cmd);
  install_element (INTERFACE_NODE, &no_ipv6_ospf6_mtu_cmd);
  install_element (INTERFACE_NODE, &no_ipv6_ospf6_mtu_mtu_cmd);
  install_element (INTERFACE_NODE, &ipv6_ospf6_mtu_ignore_cmd);
  install_element (INTERFACE_NODE, &no_ipv6_ospf6_mtu_ignore_cmd);
  install_element (INTERFACE_NODE, &ipv6_ospf6_retransmitinterval_cmd);
  install_element (INTERFACE_NODE, &no_ipv6_ospf6_retransmitinterval_cmd);
  install_element (INTERFACE_NODE, &ipv6_ospf6_transmitdelay_cmd);
  install_element (INTERFACE_NODE, &no_ipv6_ospf6_transmitdelay_cmd);
  install_element (INTERFACE_NODE, &ipv6_ospf6_instance_cmd);

  install_element (INTERFACE_NODE, &ipv6_ospf6_passive_cmd);
  install_element (INTERFACE_NODE, &no_ipv6_ospf6_passive_cmd);

  install_element (INTERFACE_NODE, &ipv6_ospf6_advertise_prefix_list_cmd);
  install_element (INTERFACE_NODE, &no_ipv6_ospf6_advertise_prefix_list_cmd);
}

DEFUN (debug_ospf6_interface,
       debug_ospf6_interface_cmd,
       "debug ospf6 interface",
       DEBUG_STR
       OSPF6_STR
       "Debug OSPFv3 Interface\n"
      )
{
  OSPF6_DEBUG_INTERFACE_ON ();
  return CMD_SUCCESS;
}

DEFUN (no_debug_ospf6_interface,
       no_debug_ospf6_interface_cmd,
       "no debug ospf6 interface",
       NO_STR
       DEBUG_STR
       OSPF6_STR
       "Debug OSPFv3 Interface\n"
      )
{
  OSPF6_DEBUG_INTERFACE_OFF ();
  return CMD_SUCCESS;
}

int
config_write_ospf6_debug_interface (struct vty *vty)
{
  if (IS_OSPF6_DEBUG_INTERFACE)
    vty_out (vty, "debug ospf6 interface%s", VNL);
  return 0;
}

void
install_element_ospf6_debug_interface ()
{
  install_element (ENABLE_NODE, &debug_ospf6_interface_cmd);
  install_element (ENABLE_NODE, &no_debug_ospf6_interface_cmd);
  install_element (CONFIG_NODE, &debug_ospf6_interface_cmd);
  install_element (CONFIG_NODE, &no_debug_ospf6_interface_cmd);
}

void
ospf6_interface_run(struct ospf6 *o, const char *ifname, struct ospf6_area *oa)
{
  struct interface *ifp;
  struct listnode *node;
  int found = 0;

  /* Get target interface. */
  for (ALL_LIST_ELEMENTS_RO (iflist, node, ifp))
    {
      if (memcmp (ifp->name, "VLINK", 5) == 0)
        continue;

     /* interface already enabled */
     if (ifp->info && OSPF6_INTERFACE(ifp->info)->area)
        continue;

      /* if ifname matches, then activate ospf6 on the interface */
      if (ospf6_ifgroup_match(ifname, ifp->name))
        {
          ospf6_add_if_to_area(o, ifp, oa);
          found = 1;
        }
    }

  if (found)
    ospf6_router_id_update (o);
}

/*
 * OSPF6 has been disabled on a group of interfaces.
 * Find which ones and disable them.
 */
void
ospf6_if_update(struct ospf6 *o)
{
  struct interface *ifp;
  struct listnode *ifpnode;
  struct listnode *ifgroupnode;
  struct ospf6_ifgroup *ifgroup;
  struct ospf6_interface *oi;
  struct ospf6_area *oa;
  int    abr_previously;

  for (ALL_LIST_ELEMENTS_RO (iflist, ifpnode, ifp))
    {
      if (memcmp (ifp->name, "VLINK", 5) == 0)
        continue;

      oi = (struct ospf6_interface *)ifp->info;
      if (oi == NULL || oi->area == NULL)
        continue;

      for (ALL_LIST_ELEMENTS_RO (o->interfaces, ifgroupnode, ifgroup))
        {
          if (ospf6_ifgroup_match(ifgroup->ifname, ifp->name))
            break;
        }

      if (ifgroupnode == NULL)
        {
          thread_execute (master, interface_down, oi, 0);
          abr_previously = ospf6_is_router_abr (o);

          oa = oi->area;
          listnode_delete (oi->area->if_list, oi);
          oi->area = (struct ospf6_area *) NULL;
          /* Withdraw inter-area routes from this area, if necessary */
          if (oa->if_list->count == 0)
              UNSET_FLAG (oa->flag, OSPF6_AREA_ENABLE);

          if (abr_previously && ! ospf6_is_router_abr (o))
            {
              struct ospf6_area *oa_temp;
              struct listnode *node;

              for (ALL_LIST_ELEMENTS_RO (o->area_list, node, oa_temp))
                {
                  ospf6_abr_nssa_translator_state_update (oa_temp);
                  ospf6_abr_disable_area (oa_temp);
                }
            }
          else if (oa->if_list->count == 0)
            ospf6_abr_disable_area (oa);

          ospf6_interface_delete (oi);
        }
    }

  ospf6_router_id_update (o);
}

