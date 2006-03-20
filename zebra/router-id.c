/*
 * Router ID for zebra daemon.
 *
 * Copyright (C) 2004 James R. Leu 
 *
 * This file is part of Quagga routing suite.
 *
 * Quagga is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * Quagga is distributed in the hope that it will be useful, but
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

#include "if.h"
#include "vty.h"
#include "sockunion.h"
#include "prefix.h"
#include "stream.h"
#include "command.h"
#include "memory.h"
#include "ioctl.h"
#include "connected.h"
#include "network.h"
#include "log.h"
#include "table.h"
#include "rib.h"

#include "zebra/zserv.h"

static struct list rid_all_sorted_list;
static struct list rid_lo_sorted_list;
static struct list rid6_all_sorted_list;
static struct prefix rid_user_assigned;
struct prefix current_router_id =
{
  .u.prefix4.s_addr = 0,
  .family = AF_INET,
  .prefixlen = 32,
};

int router_id_cmp (void *a, void *b);
int router_id6_cmp (void *a, void *b);


/* master zebra server structure */
extern struct zebra_t zebrad;

static struct connected *
router_id_find_node (struct list *l, struct connected *ifc)
{
  struct listnode *node;
  struct connected *c;

  for (ALL_LIST_ELEMENTS_RO (l, node, c))
    if (prefix_same (ifc->address, c->address))
      return c;

  return NULL;
}

static int
router_id_bad_address (struct connected *ifc)
{
  struct prefix n;

  if (ifc->address->family != AF_INET)
  {
    /* Only linklocal is taken into account */
    if (!IN6_IS_ADDR_LINKLOCAL(&ifc->address->u.prefix6))
      return 1;
  }
  else
  {
    n.u.prefix4.s_addr = htonl (INADDR_LOOPBACK);
    n.prefixlen = 8;
    n.family = AF_INET;

    if (prefix_match (&n, ifc->address))
      return 1;
  }

  return 0;
}

void
router_id_get (struct prefix *p)
{
  struct listnode *node;
  struct connected *c;

  p->u.prefix4.s_addr = 0;
  p->family = AF_INET;
  p->prefixlen = 32;

  /* loopback is prior to IP address and IPv4 is prior to IPv6 */ 
  if (rid_user_assigned.u.prefix4.s_addr)
  {
    p->u.prefix4.s_addr = rid_user_assigned.u.prefix4.s_addr;
    zlog_info ("%s: get router-id from assigned one",__func__);
  }
  else if (!list_isempty (&rid_lo_sorted_list))
  {
    node = listtail (&rid_lo_sorted_list);
    c = listgetdata (node);
    p->u.prefix4.s_addr = c->address->u.prefix4.s_addr;
    zlog_info ("%s: get router-id from loopback interface",__func__);
  }
  else if (!list_isempty (&rid_all_sorted_list))
  {
    node = listtail (&rid_all_sorted_list);
    c = listgetdata (node);
    p->u.prefix4.s_addr = c->address->u.prefix4.s_addr;
    zlog_info ("%s: get router-id from ipv4 address",__func__);
  }
  else if (!list_isempty (&rid6_all_sorted_list))
  {
    node = listtail (&rid6_all_sorted_list);
    c = listgetdata (node);
    p->u.prefix4.s_addr = c->address->u.prefix6.s6_addr32[3];
    zlog_info ("%s: get router-id from ipv6 linklocal address",__func__);
  }
}

static void
router_id_set (struct prefix *p)
{
  struct prefix p2;
  struct listnode *node;
  struct zserv *client;

  rid_user_assigned.u.prefix4.s_addr = p->u.prefix4.s_addr;

  router_id_get (&p2);

  for (ALL_LIST_ELEMENTS_RO (zebrad.client_list, node, client))
    zsend_router_id_update (client, &p2);
}

void
router_id_add_address (struct connected *ifc)
{
  struct list *l = NULL;
  struct listnode *node;
#if 0
  struct prefix before;
#endif
  struct prefix after;
  struct zserv *client;

#if 0
  memset (&before, 0, sizeof (struct prefix));
#endif
  memset (&after, 0, sizeof (struct prefix));

 if (router_id_bad_address (ifc))
    return;

#if 0
  router_id_get (&before);
#endif

  if (ifc->address->family == AF_INET)
  {
    if (!strncmp (ifc->ifp->name, "lo", 2)
        || !strncmp (ifc->ifp->name, "dummy", 5))
      l = &rid_lo_sorted_list;
    else
      l = &rid_all_sorted_list;
  }
  else
      l = &rid6_all_sorted_list;
  
  if (!router_id_find_node (l, ifc))
    {
      if (ifc->address->family == AF_INET)
        l->cmp = router_id_cmp;
      else
        l->cmp = router_id6_cmp;
      listnode_add_sort (l, ifc);
    }

#if 0
  if(before.u.prefix4.s_addr)
    return;
  else
#endif
  {
    router_id_get (&after);
    memcpy(&current_router_id,&after,sizeof(struct prefix));
 
    for (ALL_LIST_ELEMENTS_RO (zebrad.client_list, node, client))
    {
      char buf[BUFSIZ];
      zlog_info ("%s: distribute router-id (%s) to all the clients",__func__, inet_ntop(AF_INET, &current_router_id.u.prefix4, buf, BUFSIZ));
      zsend_router_id_update (client, &current_router_id);
    }
  }
}

void
router_id_del_address (struct connected *ifc)
{
  struct connected *c;
  struct list *l;
  struct prefix after;
  struct listnode *node;
  struct zserv *client;

  if (router_id_bad_address (ifc))
    return;

  if (ifc->address->family == AF_INET)
  {
    if (!strncmp (ifc->ifp->name, "lo", 2)
        || !strncmp (ifc->ifp->name, "dummy", 5))
      l = &rid_lo_sorted_list;
    else
      l = &rid_all_sorted_list;
  }
  else
      l = &rid6_all_sorted_list;

  if ((c = router_id_find_node (l, ifc)))
    listnode_delete (l, c);

   if ((ifc->address->family == AF_INET && 
	ifc->address->u.prefix4.s_addr == current_router_id.u.prefix4.s_addr) ||
       (ifc->address->family == AF_INET6 &&
	ifc->address->u.prefix6.s6_addr32[3] == current_router_id.u.prefix4.s_addr))
   {
     memset (&after, 0, sizeof (struct prefix));
     router_id_get (&after);
     memcpy(&current_router_id,&after,sizeof(struct prefix));

     for (ALL_LIST_ELEMENTS_RO (zebrad.client_list, node, client))
     {
       char buf[BUFSIZ];
       zlog_info ("%s: distribute router-id (%s) to all the clients",__func__, inet_ntop(AF_INET, &current_router_id.u.prefix4, buf, BUFSIZ));
       zsend_router_id_update (client, &current_router_id);
     }
   }
}

void
router_id_write (struct vty *vty)
{
  if (rid_user_assigned.u.prefix4.s_addr)
    vty_out (vty, "router-id %s%s", inet_ntoa (rid_user_assigned.u.prefix4),
	     VTY_NEWLINE);
}

DEFUN (router_id,
       router_id_cmd,
       "router-id A.B.C.D",
       "Manually set the router-id\n"
       "IP address to use for router-id\n")
{
  struct prefix rid;

  rid.u.prefix4.s_addr = inet_addr (argv[0]);
  if (!rid.u.prefix4.s_addr)
    return CMD_WARNING;

  rid.prefixlen = 32;
  rid.family = AF_INET;

  router_id_set (&rid);

  return CMD_SUCCESS;
}

DEFUN (no_router_id,
       no_router_id_cmd,
       "no router-id",
       NO_STR
       "Remove the manually configured router-id\n")
{
  struct prefix rid;

  rid.u.prefix4.s_addr = 0;
  rid.prefixlen = 0;
  rid.family = AF_INET;

  router_id_set (&rid);

  return CMD_SUCCESS;
}

int
router_id_cmp (void *a, void *b)
{
  unsigned int A, B;

  A = ((struct connected *) a)->address->u.prefix4.s_addr;
  B = ((struct connected *) b)->address->u.prefix4.s_addr;

  if (A > B)
    return 1;
  else if (A < B)
    return -1;
  return 0;
}

int
router_id6_cmp (void *a, void *b)
{
  unsigned int A, B;

  A = ((struct connected *) a)->address->u.prefix6.s6_addr32[3];
  B = ((struct connected *) b)->address->u.prefix6.s6_addr32[3];

  if (A > B)
    return 1;
  else if (A < B)
    return -1;
  return 0;
}

void
router_id_init (void)
{
  install_element (CONFIG_NODE, &router_id_cmd);
  install_element (CONFIG_NODE, &no_router_id_cmd);

  memset (&rid_all_sorted_list, 0, sizeof (rid_all_sorted_list));
  memset (&rid_lo_sorted_list, 0, sizeof (rid_lo_sorted_list));
  memset (&rid6_all_sorted_list, 0, sizeof (rid6_all_sorted_list));
  memset (&rid_user_assigned, 0, sizeof (rid_user_assigned));

  rid_all_sorted_list.cmp = router_id_cmp;
  rid_lo_sorted_list.cmp = router_id_cmp;
  rid6_all_sorted_list.cmp = router_id6_cmp;

  rid_user_assigned.family = AF_INET;
  rid_user_assigned.prefixlen = 32;
}
