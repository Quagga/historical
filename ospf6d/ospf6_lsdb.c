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

#include "memory.h"
#include "log.h"
#include "command.h"
#include "prefix.h"
#include "table.h"
#include "vty.h"

#include "ospf6_proto.h"
#include "ospf6_lsa.h"
#include "ospf6_lsdb.h"
#include "ospf6d.h"

#ifdef OSPF6_CONFIG
#include "ospf6_intra.h"
#ifdef SIM
#include "sim.h"
#endif //SIM
unsigned char conf_debug_ospf6_database = 0;
#endif //OSPF6_CONFIG

struct ospf6_lsdb *
ospf6_lsdb_create (void *data)
{
  struct ospf6_lsdb *lsdb;

  lsdb = (struct ospf6_lsdb *)
         XCALLOC (MTYPE_OSPF6_LSDB, sizeof (struct ospf6_lsdb));
  if (lsdb == NULL)
    {
      zlog_warn ("Can't malloc lsdb");
      return NULL;
    }
  memset (lsdb, 0, sizeof (struct ospf6_lsdb));

  lsdb->data = data;
  lsdb->table = route_table_init ();
  return lsdb;
}

void
ospf6_lsdb_delete (struct ospf6_lsdb *lsdb)
{
  ospf6_lsdb_remove_all (lsdb);
  route_table_finish (lsdb->table);
  XFREE (MTYPE_OSPF6_LSDB, lsdb);
}

static void
ospf6_lsdb_set_key (struct prefix_ipv6 *key, void *value, int len)
{
  assert (key->prefixlen % 8 == 0);

  memcpy ((caddr_t) &key->prefix + key->prefixlen / 8,
          (caddr_t) value, len);
  key->family = AF_INET6;
  key->prefixlen += len * 8;
}

#ifndef NDEBUG
static void
_lsdb_count_assert (struct ospf6_lsdb *lsdb)
{
  struct ospf6_lsa *debug;
  unsigned int num = 0;
  for (debug = ospf6_lsdb_head (lsdb); debug;
       debug = ospf6_lsdb_next (debug))
#ifdef OSPF6_MANET_TEMPORARY_LSDB
  {
    if (debug->cache == 0)
      num++;
  }
#else
    num++;
#endif //OSPF6_MANET_TEMPORARY_LSDB

  if (num == lsdb->count)
    return;

  zlog_debug ("PANIC !! lsdb[%p]->count = %d, real = %d",
             lsdb, lsdb->count, num);
  for (debug = ospf6_lsdb_head (lsdb); debug;
       debug = ospf6_lsdb_next (debug))
    zlog_debug ("%p %p %s lsdb[%p]", debug->prev, debug->next, debug->name,
               debug->lsdb);
  zlog_debug ("DUMP END");

  assert (num == lsdb->count);
}
#define ospf6_lsdb_count_assert(t) (_lsdb_count_assert (t))
#else /*NDEBUG*/
#define ospf6_lsdb_count_assert(t) ((void) 0)
#endif /*NDEBUG*/

void
ospf6_lsdb_add (struct ospf6_lsa *lsa, struct ospf6_lsdb *lsdb)
{
  struct prefix_ipv6 key;
  struct route_node *current, *nextnode, *prevnode;
  struct ospf6_lsa *next, *prev, *old = NULL;

  memset (&key, 0, sizeof (key));
#ifdef OSPF6_MANET_TEMPORARY_LSDB
  ospf6_lsdb_set_key (&key, &lsa->cache, sizeof (lsa->cache));
#endif //OSPF6_MANET_TEMPORARY_LSDB
  ospf6_lsdb_set_key (&key, &lsa->header->type, sizeof (lsa->header->type));
  ospf6_lsdb_set_key (&key, &lsa->header->adv_router,
                      sizeof (lsa->header->adv_router));
  ospf6_lsdb_set_key (&key, &lsa->header->id, sizeof (lsa->header->id));

  current = (struct route_node *)
            route_node_get (lsdb->table, (struct prefix *) &key);
  old = (struct ospf6_lsa *) current->info;
  current->info = lsa;
  ospf6_lsa_lock (lsa);

  if (old)
    {
      if (old->prev)
        old->prev->next = lsa;
      if (old->next)
        old->next->prev = lsa;
      lsa->next = old->next;
      lsa->prev = old->prev;
    }
  else
    {
      /* next link */
      nextnode = current;
      route_lock_node (nextnode);
      do {
        nextnode = route_next (nextnode);
      } while (nextnode && nextnode->info == NULL);
      if (nextnode == NULL)
        lsa->next = NULL;
      else
        {
          next = (struct ospf6_lsa *) nextnode->info;
          lsa->next = next;
          next->prev = lsa;
          route_unlock_node (nextnode);
        }

      /* prev link */
      prevnode = current;
      route_lock_node (prevnode);
      do {
        prevnode = route_prev (prevnode);
      } while (prevnode && prevnode->info == NULL);
      if (prevnode == NULL)
        lsa->prev = NULL;
      else
        {
          prev = (struct ospf6_lsa *) prevnode->info;
          lsa->prev = prev;
          prev->next = lsa;
          route_unlock_node (prevnode);
        }

#ifdef OSPF6_MANET_TEMPORARY_LSDB
      if (lsa->cache == 1)
        lsdb->count_cache++;
      else
        lsdb->count++;
#else
      lsdb->count++;
#endif //OSPF6_MANET_TEMPORARY_LSDB
    }

  if (old)
    {
      if (OSPF6_LSA_IS_CHANGED (old, lsa))
        {
          if (OSPF6_LSA_IS_MAXAGE (lsa))
            {
              if (lsdb->hook_remove)
                {
                  (*lsdb->hook_remove) (old);
                  (*lsdb->hook_remove) (lsa);
                }
            }
          else if (OSPF6_LSA_IS_MAXAGE (old))
            {
              if (lsdb->hook_add)
                (*lsdb->hook_add) (lsa);
            }
          else
            {
              if (lsdb->hook_remove)
                (*lsdb->hook_remove) (old);
              if (lsdb->hook_add)
                (*lsdb->hook_add) (lsa);
            }
        }
    }
  else if (OSPF6_LSA_IS_MAXAGE (lsa))
    {
      if (lsdb->hook_remove)
        (*lsdb->hook_remove) (lsa);
    }
  else
    {
      if (lsdb->hook_add)
        (*lsdb->hook_add) (lsa);
    }

  if (old)
    ospf6_lsa_unlock (old);

  ospf6_lsdb_count_assert (lsdb);
}

void
ospf6_lsdb_remove (struct ospf6_lsa *lsa, struct ospf6_lsdb *lsdb)
{
  struct route_node *node;
  struct prefix_ipv6 key;

  memset (&key, 0, sizeof (key));
#ifdef OSPF6_MANET_TEMPORARY_LSDB
  ospf6_lsdb_set_key (&key, &lsa->cache, sizeof (lsa->cache));
#endif //OSPF6_MANET_TEMPORARY_LSDB
  ospf6_lsdb_set_key (&key, &lsa->header->type, sizeof (lsa->header->type));
  ospf6_lsdb_set_key (&key, &lsa->header->adv_router,
                      sizeof (lsa->header->adv_router));
  ospf6_lsdb_set_key (&key, &lsa->header->id, sizeof (lsa->header->id));

  node = route_node_lookup (lsdb->table, (struct prefix *) &key);
  assert (node && node->info == lsa);

  if (lsa->prev)
    lsa->prev->next = lsa->next;
  if (lsa->next)
    lsa->next->prev = lsa->prev;

  node->info = NULL;

#ifdef OSPF6_MANET_TEMPORARY_LSDB
  if (lsa->cache == 1)
    lsdb->count_cache--;
  else
    lsdb->count--;
#else
  lsdb->count--;
#endif //OSPF6_MANET_TEMPORARY_LSDB

#ifdef BUGFIX
  if(lsa->expire) {
    THREAD_OFF(lsa->expire);
    lsa->expire=0;
  }
  if(lsa->refresh) {
    THREAD_OFF(lsa->refresh);
    lsa->refresh=0;
  }
#endif //BUGFIX

  if (lsdb->hook_remove)
    (*lsdb->hook_remove) (lsa);

  ospf6_lsa_unlock (lsa);
  route_unlock_node (node);

  ospf6_lsdb_count_assert (lsdb);
}

struct ospf6_lsa *
ospf6_lsdb_lookup (u_int16_t type, u_int32_t id, u_int32_t adv_router,
                   struct ospf6_lsdb *lsdb)
{
  struct route_node *node;
  struct prefix_ipv6 key;

  if (lsdb == NULL)
    return NULL;

  memset (&key, 0, sizeof (key));
#ifdef OSPF6_MANET_TEMPORARY_LSDB
  u_int16_t cache = 0;
  ospf6_lsdb_set_key (&key, &cache, sizeof (cache));
#endif //OSPF6_MANET_TEMPORARY_LSDB
  ospf6_lsdb_set_key (&key, &type, sizeof (type));
  ospf6_lsdb_set_key (&key, &adv_router, sizeof (adv_router));
  ospf6_lsdb_set_key (&key, &id, sizeof (id));

  node = route_node_lookup (lsdb->table, (struct prefix *) &key);
  if (node == NULL || node->info == NULL)
    return NULL;
  return (struct ospf6_lsa *) node->info;
}


#ifdef OSPF6_MANET_TEMPORARY_LSDB
struct ospf6_lsa *
ospf6_lsdb_lookup_cache (u_int16_t type, u_int32_t id, u_int32_t adv_router,
                   struct ospf6_lsdb *lsdb)
{
  struct route_node *node;
  struct prefix_ipv6 key;

  if (lsdb == NULL)
    return NULL;

  memset (&key, 0, sizeof (key));
  u_int16_t cache = 1;
  ospf6_lsdb_set_key (&key, &cache, sizeof (cache));
  ospf6_lsdb_set_key (&key, &type, sizeof (type));
  ospf6_lsdb_set_key (&key, &adv_router, sizeof (adv_router));
  ospf6_lsdb_set_key (&key, &id, sizeof (id));

  node = route_node_lookup (lsdb->table, (struct prefix *) &key);
  if (node == NULL || node->info == NULL)
    return NULL;
  return (struct ospf6_lsa *) node->info;
}
#endif //OSPF6_MANET_TEMPORARY_LSDB


/* Macro version of check_bit (). */
#define CHECK_BIT(X,P) ((((u_char *)(X))[(P) / 8]) >> (7 - ((P) % 8)) & 1)

struct ospf6_lsa *
ospf6_lsdb_lookup_next (u_int16_t type, u_int32_t id, u_int32_t adv_router,
                        struct ospf6_lsdb *lsdb)
{
  struct route_node *node;
  struct route_node *matched = NULL;
  struct prefix_ipv6 key;
  struct prefix *p;

  if (lsdb == NULL)
    return NULL;

  memset (&key, 0, sizeof (key));
#ifdef OSPF6_MANET_TEMPORARY_LSDB
  u_int16_t cache = 0;
  ospf6_lsdb_set_key (&key, &cache, sizeof (cache));
#endif //OSPF6_MANET_TEMPORARY_LSDB
  ospf6_lsdb_set_key (&key, &type, sizeof (type));
  ospf6_lsdb_set_key (&key, &adv_router, sizeof (adv_router));
  ospf6_lsdb_set_key (&key, &id, sizeof (id));

  p = (struct prefix *) &key;

  {
    char buf[64];
    prefix2str (p, buf, sizeof (buf));
    zlog_debug ("lsdb_lookup_next: key: %s", buf);
  }

  node = lsdb->table->top;
  /* walk down tree. */
  while (node && node->p.prefixlen <= p->prefixlen &&
         prefix_match (&node->p, p))
    {
      matched = node;
      node = node->link[CHECK_BIT(&p->u.prefix, node->p.prefixlen)];
    }

  if (matched)
    node = matched;
  else
    node = lsdb->table->top;
  route_lock_node (node);

  /* skip to real existing entry */
  while (node && node->info == NULL)
    node = route_next (node);

  if (! node)
    return NULL;

  if (prefix_same (&node->p, p))
    {
      struct route_node *prev = node;
      struct ospf6_lsa *lsa_prev;
      struct ospf6_lsa *lsa_next;

      node = route_next (node);
      while (node && node->info == NULL)
        node = route_next (node);

      lsa_prev = (struct ospf6_lsa *) prev->info;
      lsa_next = (struct ospf6_lsa *) (node ? node->info : NULL);
      assert (lsa_prev);
      assert (lsa_prev->next == lsa_next);
      if (lsa_next)
        assert (lsa_next->prev == lsa_prev);
      zlog_debug ("lsdb_lookup_next: assert OK with previous LSA");
    }

  if (! node)
    return NULL;

  route_unlock_node (node);
  return (struct ospf6_lsa *) node->info;
}

/* Iteration function */
struct ospf6_lsa *
ospf6_lsdb_head (struct ospf6_lsdb *lsdb)
{
  struct route_node *node;

  node = route_top (lsdb->table);
  if (node == NULL)
    return NULL;

  /* skip to the existing lsdb entry */
  while (node && node->info == NULL)
    node = route_next (node);
  if (node == NULL)
    return NULL;

  route_unlock_node (node);
  if (node->info)
    ospf6_lsa_lock ((struct ospf6_lsa *) node->info);
  return (struct ospf6_lsa *) node->info;
}

struct ospf6_lsa *
ospf6_lsdb_next (struct ospf6_lsa *lsa)
{
  struct ospf6_lsa *next = lsa->next;

  ospf6_lsa_unlock (lsa);
  if (next)
    ospf6_lsa_lock (next);

  return next;
}

struct ospf6_lsa *
ospf6_lsdb_type_router_head (u_int16_t type, u_int32_t adv_router,
                             struct ospf6_lsdb *lsdb)
{
  struct route_node *node;
  struct prefix_ipv6 key;
  struct ospf6_lsa *lsa;

  memset (&key, 0, sizeof (key));
#ifdef OSPF6_MANET_TEMPORARY_LSDB
  u_int16_t cache = 0;
  ospf6_lsdb_set_key (&key, &cache, sizeof (cache));
#endif //OSPF6_MANET_TEMPORARY_LSDB
  ospf6_lsdb_set_key (&key, &type, sizeof (type));
  ospf6_lsdb_set_key (&key, &adv_router, sizeof (adv_router));

  node = lsdb->table->top;

  /* Walk down tree. */
  while (node && node->p.prefixlen <= key.prefixlen &&
	 prefix_match (&node->p, (struct prefix *) &key))
    node = node->link[CHECK_BIT(&key.prefix, node->p.prefixlen)];

  if (node)
    route_lock_node (node);
  while (node && node->info == NULL)
    node = route_next (node);

  if (node == NULL)
    return NULL;
  else
    route_unlock_node (node);

  if (! prefix_match ((struct prefix *) &key, &node->p))
    return NULL;

  lsa = (struct ospf6_lsa *) node->info;
  ospf6_lsa_lock (lsa);

  return lsa;
}

struct ospf6_lsa *
ospf6_lsdb_type_router_next (u_int16_t type, u_int32_t adv_router,
                             struct ospf6_lsa *lsa)
{
  struct ospf6_lsa *next = lsa->next;

  if (next)
    {
      if (next->header->type != type ||
          next->header->adv_router != adv_router)
        next = NULL;
    }

  if (next)
    ospf6_lsa_lock (next);
  ospf6_lsa_unlock (lsa);
  return next;
}

struct ospf6_lsa *
ospf6_lsdb_type_head (u_int16_t type, struct ospf6_lsdb *lsdb)
{
  struct route_node *node;
  struct prefix_ipv6 key;
  struct ospf6_lsa *lsa;

  memset (&key, 0, sizeof (key));
#ifdef OSPF6_MANET_TEMPORARY_LSDB
  u_int16_t cache = 0;
  ospf6_lsdb_set_key (&key, &cache, sizeof (cache));
#endif //OSPF6_MANET_TEMPORARY_LSDB
  ospf6_lsdb_set_key (&key, &type, sizeof (type));

  /* Walk down tree. */
  node = lsdb->table->top;
  while (node && node->p.prefixlen <= key.prefixlen &&
	 prefix_match (&node->p, (struct prefix *) &key))
    node = node->link[CHECK_BIT(&key.prefix, node->p.prefixlen)];

  if (node)
    route_lock_node (node);
  while (node && node->info == NULL)
    node = route_next (node);

  if (node == NULL)
    return NULL;
  else
    route_unlock_node (node);

  if (! prefix_match ((struct prefix *) &key, &node->p))
    return NULL;

  lsa = (struct ospf6_lsa *) node->info;
  ospf6_lsa_lock (lsa);

  return lsa;
}

struct ospf6_lsa *
ospf6_lsdb_type_next (u_int16_t type, struct ospf6_lsa *lsa)
{
  struct ospf6_lsa *next = lsa->next;

  if (next)
    {
      if (next->header->type != type)
        next = NULL;
    }

  if (next)
    ospf6_lsa_lock (next);
  ospf6_lsa_unlock (lsa);
  return next;
}

void
ospf6_lsdb_remove_all (struct ospf6_lsdb *lsdb)
{
  struct ospf6_lsa *lsa;
  for (lsa = ospf6_lsdb_head (lsdb); lsa; lsa = ospf6_lsdb_next (lsa))
    ospf6_lsdb_remove (lsa, lsdb);
}

void
ospf6_lsdb_show (struct vty *vty, int level,
                 u_int16_t *type, u_int32_t *id, u_int32_t *adv_router,
                 struct ospf6_lsdb *lsdb)
{
  struct ospf6_lsa *lsa;
  void (*showfunc) (struct vty *, struct ospf6_lsa *) = NULL;

  if (level == OSPF6_LSDB_SHOW_LEVEL_NORMAL)
    showfunc = ospf6_lsa_show_summary;
  else if (level == OSPF6_LSDB_SHOW_LEVEL_DETAIL)
    showfunc = ospf6_lsa_show;
  else if (level == OSPF6_LSDB_SHOW_LEVEL_INTERNAL)
    showfunc = ospf6_lsa_show_internal;
  else if (level == OSPF6_LSDB_SHOW_LEVEL_DUMP)
    showfunc = ospf6_lsa_show_dump;

  if (type && id && adv_router)
    {
      lsa = ospf6_lsdb_lookup (*type, *id, *adv_router, lsdb);
      if (lsa)
        {
          if (level == OSPF6_LSDB_SHOW_LEVEL_NORMAL)
            ospf6_lsa_show (vty, lsa);
          else
            (*showfunc) (vty, lsa);
        }
      return;
    }

  if (level == OSPF6_LSDB_SHOW_LEVEL_NORMAL)
    ospf6_lsa_show_summary_header (vty);

  if (type && adv_router)
    lsa = ospf6_lsdb_type_router_head (*type, *adv_router, lsdb);
  else if (type)
    lsa = ospf6_lsdb_type_head (*type, lsdb);
  else
    lsa = ospf6_lsdb_head (lsdb);
  while (lsa)
    {
      if ((! adv_router || lsa->header->adv_router == *adv_router) &&
          (! id || lsa->header->id == *id))
        (*showfunc) (vty, lsa);

      if (type && adv_router)
        lsa = ospf6_lsdb_type_router_next (*type, *adv_router, lsa);
      else if (type)
        lsa = ospf6_lsdb_type_next (*type, lsa);
      else
        lsa = ospf6_lsdb_next (lsa);
    }
}

/* Decide new Link State ID to originate.
   note return value is network byte order */
u_int32_t
ospf6_new_ls_id (u_int16_t type, u_int32_t adv_router,
                 struct ospf6_lsdb *lsdb)
{
  struct ospf6_lsa *lsa;
  u_int32_t id = 1;

  for (lsa = ospf6_lsdb_type_router_head (type, adv_router, lsdb); lsa;
       lsa = ospf6_lsdb_type_router_next (type, adv_router, lsa))
    {
      if (ntohl (lsa->header->id) < id)
        continue;
      if (ntohl (lsa->header->id) > id)
        break;
      id++;
    }

  return ((u_int32_t) htonl (id));
}

/* Decide new LS sequence number to originate.
   note return value is network byte order */
u_int32_t
ospf6_new_ls_seqnum (u_int16_t type, u_int32_t id, u_int32_t adv_router,
                     struct ospf6_lsdb *lsdb)
{
  struct ospf6_lsa *lsa;
  signed long seqnum = 0;

  /* if current database copy not found, return InitialSequenceNumber */
  lsa = ospf6_lsdb_lookup (type, id, adv_router, lsdb);
  if (lsa == NULL)
    seqnum = INITIAL_SEQUENCE_NUMBER;
  else
    seqnum = (signed long) ntohl (lsa->header->seqnum) + 1;

  return ((u_int32_t) htonl (seqnum));
}

#ifdef OSPF6_CONFIG
DEFUN (debug_ospf6_database,
       debug_ospf6_database_cmd,
       "debug ospf6 database",
       DEBUG_STR
       OSPF6_STR
       "Dump ospf6 database\n"
      )
{
  unsigned char level = 0;
  level = OSPF6_DEBUG_DATABASE;
  OSPF6_DEBUG_DATABASE_ON (level);
  return CMD_SUCCESS;
}

DEFUN (no_debug_ospf6_database,
       no_debug_ospf6_database_cmd,
       "no debug ospf6 database",
       NO_STR
       DEBUG_STR
       OSPF6_STR
       "Dump ospf6 database\n"
      )
{
  unsigned char level = 0;
  level = OSPF6_DEBUG_DATABASE;
  OSPF6_DEBUG_DATABASE_OFF (level);
  return CMD_SUCCESS;
}

DEFUN (debug_ospf6_database_detail,
       debug_ospf6_database_detail_cmd,
       "debug ospf6 database detail",
       DEBUG_STR
       OSPF6_STR
       "Dump ospf6 database\n"
       "High detail\n"
      )
{
  unsigned char level = 0;
  level = OSPF6_DEBUG_DATABASE_DETAIL;
  OSPF6_DEBUG_DATABASE_ON (level);
  return CMD_SUCCESS;
}

DEFUN (no_debug_ospf6_database_detail,
       no_debug_ospf6_database_detail_cmd,
       "no debug ospf6 database detail",
       NO_STR
       DEBUG_STR
       OSPF6_STR
       "Dump ospf6 database\n"
       "High detail\n"
      )
{
  unsigned char level = 0;
  level = OSPF6_DEBUG_DATABASE_DETAIL;
  OSPF6_DEBUG_DATABASE_OFF (level);
  return CMD_SUCCESS;
}

void
install_element_ospf6_debug_database()
{
  install_element (ENABLE_NODE, &debug_ospf6_database_cmd);
  install_element (ENABLE_NODE, &debug_ospf6_database_detail_cmd);
  install_element (CONFIG_NODE, &debug_ospf6_database_cmd);
  install_element (CONFIG_NODE, &debug_ospf6_database_detail_cmd);
  install_element (ENABLE_NODE, &no_debug_ospf6_database_cmd);
  install_element (ENABLE_NODE, &no_debug_ospf6_database_detail_cmd);
  install_element (CONFIG_NODE, &no_debug_ospf6_database_cmd);
  install_element (CONFIG_NODE, &no_debug_ospf6_database_detail_cmd);
}

void
ospf6_debug_lsdb_show (int level, struct ospf6_lsdb *lsdb)
{
  struct ospf6_lsa *lsa;
  char adv_router[16], id[16];
  struct timeval now, res;
  char duration[16];
  int count = 0;

  zlog_debug("DUMPING DATABASE %p", lsdb);
  lsa = ospf6_lsdb_head (lsdb);
  while (lsa)
  {  
    assert(lsa);
    assert(lsa->header);

    inet_ntop (AF_INET, &lsa->header->id, id, sizeof (id));
    inet_ntop (AF_INET, &lsa->header->adv_router, adv_router,
             sizeof (adv_router));
#ifdef SIM
    gettimeofday_sim (&now, NULL);
#else
    gettimeofday (&now, NULL);
#endif //SIM
    timersub (&now, &lsa->installed, &res);
    timerstring (&res, duration, sizeof (duration));

    if (level == OSPF6_DEBUG_DATABASE)
    {
      zlog_debug ("%-12s %-15s %-15s %4hu %8lx %04hx %4hu %8s",
           ospf6_lstype_name (lsa->header->type),
           id, adv_router, ospf6_lsa_age_current (lsa),
           (u_long) ntohl (lsa->header->seqnum),
           ntohs (lsa->header->checksum), ntohs (lsa->header->length),
           duration);
    }
    else if (level == OSPF6_DEBUG_DATABASE_DETAIL)
	   {
      zlog_debug ("LSA %d", ++count); 
      zlog_debug(" Age: %4hu Type: %s", ospf6_lsa_age_current (lsa),
           ospf6_lstype_name (lsa->header->type));
      zlog_debug(" Link State ID: %s", id);
      zlog_debug(" Advertising Router: %s", adv_router);
      zlog_debug(" LS Sequence Number: %#010lx",
           (u_long) ntohl (lsa->header->seqnum));
      zlog_debug(" CheckSum: %#06hx Length: %hu",
           ntohs (lsa->header->checksum), ntohs (lsa->header->length));
      switch(ntohs(lsa->header->type))
      {
        case OSPF6_LSTYPE_ROUTER: 
          ospf6_debug_router_lsa_show(lsa);
          break;
        case OSPF6_LSTYPE_NETWORK:
          ospf6_debug_network_lsa_show(lsa);
          break;
        case OSPF6_LSTYPE_LINK:
          ospf6_debug_link_lsa_show(lsa);
          break;
        case OSPF6_LSTYPE_INTRA_PREFIX:
          ospf6_debug_intra_prefix_lsa_show(lsa);
          break;
        default:
          zlog_debug(" logging not implemented for LSA %s", lsa->name);
          break;
      }
    }
    else
    {
      zlog_debug("bad level when displaying database");
    }
    lsa = ospf6_lsdb_next (lsa);
  }
}

int
ospf6_debug_router_lsa_show (struct ospf6_lsa *lsa)
{
  char *start, *end, *current;
  char buf[32], name[32], bits[16], options[32];
  struct ospf6_router_lsa *router_lsa;
  struct ospf6_router_lsdesc *lsdesc;

  router_lsa = (struct ospf6_router_lsa *)
    ((char *) lsa->header + sizeof (struct ospf6_lsa_header));

  ospf6_capability_printbuf (router_lsa->bits, bits, sizeof (bits));
  ospf6_options_printbuf (router_lsa->options, options, sizeof (options));
  zlog_debug ("    Bits: %s Options: %s", bits, options);

  start = (char *) router_lsa + sizeof (struct ospf6_router_lsa);
  end = (char *) lsa->header + ntohs (lsa->header->length);
  for (current = start; current + sizeof (struct ospf6_router_lsdesc) <= end;
       current += sizeof (struct ospf6_router_lsdesc))
    {
      lsdesc = (struct ospf6_router_lsdesc *) current;

      if (lsdesc->type == OSPF6_ROUTER_LSDESC_POINTTOPOINT)
        snprintf (name, sizeof (name), "Point-To-Point");
      else if (lsdesc->type == OSPF6_ROUTER_LSDESC_TRANSIT_NETWORK)
        snprintf (name, sizeof (name), "Transit-Network");
      else if (lsdesc->type == OSPF6_ROUTER_LSDESC_STUB_NETWORK)
        snprintf (name, sizeof (name), "Stub-Network");
      else if (lsdesc->type == OSPF6_ROUTER_LSDESC_VIRTUAL_LINK)
        snprintf (name, sizeof (name), "Virtual-Link");
      else
        snprintf (name, sizeof (name), "Unknown (%#x)", lsdesc->type);

      zlog_debug ("    Type: %s Metric: %d",
               name, ntohs (lsdesc->metric));
      zlog_debug ("    Interface ID: %s",
               inet_ntop (AF_INET, &lsdesc->interface_id,
                          buf, sizeof (buf)));
      zlog_debug ("    Neighbor Interface ID: %s",
               inet_ntop (AF_INET, &lsdesc->neighbor_interface_id,
                          buf, sizeof (buf)));
      zlog_debug ("    Neighbor Router ID: %s",
               inet_ntop (AF_INET, &lsdesc->neighbor_router_id,
                          buf, sizeof (buf)));
    }
  return 0;
}

int ospf6_debug_network_lsa_show (struct ospf6_lsa *lsa)
{
  char *start, *end, *current;
  struct ospf6_network_lsa *network_lsa;
  struct ospf6_network_lsdesc *lsdesc;
  char buf[128], options[32];

  network_lsa = (struct ospf6_network_lsa *)
    ((caddr_t) lsa->header + sizeof (struct ospf6_lsa_header));

  ospf6_options_printbuf (network_lsa->options, options, sizeof (options));
  zlog_debug ("     Options: %s", options);

  start = (char *) network_lsa + sizeof (struct ospf6_network_lsa);
  end = (char *) lsa->header + ntohs (lsa->header->length);
  for (current = start; current + sizeof (struct ospf6_network_lsdesc) <= end;
       current += sizeof (struct ospf6_network_lsdesc))
    {
      lsdesc = (struct ospf6_network_lsdesc *) current;
      inet_ntop (AF_INET, &lsdesc->router_id, buf, sizeof (buf));
      zlog_debug ("     Attached Router: %s", buf);
    }
  return 0;
}

int ospf6_debug_link_lsa_show (struct ospf6_lsa *lsa)
{
  char *start, *end, *current;
  struct ospf6_link_lsa *link_lsa;
  int prefixnum;
  char buf[128], options[32];
  struct ospf6_prefix *prefix;
  const char *p, *mc, *la, *nu;
  struct in6_addr in6;

  link_lsa = (struct ospf6_link_lsa *)
    ((caddr_t) lsa->header + sizeof (struct ospf6_lsa_header));

  ospf6_options_printbuf (link_lsa->options, options, sizeof (options));
  inet_ntop (AF_INET6, &link_lsa->linklocal_addr, buf, sizeof (buf));
  prefixnum = ntohl (link_lsa->prefix_num);

  zlog_debug ("     Priority: %d Options: %s",
           link_lsa->priority, options);
  zlog_debug ("     LinkLocal Address: %s", buf);
  zlog_debug ("     Number of Prefix: %d", prefixnum);

  start = (char *) link_lsa + sizeof (struct ospf6_link_lsa);
  end = (char *) lsa->header + ntohs (lsa->header->length);
  for (current = start; current < end; current += OSPF6_PREFIX_SIZE (prefix))
    {
      prefix = (struct ospf6_prefix *) current;
      if (prefix->prefix_length == 0 ||
          current + OSPF6_PREFIX_SIZE (prefix) > end)
        break;

      p = (CHECK_FLAG (prefix->prefix_options, OSPF6_PREFIX_OPTION_P) ?
           "P" : "--");
      mc = (CHECK_FLAG (prefix->prefix_options, OSPF6_PREFIX_OPTION_MC) ?
           "MC" : "--");
      la = (CHECK_FLAG (prefix->prefix_options, OSPF6_PREFIX_OPTION_LA) ?
           "LA" : "--");
      nu = (CHECK_FLAG (prefix->prefix_options, OSPF6_PREFIX_OPTION_NU) ?
           "NU" : "--");
      zlog_debug ("     Prefix Options: %s|%s|%s|%s",
               p, mc, la, nu);

      memset (&in6, 0, sizeof (in6));
      memcpy (&in6, OSPF6_PREFIX_BODY (prefix),
              OSPF6_PREFIX_SPACE (prefix->prefix_length));
      inet_ntop (AF_INET6, &in6, buf, sizeof (buf));
      zlog_debug ("     Prefix: %s/%d",
               buf, prefix->prefix_length);
    }
  return 0;
}
int ospf6_debug_intra_prefix_lsa_show (struct ospf6_lsa *lsa)
{
  char *start, *end, *current;
  struct ospf6_intra_prefix_lsa *intra_prefix_lsa;
  int prefixnum;
  char buf[128];
  struct ospf6_prefix *prefix;
  char id[16], adv_router[16];
  const char *p, *mc, *la, *nu;
  struct in6_addr in6;

  intra_prefix_lsa = (struct ospf6_intra_prefix_lsa *)
    ((caddr_t) lsa->header + sizeof (struct ospf6_lsa_header));

  prefixnum = ntohs (intra_prefix_lsa->prefix_num);

  zlog_debug("     Number of Prefix: %d", prefixnum);

  inet_ntop (AF_INET, &intra_prefix_lsa->ref_id, id, sizeof (id));
  inet_ntop (AF_INET, &intra_prefix_lsa->ref_adv_router,
             adv_router, sizeof (adv_router));
  zlog_debug("     Reference: %s Id: %s Adv: %s",
           ospf6_lstype_name (intra_prefix_lsa->ref_type), id, adv_router);

  start = (char *) intra_prefix_lsa + sizeof (struct ospf6_intra_prefix_lsa);
  end = (char *) lsa->header + ntohs (lsa->header->length);
  for (current = start; current < end; current += OSPF6_PREFIX_SIZE (prefix))
    {
      prefix = (struct ospf6_prefix *) current;
      if (prefix->prefix_length == 0 ||
          current + OSPF6_PREFIX_SIZE (prefix) > end)
        break;

      p = (CHECK_FLAG (prefix->prefix_options, OSPF6_PREFIX_OPTION_P) ?
           "P" : "--");
      mc = (CHECK_FLAG (prefix->prefix_options, OSPF6_PREFIX_OPTION_MC) ?
           "MC" : "--");
      la = (CHECK_FLAG (prefix->prefix_options, OSPF6_PREFIX_OPTION_LA) ?
           "LA" : "--");
      nu = (CHECK_FLAG (prefix->prefix_options, OSPF6_PREFIX_OPTION_NU) ?
           "NU" : "--");
      zlog_debug ("     Prefix Options: %s|%s|%s|%s",
               p, mc, la, nu);

      memset (&in6, 0, sizeof (in6));
      memcpy (&in6, OSPF6_PREFIX_BODY (prefix),
              OSPF6_PREFIX_SPACE (prefix->prefix_length));
      inet_ntop (AF_INET6, &in6, buf, sizeof (buf));
      zlog_debug("     Prefix: %s/%d",  buf, prefix->prefix_length);
    }
  return 0;
}
#endif //OSPF6_CONFIG 
