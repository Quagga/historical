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

#ifndef OSPF6_LSDB_H
#define OSPF6_LSDB_H

#include "prefix.h"
#include "table.h"

#ifdef BUGFIX
#include "ospf6_lsa.h"
#endif //BUGFIX

struct ospf6_lsdb
{
  void *data; /* data structure that holds this lsdb */
  struct route_table *table;
  u_int32_t count;
#ifdef OSPF6_MANET_TEMPORARY_LSDB
  u_int32_t count_cache;
#endif //OSPF6_MANET_TEMPORARY_LSDB
  void (*hook_add) (struct ospf6_lsa *);
  void (*hook_remove) (struct ospf6_lsa *);
};

#ifdef BUGFIX
//XXX BUG still present
//RFC 2328 chapter 14 paragraph 2 states the MaxAge LSA
//should be flooded
#define OSPF6_LSDB_MAXAGE_REMOVER(lsdb)                                  \
  do {                                                                   \
    struct ospf6_lsa *lsa;                                               \
    for (lsa = ospf6_lsdb_head (lsdb); lsa; lsa = ospf6_lsdb_next (lsa)) \
      {                                                                  \
        if (! OSPF6_LSA_IS_MAXAGE (lsa))                                 \
          continue;                                                      \
        if (lsa->retrans_count != 0)                                     \
          continue;                                                      \
        if (IS_OSPF6_DEBUG_LSA_TYPE (lsa->header->type))                 \
          zlog_debug ("Remove MaxAge %s", lsa->name);                    \
    /*    ospf6_flood(NULL, lsa);   */                                       \
        ospf6_lsdb_remove (lsa, lsdb);                                   \
      }                                                                  \
  } while (0)
#else
#define OSPF6_LSDB_MAXAGE_REMOVER(lsdb)                                  \
  do {                                                                   \
    struct ospf6_lsa *lsa;                                               \
    for (lsa = ospf6_lsdb_head (lsdb); lsa; lsa = ospf6_lsdb_next (lsa)) \
      {                                                                  \
        if (! OSPF6_LSA_IS_MAXAGE (lsa))                                 \
          continue;                                                      \
        if (lsa->retrans_count != 0)                                     \
          continue;                                                      \
        if (IS_OSPF6_DEBUG_LSA_TYPE (lsa->header->type))                 \
          zlog_debug ("Remove MaxAge %s", lsa->name);                    \
        ospf6_lsdb_remove (lsa, lsdb);                                   \
      }                                                                  \
  } while (0)
#endif //BUGFIX

/* Function Prototypes */
struct ospf6_lsdb *ospf6_lsdb_create (void *data);
void ospf6_lsdb_delete (struct ospf6_lsdb *lsdb);

struct ospf6_lsa *
ospf6_lsdb_lookup (u_int16_t type, u_int32_t id, u_int32_t adv_router,
                   struct ospf6_lsdb *lsdb);
#ifdef OSPF6_MANET_TEMPORARY_LSDB
struct ospf6_lsa *
ospf6_lsdb_lookup_cache (u_int16_t type, u_int32_t id, u_int32_t adv_router,
                   struct ospf6_lsdb *lsdb);
#endif //OSPF6_MANET_TEMPORARY_LSDB

struct ospf6_lsa *
ospf6_lsdb_lookup_next (u_int16_t type, u_int32_t id,
                        u_int32_t adv_router, struct ospf6_lsdb *lsdb);

void ospf6_lsdb_add (struct ospf6_lsa *lsa, struct ospf6_lsdb *lsdb);
void ospf6_lsdb_remove (struct ospf6_lsa *lsa, struct ospf6_lsdb *lsdb);

struct ospf6_lsa *ospf6_lsdb_head (struct ospf6_lsdb *lsdb);
struct ospf6_lsa *ospf6_lsdb_next (struct ospf6_lsa *lsa);

struct ospf6_lsa *ospf6_lsdb_type_router_head (u_int16_t type,
                                               u_int32_t adv_router,
                                               struct ospf6_lsdb *lsdb);
struct ospf6_lsa *ospf6_lsdb_type_router_next (u_int16_t type,
                                               u_int32_t adv_router,
                                               struct ospf6_lsa *lsa);

struct ospf6_lsa *ospf6_lsdb_type_head (u_int16_t type,
                                        struct ospf6_lsdb *lsdb);
struct ospf6_lsa *ospf6_lsdb_type_next (u_int16_t type,
                                        struct ospf6_lsa *lsa);

void ospf6_lsdb_remove_all (struct ospf6_lsdb *lsdb);

#define OSPF6_LSDB_SHOW_LEVEL_NORMAL   0
#define OSPF6_LSDB_SHOW_LEVEL_DETAIL   1
#define OSPF6_LSDB_SHOW_LEVEL_INTERNAL 2
#define OSPF6_LSDB_SHOW_LEVEL_DUMP     3

void ospf6_lsdb_show
  (struct vty *vty, int level,
   u_int16_t *type, u_int32_t *id, u_int32_t *adv_router,
   struct ospf6_lsdb *lsdb);

u_int32_t ospf6_new_ls_id
  (u_int16_t type, u_int32_t adv_router, struct ospf6_lsdb *lsdb);
u_int32_t ospf6_new_ls_seqnum
  (u_int16_t type, u_int32_t id, u_int32_t adv_router, struct ospf6_lsdb *lsdb);

#ifdef OSPF6_CONFIG
/* Debug option */
extern unsigned char conf_debug_ospf6_database;
#define OSPF6_DEBUG_DATABASE   0x01
#define OSPF6_DEBUG_DATABASE_DETAIL   0x02
#define OSPF6_DEBUG_DATABASE_ON(level) \
  (conf_debug_ospf6_database |= (level))
#define OSPF6_DEBUG_DATABASE_OFF(level) \
  (conf_debug_ospf6_database &= ~(level))
#define IS_OSPF6_DEBUG_DATABASE(level) \
  (conf_debug_ospf6_database & OSPF6_DEBUG_ ## level)

void install_element_ospf6_debug_database();
void ospf6_debug_lsdb_show (int level, struct ospf6_lsdb *lsdb);

int ospf6_debug_router_lsa_show (struct ospf6_lsa *lsa);
int ospf6_debug_network_lsa_show (struct ospf6_lsa *lsa);
int ospf6_debug_link_lsa_show (struct ospf6_lsa *lsa);
int ospf6_debug_intra_prefix_lsa_show (struct ospf6_lsa *lsa);


#endif //OSPF6_CONFIG

#endif /* OSPF6_LSDB_H */


