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

#ifndef OSPF6_TOP_H
#define OSPF6_TOP_H

#include "routemap.h"
#ifdef SIM
#include "lib/zebra.h" //for ZEBRA_ROUTE_MAX
#endif //SIM
#ifdef OSPF6_MANET
#include "ospf6d.h" //for boolean
#endif //OSPF6_MANET

#ifdef SIM_ETRACE_STAT
typedef enum {
  OSPF6_HELLO_SENT = 0,
  OSPF6_HELLO_BYTE_SENT,
  OSPF6_DBDESC_SENT,
  OSPF6_DBDESC_BYTE_SENT,
  OSPF6_LSREQ_SENT,
  OSPF6_LSREQ_BYTE_SENT,
  OSPF6_LSACK_SENT,
  OSPF6_LSACK_BYTE_SENT,
  OSPF6_LSUPDATE_SENT,
  OSPF6_LSUPDATE_BYTE_SENT,
  OSPF6_LSUPDATE_MULTI_SENT,
  OSPF6_LSUPDATE_MULTI_BYTE_SENT,
  OSPF6_LSUPDATE_UNI_SENT,
  OSPF6_LSUPDATE_UNI_BYTE_SENT,
  OSPF6_LSUPDATE_UNI_COL_SENT,
  OSPF6_LSUPDATE_UNI_COL_BYTE_SENT,
  OSPF6_LSUPDATE_UNI_DBEX_SENT,
  OSPF6_LSUPDATE_UNI_DBEX_BYTE_SENT,
  OSPF6_LSUPDATE_UNI_STALE_SENT,
  OSPF6_LSUPDATE_UNI_STALE_BYTE_SENT,
  OSPF6_LSUPDATE_UNI_RXMT_SENT,
  OSPF6_LSUPDATE_UNI_RXMT_BYTE_SENT,

  OSPF6_CHANGE_OF_NUM_NEIGHS,
  OSPF6_DURATION_OF_NUM_NEIGHS,
  OSPF6_NUM_NEIGH_TIMES_DURATION_OF_NUM_NEIGHS,
  OSPF6_CHANGE_OF_NUM_ADJ,
  OSPF6_DURATION_OF_NUM_ADJ,
  OSPF6_NUM_ADJ_TIMES_DURATION_OF_NUM_ADJ,
  OSPF6_NEIGH_LIFETIME,
  OSPF6_NEIGH_DEATHS,
  OSPF6_DATABASE_EXCHANGES,
  OSPF6_NUM_LSA_DIFFS,

  OSPF6_DURATION_OF_NUM_RELSEL,
  OSPF6_NUM_RELSEL_TIMES_DURATION_OF_NUM_RELSEL,
  OSPF6_RELSEL_LIFETIME,
  OSPF6_RELSEL_DEATHS,
  OSPF6_LSA_FLOOD_RELAY,
  OSPF6_LSA_FLOOD_SUPPRESS,
  OSPF6_LSA_FLOOD_NONRELAY,
  OSPF6_ROUTER_LSA_INSTALL,
  OSPF6_ROUTER_LSA_HOPCOUNT,

  OSPF6_ORIG_RTR_LSA,
  OSPF6_ROUTE_CHANGES,
  OSPF6_ADJ_ACCUM,

  OSPF6_STAT_LENGTH
}ospf6_stats;
#endif //SIM_ETRACE_STAT

/* OSPFv3 top level data structure */
struct ospf6
{
  /* my router id */
  u_int32_t router_id;

  /* static router id */
  u_int32_t router_id_static;

  /* start time */
  struct timeval starttime;

  /* list of areas */
  struct list *area_list;

  /* AS scope link state database */
  struct ospf6_lsdb *lsdb;
  struct ospf6_lsdb *lsdb_self;

  struct ospf6_route_table *route_table;
  struct ospf6_route_table *brouter_table;

  struct ospf6_route_table *external_table;
  struct route_table *external_id_table;
  u_int32_t external_id;

  /* redistribute route-map */
  struct
  {
    char *name;
    struct route_map *map;
  } rmap[ZEBRA_ROUTE_MAX];

  u_char flag;

  struct thread *maxage_remover;
#ifdef SIM_ETRACE_STAT
  double statistics[OSPF6_STAT_LENGTH];
  long start_stat_time;
#endif //SIM_ETRACE_STAT
#ifdef OSPF6_CONFIG
  int minLSInterval;
  int minLSArrival;
#endif //OSPF6_CONFIG
};

#define OSPF6_DISABLED    0x01

/* global pointer for OSPF top data structure */
extern struct ospf6 *ospf6;

/* prototypes */
void ospf6_top_init ();

void ospf6_maxage_remove (struct ospf6 *o);

#ifdef SIM
void ospf6_delete (struct ospf6 *o);
void ospf6_disable (struct ospf6 *o);
void ospf6_enable (struct ospf6 *o);
#endif //SIM

#ifdef OSPF6_MANET
struct ospf6_pushback_neighbor
{
 /* Neighbor Router ID */
 u_int32_t router_id;

 /* Neighbor Interface ID */
 u_int32_t ifindex;
};
struct ospf6_neighbor;
struct ospf6_lsa;
struct ospf6_interface;
void ospf6_pushback_lsa_add(struct ospf6_lsa *lsa,
                            struct ospf6_neighbor *on);
void ospf6_pushback_lsa_neighbor_delete(struct ospf6_lsa *lsa,
                                        struct ospf6_neighbor *on);
void ospf6_pushback_lsa_delete(struct ospf6_lsa *lsa);
boolean ospf6_pushback_check_coverage(struct ospf6_lsa *lsa,
                                      struct ospf6_neighbor *on);
int ospf6_pushback_expiration (struct thread *thread);
void ospf6_refresh_lsa_pushback_list(struct ospf6_lsa *lsa);
long pushback_jitter(struct ospf6_interface *oi);
#endif //OSPF6_MANET
#ifdef SIM_ETRACE_STAT
void update_statistics(int, double);
#endif //SIM_ETRACE_STAT

#endif /* OSPF6_TOP_H */
