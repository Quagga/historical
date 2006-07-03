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

#ifndef OSPF6_INTERFACE_H
#define OSPF6_INTERFACE_H

#ifdef SIM
#include "lib/if.h"
#include "ospf6d.h" //for boolean
#else
#include "if.h"
#endif //SIM

#ifdef OSPF6_MANET
#include "vty.h"
#endif //OSPF6_MANET

/* Debug option */
extern unsigned char conf_debug_ospf6_interface;
#define OSPF6_DEBUG_INTERFACE_ON() \
  (conf_debug_ospf6_interface = 1)
#define OSPF6_DEBUG_INTERFACE_OFF() \
  (conf_debug_ospf6_interface = 0)
#define IS_OSPF6_DEBUG_INTERFACE \
  (conf_debug_ospf6_interface)

#ifdef OSPF6_MANET_MDR_FLOOD
typedef enum {
  OSPF6_ADJ_FULLYCONNECTED = 0,
  OSPF6_ADJ_UNICONNECTED,
  OSPF6_ADJ_BICONNECTED
}ospf6_AdjConnectivity;

//How much information to include in LSAs
//These are defined in Ogier's draft, Appendix C
typedef enum {
  OSPF6_LSA_FULLNESS_MIN = 0,   //minimal LSAs (only adjacent neighbors)
  OSPF6_LSA_FULLNESS_MINHOP,      //partial LSAs for min-hop routing
  OSPF6_LSA_FULLNESS_MINHOP2PATHS, //same as above, with some path redundancy
  OSPF6_LSA_FULLNESS_MDRFULL,  //full LSAs from MDR/MBDRs
  OSPF6_LSA_FULLNESS_FULL       //full LSAs (all routable neighbors)
}ospf6_LSAFullness;
#endif //OSPF6_MANET_MDR_FLOOD

/* Interface structure */
struct ospf6_interface
{
  /* IF info from zebra */
  struct interface *interface;

  /* back pointer */
  struct ospf6_area *area;

  /* list of ospf6 neighbor */
  struct list *neighbor_list;

  /* linklocal address of this I/F */
  struct in6_addr *linklocal_addr;

  /* Interface ID; use interface->ifindex */

  /* ospf6 instance id */
  u_char instance_id;

  /* I/F transmission delay */
  u_int32_t transdelay;

  /* Router Priority */
  u_char priority;

  /* Time Interval */
  u_int16_t hello_interval;
  u_int16_t dead_interval;
  u_int32_t rxmt_interval;

  /* Cost */
  u_int32_t cost;

  /* I/F MTU */
  u_int32_t ifmtu;

  /* Interface State */
  u_char state;

  /* OSPF6 Interface flag */
  char flag;

  /* Decision of DR Election */
  u_int32_t drouter;
  u_int32_t bdrouter;
  u_int32_t prev_drouter;
  u_int32_t prev_bdrouter;

  /* Linklocal LSA Database: includes Link-LSA */
  struct ospf6_lsdb *lsdb;
  struct ospf6_lsdb *lsdb_self;

  struct ospf6_lsdb *lsupdate_list;
  struct ospf6_lsdb *lsack_list;

  /* Ongoing Tasks */
  struct thread *thread_send_hello;
  struct thread *thread_send_lsupdate;
  struct thread *thread_send_lsack;

  struct thread *thread_network_lsa;
  struct thread *thread_link_lsa;
  struct thread *thread_intra_prefix_lsa;

  struct ospf6_route_table *route_connected;

  /* prefix-list name to filter connected prefix */
  char *plist_name;

#ifdef SIM_ETRACE_STAT
  int num_2way_neigh;
  struct timeval neigh_2way_change_time;
  int num_full_neigh;
  struct timeval neigh_full_change_time;
  struct timeval relaysel_change_time;
#endif //SIM_ETRACE_STAT

#ifdef OSPF6_CONFIG
  /* OSPF6 Interface Type */
  u_char type;
  u_char flooding;
#endif //OSPF6_CONFIG

#ifdef OSPF6_DELAYED_FLOOD
  int flood_delay; //msec
#endif //OSPF6_DELAYED_FLOOD

#ifdef OSPF6_JITTER
  int jitter; //msec
#endif //defined(OSPF6_JITTER)

#ifdef OSPF6_MANET
  long ackInterval;
  int ack_cache_timeout;
  boolean diff_hellos;
#endif //OSPF6_MANET

#ifdef OSPF6_MANET_MPR_FLOOD
  long pushBackInterval;
  struct list *two_hop_list;
  struct list *relay_list;
  struct list *relay_sel_list;
  boolean mpr_change;

#ifdef OSPF6_MANET_MPR_SP
  boolean smart_peering;
  boolean unsynch_adj;
#endif //OSPF6_MANET_MPR_SP

#ifdef OSPF6_MANET_DIFF_HELLO
  struct list *drop_neighbor_list;
  u_int16_t scs_num;
  boolean increment_scs;
  boolean full_state;
  boolean initialization;
#ifdef OSPF6_MANET_MDR_LQ
  boolean link_quality;
#endif //OSPF6_MANET_MDR_LQ
#endif //OSPF6_MANET_DIFF_HELLO
#endif //OSPF6_MANET_MPR_FLOOD

#ifdef OSPF6_MANET_MDR_FLOOD
  long BackupWaitInterval;
  int **cost_matrix;
  int **lsa_cost_matrix;
  int AdjConnectivity; //1=uniconnected, 2=biconnected, 0=fully connected
  int LSAFullness; 
  int MDRConstraint; // MPN parameter h, should be 2 or 3.
  int mdr_level;
  int mdr_count;
  struct ospf6_neighbor *parent;
  struct ospf6_neighbor *bparent;
  u_int16_t TwoHopRefresh;
  u_int16_t HelloRepeatCount;
  boolean NonPersistentMDR;
  boolean full_adj_part_lsa;  // For full adjacencies with partial LSAs.
#ifdef OSPF6_MANET_DIFF_HELLO
  struct list *lnl;
  u_int16_t hsn;
  u_int full_hello_count;
#endif //OSPF6_MANET_DIFF_HELLO
#endif //OSPF6_MANET_MDR_FLOOD

};

#ifdef OSPF6_MANET_DIFF_HELLO
struct drop_neighbor
{
  u_int32_t router_id;
  struct timeval *expire_time;
 boolean first;
};
#endif //OSPF6_MANET_DIFF_HELLO

#ifdef OSPF6_MANET_MPR_FLOOD
struct ospf6_relay
{
  u_int32_t router_id;
  boolean newly_activated;
  boolean active;

  boolean drop;
  struct timeval *drop_expire_time;
};

struct ospf6_relay_selector
{
  u_int32_t router_id;
  struct timeval *expire_time;
#ifdef SIM_ETRACE_STAT
 struct timeval install_time;
#endif //SIM_ETRACE_STAT
};
#endif //OSPF6_MANET_MPR_FLOOD


#ifdef OSPF6_CONFIG
#define OSPF6_IFTYPE_NONE              0
#define OSPF6_IFTYPE_POINTOPOINT       1
#define OSPF6_IFTYPE_BROADCAST         2
#define OSPF6_IFTYPE_NBMA              3
#define OSPF6_IFTYPE_POINTOMULTIPOINT  4
#define OSPF6_IFTYPE_VIRTUALLINK       5
#define OSPF6_IFTYPE_LOOPBACK          6
#define OSPF6_IFTYPE_MANETRELIABLE     7
#define OSPF6_IFTYPE_MAX               8

typedef enum {
 OSPF6_FLOOD_BROADCAST = 0,
 OSPF6_FLOOD_MPR_SDCDS = 1,
 OSPF6_FLOOD_MDR_SICDS = 2
} ospf6_flooding_type;
#endif //OSPF6_CONFIG


/* interface state */
#define OSPF6_INTERFACE_NONE             0
#define OSPF6_INTERFACE_DOWN             1
#define OSPF6_INTERFACE_LOOPBACK         2
#define OSPF6_INTERFACE_WAITING          3
#define OSPF6_INTERFACE_POINTTOPOINT     4
#define OSPF6_INTERFACE_DROTHER          5
#define OSPF6_INTERFACE_BDR              6
#define OSPF6_INTERFACE_DR               7
#define OSPF6_INTERFACE_MAX              8

extern const char *ospf6_interface_state_str[];

/* flags */
#define OSPF6_INTERFACE_DISABLE      0x01
#define OSPF6_INTERFACE_PASSIVE      0x02


/* Function Prototypes */

struct ospf6_interface *ospf6_interface_lookup_by_ifindex (int);
struct ospf6_interface *ospf6_interface_lookup_by_name (char *);
struct ospf6_interface *ospf6_interface_create (struct interface *);
void ospf6_interface_delete (struct ospf6_interface *);

void ospf6_interface_enable (struct ospf6_interface *);
void ospf6_interface_disable (struct ospf6_interface *);

void ospf6_interface_if_add (struct interface *);
void ospf6_interface_if_del (struct interface *);
void ospf6_interface_state_update (struct interface *);
void ospf6_interface_connected_route_update (struct interface *);

/* interface event */
int interface_up (struct thread *);
int interface_down (struct thread *);
int wait_timer (struct thread *);
int backup_seen (struct thread *);
int neighbor_change (struct thread *);

void ospf6_interface_init ();

int config_write_ospf6_debug_interface (struct vty *vty);
void install_element_ospf6_debug_interface ();

#ifdef OSPF6_MANET_DIFF_HELLO
u_int16_t ospf6_increment_scs(u_int16_t scs_num);
#endif //OSPF6_MANET_DIFF_HELLO

#endif /* OSPF6_INTERFACE_H */

