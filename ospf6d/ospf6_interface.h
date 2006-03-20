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

#include "if.h"

/****************************************************************************** 
 * Defines for OSPF6 Interface
 *****************************************************************************/

#define OSPF6_DEBUG_INTERFACE_ON() \
  (conf_debug_ospf6_interface = 1)
#define OSPF6_DEBUG_INTERFACE_OFF() \
  (conf_debug_ospf6_interface = 0)
#define IS_OSPF6_DEBUG_INTERFACE \
  (conf_debug_ospf6_interface)

/* rfc 3513, sec 2.4 - Address type identification */
#define IN6_IS_ADDR_GLOBAL(a)        \
  (! (IN6_IS_ADDR_UNSPECIFIED (a) || \
      IN6_IS_ADDR_LOOPBACK (a) ||    \
      IN6_IS_ADDR_MULTICAST (a) ||   \
      IN6_IS_ADDR_LINKLOCAL (a) ||   \
      IN6_IS_ADDR_SITELOCAL (a)))

/* Initialize address Addr, with the help of data structure DS and Type T */
#define ADDR_INIT(DS,Addr,T)              \
  do {                                    \
    if ((T) == OSPF6_NWTYPE_VIRTUALLINK)  \
      (Addr) = (&((DS)->global_addr));    \
    else                                  \
      (Addr) = (&((DS)->linklocal_addr)); \
  } while (0)

/* OSPF6 Interface defaults */
#define DEFAULT_INSTANCE_ID              0
#define DEFAULT_TRANSMISSION_DELAY       1
#define DEFAULT_PRIORITY                 1
#define DEFAULT_HELLO_INTERVAL           10
#define DEFAULT_DEAD_INTERVAL            40
#define DEFAULT_RETRANSMIT_INTERVAL      5

/* cost flags */
#define OSPF6_INTERFACE_COST_AUTO        0
#define OSPF6_INTERFACE_COST_CONFIGURED  1

/* network type for VLINK */
#define OSPF6_NWTYPE_VIRTUALLINK         9

/* Statically configured MTU */
#define OSPF6_MTU(oi) ((oi)->static_mtu ? (oi)->static_mtu : (oi)->ifmtu)

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

/* flags */
#define OSPF6_INTERFACE_DISABLE          0x01
#define OSPF6_INTERFACE_PASSIVE          0x02

#define OSPF6_IF_UP                      64

#define OSPF6_VL_MAX_COUNT               256
#define OSPF6_VL_FLAG_APPROVED           0x01
#define OSPF6_VL_MTU                     1500

/* Stale flags */
#define OSPF6_STALE_INTERFACE            0
#define OSPF6_STALE_NON_INTERFACE        1
#define OSPF6_STALE_LOCK                 2
#define OSPF6_STALE_UNLOCK               3


/****************************************************************************** 
 * External Variables
 *****************************************************************************/

/* Debug option */
extern unsigned char conf_debug_ospf6_interface;

extern const char *ospf6_interface_state_str[];


/****************************************************************************** 
 * Data Structures
 *****************************************************************************/

struct ospf6_interface;

/* virtual link data */
struct ospf6_vl_data
{
  u_int32_t vl_peer;                 /* Router-ID of the peer for VLs. */
  u_int32_t vl_area_id;              /* Transit area for this VL. */
  struct ospf6_interface *vl_oi;     /* Interface data structure for the VL. */
  struct in6_addr *peer_addr;        /* Address used to reach the peer. */
  u_char flags;
};

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

  /* copy of the linklocal address. lladdr is NULL or points on lladdr_copy */
  struct in6_addr lladdr_copy;

  /* Global address of this I/F */
  struct in6_addr *global_addr;

  /* Data for virtual link */
  struct ospf6_vl_data *vl_data;

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

  /* Cost configuration flag */
  char cost_flag;

  /* Cost */
  u_int32_t cost;
 
  /* network type for VLINK */
  u_char nw_type;

  /* I/F MTU */
  u_int32_t ifmtu;

  /* I/F statically configured MTU */
  u_int32_t static_mtu;         /* MTU advertised by OSPF */
  u_int8_t  mtu_ignore:1;       /* do not check neighbors' MTUs */

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

  struct thread *thread_wait_timer;

  struct thread *thread_network_lsa;
  struct thread *thread_link_lsa;
  struct thread *thread_intra_prefix_lsa;

  struct ospf6_route_table *route_connected;

  /* prefix-list name to filter connected prefix */
  char *plist_name;
};

struct ospf6_stale
{
  struct ospf6_route *stale;
  struct ospf6_nexthop *nexthop[2];
  int nh_count[2];
  int cost;

  /* Flag indicating current state of stale */
  u_char flag;
};

/* "interface IFNAME" command line entry */
struct ospf6_ifgroup
{
  /* Interface name. */
  char *ifname;

  /* Area ID. */
  u_int32_t area_id;
  int format;
};


/****************************************************************************** 
 * Function Prototypes
 *****************************************************************************/

struct ospf6_interface *ospf6_interface_lookup_by_ifindex (int);
struct ospf6_interface *ospf6_interface_create (struct interface *);
void ospf6_interface_delete (struct ospf6_interface *);

void ospf6_interface_enable (struct ospf6_interface *);
void ospf6_interface_disable (struct ospf6_interface *);

void ospf6_interface_if_add (struct ospf6 *, struct interface *);
void ospf6_interface_if_del (struct ospf6 *, struct interface *);
void ospf6_interface_state_update (struct interface *);
void ospf6_interface_connected_route_update (struct interface *);
void ospf6_interface_ecmp_nexthop_flush (struct ospf6_interface *,
                                         struct ospf6_route_table *);
u_int32_t ospf6_interface_get_cost (struct ospf6_interface *oi);
void ospf6_interface_update_cost (struct ospf6_interface *oi, u_int32_t newcost);
void ospf6_interface_recalculate_cost ();
struct ospf6_ifgroup * ospf6_ifgroup_new (const char *, u_int32_t,
                                                int);
void ospf6_ifgroup_free (struct ospf6 *, struct ospf6_ifgroup *);
int  ospf6_ifgroup_match (const char *, const char *);

void ospf6_interface_run (struct ospf6 *, const char *, struct ospf6_area *);
void ospf6_if_update (struct ospf6 *);

/* interface event */
int interface_up (struct thread *);
int interface_down (struct thread *);
int wait_timer (struct thread *);
int backup_seen (struct thread *);
int neighbor_change (struct thread *);

void ospf6_interface_init ();

int config_write_ospf6_debug_interface (struct vty *vty);
void install_element_ospf6_debug_interface ();

/* virtual link */
struct ospf6_vl_data *ospf6_vl_lookup (struct ospf6_area *, u_int32_t);
struct ospf6_vl_data * ospf6_vl_data_new (struct ospf6_area *, u_int32_t);
struct in6_addr *ospf6_get_vlink_src_addr(u_int32_t,struct ospf6 *);
struct in6_addr *ospf6_get_vlink_dst_addr(u_int16_t, u_int32_t, struct ospf6_lsdb *);
struct ospf6_vl_data *ospf6_get_vl_data (struct ospf6_area *,u_int32_t);
struct in6_addr *ospf6_get_vlink_addr (int);

int ospf6_vl_new (struct ospf6 *, struct ospf6_vl_data *, int);
int ospf6_vl_set_params (struct ospf6_vl_data *, struct ospf6_area *, u_int32_t cost);
int if_is_virtual_link (struct interface *ifp);

void ospf6_declare_vlinks_up (struct ospf6_area *);
void ospf6_vl_unapprove (struct ospf6_area *);
void ospf6_vl_shut_unapproved (struct ospf6_area *);
void ospf6_vl_shutdown (struct ospf6_vl_data *);
void ospf6_vl_delete (struct ospf6_area *, struct ospf6_vl_data *);
void ospf6_vl_up_check (struct ospf6_area *, u_int32_t, int, u_int32_t);
void ospf6_vl_down_check (struct ospf6_area *, u_int32_t);
#endif /* OSPF6_INTERFACE_H */

