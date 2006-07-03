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

#ifndef OSPF6_NEIGHBOR_H
#define OSPF6_NEIGHBOR_H

#if defined(SIM) || defined(OSPF6_MANET)
#include "ospf6_message.h"
#endif //SIM

#ifdef OSPF6_MANET
#include "ospf6_lsa.h"
#endif //OSPF6_MANET

#ifdef OSPF6_MANET_MDR_FLOOD
#include "ospf6_lsdb.h"
#include "ospf6_mdr.h"
#endif //OSPF6_MANET_MDR_FLOOD

/* Debug option */
extern unsigned char conf_debug_ospf6_neighbor;
#define OSPF6_DEBUG_NEIGHBOR_STATE   0x01
#define OSPF6_DEBUG_NEIGHBOR_EVENT   0x02
#define OSPF6_DEBUG_NEIGHBOR_ON(level) \
  (conf_debug_ospf6_neighbor |= (level))
#define OSPF6_DEBUG_NEIGHBOR_OFF(level) \
  (conf_debug_ospf6_neighbor &= ~(level))
#define IS_OSPF6_DEBUG_NEIGHBOR(level) \
  (conf_debug_ospf6_neighbor & OSPF6_DEBUG_NEIGHBOR_ ## level)

/* Neighbor structure */
struct ospf6_neighbor
{
  /* Neighbor Router ID String */
  char name[32];

  /* OSPFv3 Interface this neighbor belongs to */
  struct ospf6_interface *ospf6_if;

  /* Neighbor state */
  u_char state;

  /* timestamp of last changing state */
  struct timeval last_changed;

  /* Neighbor Router ID */
  u_int32_t router_id;

  /* Neighbor Interface ID */
  u_int32_t ifindex;

  /* Router Priority of this neighbor */
  u_char priority;

  u_int32_t drouter;
  u_int32_t bdrouter;
  u_int32_t prev_drouter;
  u_int32_t prev_bdrouter;

  /* Options field (Capability) */
  char options[3];

  /* IPaddr of I/F on our side link */
  struct in6_addr linklocal_addr;

  /* For Database Exchange */
  u_char               dbdesc_bits;
  u_int32_t            dbdesc_seqnum;
  /* Last received Database Description packet */
  struct ospf6_dbdesc  dbdesc_last;

  /* LS-list */
  struct ospf6_lsdb *summary_list;
  struct ospf6_lsdb *request_list;
  struct ospf6_lsdb *retrans_list;

  /* LSA list for message transmission */
  struct ospf6_lsdb *dbdesc_list;
  struct ospf6_lsdb *lsreq_list;
  struct ospf6_lsdb *lsupdate_list;
  struct ospf6_lsdb *lsack_list;

  /* Inactivity timer */
  struct thread *inactivity_timer;

  /* Thread for sending message */
  struct thread *thread_send_dbdesc;
  struct thread *thread_send_lsreq;
  struct thread *thread_send_lsupdate;
  struct thread *thread_send_lsack;

#ifdef OSPF6_MANET
  struct list *mack_list;
  boolean routable;
#endif //OSPF6_MANET

#ifdef OSPF6_MANET_MPR_FLOOD
  struct list *two_hop_neighbor_list;
  boolean covered;
  boolean Fbit;
  boolean Relay_Abit;
  boolean Relay_Nbit;
#endif //OSPF6_MANET_MPR_FLOOD

#ifdef OSPF6_MANET_DIFF_HELLO
  boolean below_exchange; // Chandra03 3.3.6.1 bullet 3
  u_int16_t scs_num;  //Chandra03 3.3.8 paragraph 1
  boolean set_scs_num;
  boolean request;
#endif //OSPF6_MANET_DIFF_HELLO

#ifdef OSPF6_MANET_MDR_FLOOD
  //New neighbor variables.
  boolean dependent;
  boolean dependent_selector;
  boolean adv; // advertised neighbor
  boolean new_adv;
  struct list *rnl;  // List of router IDs.
  struct list *lnl;
  struct ospf6_neighbor *parent;
  int hops;
  int hops2;
  struct tree_node *treenode;
  boolean child;
  boolean Report2Hop;
  boolean reverse_2way;
  int mdr_level;
  struct timeval mdr_install_time;
  int cost_matrix_index;  
#ifdef OSPF6_MANET_MDR_LQ
  boolean link_quality[3];
#endif //OSPF6_MANET_MDR_LQ
#ifdef OSPF6_MANET_DIFF_HELLO
  u_int16_t hsn;
  u_int16_t changed_hsn;
#endif //OSPF6_MANET_DIFF_HELLO
#endif //OSPF6_MANET_MDR_FLOOD

#ifdef SIM //ETRACE
  struct timeval creation_time;
#endif //SIM

};

#ifdef OSPF6_MANET
struct ospf6_mack
{
  u_int16_t age;           /* LS age */
  u_int16_t type;          /* LS type */
  u_int32_t id;            /* Link State ID */
  u_int32_t adv_router;    /* Advertising Router */
  u_int32_t seqnum;        /* LS sequence number */
  struct timeval *expire_time;
};

#ifdef OSPF6_MANET_MPR_FLOOD
struct ospf6_2hop_neighbor
{
  u_int32_t router_id;
  boolean covered;
  boolean updated;
  struct list *one_hop_neighbor_list;
};
#endif //OSPF6_MANET_MPR_FLOOD

#if defined(OSPF6_MANET_MDR_FLOOD) && defined(OSPF6_MANET_DIFF_HELLO)
struct ospf6_lnl_element
{
  u_int32_t id;
  u_int16_t hsn; 
};
#endif //OSPF6_MANET_DIFF_HELLO && OSPF6_MANET_MDR_FLOOD

#endif //OSPF6_MANET


/* Neighbor state */
#define OSPF6_NEIGHBOR_DOWN     1
#define OSPF6_NEIGHBOR_ATTEMPT  2
#define OSPF6_NEIGHBOR_INIT     3
#define OSPF6_NEIGHBOR_TWOWAY   4
#define OSPF6_NEIGHBOR_EXSTART  5
#define OSPF6_NEIGHBOR_EXCHANGE 6
#define OSPF6_NEIGHBOR_LOADING  7
#define OSPF6_NEIGHBOR_FULL     8

const extern char *ospf6_neighbor_state_str[];


/* Function Prototypes */
int ospf6_neighbor_cmp (void *va, void *vb);
void ospf6_neighbor_dbex_init (struct ospf6_neighbor *on);

struct ospf6_neighbor *ospf6_neighbor_lookup (u_int32_t,
                                              struct ospf6_interface *);
struct ospf6_neighbor *ospf6_neighbor_create (u_int32_t,
                                              struct ospf6_interface *);
void ospf6_neighbor_delete (struct ospf6_neighbor *);

/* Neighbor event */
int hello_received (struct thread *);
int twoway_received (struct thread *);
int negotiation_done (struct thread *);
int exchange_done (struct thread *);
int loading_done (struct thread *);
int adj_ok (struct thread *);
int seqnumber_mismatch (struct thread *);
int bad_lsreq (struct thread *);
int oneway_received (struct thread *);
int inactivity_timer (struct thread *);

void ospf6_neighbor_init ();
int config_write_ospf6_debug_neighbor (struct vty *vty);
void install_element_ospf6_debug_neighbor ();

#ifdef OSPF6_MANET
void ospf6_store_mack(struct ospf6_neighbor *on,
                      struct ospf6_lsa_header *lsa_header);
struct ospf6_mack *ospf6_lookup_mack(struct ospf6_neighbor *on,
                                     struct ospf6_lsa_header *lsa_header);
void ospf6_mack_list_delete(struct ospf6_neighbor *on);
int ospf6_manet_update_routable_neighbors(struct ospf6_interface *oi);

#ifdef OSPF6_MANET_MPR_FLOOD
void update_2hop_neighbor_list(struct ospf6_neighbor *o6n,
                               struct ospf6_lsa_header *lsa_header);
struct ospf6_2hop_neighbor *ospf6_2hop_neighbor_lookup (u_int32_t router_id,
                                                  struct list *two_hop_neighbor_list);
struct ospf6_2hop_neighbor *ospf6_add_2hop_neighbor(u_int32_t router_id,
                                                    struct ospf6_neighbor *o6n);
void ospf6_2hop_list_delete(struct ospf6_neighbor *o6n);
void ospf6_2hop_neighbor_delete(struct ospf6_neighbor *o6n,
                                struct ospf6_2hop_neighbor *o62n);
void ospf6_update_neighborhood(struct ospf6_interface *o6i);

#ifdef OSPF6_MANET_MPR_SP
boolean ospf6_or_update_adjacencies(struct ospf6_interface *oi);
#endif //OSPF6_MANET_MPR_SP

#ifdef OSPF6_MANET_DIFF_HELLO
struct drop_neighbor;
struct drop_neighbor *ospf6_lookup_drop_neighbor(struct ospf6_interface *oi,
                                                   u_int32_t id);
void ospf6_drop_neighbor_delete(struct ospf6_interface *o6i,
                                    struct drop_neighbor *element);
void ospf6_drop_neighbor_create(struct ospf6_neighbor *o6n);
#endif //OSPF6_MANET_DIFF_HELLO
#endif //OSPF6_MANET_MPR_FLOOD

#ifdef OSPF6_MANET_MDR_FLOOD
int need_adjacency (struct ospf6_neighbor *on);
int keep_adjacency (struct ospf6_neighbor *on); 
void ospf6_mdr_delete_all_neighbors(struct list *n_list);
void ospf6_mdr_add_neighbor(struct list *n_list, u_int32_t id);
boolean ospf6_mdr_delete_neighbor(struct list *n_list, u_int32_t id);
boolean ospf6_mdr_lookup_neighbor(struct list *n_list, u_int32_t id);
void ospf6_mdr_delete_neighbor_list(struct list *n_list);
void ospf6_neighbor_state_change (u_char next_state, struct ospf6_neighbor *on);
#ifdef OSPF6_MANET_DIFF_HELLO
int ospf6_insufficienthellosreceived (struct ospf6_neighbor *on);
void ospf6_mdr_add_lnl_element(struct ospf6_neighbor *on);
struct ospf6_lnl_element *
  ospf6_mdr_lookup_lnl_element(struct ospf6_neighbor *on);
void ospf6_mdr_delete_lnl_element(struct ospf6_interface *oi,
                                    struct ospf6_lnl_element *lnl_element);
void ospf6_mdr_create_lsa_cost_matrix(struct ospf6_interface *oi);
int ospf6_mdr_update_adv_neighbors(struct ospf6_interface *oi);
void ospf6_mdr_free_lsa_cost_matrix(struct ospf6_interface *oi);
#ifdef OSPF6_MANET_MDR_LQ
void ospf6_mdr_update_link_quality(struct ospf6_neighbor*on, boolean quality);
#endif //OSPF6_MANET_MDR_LQ
#endif //OSPF6_MANET_DIFF_HELLO
#endif //OSPF6_MANET_MDR_FLOOD

#endif //OSPF6_MANET


#ifdef SIM_ETRACE_STAT
void ospf6_neighbor_state_change_stats (u_char prev_state, u_char next_state,
                                   struct ospf6_neighbor *on);
#endif //SIM_ETRACE_STAT


#endif /* OSPF6_NEIGHBOR_H */
