/*
 * Copyright (C) 1999-2003 Yasuhiro Ohara
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

#ifndef OSPF6_MESSAGE_H
#define OSPF6_MESSAGE_H

#ifdef OSPF6_MANET
#include "ospf6d.h" //for boolean
#endif //OSPF6_MANET

#define OSPF6_MESSAGE_BUFSIZ  4096

/* Debug option */
extern unsigned char conf_debug_ospf6_message[];
#define OSPF6_DEBUG_MESSAGE_SEND 0x01
#define OSPF6_DEBUG_MESSAGE_RECV 0x02
#define OSPF6_DEBUG_MESSAGE_ON(type, level) \
  (conf_debug_ospf6_message[type] |= (level))
#define OSPF6_DEBUG_MESSAGE_OFF(type, level) \
  (conf_debug_ospf6_message[type] &= ~(level))
#define IS_OSPF6_DEBUG_MESSAGE(t, e) \
  (conf_debug_ospf6_message[t] & OSPF6_DEBUG_MESSAGE_ ## e)

/* Type */
#define OSPF6_MESSAGE_TYPE_UNKNOWN  0x0
#define OSPF6_MESSAGE_TYPE_HELLO    0x1  /* Discover/maintain neighbors */
#define OSPF6_MESSAGE_TYPE_DBDESC   0x2  /* Summarize database contents */
#define OSPF6_MESSAGE_TYPE_LSREQ    0x3  /* Database download request */
#define OSPF6_MESSAGE_TYPE_LSUPDATE 0x4  /* Database update */
#define OSPF6_MESSAGE_TYPE_LSACK    0x5  /* Flooding acknowledgment */
#define OSPF6_MESSAGE_TYPE_ALL      0x6  /* For debug option */

#ifdef OSPF6_MANET
/* TLV type */
#define OSPF6_TLV_TYPE_OPTIONS      0x1
#define OSPF6_TLV_TYPE_SCS          0x2
#define OSPF6_TLV_TYPE_NEIGHDROP    0x3
#define OSPF6_TLV_TYPE_RELAY        0x4
#define OSPF6_TLV_TYPE_WILLINGNESS  0x5
#define OSPF6_TLV_TYPE_REQUEST      0x6 //XXX draft error (double assigned type)
#define OSPF6_TLV_TYPE_FULL         0x7 //XXX draft error (double assigned type)

#define OSPF6_TLV_TYPE_HNL          0x11
#define OSPF6_TLV_TYPE_RNL          0x12
#define OSPF6_TLV_TYPE_LNL          0x13
#define OSPF6_TLV_TYPE_HS           0x14
#define OSPF6_TLV_TYPE_DD           0x15
#define OSPF6_TLV_TYPE_DNL          0x16  // Added for Ogierv7.

//Chandra03 3.3.2
#define OSPF6_TLV_SCS_OPT_SET(x,opt,i)   ((x)[(i)] |=  (opt))
#define OSPF6_TLV_SCS_OPT_ISSET(x,opt,i) ((x)[(i)] &   (opt))
#define OSPF6_TLV_SCS_OPT_CLEAR(x,opt,i) ((x)[(i)] &= ~(opt))
#define OSPF6_TLV_SCS_OPT_CLEAR_ALL(x) ((x)[0] = (x)[1] = 0)
#define OSPF6_TLV_SCS_OPT_R (1 << 7)   /* Request for current state */
#define OSPF6_TLV_SCS_OPT_FS (1 << 6)   /* Answer with current state */
#define OSPF6_TLV_SCS_OPT_N (1 << 5)   /* Incomplete state bit */

#define OSPF6_TLV_REL_OPT_SET(x,opt,i)   ((x)[(i)] |=  (opt))
#define OSPF6_TLV_REL_OPT_ISSET(x,opt,i) ((x)[(i)] &   (opt))
#define OSPF6_TLV_REL_OPT_CLEAR(x,opt,i) ((x)[(i)] &= ~(opt))
#define OSPF6_TLV_REL_OPT_CLEAR_ALL(x) ((x)[0] = (x)[1] = (x)[2] = 0)
#define OSPF6_TLV_REL_OPT_A (1 << 7)   /* Always flood */
#define OSPF6_TLV_REL_OPT_N (1 << 6)   /* Almost Never flood */

#define OSPF6_TLV_HS_OPT_SET(x,opt,i)   ((x)[(i)] |=  (opt))
#define OSPF6_TLV_HS_OPT_ISSET(x,opt,i) ((x)[(i)] &   (opt))
#define OSPF6_TLV_HS_OPT_CLEAR(x,opt,i) ((x)[(i)] &= ~(opt))
#define OSPF6_TLV_HS_OPT_CLEAR_ALL(x) ((x)[0] = (x)[1] = 0)
#endif //OSPF6_MANET

#define OSPF6_MESSAGE_TYPE_CANONICAL(T) \
  ((T) > OSPF6_MESSAGE_TYPE_LSACK ? OSPF6_MESSAGE_TYPE_UNKNOWN : (T))

extern const char *ospf6_message_type_str[];
#define OSPF6_MESSAGE_TYPE_NAME(T) \
  (ospf6_message_type_str[ OSPF6_MESSAGE_TYPE_CANONICAL (T) ])

/* OSPFv3 packet header */
struct ospf6_header
{
  u_char    version;
  u_char    type;
  u_int16_t length;
  u_int32_t router_id;
  u_int32_t area_id;
  u_int16_t checksum;
  u_char    instance_id;
  u_char    reserved;
};

#define OSPF6_MESSAGE_END(H) ((caddr_t) (H) + ntohs ((H)->length))

/* Hello */
struct ospf6_hello
{
  u_int32_t interface_id;
  u_char    priority;
  u_char    options[3];
  u_int16_t hello_interval;
  u_int16_t dead_interval;
  u_int32_t drouter;
  u_int32_t bdrouter;
  /* Followed by Router-IDs */
};

#ifdef OSPF6_MANET
/* OSPFv3 LLS header */
//Chandra03 3.1.2
struct ospf6_LLS_header
{
  u_int16_t cksum;
  u_int16_t len; //length of entire LLS data block in 32 bit words
};

/* OSPFv3 TLV header */
//Chandra03 3.1.3
struct ospf6_TLV_header
{
  u_int16_t type;
  u_int16_t len;  // length of value field in bytes
};

/* OSPFv3 options TLV */
//Chandra03 3.1.4
struct ospf6_options_TLV
{
  u_char options[4];
};
#endif //OSPF6_MANET

#ifdef OSPF6_MANET_DIFF_HELLO
/* OSPFv3 State Check Sequence TLV */
//Chandra03 3.3.2
struct ospf6_scs_TLV
{
  u_int16_t number;
  u_char    bits[2];
};

/* OSPFv3 Neighbor drop TLV */
/* No message struct needed here; just includes router-IDs */


/* OSPFv3 Neighbor Request TLV */
/* No message struct needed here; just includes router-IDs */
#endif //OSPF6_MANET_DIFF_HELLO

#ifdef OSPF6_MANET_MPR_FLOOD
/* OSPFv3  Active Overlapping Relays TLV */
//Chandra03 3.4.6
struct ospf6_relay_TLV
{
  u_char added;
  u_char bits[3];
};

/* OSPFv3  Active Overlapping Relays TLV */
//Chandra03 3.4.7
struct ospf6_will_TLV
{
  u_char will;
  u_char reserved[3];
};
#endif //OSPF6_MANET_MPR_FLOOD

#ifdef OSPF6_MANET_MDR_FLOOD

#ifdef OSPF6_MANET_DIFF_HELLO
/* OSPFv3 Hello Sequence TLV */
struct ospf6_seq_TLV
{
  u_int16_t number;
  u_char bits[2];
};
#endif //OSPF6_MANET_DIFF_HELLO

/* OSPFv3 Heard Neighbor List TLV */
/* No TLV Header needed here */

/* OSPFv3 Reported Neighbor List TLV */
/* No TLV Header needed here */

/* OSPFv3 Lost Neighbor List TLV */
/* No TLV Header needed here */

/* OSPFv3 MDR TLV */
struct ospf6_mdr_TLV
{
  u_int32_t id1;
  u_int32_t id2;
};
#endif //OSPF6_MANET_MDR_FLOOD

/* Database Description */
struct ospf6_dbdesc
{
  u_char    reserved1;
  u_char    options[3];
  u_int16_t ifmtu;
  u_char    reserved2;
  u_char    bits;
  u_int32_t seqnum;
  /* Followed by LSA Headers */
};

#define OSPF6_DBDESC_MSBIT (0x01) /* master/slave bit */
#define OSPF6_DBDESC_MBIT  (0x02) /* more bit */
#define OSPF6_DBDESC_IBIT  (0x04) /* initial bit */

/* Link State Request */
/* It is just a sequence of entries below */
struct ospf6_lsreq_entry
{
  u_int16_t reserved;     /* Must Be Zero */
  u_int16_t type;         /* LS type */
  u_int32_t id;           /* Link State ID */
  u_int32_t adv_router;   /* Advertising Router */
};

/* Link State Update */
struct ospf6_lsupdate
{
  u_int32_t lsa_number;
  /* Followed by LSAs */
};

/* Link State Acknowledgement */
/* It is just a sequence of LSA Headers */

/* Function definition */
void ospf6_hello_print (struct ospf6_header *);
void ospf6_dbdesc_print (struct ospf6_header *);
void ospf6_lsreq_print (struct ospf6_header *);
void ospf6_lsupdate_print (struct ospf6_header *);
void ospf6_lsack_print (struct ospf6_header *);

int ospf6_iobuf_size (unsigned int size);
int ospf6_receive (struct thread *thread);

int ospf6_hello_send (struct thread *thread);
int ospf6_dbdesc_send (struct thread *thread);
int ospf6_dbdesc_send_newone (struct thread *thread);
int ospf6_lsreq_send (struct thread *thread);
int ospf6_lsupdate_send_interface (struct thread *thread);
int ospf6_lsupdate_send_neighbor (struct thread *thread);
int ospf6_lsack_send_interface (struct thread *thread);
int ospf6_lsack_send_neighbor (struct thread *thread);

int config_write_ospf6_debug_message (struct vty *);
void install_element_ospf6_debug_message ();

#ifdef SIM
#ifdef OSPF6_MANET
void
ospf6_hello_recv (struct in6_addr *src, struct in6_addr *dst,
                  struct ospf6_interface *oi, struct ospf6_header *oh, int len);
void
ospf6_dbdesc_recv (struct in6_addr *src, struct in6_addr *dst,
                  struct ospf6_interface *oi, struct ospf6_header *oh, int len);
#else 
void
ospf6_hello_recv (struct in6_addr *src, struct in6_addr *dst,
                  struct ospf6_interface *oi, struct ospf6_header *oh);
void
ospf6_dbdesc_recv (struct in6_addr *src, struct in6_addr *dst,
                   struct ospf6_interface *oi, struct ospf6_header *oh);
#endif //OSPF6_MANET
void
ospf6_lsreq_recv (struct in6_addr *src, struct in6_addr *dst,
                  struct ospf6_interface *oi, struct ospf6_header *oh);
void
ospf6_lsupdate_recv (struct in6_addr *src, struct in6_addr *dst,
                     struct ospf6_interface *oi, struct ospf6_header *oh);
void
ospf6_lsack_recv (struct in6_addr *src, struct in6_addr *dst,
                  struct ospf6_interface *oi, struct ospf6_header *oh);
#endif //SIM

#ifdef OSPF6_MANET
struct ospf6_interface;
struct ospf6_relay;
struct ospf6_relay_selector;
struct ospf6_neighbor;
#endif // DEBUG


#ifdef OSPF6_DELAYED_FLOOD
struct thread *ospf6_send_lsupdate_delayed_msec(struct thread_master *m,
        int (*func) (struct thread *), void *arg, long timer, struct thread *t);
#endif //OSPF6_DELAYED_FLOOD

#ifdef OSPF6_MANET
boolean ospf6_is_rtrid_in_list(struct ospf6_interface *, u_int32_t *, int);

int ospf6_append_lls_header(struct ospf6_interface *, u_char *, u_int);
void ospf6_tlv_header_assignment(struct ospf6_TLV_header *,u_int16_t,u_int16_t);

#ifdef OSPF6_MANET_MPR_FLOOD
int ospf6_mpr_mhello_send (struct ospf6_interface *o6i);

void ospf6_mpr_process_TLVs(struct ospf6_neighbor *, struct ospf6_LLS_header *);
int ospf6_append_relays(struct ospf6_interface *oi,
                        u_char *pos,
                        u_char *max_pos,
                        boolean periodic_hello,
                        boolean full_neighbor_state);
int ospf6_create_neighbor_list(struct ospf6_interface *oi,
                           u_char *sendbuf,
                           u_char *position,
                           boolean full_neighbor_state);

#ifdef OSPF6_MANET_DIFF_HELLO
int ospf6_mpr_diff_mhello_send (struct ospf6_interface *o6i,
                       struct in6_addr dst,
                       char *scs_tlv_opt);
boolean ospf6_is_scs_wrap_around(u_int16_t old_scs_num, u_int16_t new_scs_num);
int ospf6_append_scs(struct ospf6_interface *oi,
                      char *opt,
                      u_char *pos);
int ospf6_append_drop_neighbors(struct ospf6_interface *oi,
                                u_char *pos,
                                u_char *max_pos,
                                boolean *set_N);
int ospf6_append_request(struct ospf6_interface *oi,
                         u_char *pos,
                         u_char *max_pos,
                         char *scs_tlv_option);
void ospf6_mpr_process_diff_TLVs(struct ospf6_neighbor *on,
                        struct ospf6_LLS_header * lls_ptr,
                        int seenrtrnum,
                        char *scs_tlv_option,
                        boolean *twoway,
                        boolean *send_mhello);

#endif //OSPF6_MANET_DIFF_HELLO
#endif //OSPF6_MANET_MPR_FLOOD

#ifdef OSPF6_MANET_MDR_FLOOD
int ospf6_mdr_mhello_send(struct ospf6_interface *oi);
// DNL list added for Ogierv7
u_int ospf6_mdr_create_neighbor_lists(struct ospf6_interface *oi,
                                        u_char *pos, u_char *max_pos,
                                        u_int *num_hnl, u_char *hnl,
                                        u_int *num_rnl, u_char *rnl,
                                        u_int *num_lnl, u_char *lnl,
                                        u_int *num_dnl, u_char *dnl,
                                        boolean diff);
int ospf6_append_mdr_neigh_tlv(u_char *, u_int, u_char *, u_int16_t);
boolean ospf6_mdr_process_hello_TLVs(struct ospf6_neighbor *on,
                                     struct ospf6_LLS_header *lls_ptr,
                                     boolean diff, boolean *rnl_changed);
int ospf6_append_mdr_tlv(struct ospf6_interface *oi, u_char *p);
boolean ospf6_mdr_process_mdr_TLVs(struct ospf6_neighbor *,
                           struct ospf6_LLS_header *);

#ifdef OSPF6_MANET_DIFF_HELLO
int ospf6_append_mdr_seq_tlv(struct ospf6_interface *oi, u_char *pos); 
#endif //OSPF6_MANET_DIFF_HELLO
#endif //OSPF6_MANET_MDR_FLOOD

#ifdef OSPF6_MANET_TEMPORARY_LSDB
void ospf6_lsupdate_recv_below_exchange (struct in6_addr *src,
                                       struct in6_addr *dst,
                     struct ospf6_interface *oi,
                     struct ospf6_header *oh);
#endif //OSPF6_MANET_TEMPORARY_LSDB

//################## PRINTING SECTION ########################
void ospf6_mhello_print (struct ospf6_header *oh, int len);
void print_tlv(struct ospf6_TLV_header *tlv_header, boolean log);

//################## END PRINTING SECTION ########################

#ifdef USER_CHECKSUM
u_int16_t ospf6_do_checksum(struct in6_addr*, struct in6_addr*,struct ospf6_header*);
#endif

#endif //OSPF6_MANET

#endif /* OSPF6_MESSAGE_H */

