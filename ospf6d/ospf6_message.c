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
#include "vty.h"
#include "command.h"
#include "thread.h"
#include "linklist.h"

#include "ospf6_proto.h"
#include "ospf6_lsa.h"
#include "ospf6_lsdb.h"
#include "ospf6_network.h"
#include "ospf6_message.h"

#include "ospf6_top.h"
#include "ospf6_area.h"
#include "ospf6_neighbor.h"
#include "ospf6_interface.h"

#include "ospf6_flood.h"
#include "ospf6d.h"

#ifdef SIM
#include "sim.h"
#endif //SIM
#ifdef SIM_ETRACE_STAT
#include "ospf6_sim_printing.h"
#endif //SIM_ETRACE_STAT
#ifdef OSPF6_MANET_MPR_FLOOD
#include "ospf6_mpr.h"
#endif //OSPF6_MANET_MPR_FLOOD
#ifdef OSPF6_MANET_MDR_FLOOD
#include "ospf6_mdr.h"
#endif //OSPF6_MANET_MDR_FLOOD

#ifdef USER_CHECKSUM
/* IPv6 pseudo header for checksum calculation */
typedef struct 
{
    struct in6_addr src;
    struct in6_addr dst;
    u_int32_t upper_len;
    char zero[3];
    u_int8_t nh;

} pseudo_header;

#endif

unsigned char conf_debug_ospf6_message[6] = {0x03, 0, 0, 0, 0, 0};
const char *ospf6_message_type_str[] =
  { "Unknown", "Hello", "DbDesc", "LSReq", "LSUpdate", "LSAck" };

/* print functions */

static void
ospf6_header_print (struct ospf6_header *oh)
{
  char router_id[16], area_id[16];
  inet_ntop (AF_INET, &oh->router_id, router_id, sizeof (router_id));
  inet_ntop (AF_INET, &oh->area_id, area_id, sizeof (area_id));

  zlog_debug ("    OSPFv%d Type:%d Len:%hu Router-ID:%s",
             oh->version, oh->type, ntohs (oh->length), router_id);
  zlog_debug ("    Area-ID:%s Cksum:%hx Instance-ID:%d",
             area_id, ntohs (oh->checksum), oh->instance_id);
}

void
ospf6_hello_print (struct ospf6_header *oh)
{
  struct ospf6_hello *hello;
#ifdef OSPF6_MANET
  char options[36];
#else
  char options[16];
#endif //OSPF6_MANET
  char drouter[16], bdrouter[16], neighbor[16];
  char *p;

  ospf6_header_print (oh);
  assert (oh->type == OSPF6_MESSAGE_TYPE_HELLO);

  hello = (struct ospf6_hello *)
    ((caddr_t) oh + sizeof (struct ospf6_header));

  inet_ntop (AF_INET, &hello->drouter, drouter, sizeof (drouter));
  inet_ntop (AF_INET, &hello->bdrouter, bdrouter, sizeof (bdrouter));
  ospf6_options_printbuf (hello->options, options, sizeof (options));

  zlog_debug ("    I/F-Id:%ld Priority:%d Option:%s",
             (u_long) ntohl (hello->interface_id), hello->priority, options);
  zlog_debug ("    HelloInterval:%hu DeadInterval:%hu",
             ntohs (hello->hello_interval), ntohs (hello->dead_interval));
  zlog_debug ("    DR:%s BDR:%s", drouter, bdrouter);

  for (p = (char *) ((caddr_t) hello + sizeof (struct ospf6_hello));
       p + sizeof (u_int32_t) <= OSPF6_MESSAGE_END (oh);
       p += sizeof (u_int32_t))
    {
      inet_ntop (AF_INET, (void *) p, neighbor, sizeof (neighbor));
      zlog_debug ("    Neighbor: %s", neighbor);
    }

  if (p != OSPF6_MESSAGE_END (oh))
    zlog_debug ("Trailing garbage exists");
}

void
ospf6_dbdesc_print (struct ospf6_header *oh)
{
  struct ospf6_dbdesc *dbdesc;
  char options[16];
  char *p;

  ospf6_header_print (oh);
  assert (oh->type == OSPF6_MESSAGE_TYPE_DBDESC);

  dbdesc = (struct ospf6_dbdesc *)
    ((caddr_t) oh + sizeof (struct ospf6_header));

  ospf6_options_printbuf (dbdesc->options, options, sizeof (options));

  zlog_debug ("    MBZ: %#x Option: %s IfMTU: %hu",
             dbdesc->reserved1, options, ntohs (dbdesc->ifmtu));
  zlog_debug ("    MBZ: %#x Bits: %s%s%s SeqNum: %#lx",
             dbdesc->reserved2,
             (CHECK_FLAG (dbdesc->bits, OSPF6_DBDESC_IBIT) ? "I" : "-"),
             (CHECK_FLAG (dbdesc->bits, OSPF6_DBDESC_MBIT) ? "M" : "-"),
             (CHECK_FLAG (dbdesc->bits, OSPF6_DBDESC_MSBIT) ? "m" : "s"),
             (u_long) ntohl (dbdesc->seqnum));

  for (p = (char *) ((caddr_t) dbdesc + sizeof (struct ospf6_dbdesc));
       p + sizeof (struct ospf6_lsa_header) <= OSPF6_MESSAGE_END (oh);
       p += sizeof (struct ospf6_lsa_header))
    ospf6_lsa_header_print_raw ((struct ospf6_lsa_header *) p);

  if (p != OSPF6_MESSAGE_END (oh))
    zlog_debug ("Trailing garbage exists");
}

void
ospf6_lsreq_print (struct ospf6_header *oh)
{
  char id[16], adv_router[16];
  char *p;

  ospf6_header_print (oh);
  assert (oh->type == OSPF6_MESSAGE_TYPE_LSREQ);

  for (p = (char *) ((caddr_t) oh + sizeof (struct ospf6_header));
       p + sizeof (struct ospf6_lsreq_entry) <= OSPF6_MESSAGE_END (oh);
       p += sizeof (struct ospf6_lsreq_entry))
    {
      struct ospf6_lsreq_entry *e = (struct ospf6_lsreq_entry *) p;
      inet_ntop (AF_INET, &e->adv_router, adv_router, sizeof (adv_router));
      inet_ntop (AF_INET, &e->id, id, sizeof (id));
      zlog_debug ("    [%s Id:%s Adv:%s]",
                 ospf6_lstype_name (e->type), id, adv_router);
    }

  if (p != OSPF6_MESSAGE_END (oh))
    zlog_debug ("Trailing garbage exists");
}

void
ospf6_lsupdate_print (struct ospf6_header *oh)
{
  struct ospf6_lsupdate *lsupdate;
  u_long num;
  char *p;

  ospf6_header_print (oh);
  assert (oh->type == OSPF6_MESSAGE_TYPE_LSUPDATE);

  lsupdate = (struct ospf6_lsupdate *)
    ((caddr_t) oh + sizeof (struct ospf6_header));

  num = ntohl (lsupdate->lsa_number);
  zlog_debug ("    Number of LSA: %ld", num);

  for (p = (char *) ((caddr_t) lsupdate + sizeof (struct ospf6_lsupdate));
       p < OSPF6_MESSAGE_END (oh) &&
       p + OSPF6_LSA_SIZE (p) <= OSPF6_MESSAGE_END (oh);
       p += OSPF6_LSA_SIZE (p))
    {
      ospf6_lsa_header_print_raw ((struct ospf6_lsa_header *) p);
      if (OSPF6_LSA_SIZE (p) < sizeof (struct ospf6_lsa_header))
        {
          zlog_debug ("    Malformed LSA length, quit printing");
          break;
        }
    }

  if (p != OSPF6_MESSAGE_END (oh))
    {
      char buf[32];

      int num = 0;
      memset (buf, 0, sizeof (buf));

      zlog_debug ("    Trailing garbage exists");
      while (p < OSPF6_MESSAGE_END (oh))
        {
          snprintf (buf, sizeof (buf), "%s %2x", buf, *p++);
          num++;
          if (num == 8)
            {
              zlog_debug ("    %s", buf);
              memset (buf, 0, sizeof (buf));
              num = 0;
            }
        }
      if (num)
        zlog_debug ("    %s", buf);
    }
}

void
ospf6_lsack_print (struct ospf6_header *oh)
{
  char *p;

  ospf6_header_print (oh);
  assert (oh->type == OSPF6_MESSAGE_TYPE_LSACK);

  for (p = (char *) ((caddr_t) oh + sizeof (struct ospf6_header));
       p + sizeof (struct ospf6_lsa_header) <= OSPF6_MESSAGE_END (oh);
       p += sizeof (struct ospf6_lsa_header))
    ospf6_lsa_header_print_raw ((struct ospf6_lsa_header *) p);

  if (p != OSPF6_MESSAGE_END (oh))
    zlog_debug ("Trailing garbage exists");
}

/* Receive function */
#define MSG_OK    0
#define MSG_NG    1
static int
ospf6_header_examin (struct in6_addr *src, struct in6_addr *dst,
                     struct ospf6_interface *oi, struct ospf6_header *oh)
{
  u_char type;
  type = OSPF6_MESSAGE_TYPE_CANONICAL (oh->type);

  /* version check */
  if (oh->version != OSPFV3_VERSION)
    {
      if (IS_OSPF6_DEBUG_MESSAGE (type, RECV))
        zlog_debug ("Message with unknown version");
      return MSG_NG;
    }

  /* Area-ID check */
  if (oh->area_id != oi->area->area_id)
    {
      if (oh->area_id == BACKBONE_AREA_ID)
        {
          if (IS_OSPF6_DEBUG_MESSAGE (type, RECV))
            zlog_debug ("Message may be via Virtual Link: not supported");
          return MSG_NG;
        }

      if (IS_OSPF6_DEBUG_MESSAGE (type, RECV))
        zlog_debug ("Area-ID mismatch");
      return MSG_NG;
    }

  /* Instance-ID check */
  if (oh->instance_id != oi->instance_id)
    {
      if (IS_OSPF6_DEBUG_MESSAGE (type, RECV))
        zlog_debug ("Instance-ID mismatch");
      return MSG_NG;
    }

  /* Router-ID check */
  if (oh->router_id == oi->area->ospf6->router_id)
    zlog_warn ("Detect duplicate Router-ID");

  return MSG_OK;
} 

#ifdef OSPF6_MANET_MDR_FLOOD
// Ogierv3 10.3
void
ospf6_mdr_mhello_recv (struct in6_addr *src, struct in6_addr *dst,
                  struct ospf6_interface *oi, struct ospf6_header *oh, int len)
{
  struct ospf6_hello *hello;
  struct ospf6_neighbor *on;
  int neighborchange = 0;
  int backupseen = 0;
  boolean calc_cds = false; // Set if calculate_cds() must be called.
  u_char prev_state;
  boolean twoway = false;
  boolean rnl_changed = false;
  boolean mdr_level_changed;
  struct ospf6_LLS_header *lls_ptr = NULL;

  if (ospf6_header_examin (src, dst, oi, oh) != MSG_OK)
    return;

  hello = (struct ospf6_hello *)
    ((caddr_t) oh + sizeof (struct ospf6_header));

  /* HelloInterval check */
  if (ntohs (hello->hello_interval) != oi->hello_interval)
  {
  if (IS_OSPF6_DEBUG_MESSAGE (oh->type, RECV))
      zlog_info ("HelloInterval mismatch");
    return;
  }

  /* RouterDeadInterval check */
  if (ntohs (hello->dead_interval) != oi->dead_interval)
  {
    if (IS_OSPF6_DEBUG_MESSAGE (oh->type, RECV))
      zlog_info ("RouterDeadInterval mismatch");
    return;
  }

  /* E-bit check */
  if (OSPF6_OPT_ISSET (hello->options, OSPF6_OPT_E, 2) !=
      OSPF6_OPT_ISSET (oi->area->options, OSPF6_OPT_E, 2))
  {
    if (IS_OSPF6_DEBUG_MESSAGE (oh->type, RECV))
      zlog_info ("E-bit mismatch");
    return;
  }

  /* Find neighbor, create if not existent */
  on = ospf6_neighbor_lookup (oh->router_id, oi);
  if (on == NULL)
  {
    on = ospf6_neighbor_create (oh->router_id, oi);
    on->prev_drouter = on->drouter = hello->drouter;
    on->prev_bdrouter = on->bdrouter = hello->bdrouter;
    on->priority = hello->priority;
    on->ifindex = ntohl (hello->interface_id);
    memcpy (&on->linklocal_addr, src, sizeof (struct in6_addr));
  }

  /* process TLVs */
  /* set LLS pointer */
  prev_state = on->state;
  lls_ptr = (struct ospf6_LLS_header *) (hello + 1);
  if (ntohs(oh->length) < len && OSPF6_OPT_ISSET(hello->options, OSPF6_OPT_L,1))
    twoway = ospf6_mdr_process_hello_TLVs(on, lls_ptr, 
               OSPF6_OPT_ISSET(hello->options, OSPF6_OPT_D, 1), &rnl_changed);
  if (rnl_changed) 
    calc_cds = true;

  /* RouterPriority check */
  if (on->priority != hello->priority)
  {
    on->priority = hello->priority;
    calc_cds = true;
    neighborchange++;
  }

  /* DR check */
  if (on->drouter != hello->drouter)
  {
    on->prev_drouter = on->drouter;
    on->drouter = hello->drouter;
    if (on->prev_drouter == on->router_id || on->drouter == on->router_id)
    {
      neighborchange++;
      calc_cds = true;
    }
  }

  /* BDR check */
  if (on->bdrouter != hello->bdrouter)
  {
    on->prev_bdrouter = on->bdrouter;
    on->bdrouter = hello->bdrouter;
    if (on->prev_bdrouter == on->router_id || on->bdrouter == on->router_id)
    {
      neighborchange++;
      calc_cds = true;
    }
  }

  /* BackupSeen check */
  if (oi->state == OSPF6_INTERFACE_WAITING)
  {
    if (hello->bdrouter == on->router_id)
      backupseen++;
    else if (hello->drouter == on->router_id && hello->bdrouter == htonl (0))
      backupseen++;
  }

  mdr_level_changed = ospf6_mdr_set_mdr_level(on, on->drouter, on->bdrouter);
  if (mdr_level_changed) calc_cds = true;

  // Receiving Hello changes 2-hop nbr info, and nbr MDR levels,
  // and children. But calc_cds must be called before checking
  // need adj. Children is the only thing that does not affect
  // decision to run calc_cds. Any other change does.

  /* execute neighbor events */
  thread_execute (master, hello_received, on, 0);
  if (twoway)
    thread_execute (master, twoway_received, on, 0);
  else
    thread_execute (master, oneway_received, on, 0);

  if (prev_state < OSPF6_NEIGHBOR_TWOWAY && on->state >= OSPF6_NEIGHBOR_TWOWAY)
    calc_cds = true;
  if (prev_state >= OSPF6_NEIGHBOR_TWOWAY && on->state < OSPF6_NEIGHBOR_TWOWAY)
    calc_cds = true;

  // The CDS is calculated only if there is a change to
  // 2-hop neighbor information, including the MDR level of neighbors.

  // Things that could require calc cds besides receiving hello:
  // dead interval (done).  DD packet that changes mdr_level of nbr,
  // but we can wait until next hello from the nbr.
                                                                                
  // RGO. MDRs need to be calculated only before sending Hello.
  // This sometimes improves performance.
  //if (calc_cds)
  //  ospf6_calculate_mdr(on->ospf6_if);

  // Check to see if any neighbor should be adjacent.
  // This can result from calculating CDS and parents, or from
  // a change in the MDR level of neighbors, or because there is
  // a new neighbor, or because a neighbor (child) selected the
  // router as a parent. The last reason is the only time an
  // adjacency might be needed without calling calculate_mdr().

  // Check to see if any adjacent neighbor should be non-adjacent.
  // This can result because the router is no longer DR/BDR, or because an
  // adjacent neighbor is no longer DR/BDR. (Only two possible reasons.)

   ospf6_mdr_update_adjacencies(on->ospf6_if); 

  /* Schedule interface events */
  if (backupseen)
    thread_add_event (master, backup_seen, oi, 0);
  if (neighborchange)
    thread_add_event (master, neighbor_change, oi, 0);
}
#endif //OSPF6_MANET_MDR_FLOOD

#ifdef OSPF6_MANET_MPR_FLOOD
void
ospf6_mhello_recv (struct in6_addr *src, struct in6_addr *dst,
                  struct ospf6_interface *oi, struct ospf6_header *oh, int len)
{
  struct ospf6_hello *hello;
  struct ospf6_neighbor *on;
  int neighborchange = 0;
  int backupseen = 0;

  u_int32_t *router_id_ptr;
  int seenrtrnum = 0, router_id_space = 0;
  boolean twoway;
  struct ospf6_LLS_header *lls_ptr = NULL;

  if (ospf6_header_examin (src, dst, oi, oh) != MSG_OK)
    return;

  hello = (struct ospf6_hello *)
    ((caddr_t) oh + sizeof (struct ospf6_header));

  /* HelloInterval check */
  if (ntohs (hello->hello_interval) != oi->hello_interval)
  {
  if (IS_OSPF6_DEBUG_MESSAGE (oh->type, RECV))
      zlog_info ("HelloInterval mismatch");
    return;
  }

  /* RouterDeadInterval check */
  if (ntohs (hello->dead_interval) != oi->dead_interval)
  {
    if (IS_OSPF6_DEBUG_MESSAGE (oh->type, RECV))
      zlog_info ("RouterDeadInterval mismatch");
    return;
  }

  /* E-bit check */
  if (OSPF6_OPT_ISSET (hello->options, OSPF6_OPT_E, 2) !=
      OSPF6_OPT_ISSET (oi->area->options, OSPF6_OPT_E, 2))
  {
    if (IS_OSPF6_DEBUG_MESSAGE (oh->type, RECV))
      zlog_info ("E-bit mismatch");
    return;
  }

  /* Find neighbor, create if not existent */
  on = ospf6_neighbor_lookup (oh->router_id, oi);
  if (on == NULL)
  {
    on = ospf6_neighbor_create (oh->router_id, oi);
    on->prev_drouter = on->drouter = hello->drouter;
    on->prev_bdrouter = on->bdrouter = hello->bdrouter;
    on->priority = hello->priority;
    on->ifindex = ntohl (hello->interface_id);
    memcpy (&on->linklocal_addr, src, sizeof (struct in6_addr));
  }
  on->Fbit = OSPF6_OPT_ISSET(hello->options, OSPF6_OPT_F, 1);

  /* set pointer positions */
  router_id_space = ntohs(oh->length) -
                  sizeof(struct ospf6_header) - sizeof(struct ospf6_hello);
  seenrtrnum = router_id_space / sizeof(u_int32_t);
  router_id_ptr = (u_int32_t *) (hello + 1);
  lls_ptr = (struct ospf6_LLS_header *) (router_id_ptr + seenrtrnum);

  twoway = ospf6_is_rtrid_in_list(oi, router_id_ptr, seenrtrnum);

  /* process TLVs */
  /* set LLS pointer */
  if (ntohs(oh->length) < len && OSPF6_OPT_ISSET(hello->options, OSPF6_OPT_L,1))
    ospf6_mpr_process_TLVs(on, lls_ptr);

  /* RouterPriority check */
  if (on->priority != hello->priority)
  {
    on->priority = hello->priority;
    neighborchange++;
  }

  /* DR check */
  if (on->drouter != hello->drouter)
  {
    on->prev_drouter = on->drouter;
    on->drouter = hello->drouter;
    if (on->prev_drouter == on->router_id || on->drouter == on->router_id)
      neighborchange++;
  }

  /* BDR check */
  if (on->bdrouter != hello->bdrouter)
  {
    on->prev_bdrouter = on->bdrouter;
    on->bdrouter = hello->bdrouter;
    if (on->prev_bdrouter == on->router_id || on->bdrouter == on->router_id)
      neighborchange++;
  }

  /* BackupSeen check */
  if (oi->state == OSPF6_INTERFACE_WAITING)
  {
    if (hello->bdrouter == on->router_id)
      backupseen++;
    else if (hello->drouter == on->router_id && hello->bdrouter == htonl (0))
      backupseen++;
  }

  /* execute neighbor events */
  thread_execute (master, hello_received, on, 0);
  if (twoway)
    thread_execute (master, twoway_received, on, 0);
  else
    thread_execute (master, oneway_received, on, 0);

  /* Schedule interface events */
  if (backupseen)
    thread_add_event (master, backup_seen, oi, 0);
  if (neighborchange)
    thread_add_event (master, neighbor_change, oi, 0);
}

#ifdef OSPF6_MANET_DIFF_HELLO
void
ospf6_mpr_diff_mhello_recv (struct in6_addr *src, struct in6_addr *dst,
                  struct ospf6_interface *oi, struct ospf6_header *oh, int len)
{
  struct ospf6_hello *hello;
  struct ospf6_neighbor *on;
  int neighborchange = 0;
  int backupseen = 0;

  u_int32_t *router_id_ptr;
  int seenrtrnum = 0, router_id_space = 0;
  boolean twoway, send_mhello = false;
  char scs_tlv_option[2] = {0, 0};
  struct ospf6_LLS_header *lls_ptr = NULL;

  if (ospf6_header_examin (src, dst, oi, oh) != MSG_OK)
    return;

  hello = (struct ospf6_hello *)
    ((caddr_t) oh + sizeof (struct ospf6_header));

  /* HelloInterval check */
  if (ntohs (hello->hello_interval) != oi->hello_interval)
  {
  if (IS_OSPF6_DEBUG_MESSAGE (oh->type, RECV))
      zlog_info ("HelloInterval mismatch");
    return;
  }

  /* RouterDeadInterval check */
  if (ntohs (hello->dead_interval) != oi->dead_interval)
  {
    if (IS_OSPF6_DEBUG_MESSAGE (oh->type, RECV))
      zlog_info ("RouterDeadInterval mismatch");
    return;
  }

  /* E-bit check */
  if (OSPF6_OPT_ISSET (hello->options, OSPF6_OPT_E,2) !=
      OSPF6_OPT_ISSET (oi->area->options, OSPF6_OPT_E,2))
  {
    if (IS_OSPF6_DEBUG_MESSAGE (oh->type, RECV))
      zlog_info ("E-bit mismatch");
    return;
  }

  /* Find neighbor, create if not existent */
  on = ospf6_neighbor_lookup (oh->router_id, oi);
  if (on == NULL)
  {
    //Chandra03 3.3.6.1 paragraph 2 bullet 1
    on = ospf6_neighbor_create (oh->router_id, oi);
    on->prev_drouter = on->drouter = hello->drouter;
    on->prev_bdrouter = on->bdrouter = hello->bdrouter;
    on->priority = hello->priority;
    on->ifindex = ntohl (hello->interface_id);
    memcpy (&on->linklocal_addr, src, sizeof (struct in6_addr));
  }
  on->Fbit = OSPF6_OPT_ISSET(hello->options, OSPF6_OPT_F, 1);

  /* set pointer positions */
  router_id_space = ntohs(oh->length) -
                  sizeof(struct ospf6_header) - sizeof(struct ospf6_hello);
  seenrtrnum = router_id_space / sizeof(u_int32_t);
  router_id_ptr = (u_int32_t *) (hello + 1);
  lls_ptr = (struct ospf6_LLS_header *) (router_id_ptr + seenrtrnum);

  /* TwoWay check (if false not necessarily oneway with diff hellos) */
  twoway = ospf6_is_rtrid_in_list(oi, router_id_ptr, seenrtrnum);

  /* process TLVs */
  /* set LLS pointer */
  if (ntohs(oh->length) < len && OSPF6_OPT_ISSET(hello->options, OSPF6_OPT_L,1))
    ospf6_mpr_process_diff_TLVs(on, lls_ptr, seenrtrnum, scs_tlv_option,
                   &twoway, &send_mhello);

  /* RouterPriority check */
  if (on->priority != hello->priority)
  {
    on->priority = hello->priority;
    neighborchange++;
  }

  /* DR check */
  if (on->drouter != hello->drouter)
  {
    on->prev_drouter = on->drouter;
    on->drouter = hello->drouter;
    if (on->prev_drouter == on->router_id || on->drouter == on->router_id)
      neighborchange++;
  }

  /* BDR check */
  if (on->bdrouter != hello->bdrouter)
  {
    on->prev_bdrouter = on->bdrouter;
    on->bdrouter = hello->bdrouter;
    if (on->prev_bdrouter == on->router_id || on->bdrouter == on->router_id)
      neighborchange++;
  }

  /* BackupSeen check */
  if (oi->state == OSPF6_INTERFACE_WAITING)
  {
    if (hello->bdrouter == on->router_id)
      backupseen++;
    else if (hello->drouter == on->router_id && hello->bdrouter == htonl (0))
      backupseen++;
  }

  /* execute neighbor events */
  thread_execute (master, hello_received, on, 0);
  if (twoway)
    thread_execute (master, twoway_received, on, 0);
  else
  {
    thread_execute (master, oneway_received, on, 0);
    if (on->state == OSPF6_NEIGHBOR_INIT)
      // Chandra 3.3.7 paragraph 2
      on->request = true;
  }
 // if (send_mhello &&
 //  elapsed_time(&ospf6->starttime) > oi->dead_interval)//graceful restart
 //     ospf6_diff_mhello_send(oi, on->linklocal_addr, scs_tlv_option);

  /* Schedule interface events */
  if (backupseen)
    thread_add_event (master, backup_seen, oi, 0);
  if (neighborchange)
    thread_add_event (master, neighbor_change, oi, 0);
}
#endif //OSPF6_MANET_DIFF_HELLO
#endif //OSPF6_MANET_MPR_FLOOD

void
#ifdef OSPF6_MANET
ospf6_hello_recv (struct in6_addr *src, struct in6_addr *dst,
                  struct ospf6_interface *oi, struct ospf6_header *oh, int len)
#else
ospf6_hello_recv (struct in6_addr *src, struct in6_addr *dst,
                  struct ospf6_interface *oi, struct ospf6_header *oh)
#endif //OSPF6_MANET
{
  struct ospf6_hello *hello;
  struct ospf6_neighbor *on;
  char *p;
  int twoway = 0;
  int neighborchange = 0;
  int backupseen = 0;

  if (ospf6_header_examin (src, dst, oi, oh) != MSG_OK)
    return;

  hello = (struct ospf6_hello *)
    ((caddr_t) oh + sizeof (struct ospf6_header));

#ifdef OSPF6_MANET
  if (oi->type == OSPF6_IFTYPE_MANETRELIABLE)
  {
#ifdef OSPF6_MANET_MPR_FLOOD
    if (oi->flooding == OSPF6_FLOOD_MPR_SDCDS)
    {
      //Chandra03 3.3.9 
      if (!OSPF6_OPT_ISSET(hello->options, OSPF6_OPT_I, 1))
        ospf6_mhello_recv (src, dst, oi, oh, len);
#ifdef OSPF6_MANET_DIFF_HELLO
      else
        //Chandra03 3.3.6.1 paragraph 2
        ospf6_mpr_diff_mhello_recv(src, dst, oi, oh, len);
#endif //OSPF6_MANET_DIFF_HELLO
      return;
    }
#endif //OSPF6_MANET_MPR_FLOOD
#ifdef OSPF6_MANET_MDR_FLOOD
    if (oi->flooding == OSPF6_FLOOD_MDR_SICDS)
    {
      ospf6_mdr_mhello_recv(src, dst, oi, oh, len); 
      return;
    }
#endif //OSPF6_MANET_MDR_FLOOD
  }
#endif //OSPF_MANET

  /* HelloInterval check */
  if (ntohs (hello->hello_interval) != oi->hello_interval)
    {
      if (IS_OSPF6_DEBUG_MESSAGE (oh->type, RECV))
        zlog_debug ("HelloInterval mismatch");
      return;
    }

  /* RouterDeadInterval check */
  if (ntohs (hello->dead_interval) != oi->dead_interval)
    {
      if (IS_OSPF6_DEBUG_MESSAGE (oh->type, RECV))
        zlog_debug ("RouterDeadInterval mismatch");
      return;
    }

  /* E-bit check */
#ifdef OSPF6_MANET
  if (OSPF6_OPT_ISSET (hello->options, OSPF6_OPT_E,2) !=
      OSPF6_OPT_ISSET (oi->area->options, OSPF6_OPT_E,2))
#else
  if (OSPF6_OPT_ISSET (hello->options, OSPF6_OPT_E) !=
      OSPF6_OPT_ISSET (oi->area->options, OSPF6_OPT_E))
#endif //OSPF6_MANET
    {
      if (IS_OSPF6_DEBUG_MESSAGE (oh->type, RECV))
        zlog_debug ("E-bit mismatch");
      return;
    }

  /* Find neighbor, create if not exist */
  on = ospf6_neighbor_lookup (oh->router_id, oi);
  if (on == NULL)
    {
      on = ospf6_neighbor_create (oh->router_id, oi);
      on->prev_drouter = on->drouter = hello->drouter;
      on->prev_bdrouter = on->bdrouter = hello->bdrouter;
      on->priority = hello->priority;
      on->ifindex = ntohl (hello->interface_id);
      memcpy (&on->linklocal_addr, src, sizeof (struct in6_addr));
    }

  /* TwoWay check */
  for (p = (char *) ((caddr_t) hello + sizeof (struct ospf6_hello));
       p + sizeof (u_int32_t) <= OSPF6_MESSAGE_END (oh);
       p += sizeof (u_int32_t))
    {
      u_int32_t *router_id = (u_int32_t *) p;

      if (*router_id == oi->area->ospf6->router_id)
        twoway++;
    }

  if (p != OSPF6_MESSAGE_END (oh))
    {
      if (IS_OSPF6_DEBUG_MESSAGE (oh->type, RECV))
        zlog_debug ("Trailing garbage ignored");
    }

  /* RouterPriority check */
  if (on->priority != hello->priority)
    {
      on->priority = hello->priority;
      neighborchange++;
    }

  /* DR check */
  if (on->drouter != hello->drouter)
    {
      on->prev_drouter = on->drouter;
      on->drouter = hello->drouter;
      if (on->prev_drouter == on->router_id || on->drouter == on->router_id)
        neighborchange++;
    }

  /* BDR check */
  if (on->bdrouter != hello->bdrouter)
    {
      on->prev_bdrouter = on->bdrouter;
      on->bdrouter = hello->bdrouter;
      if (on->prev_bdrouter == on->router_id || on->bdrouter == on->router_id)
        neighborchange++;
    }

  /* BackupSeen check */
  if (oi->state == OSPF6_INTERFACE_WAITING)
    {
      if (hello->bdrouter == on->router_id)
        backupseen++;
      else if (hello->drouter == on->router_id && hello->bdrouter == htonl (0))
        backupseen++;
    }

  /* Execute neighbor events */
  thread_execute (master, hello_received, on, 0);
  if (twoway)
    thread_execute (master, twoway_received, on, 0);
  else
    thread_execute (master, oneway_received, on, 0);

  /* Schedule interface events */
  if (backupseen)
    thread_add_event (master, backup_seen, oi, 0);
  if (neighborchange)
    thread_add_event (master, neighbor_change, oi, 0);
}

static void
ospf6_dbdesc_recv_master (struct ospf6_header *oh,
                          struct ospf6_neighbor *on)
{
  struct ospf6_dbdesc *dbdesc;
  char *p;
#ifdef SIM_ETRACE_STAT
  int diff_count = 0;
  char diff_buf[4000];
  sprintf(diff_buf, "LSAs: ");
#endif //SIM_ETRACE_STAT

  dbdesc = (struct ospf6_dbdesc *)
    ((caddr_t) oh + sizeof (struct ospf6_header));

  if (on->state < OSPF6_NEIGHBOR_INIT)
    {
      if (IS_OSPF6_DEBUG_MESSAGE (oh->type, RECV))
        zlog_debug ("Neighbor state less than Init, ignore");
      return;
    }

  switch (on->state)
    {
    case OSPF6_NEIGHBOR_TWOWAY:
      if (IS_OSPF6_DEBUG_MESSAGE (oh->type, RECV))
        zlog_debug ("Neighbor state is 2-Way, ignore");
      return;

    case OSPF6_NEIGHBOR_INIT:
      thread_execute (master, twoway_received, on, 0);
      if (on->state != OSPF6_NEIGHBOR_EXSTART)
        {
          if (IS_OSPF6_DEBUG_MESSAGE (oh->type, RECV))
            zlog_debug ("Neighbor state is not ExStart, ignore");
          return;
        }
      /* else fall through to ExStart */

    case OSPF6_NEIGHBOR_EXSTART:
      /* if neighbor obeys us as our slave, schedule negotiation_done
         and process LSA Headers. Otherwise, ignore this message */
      if (! CHECK_FLAG (dbdesc->bits, OSPF6_DBDESC_MSBIT) &&
          ! CHECK_FLAG (dbdesc->bits, OSPF6_DBDESC_IBIT) &&
          ntohl (dbdesc->seqnum) == on->dbdesc_seqnum)
        {
          /* execute NegotiationDone */
          thread_execute (master, negotiation_done, on, 0);

          /* Record neighbor options */
          memcpy (on->options, dbdesc->options, sizeof (on->options));
        }
      else
        {
          if (IS_OSPF6_DEBUG_MESSAGE (oh->type, RECV))
            zlog_debug ("Negotiation failed");
          return;
        }
      /* fall through to exchange */

    case OSPF6_NEIGHBOR_EXCHANGE:
      if (! memcmp (dbdesc, &on->dbdesc_last, sizeof (struct ospf6_dbdesc)))
        {
          /* Duplicated DatabaseDescription is dropped by master */
          if (IS_OSPF6_DEBUG_MESSAGE (oh->type, RECV))
            zlog_debug ("Duplicated dbdesc discarded by Master, ignore");
          return;
        }

      if (CHECK_FLAG (dbdesc->bits, OSPF6_DBDESC_MSBIT))
        {
          if (IS_OSPF6_DEBUG_MESSAGE (oh->type, RECV))
            zlog_debug ("Master/Slave bit mismatch");
          thread_add_event (master, seqnumber_mismatch, on, 0);
          return;
        }

      if (CHECK_FLAG (dbdesc->bits, OSPF6_DBDESC_IBIT))
        {
          if (IS_OSPF6_DEBUG_MESSAGE (oh->type, RECV))
            zlog_debug ("Initialize bit mismatch");
          thread_add_event (master, seqnumber_mismatch, on, 0);
          return;
        }

#ifdef OSPF6_MANET_MDR_FLOOD
      OSPF6_OPT_CLEAR(on->options,OSPF6_OPT_L,1);
      OSPF6_OPT_CLEAR(dbdesc->options,OSPF6_OPT_L,1);
#endif //OSPF6_MANET_MDR_FLOOD
      if (memcmp (on->options, dbdesc->options, sizeof (on->options)))
        {
          if (IS_OSPF6_DEBUG_MESSAGE (oh->type, RECV))
            zlog_debug ("Option field mismatch");
          thread_add_event (master, seqnumber_mismatch, on, 0);
          return;
        }

      if (ntohl (dbdesc->seqnum) != on->dbdesc_seqnum)
        {
          if (IS_OSPF6_DEBUG_MESSAGE (oh->type, RECV))
            zlog_debug ("Sequence number mismatch (%#lx expected)",
                         (u_long) on->dbdesc_seqnum);
          thread_add_event (master, seqnumber_mismatch, on, 0);
          return;
        }
      break;

    case OSPF6_NEIGHBOR_LOADING:
    case OSPF6_NEIGHBOR_FULL:
      if (! memcmp (dbdesc, &on->dbdesc_last, sizeof (struct ospf6_dbdesc)))
        {
          /* Duplicated DatabaseDescription is dropped by master */
          if (IS_OSPF6_DEBUG_MESSAGE (oh->type, RECV))
            zlog_debug ("Duplicated dbdesc discarded by Master, ignore");
          return;
        }

      if (IS_OSPF6_DEBUG_MESSAGE (oh->type, RECV))
        zlog_debug ("Not duplicate dbdesc in state %s",
		    ospf6_neighbor_state_str[on->state]);
      thread_add_event (master, seqnumber_mismatch, on, 0);
      return;

    default:
      assert (0);
      break;
    }

  /* Process LSA headers */
  for (p = (char *) ((caddr_t) dbdesc + sizeof (struct ospf6_dbdesc));
       p + sizeof (struct ospf6_lsa_header) <= OSPF6_MESSAGE_END (oh);
       p += sizeof (struct ospf6_lsa_header))
    {
      struct ospf6_lsa *his, *mine;
      struct ospf6_lsdb *lsdb = NULL;
#ifdef OSPF6_MANET_TEMPORARY_LSDB
      struct ospf6_lsa *mine_cache = NULL;
#endif //OSPF6_MANET_TEMPORARY_LSDB

      his = ospf6_lsa_create_headeronly ((struct ospf6_lsa_header *) p);

      if (IS_OSPF6_DEBUG_MESSAGE (oh->type, RECV))
        zlog_debug ("%s", his->name);

      switch (OSPF6_LSA_SCOPE (his->header->type))
        {
        case OSPF6_SCOPE_LINKLOCAL:
          lsdb = on->ospf6_if->lsdb;
          break;
        case OSPF6_SCOPE_AREA:
          lsdb = on->ospf6_if->area->lsdb;
          break;
        case OSPF6_SCOPE_AS:
          lsdb = on->ospf6_if->area->ospf6->lsdb;
          break;
        case OSPF6_SCOPE_RESERVED:
          if (IS_OSPF6_DEBUG_MESSAGE (oh->type, RECV))
            zlog_debug ("Ignoring LSA of reserved scope");
          ospf6_lsa_delete (his);
          continue;
          break;
        }

      if (ntohs (his->header->type) == OSPF6_LSTYPE_AS_EXTERNAL &&
          IS_AREA_STUB (on->ospf6_if->area))
        {
          if (IS_OSPF6_DEBUG_MESSAGE (oh->type, RECV))
            zlog_debug ("SeqNumMismatch (E-bit mismatch), discard");
          ospf6_lsa_delete (his);
          thread_add_event (master, seqnumber_mismatch, on, 0);
          return;
        }

      mine = ospf6_lsdb_lookup (his->header->type, his->header->id,
                                his->header->adv_router, lsdb);
#ifdef OSPF6_MANET
      if (mine == NULL || ospf6_lsa_compare (his, mine) < 0)
      { //I don't have this LSA or "his" LSA is newer
#ifdef OSPF6_MANET_TEMPORARY_LSDB
        mine_cache = ospf6_lsdb_lookup_cache(his->header->type, his->header->id,
                                             his->header->adv_router, lsdb);
        if(on->ospf6_if->type == OSPF6_IFTYPE_MANETRELIABLE &&
           mine_cache && ospf6_lsa_compare (his, mine_cache) == 0)
        {
          struct ospf6_lsa *mine_lsdb = ospf6_lsa_copy(mine_cache);
          /* (b) immediately flood and (c) remove from all retrans-list */
          ospf6_flood (on, mine_lsdb);

          /* (d), installing lsdb, which may cause routing
           * table calculation (replacing database copy) */
          ospf6_install_lsa (mine_lsdb);
          /* remove lsa from lsdb_cache */
          ospf6_lsdb_remove (mine_cache, lsdb);
        }
        else
        {
          if (IS_OSPF6_DEBUG_MESSAGE (oh->type, RECV))
          {
            if (mine == NULL)
              zlog_debug ("Add request (No database copy)");
            else
              zlog_debug ("Add request (Received MoreRecent)");
          }
          ospf6_lsdb_add (his, on->request_list);
        }
#else
        if (IS_OSPF6_DEBUG_MESSAGE (oh->type, RECV))
        {
          if (mine == NULL)
            zlog_debug ("Add request (No database copy)");
          else
            zlog_debug ("Add request (Received MoreRecent)");
        }
        ospf6_lsdb_add (his, on->request_list);
#endif //OSPF6_MANET_TEMPORARY_LSDB
#ifdef SIM_ETRACE_STAT
        strcat(diff_buf, his->name);
        diff_count++;
#endif //SIM_ETRACE_STAT
      }
#ifdef OSPF6_MANET_MDR_FLOOD_DD
      {
      // If his is newer or same as mine, then remove mine
      // from summary_list for neighbor
      struct ospf6_lsa *mine_summary;
      if (mine != NULL && ospf6_lsa_compare (his, mine) <= 0)
      {
        mine_summary = ospf6_lsdb_lookup (his->header->type, his->header->id,
                              his->header->adv_router, on->summary_list);
        if (mine_summary) ospf6_lsdb_remove (mine_summary, on->summary_list);
      }
      }
#endif //OSPF6_MANET_MDR_FLOOD_DD
#else //OSPF6_MANET
      if (mine == NULL)
        {
          if (IS_OSPF6_DEBUG_MESSAGE (oh->type, RECV))
            zlog_debug ("Add request (No database copy)");
          ospf6_lsdb_add (his, on->request_list);
        }
      else if (ospf6_lsa_compare (his, mine) < 0)
        {
          if (IS_OSPF6_DEBUG_MESSAGE (oh->type, RECV))
            zlog_debug ("Add request (Received MoreRecent)");
          ospf6_lsdb_add (his, on->request_list);
        }
#endif //OSPF6_MANET
#ifdef OSPF6_MANET_MDR_FLOOD_DD
      if (!(mine == NULL || ospf6_lsa_compare (his, mine) < 0))
#else
      else
#endif //OSPF6_MANET_MDR_FLOOD_DD
        {
          if (IS_OSPF6_DEBUG_MESSAGE (oh->type, RECV))
            zlog_debug ("Discard (Existing MoreRecent)");
          ospf6_lsa_delete (his);
        }
    }

#ifdef SIM_ETRACE_STAT
  if (p != (char *)((caddr_t)dbdesc+sizeof(struct ospf6_dbdesc)))
  {
    TraceEvent_sim(1,"LSA_DATABASE sync diff %d neighbor %s %s",
                   diff_count, on->name, diff_buf);
    update_statistics(OSPF6_DATABASE_EXCHANGES, 1);
    update_statistics(OSPF6_NUM_LSA_DIFFS, (double)diff_count);
  }
#endif //SIM_ETRACE_STAT

  if (p != OSPF6_MESSAGE_END (oh))
    {
      if (IS_OSPF6_DEBUG_MESSAGE (oh->type, RECV))
        zlog_debug ("Trailing garbage ignored");
    }

  /* Increment sequence number */
  on->dbdesc_seqnum ++;

  /* schedule send lsreq */
  if (on->thread_send_lsreq == NULL)
    on->thread_send_lsreq =
      thread_add_event (master, ospf6_lsreq_send, on, 0);

  THREAD_OFF (on->thread_send_dbdesc);

  /* More bit check */
  if (! CHECK_FLAG (dbdesc->bits, OSPF6_DBDESC_MBIT) &&
      ! CHECK_FLAG (on->dbdesc_bits, OSPF6_DBDESC_MBIT))
    thread_add_event (master, exchange_done, on, 0);
  else
    on->thread_send_dbdesc =
      thread_add_event (master, ospf6_dbdesc_send_newone, on, 0);

  /* save last received dbdesc */
  memcpy (&on->dbdesc_last, dbdesc, sizeof (struct ospf6_dbdesc));
}

static void
ospf6_dbdesc_recv_slave (struct ospf6_header *oh,
                         struct ospf6_neighbor *on)
{
  struct ospf6_dbdesc *dbdesc;
  char *p;
#ifdef SIM_ETRACE_STAT
  int diff_count = 0;
  char diff_buf[4000];
  sprintf(diff_buf, "LSAs: ");
#endif //SIM_ETRACE_STAT

  dbdesc = (struct ospf6_dbdesc *)
    ((caddr_t) oh + sizeof (struct ospf6_header));

  if (on->state < OSPF6_NEIGHBOR_INIT)
    {
      if (IS_OSPF6_DEBUG_MESSAGE (oh->type, RECV))
        zlog_debug ("Neighbor state less than Init, ignore");
      return;
    }

  switch (on->state)
    {
    case OSPF6_NEIGHBOR_TWOWAY:
      if (IS_OSPF6_DEBUG_MESSAGE (oh->type, RECV))
        zlog_debug ("Neighbor state is 2-Way, ignore");
      return;

    case OSPF6_NEIGHBOR_INIT:
      thread_execute (master, twoway_received, on, 0);
      if (on->state != OSPF6_NEIGHBOR_EXSTART)
        {
          if (IS_OSPF6_DEBUG_MESSAGE (oh->type, RECV))
            zlog_debug ("Neighbor state is not ExStart, ignore");
          return;
        }
      /* else fall through to ExStart */

    case OSPF6_NEIGHBOR_EXSTART:
      /* If the neighbor is Master, act as Slave. Schedule negotiation_done
         and process LSA Headers. Otherwise, ignore this message */
      if (CHECK_FLAG (dbdesc->bits, OSPF6_DBDESC_IBIT) &&
          CHECK_FLAG (dbdesc->bits, OSPF6_DBDESC_MBIT) &&
          CHECK_FLAG (dbdesc->bits, OSPF6_DBDESC_MSBIT) &&
          ntohs (oh->length) == sizeof (struct ospf6_header) +
                                sizeof (struct ospf6_dbdesc))
        {
          /* set the master/slave bit to slave */
          UNSET_FLAG (on->dbdesc_bits, OSPF6_DBDESC_MSBIT);

          /* set the DD sequence number to one specified by master */
          on->dbdesc_seqnum = ntohl (dbdesc->seqnum);

          /* schedule NegotiationDone */
          thread_execute (master, negotiation_done, on, 0);

          /* Record neighbor options */
          memcpy (on->options, dbdesc->options, sizeof (on->options));
        }
      else
        {
          if (IS_OSPF6_DEBUG_MESSAGE (oh->type, RECV))
            zlog_debug ("Negotiation failed");
          return;
        }
      break;

    case OSPF6_NEIGHBOR_EXCHANGE:
      if (! memcmp (dbdesc, &on->dbdesc_last, sizeof (struct ospf6_dbdesc)))
        {
          /* Duplicated DatabaseDescription causes slave to retransmit */
          if (IS_OSPF6_DEBUG_MESSAGE (oh->type, RECV))
            zlog_debug ("Duplicated dbdesc causes retransmit");
          THREAD_OFF (on->thread_send_dbdesc);
          on->thread_send_dbdesc =
            thread_add_event (master, ospf6_dbdesc_send, on, 0);
          return;
        }

      if (! CHECK_FLAG (dbdesc->bits, OSPF6_DBDESC_MSBIT))
        {
          if (IS_OSPF6_DEBUG_MESSAGE (oh->type, RECV))
            zlog_debug ("Master/Slave bit mismatch");
          thread_add_event (master, seqnumber_mismatch, on, 0);
          return;
        }

      if (CHECK_FLAG (dbdesc->bits, OSPF6_DBDESC_IBIT))
        {
          if (IS_OSPF6_DEBUG_MESSAGE (oh->type, RECV))
            zlog_debug ("Initialize bit mismatch");
          thread_add_event (master, seqnumber_mismatch, on, 0);
          return;
        }
#ifdef OSPF6_MANET_MDR_FLOOD
      OSPF6_OPT_CLEAR(on->options,OSPF6_OPT_L,1);
      OSPF6_OPT_CLEAR(dbdesc->options,OSPF6_OPT_L,1);
#endif //OSPF6_MANET_MDR_FLOOD
      if (memcmp (on->options, dbdesc->options, sizeof (on->options)))
        {
          if (IS_OSPF6_DEBUG_MESSAGE (oh->type, RECV))
            zlog_debug ("Option field mismatch");
          thread_add_event (master, seqnumber_mismatch, on, 0);
          return;
        }

      if (ntohl (dbdesc->seqnum) != on->dbdesc_seqnum + 1)
        {
          if (IS_OSPF6_DEBUG_MESSAGE (oh->type, RECV))
            zlog_debug ("Sequence number mismatch (%#lx expected)",
                         (u_long) on->dbdesc_seqnum + 1);
          thread_add_event (master, seqnumber_mismatch, on, 0);
          return;
        }
      break;

    case OSPF6_NEIGHBOR_LOADING:
    case OSPF6_NEIGHBOR_FULL:
      if (! memcmp (dbdesc, &on->dbdesc_last, sizeof (struct ospf6_dbdesc)))
        {
          /* Duplicated DatabaseDescription causes slave to retransmit */
          if (IS_OSPF6_DEBUG_MESSAGE (oh->type, RECV))
            zlog_debug ("Duplicated dbdesc causes retransmit");
          THREAD_OFF (on->thread_send_dbdesc);
          on->thread_send_dbdesc =
            thread_add_event (master, ospf6_dbdesc_send, on, 0);
          return;
        }

      if (IS_OSPF6_DEBUG_MESSAGE (oh->type, RECV))
        zlog_debug ("Not duplicate dbdesc in state %s",
		    ospf6_neighbor_state_str[on->state]);
      thread_add_event (master, seqnumber_mismatch, on, 0);
      return;

    default:
      assert (0);
      break;
    }

  /* Process LSA headers */
  for (p = (char *) ((caddr_t) dbdesc + sizeof (struct ospf6_dbdesc));
       p + sizeof (struct ospf6_lsa_header) <= OSPF6_MESSAGE_END (oh);
       p += sizeof (struct ospf6_lsa_header))
    {
      struct ospf6_lsa *his, *mine;
      struct ospf6_lsdb *lsdb = NULL;
#ifdef OSPF6_MANET_TEMPORARY_LSDB
      struct ospf6_lsa *mine_cache=NULL;
#endif //OSPF6_MANET_TEMPORARY_LSDB

      his = ospf6_lsa_create_headeronly ((struct ospf6_lsa_header *) p);

      switch (OSPF6_LSA_SCOPE (his->header->type))
        {
        case OSPF6_SCOPE_LINKLOCAL:
          lsdb = on->ospf6_if->lsdb;
          break;
        case OSPF6_SCOPE_AREA:
          lsdb = on->ospf6_if->area->lsdb;
          break;
        case OSPF6_SCOPE_AS:
          lsdb = on->ospf6_if->area->ospf6->lsdb;
          break;
        case OSPF6_SCOPE_RESERVED:
          if (IS_OSPF6_DEBUG_MESSAGE (oh->type, RECV))
            zlog_debug ("Ignoring LSA of reserved scope");
          ospf6_lsa_delete (his);
          continue;
          break;
        }

      if (OSPF6_LSA_SCOPE (his->header->type) == OSPF6_SCOPE_AS &&
          IS_AREA_STUB (on->ospf6_if->area))
        {
          if (IS_OSPF6_DEBUG_MESSAGE (oh->type, RECV))
            zlog_debug ("E-bit mismatch with LSA Headers");
          ospf6_lsa_delete (his);
          thread_add_event (master, seqnumber_mismatch, on, 0);
          return;
        }

      mine = ospf6_lsdb_lookup (his->header->type, his->header->id,
                                his->header->adv_router, lsdb);
      if (mine == NULL || ospf6_lsa_compare (his, mine) < 0)
      {
#ifdef OSPF6_MANET_TEMPORARY_LSDB
        mine_cache = ospf6_lsdb_lookup_cache(his->header->type, his->header->id,
                                             his->header->adv_router, lsdb);
        if(on->ospf6_if->type == OSPF6_IFTYPE_MANETRELIABLE &&
           mine_cache && ospf6_lsa_compare (his, mine_cache) == 0)
        {
          struct ospf6_lsa *mine_lsdb = ospf6_lsa_copy(mine_cache);
          /* (b) immediately flood and (c) remove from all retrans-list */
          ospf6_flood (on, mine_lsdb);

          /* (d), installing lsdb, which may cause routing
           * table calculation (replacing database copy) */
          ospf6_install_lsa (mine_lsdb);
          /* remove lsa from lsdb_cache */
          ospf6_lsdb_remove (mine_cache, lsdb);
        }
        else
        {
          if (IS_OSPF6_DEBUG_MESSAGE (oh->type, RECV))
            zlog_debug ("Add request-list: %s", his->name);
          ospf6_lsdb_add (his, on->request_list);
        }
#else
        if (IS_OSPF6_DEBUG_MESSAGE (oh->type, RECV))
          zlog_debug ("Add request-list: %s", his->name);
        ospf6_lsdb_add (his, on->request_list);
#endif //OSPF6_MANET_TEMPORARY_LSDB
#ifdef SIM_ETRACE_STAT
        strcat(diff_buf, his->name);
        diff_count++;
#endif //SIM_ETRACE_STAT
      }
#ifdef OSPF6_MANET_MDR_FLOOD_DD
      {
      // If his is newer or same as mine, then remove mine
      // from summary_list for neighbor
      struct ospf6_lsa *mine_summary;
      if (mine != NULL && ospf6_lsa_compare (his, mine) <= 0)
      {
        mine_summary = ospf6_lsdb_lookup (his->header->type, his->header->id,
                              his->header->adv_router, on->summary_list);
        if (mine_summary) ospf6_lsdb_remove (mine_summary, on->summary_list);
      }
      }
      if (!(mine == NULL || ospf6_lsa_compare (his, mine) < 0))
#else
      else
#endif //OSPF6_MANET_MDR_FLOOD_DD
        ospf6_lsa_delete (his);
    }

#ifdef SIM_ETRACE_STAT
  if (p != (char *)((caddr_t)dbdesc+sizeof(struct ospf6_dbdesc)))
  {
    TraceEvent_sim(1,"LSA_DATABASE sync diff %d neighbor %s %s",
                   diff_count, on->name, diff_buf);
    update_statistics(OSPF6_DATABASE_EXCHANGES, 1);
    update_statistics(OSPF6_NUM_LSA_DIFFS, (double)diff_count);
  }
#endif //SIM_ETRACE_STAT

  if (p != OSPF6_MESSAGE_END (oh))
    {
      if (IS_OSPF6_DEBUG_MESSAGE (oh->type, RECV))
        zlog_debug ("Trailing garbage ignored");
    }

  /* Set sequence number to Master's */
  on->dbdesc_seqnum = ntohl (dbdesc->seqnum);

  /* schedule send lsreq */
  if (on->thread_send_lsreq == NULL)
    on->thread_send_lsreq =
      thread_add_event (master, ospf6_lsreq_send, on, 0);

  THREAD_OFF (on->thread_send_dbdesc);
  on->thread_send_dbdesc =
    thread_add_event (master, ospf6_dbdesc_send_newone, on, 0);

  /* save last received dbdesc */
  memcpy (&on->dbdesc_last, dbdesc, sizeof (struct ospf6_dbdesc));
}

void
#ifdef OSPF6_MANET
ospf6_dbdesc_recv (struct in6_addr *src, struct in6_addr *dst,
                   struct ospf6_interface *oi, struct ospf6_header *oh, int len)
#else
ospf6_dbdesc_recv (struct in6_addr *src, struct in6_addr *dst,
                   struct ospf6_interface *oi, struct ospf6_header *oh)
#endif //OSPF6_MANET
{
  struct ospf6_neighbor *on;
  struct ospf6_dbdesc *dbdesc;

  if (ospf6_header_examin (src, dst, oi, oh) != MSG_OK)
    return;

  on = ospf6_neighbor_lookup (oh->router_id, oi);
  if (on == NULL)
    {
      if (IS_OSPF6_DEBUG_MESSAGE (oh->type, RECV))
        zlog_debug ("Neighbor not found, ignore");
      return;
    }

  if (memcmp (src, &on->linklocal_addr, sizeof (struct in6_addr)))
    {
      if (IS_OSPF6_DEBUG_MESSAGE (oh->type, RECV))
        zlog_debug ("Seems to be from Secondary I/F of the neighbor, ignore");
      return;
    }

  dbdesc = (struct ospf6_dbdesc *)
    ((caddr_t) oh + sizeof (struct ospf6_header));

  /* Interface MTU check */
  if (ntohs (dbdesc->ifmtu) != oi->ifmtu)
    {
      if (IS_OSPF6_DEBUG_MESSAGE (oh->type, RECV))
        zlog_debug ("I/F MTU mismatch");
      return;
    }

  if (dbdesc->reserved1 || dbdesc->reserved2)
    {
      if (IS_OSPF6_DEBUG_MESSAGE (oh->type, RECV))
        zlog_debug ("Non-0 reserved field in %s's DbDesc, correct",
		    on->name);
      dbdesc->reserved1 = 0;
      dbdesc->reserved2 = 0;
    }

#ifdef OSPF6_MANET_MDR_FLOOD
  if (on->ospf6_if->type == OSPF6_IFTYPE_MANETRELIABLE &&
      on->ospf6_if->flooding == OSPF6_FLOOD_MDR_SICDS)
  {
    if (OSPF6_OPT_ISSET(dbdesc->options, OSPF6_OPT_L,1) &&
        len > ntohs(oh->length))
    {
      struct ospf6_LLS_header *lls_ptr = 
        (struct ospf6_LLS_header *) OSPF6_MESSAGE_END (oh); 
      ospf6_mdr_process_mdr_TLVs(on, lls_ptr);
    }
    //this is required due to not moving to EXSTART in twoway_received()
    if (on->state == OSPF6_NEIGHBOR_INIT)
      ospf6_neighbor_state_change (OSPF6_NEIGHBOR_TWOWAY, on);
    if (on->state == OSPF6_NEIGHBOR_TWOWAY && need_adjacency(on))
    {
      ospf6_neighbor_state_change (OSPF6_NEIGHBOR_EXSTART, on);
      SET_FLAG (on->dbdesc_bits, OSPF6_DBDESC_MSBIT);
      SET_FLAG (on->dbdesc_bits, OSPF6_DBDESC_MBIT);
      SET_FLAG (on->dbdesc_bits, OSPF6_DBDESC_IBIT);

      if (ntohl (oh->router_id) < ntohl (ospf6->router_id))
      {
        //if neighbor state is TWOWAY and adjacency is needed, 
        //then send DD packet only if router is master (has larger 
        //ID than neighbor).  If router is slave, then negotiation is 
        //finished upon reception of the DD packet, and 
        //this will be handled in ospf6_dbdesc_recv_slave(). 
        THREAD_OFF (on->thread_send_dbdesc);
        on->thread_send_dbdesc =
        thread_add_event (master, ospf6_dbdesc_send, on, 0);
      }
    }
  }
#endif //OSPF6_MANET_MDR_FLOOD

#ifdef OSPF6_MANET_MPR_SP
  if (on->ospf6_if->type == OSPF6_IFTYPE_MANETRELIABLE &&
      on->ospf6_if->flooding == OSPF6_FLOOD_MPR_SDCDS &&
      on->ospf6_if->smart_peering)
  {
  //Always form an adjacency if it is inititiated by a neighbor, so
  //dd packets aren't retransmitted.
    if (on->state == OSPF6_NEIGHBOR_TWOWAY)
    {
      ospf6_neighbor_state_change (OSPF6_NEIGHBOR_EXSTART, on);
      SET_FLAG (on->dbdesc_bits, OSPF6_DBDESC_MSBIT);
      SET_FLAG (on->dbdesc_bits, OSPF6_DBDESC_MBIT);
      SET_FLAG (on->dbdesc_bits, OSPF6_DBDESC_IBIT);

      if (ntohl (oh->router_id) < ntohl (ospf6->router_id))
      {
        //if neighbor state is TWOWAY and adjacency is needed,
        //then send DD packet only if router is master (has larger
        //ID than neighbor).  If router is slave, then negotiation is
        //finished upon reception of the DD packet, and
        //this will be handled in ospf6_dbdesc_recv_slave().
        THREAD_OFF (on->thread_send_dbdesc);
        on->thread_send_dbdesc =
        thread_add_event (master, ospf6_dbdesc_send, on, 0);
      }
    }
  }
#endif //OSPF6_MANET_MPR_SP

  if (ntohl (oh->router_id) < ntohl (ospf6->router_id))
    ospf6_dbdesc_recv_master (oh, on);
  else if (ntohl (ospf6->router_id) < ntohl (oh->router_id))
    ospf6_dbdesc_recv_slave (oh, on);
  else
    {
      if (IS_OSPF6_DEBUG_MESSAGE (oh->type, RECV))
        zlog_debug ("Can't decide which is master, ignore");
    }
}

void
ospf6_lsreq_recv (struct in6_addr *src, struct in6_addr *dst,
                  struct ospf6_interface *oi, struct ospf6_header *oh)
{
  struct ospf6_neighbor *on;
  char *p;
  struct ospf6_lsreq_entry *e;
  struct ospf6_lsdb *lsdb = NULL;
  struct ospf6_lsa *lsa;

  if (ospf6_header_examin (src, dst, oi, oh) != MSG_OK)
    return;

  on = ospf6_neighbor_lookup (oh->router_id, oi);
  if (on == NULL)
    {
      if (IS_OSPF6_DEBUG_MESSAGE (oh->type, RECV))
        zlog_debug ("Neighbor not found, ignore");
      return;
    }

  if (memcmp (src, &on->linklocal_addr, sizeof (struct in6_addr)))
    {
      if (IS_OSPF6_DEBUG_MESSAGE (oh->type, RECV))
        zlog_debug ("Seems to be from Secondary I/F of the neighbor, ignore");
      return;
    }

  if (on->state != OSPF6_NEIGHBOR_EXCHANGE &&
      on->state != OSPF6_NEIGHBOR_LOADING &&
      on->state != OSPF6_NEIGHBOR_FULL)
    {
      if (IS_OSPF6_DEBUG_MESSAGE (oh->type, RECV))
        zlog_debug ("Neighbor state less than Exchange, ignore");
      return;
    }

  /* Process each request */
  for (p = (char *) ((caddr_t) oh + sizeof (struct ospf6_header));
       p + sizeof (struct ospf6_lsreq_entry) <= OSPF6_MESSAGE_END (oh);
       p += sizeof (struct ospf6_lsreq_entry))
    {
      e = (struct ospf6_lsreq_entry *) p;

      switch (OSPF6_LSA_SCOPE (e->type))
        {
        case OSPF6_SCOPE_LINKLOCAL:
          lsdb = on->ospf6_if->lsdb;
          break;
        case OSPF6_SCOPE_AREA:
          lsdb = on->ospf6_if->area->lsdb;
          break;
        case OSPF6_SCOPE_AS:
          lsdb = on->ospf6_if->area->ospf6->lsdb;
          break;
        default:
          if (IS_OSPF6_DEBUG_MESSAGE (oh->type, RECV))
            zlog_debug ("Ignoring LSA of reserved scope");
          continue;
          break;
        }

      /* Find database copy */
      lsa = ospf6_lsdb_lookup (e->type, e->id, e->adv_router, lsdb);
      if (lsa == NULL)
        {
          char id[16], adv_router[16];
          if (IS_OSPF6_DEBUG_MESSAGE (oh->type, RECV))
            {
              inet_ntop (AF_INET, &e->id, id, sizeof (id));
              inet_ntop (AF_INET, &e->adv_router, adv_router,
                     sizeof (adv_router));
              zlog_debug ("Can't find requested [%s Id:%s Adv:%s]",
			  ospf6_lstype_name (e->type), id, adv_router);
            }
          thread_add_event (master, bad_lsreq, on, 0);
          return;
        }

      ospf6_lsdb_add (ospf6_lsa_copy (lsa), on->lsupdate_list);
    }

  if (p != OSPF6_MESSAGE_END (oh))
    {
      if (IS_OSPF6_DEBUG_MESSAGE (oh->type, RECV))
        zlog_debug ("Trailing garbage ignored");
    }

  /* schedule send lsupdate */


#ifdef OSPF6_DELAYED_FLOOD
  on->thread_send_lsupdate =
    ospf6_send_lsupdate_delayed_msec(master, ospf6_lsupdate_send_neighbor,
                                     on, on->ospf6_if->flood_delay, 
                                     on->thread_send_lsupdate);
#else
  THREAD_OFF (on->thread_send_lsupdate);
  on->thread_send_lsupdate =
    thread_add_event (master, ospf6_lsupdate_send_neighbor, on, 0);
#endif //OSPF6_DELAYED_FLOOD
}

void
ospf6_lsupdate_recv (struct in6_addr *src, struct in6_addr *dst,
                     struct ospf6_interface *oi, struct ospf6_header *oh)
{
  struct ospf6_neighbor *on;
  struct ospf6_lsupdate *lsupdate;
  unsigned long num;
  char *p;

  if (ospf6_header_examin (src, dst, oi, oh) != MSG_OK)
    return;

  on = ospf6_neighbor_lookup (oh->router_id, oi);
  if (on == NULL)
    {
      if (IS_OSPF6_DEBUG_MESSAGE (oh->type, RECV))
        zlog_debug ("Neighbor not found, ignore");
#ifdef OSPF6_MANET_TEMPORARY_LSDB
      ospf6_lsupdate_recv_below_exchange (src, dst, oi, oh);
#endif //OSPF6_MANET_TEMPORARY_LSDB
      return;
    }

  if (memcmp (src, &on->linklocal_addr, sizeof (struct in6_addr)))
    {
      if (IS_OSPF6_DEBUG_MESSAGE (oh->type, RECV))
        zlog_debug ("Seems to be from Secondary I/F of the neighbor, ignore");
      return;
    }

#ifdef OSPF6_MANET_MDR_FLOOD
  // receive LSAs from neighbors below 2-way Ogierv3 6 par 2
  if (on->ospf6_if->flooding == OSPF6_FLOOD_MDR_SICDS &&
      on->ospf6_if->type == OSPF6_IFTYPE_MANETRELIABLE)
  {
    if (on->state < OSPF6_NEIGHBOR_TWOWAY)
    {
      if (IS_OSPF6_DEBUG_MESSAGE (oh->type, RECV))
        zlog_debug ("Neighbor state less than 2-way, ignore");
      return;
    }
  }
  else 
#endif //OSPF6_MANET_MDR_FLOOD
#ifdef OSPF6_MANET_MPR_FLOOD  //SP_DRAFT_MOD  
  //receive LSAs from neighbors below 2-way 
  if (on->ospf6_if->flooding == OSPF6_FLOOD_MPR_SDCDS &&
      on->ospf6_if->type == OSPF6_IFTYPE_MANETRELIABLE)
  {
    if (on->state < OSPF6_NEIGHBOR_TWOWAY)
    {
      if (IS_OSPF6_DEBUG_MESSAGE (oh->type, RECV))
        zlog_debug ("Neighbor state less than 2-way, ignore");
      return;
    }
  }
  else
#endif //OSPF6_MANET_MPR_FLOOD
  if (on->state != OSPF6_NEIGHBOR_EXCHANGE &&
      on->state != OSPF6_NEIGHBOR_LOADING &&
      on->state != OSPF6_NEIGHBOR_FULL)
    {
      if (IS_OSPF6_DEBUG_MESSAGE (oh->type, RECV))
        zlog_debug ("Neighbor state less than Exchange, ignore");
#ifdef OSPF6_MANET_TEMPORARY_LSDB
      ospf6_lsupdate_recv_below_exchange (src, dst, oi, oh);
#endif //OSPF6_MANET_TEMPORARY_LSDB
      return;
    }

  lsupdate = (struct ospf6_lsupdate *)
    ((caddr_t) oh + sizeof (struct ospf6_header));

  num = ntohl (lsupdate->lsa_number);

  /* Process LSAs */
  for (p = (char *) ((caddr_t) lsupdate + sizeof (struct ospf6_lsupdate));
       p < OSPF6_MESSAGE_END (oh) &&
       p + OSPF6_LSA_SIZE (p) <= OSPF6_MESSAGE_END (oh);
       p += OSPF6_LSA_SIZE (p))
    {
      if (num == 0)
        break;
      if (OSPF6_LSA_SIZE (p) < sizeof (struct ospf6_lsa_header))
        {
          if (IS_OSPF6_DEBUG_MESSAGE (oh->type, RECV))
            zlog_debug ("Malformed LSA length, quit processing");
          break;
        }

      // Pass in dst address in case it is multicast
#ifdef OSPF6_MANET
      ospf6_receive_lsa ((struct ospf6_lsa_header *) p, on, dst);
#else
      ospf6_receive_lsa (on, (struct ospf6_lsa_header *) p);
#endif //OSPF6_MANET
      num--;
    }

  if (num != 0)
    {
      if (IS_OSPF6_DEBUG_MESSAGE (oh->type, RECV))
        zlog_debug ("Malformed LSA number or LSA length");
    }
  if (p != OSPF6_MESSAGE_END (oh))
    {
      if (IS_OSPF6_DEBUG_MESSAGE (oh->type, RECV))
        zlog_debug ("Trailing garbage ignored");
    }

  /* RFC2328 Section 10.9: When the neighbor responds to these requests
     with the proper Link State Update packet(s), the Link state request
     list is truncated and a new Link State Request packet is sent. */
  /* send new Link State Request packet if this LS Update packet
     can be recognized as a response to our previous LS Request */
  if (! IN6_IS_ADDR_MULTICAST (dst) &&
      (on->state == OSPF6_NEIGHBOR_EXCHANGE ||
       on->state == OSPF6_NEIGHBOR_LOADING))
    {
      THREAD_OFF (on->thread_send_lsreq);
#ifdef BUGFIX
      // this was causing a flood of requests and updates because the
      // LSA was not being accepted until after minLSArrival passed
      //XXX BOEING  Is delaying this send by MinLSArrival acceptable???
#ifdef SIM_ETRACE_STAT
      TraceEvent_sim(2,"Requesting LSAs from %s", on->name);
#endif //SIM_ETRACE_STAT
      on->thread_send_lsreq = thread_add_timer (master, ospf6_lsreq_send, on,
                                                oi->area->ospf6->minLSArrival);
#else
      on->thread_send_lsreq =thread_add_event (master, ospf6_lsreq_send, on, 0);
#endif //BUGFIX
    }
}

#ifdef OSPF6_MANET_TEMPORARY_LSDB
void
ospf6_lsupdate_recv_below_exchange (struct in6_addr *src, struct in6_addr *dst,
                     struct ospf6_interface *oi, struct ospf6_header *oh)
{
  struct ospf6_lsupdate *lsupdate;
  unsigned long num;
  char *p;
  struct ospf6_area *oa;
  struct listnode *i, *j;

  lsupdate = (struct ospf6_lsupdate *)
    ((caddr_t) oh + sizeof (struct ospf6_header));

 if(oi->type != OSPF6_IFTYPE_MANETRELIABLE)
  return;

  num = ntohl (lsupdate->lsa_number);

  /* Process LSAs */
  for (p = (char *) ((caddr_t) lsupdate + sizeof (struct ospf6_lsupdate));
       p < OSPF6_MESSAGE_END (oh) &&
       p + OSPF6_LSA_SIZE (p) <= OSPF6_MESSAGE_END (oh);
       p += OSPF6_LSA_SIZE (p))
    {
      if (num == 0)
        break;
      if (OSPF6_LSA_SIZE (p) < sizeof (struct ospf6_lsa_header))
        {
          if (IS_OSPF6_DEBUG_MESSAGE (oh->type, RECV))
            zlog_info ("Malformed LSA length, quit processing");
          break;
        }
   ospf6_receive_lsa_below_exchange ((struct ospf6_lsa_header *) p, oi);
      num--;
    }

  if (num != 0)
    {
      if (IS_OSPF6_DEBUG_MESSAGE (oh->type, RECV))
        zlog_info ("Malformed LSA number or LSA length");
    }
  if (p != OSPF6_MESSAGE_END (oh))
    {
      if (IS_OSPF6_DEBUG_MESSAGE (oh->type, RECV))
        zlog_info ("Trailing garbage ignored");
    }

 // XXX BOEING how should database be cleansed  FIXME
/*  for (i = listhead (oi->area->ospf6->area_list); i; nextnode (i))
    {
      oa = (struct ospf6_area *) getdata (i);
      for (j = listhead (oa->if_list); j; nextnode (j))
        {
          oi = (struct ospf6_interface *) getdata (j);
     if(oi->type == OSPF6_IFTYPE_MANETRELIABLE)
      ospf6_lsdb_maxage_remover(oi->lsdb_cache);
        }
      ospf6_lsdb_maxage_remover(oa->lsdb_cache);
    }
  ospf6_lsdb_maxage_remover(oi->area->ospf6->lsdb_cache);

}

void
ospf6_lsdb_maxage_remover(struct ospf6_lsdb *lsdb_cache)
{
 struct ospf6_lsa *lsa;

 for (lsa = ospf6_lsdb_head (lsdb_cache); lsa; lsa = ospf6_lsdb_next (lsa))
 {
  if (! OSPF6_LSA_IS_MAXAGE (lsa))
   continue;
  else if (lsa->retrans_count != 0)
   continue;
  if (IS_OSPF6_DEBUG_LSA_TYPE (lsa->header->type))
    zlog_info (" remove maxage %s", lsa->name);
  ospf6_lsdb_remove (lsa, lsdb_cache);
 }
*/
}
#endif //OSPF6_MANET_TEMPORARY_LSDB

void
ospf6_lsack_recv (struct in6_addr *src, struct in6_addr *dst,
                  struct ospf6_interface *oi, struct ospf6_header *oh)
{
  struct ospf6_neighbor *on;
  char *p;
  struct ospf6_lsa *his, *mine;
  struct ospf6_lsdb *lsdb = NULL;

  assert (oh->type == OSPF6_MESSAGE_TYPE_LSACK);
  if (ospf6_header_examin (src, dst, oi, oh) != MSG_OK)
    return;

  on = ospf6_neighbor_lookup (oh->router_id, oi);
  if (on == NULL)
    {
      if (IS_OSPF6_DEBUG_MESSAGE (oh->type, RECV))
        zlog_debug ("Neighbor not found, ignore");
      return;
    }

  if (memcmp (src, &on->linklocal_addr, sizeof (struct in6_addr)))
    {
      if (IS_OSPF6_DEBUG_MESSAGE (oh->type, RECV))
        zlog_debug ("Seems to be from Secondary I/F of the neighbor, ignore");
      return;
    }

#ifdef OSPF6_MANET_MPR_SH
  // SURROGATE_HELLO
  //Chandra03 3.4.9 paragraph 1 condition 6 and Chandra03 3.3.6.1 paragraph 1
  //received ack counts as received hello with no state change
  if (oi->type == OSPF6_IFTYPE_MANETRELIABLE &&
      oi->flooding == OSPF6_FLOOD_MPR_SDCDS)
//      (oi->flooding == OSPF6_FLOOD_MPR_SDCDS ||
//       oi->flooding == OSPF6_FLOOD_MDR_SICDS))  // XXX this works with SICDS
    thread_execute (master, hello_received, on, 0);
#endif //OSPF6_MANET_MPR_FLOOD

  if (on->state != OSPF6_NEIGHBOR_EXCHANGE &&
      on->state != OSPF6_NEIGHBOR_LOADING &&
      on->state != OSPF6_NEIGHBOR_FULL)
    {
      if (IS_OSPF6_DEBUG_MESSAGE (oh->type, RECV))
        zlog_debug ("Neighbor state less than Exchange, ignore");
      return;
    }

  for (p = (char *) ((caddr_t) oh + sizeof (struct ospf6_header));
       p + sizeof (struct ospf6_lsa_header) <= OSPF6_MESSAGE_END (oh);
       p += sizeof (struct ospf6_lsa_header))
    {
      his = ospf6_lsa_create_headeronly ((struct ospf6_lsa_header *) p);

      switch (OSPF6_LSA_SCOPE (his->header->type))
        {
        case OSPF6_SCOPE_LINKLOCAL:
          lsdb = on->ospf6_if->lsdb;
          break;
        case OSPF6_SCOPE_AREA:
          lsdb = on->ospf6_if->area->lsdb;
          break;
        case OSPF6_SCOPE_AS:
          lsdb = on->ospf6_if->area->ospf6->lsdb;
          break;
        case OSPF6_SCOPE_RESERVED:
          if (IS_OSPF6_DEBUG_MESSAGE (oh->type, RECV))
            zlog_debug ("Ignoring LSA of reserved scope");
          ospf6_lsa_delete (his);
          continue;
          break;
        }

      if (IS_OSPF6_DEBUG_MESSAGE (oh->type, RECV))
        zlog_debug ("%s acknowledged by %s", his->name, on->name);

#ifdef OSPF6_MANET
      ospf6_store_mack(on, his->header);
#endif //OSPF6_MANET

      /* Find database copy */
      mine = ospf6_lsdb_lookup (his->header->type, his->header->id,
                                his->header->adv_router, lsdb);
      if (mine == NULL)
        {
          if (IS_OSPF6_DEBUG_MESSAGE (oh->type, RECV))
            zlog_debug ("No database copy");
          ospf6_lsa_delete (his);
          continue;
        }

#ifdef OSPF6_MANET
      // Delete pushback neighbor corresponding to source of LSAck
      //Chandra03 3.4.9 paragraph 2
      if (on->ospf6_if->type == OSPF6_IFTYPE_MANETRELIABLE &&
          mine->pushBackTimer && ospf6_lsa_compare (his, mine) == 0)
      {
        ospf6_pushback_lsa_neighbor_delete(mine, on);
      }
#endif //OSPF6_MANET

      /* Check if the LSA is on his retrans-list */
      mine = ospf6_lsdb_lookup (his->header->type, his->header->id,
                                his->header->adv_router, on->retrans_list);
      if (mine == NULL)
        {
          if (IS_OSPF6_DEBUG_MESSAGE (oh->type, RECV))
            zlog_debug ("Not on %s's retrans-list", on->name);
          ospf6_lsa_delete (his);
          continue;
        }

      if (ospf6_lsa_compare (his, mine) != 0)
        {
          /* Log this questionable acknowledgement,
             and examine the next one. */
          if (IS_OSPF6_DEBUG_MESSAGE (oh->type, RECV))
            zlog_debug ("Questionable acknowledgement");
          ospf6_lsa_delete (his);
          continue;
        }

      if (IS_OSPF6_DEBUG_MESSAGE (oh->type, RECV))
        zlog_debug ("Acknowledged, remove from %s's retrans-list",
		    on->name);

      if (OSPF6_LSA_IS_MAXAGE (mine))
        ospf6_maxage_remove (on->ospf6_if->area->ospf6);

      ospf6_decrement_retrans_count (mine);
      ospf6_lsdb_remove (mine, on->retrans_list);
      ospf6_lsa_delete (his);
    }

  if (p != OSPF6_MESSAGE_END (oh))
    {
      if (IS_OSPF6_DEBUG_MESSAGE (oh->type, RECV))
        zlog_debug ("Trailing garbage ignored");
    }
}

u_char *recvbuf = NULL;
u_char *sendbuf = NULL;
unsigned int iobuflen = 0;

int
ospf6_iobuf_size (unsigned int size)
{
  char *recvnew, *sendnew;

  if (size <= iobuflen)
    return iobuflen;

  recvnew = (char *) XMALLOC (MTYPE_OSPF6_MESSAGE, size);
  sendnew = (char *) XMALLOC (MTYPE_OSPF6_MESSAGE, size);
  if (recvnew == NULL || sendnew == NULL)
    {
      if (recvnew)
        XFREE (MTYPE_OSPF6_MESSAGE, recvnew);
      if (sendnew)
        XFREE (MTYPE_OSPF6_MESSAGE, sendnew);
      zlog_debug ("Could not allocate I/O buffer of size %d.", size);
      return iobuflen;
    }

  if (recvbuf)
    XFREE (MTYPE_OSPF6_MESSAGE, recvbuf);
  if (sendbuf)
    XFREE (MTYPE_OSPF6_MESSAGE, sendbuf);
  recvbuf = (u_char *) recvnew;
  sendbuf = (u_char *) sendnew;
  iobuflen = size;

  return iobuflen;
}

int
ospf6_receive (struct thread *thread)
{
  int sockfd;
  unsigned int len;
  char srcname[64], dstname[64];
  struct in6_addr src, dst;
  unsigned int ifindex;
  struct iovec iovector[2];
  struct ospf6_interface *oi;
  struct ospf6_header *oh;

  /* add next read thread */
  sockfd = THREAD_FD (thread);
#ifndef SIM
  thread_add_read (master, ospf6_receive, NULL, sockfd);
#endif //SIM

  /* initialize */
  memset (recvbuf, 0, iobuflen);
  iovector[0].iov_base = recvbuf;
  iovector[0].iov_len = iobuflen;
  iovector[1].iov_base = NULL;
  iovector[1].iov_len = 0;

  /* receive message */
  len = ospf6_recvmsg (&src, &dst, &ifindex, iovector);
  if (len > iobuflen)
    {
      zlog_err ("Excess message read");
      return 0;
    }
  else if (len < sizeof (struct ospf6_header))
    {
      zlog_err ("Deficient message read");
      return 0;
    }

  oi = ospf6_interface_lookup_by_ifindex (ifindex);
  if (oi == NULL || oi->area == NULL)
    {
      zlog_debug ("Message received on disabled interface");
      return 0;
    }

  oh = (struct ospf6_header *) recvbuf;

  /* Log */
  if (IS_OSPF6_DEBUG_MESSAGE (oh->type, RECV))
    {
      inet_ntop (AF_INET6, &src, srcname, sizeof (srcname));
      inet_ntop (AF_INET6, &dst, dstname, sizeof (dstname));
      zlog_debug ("%s received on %s",
                 OSPF6_MESSAGE_TYPE_NAME (oh->type), oi->interface->name);
      zlog_debug ("    src: %s", srcname);
      zlog_debug ("    dst: %s", dstname);
      if (len != ntohs (oh->length))
        zlog_debug ("Message length does not match actually received: %d", len);

      switch (oh->type)
        {
          case OSPF6_MESSAGE_TYPE_HELLO:
#ifdef OSPF6_MANET
            if (oi->type == OSPF6_IFTYPE_MANETRELIABLE)
              ospf6_mhello_print(oh, len);
            else
              ospf6_hello_print (oh);
#else
            ospf6_hello_print (oh);
#endif //OSPF6_MANET
            break;
          case OSPF6_MESSAGE_TYPE_DBDESC:
            ospf6_dbdesc_print (oh);
            break;
          case OSPF6_MESSAGE_TYPE_LSREQ:
            ospf6_lsreq_print (oh);
            break;
          case OSPF6_MESSAGE_TYPE_LSUPDATE:
            ospf6_lsupdate_print (oh);
            break;
          case OSPF6_MESSAGE_TYPE_LSACK:
            ospf6_lsack_print (oh);
            break;
          default:
            zlog_debug ("Unknown message");
            break;
        }
    }

  if (CHECK_FLAG (oi->flag, OSPF6_INTERFACE_PASSIVE))
    {
      if (IS_OSPF6_DEBUG_MESSAGE (oh->type, RECV))
        zlog_debug ("Ignore message on passive interface %s",
                   oi->interface->name);
      return 0;
    }

  switch (oh->type)
    {
      case OSPF6_MESSAGE_TYPE_HELLO:
#ifdef OSPF6_MANET
        ospf6_hello_recv (&src, &dst, oi, oh, len);
#else
        ospf6_hello_recv (&src, &dst, oi, oh);
#endif //OSPF6_MANET
        break;

      case OSPF6_MESSAGE_TYPE_DBDESC:
#ifdef OSPF6_MANET
        ospf6_dbdesc_recv (&src, &dst, oi, oh, len);
#else
        ospf6_dbdesc_recv (&src, &dst, oi, oh);
#endif //OSPF6_MANET
        break;

      case OSPF6_MESSAGE_TYPE_LSREQ:
        ospf6_lsreq_recv (&src, &dst, oi, oh);
        break;

      case OSPF6_MESSAGE_TYPE_LSUPDATE:
        ospf6_lsupdate_recv (&src, &dst, oi, oh);
        break;

      case OSPF6_MESSAGE_TYPE_LSACK:
        ospf6_lsack_recv (&src, &dst, oi, oh);
        break;

      default:
        if (IS_OSPF6_DEBUG_MESSAGE (OSPF6_MESSAGE_TYPE_UNKNOWN, RECV))
          zlog_debug ("Unknown message");
        break;
    }

  return 0;
}

void
#ifdef OSPF6_MANET
// Send in length because TLV might be longer than OSPF header length
ospf6_send (struct in6_addr *src, struct in6_addr *dst,
            struct ospf6_interface *oi, struct ospf6_header *oh, int length)
#else
ospf6_send (struct in6_addr *src, struct in6_addr *dst,
            struct ospf6_interface *oi, struct ospf6_header *oh)
#endif //OSPF6_MANET
{
  int len;
  char srcname[64], dstname[64];
  struct iovec iovector[2];

  /* initialize */
  iovector[0].iov_base = (caddr_t) oh;
#ifdef OSPF6_MANET
  iovector[0].iov_len = length;
#else
  int length = ntohs(oh->length);
  iovector[0].iov_len = ntohs (oh->length);
#endif //OSPF6_MANET

  iovector[1].iov_base = NULL;
  iovector[1].iov_len = 0;

  /* fill OSPF header */
  oh->version = OSPFV3_VERSION;
  /* message type must be set before */
  /* message length must be set before */
  oh->router_id = oi->area->ospf6->router_id;
  oh->area_id = oi->area->area_id;
  /* checksum is calculated by kernel */
  oh->instance_id = oi->instance_id;
  oh->reserved = 0;

  /* Log */
  if (IS_OSPF6_DEBUG_MESSAGE (oh->type, SEND))
    {
      inet_ntop (AF_INET6, dst, dstname, sizeof (dstname));
      if (src)
        inet_ntop (AF_INET6, src, srcname, sizeof (srcname));
      else
        memset (srcname, 0, sizeof (srcname));
      zlog_debug ("%s send on %s",
                 OSPF6_MESSAGE_TYPE_NAME (oh->type), oi->interface->name);
      zlog_debug ("    src: %s", srcname);
      zlog_debug ("    dst: %s", dstname);

      switch (oh->type)
        {
          case OSPF6_MESSAGE_TYPE_HELLO:
#ifdef OSPF6_MANET
            if (oi->type == OSPF6_IFTYPE_MANETRELIABLE)
              ospf6_mhello_print(oh, length);
            else
              ospf6_hello_print (oh);
#else
            ospf6_hello_print (oh);
#endif //OSPF6_MANET
            break;
          case OSPF6_MESSAGE_TYPE_DBDESC:
            ospf6_dbdesc_print (oh);
            break;
          case OSPF6_MESSAGE_TYPE_LSREQ:
            ospf6_lsreq_print (oh);
            break;
          case OSPF6_MESSAGE_TYPE_LSUPDATE:
            ospf6_lsupdate_print (oh);
            break;
          case OSPF6_MESSAGE_TYPE_LSACK:
            ospf6_lsack_print (oh);
            break;
          default:
            zlog_debug ("Unknown message");
            assert (0);
            break;
        }
    }
#ifdef SIM_ETRACE_STAT
  switch (oh->type)
  {
    case OSPF6_MESSAGE_TYPE_HELLO:
      update_statistics(OSPF6_HELLO_SENT, 1);
      update_statistics(OSPF6_HELLO_BYTE_SENT, (double)length);
      break;
    case OSPF6_MESSAGE_TYPE_DBDESC:
      update_statistics(OSPF6_DBDESC_SENT, 1);
      update_statistics(OSPF6_DBDESC_BYTE_SENT, (double)length);
      break;
    case OSPF6_MESSAGE_TYPE_LSREQ:
      update_statistics(OSPF6_LSREQ_SENT, 1);
      update_statistics(OSPF6_LSREQ_BYTE_SENT, (double)length);
      break;
    case OSPF6_MESSAGE_TYPE_LSUPDATE:
      update_statistics(OSPF6_LSUPDATE_SENT, 1);
      update_statistics(OSPF6_LSUPDATE_BYTE_SENT, (double)length);
      if (IN6_IS_ADDR_MULTICAST(dst))
      {
        update_statistics(OSPF6_LSUPDATE_MULTI_SENT, 1);
        update_statistics(OSPF6_LSUPDATE_MULTI_BYTE_SENT, (double)length);
      }
      else
      {
        update_statistics(OSPF6_LSUPDATE_UNI_SENT, 1);
        update_statistics(OSPF6_LSUPDATE_UNI_BYTE_SENT, (double)length);
      }
      break;
    case OSPF6_MESSAGE_TYPE_LSACK:
      update_statistics(OSPF6_LSACK_SENT, 1);
      update_statistics(OSPF6_LSACK_BYTE_SENT, (double)length);
      break;
    default:
      zlog_info ("Unknown message");
      assert (0);
      break;
  }
#endif //SIM_ETRACE_STAT

  /* send message */
#ifdef USER_CHECKSUM
  /*
   * prior to sending packet, compute checksum.  Done in userspace
   * so we can detect extra TLVs on end of packet and not include
   * this area of the packet in checksum calc.
   */
  oh->checksum = 0;  /* initialize checksum */
  oh->checksum = ospf6_do_checksum(src,dst,oh);
#endif
  len = ospf6_sendmsg (src, dst, &oi->interface->ifindex, iovector);
#ifdef OSPF6_MANET
  if (len != length)
    zlog_err ("Could not send entire message length %d != %d", length, len);
#else
  if (len != ntohs (oh->length))
  zlog_err ("Could not send entire message length %d != %d", oh->length, len);
#endif //OSPF6_MANET
}

#ifdef OSPF6_MANET_MDR_FLOOD
// Ogierv3 10.1
int ospf6_mdr_mhello_send(struct ospf6_interface *oi)
{
  int length=0;
  u_int lls_length=0;
  struct ospf6_header *oh;
  struct ospf6_hello *hello;
  u_char *pos, *lls;
  u_char hnl[iobuflen], rnl[iobuflen], lnl[iobuflen];
  u_int num_hnl=0, num_rnl=0, num_lnl=0;
  u_char dnl[iobuflen];
  u_int num_dnl=0;
  boolean diff = false;

#ifdef SIM_ETRACE_STAT
  ospf6_print_neighborhood_sim(oi);
#endif //SIM_ETRACE_STAT

  // Calculate cds and update adj before hello is sent.
  ospf6_calculate_mdr(oi);
  ospf6_mdr_update_adjacencies(oi); 

  memset (sendbuf, 0, iobuflen);
  oh = (struct ospf6_header *) sendbuf;
  oh->type = OSPF6_MESSAGE_TYPE_HELLO;

  hello = (struct ospf6_hello *)((caddr_t) oh + sizeof (struct ospf6_header));
  hello->interface_id = htonl (oi->interface->ifindex);
  hello->priority = oi->priority;
  hello->options[0] = oi->area->options[0];
  hello->options[1] = oi->area->options[1];
  hello->options[2] = oi->area->options[2];
  hello->hello_interval = htons (oi->hello_interval);
  hello->dead_interval = htons (oi->dead_interval);
  hello->drouter = 0;
  hello->bdrouter = 0;

  if (oi->mdr_level == OSPF6_MDR)
  {
    hello->drouter = oi->area->ospf6->router_id;
    if (oi->parent)
      hello->bdrouter = oi->parent->router_id;
  }
  else if (oi->mdr_level == OSPF6_BMDR)
  {
    hello->bdrouter = oi->area->ospf6->router_id;
    if (oi->parent)
      hello->drouter = oi->parent->router_id;
  }
  else 
  {
    if (oi->parent)
      hello->drouter = oi->parent->router_id;
    if (oi->bparent)
      hello->bdrouter = oi->bparent->router_id;
  }

  pos = (u_char *)((caddr_t) hello + sizeof (struct ospf6_hello));
  oh->length = htons (pos - sendbuf);

#ifdef OSPF6_MANET_DIFF_HELLO
  //Is this a Diff Hello
  if (oi->diff_hellos && oi->full_hello_count > 1)
  {
    oi->full_hello_count--;
    diff = true;
    OSPF6_OPT_SET(hello->options, OSPF6_OPT_D, 1);
  }
  else
    oi->full_hello_count = oi->TwoHopRefresh;
#endif //OSPF6_MANET_DIFF_HELLO
    
  // dnl added for Ogierv7
  lls_length = ospf6_mdr_create_neighbor_lists(oi, pos, sendbuf+iobuflen,
                  &num_hnl, hnl, &num_rnl, rnl, &num_lnl, lnl,
                  &num_dnl, dnl, diff);

  if (lls_length == 0)
  { //No TLVs to append - send empty hello
    ospf6_send (oi->linklocal_addr, &allspfrouters6, oi, oh, ntohs(oh->length));
    oi->thread_send_hello = thread_add_timer (master, ospf6_hello_send,
                                             oi, oi->hello_interval);
    return 0;
  }
  //LLS will be sent
  OSPF6_OPT_SET(hello->options, OSPF6_OPT_L, 1);

  /* leave room for LLS header */
  lls = pos;
  pos += sizeof(struct ospf6_LLS_header);
  
#ifdef OSPF6_MANET_DIFF_HELLO
  //Seq TLV
  if (oi->diff_hellos)  //append seq tlv when diff hellos enabled
    pos += ospf6_append_mdr_seq_tlv(oi, pos);

  //LNL TLV
  pos += ospf6_append_mdr_neigh_tlv(pos, num_lnl, lnl, OSPF6_TLV_TYPE_LNL);
#endif //OSPF6_MANET_DIFF_HELLO

  //HNL TLV
  pos += ospf6_append_mdr_neigh_tlv(pos, num_hnl, hnl, OSPF6_TLV_TYPE_HNL);

  //RNL TLV
  pos += ospf6_append_mdr_neigh_tlv(pos, num_rnl, rnl, OSPF6_TLV_TYPE_RNL);

  // DNL added for Ogierv7
  //DNL TLV
  pos += ospf6_append_mdr_neigh_tlv(pos, num_dnl, dnl, OSPF6_TLV_TYPE_DNL);

  //LLS header must be added here, so the checksum is computed correctly
  ospf6_append_lls_header(oi, lls, lls_length);

  //Send hello
  length = pos - sendbuf;
  ospf6_send (oi->linklocal_addr, &allspfrouters6, oi, oh, length);
  oi->thread_send_hello = thread_add_timer (master, ospf6_hello_send,
                                             oi, oi->hello_interval);
  return 0;
}
#endif //OSPF6_MANET_MDR_FLOOD

#ifdef OSPF6_MANET_MPR_FLOOD
//Chandra03 3.3.7
int ospf6_mpr_mhello_send(struct ospf6_interface *oi)
{
  int length;
  int relay_length = 0;
  struct ospf6_header *oh;
  struct ospf6_hello *hello;
  u_char *pos, *lls;

  memset (sendbuf, 0, iobuflen);
  oh = (struct ospf6_header *) sendbuf;
  oh->type = OSPF6_MESSAGE_TYPE_HELLO;

  hello = (struct ospf6_hello *)((caddr_t) oh + sizeof (struct ospf6_header));
  hello->interface_id = htonl (oi->interface->ifindex);
  hello->priority = oi->priority;
  hello->options[0] = oi->area->options[0];
  hello->options[1] = oi->area->options[1];
  hello->options[2] = oi->area->options[2];
  hello->hello_interval = htons (oi->hello_interval);
  hello->dead_interval = htons (oi->dead_interval);
  hello->drouter = oi->drouter;
  hello->bdrouter = oi->bdrouter;

  OSPF6_OPT_SET(hello->options, OSPF6_OPT_F, 1); //supports MPR flooding

  ospf6_calculate_relays(oi);

  pos = (u_char *)((caddr_t) hello + sizeof (struct ospf6_hello));
  /* new neighbors or all neighbors if A option set*/
  pos += ospf6_create_neighbor_list(oi, sendbuf, pos, true);//full state
  oh->length = htons (pos - sendbuf);

  lls = pos;
  /* leave room for LLS header */
  pos += sizeof(struct ospf6_LLS_header);

  /* Relay TLV */
  relay_length = ospf6_append_relays(oi,
             pos,
             sendbuf + iobuflen,
             true,
             true);

  if (relay_length > 0)  //relay(s) to add
  {
    OSPF6_OPT_SET(hello->options, OSPF6_OPT_L,1);  //Relay TLV will be appended
    pos += relay_length;
    /* place LLS header at the front position of the buffer*/
    length = pos - sendbuf;
    ospf6_append_lls_header(oi, lls, (u_int)(pos-lls));
  }
  else
    length = lls - sendbuf; //no relay(s) to add

  ospf6_send (oi->linklocal_addr, &allspfrouters6, oi, oh, length);

  oi->thread_send_hello = thread_add_timer (master, ospf6_hello_send,
                                             oi, oi->hello_interval);
  return 0;
}

#ifdef OSPF6_MANET_DIFF_HELLO
//Chandra03 3.3.7
int ospf6_mpr_diff_mhello_send(struct ospf6_interface *oi,
                  struct in6_addr dst,
                  char *scs_tlv_option)
{
  int length;
  struct ospf6_header *oh;
  struct ospf6_hello *hello;
  u_char *pos, *lls;
  boolean set_N = false;

  memset (sendbuf, 0, iobuflen);
  oh = (struct ospf6_header *) sendbuf;
  oh->type = OSPF6_MESSAGE_TYPE_HELLO;

  hello = (struct ospf6_hello *)((caddr_t) oh + sizeof (struct ospf6_header));
  hello->interface_id = htonl (oi->interface->ifindex);
  hello->priority = oi->priority;
  hello->options[0] = oi->area->options[0];
  hello->options[1] = oi->area->options[1];
  hello->options[2] = oi->area->options[2];
  hello->hello_interval = htons (oi->hello_interval);
  hello->dead_interval = htons (oi->dead_interval);
  hello->drouter = oi->drouter;
  hello->bdrouter = oi->bdrouter;

  OSPF6_OPT_SET(hello->options, OSPF6_OPT_F, 1); //supports MPR flooding
  OSPF6_OPT_SET(hello->options, OSPF6_OPT_L, 1); //TLV will be appended
  //Chandra03 3.3.6.1 paragraph 1
  OSPF6_OPT_SET(hello->options, OSPF6_OPT_I, 1); //partial hello information

  ospf6_calculate_relays(oi);

  pos = (u_char *)((caddr_t) hello + sizeof (struct ospf6_hello));
  /* new neighbors or all neighbors if FS option set*/
  pos += ospf6_create_neighbor_list(oi, sendbuf, pos,
              OSPF6_TLV_SCS_OPT_ISSET(scs_tlv_option, OSPF6_TLV_SCS_OPT_FS, 0));
  oh->length = htons (pos - sendbuf);

 lls = pos;
 /* leave room for LLS header */
 pos += sizeof(struct ospf6_LLS_header);

  /* SCS TLV */
  if(oi->increment_scs)
    oi->scs_num = ospf6_increment_scs(oi->scs_num);
  /* append scs below because tlv_option may change -- advance position */
  pos += sizeof(struct ospf6_TLV_header) + sizeof(struct ospf6_scs_TLV);

  /* Drop TLV */
  pos += ospf6_append_drop_neighbors(oi, pos, sendbuf+iobuflen, &set_N);
  if(!oi->increment_scs && set_N)
    OSPF6_TLV_SCS_OPT_SET(scs_tlv_option, OSPF6_TLV_SCS_OPT_N, 0);

  /* Relay TLV */
  pos += ospf6_append_relays(oi,
             pos,
             sendbuf + iobuflen,
             IN6_IS_ADDR_MULTICAST(&dst),
             OSPF6_TLV_SCS_OPT_ISSET(scs_tlv_option, OSPF6_TLV_SCS_OPT_FS, 0));

  // Request TLV
  // Chandra03 3.3.7 paragraph 1 
  if (oi->initialization == true)
  {
    // router interface is initializing
    // request full neighbor state from all neighbors
    struct listnode *n;
    struct ospf6_neighbor *on;
    oi->initialization = false;
    OSPF6_TLV_SCS_OPT_SET(scs_tlv_option, OSPF6_TLV_SCS_OPT_R, 0);
    for (n = listhead(oi->neighbor_list); n; nextnode(n))
    { //clear all neighbor request
      on = (struct ospf6_neighbor *) getdata(n);
      on->request = false;
    }
  }
  else 
    pos += ospf6_append_request(oi, pos, sendbuf+iobuflen, scs_tlv_option);

  /* append SCS TLV */
  ospf6_append_scs(oi, scs_tlv_option, lls+sizeof(struct ospf6_LLS_header));

  /* place LLS header at the front position of the buffer*/
  length = pos - sendbuf;
  ospf6_append_lls_header(oi, lls, (u_int)(pos-lls));

  ospf6_send (oi->linklocal_addr, &dst, oi, oh, length);

  if (IN6_IS_ADDR_MULTICAST(&dst))
  { /* this is a periodic hello - set next timer thread */
    oi->thread_send_hello = thread_add_timer (master, ospf6_hello_send,
                                             oi, oi->hello_interval);
  }
  oi->increment_scs = false;
  return 0;
}
#endif //OSPF6_MANET_DIFF_HELLO
#endif //OSPF6_MANET_MPR_FLOOD

int
ospf6_hello_send (struct thread *thread)
{
  struct ospf6_interface *oi;
  struct ospf6_header *oh;
  struct ospf6_hello *hello;
  u_char *p;
  struct listnode *node;
  struct ospf6_neighbor *on;

  oi = (struct ospf6_interface *) THREAD_ARG (thread);
  oi->thread_send_hello = (struct thread *) NULL;

  if (oi->state <= OSPF6_INTERFACE_DOWN)
    {
      if (IS_OSPF6_DEBUG_MESSAGE (OSPF6_MESSAGE_TYPE_HELLO, SEND))
        zlog_debug ("Unable to send Hello on down interface %s",
                   oi->interface->name);
      return 0;
    }

#ifdef OSPF6_CONFIG
  if (oi->type == OSPF6_IFTYPE_LOOPBACK)
    return 0;

  if(oi->type == OSPF6_IFTYPE_MANETRELIABLE &&
     oi->flooding == OSPF6_FLOOD_MPR_SDCDS)
  {
#ifdef OSPF6_MANET_MPR_FLOOD
    if (!oi->diff_hellos)
    {
      return ospf6_mpr_mhello_send(oi);
    }
#ifdef OSPF6_MANET_DIFF_HELLO
    //Chandra03 3.3.10 paragraph 2 bullet 1
    else if (elapsed_time(&ospf6->starttime) > oi->dead_interval)
    { //graceful restart 
      struct in6_addr dst;
      char scs_tlv_option[2] = {0, 0};

      //graceful restart
      //Chandra03 3.3.10 paragraph 2 bullet 3
      if(elapsed_time(&ospf6->starttime)-oi->dead_interval<oi->hello_interval)
        oi->full_state = true;

      if (oi->full_state == true)
      {
        OSPF6_TLV_SCS_OPT_SET(scs_tlv_option, OSPF6_TLV_SCS_OPT_FS, 0);
        oi->full_state = false;
      }

      /* initialize destination - may change within send */
      inet_pton (AF_INET6, ALLSPFROUTERS6, &dst);
      return ospf6_mpr_diff_mhello_send(oi, dst, scs_tlv_option);
    }
#endif //OSPF6_MANET_DIFF_HELLO
#endif //OSPF6_MANET_MPR_FLOOD
  }
  else if(oi->type == OSPF6_IFTYPE_MANETRELIABLE &&
          oi->flooding == OSPF6_FLOOD_MDR_SICDS)
  {
#ifdef OSPF6_MANET_MDR_FLOOD
    return ospf6_mdr_mhello_send(oi);
#endif //OSPF6_MANET_MDR_FLOOD
  }
#endif //OSPF6_CONFIG

  /* set next thread */
  oi->thread_send_hello = thread_add_timer (master, ospf6_hello_send,
                                            oi, oi->hello_interval);

  memset (sendbuf, 0, iobuflen);
  oh = (struct ospf6_header *) sendbuf;
  hello = (struct ospf6_hello *)((caddr_t) oh + sizeof (struct ospf6_header));

  hello->interface_id = htonl (oi->interface->ifindex);
  hello->priority = oi->priority;
  hello->options[0] = oi->area->options[0];
  hello->options[1] = oi->area->options[1];
  hello->options[2] = oi->area->options[2];
  hello->hello_interval = htons (oi->hello_interval);
  hello->dead_interval = htons (oi->dead_interval);
  hello->drouter = oi->drouter;
  hello->bdrouter = oi->bdrouter;

  p = (u_char *)((caddr_t) hello + sizeof (struct ospf6_hello));

  for (node = listhead (oi->neighbor_list); node; nextnode (node))
    {
      on = (struct ospf6_neighbor *) getdata (node);

      if (on->state < OSPF6_NEIGHBOR_INIT)
        continue;

      if (p - sendbuf + sizeof (u_int32_t) > oi->ifmtu)
        {
          if (IS_OSPF6_DEBUG_MESSAGE (OSPF6_MESSAGE_TYPE_HELLO, SEND))
            zlog_debug ("sending Hello message: exceeds I/F MTU");
          break;
        }

      memcpy (p, &on->router_id, sizeof (u_int32_t));
      p += sizeof (u_int32_t);
    }

  oh->type = OSPF6_MESSAGE_TYPE_HELLO;
  oh->length = htons (p - sendbuf);

#ifdef OSPF6_MANET
  ospf6_send (oi->linklocal_addr, &allspfrouters6, oi, oh, ntohs(oh->length));
#else
  ospf6_send (oi->linklocal_addr, &allspfrouters6, oi, oh);
#endif //OSPF6_MANET
  return 0;
}

int
ospf6_dbdesc_send (struct thread *thread)
{
  struct ospf6_neighbor *on;
  struct ospf6_header *oh;
  struct ospf6_dbdesc *dbdesc;
  u_char *p;
  struct ospf6_lsa *lsa;
#ifdef OSPF6_MANET
  int length = 0;
#ifdef OSPF6_MANET_MDR_FLOOD
  u_char *lls = NULL;
#endif //OSPF6_MANET_MDR_FLOOD
#endif //OSPF6_MANET

  on = (struct ospf6_neighbor *) THREAD_ARG (thread);
  on->thread_send_dbdesc = (struct thread *) NULL;

  if (on->state < OSPF6_NEIGHBOR_EXSTART)
    {
      if (IS_OSPF6_DEBUG_MESSAGE (OSPF6_MESSAGE_TYPE_DBDESC, SEND))
        zlog_debug ("Quit to send DbDesc to neighbor %s state %s",
		    on->name, ospf6_neighbor_state_str[on->state]);
      return 0;
    }

  /* set next thread if master */
  if (CHECK_FLAG (on->dbdesc_bits, OSPF6_DBDESC_MSBIT))
    on->thread_send_dbdesc =
      thread_add_timer (master, ospf6_dbdesc_send, on,
                        on->ospf6_if->rxmt_interval);

  memset (sendbuf, 0, iobuflen);
  oh = (struct ospf6_header *) sendbuf;
  dbdesc = (struct ospf6_dbdesc *)((caddr_t) oh +
                                   sizeof (struct ospf6_header));

  /* if this is initial one, initialize sequence number for DbDesc */
  if (CHECK_FLAG (on->dbdesc_bits, OSPF6_DBDESC_IBIT))
    {
      struct timeval tv;
#ifdef SIM
      if (gettimeofday_sim (&tv, (struct timezone *) NULL) < 0)
#else
      if (gettimeofday (&tv, (struct timezone *) NULL) < 0)
#endif //SIM
        tv.tv_sec = 1;
      on->dbdesc_seqnum = tv.tv_sec;
    }

  dbdesc->options[0] = on->ospf6_if->area->options[0];
  dbdesc->options[1] = on->ospf6_if->area->options[1];
  dbdesc->options[2] = on->ospf6_if->area->options[2];
  dbdesc->ifmtu = htons (on->ospf6_if->ifmtu);
  dbdesc->bits = on->dbdesc_bits;
  dbdesc->seqnum = htonl (on->dbdesc_seqnum);

  /* if this is not initial one, set LSA headers in dbdesc */
  p = (u_char *)((caddr_t) dbdesc + sizeof (struct ospf6_dbdesc));
  if (! CHECK_FLAG (on->dbdesc_bits, OSPF6_DBDESC_IBIT))
    {
      for (lsa = ospf6_lsdb_head (on->dbdesc_list); lsa;
           lsa = ospf6_lsdb_next (lsa))
        {
          ospf6_lsa_age_update_to_send (lsa, on->ospf6_if->transdelay);

          /* MTU check */
          if (p - sendbuf + sizeof (struct ospf6_lsa_header) >
              on->ospf6_if->ifmtu)
            {
              ospf6_lsa_unlock (lsa);
              break;
            }
          memcpy (p, lsa->header, sizeof (struct ospf6_lsa_header));
          p += sizeof (struct ospf6_lsa_header);
        }
    }
#ifdef OSPF6_MANET
#ifdef OSPF6_MANET_MDR_FLOOD
  else if (on->ospf6_if->type == OSPF6_IFTYPE_MANETRELIABLE &&
           on->ospf6_if->flooding == OSPF6_FLOOD_MDR_SICDS &&
           on->ospf6_if->AdjConnectivity > OSPF6_ADJ_FULLYCONNECTED)
  {
    u_int size = sizeof(struct ospf6_LLS_header) + 
                 sizeof(struct ospf6_TLV_header) + 
                 sizeof(struct ospf6_mdr_TLV);
 
    if (p + size >= sendbuf + iobuflen)
      zlog_warn ("Send DD Packet: Buffer shortage on %s",
        on->ospf6_if->interface->name);
    else
    {
      lls = p;

      OSPF6_OPT_SET(dbdesc->options, OSPF6_OPT_L, 1);
      lls += ospf6_append_lls_header(on->ospf6_if, lls, size);

      /* Router TLV */
      //mdr, mbdr, parent, bparent already up to date ??? XXX
      lls += ospf6_append_mdr_tlv(on->ospf6_if, lls);
      length = lls - sendbuf;
    }
  }
  if (lls == NULL)
    length = p - sendbuf;
#else
  length = p - sendbuf;
#endif //OSPF6_MANET_MDR_FLOOD
#endif //OSPF6_MANET

  oh->length = htons (p - sendbuf);
  oh->type = OSPF6_MESSAGE_TYPE_DBDESC;

#ifdef OSPF6_MANET
  ospf6_send (on->ospf6_if->linklocal_addr, &on->linklocal_addr,
              on->ospf6_if, oh, length);
#else
  ospf6_send (on->ospf6_if->linklocal_addr, &on->linklocal_addr,
              on->ospf6_if, oh);
#endif //OSPF6_MANET
  return 0;
}

int
ospf6_dbdesc_send_newone (struct thread *thread)
{
  struct ospf6_neighbor *on;
  struct ospf6_lsa *lsa;
  unsigned int size = 0;

  on = (struct ospf6_neighbor *) THREAD_ARG (thread);
  ospf6_lsdb_remove_all (on->dbdesc_list);

  /* move LSAs from summary_list to dbdesc_list (within neighbor structure)
     so that ospf6_send_dbdesc () can send those LSAs */
  size = sizeof (struct ospf6_lsa_header) + sizeof (struct ospf6_dbdesc);
  for (lsa = ospf6_lsdb_head (on->summary_list); lsa;
       lsa = ospf6_lsdb_next (lsa))
    {
      if (size + sizeof (struct ospf6_lsa_header) > on->ospf6_if->ifmtu)
        {
          ospf6_lsa_unlock (lsa);
          break;
        }

      ospf6_lsdb_add (ospf6_lsa_copy (lsa), on->dbdesc_list);
      ospf6_lsdb_remove (lsa, on->summary_list);
      //printf("%d %d lsa removed from summary list, count %d \n",
              //ospf6->router_id, on->router_id, on->summary_list->count);
      size += sizeof (struct ospf6_lsa_header);
    }

  if (on->summary_list->count == 0)
    UNSET_FLAG (on->dbdesc_bits, OSPF6_DBDESC_MBIT);

  /* If slave, More bit check must be done here */
  if (! CHECK_FLAG (on->dbdesc_bits, OSPF6_DBDESC_MSBIT) && /* Slave */
      ! CHECK_FLAG (on->dbdesc_last.bits, OSPF6_DBDESC_MBIT) &&
      ! CHECK_FLAG (on->dbdesc_bits, OSPF6_DBDESC_MBIT))
    thread_add_event (master, exchange_done, on, 0);

  thread_execute (master, ospf6_dbdesc_send, on, 0);
  return 0;
}

int
ospf6_lsreq_send (struct thread *thread)
{
  struct ospf6_neighbor *on;
  struct ospf6_header *oh;
  struct ospf6_lsreq_entry *e;
  u_char *p;
  struct ospf6_lsa *lsa;

  on = (struct ospf6_neighbor *) THREAD_ARG (thread);
  on->thread_send_lsreq = (struct thread *) NULL;

  /* LSReq will be sent only in ExStart or Loading */
  if (on->state != OSPF6_NEIGHBOR_EXCHANGE &&
      on->state != OSPF6_NEIGHBOR_LOADING)
    {
      if (IS_OSPF6_DEBUG_MESSAGE (OSPF6_MESSAGE_TYPE_LSREQ, SEND))
        zlog_debug ("Quit to send LSReq to neighbor %s state %s",
		    on->name, ospf6_neighbor_state_str[on->state]);
      return 0;
    }

  /* schedule loading_done if request list is empty */
  if (on->request_list->count == 0)
    {
      thread_add_event (master, loading_done, on, 0);
      return 0;
    }

  /* set next thread */
  on->thread_send_lsreq =
    thread_add_timer (master, ospf6_lsreq_send, on,
                      on->ospf6_if->rxmt_interval);

  memset (sendbuf, 0, iobuflen);
  oh = (struct ospf6_header *) sendbuf;

  /* set Request entries in lsreq */
  p = (u_char *)((caddr_t) oh + sizeof (struct ospf6_header));
  for (lsa = ospf6_lsdb_head (on->request_list); lsa;
       lsa = ospf6_lsdb_next (lsa))
    {
      /* MTU check */
      if (p - sendbuf + sizeof (struct ospf6_lsreq_entry) > on->ospf6_if->ifmtu)
        {
          ospf6_lsa_unlock (lsa);
          break;
        }

      e = (struct ospf6_lsreq_entry *) p;
      e->type = lsa->header->type;
      e->id = lsa->header->id;
      e->adv_router = lsa->header->adv_router;
      p += sizeof (struct ospf6_lsreq_entry);
    }

  oh->type = OSPF6_MESSAGE_TYPE_LSREQ;
  oh->length = htons (p - sendbuf);

#ifdef OSPF6_MANET
  ospf6_send (on->ospf6_if->linklocal_addr, &on->linklocal_addr,
              on->ospf6_if, oh, ntohs(oh->length));
#else
  ospf6_send (on->ospf6_if->linklocal_addr, &on->linklocal_addr,
              on->ospf6_if, oh);
#endif //OSPF6_MANET
  return 0;
}
#ifdef OSPF6_DELAYED_FLOOD
int
ospf6_lsupdate_send_neighbor (struct thread *thread)
{
  struct ospf6_neighbor *on;
  struct ospf6_header *oh;
  struct ospf6_lsupdate *lsupdate;
  u_char *p;
  int num;
  struct ospf6_lsa *lsa;

  double rxmt_time;
  double lsa_rxmt_time;
  boolean rxmt_now = false;
  int rxmt = 0;
#ifdef SIM_ETRACE_STAT
  int rxmt_size = 0;
  int dbexch_size = 0;
  int stale_size = 0;
  int dbexch = 0;
  int stale = 0;
#endif //SIM_ETRACE_STAT

  on = (struct ospf6_neighbor *) THREAD_ARG (thread);
  on->thread_send_lsupdate = (struct thread *) NULL;

  if (IS_OSPF6_DEBUG_MESSAGE (OSPF6_MESSAGE_TYPE_LSUPDATE, SEND))
    zlog_debug ("LSUpdate to neighbor %s", on->name);

  if (on->state < OSPF6_NEIGHBOR_EXCHANGE)
    {
      if (IS_OSPF6_DEBUG_MESSAGE (OSPF6_MESSAGE_TYPE_LSUPDATE, SEND))
        zlog_debug ("Quit to send (neighbor state %s)",
      ospf6_neighbor_state_str[on->state]);
      return 0;
    }

  /* if we have nothing to send, return */
  if (on->lsupdate_list->count == 0 &&
      on->retrans_list->count == 0)
  {
    if (IS_OSPF6_DEBUG_MESSAGE (OSPF6_MESSAGE_TYPE_LSUPDATE, SEND))
      zlog_debug ("Quit to send (nothing to send)");
    return 0;
  }

  memset (sendbuf, 0, iobuflen);
  oh = (struct ospf6_header *) sendbuf;
  lsupdate = (struct ospf6_lsupdate *) 
             ((caddr_t) oh + sizeof (struct ospf6_header));

  p = (u_char *)((caddr_t) lsupdate + sizeof (struct ospf6_lsupdate));
  num = 0;

  /* lsupdate_list: lists LSAs which doen't need to be
     retransmitted. remove those from the list */
  for (lsa = ospf6_lsdb_head (on->lsupdate_list); lsa;
       lsa = ospf6_lsdb_next (lsa))
  {
    /* MTU check */
    if ( (p - sendbuf + (unsigned int)OSPF6_LSA_SIZE (lsa->header))
          > on->ospf6_if->ifmtu)
    {
      ospf6_lsa_unlock (lsa);
      break;
    }

    ospf6_lsa_age_update_to_send (lsa, on->ospf6_if->transdelay);
    memcpy (p, lsa->header, OSPF6_LSA_SIZE (lsa->header));
    p += OSPF6_LSA_SIZE (lsa->header);
    num++;
#ifdef SIM_ETRACE_STAT
    if (lsa->unicast_stale)
    {
      stale_size += OSPF6_LSA_SIZE (lsa->header);
      stale++;
    }
    else
    {
      dbexch_size += OSPF6_LSA_SIZE (lsa->header);
      dbexch++;
    }
#endif //SIM_ETRACE_STAT
    assert (lsa->lock == 2);
    ospf6_lsdb_remove (lsa, on->lsupdate_list);
  }

  //Determine if there is at least one LSA with expired rxmt time
  rxmt_time = (double) on->ospf6_if->rxmt_interval;
  for (lsa = ospf6_lsdb_head (on->retrans_list); lsa;
       lsa = ospf6_lsdb_next (lsa))
  {
    lsa_rxmt_time = on->ospf6_if->rxmt_interval-elapsed_time(&lsa->rxmt_time);
    if (lsa_rxmt_time < .001)//thread_add_timer only works on 1 msec increment
    {
      rxmt_now = true;
      break;
    }
  }

  if(rxmt_now)
  {
    int i;
    boolean same;
    char *u;
    for (lsa = ospf6_lsdb_head (on->retrans_list); lsa;
         lsa = ospf6_lsdb_next (lsa))
    {
      lsa_rxmt_time = on->ospf6_if->rxmt_interval-elapsed_time(&lsa->rxmt_time);
      if (lsa_rxmt_time > ((double) on->ospf6_if->flood_delay)/1000)
      { //flood lsa that have expired or will expire within flood_delay msec
        //this lsa should not be retransmitted yet
        if (lsa_rxmt_time < rxmt_time)
          rxmt_time = lsa_rxmt_time;
        continue;
      }
      set_time(&lsa->rxmt_time);  //set the time lsa is retransmitted

/*
#ifdef OSPF6_MANET_MDR_FLOOD
      if (on->ospf6_if->flooding == OSPF6_FLOOD_MDR_SICDS &&
          on->ospf6_if->type == OSPF6_IFTYPE_MANETRELIABLE &&
          on->ospf6_if->mdr_level == OSPF6_OTHER)
      {
        //TODO when should this be removed from the list
        //TODO will skipping this LSA mess anything up????
        continue;
      }
#endif //OSPF6_MANET_MDR_FLOOD 
*/

#if 1 //SAME XXX BOEING Check if LSA already added from update_list:  KEEP ???
      same = false;
      u = (char *)((caddr_t) lsupdate + sizeof (struct ospf6_lsupdate));
      for (i=0; i<num-rxmt; i++)
      {
        if (lsa->header->type == ((struct ospf6_lsa_header *) u)->type &&
            lsa->header->id == ((struct ospf6_lsa_header *) u)->id &&
            lsa->header->adv_router == 
                               ((struct ospf6_lsa_header *) u)->adv_router &&
            lsa->header->seqnum == ((struct ospf6_lsa_header *) u)->seqnum &&
            lsa->header->length == ((struct ospf6_lsa_header *) u)->length)
        {
          same = true;
          break;
        }
        u += OSPF6_LSA_SIZE (u);
      }
      if (same)
        continue;
#endif //SAME

      /* MTU check */
      if ( (p - sendbuf + (unsigned int)OSPF6_LSA_SIZE (lsa->header))
           > on->ospf6_if->ifmtu)
      {
        ospf6_lsa_unlock (lsa);
        break;
      }

      ospf6_lsa_age_update_to_send (lsa, on->ospf6_if->transdelay);
      memcpy (p, lsa->header, OSPF6_LSA_SIZE (lsa->header));
      p += OSPF6_LSA_SIZE (lsa->header);
      num++;
      rxmt++;
#ifdef SIM_ETRACE_STAT
      rxmt_size += OSPF6_LSA_SIZE (lsa->header);
#endif //SIM_ETRACE_STAT
    }
  }

  lsupdate->lsa_number = htonl (num);

  oh->type = OSPF6_MESSAGE_TYPE_LSUPDATE;
  oh->length = htons (p - sendbuf);

  if (num != 0) {
#ifdef OSPF6_MANET
    ospf6_send (on->ospf6_if->linklocal_addr, &on->linklocal_addr,
                on->ospf6_if, oh, ntohs(oh->length));
#else
    ospf6_send (on->ospf6_if->linklocal_addr, &on->linklocal_addr,
                on->ospf6_if, oh);
#endif //OSPF6_MANET

#ifdef SIM_ETRACE_STAT
    TraceEvent_sim(1,"unicast_LSU %d bytes %d rxmt %d bytes, %d dbexch %d bytes, %d stale %d bytes to %s",
                   p-sendbuf, rxmt, rxmt_size, dbexch, dbexch_size, stale, 
                   stale_size, ip2str(on->router_id));
    int ospf6head = 20;  // add the ospf header length
    if (rxmt > 0 && dbexch > 0 ||
        rxmt > 0 && stale > 0 ||
        dbexch > 0 && stale > 0) 
    {
      update_statistics(OSPF6_LSUPDATE_UNI_COL_SENT, 1);
      update_statistics(OSPF6_LSUPDATE_UNI_COL_BYTE_SENT,  
                        (double) (rxmt_size+dbexch_size+stale_size+ospf6head));
    }
    else if (rxmt > 0) 
    {
      update_statistics(OSPF6_LSUPDATE_UNI_RXMT_SENT, 1);
      update_statistics(OSPF6_LSUPDATE_UNI_RXMT_BYTE_SENT, 
                        (double)(rxmt_size+ospf6head));
    }
    else if (stale > 0) 
    {
      update_statistics(OSPF6_LSUPDATE_UNI_STALE_SENT, 1);
      update_statistics(OSPF6_LSUPDATE_UNI_STALE_BYTE_SENT, 
                        (double)(stale_size+ospf6head));
    }
    else 
    {
      update_statistics(OSPF6_LSUPDATE_UNI_DBEX_SENT, 1);
      update_statistics(OSPF6_LSUPDATE_UNI_DBEX_BYTE_SENT,
                        (double)(dbexch_size+ospf6head));
    }
#endif //SIM_ETRACE_STAT
  }

  if (on->lsupdate_list->count != 0 || on->retrans_list->count != 0)
  {
    if (on->lsupdate_list->count != 0)
    {
      on->thread_send_lsupdate =
        ospf6_send_lsupdate_delayed_msec(master, ospf6_lsupdate_send_neighbor,
                                         on, on->ospf6_if->flood_delay, 
                                         on->thread_send_lsupdate);
    }
    else
    {
      on->thread_send_lsupdate =
        ospf6_send_lsupdate_delayed_msec(master, ospf6_lsupdate_send_neighbor,
                                         on, (long) (rxmt_time*1000), 
                                         on->thread_send_lsupdate);
    }
  }
  return 0;
}

struct thread *ospf6_send_lsupdate_delayed_msec(struct thread_master *m,
        int (*func) (struct thread *), void *arg, long timer_msec,
     struct thread *t)
{
  double time_remaining;
  if (!t)
  {
    t = thread_add_timer_msec (m, func, arg, timer_msec);
    return t;
  }

  time_remaining = elapsed_time(&t->u.sands) * (-1);
  if (time_remaining > ((double)timer_msec)/1000)
  {
    THREAD_OFF (t);
    t = thread_add_timer_msec (m, func, arg, timer_msec);
  }
  return t;
}

#else //OSPF6_DELAYED_FLOOD
int
ospf6_lsupdate_send_neighbor (struct thread *thread)
{
  struct ospf6_neighbor *on;
  struct ospf6_header *oh;
  struct ospf6_lsupdate *lsupdate;
  u_char *p;
  int num;
  struct ospf6_lsa *lsa;

  on = (struct ospf6_neighbor *) THREAD_ARG (thread);
  on->thread_send_lsupdate = (struct thread *) NULL;

  if (IS_OSPF6_DEBUG_MESSAGE (OSPF6_MESSAGE_TYPE_LSUPDATE, SEND))
    zlog_debug ("LSUpdate to neighbor %s", on->name);

  if (on->state < OSPF6_NEIGHBOR_EXCHANGE)
    {
      if (IS_OSPF6_DEBUG_MESSAGE (OSPF6_MESSAGE_TYPE_LSUPDATE, SEND))
        zlog_debug ("Quit to send (neighbor state %s)",
		    ospf6_neighbor_state_str[on->state]);
      return 0;
    }

  /* if we have nothing to send, return */
  if (on->lsupdate_list->count == 0 &&
      on->retrans_list->count == 0)
    {
      if (IS_OSPF6_DEBUG_MESSAGE (OSPF6_MESSAGE_TYPE_LSUPDATE, SEND))
        zlog_debug ("Quit to send (nothing to send)");
      return 0;
    }

  memset (sendbuf, 0, iobuflen);
  oh = (struct ospf6_header *) sendbuf;
  lsupdate = (struct ospf6_lsupdate *)
    ((caddr_t) oh + sizeof (struct ospf6_header));

  p = (u_char *)((caddr_t) lsupdate + sizeof (struct ospf6_lsupdate));
  num = 0;

  /* lsupdate_list lists those LSA which doesn't need to be
     retransmitted. remove those from the list */
  for (lsa = ospf6_lsdb_head (on->lsupdate_list); lsa;
       lsa = ospf6_lsdb_next (lsa))
    {
      /* MTU check */
      if ( (p - sendbuf + (unsigned int)OSPF6_LSA_SIZE (lsa->header))
          > on->ospf6_if->ifmtu)
        {
          ospf6_lsa_unlock (lsa);
          break;
        }

      ospf6_lsa_age_update_to_send (lsa, on->ospf6_if->transdelay);
      memcpy (p, lsa->header, OSPF6_LSA_SIZE (lsa->header));
      p += OSPF6_LSA_SIZE (lsa->header);
      num++;

      assert (lsa->lock == 2);
      ospf6_lsdb_remove (lsa, on->lsupdate_list);
    }

  for (lsa = ospf6_lsdb_head (on->retrans_list); lsa;
       lsa = ospf6_lsdb_next (lsa))
    {
      /* MTU check */
      if ( (p - sendbuf + (unsigned int)OSPF6_LSA_SIZE (lsa->header))
          > on->ospf6_if->ifmtu)
        {
          ospf6_lsa_unlock (lsa);
          break;
        }

      ospf6_lsa_age_update_to_send (lsa, on->ospf6_if->transdelay);
      memcpy (p, lsa->header, OSPF6_LSA_SIZE (lsa->header));
      p += OSPF6_LSA_SIZE (lsa->header);
      num++;
    }

  lsupdate->lsa_number = htonl (num);

  oh->type = OSPF6_MESSAGE_TYPE_LSUPDATE;
  oh->length = htons (p - sendbuf);

#ifdef OSPF6_MANET
  ospf6_send (on->ospf6_if->linklocal_addr, &on->linklocal_addr,
              on->ospf6_if, oh, ntohs(oh->length));
#else
  ospf6_send (on->ospf6_if->linklocal_addr, &on->linklocal_addr,
              on->ospf6_if, oh);
#endif //OSPF6_MANET

  if (on->lsupdate_list->count != 0 ||
      on->retrans_list->count != 0)
    {
      if (on->lsupdate_list->count != 0)
        on->thread_send_lsupdate =
          thread_add_event (master, ospf6_lsupdate_send_neighbor, on, 0);
      else
        on->thread_send_lsupdate =
          thread_add_timer (master, ospf6_lsupdate_send_neighbor, on,
                            on->ospf6_if->rxmt_interval);
    }

  return 0;
}
#endif //OSPF6_DELAYED_FLOOD

int
ospf6_lsupdate_send_interface (struct thread *thread)
{
  struct ospf6_interface *oi;
  struct ospf6_header *oh;
  struct ospf6_lsupdate *lsupdate;
  u_char *p;
  int num;
  struct ospf6_lsa *lsa;

  oi = (struct ospf6_interface *) THREAD_ARG (thread);
  oi->thread_send_lsupdate = (struct thread *) NULL;

  if (oi->state <= OSPF6_INTERFACE_WAITING)
    {
      if (IS_OSPF6_DEBUG_MESSAGE (OSPF6_MESSAGE_TYPE_LSUPDATE, SEND))
        zlog_debug ("Quit to send LSUpdate to interface %s state %s",
		    oi->interface->name, ospf6_interface_state_str[oi->state]);
      return 0;
    }

  /* if we have nothing to send, return */
  if (oi->lsupdate_list->count == 0)
    return 0;

  memset (sendbuf, 0, iobuflen);
  oh = (struct ospf6_header *) sendbuf;
  lsupdate = (struct ospf6_lsupdate *)((caddr_t) oh +
                                       sizeof (struct ospf6_header));

  p = (u_char *)((caddr_t) lsupdate + sizeof (struct ospf6_lsupdate));
  num = 0;

  for (lsa = ospf6_lsdb_head (oi->lsupdate_list); lsa;
       lsa = ospf6_lsdb_next (lsa))
    {
      /* MTU check */
      if ( (p - sendbuf + ((unsigned int)OSPF6_LSA_SIZE (lsa->header)))
          > oi->ifmtu)
        {
          ospf6_lsa_unlock (lsa);
          break;
        }

      ospf6_lsa_age_update_to_send (lsa, oi->transdelay);

      memcpy (p, lsa->header, OSPF6_LSA_SIZE (lsa->header));
      p += OSPF6_LSA_SIZE (lsa->header);
      num++;

      assert (lsa->lock == 2);
      ospf6_lsdb_remove (lsa, oi->lsupdate_list);
    }

  lsupdate->lsa_number = htonl (num);

  oh->type = OSPF6_MESSAGE_TYPE_LSUPDATE;
  oh->length = htons (p - sendbuf);

#ifdef OSPF6_CONFIG
  if (oi->type == OSPF6_IFTYPE_BROADCAST ||
      oi->type == OSPF6_IFTYPE_NBMA)
 {
  if (oi->state == OSPF6_INTERFACE_DR ||
    oi->state == OSPF6_INTERFACE_BDR)
#ifdef OSPF6_MANET
   ospf6_send (oi->linklocal_addr, &allspfrouters6,oi,oh,ntohs(oh->length));
#else
   ospf6_send (oi->linklocal_addr, &allspfrouters6, oi, oh);
#endif //OSPF6_MANET
  else
#ifdef OSPF6_MANET
   ospf6_send (oi->linklocal_addr, &alldrouters6, oi, oh, ntohs(oh->length));
#else
   ospf6_send (oi->linklocal_addr, &alldrouters6, oi, oh);
#endif //OSPF6_MANET
 }
 else
#ifdef OSPF6_MANET
  if(oi->type == OSPF6_IFTYPE_MANETRELIABLE ||
    oi->type == OSPF6_IFTYPE_POINTOMULTIPOINT)
   ospf6_send (oi->linklocal_addr, &allspfrouters6, oi,oh,ntohs(oh->length));
  else
   ospf6_send (oi->linklocal_addr, &alldrouters6, oi, oh, ntohs(oh->length));
#else
  ospf6_send (oi->linklocal_addr, &alldrouters6, oi, oh);
#endif //OSPF6_MANET

#else //OSPF6_CONFIG
  if (oi->state == OSPF6_INTERFACE_DR ||
      oi->state == OSPF6_INTERFACE_BDR)
    ospf6_send (oi->linklocal_addr, &allspfrouters6, oi, oh);
  else
    ospf6_send (oi->linklocal_addr, &alldrouters6, oi, oh);
#endif //OSPF6_CONFIG

  if (oi->lsupdate_list->count > 0)
    {
#ifdef OSPF6_DELAYED_FLOOD
      oi->thread_send_lsupdate =
     ospf6_send_lsupdate_delayed_msec(master, ospf6_lsupdate_send_interface,
                                      oi, oi->flood_delay, 
                                      oi->thread_send_lsupdate);
#else
      oi->thread_send_lsupdate =
        thread_add_event (master, ospf6_lsupdate_send_interface, oi, 0);
#endif //OSPF6_DELAYED_FLOOD
    }
  return 0;
}

int
ospf6_lsack_send_neighbor (struct thread *thread)
{
  struct ospf6_neighbor *on;
  struct ospf6_header *oh;
  u_char *p;
  struct ospf6_lsa *lsa;

  on = (struct ospf6_neighbor *) THREAD_ARG (thread);
  on->thread_send_lsack = (struct thread *) NULL;

  if (on->state < OSPF6_NEIGHBOR_EXCHANGE)
    {
      if (IS_OSPF6_DEBUG_MESSAGE (OSPF6_MESSAGE_TYPE_LSACK, SEND))
        zlog_debug ("Quit to send LSAck to neighbor %s state %s",
		    on->name, ospf6_neighbor_state_str[on->state]);
      return 0;
    }

  /* if we have nothing to send, return */
  if (on->lsack_list->count == 0)
    return 0;

  memset (sendbuf, 0, iobuflen);
  oh = (struct ospf6_header *) sendbuf;

  p = (u_char *)((caddr_t) oh + sizeof (struct ospf6_header));

  for (lsa = ospf6_lsdb_head (on->lsack_list); lsa;
       lsa = ospf6_lsdb_next (lsa))
    {
      /* MTU check */
      if (p - sendbuf + sizeof (struct ospf6_lsa_header) > on->ospf6_if->ifmtu)
        {
          /* if we run out of packet size/space here,
             better to try again soon. */
          THREAD_OFF (on->thread_send_lsack);
          on->thread_send_lsack =
            thread_add_event (master, ospf6_lsack_send_neighbor, on, 0);

          ospf6_lsa_unlock (lsa);
          break;
        }

      ospf6_lsa_age_update_to_send (lsa, on->ospf6_if->transdelay);
      memcpy (p, lsa->header, sizeof (struct ospf6_lsa_header));
      p += sizeof (struct ospf6_lsa_header);

      assert (lsa->lock == 2);
      ospf6_lsdb_remove (lsa, on->lsack_list);
    }

  oh->type = OSPF6_MESSAGE_TYPE_LSACK;
  oh->length = htons (p - sendbuf);

#ifdef OSPF6_MANET
  ospf6_send (on->ospf6_if->linklocal_addr, &on->linklocal_addr,
              on->ospf6_if, oh, ntohs(oh->length));
#else
  ospf6_send (on->ospf6_if->linklocal_addr, &on->linklocal_addr,
              on->ospf6_if, oh);
#endif //OSPF6_MANET
  return 0;
}

int
ospf6_lsack_send_interface (struct thread *thread)
{
  struct ospf6_interface *oi;
  struct ospf6_header *oh;
  u_char *p;
  struct ospf6_lsa *lsa;

  oi = (struct ospf6_interface *) THREAD_ARG (thread);
  oi->thread_send_lsack = (struct thread *) NULL;

  if (oi->state <= OSPF6_INTERFACE_WAITING)
    {
      if (IS_OSPF6_DEBUG_MESSAGE (OSPF6_MESSAGE_TYPE_LSACK, SEND))
        zlog_debug ("Quit to send LSAck to interface %s state %s",
		    oi->interface->name, ospf6_interface_state_str[oi->state]);
      return 0;
    }

  /* if we have nothing to send, return */
  if (oi->lsack_list->count == 0)
    return 0;

#if defined(OSPF6_MANET_MPR_SH) && defined(OSPF6_MANET_DIFF_HELLO)
  // SURROGATE_HELLO
  //Chandra03 3.4.9 paragraph 1 condition 6 and Chandra03 3.3.6.1 paragraph 1
  //sent ack counts as received hello with no state change
  // This is the portion in Incremental Hellos that doesn't send a Hello
  // that would normally have been sent
  if (oi->type == OSPF6_IFTYPE_MANETRELIABLE &&
      oi->flooding == OSPF6_FLOOD_MPR_SDCDS &&
      oi->diff_hellos)
  {
    struct listnode *n;
    boolean request = false;
    struct ospf6_neighbor *on;

    ospf6_calculate_relays(oi);
    //graceful restart
    if(elapsed_time(&ospf6->starttime)-oi->dead_interval<oi->hello_interval)
      oi->full_state = true;

    for (n = listhead(oi->neighbor_list); n; nextnode(n))
    { 
      on = (struct ospf6_neighbor *) getdata(n);
      if (on->request == true)
        request = true;
    }

    if(!oi->increment_scs && !oi->full_state && !oi->initialization && !request)
    {
      //reset hello interval to (HelloInterval +/- ~U(HelloInterval / 4))
      double jitter;
      long interval;
#ifdef SIM
      double rand_= (double) rand_sim()/RAND_MAX;
#else
      double rand_ = (double) rand()/RAND_MAX;
#endif //SIM
      if (rand_ > .5)
        jitter =  (rand_*oi->hello_interval/4) * 1000;
      else
        jitter = (-1) * (rand_*oi->hello_interval/4) * 1000;

      interval = (long) oi->hello_interval*1000  + (long) jitter;

      THREAD_OFF(oi->thread_send_hello);
      oi->thread_send_hello = 
       thread_add_timer_msec (master, ospf6_hello_send, oi, interval);
    }
  }
#endif //defined(OSPF6_MANET_MPR_FLOOD) && defined(OSPF6_MANET_DIFF_HELLO)

  memset (sendbuf, 0, iobuflen);
  oh = (struct ospf6_header *) sendbuf;

  p = (u_char *)((caddr_t) oh + sizeof (struct ospf6_header));

  for (lsa = ospf6_lsdb_head (oi->lsack_list); lsa;
       lsa = ospf6_lsdb_next (lsa))
    {
      /* MTU check */
      if (p - sendbuf + sizeof (struct ospf6_lsa_header) > oi->ifmtu)
        {
          /* if we run out of packet size/space here,
             better to try again soon. */
          THREAD_OFF (oi->thread_send_lsack);
          oi->thread_send_lsack =
            thread_add_event (master, ospf6_lsack_send_interface, oi, 0);

          ospf6_lsa_unlock (lsa);
          break;
        }

      ospf6_lsa_age_update_to_send (lsa, oi->transdelay);
      memcpy (p, lsa->header, sizeof (struct ospf6_lsa_header));
      p += sizeof (struct ospf6_lsa_header);

      assert (lsa->lock == 2);
      ospf6_lsdb_remove (lsa, oi->lsack_list);
    }

  oh->type = OSPF6_MESSAGE_TYPE_LSACK;
  oh->length = htons (p - sendbuf);

#ifdef OSPF6_CONFIG
  if (oi->type == OSPF6_IFTYPE_BROADCAST ||
      oi->type == OSPF6_IFTYPE_NBMA)
 {
  if (oi->state == OSPF6_INTERFACE_DR ||
    oi->state == OSPF6_INTERFACE_BDR)
#ifdef OSPF6_MANET
   ospf6_send (oi->linklocal_addr, &allspfrouters6,oi,oh,ntohs(oh->length));
#else
   ospf6_send (oi->linklocal_addr, &allspfrouters6, oi, oh);
#endif //OSPF6_MANET
  else
#ifdef OSPF6_MANET
   ospf6_send (oi->linklocal_addr, &alldrouters6,oi,oh,ntohs(oh->length));
#else
   ospf6_send (oi->linklocal_addr, &alldrouters6, oi, oh);
#endif //OSPF6_MANET
 }
 else
 {
#ifdef OSPF6_MANET
  ospf6_send (oi->linklocal_addr, &allspfrouters6, oi, oh, ntohs(oh->length));
#else
  ospf6_send (oi->linklocal_addr, &allspfrouters6, oi, oh);
#endif //OSPF6_MANET

 }
#else //OSPF6_CONFIG
  if (oi->state == OSPF6_INTERFACE_DR ||
      oi->state == OSPF6_INTERFACE_BDR)
    ospf6_send (oi->linklocal_addr, &allspfrouters6, oi, oh);
  else
    ospf6_send (oi->linklocal_addr, &alldrouters6, oi, oh);
#endif //OSPF6_CONFIG

  if (oi->thread_send_lsack == NULL && oi->lsack_list->count > 0)
    {
      oi->thread_send_lsack =
        thread_add_event (master, ospf6_lsack_send_interface, oi, 0);
    }

  return 0;
}


/* Commands */
DEFUN (debug_ospf6_message,
       debug_ospf6_message_cmd,
       "debug ospf6 message (unknown|hello|dbdesc|lsreq|lsupdate|lsack|all)",
       DEBUG_STR
       OSPF6_STR
       "Debug OSPFv3 message\n"
       "Debug Unknown message\n"
       "Debug Hello message\n"
       "Debug Database Description message\n"
       "Debug Link State Request message\n"
       "Debug Link State Update message\n"
       "Debug Link State Acknowledgement message\n"
       "Debug All message\n"
       )
{
  unsigned char level = 0;
  int type = 0;
  int i;

  assert (argc > 0);

  /* check type */
  if (! strncmp (argv[0], "u", 1))
    type = OSPF6_MESSAGE_TYPE_UNKNOWN;
  else if (! strncmp (argv[0], "h", 1))
    type = OSPF6_MESSAGE_TYPE_HELLO;
  else if (! strncmp (argv[0], "d", 1))
    type = OSPF6_MESSAGE_TYPE_DBDESC;
  else if (! strncmp (argv[0], "lsr", 3))
    type = OSPF6_MESSAGE_TYPE_LSREQ;
  else if (! strncmp (argv[0], "lsu", 3))
    type = OSPF6_MESSAGE_TYPE_LSUPDATE;
  else if (! strncmp (argv[0], "lsa", 3))
    type = OSPF6_MESSAGE_TYPE_LSACK;
  else if (! strncmp (argv[0], "a", 1))
    type = OSPF6_MESSAGE_TYPE_ALL;

  if (argc == 1)
    level = OSPF6_DEBUG_MESSAGE_SEND | OSPF6_DEBUG_MESSAGE_RECV;
  else if (! strncmp (argv[1], "s", 1))
    level = OSPF6_DEBUG_MESSAGE_SEND;
  else if (! strncmp (argv[1], "r", 1))
    level = OSPF6_DEBUG_MESSAGE_RECV;

  if (type == OSPF6_MESSAGE_TYPE_ALL)
    {
      for (i = 0; i < 6; i++)
        OSPF6_DEBUG_MESSAGE_ON (i, level);
    }
  else
    OSPF6_DEBUG_MESSAGE_ON (type, level);

  return CMD_SUCCESS;
}

ALIAS (debug_ospf6_message,
       debug_ospf6_message_sendrecv_cmd,
       "debug ospf6 message (unknown|hello|dbdesc|lsreq|lsupdate|lsack|all) (send|recv)",
       DEBUG_STR
       OSPF6_STR
       "Debug OSPFv3 message\n"
       "Debug Unknown message\n"
       "Debug Hello message\n"
       "Debug Database Description message\n"
       "Debug Link State Request message\n"
       "Debug Link State Update message\n"
       "Debug Link State Acknowledgement message\n"
       "Debug All message\n"
       "Debug only sending message\n"
       "Debug only receiving message\n"
       );


DEFUN (no_debug_ospf6_message,
       no_debug_ospf6_message_cmd,
       "no debug ospf6 message (unknown|hello|dbdesc|lsreq|lsupdate|lsack|all)",
       NO_STR
       DEBUG_STR
       OSPF6_STR
       "Debug OSPFv3 message\n"
       "Debug Unknown message\n"
       "Debug Hello message\n"
       "Debug Database Description message\n"
       "Debug Link State Request message\n"
       "Debug Link State Update message\n"
       "Debug Link State Acknowledgement message\n"
       "Debug All message\n"
       )
{
  unsigned char level = 0;
  int type = 0;
  int i;

  assert (argc > 0);

  /* check type */
  if (! strncmp (argv[0], "u", 1))
    type = OSPF6_MESSAGE_TYPE_UNKNOWN;
  else if (! strncmp (argv[0], "h", 1))
    type = OSPF6_MESSAGE_TYPE_HELLO;
  else if (! strncmp (argv[0], "d", 1))
    type = OSPF6_MESSAGE_TYPE_DBDESC;
  else if (! strncmp (argv[0], "lsr", 3))
    type = OSPF6_MESSAGE_TYPE_LSREQ;
  else if (! strncmp (argv[0], "lsu", 3))
    type = OSPF6_MESSAGE_TYPE_LSUPDATE;
  else if (! strncmp (argv[0], "lsa", 3))
    type = OSPF6_MESSAGE_TYPE_LSACK;
  else if (! strncmp (argv[0], "a", 1))
    type = OSPF6_MESSAGE_TYPE_ALL;

  if (argc == 1)
    level = OSPF6_DEBUG_MESSAGE_SEND | OSPF6_DEBUG_MESSAGE_RECV;
  else if (! strncmp (argv[1], "s", 1))
    level = OSPF6_DEBUG_MESSAGE_SEND;
  else if (! strncmp (argv[1], "r", 1))
    level = OSPF6_DEBUG_MESSAGE_RECV;

  if (type == OSPF6_MESSAGE_TYPE_ALL)
    {
      for (i = 0; i < 6; i++)
        OSPF6_DEBUG_MESSAGE_OFF (i, level);
    }
  else
    OSPF6_DEBUG_MESSAGE_OFF (type, level);

  return CMD_SUCCESS;
}

ALIAS (no_debug_ospf6_message,
       no_debug_ospf6_message_sendrecv_cmd,
       "no debug ospf6 message "
       "(unknown|hello|dbdesc|lsreq|lsupdate|lsack|all) (send|recv)",
       NO_STR
       DEBUG_STR
       OSPF6_STR
       "Debug OSPFv3 message\n"
       "Debug Unknown message\n"
       "Debug Hello message\n"
       "Debug Database Description message\n"
       "Debug Link State Request message\n"
       "Debug Link State Update message\n"
       "Debug Link State Acknowledgement message\n"
       "Debug All message\n"
       "Debug only sending message\n"
       "Debug only receiving message\n"
       );

int
config_write_ospf6_debug_message (struct vty *vty)
{
  const char *type_str[] = {"unknown", "hello", "dbdesc",
                      "lsreq", "lsupdate", "lsack"};
  unsigned char s = 0, r = 0;
  int i;

  for (i = 0; i < 6; i++)
    {
      if (IS_OSPF6_DEBUG_MESSAGE (i, SEND))
        s |= 1 << i;
      if (IS_OSPF6_DEBUG_MESSAGE (i, RECV))
        r |= 1 << i;
    }

  if (s == 0x3f && r == 0x3f)
    {
      vty_out (vty, "debug ospf6 message all%s", VNL);
      return 0;
    }

  if (s == 0x3f && r == 0)
    {
      vty_out (vty, "debug ospf6 message all send%s", VNL);
      return 0;
    }
  else if (s == 0 && r == 0x3f)
    {
      vty_out (vty, "debug ospf6 message all recv%s", VNL);
      return 0;
    }

  /* Unknown message is logged by default */
  if (! IS_OSPF6_DEBUG_MESSAGE (OSPF6_MESSAGE_TYPE_UNKNOWN, SEND) &&
      ! IS_OSPF6_DEBUG_MESSAGE (OSPF6_MESSAGE_TYPE_UNKNOWN, RECV))
    vty_out (vty, "no debug ospf6 message unknown%s", VNL);
  else if (! IS_OSPF6_DEBUG_MESSAGE (OSPF6_MESSAGE_TYPE_UNKNOWN, SEND))
    vty_out (vty, "no debug ospf6 message unknown send%s", VNL);
  else if (! IS_OSPF6_DEBUG_MESSAGE (OSPF6_MESSAGE_TYPE_UNKNOWN, RECV))
    vty_out (vty, "no debug ospf6 message unknown recv%s", VNL);

  for (i = 1; i < 6; i++)
    {
      if (IS_OSPF6_DEBUG_MESSAGE (i, SEND) &&
          IS_OSPF6_DEBUG_MESSAGE (i, RECV))
        vty_out (vty, "debug ospf6 message %s%s", type_str[i], VNL);
      else if (IS_OSPF6_DEBUG_MESSAGE (i, SEND))
        vty_out (vty, "debug ospf6 message %s send%s", type_str[i],
                 VNL);
      else if (IS_OSPF6_DEBUG_MESSAGE (i, RECV))
        vty_out (vty, "debug ospf6 message %s recv%s", type_str[i],
                 VNL);
    }

  return 0;
}

void
install_element_ospf6_debug_message ()
{
  install_element (ENABLE_NODE, &debug_ospf6_message_cmd);
  install_element (ENABLE_NODE, &no_debug_ospf6_message_cmd);
  install_element (ENABLE_NODE, &debug_ospf6_message_sendrecv_cmd);
  install_element (ENABLE_NODE, &no_debug_ospf6_message_sendrecv_cmd);
  install_element (CONFIG_NODE, &debug_ospf6_message_cmd);
  install_element (CONFIG_NODE, &no_debug_ospf6_message_cmd);
  install_element (CONFIG_NODE, &debug_ospf6_message_sendrecv_cmd);
  install_element (CONFIG_NODE, &no_debug_ospf6_message_sendrecv_cmd);
}

#ifdef OSPF6_MANET
boolean ospf6_is_rtrid_in_list(struct ospf6_interface *oi,
                      u_int32_t *router_id,
                      int num)
{
  int i;
  boolean found = false;
  for (i = 0; i < num; i++)
  {
    if (*router_id == oi->area->ospf6->router_id)
    {
      found = true;
      break;
    }
    router_id++;
  }
  return found;
}

int ospf6_append_lls_header(struct ospf6_interface *oi,
                            u_char *lls,
                            u_int len)
{
  struct ospf6_LLS_header lls_header;
  u_int count;
  u_int16_t checksum, *p; /*16-bit*/
  u_int32_t sum = 0;

  /*this checksum algorithm can be found in RFC 1071 section 4.1 */
  count = len;
  p = (u_int16_t*) lls;
  while (count > 1)  {
    sum += *p++;
    count -= 2;
  }
  sum += htons(len/4);

  /* add left-over byte, if any */
  if (count > 0)
    sum += (char)*p;

  /*  Fold 32-bit sum to 16 bits */
  while (sum>>16)
    sum = (sum & 0xffff) + (sum >> 16);

  /* take the one's complement of the sum */
  checksum = ~sum;

  lls_header.len = htons((u_int16_t)(len/4));
  lls_header.cksum = checksum;

  memcpy(lls, &lls_header, sizeof(struct ospf6_LLS_header));

  return(sizeof(struct ospf6_LLS_header));
}

void ospf6_tlv_header_assignment(struct ospf6_TLV_header *tlv_header,
                                 u_int16_t type, u_int16_t len)
{
  tlv_header->type = htons(type);
  tlv_header->len = htons(len);
}

#ifdef OSPF6_MANET_MPR_FLOOD
void ospf6_mpr_process_TLVs(struct ospf6_neighbor *on,
                      struct ospf6_LLS_header *lls_ptr)
{
 struct ospf6_interface *oi = on->ospf6_if;
  u_int32_t *relay_id_ptr=NULL;
  int length_lls = 0, tlv_val_len, added_relays=0, dropped_relays=0;
  struct ospf6_TLV_header *tlv_header = NULL;
  struct ospf6_options_TLV *tlv_val_opt = NULL;
  struct ospf6_relay_TLV *tlv_val_relay = NULL;
  struct ospf6_will_TLV *tlv_val_will = NULL;

 length_lls =  ntohs(lls_ptr->len) * 4 - sizeof(struct ospf6_LLS_header);
  tlv_header = (struct ospf6_TLV_header *) (lls_ptr + 1);
  while (length_lls > 0)
  {
    tlv_val_len = ntohs(tlv_header->len);
    length_lls -= (sizeof(tlv_header) + tlv_val_len);
    switch (ntohs(tlv_header->type))
    {
      case OSPF6_TLV_TYPE_OPTIONS:
      {
        assert(!tlv_val_opt); //Malformed packet: 2 option TLVs
        tlv_val_opt = (struct ospf6_options_TLV *) (tlv_header + 1);
        tlv_header = (struct ospf6_TLV_header *) (tlv_val_opt + 1);
        break;
      }
      case OSPF6_TLV_TYPE_RELAY:
      {
        assert(!tlv_val_relay); //Malformed packet: 2 RELAY TLVs
        tlv_val_relay = (struct ospf6_relay_TLV*) (tlv_header + 1);
        added_relays = tlv_val_relay->added;
        relay_id_ptr = (u_int32_t *) (tlv_val_relay + 1);
        dropped_relays = (ntohs(tlv_header->len)-sizeof(tlv_val_relay)) /
                                           sizeof(u_int32_t) - added_relays;
        assert(!dropped_relays);//shouldn't have dropped relays(not diff hellos)
        tlv_header = (struct ospf6_TLV_header *) (relay_id_ptr + added_relays);
        break;
      }
      case OSPF6_TLV_TYPE_WILLINGNESS:
      {
        assert(!tlv_val_will); //Malformed packet: 2 willingness TLVs
        tlv_val_will = (struct ospf6_will_TLV*) (tlv_header + 1);
        tlv_header = (struct ospf6_TLV_header *) (tlv_val_will + 1);
        break;
      }
      default:
      {
        /* advance tlv_header pointer */
        tlv_header = (struct ospf6_TLV_header *)
          ((char *)tlv_header + (ntohs(tlv_header->len)+sizeof(tlv_header)));
        break;
      }
    }
  }

  if (tlv_val_relay)
  {
    if (OSPF6_TLV_REL_OPT_ISSET(tlv_val_relay->bits,OSPF6_TLV_REL_OPT_A ,0))
      on->Relay_Abit = true;
     else 
      on->Relay_Abit = false;

    if (OSPF6_TLV_REL_OPT_ISSET(tlv_val_relay->bits,OSPF6_TLV_REL_OPT_N ,0))
      on->Relay_Nbit = true;
     else 
      on->Relay_Nbit = false;

    if(relay_id_ptr && ospf6_is_rtrid_in_list(oi, relay_id_ptr, added_relays))
      ospf6_refresh_relay_selector(on);
  }
}

int ospf6_append_relays(struct ospf6_interface *oi,
                        u_char *pos,
                        u_char *max_pos,
                        boolean periodic_hello,
                        boolean full_neighbor_state)
{
  struct listnode *n;
  int data_size = 0, added_relays = 0, active_size = 0, drop_size = 0;
  struct ospf6_relay *relay;
  char buffer1[iobuflen], buffer2[iobuflen];

  n = listhead(oi->relay_list);
  while(n)
  {
    relay = (struct ospf6_relay*) getdata(n);
    nextnode(n);

    if (pos + (sizeof(struct ospf6_TLV_header) +
      sizeof(struct ospf6_relay_TLV)*(data_size+1)+sizeof(relay)) >= max_pos)
    {
      zlog_warn ("Send HELLO: Buffer shortage on %s",
                    oi->interface->name);
      break;
    }

    if(relay->drop)
    {
      if (elapsed_time(relay->drop_expire_time) >= oi->dead_interval)
      {
        ospf6_relay_delete(oi, relay);
        continue;
      }
      if (full_neighbor_state)
        continue; //don't list dropped relays when giving full state
      memcpy (buffer2+drop_size, &relay->router_id, sizeof(u_int32_t));
      drop_size += sizeof(u_int32_t);
    }
    else
    {
      if (!(relay->newly_activated || full_neighbor_state))
        continue;
      if (periodic_hello)
        relay->newly_activated = false;
      memcpy (buffer1+active_size, &relay->router_id, sizeof(u_int32_t));
      active_size += sizeof(u_int32_t);
    }
    data_size = active_size + drop_size;
  }
  added_relays = active_size / sizeof(u_int32_t);

  if (data_size > 0)
  {
    struct ospf6_TLV_header tlv_header;
    struct ospf6_relay_TLV relay_tlv;
    u_char *tlv;

    relay_tlv.added = added_relays;
    OSPF6_TLV_REL_OPT_CLEAR_ALL(relay_tlv.bits);

    ospf6_tlv_header_assignment(&tlv_header,
                                OSPF6_TLV_TYPE_RELAY,
                                data_size+sizeof(struct ospf6_relay_TLV));
    data_size += sizeof(sizeof(struct ospf6_TLV_header));
    data_size += sizeof(struct ospf6_relay_TLV);

    tlv = pos;
    memcpy(pos, &tlv_header, sizeof(struct ospf6_TLV_header));
    pos +=  sizeof(struct ospf6_TLV_header);
    memcpy(pos, &relay_tlv, sizeof(struct ospf6_relay_TLV));
    pos += sizeof(struct ospf6_relay_TLV);
    if (active_size)
    {
      memcpy(pos, buffer1, active_size);
      pos += active_size;
    }
    if (drop_size)
      memcpy(pos, buffer2, drop_size);
  }
  return data_size;
}

int ospf6_create_neighbor_list(struct ospf6_interface *oi,
                           u_char *sendbuf,
                           u_char *position,
                           boolean full_neighbor_state)
{
  struct listnode *n;
 int data_size = 0;
  struct ospf6_neighbor *on;

  for (n = listhead(oi->neighbor_list); n; nextnode(n))
  {
    on = (struct ospf6_neighbor *) getdata(n);

    if (on->state < OSPF6_NEIGHBOR_INIT)
      continue;
#ifdef OSPF6_MANET_DIFF_HELLO
    if (!(full_neighbor_state || on->below_exchange))
#else
    if (!(full_neighbor_state))
#endif //OSPF6_MANET_DIFF_HELLO
      continue;

    if (position - sendbuf + sizeof (u_int32_t) > oi->ifmtu)
    {
      if (IS_OSPF6_DEBUG_MESSAGE (OSPF6_MESSAGE_TYPE_HELLO, SEND))
      {
        zlog_info ("sending Hello message: exceeds I/F MTU");
        break;
      }
    }
    memcpy (position, &on->router_id, sizeof (u_int32_t));
    position += sizeof (u_int32_t);
  data_size += sizeof (u_int32_t);
 }
 return data_size;
}

#ifdef OSPF6_MANET_DIFF_HELLO
boolean ospf6_is_scs_wrap_around(u_int16_t old_scs_num, u_int16_t new_scs_num)
{
  if (old_scs_num == MAX_SCS_NUMBER && new_scs_num == 0)
    return true;
  return false;
}

int ospf6_append_scs(struct ospf6_interface *oi,
                     char *opt,
                     u_char *pos)
{
  struct ospf6_TLV_header tlv_header;
  struct ospf6_scs_TLV    scs_tlv;
  int data_size = 0;

  scs_tlv.number = htons(oi->scs_num);
  scs_tlv.bits[0] = opt[0];
  scs_tlv.bits[1] = opt[1];
  data_size += sizeof(struct ospf6_scs_TLV);

  ospf6_tlv_header_assignment(&tlv_header,
                              OSPF6_TLV_TYPE_SCS,
                              sizeof(struct ospf6_scs_TLV));
  data_size += sizeof(struct ospf6_TLV_header);

  memcpy(pos, &tlv_header, sizeof(struct ospf6_TLV_header));
  memcpy(pos + sizeof(struct ospf6_TLV_header),
                      &scs_tlv, sizeof(struct ospf6_scs_TLV));

 return data_size;
}

int ospf6_append_drop_neighbors(struct ospf6_interface *oi,
                                u_char *pos,
                                u_char *max_pos,
                                boolean *set_N)
{
  struct listnode *n;
  struct drop_neighbor *drop_neigh;
  char drop_tlv[iobuflen];
  int data_size = 0;

  n = listhead(oi->drop_neighbor_list);
  while(n)
  {
    drop_neigh = (struct drop_neighbor *) getdata (n);
    nextnode(n);
    //Chandra03 3.3.6.2 paragraph 1 bullet 4
    if (elapsed_time(drop_neigh->expire_time) > oi->dead_interval)
    {
      ospf6_drop_neighbor_delete(oi, drop_neigh);
      continue;
    }
    if (pos + (sizeof(struct ospf6_TLV_header) +
        sizeof(u_int32_t) * (data_size+1)) >= max_pos)
    {
      zlog_warn ("Send HELLO: Buffer shortage on %s",
                     oi->interface->name);
      break;
    }
    //Chandra03 3.3.6.2 paragraph 1 bullet 4
    if (!drop_neigh->first)
      *set_N = true;
    drop_neigh->first = false;
    memcpy (drop_tlv + data_size, &(drop_neigh->router_id), sizeof(u_int32_t));
    data_size += sizeof(u_int32_t);
  }

  if (data_size > 0)
  {
    struct ospf6_TLV_header tlv_header;
    ospf6_tlv_header_assignment(&tlv_header,
                                OSPF6_TLV_TYPE_NEIGHDROP,
                                data_size);
    memcpy(pos, &tlv_header, sizeof(struct ospf6_TLV_header));
    memcpy(pos + sizeof(struct ospf6_TLV_header), drop_tlv, data_size);

    data_size += sizeof(struct ospf6_TLV_header);
  }
  return data_size;
}

int ospf6_append_request(struct ospf6_interface *oi,
                         u_char *pos,
                         u_char *max_pos,
                         char *scs_tlv_option)
{
  int data_size = 0;
  struct listnode *n;
  struct ospf6_neighbor *on;
  char request_tlv[iobuflen];

  for (n = listhead(oi->neighbor_list); n; nextnode(n))
  {
    on = (struct ospf6_neighbor *) getdata(n);

    if (on->state < OSPF6_NEIGHBOR_INIT)
      continue;

    if (on->request == false)
      continue;

    if (pos + (sizeof(struct ospf6_TLV_header) +
        sizeof(u_int32_t) * (data_size+1)) >= max_pos)
    {
      zlog_warn ("Send HELLO: Buffer shortage on %s",
                     oi->interface->name);
      break;
    }
    on->request = false;
    memcpy (request_tlv + data_size, &(on->router_id), sizeof(u_int32_t));
    data_size += sizeof(u_int32_t);
  }

  if (data_size > 0)
  {
    struct ospf6_TLV_header tlv_header;
    ospf6_tlv_header_assignment(&tlv_header,
                                OSPF6_TLV_TYPE_REQUEST,
                                data_size);
    memcpy(pos, &tlv_header, sizeof(struct ospf6_TLV_header));
    memcpy(pos + sizeof(struct ospf6_TLV_header), request_tlv, data_size);

    data_size += sizeof(struct ospf6_TLV_header);
    OSPF6_TLV_SCS_OPT_SET(scs_tlv_option, OSPF6_TLV_SCS_OPT_R, 0);
  }
  return data_size;
}

void ospf6_mpr_process_diff_TLVs(struct ospf6_neighbor *on,
                             struct ospf6_LLS_header * lls_ptr,
                             int seenrtrnum,
                             char *scs_tlv_option,
                             boolean *twoway,
                             boolean *send_mhello)
{
  struct ospf6_interface *oi = on->ospf6_if;
  u_int16_t old_scs_num, new_scs_num = 0;
  u_int32_t *relay_id_ptr=NULL, *drop_relay_id_ptr=NULL;
  u_int32_t *tlv_val_req=NULL, *tlv_val_full=NULL, *tlv_val_drop = NULL;
  int length_lls=0, tlv_val_len, added_relays=0, dropped_relays=0;
  int rtrdropnum=0, reqnum=0, fullnum=0;
  struct ospf6_TLV_header *tlv_header = NULL;
  struct ospf6_options_TLV *tlv_val_opt = NULL;
  struct ospf6_scs_TLV *tlv_val_scs = NULL;
  struct ospf6_relay_TLV *tlv_val_relay = NULL;
  struct ospf6_will_TLV *tlv_val_will = NULL;

  old_scs_num = on->scs_num;
  length_lls =  ntohs(lls_ptr->len) * 4 - sizeof(struct ospf6_LLS_header);
  tlv_header = (struct ospf6_TLV_header *) (lls_ptr + 1);
  while (length_lls > 0)
  {
    tlv_val_len = ntohs(tlv_header->len);
    length_lls -= (sizeof(tlv_header) + tlv_val_len);
    switch (ntohs(tlv_header->type))
    {
      case OSPF6_TLV_TYPE_OPTIONS:
        assert(!tlv_val_opt); //Malformed packet: 2 option TLVs
        tlv_val_opt = (struct ospf6_options_TLV *) (tlv_header + 1);
        tlv_header = (struct ospf6_TLV_header *) (tlv_val_opt + 1);
        break;
      case OSPF6_TLV_TYPE_SCS:
        assert(!tlv_val_scs); //Malformed packet: 2 SCS TLVs
        tlv_val_scs = (struct ospf6_scs_TLV *) (tlv_header + 1);
        new_scs_num = ntohs(tlv_val_scs->number);
        if (on->set_scs_num)
        {
          on->set_scs_num = false;
          old_scs_num = new_scs_num-2;
          on->scs_num = old_scs_num;
        } 
        tlv_header = (struct ospf6_TLV_header *) (tlv_val_scs + 1);
        break;
      case OSPF6_TLV_TYPE_NEIGHDROP:
      {
        assert(!tlv_val_drop); //Malformed packet: 2 DROP TLVs
        tlv_val_drop = (u_int32_t*) (tlv_header + 1);
        rtrdropnum = ntohs(tlv_header->len)/4;
        tlv_header = (struct ospf6_TLV_header *) (tlv_val_drop + rtrdropnum);
        break;
      }
      case OSPF6_TLV_TYPE_REQUEST:
        assert(!tlv_val_req); //Malformed packet: 2 Request TLVs
        tlv_val_req = (u_int32_t*) (tlv_header + 1);
        reqnum = ntohs(tlv_header->len)/4;
        tlv_header = (struct ospf6_TLV_header *) (tlv_val_req + reqnum);
        break;
      case OSPF6_TLV_TYPE_FULL:
        assert(!tlv_val_full); //Malformed packet: 2 Request TLVs
        tlv_val_full = (u_int32_t*) (tlv_header + 1);
        fullnum = ntohs(tlv_header->len)/4;
        tlv_header = (struct ospf6_TLV_header *) (tlv_val_full + fullnum);
        break;
      case OSPF6_TLV_TYPE_RELAY:
        assert(!tlv_val_relay); //Malformed packet: 2 RELAY TLVs
        tlv_val_relay = (struct ospf6_relay_TLV*) (tlv_header + 1);
        added_relays = tlv_val_relay->added;
        relay_id_ptr = (u_int32_t *) (tlv_val_relay + 1);
        dropped_relays = (ntohs(tlv_header->len)-sizeof(tlv_val_relay)) /
                                           sizeof(u_int32_t) - added_relays;
        if (dropped_relays)
          drop_relay_id_ptr = (u_int32_t *) (tlv_val_relay+(1 + added_relays));

        tlv_header = (struct ospf6_TLV_header *)
                   (relay_id_ptr + (added_relays + dropped_relays));
        break;
      case OSPF6_TLV_TYPE_WILLINGNESS:
        assert(!tlv_val_will); //Malformed packet: 2 willingness TLVs
        tlv_val_will = (struct ospf6_will_TLV*) (tlv_header + 1);
        tlv_header = (struct ospf6_TLV_header *) (tlv_val_will + 1);
        break;
      default:
        /* advance tlv_header pointer */
        tlv_header = (struct ospf6_TLV_header *)
          ((char *)tlv_header + (ntohs(tlv_header->len)+sizeof(tlv_header)));
        break;
    }
  }

  /* SCS processing */
  if (tlv_val_scs)
  {
    /* Chandra03 3.3.8.2:  Receiving Hellos with the R bit set*/
    if (OSPF6_TLV_SCS_OPT_ISSET(tlv_val_scs->bits,OSPF6_TLV_SCS_OPT_R,0))
    { 
      if (reqnum == 0) //requesting state from all neighbors
        on->ospf6_if->full_state = true;
      else if (reqnum > 0 && ospf6_is_rtrid_in_list(oi, tlv_val_req, reqnum))
        on->ospf6_if->full_state = true;
    }

    /* Chandra03 3.3.8.3 paragraph 1 bullet 1*/ 
    if (new_scs_num == old_scs_num)
    {
      if (on->state >= OSPF6_NEIGHBOR_TWOWAY)
        *twoway = true;
      if (ospf6_lookup_relay_selector(oi, on->router_id))
        ospf6_refresh_relay_selector(on);
    }
    /* Chandra03 3.3.8.3:  Receiving Hello with the FS bit set*/
    else if (OSPF6_TLV_SCS_OPT_ISSET(tlv_val_scs->bits,OSPF6_TLV_SCS_OPT_FS,0))
    { 

/*    XXX I don't understand why you would not want full state when
          you currently have a different SCS number.
          If the SCS number is the same then no processing is done anyway.
      if (fullnum > 0 && !ospf6_is_rtrid_in_list(oi, tlv_val_req, reqnum))
      { //full state is not for this neighbor
        //twoway will be set in mhello_recv() because full state
        if (ospf6_lookup_relay_selector(oi, on->router_id))
          ospf6_refresh_relay_selector(on);
        return;
      }
*/
      /* Chandra03 3.3.8.3 paragraph 1 bullet 2*/ 
      on->scs_num = new_scs_num;
      if (*twoway) // router_id found in neighbor list
      {
        struct ospf6_relay_selector *relay_sel;
        if (tlv_val_relay && relay_id_ptr &&
               ospf6_is_rtrid_in_list(oi, relay_id_ptr, added_relays))
        {
          ospf6_refresh_relay_selector(on);
        }
        else if((relay_sel=ospf6_lookup_relay_selector(oi, on->router_id)))
        {
          ospf6_relay_selector_delete(oi, relay_sel);
        }
      }
    }
    else if (on->state >= OSPF6_NEIGHBOR_TWOWAY || *twoway)
    {
      *twoway = true;
      /* Chandra03 3.3.8 paragraph 2 */
      if (new_scs_num < old_scs_num &&
            !ospf6_is_scs_wrap_around(old_scs_num, new_scs_num))
      { 
        on->request = true;
      }
      /* Chandra03 3.3.8 paragraph 3*/
      else if (ospf6_is_scs_wrap_around(old_scs_num, new_scs_num) ||
               new_scs_num == old_scs_num + 1)
      { 
        boolean increment_scs = false;
        
        /* Chandra03 3.3.8 paragraph 3 bullet 1*/
        if (seenrtrnum > 0) 
          increment_scs = true; 

        /* Chandra03 3.3.8 paragraph 3 bullet 3*/
        if (rtrdropnum > 0 && tlv_val_drop &&
                 ospf6_is_rtrid_in_list(oi, tlv_val_drop, rtrdropnum))
        {
         /*thread_add_event (master, neighbor_change, on->ospf6_if, 0);
         listnode_delete (on->ospf6_if->neighbor_list, on);
         ospf6_neighbor_delete (on); */ //BOEING Draft Change
          *twoway = false;
          return;
        }
        /* Chandra03 3.3.8 paragraph 3 bullet 3*/
        else if (rtrdropnum > 0 && tlv_val_drop) 
          increment_scs = true;

        /* Chandra03 3.3.8 paragraph 3 bullet 4*/
        if (tlv_val_relay && ((added_relays + dropped_relays) > 0))
        { 
          increment_scs = true;
          if(drop_relay_id_ptr &&
                ospf6_is_rtrid_in_list(oi, drop_relay_id_ptr, dropped_relays))
          {
            struct ospf6_relay_selector *relay_sel;
            if((relay_sel=ospf6_lookup_relay_selector(oi, on->router_id)))
              ospf6_relay_selector_delete(oi, relay_sel);
          }
          else if (relay_id_ptr &&
               ospf6_is_rtrid_in_list(oi, relay_id_ptr, added_relays))
            ospf6_refresh_relay_selector(on);
          else if (ospf6_lookup_relay_selector(oi, ospf6->router_id))
            ospf6_refresh_relay_selector(on);
        }

        //Chandra03 3.3.8.1 Receiving hellos with the N bit set
        if (OSPF6_TLV_SCS_OPT_ISSET(tlv_val_scs->bits,OSPF6_TLV_SCS_OPT_N,0))
        { 
          on->request = true;
        }
        else if (increment_scs)
          on->scs_num = ospf6_increment_scs(on->scs_num);
        else
        { /* Chandra03 3.3.8 paragraph 3 bullet 5*/
          on->request = true;
        }
      }
      /* Chandra03 3.3.8 paragraph 4 */
      else if (new_scs_num > old_scs_num + 1)
      { 
        on->request = true;
      }
    }
  }
}
#endif// OSPF6_MANET_DIFF_HELLO
#endif //OSPF6_MANET_MPR_FLOOD

#ifdef OSPF6_MANET_MDR_FLOOD
// Ogierv3 10.1
// DNL list added for Ogierv7.
u_int ospf6_mdr_create_neighbor_lists(struct ospf6_interface *oi,
                                            u_char *pos, u_char *max_pos,
                                            u_int *num_hnl, u_char *hnl,
                                            u_int *num_rnl, u_char *rnl,
                                            u_int *num_lnl, u_char *lnl,
                                            u_int *num_dnl, u_char *dnl,
                                            boolean diff)
{
  struct listnode *n;
  struct ospf6_neighbor *on;
  u_int lls_length=0, lls_header=0, seq_tlv=0;
  u_int hnl_length=0, rnl_length=0, lnl_length=0;
  u_int dnl_length=0;
  int size_tlv_head = sizeof(struct ospf6_TLV_header);
  int size_rid = sizeof(u_int32_t);
  
  lls_header = sizeof(struct ospf6_LLS_header);
#ifdef OSPF6_MANET_DIFF_HELLO
  if (oi->diff_hellos)
    seq_tlv = sizeof(struct ospf6_TLV_header) + sizeof(struct ospf6_seq_TLV);
#endif //OSPF6_MANET_DIFF_HELLO
  lls_length = lls_header + seq_tlv;

  for (n = listhead(oi->neighbor_list); n; nextnode(n))
  {
    on = (struct ospf6_neighbor *) getdata(n);

    if (on->state <= OSPF6_NEIGHBOR_INIT)
    {
      if (((*num_hnl) && pos+lls_length+size_rid >= max_pos) ||
          (!(*num_hnl) && pos+lls_length+size_tlv_head+size_rid >= max_pos))
      {
        zlog_warn ("Send HELLO: Buffer shortage on %s", oi->interface->name);
        break;
      }
#ifdef OSPF6_MANET_DIFF_HELLO
      if (!diff || (diff && on->changed_hsn + oi->HelloRepeatCount > oi->hsn))
#endif //OSPF6_MANET_DIFF_HELLO
      {
        memcpy (hnl, &on->router_id, size_rid);
        hnl += size_rid;
        (*num_hnl)++;
        hnl_length = size_tlv_head + size_rid*(*num_hnl);
      }
    }
    else
    {
      if (((*num_rnl) && pos+lls_length+size_rid >= max_pos) ||
          (!(*num_rnl) && pos+lls_length+size_tlv_head+size_rid >= max_pos))
      {
        zlog_warn ("Send HELLO: Buffer shortage on %s", oi->interface->name);
        break;
      }
#ifdef OSPF6_MANET_DIFF_HELLO
      // dependent neighbors are included in DNL and therefore
      // are not included in the RNL in a full Hello.
      if ((!diff && !on->dependent) ||
          (diff && (on->changed_hsn + oi->HelloRepeatCount > oi->hsn ||
           !on->reverse_2way)))
#endif //OSPF6_MANET_DIFF_HELLO
      {
        memcpy (rnl, &on->router_id, size_rid);
        rnl += size_rid;
        (*num_rnl)++;
        rnl_length = size_tlv_head + size_rid*(*num_rnl);
      }
    }
    // Create DNL
    if (oi->mdr_level >= OSPF6_BMDR)
    {
      if (on->dependent && on->state > OSPF6_NEIGHBOR_INIT)
      {
        memcpy (dnl, &on->router_id, size_rid);
        dnl += size_rid;
        (*num_dnl)++;
        dnl_length = size_tlv_head + size_rid*(*num_dnl);
      }
    }
    lls_length = lls_header + seq_tlv + hnl_length + rnl_length
                 + dnl_length;
  }

#ifdef OSPF6_MANET_DIFF_HELLO
  if (oi->lnl && diff)
  {
    struct ospf6_lnl_element *lnl_element;
    n = listhead(oi->lnl);
    while(n)
    {
      lnl_element = (struct ospf6_lnl_element *) getdata(n);
      nextnode(n);
  
      if (lnl_element->hsn + oi->HelloRepeatCount <= oi->hsn)
      {
        ospf6_mdr_delete_lnl_element(oi, lnl_element);
        continue;
      }

      if (((*num_lnl) && pos+lls_length+size_rid >= max_pos) ||
          (!(*num_lnl) && pos+lls_length+size_tlv_head+size_rid >= max_pos))
      {
        zlog_warn ("Send HELLO: Buffer shortage on %s", oi->interface->name);
        break;
      }
      memcpy (lnl, &lnl_element->id, size_rid);
      lnl += size_rid;
      (*num_lnl)++;
      lnl_length = size_tlv_head + size_rid*(*num_lnl);
    }
    lls_length = lls_header + seq_tlv + hnl_length + rnl_length + lnl_length
                            + dnl_length;
  }
#endif //OSPF6_MANET_DIFF_HELLO

  if (lls_length == sizeof(struct ospf6_LLS_header))
    return 0;
  return lls_length;
}

int ospf6_append_mdr_neigh_tlv(u_char *pos, u_int n, u_char *rid, 
                               u_int16_t type)
{
  struct ospf6_TLV_header tlv_header;
  if (n <= 0) 
    return 0;
  ospf6_tlv_header_assignment(&tlv_header, type, sizeof(u_int32_t) * n);
  memcpy(pos, &tlv_header, sizeof(struct ospf6_TLV_header));
  memcpy(pos + sizeof(struct ospf6_TLV_header), rid, sizeof(u_int32_t) * n);

  return (sizeof(struct ospf6_TLV_header) + sizeof(u_int32_t) * n); 
}

#ifdef OSPF6_MANET_DIFF_HELLO
int ospf6_append_mdr_seq_tlv(struct ospf6_interface *oi, u_char *pos)
{
  struct ospf6_TLV_header tlv_header;
  struct ospf6_seq_TLV seq_tlv;
  
  seq_tlv.number = htons(oi->hsn++);
  OSPF6_TLV_HS_OPT_CLEAR_ALL(seq_tlv.bits);
  ospf6_tlv_header_assignment(&tlv_header, OSPF6_TLV_TYPE_HS, 4);
  memcpy(pos, &tlv_header, sizeof(struct ospf6_TLV_header));


  memcpy(pos + sizeof(struct ospf6_TLV_header), &seq_tlv, sizeof(seq_tlv));

  return (sizeof(struct ospf6_TLV_header) + sizeof(seq_tlv));
}
#endif //OSPF6_MANET_DIFF_HELLO

boolean ospf6_mdr_process_hello_TLVs(struct ospf6_neighbor *on,
                                     struct ospf6_LLS_header *lls_ptr,
                                     boolean diff, boolean *rnl_changed)
{
  struct ospf6_interface *oi = on->ospf6_if;
  int length_lls = 0, tlv_val_len;
  boolean twoway = false;
  u_int  i, num_hnl=0, num_rnl=0, num_lnl=0;
  u_int num_dnl=0;
  struct ospf6_TLV_header *tlv_header = NULL;
#ifdef OSPF6_MANET_DIFF_HELLO
  struct ospf6_seq_TLV *seq_tlv = NULL;
  boolean insufficienthellosreceived = false;
  u_int16_t prev_seq=0;
#endif //OSPF6_MANET_DIFF_HELLO
  boolean in_rnl;
  struct listnode *n; 
  u_int32_t *nid; 
  u_int32_t *hnl = NULL;
  u_int32_t *rnl = NULL;
  u_int32_t *lnl = NULL;
  u_int32_t *dnl = NULL; // Added for Ogierv7.
  *rnl_changed = false;
#ifdef OSPF6_MANET_MDR_LQ
  boolean link_quality = false;
#endif //OSPF6_MANET_MDR_LQ

  length_lls =  ntohs(lls_ptr->len) * 4 - sizeof(struct ospf6_LLS_header);
  tlv_header = (struct ospf6_TLV_header *) (lls_ptr + 1);
  while (length_lls > 0)
  {
    tlv_val_len = ntohs(tlv_header->len);
    length_lls -= (sizeof(tlv_header) + tlv_val_len);
    switch (ntohs(tlv_header->type))
    {
      case OSPF6_TLV_TYPE_HNL:
      {
        assert(!hnl); //Malformed packet: 2 option TLVs
        hnl = (u_int32_t *) (tlv_header + 1);
        num_hnl = ntohs(tlv_header->len)/4;
        tlv_header = (struct ospf6_TLV_header *) (hnl + num_hnl);
        break;
      }
      case OSPF6_TLV_TYPE_RNL:
      {
        assert(!rnl); //Malformed packet: 2 option TLVs
        rnl = (u_int32_t *) (tlv_header + 1);
        num_rnl = ntohs(tlv_header->len)/4;
        tlv_header = (struct ospf6_TLV_header *) (rnl + num_rnl);
        break;
      }
      case OSPF6_TLV_TYPE_DNL: // Added for Ogierv7.
      {
        assert(!dnl); //Malformed packet: 2 option TLVs
        dnl = (u_int32_t *) (tlv_header + 1);
        num_dnl = ntohs(tlv_header->len)/4;
        tlv_header = (struct ospf6_TLV_header *) (dnl + num_dnl);
        break;
      }

#ifdef OSPF6_MANET_DIFF_HELLO
      case OSPF6_TLV_TYPE_LNL:
      {
        assert(!lnl); //Malformed packet: 2 option TLVs
        lnl = (u_int32_t *) (tlv_header + 1);
        num_lnl = ntohs(tlv_header->len)/4;
        tlv_header = (struct ospf6_TLV_header *) (lnl + num_lnl);
        break;
      }
     case OSPF6_TLV_TYPE_HS:
      {
        assert(!seq_tlv); //Malformed packet: 2 option TLVs
        seq_tlv = (struct ospf6_seq_TLV *) (tlv_header + 1);
        tlv_header = (struct ospf6_TLV_header *) (seq_tlv + 1);
        break;
      }
#endif //OSPF6_MANET_DIFF_HELLO
      default:
      {
        /* advance tlv_header pointer */
        tlv_header = (struct ospf6_TLV_header *)
          ((char *)tlv_header + (ntohs(tlv_header->len)+sizeof(tlv_header)));
        break;
      }
    }
  }

  // DNL list is always full whether or not Hello is differential.
  // If Hello does not contain DNL, then it has no dependent nbrs.
  on->dependent_selector = false;
  for (i = 0; i < num_dnl; i++)
    if (dnl[i] == oi->area->ospf6->router_id)
      on->dependent_selector = true;

#ifdef OSPF6_MANET_DIFF_HELLO
  if (seq_tlv)
  { 
    prev_seq = on->hsn;
    on->hsn = ntohs(seq_tlv->number);
  }

  //differential hello
  if (diff)
  {
    boolean found = false;
    if (!seq_tlv)
    {  //sequence #s should be found in all hellos when running diff hellos
      printf("Error:  seq_tlv should exist\n");
      exit(0);
    }

    if (on->state > OSPF6_NEIGHBOR_DOWN &&
        on->hsn > prev_seq + oi->HelloRepeatCount)
      insufficienthellosreceived = true; 

    //check hello LNL
    for (i = 0; i < num_lnl; i++)
    {
      if (!found && lnl[i] == oi->area->ospf6->router_id)
      {
        twoway = false;
        found = true;
        // reverse_2way keeps track of whether neighbor
        // considers me to be 2-way.
        on->reverse_2way = false;
        continue;
      }
      if (ospf6_mdr_delete_neighbor(on->rnl, lnl[i]))
          *rnl_changed = true;
    }
    //check hello HNL
    for (i = 0; i < num_hnl; i++)
    {
      if (!found && hnl[i] == oi->area->ospf6->router_id)
      {
        twoway = true;
        found = true;
        // Neighbor no longer considers me to be 2-way.
        // So let him know that I see him.
        if (on->reverse_2way)
        {
          on->reverse_2way = false;  //include neighbor in next hello
          //on->changed_hsn = oi->hsn; // Include neighbor in next few hellos.
        }
        continue;
      }
      if (ospf6_mdr_delete_neighbor(on->rnl, hnl[i]))
          *rnl_changed = true;
    }
    //check hello RNL
    for (i = 0; i < num_rnl; i++)
    {
      if (!found && rnl[i] == oi->area->ospf6->router_id)
      {
        twoway = true;
        found = true;
        on->reverse_2way = true;
#ifdef OSPF6_MANET_MDR_LQ
        link_quality = true;
#endif //OSPF6_MANET_MDR_LQ
        continue;
      }
      if (!ospf6_mdr_lookup_neighbor(on->rnl, rnl[i]))
      {
        ospf6_mdr_add_neighbor(on->rnl, rnl[i]);
        *rnl_changed = true;
      }
    }

    //keep same state - not found in any list
    // Insufficient hellos implies oneway if router does not find itself.
    if (!found && on->state >= OSPF6_NEIGHBOR_TWOWAY && 
        !insufficienthellosreceived)
    {
      twoway = true;
#ifdef OSPF6_MANET_MDR_LQ
      if(on->reverse_2way)
        link_quality = true;
#endif //OSPF6_MANET_MDR_LQ
    }

#ifdef OSPF6_MANET_MDR_LQ
    ospf6_mdr_update_link_quality(on, link_quality);
#endif //OSPF6_MANET_MDR_LQ
    return twoway;
  }
#endif //OSPF6_MANET_DIFF_HELLO

  //not a differential hello
  //this code is for the periodic full hello within diff hellos
  // RNL need not include any neighbor that is in DNL list,
  // so must check both lists.

  in_rnl = ospf6_is_rtrid_in_list(oi, rnl, num_rnl) ||
           ospf6_is_rtrid_in_list(oi, dnl, num_dnl);
  if (ospf6_is_rtrid_in_list(oi, hnl, num_hnl))
  {
    twoway = true;
    if (on->reverse_2way)
    {
      on->reverse_2way = false;  //include neighbor in next hello
      //on->changed_hsn = oi->hsn; // Include neighbor in next few hellos.
    }
  }
  else if (in_rnl)
  {
    twoway = true;
    on->reverse_2way = true;
#ifdef OSPF6_MANET_MDR_LQ
    link_quality = true;
#endif //OSPF6_MANET_MDR_LQ
  }
  else // not in any list of full hello
  {
    twoway = false;
    on->reverse_2way = false;
  }

  // Must compare old and new versions of on->rnl to determine
  // whether rnl changed. For speed, we require order to be the same.
  if (in_rnl && on->rnl->count == 0 && num_rnl == 1)
  {}
  else if (in_rnl && on->rnl->count != num_rnl-1)
    *rnl_changed = true;
  else if (!in_rnl && on->rnl->count == 0 && num_rnl == 0)
  {}
  else if (!in_rnl && on->rnl->count != num_rnl)
    *rnl_changed = true;
  else
  {
    for (i = 0; i < num_rnl; i++)
    {
      //must skip my own ID since it is not in the rnl list
      if (rnl[i] == oi->area->ospf6->router_id)
        continue;
      *rnl_changed = true;
      for (n = listhead(on->rnl); n; nextnode(n))
      {
        nid = (u_int32_t *) getdata(n);
        if (*nid == rnl[i])
        {
          *rnl_changed = false;
          break;
        }
      }
      if(*rnl_changed)
        break;
    }
  }

  ospf6_mdr_delete_all_neighbors(on->rnl);
  if (!on->Report2Hop)
  {
    on->Report2Hop = true; // full hello received
    *rnl_changed = true; // This affects CDS calculation.
  }
  for (i = 0; i < num_rnl; i++)
  {
    if (rnl[i] == oi->area->ospf6->router_id)
    {
      twoway = true;
      continue;
    }
    ospf6_mdr_add_neighbor(on->rnl, rnl[i]);
  }
  // Repeat for DNL list.
  // RNL is actually the union of the 2 lists.
  for (i = 0; i < num_dnl; i++)
  {
    if (dnl[i] == oi->area->ospf6->router_id)
    {
      twoway = true;
      continue;
    }
    // Add dependent nbr to RNL.
    ospf6_mdr_add_neighbor(on->rnl, dnl[i]);
  }
#ifdef OSPF6_MANET_MDR_LQ
  if(oi->diff_hellos)
    ospf6_mdr_update_link_quality(on, link_quality);
#endif //OSPF6_MANET_MDR_LQ
  return twoway;
}

int ospf6_append_mdr_tlv(struct ospf6_interface *oi, u_char *p)
{
  int data_size = 0;
  struct ospf6_TLV_header tlv_header;
  struct ospf6_mdr_TLV mdr_tlv;

  //find dr, bdr, or parents
  if (oi->mdr_level == OSPF6_MDR)
  {
    mdr_tlv.id1 = oi->area->ospf6->router_id;
    if (oi->parent)
      mdr_tlv.id2 = oi->parent->router_id;
    else
      mdr_tlv.id2 = 0;
  }
  else if (oi->mdr_level == OSPF6_BMDR)
  {
    mdr_tlv.id2 = oi->area->ospf6->router_id;
    if (oi->parent)
      mdr_tlv.id1 = oi->parent->router_id;
    else
      mdr_tlv.id1 = 0;
  }
  else 
  {
    mdr_tlv.id1 = (oi->parent ? oi->parent->router_id : 0);
    mdr_tlv.id2 = (oi->bparent ? oi->bparent->router_id : 0);
  }

  ospf6_tlv_header_assignment(&tlv_header, OSPF6_TLV_TYPE_DD, sizeof(mdr_tlv));
  data_size += sizeof(struct ospf6_TLV_header);
  memcpy(p, &tlv_header, sizeof(struct ospf6_TLV_header));

  data_size += sizeof(struct ospf6_mdr_TLV);
  memcpy(p + sizeof(struct ospf6_TLV_header), &mdr_tlv, sizeof(mdr_tlv));

  return data_size;
}

// Returns true if on->mdr_level changed.
boolean ospf6_mdr_process_mdr_TLVs(struct ospf6_neighbor *on,
                           struct ospf6_LLS_header *lls_ptr)
{
  int length_lls = 0, tlv_val_len;
  struct ospf6_TLV_header *tlv_header = NULL;
  struct ospf6_mdr_TLV *dd = NULL;
  boolean mdr_level_changed = false;

  length_lls =  ntohs(lls_ptr->len) * 4 - sizeof(struct ospf6_LLS_header);
  tlv_header = (struct ospf6_TLV_header *) (lls_ptr + 1);
  while (length_lls > 0)
  {
    tlv_val_len = ntohs(tlv_header->len);
    length_lls -= (sizeof(tlv_header) + tlv_val_len);
    switch (ntohs(tlv_header->type))
    {
      case OSPF6_TLV_TYPE_DD:
      {
        assert(!dd); //Malformed packet: 2 option TLVs
        dd = (struct ospf6_mdr_TLV *) (tlv_header + 1);
        tlv_header = (struct ospf6_TLV_header *) (dd+1);
        break;
      }
      default:
      {
        /* advance tlv_header pointer */
        tlv_header = (struct ospf6_TLV_header *)
          ((char *)tlv_header + (ntohs(tlv_header->len)+sizeof(tlv_header)));
        break;
      }
    }
  }
  if (dd)
  {
    mdr_level_changed = ospf6_mdr_set_mdr_level(on, dd->id1, dd->id2);
    if (on->mdr_level == OSPF6_MDR || on->mdr_level == OSPF6_BMDR)
      on->dependent_selector = 1;  // For need_adjacency().
  }
  return mdr_level_changed;
}
#endif // OSPF6_MANET_MDR_FLOOD


//################## PRINTING SECTION ########################
void ospf6_mhello_print (struct ospf6_header *oh, int len)
{
  ospf6_hello_print(oh);

#if defined(OSPF6_MANET_MPR_FLOOD) || defined (OSPF6_MANET_MDR_FLOOD)
{
  struct ospf6_hello *hello;
  struct ospf6_LLS_header * lls_ptr;
  struct ospf6_TLV_header *tlv_header;
  int seenrtrnum = 0, router_id_space = 0;
  u_int32_t *router_id_ptr;
  int length_lls = 0, tlv_len=0;

  hello = (struct ospf6_hello *)
    ((caddr_t) oh + sizeof (struct ospf6_header));

  /* set pointer positions */
  router_id_space = ntohs(oh->length) -
                    sizeof(struct ospf6_header) - sizeof(struct ospf6_hello);
  seenrtrnum = router_id_space / sizeof(u_int32_t);
  router_id_ptr = (u_int32_t *) (hello + 1);
  lls_ptr = (struct ospf6_LLS_header *) (router_id_ptr + seenrtrnum);

  /* process TLVs */
  /* set LLS pointer */
  if (!(OSPF6_OPT_ISSET(hello->options, OSPF6_OPT_L,1) && lls_ptr))
    return;
  if (ntohs(oh->length) >= len) 
    return;  //LLS flag lied that data exists beyond OSPF packet

  length_lls =  ntohs(lls_ptr->len) * 4 - sizeof(struct ospf6_LLS_header);
  tlv_header = (struct ospf6_TLV_header *) (lls_ptr + 1);

  while(length_lls)
  {
    print_tlv(tlv_header, true);
    tlv_len = sizeof(tlv_header) + ntohs(tlv_header->len);
    length_lls -= tlv_len;
    tlv_header = (struct ospf6_TLV_header *) ((char *) tlv_header + tlv_len);
  }
}
#endif //OSPF6_MANET_MPR_FLOOD || OSPF6_MANET_MDR_FLOOD
}

void print_tlv(struct ospf6_TLV_header *tlv_header, boolean log)
{
  int i;
  if (log)
    zlog_info("    TLV len:%d type:", ntohs(tlv_header->len));
  else
    printf(" TLV len:%d type:", ntohs(tlv_header->len));

  switch (ntohs(tlv_header->type))
  {
    case OSPF6_TLV_TYPE_OPTIONS:
    {
      struct ospf6_options_TLV *tlv_val_opt;
      tlv_val_opt = (struct ospf6_options_TLV *) (tlv_header + 1);
      if (log)
        zlog_info("     OPTIONS-%x %x %x %x", tlv_val_opt->options[0],
                  tlv_val_opt->options[1], tlv_val_opt->options[2],
                  tlv_val_opt->options[3]);
      else
        printf("OPTIONS-%x %x %x %x\n", tlv_val_opt->options[0],
               tlv_val_opt->options[1], tlv_val_opt->options[2],
               tlv_val_opt->options[3]);
      break;
    }
#ifdef OSPF6_MANET_DIFF_HELLO
    case OSPF6_TLV_TYPE_SCS:
    {
      struct ospf6_scs_TLV *tlv_val_scs;
      tlv_val_scs = (struct ospf6_scs_TLV *) (tlv_header + 1);
      if (log)
        zlog_info("     SCS-scs# %x, Bits R:%d, FS:%d, N:%d",
                  ntohs(tlv_val_scs->number),
      (OSPF6_TLV_SCS_OPT_ISSET(tlv_val_scs->bits, OSPF6_TLV_SCS_OPT_R, 0)?1:0),
      (OSPF6_TLV_SCS_OPT_ISSET(tlv_val_scs->bits, OSPF6_TLV_SCS_OPT_FS, 0)?1:0),
      (OSPF6_TLV_SCS_OPT_ISSET(tlv_val_scs->bits, OSPF6_TLV_SCS_OPT_N, 0)?1:0));
      else
        printf("SCS-scs# %x, Bits R:%d, FS:%d, N:%d\n",
               ntohs(tlv_val_scs->number),
      (OSPF6_TLV_SCS_OPT_ISSET(tlv_val_scs->bits, OSPF6_TLV_SCS_OPT_R, 0)?1:0),
      (OSPF6_TLV_SCS_OPT_ISSET(tlv_val_scs->bits, OSPF6_TLV_SCS_OPT_FS, 0)?1:0),
      (OSPF6_TLV_SCS_OPT_ISSET(tlv_val_scs->bits, OSPF6_TLV_SCS_OPT_N, 0)?1:0));
      break;
    }
    case OSPF6_TLV_TYPE_NEIGHDROP:
    {
      u_int32_t *tlv_val_drop = NULL;
      tlv_val_drop = (u_int32_t*) (tlv_header + 1);
      if (log)
      {
        zlog_info("     NEIGHDROP-");
        for (i = 0; i < ntohs(tlv_header->len)/4; i++)
          zlog_info("       %s,",ip2str(tlv_val_drop[i]));
      }
      else
      {
        printf("    NEIGHDROP-");
        for (i = 0; i < ntohs(tlv_header->len)/4; i++)
          printf("%s,",ip2str(tlv_val_drop[i]));
        printf("\n");
      }
      break; 
    }
    case OSPF6_TLV_TYPE_REQUEST:
    {
      u_int32_t *tlv_val_req = NULL;
      tlv_val_req = (u_int32_t*) (tlv_header + 1);
      if (log)
      {
        zlog_info("     REQUEST-");
        for (i = 0; i < ntohs(tlv_header->len)/4; i++)
          zlog_info("       %s,",ip2str(tlv_val_req[i]));
      }
      else
      {
        printf("    REQUEST-");
        for (i = 0; i < ntohs(tlv_header->len)/4; i++)
          printf("%s,",ip2str(tlv_val_req[i]));
        printf("\n");
      }
      break; 
    }
    case OSPF6_TLV_TYPE_FULL:
    {
      u_int32_t *tlv_val_full = NULL;
      tlv_val_full = (u_int32_t*) (tlv_header + 1);
      if (log)
      {
        zlog_info("     FULL-");
        for (i = 0; i < ntohs(tlv_header->len)/4; i++)
          zlog_info("       %s,",ip2str(tlv_val_full[i]));
      }
      else
      {
        printf("    FULL-");
        for (i = 0; i < ntohs(tlv_header->len)/4; i++)
          printf("%s,",ip2str(tlv_val_full[i]));
        printf("\n");
      }
      break; 
    }
#endif //OSPF6_MANET_DIFF_HELLO
#ifdef OSPF6_MANET_MPR_FLOOD
    case OSPF6_TLV_TYPE_RELAY:
    {
    struct ospf6_relay_TLV *tlv_val_relay;
    u_int32_t *relay_id_ptr;

    tlv_val_relay = (struct ospf6_relay_TLV*) (tlv_header + 1);
    relay_id_ptr = (u_int32_t *) (tlv_val_relay + 1);

    if (log)
    {
     zlog_info("     RELAY-added:%d ", tlv_val_relay->added);
     for (i = 0; i < ntohs(tlv_header->len)/4-1; i++)
      zlog_info("       %s,",ip2str(relay_id_ptr[i]));
    }
    else
    {
     printf("RELAY-added:%d ", tlv_val_relay->added);
     for (i = 0; i < ntohs(tlv_header->len)/4-1; i++)
      printf("%s,",ip2str(relay_id_ptr[i]));
     printf("\n");
    }
    break;
   }
  case OSPF6_TLV_TYPE_WILLINGNESS:
      {
        struct ospf6_will_TLV *tlv_val_will;
    tlv_val_will = (struct ospf6_will_TLV*) (tlv_header + 1);
    if (log)
     zlog_info("     WILLINGNESS-%d", tlv_val_will->will);
    else
     printf("WILLINGNESS-%d\n", tlv_val_will->will);
        break;
      }
#endif //OSPF6_MANET_MPR_FLOOD
#ifdef OSPF6_MANET_MDR_FLOOD
    case OSPF6_TLV_TYPE_HNL:
    {
      u_int32_t *tlv_val_hnl = NULL;
      tlv_val_hnl = (u_int32_t*) (tlv_header + 1);
      if (log)
      {
        zlog_info("     HNL-");
        for (i = 0; i < ntohs(tlv_header->len)/4; i++)
          zlog_info("       %s,",ip2str(tlv_val_hnl[i]));
      }
      else
      {
        printf("    HNL-");
        for (i = 0; i < ntohs(tlv_header->len)/4; i++)
          printf("%s,",ip2str(tlv_val_hnl[i]));
        printf("\n");
      }
      break;
    }
    case OSPF6_TLV_TYPE_RNL:
    {
      u_int32_t *tlv_val_rnl = NULL;
      tlv_val_rnl = (u_int32_t*) (tlv_header + 1);
      if (log)
      {
        zlog_info("     RNL-");
        for (i = 0; i < ntohs(tlv_header->len)/4; i++)
          zlog_info("       %s,",ip2str(tlv_val_rnl[i]));
      }
      else
      {
        printf("    RNL-");
        for (i = 0; i < ntohs(tlv_header->len)/4; i++)
          printf("%s,",ip2str(tlv_val_rnl[i]));
        printf("\n");
      }
      break;
    }
    case OSPF6_TLV_TYPE_LNL:
    {
      u_int32_t *tlv_val_lnl = NULL;
      tlv_val_lnl = (u_int32_t*) (tlv_header + 1);
      if (log)
      {
        zlog_info("     LNL-");
        for (i = 0; i < ntohs(tlv_header->len)/4; i++)
          zlog_info("       %s,",ip2str(tlv_val_lnl[i]));
      }
      else
      {
        printf("    LNL-");
        for (i = 0; i < ntohs(tlv_header->len)/4; i++)
          printf("%s,",ip2str(tlv_val_lnl[i]));
        printf("\n");
      }
      break;
    }
    case OSPF6_TLV_TYPE_DD:
    {
      struct ospf6_mdr_TLV *mdr_tlv;
      mdr_tlv = (struct ospf6_mdr_TLV *) (tlv_header + 1);
      if (log)
      {
        zlog_info("     DD-ID1 %s", ip2str(mdr_tlv->id1));
        zlog_info("     DD-ID2 %s", ip2str(mdr_tlv->id2));
      }
      else
      {
        printf("DD-ID1 %s ", ip2str(mdr_tlv->id1));
        printf("%s\n", ip2str(mdr_tlv->id2));
      }
      break;
    }
#ifdef OSPF6_MANET_DIFF_HELLO
    case OSPF6_TLV_TYPE_HS:
    {
      struct ospf6_seq_TLV *seq_tlv;
      seq_tlv = (struct ospf6_seq_TLV *) (tlv_header + 1);
      if (log)
        zlog_info("     SEQ-# %x", ntohs(seq_tlv->number));
      else
        printf("SEQ-# %x\n", ntohs(seq_tlv->number));
      break;
    }
#endif //OSPF6_MANET_DIFF_HELLO
#endif //OSPF6_MANET_MDR_FLOOD
    default:
    {
      if (log)
        zlog_info("     %d", ntohs(tlv_header->type));
      else
        printf("%d\n", ntohs(tlv_header->type));
      break;
    }
  }
}

//################## END PRINTING SECTION ########################
#endif //OSPF6_MANET

#ifdef USER_CHECKSUM

u_int16_t ospf6_do_checksum(struct in6_addr *saddr, struct in6_addr *daddr,struct ospf6_header *hdr)
{
   pseudo_header ph;
   u_int16_t checksum;
   unsigned long sum = 0;
   int count;
   unsigned short *p; /* 16-bit */

               memset(&ph, 0, sizeof(pseudo_header));
               memcpy(&ph.src, saddr, sizeof(struct in6_addr));
               memcpy(&ph.dst, daddr, sizeof(struct in6_addr));
               ph.upper_len = hdr->length;
               ph.nh = IPPROTO_OSPFIGP;



        count = sizeof(ph); /* count always even number */
        p = (unsigned short*) &ph;

	/* sum the psuedo-header */
	/* count and p are initialized above per protocol */
	while (count > 1) {
		sum += *p++;
		count -= 2;
	}
    
	/* one's complement sum 16-bit words of data */
	count = ntohs(hdr->length);
	p = (unsigned short*) hdr;
	while (count > 1)  {
		sum += *p++;
		count -= 2;
	}
	/* add left-over byte, if any */
	if (count > 0)
		sum += (unsigned char)*p;
 
	/*  Fold 32-bit sum to 16 bits */
	while (sum>>16)
		sum = (sum & 0xffff) + (sum >> 16);
	/* take the one's complement of the sum */ 
	checksum = ~sum;
    
	return(checksum);
}


#endif


