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

#include "log.h"
#include "thread.h"
#include "linklist.h"
#include "vty.h"
#include "command.h"

#include "ospf6d.h"
#include "ospf6_proto.h"
#include "ospf6_lsa.h"
#include "ospf6_lsdb.h"
#include "ospf6_message.h"
#include "ospf6_route.h"
#include "ospf6_spf.h"

#include "ospf6_top.h"
#include "ospf6_area.h"
#include "ospf6_interface.h"
#include "ospf6_neighbor.h"

#include "ospf6_flood.h"
#ifdef SIM
#include "sim.h"
#include "ospf6_sim_printing.h"
#endif //SIM
#if defined(OSPF6_MANET) || defined(BUGFIX)
#include "ospf6d.h" //for settime()
#endif //OSPF6_MANET || BUGFIX
#ifdef OSPF6_MANET_MPR_FLOOD
#include "ospf6_mpr.h"
#endif //OSPF6_MANET_MPR_FLOOD
#ifdef OSPF6_MANET_MDR_FLOOD
#include "ospf6_mdr.h"
#endif //OSPF6_MANET_MDR_FLOOD

unsigned char conf_debug_ospf6_flooding;

struct ospf6_lsdb *
ospf6_get_scoped_lsdb (struct ospf6_lsa *lsa)
{
  struct ospf6_lsdb *lsdb = NULL;
  switch (OSPF6_LSA_SCOPE (lsa->header->type))
    {
    case OSPF6_SCOPE_LINKLOCAL:
      lsdb = OSPF6_INTERFACE (lsa->lsdb->data)->lsdb;
      break;
    case OSPF6_SCOPE_AREA:
      lsdb = OSPF6_AREA (lsa->lsdb->data)->lsdb;
      break;
    case OSPF6_SCOPE_AS:
      lsdb = OSPF6_PROCESS (lsa->lsdb->data)->lsdb;
      break;
    default:
      assert (0);
      break;
    }
  return lsdb;
}

struct ospf6_lsdb *
ospf6_get_scoped_lsdb_self (struct ospf6_lsa *lsa)
{
  struct ospf6_lsdb *lsdb_self = NULL;
  switch (OSPF6_LSA_SCOPE (lsa->header->type))
    {
    case OSPF6_SCOPE_LINKLOCAL:
      lsdb_self = OSPF6_INTERFACE (lsa->lsdb->data)->lsdb_self;
      break;
    case OSPF6_SCOPE_AREA:
      lsdb_self = OSPF6_AREA (lsa->lsdb->data)->lsdb_self;
      break;
    case OSPF6_SCOPE_AS:
      lsdb_self = OSPF6_PROCESS (lsa->lsdb->data)->lsdb_self;
      break;
    default:
      assert (0);
      break;
    }
  return lsdb_self;
}

void
ospf6_lsa_originate (struct ospf6_lsa *lsa)
{
  struct ospf6_lsa *old;
  struct ospf6_lsdb *lsdb_self;

  /* find previous LSA */
  old = ospf6_lsdb_lookup (lsa->header->type, lsa->header->id,
                           lsa->header->adv_router, lsa->lsdb);

  /* if the new LSA does not differ from previous,
     suppress this update of the LSA */
  if (old && ! OSPF6_LSA_IS_DIFFER (lsa, old))
    {
      if (IS_OSPF6_DEBUG_ORIGINATE_TYPE (lsa->header->type))
        zlog_debug ("Suppress updating LSA: %s", lsa->name);
      ospf6_lsa_delete (lsa);
      return;
    }

#ifdef BUGFIX
  set_time(&lsa->originated);
#endif //BUGFIX

#ifdef SIM //ETRACE
  char id[16], adv_router[16];
  inet_ntop (AF_INET, &lsa->header->id, id, sizeof (id));
  inet_ntop (AF_INET, &lsa->header->adv_router, adv_router,sizeof (adv_router));
  TraceEvent_sim(2,"Orig LSA %s -id %s -advrt %s -age %d -seq %lu -len %d",
                 ospf6_lstype_name(lsa->header->type), id, adv_router,
                 ntohs(age_mask(lsa->header)), ntohl(lsa->header->seqnum),
                 ntohs(lsa->header->length));
#endif //ETRACE

  /* store it in the LSDB for self-originated LSAs */
  lsdb_self = ospf6_get_scoped_lsdb_self (lsa);
  ospf6_lsdb_add (ospf6_lsa_copy (lsa), lsdb_self);
#ifdef OSPF6_CONFIG
  if (IS_OSPF6_DEBUG_DATABASE (DATABASE_DETAIL))
    ospf6_debug_lsdb_show(OSPF6_DEBUG_DATABASE_DETAIL, lsdb_self);
  else if (IS_OSPF6_DEBUG_DATABASE (DATABASE))
    ospf6_debug_lsdb_show(OSPF6_DEBUG_DATABASE, lsdb_self);
#endif //OSPF6_CONFIG


  lsa->refresh = thread_add_timer (master, ospf6_lsa_refresh, lsa,
                                   LS_REFRESH_TIME);

  if (IS_OSPF6_DEBUG_LSA_TYPE (lsa->header->type) ||
      IS_OSPF6_DEBUG_ORIGINATE_TYPE (lsa->header->type))
    {
      zlog_debug ("LSA Originate:");
      ospf6_lsa_header_print (lsa);
    }

  if (old)
    ospf6_flood_clear (old);
  ospf6_flood (NULL, lsa);
  ospf6_install_lsa (lsa);
}

void
ospf6_lsa_originate_process (struct ospf6_lsa *lsa,
                             struct ospf6 *process)
{
  lsa->lsdb = process->lsdb;
  ospf6_lsa_originate (lsa);
}

void
ospf6_lsa_originate_area (struct ospf6_lsa *lsa,
                          struct ospf6_area *oa)
{
  lsa->lsdb = oa->lsdb;
  ospf6_lsa_originate (lsa);
}

void
ospf6_lsa_originate_interface (struct ospf6_lsa *lsa,
                               struct ospf6_interface *oi)
{
  lsa->lsdb = oi->lsdb;
  ospf6_lsa_originate (lsa);
}

void
ospf6_lsa_purge (struct ospf6_lsa *lsa)
{
  struct ospf6_lsa *self;
  struct ospf6_lsdb *lsdb_self;

  /* remove it from the LSDB for self-originated LSAs */
  lsdb_self = ospf6_get_scoped_lsdb_self (lsa);
  self = ospf6_lsdb_lookup (lsa->header->type, lsa->header->id,
                            lsa->header->adv_router, lsdb_self);
  if (self)
    {
      THREAD_OFF (self->expire);
      THREAD_OFF (self->refresh);
      ospf6_lsdb_remove (self, lsdb_self);
    }

  ospf6_lsa_premature_aging (lsa);
}


void
ospf6_increment_retrans_count (struct ospf6_lsa *lsa)
{
  /* The LSA must be the original one (see the description
     in ospf6_decrement_retrans_count () below) */
  lsa->retrans_count++;
}

void
ospf6_decrement_retrans_count (struct ospf6_lsa *lsa)
{
  struct ospf6_lsdb *lsdb;
  struct ospf6_lsa *orig;

  /* The LSA must be on the retrans-list of a neighbor. It means
     the "lsa" is a copied one, and we have to decrement the
     retransmission count of the original one (instead of this "lsa"'s).
     In order to find the original LSA, first we have to find
     appropriate LSDB that have the original LSA. */
  lsdb = ospf6_get_scoped_lsdb (lsa);

  /* Find the original LSA of which the retrans_count should be decremented */
  orig = ospf6_lsdb_lookup (lsa->header->type, lsa->header->id,
                            lsa->header->adv_router, lsdb);
  if (orig)
    {
      orig->retrans_count--;
      assert (orig->retrans_count >= 0);
    }
}

/* RFC2328 section 13.2 Installing LSAs in the database */
void
ospf6_install_lsa (struct ospf6_lsa *lsa)
{
  struct ospf6_lsa *old;
  struct timeval now;

  if (IS_OSPF6_DEBUG_LSA_TYPE (lsa->header->type) ||
      IS_OSPF6_DEBUG_EXAMIN_TYPE (lsa->header->type))
    zlog_debug ("Install LSA: %s", lsa->name);

  /* Remove the old instance from all neighbors' Link state
     retransmission list (RFC2328 13.2 last paragraph) */
#ifdef OSPF6_MANET_TEMPORARY_LSDB
  if (lsa->cache == 1)  //XXX what should be done with old
    old = ospf6_lsdb_lookup_cache (lsa->header->type, lsa->header->id,
                                   lsa->header->adv_router, lsa->lsdb);
  else
  {
    old = ospf6_lsdb_lookup (lsa->header->type, lsa->header->id,
                             lsa->header->adv_router, lsa->lsdb);
    if (old)
    {
      THREAD_OFF (old->expire);
      ospf6_flood_clear (old);
    }
  }
#else
  old = ospf6_lsdb_lookup (lsa->header->type, lsa->header->id,
                           lsa->header->adv_router, lsa->lsdb);
  if (old)
    {
      THREAD_OFF (old->expire);
      ospf6_flood_clear (old);
    }
#endif //OSPF6_MANET_TEMPORARY_LSDB

#ifdef SIM
  gettimeofday_sim (&now, (struct timezone *) NULL);
#else
  gettimeofday (&now, (struct timezone *) NULL);
#endif //SIM

  if (! OSPF6_LSA_IS_MAXAGE (lsa))
    lsa->expire = thread_add_timer (master, ospf6_lsa_expire, lsa,
                                    MAXAGE + lsa->birth.tv_sec - now.tv_sec);
  else
    lsa->expire = NULL;

  /* actually install */
  lsa->installed = now;
  ospf6_lsdb_add (lsa, lsa->lsdb);

#ifdef SIM_ETRACE_STAT
  if (ntohs(lsa->header->type) == OSPF6_LSTYPE_ROUTER)
  {
    update_statistics(OSPF6_ROUTER_LSA_INSTALL, 1);
    update_statistics(OSPF6_ROUTER_LSA_HOPCOUNT, hopcount_mask(lsa->header)>>4);
  }
#endif //SIM_ETRACE_STAT

#ifdef OSPF6_CONFIG
  if (IS_OSPF6_DEBUG_DATABASE (DATABASE_DETAIL))
    ospf6_debug_lsdb_show(OSPF6_DEBUG_DATABASE_DETAIL, lsa->lsdb);
  else if (IS_OSPF6_DEBUG_DATABASE (DATABASE))
    ospf6_debug_lsdb_show(OSPF6_DEBUG_DATABASE, lsa->lsdb);
#endif //OSPF6_CONFIG

#ifdef OSPF6_MANET_TEMPORARY_LSDB
  if (lsa->cache == 1)
    return;
#endif //OSPF6_MANET_TEMPORARY_LSDB

#ifdef OSPF6_MANET_MPR_FLOOD
{
// Chandra03 3.4.2 paragraph 1
// If you get a new LSA, update your 2hop neighbor list accordingly
  
  struct ospf6_neighbor *on;
  struct listnode *i;
  struct ospf6_interface *oi;
  struct interface *ifp;

  if (lsa->header->type == htons(OSPF6_LSTYPE_ROUTER))
  {
    for (i = listhead(iflist); i; nextnode(i))
    {
      ifp = (struct interface *) getdata (i);
      oi = (struct ospf6_interface *) ifp->info;
      if (!oi || oi->type != OSPF6_IFTYPE_MANETRELIABLE || 
          oi->flooding != OSPF6_FLOOD_MPR_SDCDS)
        continue;
      on = ospf6_neighbor_lookup(lsa->header->adv_router, oi);
      if (on)
        update_2hop_neighbor_list(on, lsa->header); 
    }
  }
}
#endif //OSPF6_MANET_MPR_FLOOD
  return;
}

#ifdef OSPF6_MANET_MPR_FLOOD
//Chandra03 3.4.8
void
ospf6_flood_interface_mpr (struct ospf6_neighbor *from,
                       struct ospf6_lsa *lsa, struct ospf6_interface *oi)
{
  struct listnode *node;
  struct ospf6_neighbor *on;
  struct ospf6_lsa *req;
  int retrans_added = 0;
  int is_debug = 0;
  struct ospf6_mack *mack;
  boolean flood_lsa = true;
 
#ifdef SIM_ETRACE_STAT
  boolean suppressed_flood = false;
#endif //SIM_ETRACE_STAT

  /* Determine whether the originator of the LSA ("from") is an MPR selector*/
  //Chandra03 3.4.8 paragraph 2 condition 1
  if (from != NULL && 
#ifndef CISCO_INTEROP
      from->Fbit && 
#endif //CISCO_INTEROP
      !from->Relay_Abit &&
      !ospf6_lookup_relay_selector(oi, from->router_id))
    flood_lsa = false;

  if (IS_OSPF6_DEBUG_FLOODING ||
      IS_OSPF6_DEBUG_FLOOD_TYPE (lsa->header->type))
  {
    is_debug++;
    zlog_debug ("Flooding on %s: %s", oi->interface->name, lsa->name);
  }

  /* (1) For each neighbor */
  for (node = listhead (oi->neighbor_list); node; nextnode (node))
  {
    on = (struct ospf6_neighbor *) getdata (node);

    if (is_debug)
      zlog_debug ("To neighbor %s", on->name);

    /* (a) if neighbor state < Exchange, examine next */
    if (on->state < OSPF6_NEIGHBOR_EXCHANGE)
    {
      if (is_debug)
        zlog_debug ("Neighbor state less than ExChange, next neighbor");
        continue;
    }

    /* (b) if neighbor not yet Full, check request-list */
    if (on->state != OSPF6_NEIGHBOR_FULL)
    {
      if (is_debug)
        zlog_debug ("Neighbor not yet Full");

        req = ospf6_lsdb_lookup (lsa->header->type, lsa->header->id,
                                   lsa->header->adv_router, on->request_list);
        if (req == NULL)
        {
          if (is_debug)
            zlog_debug ("Not on request-list for this neighbor");
            /* fall through */
          }
        else
        {
          /* If new LSA less recent, examin next neighbor */
          if (ospf6_lsa_compare (lsa, req) > 0)
          {
            if (is_debug)
              zlog_debug ("Requesting is newer, next neighbor");
            continue;
          }

          /* If the same instance, delete from request-list and
             examin next neighbor */
          if (ospf6_lsa_compare (lsa, req) == 0)
          {
            if (is_debug)
              zlog_debug ("Requesting the same, remove it, next neighbor");
            ospf6_lsdb_remove (req, on->request_list);
            continue;
          }
          
          /* If the new LSA is more recent, delete from request-list */
          if (ospf6_lsa_compare (lsa, req) < 0)
          {
            if (is_debug)
              zlog_debug ("Received is newer, remove requesting");
            ospf6_lsdb_remove (req, on->request_list);
            /* fall through */
          }
        }
      }

      /* (c) If the new LSA was received from this neighbor,
         examin next neighbor */
      if (from == on)
      {
        if (is_debug)
          zlog_debug ("Received is from the neighbor, next neighbor");
        continue;
      }

      /* At this point, we are not positive that the neighbor has
         an up-to-date instance of this new LSA */
      /* However, in the MANET case, we need to:
         i) check whether neighbor sent a multicast ACK for it already
         ii) whether I am an active relay for this originator */
      /* Has LSA been acked previously with multicast ack? */
      mack = ospf6_lookup_mack(on, lsa->header);
      //Chandra03 3.4.9 paragraph 1 condition 2
      if (oi->type == OSPF6_IFTYPE_MANETRELIABLE && mack)
      { //Don't add LSA to neighbor's retransmission list
        continue; // examine next neighbor: neighbor already acked
      }

      /* check if this is a flooding node.  Must check here due to request
       * list deletion above */
      if (!flood_lsa)
      {
#ifdef SIM_ETRACE_STAT
        suppressed_flood = true; /*Flag that transmission was suppressed*/
#endif //SIM_ETRACE_STAT
        /* Add this neighbor (on) to the list of neighbors for which
           LSA is stored on pushback list for possible retransmission */
        ospf6_pushback_lsa_add(lsa, on);
        continue; 
      }

      /* (d) add retrans-list, schedule retransmission */
      if (is_debug)
        zlog_debug ("Add retrans-list of this neighbor");
      ospf6_increment_retrans_count (lsa);
#ifdef OSPF6_DELAYED_FLOOD
      set_time(&lsa->rxmt_time);
      ospf6_lsdb_add (ospf6_lsa_copy (lsa), on->retrans_list);
      on->thread_send_lsupdate =
        ospf6_send_lsupdate_delayed_msec(master, ospf6_lsupdate_send_neighbor, 
          on, oi->rxmt_interval*1000, on->thread_send_lsupdate);
#else
      //thread_add_timer must be used for delayed events
      ospf6_lsdb_add (ospf6_lsa_copy (lsa), on->retrans_list);
      if (on->thread_send_lsupdate == NULL)
        on->thread_send_lsupdate =
          thread_add_timer (master, ospf6_lsupdate_send_neighbor,
                            on, on->ospf6_if->rxmt_interval);
#endif // OSPF6_DELAYED_FLOOD
      retrans_added++;
    }

#ifdef SIM_ETRACE_STAT 
    /* At this point, I have cycled through all neighbors on this i/f */
    if(suppressed_flood)
    {
      char id[16], adv_router[16];
      inet_ntop (AF_INET, &lsa->header->id, id, sizeof (id));
      inet_ntop (AF_INET, &lsa->header->adv_router, adv_router,
                 sizeof (adv_router));
      TraceEvent_sim(2,"Suppress Flood LSA %s -id %s -advrt %s -age %d -seq %lu -len %d from %s",
                     ospf6_lstype_name(lsa->header->type), id, adv_router,
                     ntohs(age_mask(lsa->header)), ntohl(lsa->header->seqnum),
                     ntohs(lsa->header->length), from->name);
#ifdef SIM
      ospf6_print_pushback_list_sim(lsa);
#endif //SIM
      update_statistics(OSPF6_LSA_FLOOD_SUPPRESS, 1);
    }
#endif //SIM_ETRACE_STAT

  /* (2) examin next interface if not added to retrans-list */
  if (retrans_added == 0)
    {
      if (is_debug)
        zlog_debug ("No retransmission scheduled, next interface");
      return;
    }

  /* (3) If the new LSA was received on this interface,
     and it was from DR or BDR, examin next interface */
  if (from && from->ospf6_if == oi &&
      (from->router_id == oi->drouter || from->router_id == oi->bdrouter))
    {
      if (is_debug)
        zlog_debug ("Received is from the I/F's DR or BDR, next interface");
      return;
    }

  /* (4) If the new LSA was received on this interface,
     and the interface state is BDR, examin next interface */
  if (from && from->ospf6_if == oi && oi->state == OSPF6_INTERFACE_BDR)
    {
      if (is_debug)
        zlog_debug ("Received is from the I/F, itself BDR, next interface");
      return;
    }
    
    //Chandra03 3.4.9 paragraph 1 condition 3
    if (from && from->ospf6_if == oi)
      SET_FLAG (lsa->flag, OSPF6_LSA_FLOODBACK);

  /* (5) flood the LSA out the interface. */
  if (is_debug)
    zlog_debug ("Schedule flooding for the interface");
  ospf6_lsdb_add (ospf6_lsa_copy (lsa), oi->lsupdate_list);

#ifdef SIM_ETRACE_STAT
  char id[16], adv_router[16];
  inet_ntop (AF_INET, &lsa->header->id, id, sizeof (id));
  inet_ntop (AF_INET,&lsa->header->adv_router,adv_router,sizeof (adv_router));    TraceEvent_sim(2,"Schedule Flood LSA %s -id %s -advrt %s -age %d -seq %lu -len %d from %s",
                   ospf6_lstype_name(lsa->header->type), id, adv_router,
                   ntohs(age_mask(lsa->header)), ntohl(lsa->header->seqnum),
                   ntohs(lsa->header->length), from->name);
  update_statistics(OSPF6_LSA_FLOOD_RELAY, 1);
#endif //SIM_ETRACE_STAT 

#ifdef OSPF6_DELAYED_FLOOD
  oi->thread_send_lsupdate = 
    ospf6_send_lsupdate_delayed_msec(master, ospf6_lsupdate_send_interface, 
                                     oi, oi->flood_delay, 
                                     oi->thread_send_lsupdate);
#else
  if (oi->thread_send_lsupdate == NULL)
    oi->thread_send_lsupdate =
      thread_add_event (master, ospf6_lsupdate_send_interface, oi, 0);
#endif //OSPF6_DELAYED_FLOOD
}
#endif //OSPF6_MANET_MPR_FLOOD

#ifdef OSPF6_MANET_MDR_FLOOD
void
ospf6_flood_interface_mdr (struct ospf6_neighbor *from,
                       struct ospf6_lsa *lsa, struct ospf6_interface *oi)
{
  struct listnode *node;
  struct ospf6_neighbor *on;
  struct ospf6_lsa *req;
  int retrans_added = 0;
  int is_debug = 0;
  struct ospf6_mack *mack;
  struct list *flood_neighbors = list_new();
  boolean flood_lsa = true;

  if (IS_OSPF6_DEBUG_FLOODING ||
      IS_OSPF6_DEBUG_FLOOD_TYPE (lsa->header->type))
  {
    is_debug++;
    zlog_debug ("Flooding on %s: %s", oi->interface->name, lsa->name);
  }

  /* (1) For each neighbor */
  for (node = listhead (oi->neighbor_list); node; nextnode (node))
  {
    on = (struct ospf6_neighbor *) getdata (node);

    if (is_debug)
      zlog_debug ("To neighbor %s", on->name);

    /* (a) if neighbor state < Exchange, examin next */
    // Consider adjacent and (backup) dependent neighbors.
    // RGO. Change for version 05, require all bidirectional neighbors
    // to be covered
    //if (on->state < OSPF6_NEIGHBOR_EXCHANGE
    //    && !on->dependent && !on->bdependent)
    if (on->state < OSPF6_NEIGHBOR_TWOWAY)
    {
      if (is_debug)
        zlog_debug ("Neighbor state less than TwoWay, next neighbor");
        continue;
    }

    /* (b) if neighbor not yet Full, check request-list */
    if (on->state >= OSPF6_NEIGHBOR_EXCHANGE && on->state != OSPF6_NEIGHBOR_FULL)
    {
      if (is_debug)
        zlog_debug ("Neighbor not yet Full");

        req = ospf6_lsdb_lookup (lsa->header->type, lsa->header->id,
                                   lsa->header->adv_router, on->request_list);
        if (req == NULL)
        {
          if (is_debug)
            zlog_debug ("Not on request-list for this neighbor");
            /* fall through */
          }
        else
        {
          /* If new LSA less recent, examin next neighbor */
          if (ospf6_lsa_compare (lsa, req) > 0)
          {
            if (is_debug)
              zlog_debug ("Requesting is newer, next neighbor");
            continue;
          }

          /* If the same instance, delete from request-list and
             examin next neighbor */
          if (ospf6_lsa_compare (lsa, req) == 0)
          {
            if (is_debug)
              zlog_debug ("Requesting the same, remove it, next neighbor");
            ospf6_lsdb_remove (req, on->request_list);
            continue;
          }
          
          /* If the new LSA is more recent, delete from request-list */
          if (ospf6_lsa_compare (lsa, req) < 0)
          {
            if (is_debug)
              zlog_debug ("Received is newer, remove requesting");
            ospf6_lsdb_remove (req, on->request_list);
            /* fall through */
          }
        }
      }

      /* (c) If the new LSA was received from this neighbor,
         examin next neighbor */
      if (from == on)
      {
        if (is_debug)
          zlog_debug ("Received is from the neighbor, next neighbor");
        continue;
      }

      //Ogierv3 Section 6 Par 3
      /* At this point, we are not positive that the neighbor has
         an up-to-date instance of this new LSA */
      /* However, in the MANET case, we need to:
         i) check whether neighbor sent a multicast ACK for it already
         ii) whether I am an active relay for this originator */
      /* Has LSA been acked previously with multicast ack? */
      mack = ospf6_lookup_mack(on, lsa->header);
      if (oi->type == OSPF6_IFTYPE_MANETRELIABLE && mack)
      { //Don't add LSA to neighbor's retransmission list
        continue; // examine next neighbor: neighbor already acked
      }
      /* Here, checking for coverage of this neighbor on the sender's RNL.
         If not present, I add this to the flood_neighbors list.
         If LSA was received as a unicast, however, can't assume that
         neighbor "on" was covered by the transmission, so still need to
         add to flood_neighbors regardless of from->rnl*/
      if (from)
        if (!from->Report2Hop || 
            (!CHECK_FLAG (lsa->flag, OSPF6_LSA_RECVMCAST)) ||
            !ospf6_mdr_lookup_neighbor(from->rnl, on->router_id))
          listnode_add(flood_neighbors, on);

      // Retransmit only to adjacent neighbors.
      if (on->state < OSPF6_NEIGHBOR_EXCHANGE) 
        continue;

      /* (d) add retrans-list, schedule retransmission */
      if (is_debug)
        zlog_debug ("Add retrans-list of this neighbor");
      ospf6_increment_retrans_count (lsa);

#ifdef OSPF6_DELAYED_FLOOD
      set_time(&lsa->rxmt_time);
      ospf6_lsdb_add (ospf6_lsa_copy (lsa), on->retrans_list);
      on->thread_send_lsupdate =
        ospf6_send_lsupdate_delayed_msec(master, ospf6_lsupdate_send_neighbor, 
          on, oi->rxmt_interval*1000, on->thread_send_lsupdate);
#else
      //thread_add_timer must be used for delayed events
      ospf6_lsdb_add (ospf6_lsa_copy (lsa), on->retrans_list);
      if (on->thread_send_lsupdate == NULL)
        on->thread_send_lsupdate =
          thread_add_timer (master, ospf6_lsupdate_send_neighbor,
                            on, oi->rxmt_interval);
#endif // OSPF6_DELAYED_FLOOD
      retrans_added++;

    }

  /* (2) examin next interface if not added to retrans-list */
  /*
    if (retrans_added == 0)
    {
      if (is_debug)
        zlog_debug ("No retransmission scheduled, next interface");
      list_delete (flood_neighbors);
      return;
    }
  */

  //Ogierv3 Section 6 - Remove (3) and (4)

  //Ogierv3 Section 6 - Replace (5)  
  //Ogierv3 Forwarding Procedure bullet(a)
  if (from && oi->mdr_level == OSPF6_MDR)
  {
    if (flood_neighbors->count == 0)
      flood_lsa = false;
  }
  
  //Ogierv3 Forwarding Procedure bullet(c)
  if (from && oi->mdr_level == OSPF6_BMDR)
  {
    for (node = listhead(flood_neighbors); node; nextnode (node))
    {
      on = (struct ospf6_neighbor *) getdata (node);
      ospf6_pushback_lsa_add(lsa, on);
    }
    flood_lsa = false;
  }

  if (from && oi->mdr_level == OSPF6_OTHER)
  {
    //OTHER routers do not flood
    flood_lsa = false;
  }
  list_delete (flood_neighbors);

  if (!flood_lsa)
  {
#ifdef SIM_ETRACE_STAT
    char id[16], adv_router[16];
    inet_ntop (AF_INET, &lsa->header->id, id, sizeof (id));
    inet_ntop (AF_INET, &lsa->header->adv_router, adv_router,
               sizeof (adv_router));
    TraceEvent_sim(2,"Suppress Flood LSA %s -id %s -advrt %s -age %d -seq %lu -len %d from %s",
                   ospf6_lstype_name(lsa->header->type), id, adv_router,
                   ntohs(age_mask(lsa->header)), ntohl(lsa->header->seqnum),
                   ntohs(lsa->header->length), from->name);
#ifdef SIM
    ospf6_print_pushback_list_sim(lsa);
#endif //SIM
    update_statistics(OSPF6_LSA_FLOOD_SUPPRESS, 1);
#endif //SIM_ETRACE_STAT
    return;
  }

  if (from && from->ospf6_if == oi)
    SET_FLAG (lsa->flag, OSPF6_LSA_FLOODBACK);

  /* (5) flood the LSA out the interface. */
  if (is_debug)
    zlog_debug ("Schedule flooding for the interface");

#ifdef SIM_ETRACE_STAT
  char id[16], adv_router[16];
  inet_ntop (AF_INET, &lsa->header->id, id, sizeof (id));
  inet_ntop (AF_INET,&lsa->header->adv_router,adv_router,sizeof (adv_router));
  TraceEvent_sim(2,"Schedule Flood LSA %s -id %s -advrt %s -age %d -seq %lu -len %d from %s",
                 ospf6_lstype_name(lsa->header->type), id, adv_router,
                 ntohs(age_mask(lsa->header)), ntohl(lsa->header->seqnum),
                 ntohs(lsa->header->length), from->name);
  update_statistics(OSPF6_LSA_FLOOD_RELAY, 1);
#endif //SIM_ETRACE_STAT

  ospf6_lsdb_add (ospf6_lsa_copy (lsa), oi->lsupdate_list);
#ifdef OSPF6_DELAYED_FLOOD
  oi->thread_send_lsupdate = 
      ospf6_send_lsupdate_delayed_msec(master, ospf6_lsupdate_send_interface, 
                                       oi, oi->flood_delay, 
                                       oi->thread_send_lsupdate);
#else
  if (oi->thread_send_lsupdate == NULL)
    oi->thread_send_lsupdate =
        thread_add_event (master, ospf6_lsupdate_send_interface, oi, 0);
#endif //OSPF6_DELAYED_FLOOD
}
#endif //OSPF6_MANET_MDR_FLOOD

/* RFC2740 section 3.5.2. Sending Link State Update packets */
/* RFC2328 section 13.3 Next step in the flooding procedure */
void
ospf6_flood_interface (struct ospf6_neighbor *from,
                       struct ospf6_lsa *lsa, struct ospf6_interface *oi)
{
  struct listnode *node;
  struct ospf6_neighbor *on;
  struct ospf6_lsa *req;
  int retrans_added = 0;
  int is_debug = 0;
 
#ifdef OSPF6_CONFIG
  if (oi->type == OSPF6_IFTYPE_LOOPBACK)
    return;
#endif //OSPF6_CONFIG

#ifdef OSPF6_MANET
  if (oi->type == OSPF6_IFTYPE_MANETRELIABLE)
  {
#ifdef OSPF6_MANET_MPR_FLOOD
    if (oi->flooding == OSPF6_FLOOD_MPR_SDCDS)
    {
      ospf6_flood_interface_mpr(from, lsa, oi);
      return; 
    }
#endif //OSPF6_MANET_MPR_FLOOD
#ifdef OSPF6_MANET_MDR_FLOOD
    if (oi->flooding == OSPF6_FLOOD_MDR_SICDS)
    {
      ospf6_flood_interface_mdr(from, lsa, oi);
      return; 
    }
#endif //OSPF6_MANET_MDR_FLOOD
  }
#endif //OSPF6_MANET

  if (IS_OSPF6_DEBUG_FLOODING ||
      IS_OSPF6_DEBUG_FLOOD_TYPE (lsa->header->type))
  {
    is_debug++;
    zlog_debug ("Flooding on %s: %s", oi->interface->name, lsa->name);
  }

  /* (1) For each neighbor */
  for (node = listhead (oi->neighbor_list); node; nextnode (node))
  {
    on = (struct ospf6_neighbor *) getdata (node);

    if (is_debug)
      zlog_debug ("To neighbor %s", on->name);

    /* (a) if neighbor state < Exchange, examin next */
    if (on->state < OSPF6_NEIGHBOR_EXCHANGE)
    {
      if (is_debug)
        zlog_debug ("Neighbor state less than ExChange, next neighbor");
        continue;
    }

    /* (b) if neighbor not yet Full, check request-list */
    if (on->state != OSPF6_NEIGHBOR_FULL)
    {
      if (is_debug)
        zlog_debug ("Neighbor not yet Full");

        req = ospf6_lsdb_lookup (lsa->header->type, lsa->header->id,
                                   lsa->header->adv_router, on->request_list);
        if (req == NULL)
        {
          if (is_debug)
            zlog_debug ("Not on request-list for this neighbor");
            /* fall through */
          }
        else
        {
          /* If new LSA less recent, examin next neighbor */
          if (ospf6_lsa_compare (lsa, req) > 0)
          {
            if (is_debug)
              zlog_debug ("Requesting is newer, next neighbor");
            continue;
          }

          /* If the same instance, delete from request-list and
             examin next neighbor */
          if (ospf6_lsa_compare (lsa, req) == 0)
          {
            if (is_debug)
              zlog_debug ("Requesting the same, remove it, next neighbor");
            ospf6_lsdb_remove (req, on->request_list);
            continue;
          }
          
          /* If the new LSA is more recent, delete from request-list */
          if (ospf6_lsa_compare (lsa, req) < 0)
          {
            if (is_debug)
              zlog_debug ("Received is newer, remove requesting");
            ospf6_lsdb_remove (req, on->request_list);
            /* fall through */
          }
        }
      }

      /* (c) If the new LSA was received from this neighbor,
         examin next neighbor */
      if (from == on)
      {
        if (is_debug)
          zlog_debug ("Received is from the neighbor, next neighbor");
        continue;
      }

      /* (d) add retrans-list, schedule retransmission */
      if (is_debug)
        zlog_debug ("Add retrans-list of this neighbor");
      ospf6_increment_retrans_count (lsa);
#ifdef OSPF6_DELAYED_FLOOD
      set_time(&lsa->rxmt_time);
      ospf6_lsdb_add (ospf6_lsa_copy (lsa), on->retrans_list);
      on->thread_send_lsupdate =
        ospf6_send_lsupdate_delayed_msec(master, ospf6_lsupdate_send_neighbor, 
          on, oi->rxmt_interval*1000, on->thread_send_lsupdate);
#elif BUGFIX
      //thread_add_timer must be used for delayed events
      ospf6_lsdb_add (ospf6_lsa_copy (lsa), on->retrans_list);
      if (on->thread_send_lsupdate == NULL)
        on->thread_send_lsupdate =
          thread_add_timer (master, ospf6_lsupdate_send_neighbor,
                            on, on->ospf6_if->rxmt_interval);
#else
      ospf6_lsdb_add (ospf6_lsa_copy (lsa), on->retrans_list);
      if (on->thread_send_lsupdate == NULL)
        on->thread_send_lsupdate =
          thread_add_event (master, ospf6_lsupdate_send_neighbor,
                            on, on->ospf6_if->rxmt_interval);
#endif // OSPF6_DELAYED_FLOOD  and BUGFIX
      retrans_added++;
    }

  /* (2) examin next interface if not added to retrans-list */
  if (retrans_added == 0)
    {
      if (is_debug)
        zlog_debug ("No retransmission scheduled, next interface");
      return;
    }

  /* (3) If the new LSA was received on this interface,
     and it was from DR or BDR, examin next interface */
  if (from && from->ospf6_if == oi &&
      (from->router_id == oi->drouter || from->router_id == oi->bdrouter))
    {
      if (is_debug)
        zlog_debug ("Received is from the I/F's DR or BDR, next interface");
      return;
    }

  /* (4) If the new LSA was received on this interface,
     and the interface state is BDR, examin next interface */
  if (from && from->ospf6_if == oi && oi->state == OSPF6_INTERFACE_BDR)
    {
      if (is_debug)
        zlog_debug ("Received is from the I/F, itself BDR, next interface");
      return;
    }

#ifdef BUGFIX
    if (from && from->ospf6_if == oi)
      SET_FLAG (lsa->flag, OSPF6_LSA_FLOODBACK);
#endif //BUGFIX

  /* (5) flood the LSA out the interface. */
  if (is_debug)
    zlog_debug ("Schedule flooding for the interface");

#ifdef SIM_ETRACE_STAT
  char id[16], adv_router[16];
  inet_ntop (AF_INET, &lsa->header->id, id, sizeof (id));
  inet_ntop (AF_INET,&lsa->header->adv_router,adv_router,sizeof (adv_router));    TraceEvent_sim(2,"Schedule Flood LSA %s -id %s -advrt %s -age %d -seq %lu -len %d from %s",
                   ospf6_lstype_name(lsa->header->type), id, adv_router,
                   ntohs(age_mask(lsa->header)), ntohl(lsa->header->seqnum),
                   ntohs(lsa->header->length), from->name);
  update_statistics(OSPF6_LSA_FLOOD_RELAY, 1);
#endif //SIM_ETRACE_STAT 

#ifdef OSPF6_CONFIG
  if (oi->type == OSPF6_IFTYPE_BROADCAST ||
      oi->type == OSPF6_IFTYPE_MANETRELIABLE ||
      oi->type == OSPF6_IFTYPE_POINTOMULTIPOINT ||
      oi->type == OSPF6_IFTYPE_NBMA)
#else
  if (if_is_broadcast (oi->interface))
#endif //OSPF6_CONFIG
  {
    ospf6_lsdb_add (ospf6_lsa_copy (lsa), oi->lsupdate_list);
#ifdef OSPF6_DELAYED_FLOOD
    oi->thread_send_lsupdate = 
      ospf6_send_lsupdate_delayed_msec(master, ospf6_lsupdate_send_interface, 
                                       oi, oi->flood_delay, 
                                       oi->thread_send_lsupdate);
#else
    if (oi->thread_send_lsupdate == NULL)
      oi->thread_send_lsupdate =
        thread_add_event (master, ospf6_lsupdate_send_interface, oi, 0);
#endif //OSPF6_DELAYED_FLOOD
  }
  else
  {
    /* reschedule retransmissions to all neighbors */
    for (node = listhead (oi->neighbor_list); node; nextnode (node))
    {
      on = (struct ospf6_neighbor *) getdata (node);
#ifdef OSPF6_DELAYED_FLOOD
       on->thread_send_lsupdate =
         ospf6_send_lsupdate_delayed_msec(master, ospf6_lsupdate_send_neighbor,
                                          on, oi->flood_delay, 
                                          on->thread_send_lsupdate);
#else
      THREAD_OFF (on->thread_send_lsupdate);
      on->thread_send_lsupdate =
        thread_add_event (master, ospf6_lsupdate_send_neighbor, on, 0);
#endif //OSPF6_DELAYED_FLOOD
    }
  }
}

void
ospf6_flood_area (struct ospf6_neighbor *from,
                  struct ospf6_lsa *lsa, struct ospf6_area *oa)
{
  struct listnode *node;
  struct ospf6_interface *oi;

  for (node = listhead (oa->if_list); node; nextnode (node))
    {
      oi = OSPF6_INTERFACE (getdata (node));

      if (OSPF6_LSA_SCOPE (lsa->header->type) == OSPF6_SCOPE_LINKLOCAL &&
          oi != OSPF6_INTERFACE (lsa->lsdb->data))
        continue;

#if 0
      if (OSPF6_LSA_SCOPE (lsa->header->type) == OSPF6_SCOPE_AS &&
          ospf6_is_interface_virtual_link (oi))
        continue;
#endif/*0*/

      ospf6_flood_interface (from, lsa, oi);
    }
}

void
ospf6_flood_process (struct ospf6_neighbor *from,
                     struct ospf6_lsa *lsa, struct ospf6 *process)
{
  struct listnode *node;
  struct ospf6_area *oa;

  for (node = listhead (process->area_list); node; nextnode (node))
    {
      oa = OSPF6_AREA (getdata (node));

      if (OSPF6_LSA_SCOPE (lsa->header->type) == OSPF6_SCOPE_AREA &&
          oa != OSPF6_AREA (lsa->lsdb->data))
        continue;
      if (OSPF6_LSA_SCOPE (lsa->header->type) == OSPF6_SCOPE_LINKLOCAL &&
          oa != OSPF6_INTERFACE (lsa->lsdb->data)->area)
        continue;

      if (ntohs (lsa->header->type) == OSPF6_LSTYPE_AS_EXTERNAL &&
          IS_AREA_STUB (oa))
        continue;

      ospf6_flood_area (from, lsa, oa);
    }
}

void
ospf6_flood (struct ospf6_neighbor *from, struct ospf6_lsa *lsa)
{
  ospf6_flood_process (from, lsa, ospf6);
}

void
ospf6_flood_clear_interface (struct ospf6_lsa *lsa, struct ospf6_interface *oi)
{
  struct listnode *node;
  struct ospf6_neighbor *on;
  struct ospf6_lsa *rem;
#ifdef OSPF6_DELAYED_FLOOD
  struct ospf6_lsa *update;
#endif //OSPF6_DELAYED_FLOOD

  for (node = listhead (oi->neighbor_list); node; nextnode (node))
    {
      on = OSPF6_NEIGHBOR (getdata (node));
      rem = ospf6_lsdb_lookup (lsa->header->type, lsa->header->id,
                               lsa->header->adv_router, on->retrans_list);
      if (rem && ! ospf6_lsa_compare (rem, lsa))
        {
          if (IS_OSPF6_DEBUG_FLOODING ||
              IS_OSPF6_DEBUG_FLOOD_TYPE (lsa->header->type))
            zlog_debug ("Remove %s from retrans_list of %s",
                       rem->name, on->name);
          ospf6_decrement_retrans_count (rem);
          ospf6_lsdb_remove (rem, on->retrans_list);
        }
#ifdef OSPF6_DELAYED_FLOOD
      //remove stale LSA from neighbor update list
      update = ospf6_lsdb_lookup (lsa->header->type, lsa->header->id,
                                  lsa->header->adv_router, on->lsupdate_list);
      if (update && ospf6_lsa_compare (update, lsa) == 0)
      {//update is a stale lsa
        if (IS_OSPF6_DEBUG_FLOODING)
          zlog_info ("Remove %s from neighbor lsupdate_list of %s",
                     update->name, on->name);
        ospf6_lsdb_remove (update, on->lsupdate_list);
      }
#endif //OSPF6_DELAYED_FLOOD
    }
}

void
ospf6_flood_clear_area (struct ospf6_lsa *lsa, struct ospf6_area *oa)
{
  struct listnode *node;
  struct ospf6_interface *oi;
#ifdef OSPF6_DELAYED_FLOOD
  struct ospf6_lsa *update;
#endif //OSPF6_DELAYED_FLOOD

  for (node = listhead (oa->if_list); node; nextnode (node))
    {
      oi = OSPF6_INTERFACE (getdata (node));

      if (OSPF6_LSA_SCOPE (lsa->header->type) == OSPF6_SCOPE_LINKLOCAL &&
          oi != OSPF6_INTERFACE (lsa->lsdb->data))
        continue;

#if 0
      if (OSPF6_LSA_SCOPE (lsa->header->type) == OSPF6_SCOPE_AS &&
          ospf6_is_interface_virtual_link (oi))
        continue;
#endif/*0*/

    ospf6_flood_clear_interface (lsa, oi);
#ifdef OSPF6_DELAYED_FLOOD
      //remove stale LSA from interface update list
      update = ospf6_lsdb_lookup (lsa->header->type, lsa->header->id,
      lsa->header->adv_router, oi->lsupdate_list);
      if (update && ospf6_lsa_compare (update, lsa) == 0)
      { //update is a stale lsa
        if (IS_OSPF6_DEBUG_FLOODING)
          zlog_info ("Remove %s from interface lsupdate_list", update->name);
        ospf6_lsdb_remove (update, oi->lsupdate_list);
      }
#endif //OSPF6_DELAYED_FLOOD
    }
}

void
ospf6_flood_clear_process (struct ospf6_lsa *lsa, struct ospf6 *process)
{
  struct listnode *node;
  struct ospf6_area *oa;

  for (node = listhead (process->area_list); node; nextnode (node))
    {
      oa = OSPF6_AREA (getdata (node));

      if (OSPF6_LSA_SCOPE (lsa->header->type) == OSPF6_SCOPE_AREA &&
          oa != OSPF6_AREA (lsa->lsdb->data))
        continue;
      if (OSPF6_LSA_SCOPE (lsa->header->type) == OSPF6_SCOPE_LINKLOCAL &&
          oa != OSPF6_INTERFACE (lsa->lsdb->data)->area)
        continue;

      if (ntohs (lsa->header->type) == OSPF6_LSTYPE_AS_EXTERNAL &&
          IS_AREA_STUB (oa))
        continue;

      ospf6_flood_clear_area (lsa, oa);
    }
}

void
ospf6_flood_clear (struct ospf6_lsa *lsa)
{
#ifdef OSPF6_DELAYED_FLOOD
  ospf6_pushback_lsa_delete(lsa);
#endif //OSPF6_DELAYED_FLOOD
  ospf6_flood_clear_process (lsa, ospf6);
}


/* RFC2328 13.5 (Table 19): Sending link state acknowledgements. */
static void
ospf6_acknowledge_lsa_bdrouter (struct ospf6_lsa *lsa, int ismore_recent,
                                struct ospf6_neighbor *from)
{
  struct ospf6_interface *oi;
  int is_debug = 0;

  if (IS_OSPF6_DEBUG_FLOODING ||
      IS_OSPF6_DEBUG_FLOOD_TYPE (lsa->header->type))
    is_debug++;

  assert (from && from->ospf6_if);
  oi = from->ospf6_if;

  /* LSA has been flood back out receiving interface.
     No acknowledgement sent. */
  if (CHECK_FLAG (lsa->flag, OSPF6_LSA_FLOODBACK))
    {
      if (is_debug)
        zlog_debug ("No acknowledgement (BDR & FloodBack)");
      return;
    }

  /* LSA is more recent than database copy, but was not flooded
     back out receiving interface. Delayed acknowledgement sent
     if advertisement received from Designated Router,
     otherwide do nothing. */
  if (ismore_recent < 0)
    {
      if (oi->drouter == from->router_id)
        {
          if (is_debug)
            zlog_debug ("Delayed acknowledgement (BDR & MoreRecent & from DR)");
          /* Delayed acknowledgement */
          ospf6_lsdb_add (ospf6_lsa_copy (lsa), oi->lsack_list);
          if (oi->thread_send_lsack == NULL)
#ifdef OSPF6_MANET
          {
            // Remove "3" magic number -- send ACK after ackInterval
            if (oi->type == OSPF6_IFTYPE_MANETRELIABLE)
              //Chandra03 3.4.9 paragraph 1 condition 1
              oi->thread_send_lsack =
                thread_add_timer_msec (master, ospf6_lsack_send_interface,
                                       oi, oi->ackInterval);
            else
              oi->thread_send_lsack =
                thread_add_timer (master, ospf6_lsack_send_interface, oi, 3);
          }
#else 
            oi->thread_send_lsack =
              thread_add_timer (master, ospf6_lsack_send_interface, oi, 3);
#endif //OSPF6_MANET
        }
      else
        {
          if (is_debug)
            zlog_debug ("No acknowledgement (BDR & MoreRecent & ! from DR)");
        }
      return;
    }

  /* LSA is a duplicate, and was treated as an implied acknowledgement.
     Delayed acknowledgement sent if advertisement received from
     Designated Router, otherwise do nothing */
  if (CHECK_FLAG (lsa->flag, OSPF6_LSA_DUPLICATE) &&
      CHECK_FLAG (lsa->flag, OSPF6_LSA_IMPLIEDACK))
    {
      if (oi->drouter == from->router_id)
        {
          if (is_debug)
            zlog_debug ("Delayed acknowledgement (BDR & Duplicate & ImpliedAck & from DR)");
          /* Delayed acknowledgement */
          ospf6_lsdb_add (ospf6_lsa_copy (lsa), oi->lsack_list);
          if (oi->thread_send_lsack == NULL)
#ifdef OSPF6_MANET
          {
            // Remove "3" magic number -- send ACK after ackInterval
            if (oi->type == OSPF6_IFTYPE_MANETRELIABLE)
              //Chandra03 3.4.9 paragraph 1 condition 1
              oi->thread_send_lsack =
                thread_add_timer_msec (master, ospf6_lsack_send_interface,
                                       oi, oi->ackInterval);
            else
              oi->thread_send_lsack =
                thread_add_timer (master, ospf6_lsack_send_interface, oi, 3);
          }
#else
            oi->thread_send_lsack =
              thread_add_timer (master, ospf6_lsack_send_interface, oi, 3);
#endif //OSPF6_MANET
        }
      else
        {
          if (is_debug)
            zlog_debug ("No acknowledgement (BDR & Duplicate & ImpliedAck & ! from DR)");
        }
      return;
    }

  /* LSA is a duplicate, and was not treated as an implied acknowledgement.
     Direct acknowledgement sent */
  if (CHECK_FLAG (lsa->flag, OSPF6_LSA_DUPLICATE) &&
      ! CHECK_FLAG (lsa->flag, OSPF6_LSA_IMPLIEDACK))
    {
      if (is_debug)
        zlog_debug ("Direct acknowledgement (BDR & Duplicate)");
#ifdef OSPF6_MANET
      // This is implementing multicast ACK
      /// Delay by ackInterval for coalescing ACKs
      if (oi->type == OSPF6_IFTYPE_MANETRELIABLE)
      {
        ospf6_lsdb_add (ospf6_lsa_copy (lsa), oi->lsack_list);
        if (oi->thread_send_lsack == NULL)
          //Chandra03 3.4.9 paragraph 1 condition 1
          oi->thread_send_lsack =
            thread_add_timer_msec (master, ospf6_lsack_send_interface,
                                   oi, oi->ackInterval);
      }
      else
      {
        ospf6_lsdb_add (ospf6_lsa_copy (lsa), from->lsack_list);
        if (from->thread_send_lsack == NULL)
          from->thread_send_lsack =
            thread_add_event (master, ospf6_lsack_send_neighbor, from, 0);
      }
#else
      ospf6_lsdb_add (ospf6_lsa_copy (lsa), from->lsack_list);
      if (from->thread_send_lsack == NULL)
        from->thread_send_lsack =
          thread_add_event (master, ospf6_lsack_send_neighbor, from, 0);
#endif //OSPF6_MANET
      return;
    }

  /* LSA's LS age is equal to Maxage, and there is no current instance
     of the LSA in the link state database, and none of router's
     neighbors are in states Exchange or Loading */
  /* Direct acknowledgement sent, but this case is handled in
     early of ospf6_receive_lsa () */
}

static void
#ifdef OSPF6_MANET
ospf6_acknowledge_lsa_allother (struct ospf6_lsa *lsa, int ismore_recent,
                                struct ospf6_neighbor *from,
                                struct in6_addr *dst)
#else
ospf6_acknowledge_lsa_allother (struct ospf6_lsa *lsa, int ismore_recent,
                                struct ospf6_neighbor *from)
#endif //OSPF6_MANET
{
  struct ospf6_interface *oi;
  int is_debug = 0;

  if (IS_OSPF6_DEBUG_FLOODING ||
      IS_OSPF6_DEBUG_FLOOD_TYPE (lsa->header->type))
    is_debug++;

  assert (from && from->ospf6_if);
  oi = from->ospf6_if;

  /* LSA has been flood back out receiving interface.
     No acknowledgement sent. */
  if (CHECK_FLAG (lsa->flag, OSPF6_LSA_FLOODBACK))
    {
      if (is_debug)
        zlog_debug ("No acknowledgement (AllOther & FloodBack)");
      return;
    }

  /* LSA is more recent than database copy, but was not flooded
     back out receiving interface. Delayed acknowledgement sent. */
  if (ismore_recent < 0)
    {
      if (is_debug)
        zlog_debug ("Delayed acknowledgement (AllOther & MoreRecent)");
      /* Delayed acknowledgement */
      ospf6_lsdb_add (ospf6_lsa_copy (lsa), oi->lsack_list);
      if (oi->thread_send_lsack == NULL)
#ifdef OSPF6_MANET
      {
        // Remove "3" magic number -- send ACK after ackInterval
        if (oi->type == OSPF6_IFTYPE_MANETRELIABLE)
          //Chandra03 3.4.9 paragraph 1 condition 1
          oi->thread_send_lsack =
            thread_add_timer_msec (master, ospf6_lsack_send_interface,
                                   oi, oi->ackInterval);
        else
          oi->thread_send_lsack =
            thread_add_timer (master, ospf6_lsack_send_interface, oi, 3);
      }
#else
        oi->thread_send_lsack =
          thread_add_timer (master, ospf6_lsack_send_interface, oi, 3);
#endif //OSPF6_MANET
      return;
    }

  /* LSA is a duplicate, and was treated as an implied acknowledgement.
     No acknowledgement sent. */
  if (CHECK_FLAG (lsa->flag, OSPF6_LSA_DUPLICATE) &&
      CHECK_FLAG (lsa->flag, OSPF6_LSA_IMPLIEDACK))
    {
      if (is_debug)
        zlog_debug ("No acknowledgement (AllOther & Duplicate & ImpliedAck)");
      return;
    }

  /* LSA is a duplicate, and was not treated as an implied acknowledgement.
     Direct acknowledgement sent */
  if (CHECK_FLAG (lsa->flag, OSPF6_LSA_DUPLICATE) &&
      ! CHECK_FLAG (lsa->flag, OSPF6_LSA_IMPLIEDACK))
    {
#ifdef OSPF6_MANET
      //Chandra03 3.4.9 paragraph 1 condition 3
      //only acknowledge the first arrival of the lsa
      if(oi->type==OSPF6_IFTYPE_MANETRELIABLE && IN6_IS_ADDR_MULTICAST(dst))
      {
        return;  //NO ACK
      }
#endif //OSPF6_MANET


      if (is_debug)
        zlog_debug ("Direct acknowledgement (AllOther & Duplicate)");

#ifdef OSPF6_MANET
      // Send multicast ACK after waiting for ackInterval to coalesce ACKs
      // Chandra03 3.4.8.3 paragraph 2 condition 3
      if (oi->type == OSPF6_IFTYPE_MANETRELIABLE)
      {
        ospf6_lsdb_add (ospf6_lsa_copy (lsa), oi->lsack_list);
#ifdef OSPF6_MANET_MDR_FLOOD
        // SICDS sends a multicast ACK immediately if router
        // is MDR/BMDR, or if full adjacencies are used.
        if (oi->flooding == OSPF6_FLOOD_MDR_SICDS &&
            (oi->AdjConnectivity == OSPF6_ADJ_FULLYCONNECTED ||
             oi->mdr_level == OSPF6_MDR || oi->mdr_level == OSPF6_BMDR))
        {
          if (oi->thread_send_lsack)
            THREAD_OFF(oi->thread_send_lsack);
          oi->thread_send_lsack =
            thread_add_timer_msec (master, ospf6_lsack_send_interface,
                                   oi, 0);
        }
        else
#endif //OSPF6_MANET_MDR_FLOOD
        if (oi->thread_send_lsack == NULL)
          //Chandra03 3.4.9 paragraph 1 condition 1
          //Chandra03 3.4.9 paragraph 1 condition 7
          oi->thread_send_lsack =
            thread_add_timer_msec (master, ospf6_lsack_send_interface,
                                   oi, oi->ackInterval);
      }
      else
      {
        ospf6_lsdb_add (ospf6_lsa_copy (lsa), from->lsack_list);
        if (from->thread_send_lsack == NULL)
          from->thread_send_lsack =
            thread_add_event (master, ospf6_lsack_send_neighbor, from, 0);
      }
#else
      ospf6_lsdb_add (ospf6_lsa_copy (lsa), from->lsack_list);
      if (from->thread_send_lsack == NULL)
        from->thread_send_lsack =
          thread_add_event (master, ospf6_lsack_send_neighbor, from, 0);
#endif //OSPF6_MANET
      return;
    }

  /* LSA's LS age is equal to Maxage, and there is no current instance
     of the LSA in the link state database, and none of router's
     neighbors are in states Exchange or Loading */
  /* Direct acknowledgement sent, but this case is handled in
     early of ospf6_receive_lsa () */
}

void
#ifdef OSPF6_MANET
ospf6_acknowledge_lsa (struct ospf6_lsa *lsa, int ismore_recent,
                       struct ospf6_neighbor *from, struct in6_addr *dst)
#else
ospf6_acknowledge_lsa (struct ospf6_lsa *lsa, int ismore_recent,
                       struct ospf6_neighbor *from)
#endif //OSPF6_MANET
{
  struct ospf6_interface *oi;

  assert (from && from->ospf6_if);
  oi = from->ospf6_if;

  if (oi->state == OSPF6_INTERFACE_BDR)
    ospf6_acknowledge_lsa_bdrouter (lsa, ismore_recent, from);
  else
#ifdef OSPF6_MANET
    ospf6_acknowledge_lsa_allother (lsa, ismore_recent, from, dst);
#else
    ospf6_acknowledge_lsa_allother (lsa, ismore_recent, from);
#endif //OSPF6_MANET
}

/* RFC2328 section 13 (4):
   if MaxAge LSA and if we have no instance, and no neighbor
   is in states Exchange or Loading
   returns 1 if match this case, else returns 0 */
static int
ospf6_is_maxage_lsa_drop (struct ospf6_lsa *lsa, struct ospf6_neighbor *from)
{
  struct ospf6_neighbor *on;
  struct ospf6_interface *oi;
  struct ospf6_area *oa;
  struct ospf6 *process = NULL;
  struct listnode *i, *j, *k;
  int count = 0;

  if (! OSPF6_LSA_IS_MAXAGE (lsa))
    return 0;

  if (ospf6_lsdb_lookup (lsa->header->type, lsa->header->id,
                         lsa->header->adv_router, lsa->lsdb))
    return 0;

  process = from->ospf6_if->area->ospf6;
  for (i = listhead (process->area_list); i; nextnode (i))
    {
      oa = OSPF6_AREA (getdata (i));
      for (j = listhead (oa->if_list); j; nextnode (j))
        {
          oi = OSPF6_INTERFACE (getdata (j));
          for (k = listhead (oi->neighbor_list); k; nextnode (k))
            {
              on = OSPF6_NEIGHBOR (getdata (k));
              if (on->state == OSPF6_NEIGHBOR_EXCHANGE ||
                  on->state == OSPF6_NEIGHBOR_LOADING)
                count++;
            }
        }
    }

  if (count == 0)
    return 1;
  return 0;
}

/* RFC2328 section 13 The Flooding Procedure */
void
#ifdef OSPF6_MANET
ospf6_receive_lsa (struct ospf6_lsa_header *lsa_header,
                   struct ospf6_neighbor *from,
                   struct in6_addr *dst)
#else
ospf6_receive_lsa (struct ospf6_neighbor *from,
                   struct ospf6_lsa_header *lsa_header)
#endif //OSPF6_MANET
{
  struct ospf6_lsa *new_ = NULL, *old = NULL, *rem = NULL;
  int ismore_recent;
  unsigned short cksum;
  int is_debug = 0;

  ismore_recent = 1;
  assert (from);

  /* make lsa structure for received lsa */
  new_ = ospf6_lsa_create (lsa_header);

  if (IS_OSPF6_DEBUG_FLOODING ||
      IS_OSPF6_DEBUG_FLOOD_TYPE (new_->header->type))
    {
      is_debug++;
      zlog_debug ("LSA Receive from %s", from->name);
      ospf6_lsa_header_print (new_);
    }

  /* (1) LSA Checksum */
  cksum = ntohs (new_->header->checksum);
  if (ntohs (ospf6_lsa_checksum (new_->header)) != cksum)
    {
      if (is_debug)
        zlog_debug ("Wrong LSA Checksum, discard");
      ospf6_lsa_delete (new_);
      return;
    }

  /* (2) Examine the LSA's LS type. 
  if (IS_AREA_STUB (from->ospf6_if->area) &&
      OSPF6_LSA_SCOPE (new_->header->type) == OSPF6_SCOPE_AS)
    {
      if (is_debug)
        zlog_debug ("AS-External-LSA (or AS-scope LSA) in stub area, discard");
      ospf6_lsa_delete (new_);
      return;
    }

  /* (3) LSA which have reserved scope is discarded
     RFC2470 3.5.1. Receiving Link State Update packets  */
  /* Flooding scope check. LSAs with unknown scope are discarded here.
     Set appropriate LSDB for the LSA */
  switch (OSPF6_LSA_SCOPE (new_->header->type))
    {
    case OSPF6_SCOPE_LINKLOCAL:
      new_->lsdb = from->ospf6_if->lsdb;
      break;
    case OSPF6_SCOPE_AREA:
      new_->lsdb = from->ospf6_if->area->lsdb;
      break;
    case OSPF6_SCOPE_AS:
      new_->lsdb = from->ospf6_if->area->ospf6->lsdb;
      break;
    default:
      if (is_debug)
        zlog_debug ("LSA has reserved scope, discard");
      ospf6_lsa_delete (new_);
      return;
    }

#ifdef OSPF6_MANET
  /* If LSA was received as multicast, flag it (for later flooding decisions)*/
  if (IN6_IS_ADDR_MULTICAST(dst))
    SET_FLAG (new_->flag, OSPF6_LSA_RECVMCAST);
#endif

#ifdef SIM_ETRACE_STAT
  ospf6_lsa_increment_hopcount(new_->header);
#endif //SIM_ETRACE_STAT

  /* (4) if MaxAge LSA and if we have no instance, and no neighbor
         is in states Exchange or Loading */
  if (ospf6_is_maxage_lsa_drop (new_, from))
    {
      /* log */
      if (is_debug)
        zlog_debug ("Drop MaxAge LSA with direct acknowledgement.");

      /* a) Acknowledge back to neighbor (Direct acknowledgement, 13.5) */
#ifdef OSPF6_MANET
      if (from->ospf6_if->type == OSPF6_IFTYPE_MANETRELIABLE)
      {
        ospf6_lsdb_add (ospf6_lsa_copy (new_), from->ospf6_if->lsack_list);
        if (from->ospf6_if->thread_send_lsack == NULL)
          //Chandra03 3.4.9 paragraph 1 condition 1
          from->ospf6_if->thread_send_lsack =
            thread_add_timer_msec (master,
                                   ospf6_lsack_send_interface,
                                   from->ospf6_if,
                                   from->ospf6_if->ackInterval);
      }
      else
      {
        ospf6_lsdb_add (ospf6_lsa_copy (new_), from->lsack_list);
        if (from->thread_send_lsack == NULL)
          from->thread_send_lsack =
            thread_add_event (master, ospf6_lsack_send_neighbor, from, 0);
      }
#else
      ospf6_lsdb_add (ospf6_lsa_copy (new_), from->lsack_list);
      if (from->thread_send_lsack == NULL)
        from->thread_send_lsack =
          thread_add_event (master, ospf6_lsack_send_neighbor, from, 0);
#endif //OSPF6_MANET

      /* b) Discard */
      ospf6_lsa_delete (new_);
      return;
    }

  /* (5) */
  /* lookup the same database copy in lsdb */
  old = ospf6_lsdb_lookup (new_->header->type, new_->header->id,
                           new_->header->adv_router, new_->lsdb);
  if (old)
    {
      ismore_recent = ospf6_lsa_compare (new_, old);
      if (ntohl (new_->header->seqnum) == ntohl (old->header->seqnum))
        {
          if (is_debug)
            zlog_debug ("Received is duplicated LSA");
          SET_FLAG (new_->flag, OSPF6_LSA_DUPLICATE);
        }
    }

#ifdef OSPF6_MANET
  ospf6_store_mack(from, new_->header);
#endif //OSPF6_MANET

  /* if no database copy or received is more recent */
  if (old == NULL || ismore_recent < 0)
    {
      /* in case we have no database copy */
      ismore_recent = -1;

      /* (a) MinLSArrival check */
      if (old)
        {
          struct timeval now, res;
#ifdef SIM
          gettimeofday_sim (&now, (struct timezone *) NULL);
#else
          gettimeofday (&now, (struct timezone *) NULL);
#endif //SIM
          timersub (&now, &old->installed, &res);
#ifdef OSPF6_CONFIG
          if (res.tv_sec < from->ospf6_if->area->ospf6->minLSArrival)
#else
          if (res.tv_sec < MIN_LS_ARRIVAL)
#endif //OSPF6_CONFIG
            {
              if (is_debug)
                zlog_debug ("LSA can't be updated within MinLSArrival, discard");
              ospf6_lsa_delete (new_);
              return;   /* examin next lsa */
            }
        }

#ifdef SIM
      gettimeofday_sim (&new_->received, (struct timezone *) NULL);
#else
      gettimeofday (&new_->received, (struct timezone *) NULL);
#endif //SIM

      if (is_debug)
        zlog_debug ("Flood, Install, Possibly acknowledge the received LSA");

      /* (b) immediately flood and (c) remove from all retrans-list */
      /* Prevent self-originated LSA to be flooded. this is to make
      reoriginated instance of the LSA not to be rejected by other routers
      due to MinLSArrival. */
      if (new_->header->adv_router != from->ospf6_if->area->ospf6->router_id)
        ospf6_flood (from, new_);

      /* (c) Remove the current database copy from all neighbors' Link
             state retransmission lists. */
      /* XXX, flood_clear ? */

      /* (d), installing lsdb, which may cause routing
              table calculation (replacing database copy) */
      ospf6_install_lsa (new_);

#ifdef OSPF6_MANET_TEMPORARY_LSDB
{
      struct ospf6_lsa *cache_lsa;
      cache_lsa = ospf6_lsdb_lookup_cache(new_->header->type, new_->header->id,
                                          new_->header->adv_router, new_->lsdb);
      if (cache_lsa)
      {
        if (ospf6_lsa_compare(new_, cache_lsa) < 1)
        {
          // new lsa more rececnt or same as cache_lsa
          ospf6_lsdb_remove (cache_lsa, cache_lsa->lsdb);
        }
      }
}
#endif //OSPF6_MANET_TEMPORARY_LSDB

      /* (e) possibly acknowledge */
#ifdef OSPF6_MANET
      ospf6_acknowledge_lsa (new_, ismore_recent, from, dst);
#else
      ospf6_acknowledge_lsa (new_, ismore_recent, from);
#endif //OSPF6_MANET

      /* (f) Self Originated LSA, section 13.4 */
      if (new_->header->adv_router == from->ospf6_if->area->ospf6->router_id)
        {
          /* Self-originated LSA (newer than ours) is received from
             another router. We have to make a new instance of the LSA
             or have to flush this LSA. */
          if (is_debug)
            {
              zlog_debug ("Newer instance of the self-originated LSA");
              zlog_debug ("Schedule reorigination");
            }
          new_->refresh = thread_add_event (master, ospf6_lsa_refresh, new_, 0);
        }

      return;
    }

  /* (6) if there is instance on sending neighbor's request list */
  if (ospf6_lsdb_lookup (new_->header->type, new_->header->id,
                         new_->header->adv_router, from->request_list))
    {
      /* if no database copy, should go above state (5) */
      assert (old);

      if (is_debug)
        {
          zlog_debug ("Received is not newer, on the neighbor's request-list");
          zlog_debug ("BadLSReq, discard the received LSA");
        }

      /* BadLSReq */
      thread_add_event (master, bad_lsreq, from, 0);

      ospf6_lsa_delete (new_);
      return;
    }

  /* (7) if neither one is more recent */
  if (ismore_recent == 0)
    {
      if (is_debug)
        zlog_debug ("The same instance as database copy (neither recent)");

#ifdef OSPF6_MANET
      if (from->ospf6_if->type == OSPF6_IFTYPE_MANETRELIABLE &&
          old->pushBackTimer && ospf6_lsa_compare (new_, old) == 0)
      { 
#ifdef OSPF6_MANET_MPR_FLOOD
        if (from->ospf6_if->flooding == OSPF6_FLOOD_MPR_SDCDS)
        {
          //Chandra03 3.4.8 paragraph 2 condition 2.2
          // possibly remove old LSA source from the pushback neighbor list
          ospf6_pushback_lsa_neighbor_delete(old, from);
          if (old->pushBackTimer && ospf6_pushback_check_coverage(old, from))
          {
            //if neighbors of "from" cover neighbors in pushback neigh list
            //reset pushBackTimer and wait for more acks to come in
            THREAD_OFF(old->pushBackTimer);
            old->pushBackTimer =
              thread_add_timer_msec (master, ospf6_pushback_expiration, old,
              from->ospf6_if->pushBackInterval+pushback_jitter(from->ospf6_if));

#ifdef SIM_ETRACE_STAT 
            char id[16], adv_router[16];
            inet_ntop (AF_INET, &old->header->id, id, sizeof (id));
            inet_ntop (AF_INET, &old->header->adv_router, adv_router,
                       sizeof (adv_router));
            TraceEvent_sim(2,"Re-pushback Flood LSA %s -id %s -advrt %s -age %d -seq %lu -len %d from %s",
                       ospf6_lstype_name(old->header->type), id, adv_router,
                       ntohs(age_mask(old->header)), ntohl(old->header->seqnum),
                       ntohs(old->header->length), from->name);
#endif //SIM_ETRACE_STAT
          }
        }
#endif //OSPF6_MANET_MPR_FLOOD

#ifdef OSPF6_MANET_MDR_FLOOD
        if (from->ospf6_if->flooding == OSPF6_FLOOD_MDR_SICDS)
        {
          struct listnode *n;
          u_int32_t *id;
          struct ospf6_neighbor *neigh; 

          //remove sender from pushback list
          ospf6_pushback_lsa_neighbor_delete(old,from);
          //loop over neighbor neighbors
          //RGO-- enforce that LSA was received as multicast-- otherwise,
          //      cannot assume that sender's neighbors received
      	  if (IN6_IS_ADDR_MULTICAST(dst))
          {
            for (n = listhead(from->rnl); n; nextnode(n))
            {
              if (!old->pushBackTimer)
                break;
              id = (u_int32_t *) getdata(n); 
              if (*id == from->ospf6_if->area->ospf6->router_id)
                continue;
              neigh = ospf6_neighbor_lookup(*id, from->ospf6_if);
              //remove sender's neighbors from pushback list
              if (neigh)
                ospf6_pushback_lsa_neighbor_delete(old,neigh);
            }
          }
        }
#endif //OSPF6_MANET_MDR_FLOOD
      }
#endif //OSPF6_MANET

      /* (a) if on retrans-list, Treat this LSA as an Ack: Implied Ack */
      rem = ospf6_lsdb_lookup (new_->header->type, new_->header->id,
                               new_->header->adv_router, from->retrans_list);
      if (rem)
        {
          if (is_debug)
            {
              zlog_debug ("It is on the neighbor's retrans-list.");
              zlog_debug ("Treat as an Implied acknowledgement");
            }
          SET_FLAG (new_->flag, OSPF6_LSA_IMPLIEDACK);
          ospf6_decrement_retrans_count (rem);
          ospf6_lsdb_remove (rem, from->retrans_list);
        }

      if (is_debug)
        zlog_debug ("Possibly acknowledge and then discard");

      /* (b) possibly acknowledge */
#ifdef OSPF6_MANET
      ospf6_acknowledge_lsa (new_, ismore_recent, from, dst);
#else
      ospf6_acknowledge_lsa (new_, ismore_recent, from);
#endif //OSPF6_MANET

      ospf6_lsa_delete (new_);
      return;
    }

  /* (8) previous database copy is more recent */
    {
      assert (old);

      /* If database copy is in 'Seqnumber Wrapping',
         simply discard the received LSA */
      if (OSPF6_LSA_IS_MAXAGE (old) &&
          old->header->seqnum == htonl (MAX_SEQUENCE_NUMBER))
        {
          if (is_debug)
            {
              zlog_debug ("The LSA is in Seqnumber Wrapping");
              zlog_debug ("MaxAge & MaxSeqNum, discard");
            }
          ospf6_lsa_delete (new_);
          return;
        }

#ifdef OSPF6_MANET_MDR_FLOOD
        // SICDS does not send LSA to non-adjacent neighbor here.
        if (from->ospf6_if->flooding == OSPF6_FLOOD_MDR_SICDS &&
            from->state < OSPF6_NEIGHBOR_EXCHANGE)
        {
          ospf6_lsa_delete (new_); //XXX Insure
          return;
        }
#endif //OSPF6_MANET_MDR_FLOOD

      /* Otherwise, Send database copy of this LSA to this neighbor */
        {
          if (is_debug)
            {
              zlog_debug ("Database copy is more recent.");
              zlog_debug ("Send back directly and then discard");
            }

          /* XXX, MinLSArrival check !? RFC 2328 13 (8) */

#ifdef OSPF6_MANET
      // XXX BOEING Draft Change  -- suppressing stale LSA responses
      // when the LSA will be sent pushBack algorithm
      if (old->pushBackTimer)
      {
        ospf6_lsa_delete (new_);
        return;
      }
#endif //OSPF6_MANET

#if defined(SIM_ETRACE_STAT) 
      struct ospf6_lsa *old_copy = ospf6_lsa_copy(old);
      old_copy->unicast_stale = true;
      ospf6_lsdb_add (old_copy, from->lsupdate_list);

#ifdef OSPF6_MANET_MPR_FLOOD
      char id[16], adv_router[16], buf[128];
      inet_ntop (AF_INET, &old->header->id, id, sizeof (id));
      inet_ntop (AF_INET, &old->header->adv_router, adv_router,
                 sizeof (adv_router));
      inet_ntop (AF_INET6, dst, buf, sizeof(char)*128);
      TraceEvent_sim(2,"Database LSA %s -id %s -advrt %s -age %d -seq %lu -len %d is more recent than -age %d -seq %lu -len %d from %s to %s",
                    ospf6_lstype_name(old->header->type), id, adv_router,
                    ntohs(age_mask(old->header)), ntohl(old->header->seqnum),
                    ntohs(old->header->length), ntohs(age_mask(new_->header)),
                    ntohl(new_->header->seqnum), ntohs(new_->header->length),
                    from->name, buf);
#endif //OSPF6_MANET_MPR_FLOOD
#else
      ospf6_lsdb_add (ospf6_lsa_copy (old), from->lsupdate_list);
#endif //SIM_ETRACE_STAT

#ifdef OSPF6_DELAYED_FLOOD
      from->thread_send_lsupdate =
        ospf6_send_lsupdate_delayed_msec(master, ospf6_lsupdate_send_neighbor, 
                                         from, from->ospf6_if->flood_delay, 
                                         from->thread_send_lsupdate);
#else
#ifdef BUGFIX
      //should respond to lsa immediately if not a duplicate, but
      //this code could respond to lsa before MinLSArrival passes
      //RFC 2328 13 (8)
      THREAD_OFF(from->thread_send_lsupdate);
      from->thread_send_lsupdate = NULL;
#endif //BUGFIX
      if (from->thread_send_lsupdate == NULL)
        from->thread_send_lsupdate =
          thread_add_event (master, ospf6_lsupdate_send_neighbor, from, 0);
#endif //OSPF6_DELAYED_FLOOD
      ospf6_lsa_delete (new_);
      return;
    }
  return;
  }
}

#ifdef OSPF6_MANET_TEMPORARY_LSDB
void
ospf6_receive_lsa_below_exchange (struct ospf6_lsa_header *lsa_header,
                                  struct ospf6_interface *oi)
{
  struct ospf6_lsa *new_ = NULL, *old = NULL;
  unsigned short cksum;
  struct ospf6_lsdb *lsdb = NULL;
  int ismore_recent = 1;
  int is_debug = 0;

  if(oi->type != OSPF6_IFTYPE_MANETRELIABLE)
    return;

  /* make lsa structure for received lsa */
  new_ = ospf6_lsa_create (lsa_header);

  if (IS_OSPF6_DEBUG_FLOODING ||
      IS_OSPF6_DEBUG_FLOOD_TYPE (new_->header->type))
    {
      is_debug++;
      zlog_debug ("LSA Receive Below Exchange");
      ospf6_lsa_header_print (new_);
    }

  /* (1) LSA Checksum */
  cksum = ntohs (new_->header->checksum);
  if (ntohs (ospf6_lsa_checksum (new_->header)) != cksum)
    {
      if (is_debug)
        zlog_info ("Wrong LSA Checksum");
      ospf6_lsa_delete (new_);
      return;
    }

  /* (2) Examine the LSA's LS type.
     RFC2470 3.5.1. Receiving Link State Update packets  */
  if (IS_AREA_STUB (oi->area) &&
      OSPF6_LSA_SCOPE (new_->header->type) == OSPF6_SCOPE_AS)
    {
      if (is_debug)
        zlog_debug ("AS-External-LSA (or AS-scope LSA) in stub area, discard");
      ospf6_lsa_delete (new_);
      return;
    }

  /* (3) LSA which have reserved scope is discarded
     RFC2470 3.5.1. Receiving Link State Update packets  */
  /* Flooding scope check. LSAs with unknown scope are discarded here.
     Set appropriate LSDB for the LSA */
  switch (OSPF6_LSA_SCOPE (new_->header->type))
    {
    case OSPF6_SCOPE_LINKLOCAL:
      new_->lsdb = oi->lsdb;
      break;
    case OSPF6_SCOPE_AREA:
      new_->lsdb = oi->area->lsdb;
      break;
    case OSPF6_SCOPE_AS:
      new_->lsdb = oi->area->ospf6->lsdb;
      break;
    default:
      if (is_debug)
        zlog_debug ("LSA has reserved scope, discard");
      ospf6_lsa_delete (new_);
      return;
    }

  /* (4) if MaxAge LSA and if we have no instance, and no neighbor
         is in states Exchange or Loading */
  if (ospf6_is_maxage_lsa_drop (new_, NULL))
    {
      /* log */
      if (is_debug)
        zlog_info ("Drop MaxAge LSA");
      ospf6_lsa_delete (new_);
      return;
    }

   if (new_->header->adv_router == oi->area->ospf6->router_id)
   {  //self originated:  ignore non-neighbor LSAs  XXX?
     ospf6_lsa_delete (new_);
     return;
   }

  lsdb = ospf6_get_scoped_lsdb (new_);
  old = ospf6_lsdb_lookup (new_->header->type, new_->header->id,
                           new_->header->adv_router, lsdb);
  if (old && ospf6_lsa_compare (old, new_) < 1)
  {
    ospf6_lsa_delete (new_);
    return;
  }

  /* (5) */
  /* limit the size of the LSA cache */
  /* lookup the same database copy in lsdb cache*/
  if (lsdb->count_cache > 200)
  {
    ospf6_lsa_delete (new_);
    return;
  }

  old = ospf6_lsdb_lookup_cache (new_->header->type, new_->header->id,
                           new_->header->adv_router, lsdb);
  if (old)
    ismore_recent = ospf6_lsa_compare (new_, old);

  /* if no database copy or received is more recent */
  if (old == NULL  || ismore_recent < 0)
    {
      /* (a) MinLSArrival check */
      if (old)
      {
        struct timeval now, res;
#ifdef SIM
        gettimeofday_sim (&now, (struct timezone *) NULL);
#else
        gettimeofday (&now, (struct timezone *) NULL);
#endif //SIM
        timersub (&now, &old->installed, &res);
#ifdef OSPF6_CONFIG
          if (res.tv_sec < oi->area->ospf6->minLSArrival)
#else
          if (res.tv_sec < MIN_LS_ARRIVAL)
#endif //OSPF6_CONFIG
        {
          if (is_debug)
            zlog_info ("LSA can't be updated within MinLSArrival");
          ospf6_lsa_delete (new_);
          return;   /* examin next lsa */
        }
      }

#ifdef SIM
      gettimeofday_sim (&new_->installed, (struct timezone *) NULL);
#else
      gettimeofday (&new_->installed, (struct timezone *) NULL);
#endif //SIM
      new_->cache = 1;
      ospf6_lsdb_add (new_, lsdb);
#ifdef OSPF6_CONFIG
  if (IS_OSPF6_DEBUG_DATABASE (DATABASE_DETAIL))
    ospf6_debug_lsdb_show(OSPF6_DEBUG_DATABASE_DETAIL, lsdb);
  else if (IS_OSPF6_DEBUG_DATABASE (DATABASE))
    ospf6_debug_lsdb_show(OSPF6_DEBUG_DATABASE, lsdb);
#endif //OSPF6_CONFIG
    }
  else
    ospf6_lsa_delete (new_);
}
#endif //OSPF6_MANET_TEMPORARY_LSDB

DEFUN (debug_ospf6_flooding,
       debug_ospf6_flooding_cmd,
       "debug ospf6 flooding",
       DEBUG_STR
       OSPF6_STR
       "Debug OSPFv3 flooding function\n"
      )
{
  OSPF6_DEBUG_FLOODING_ON ();
  return CMD_SUCCESS;
}

DEFUN (no_debug_ospf6_flooding,
       no_debug_ospf6_flooding_cmd,
       "no debug ospf6 flooding",
       NO_STR
       DEBUG_STR
       OSPF6_STR
       "Debug OSPFv3 flooding function\n"
      )
{
  OSPF6_DEBUG_FLOODING_OFF ();
  return CMD_SUCCESS;
}

int
config_write_ospf6_debug_flood (struct vty *vty)
{
  if (IS_OSPF6_DEBUG_FLOODING)
    vty_out (vty, "debug ospf6 flooding%s", VNL);
  return 0;
}

void
install_element_ospf6_debug_flood ()
{
  install_element (ENABLE_NODE, &debug_ospf6_flooding_cmd);
  install_element (ENABLE_NODE, &no_debug_ospf6_flooding_cmd);
  install_element (CONFIG_NODE, &debug_ospf6_flooding_cmd);
  install_element (CONFIG_NODE, &no_debug_ospf6_flooding_cmd);
}
