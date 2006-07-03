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
#include "memory.h"
#include "thread.h"
#include "linklist.h"
#include "vty.h"
#include "command.h"

#include "ospf6_proto.h"
#include "ospf6_lsa.h"
#include "ospf6_lsdb.h"
#include "ospf6_message.h"
#include "ospf6_top.h"
#include "ospf6_area.h"
#include "ospf6_interface.h"
#include "ospf6_neighbor.h"
#include "ospf6_intra.h"
#include "ospf6_flood.h"
#ifdef OSPF6_MANET_MDR_FLOOD
#include "ospf6_route.h"
#include "ospf6_spf.h"
#endif //OSPF6_MANET_MDR_FLOOD
#include "ospf6d.h"
#ifdef SIM
#include "sim.h"
#include "ospf6_sim_printing.h"
#endif //SIM

unsigned char conf_debug_ospf6_neighbor = 0;

const char *ospf6_neighbor_state_str[] =
{ "None", "Down", "Attempt", "Init", "Twoway", "ExStart", "ExChange",
  "Loading", "Full", NULL };

int
ospf6_neighbor_cmp (void *va, void *vb)
{
  struct ospf6_neighbor *ona = (struct ospf6_neighbor *) va;
  struct ospf6_neighbor *onb = (struct ospf6_neighbor *) vb;
  return (ntohl (ona->router_id) < ntohl (onb->router_id) ? -1 : 1);
}

struct ospf6_neighbor *
ospf6_neighbor_lookup (u_int32_t router_id,
                       struct ospf6_interface *oi)
{
  struct listnode *n;
  struct ospf6_neighbor *on;

  for (n = listhead (oi->neighbor_list); n; nextnode (n))
    {
      on = (struct ospf6_neighbor *) getdata (n);
      if (on->router_id == router_id)
        return on;
    }
  return (struct ospf6_neighbor *) NULL;
}

/* create ospf6_neighbor */
struct ospf6_neighbor *
ospf6_neighbor_create (u_int32_t router_id, struct ospf6_interface *oi)
{
  struct ospf6_neighbor *on;
  char buf[16];

  on = (struct ospf6_neighbor *)
    XMALLOC (MTYPE_OSPF6_NEIGHBOR, sizeof (struct ospf6_neighbor));
  if (on == NULL)
    {
      zlog_warn ("neighbor: malloc failed");
      return NULL;
    }

  memset (on, 0, sizeof (struct ospf6_neighbor));
  inet_ntop (AF_INET, &router_id, buf, sizeof (buf));
  snprintf (on->name, sizeof (on->name), "%s%%%s",
            buf, oi->interface->name);
  on->ospf6_if = oi;
  on->state = OSPF6_NEIGHBOR_DOWN;
#ifdef SIM
  gettimeofday_sim (&on->last_changed, (struct timezone *) NULL);
#else
  gettimeofday (&on->last_changed, (struct timezone *) NULL);
#endif //SIM
  on->router_id = router_id;

  on->summary_list = ospf6_lsdb_create (on);
  on->request_list = ospf6_lsdb_create (on);
  on->retrans_list = ospf6_lsdb_create (on);

  on->dbdesc_list = ospf6_lsdb_create (on);
  on->lsreq_list = ospf6_lsdb_create (on);
  on->lsupdate_list = ospf6_lsdb_create (on);
  on->lsack_list = ospf6_lsdb_create (on);

#ifdef OSPF6_MANET
  if (oi->type == OSPF6_IFTYPE_MANETRELIABLE)
  {
#ifdef OSPF6_MANET_MPR_FLOOD
#ifdef OSPF6_MANET_DIFF_HELLO
    struct drop_neighbor *drop_neigh = NULL;
    drop_neigh = ospf6_lookup_drop_neighbor(oi, router_id);
    if (drop_neigh)
      ospf6_drop_neighbor_delete(oi, drop_neigh);
    on->set_scs_num = true;
    //Chandra03 3.3.6.1 paragraph 2 bullet 2
    oi->increment_scs = true;
    on->below_exchange = true;
#endif //OSPF6_MANET_DIFF_HELLO
    on->Fbit = false;
    on->Relay_Abit = false;
    on->Relay_Nbit = false;
    on->two_hop_neighbor_list = NULL;
#endif //OSPF6_MANET_MPR_FLOOD

#ifdef OSPF6_MANET_MDR_FLOOD
#ifdef OSPF6_MANET_DIFF_HELLO
{
    struct ospf6_lnl_element *lnl_element;
    lnl_element = ospf6_mdr_lookup_lnl_element(on);
    if (lnl_element)
      ospf6_mdr_delete_lnl_element(oi, lnl_element);
}
#endif //OSPF6_MANET_DIFF_HELLO
    on->rnl = list_new();
    on->Report2Hop = false;
    on->reverse_2way = false;
    on->dependent = false;
    on->dependent_selector = false;
    on->routable = false;
    on->adv = false;
    on->new_adv = false;
#endif //OSPF6_MANET_MDR_FLOOD

    on->mack_list = list_new();
  }
#endif //OSPF6_MANET

  listnode_add_sort (oi->neighbor_list, on);
  return on;
}

void
ospf6_neighbor_delete (struct ospf6_neighbor *on)
{
  struct ospf6_lsa *lsa;

  ospf6_lsdb_remove_all (on->summary_list);
  ospf6_lsdb_remove_all (on->request_list);
  for (lsa = ospf6_lsdb_head (on->retrans_list); lsa;
       lsa = ospf6_lsdb_next (lsa))
    {
      ospf6_decrement_retrans_count (lsa);
      ospf6_lsdb_remove (lsa, on->retrans_list);
    }

  ospf6_lsdb_remove_all (on->dbdesc_list);
  ospf6_lsdb_remove_all (on->lsreq_list);
  ospf6_lsdb_remove_all (on->lsupdate_list);
  ospf6_lsdb_remove_all (on->lsack_list);

  ospf6_lsdb_delete (on->summary_list);
  ospf6_lsdb_delete (on->request_list);
  ospf6_lsdb_delete (on->retrans_list);

  ospf6_lsdb_delete (on->dbdesc_list);
  ospf6_lsdb_delete (on->lsreq_list);
  ospf6_lsdb_delete (on->lsupdate_list);
  ospf6_lsdb_delete (on->lsack_list);

#ifdef OSPF6_MANET
  if (on->ospf6_if->type == OSPF6_IFTYPE_MANETRELIABLE)
  {
#ifdef OSPF6_MANET_MPR_FLOOD
#ifdef OSPF6_MANET_DIFF_HELLO
    //Chandra03 3.3.6.2 paragraph 1 bullet 2
    ospf6_drop_neighbor_create(on);
    //Chandra03 3.3.6.2 paragraph 1 bullet 3
    on->ospf6_if->increment_scs = true;
#endif //OSPF6_MANET_DIFF_HELLO
#endif //OSPF6_MANET_MPR_FLOOD

#ifdef OSPF6_MANET_MDR_FLOOD
#ifdef OSPF6_MANET_DIFF_HELLO
    ospf6_mdr_add_lnl_element(on);
#endif //OSPF6_MANET_DIFF_HELLO
    ospf6_mdr_set_mdr_level(on, 0, 0); //important for statisics gathering
    ospf6_mdr_delete_neighbor_list(on->rnl);
#endif //OSPF6_MANET_MDR_FLOOD

    ospf6_mack_list_delete(on);
  }
#endif //OSPF6_MANET

  THREAD_OFF (on->inactivity_timer);

  THREAD_OFF (on->thread_send_dbdesc);
  THREAD_OFF (on->thread_send_lsreq);
  THREAD_OFF (on->thread_send_lsupdate);
  THREAD_OFF (on->thread_send_lsack);

  XFREE (MTYPE_OSPF6_NEIGHBOR, on);
}

//static 
void
ospf6_neighbor_state_change (u_char next_state, struct ospf6_neighbor *on)
{
  u_char prev_state;
#ifdef OSPF6_MANET
  u_char type = on->ospf6_if->type;
  int change;
#endif //OSPF6_MANET

  prev_state = on->state;
  on->state = next_state;

  if (prev_state == next_state)
    return;

#ifdef SIM_ETRACE_STAT
  ospf6_neighbor_state_change_stats (prev_state, next_state, on);
#endif //SIM_ETRACE_STAT

#ifdef SIM
  gettimeofday_sim (&on->last_changed, (struct timezone *) NULL);
#else
  gettimeofday (&on->last_changed, (struct timezone *) NULL);
#endif //SIM

  /* log */
  if (IS_OSPF6_DEBUG_NEIGHBOR (STATE))
    {
      zlog_debug ("Neighbor state change %s: [%s]->[%s]", on->name,
                  ospf6_neighbor_state_str[prev_state],
                  ospf6_neighbor_state_str[next_state]);
    }

#ifdef OSPF6_MANET
  if (type == OSPF6_IFTYPE_MANETRELIABLE)
  {
#ifdef OSPF6_MANET_MPR_FLOOD  
    if (on->ospf6_if->flooding == OSPF6_FLOOD_MPR_SDCDS)
    {
      if (prev_state == OSPF6_NEIGHBOR_FULL) //XXX OR/SP
      {
        on->ospf6_if->mpr_change = true;
        ospf6_2hop_list_delete(on);
        ospf6_update_neighborhood(on->ospf6_if);
      } 
      else if (next_state == OSPF6_NEIGHBOR_FULL) //XXX OR/SP
      {
        // Building the two-hop neighbor list
        // By definition, section 3.4.3 bullet 2
        /* 1-hop neighbor may have been a 2-hop neighbor */
        struct ospf6_2hop_neighbor *o2n = NULL;
        o2n = ospf6_2hop_neighbor_lookup(on->router_id,
                                         on->ospf6_if->two_hop_list);
        if (o2n)
        {
          struct listnode *n;
          struct ospf6_neighbor *oN = NULL;
          n = listhead (o2n->one_hop_neighbor_list);
          while(n)
          {
            oN = (struct ospf6_neighbor *) getdata (n);
            nextnode(n);
            listnode_delete(oN->two_hop_neighbor_list, o2n);
          }
          listnode_delete(on->ospf6_if->two_hop_list, o2n);
          list_delete(o2n->one_hop_neighbor_list);
          free(o2n);
        }
        on->two_hop_neighbor_list = list_new();
        on->ospf6_if->mpr_change = true;
        ospf6_update_neighborhood(on->ospf6_if);
      }
#ifdef OSPF6_MANET_DIFF_HELLO
      /* Chandra03 3.3.6.1 paragraph 2 bullet 3*/
      if (on->state >= OSPF6_NEIGHBOR_EXCHANGE)
      {
        on->below_exchange = false;
      }
#endif //OSPF6_MANET_DIFF_HELLO
    }
#endif //OSPF6_MANET_MPR_FLOOD

    change = ospf6_manet_update_routable_neighbors(on->ospf6_if);
    if (on->ospf6_if->flooding == OSPF6_FLOOD_MDR_SICDS)
    {
      if (((prev_state < OSPF6_NEIGHBOR_TWOWAY) &&
          (next_state >= OSPF6_NEIGHBOR_TWOWAY)) ||
         ((prev_state >= OSPF6_NEIGHBOR_TWOWAY) &&
          (next_state < OSPF6_NEIGHBOR_TWOWAY)) ||
         ((prev_state < OSPF6_NEIGHBOR_INIT) &&
          (next_state >= OSPF6_NEIGHBOR_INIT)) ||
         ((prev_state >= OSPF6_NEIGHBOR_INIT) &&
          (next_state < OSPF6_NEIGHBOR_INIT)))
        on->changed_hsn = on->ospf6_if->hsn;
      // Condition for LSA change depends on LSAFullness.
      if (on->ospf6_if->LSAFullness == OSPF6_LSA_FULLNESS_MINHOP ||
          on->ospf6_if->LSAFullness == OSPF6_LSA_FULLNESS_MINHOP2PATHS) 
        change = ospf6_mdr_update_adv_neighbors(on->ospf6_if);
    }

    //schedule LSAs if change
    if (on->ospf6_if->flooding == OSPF6_FLOOD_MDR_SICDS &&
        on->ospf6_if->AdjConnectivity > OSPF6_ADJ_FULLYCONNECTED &&
        (on->ospf6_if->LSAFullness == OSPF6_LSA_FULLNESS_FULL ||
        on->ospf6_if->LSAFullness == OSPF6_LSA_FULLNESS_MINHOP ||
        on->ospf6_if->LSAFullness == OSPF6_LSA_FULLNESS_MINHOP2PATHS))
        //(on->ospf6_if->LSAFullness == OSPF6_LSA_FULLNESS_MDRFULL &&
         //!on->ospf6_if->full_adj_part_lsa &&
        //on->ospf6_if->mdr_level != OSPF6_OTHER)))
    {
      if (change)
        OSPF6_ROUTER_LSA_SCHEDULE (on->ospf6_if->area);
    }
    // This section handles MDRFULL for all routers, with or without
    // full_adj_part_lsa.
    else if (on->ospf6_if->flooding == OSPF6_FLOOD_MDR_SICDS &&
        on->ospf6_if->AdjConnectivity > OSPF6_ADJ_FULLYCONNECTED &&
        on->ospf6_if->LSAFullness == OSPF6_LSA_FULLNESS_MDRFULL)
    {
        // Four cases: MDR/BMDR and Other with partial adj, then
        // MDR/BMDR and Other with full adj.
        if (!on->ospf6_if->full_adj_part_lsa &&
            on->ospf6_if->mdr_level >= OSPF6_BMDR)
        {
          if (change)
            OSPF6_ROUTER_LSA_SCHEDULE (on->ospf6_if->area);
        }
        else if (on->ospf6_if->full_adj_part_lsa &&
            on->ospf6_if->mdr_level >= OSPF6_BMDR)
        {
          if (prev_state == OSPF6_NEIGHBOR_FULL ||
              next_state == OSPF6_NEIGHBOR_FULL)
            OSPF6_ROUTER_LSA_SCHEDULE (on->ospf6_if->area);
        }
       // If MDR full LSAs are used and router is Other, schedule an
       // LSA if a Full (b)parent is not advertised, or if an advertised
       // neighbor becomes less than Full.  Similar condition for
       // partial-topology adjacencies, but parents need not be checked.
       // An LSA is also originated from mdr_calc when a parent
       // is selected that is already Full but not yet advertised.
        else if (on->ospf6_if->full_adj_part_lsa &&
            on->ospf6_if->mdr_level == OSPF6_OTHER)
        {
          if ((on->mdr_level >= OSPF6_BMDR &&
              (on->ospf6_if->parent == on || on->ospf6_if->bparent == on) &&
               !on->adv && on->state == OSPF6_NEIGHBOR_FULL) ||
               on->adv && on->state < OSPF6_NEIGHBOR_FULL)
            OSPF6_ROUTER_LSA_SCHEDULE (on->ospf6_if->area);
        }
        else if (!on->ospf6_if->full_adj_part_lsa &&
            on->ospf6_if->mdr_level == OSPF6_OTHER)
        {
          if ((on->mdr_level >= OSPF6_BMDR &&
               !on->adv && on->state == OSPF6_NEIGHBOR_FULL) ||
               on->adv && on->state < OSPF6_NEIGHBOR_FULL)
            OSPF6_ROUTER_LSA_SCHEDULE (on->ospf6_if->area);
        }
    }  
#ifdef OSPF6_MANET_MPR_SP
    else if (on->ospf6_if->flooding == OSPF6_FLOOD_MPR_SDCDS &&
             on->ospf6_if->smart_peering)
    {
      struct ospf6_area* oa = on->ospf6_if->area;
      boolean new_adjacency = false;

      if (change)  //BUGFIX_SP
      {
         //perform sync SPF, so adjacency check will be working with 
         //accurate routes
         ospf6_spf_calculation(oa->ospf6->router_id,oa->spf_table_sync,oa,true);
         ospf6_manet_update_routable_neighbors(on->ospf6_if);
         new_adjacency = ospf6_or_update_adjacencies(on->ospf6_if);
      }

      //A new router-LSA will be scheduled, but want to delay it because
      //an adjacency will come up soon that will cause another router-LSA
      //origination
      if(new_adjacency && change && on->ospf6_if->unsynch_adj)
      {
        if (!oa->thread_router_lsa)
          oa->thread_router_lsa =
            thread_add_timer_msec(master, ospf6_router_lsa_originate, 
                                  oa, oa->ospf6->minLSInterval*1000);
         
      }
      //build a router-LSA now
      else if(change && on->ospf6_if->unsynch_adj)
          OSPF6_ROUTER_LSA_SCHEDULE (on->ospf6_if->area);
      else if (prev_state == OSPF6_NEIGHBOR_FULL ||
             next_state == OSPF6_NEIGHBOR_FULL)
      {
        OSPF6_ROUTER_LSA_SCHEDULE (on->ospf6_if->area);
      }
    }
#endif //OSPF6_MANET_MPR_SP
    else // full adj or lsa includes only adjacent neighbors
    {
      if (prev_state == OSPF6_NEIGHBOR_FULL ||
             next_state == OSPF6_NEIGHBOR_FULL)
      {
        OSPF6_ROUTER_LSA_SCHEDULE (on->ospf6_if->area);
        //OSPF6_INTRA_PREFIX_LSA_SCHEDULE_STUB (on->ospf6_if->area);
      }
    }
  }
  else
#endif //OSPF6_MANET
  if (prev_state == OSPF6_NEIGHBOR_FULL || next_state == OSPF6_NEIGHBOR_FULL)
    {
      OSPF6_ROUTER_LSA_SCHEDULE (on->ospf6_if->area);
      if (on->ospf6_if->state == OSPF6_INTERFACE_DR)
        {
          OSPF6_NETWORK_LSA_SCHEDULE (on->ospf6_if);
          OSPF6_INTRA_PREFIX_LSA_SCHEDULE_TRANSIT (on->ospf6_if);
        }
      OSPF6_INTRA_PREFIX_LSA_SCHEDULE_STUB (on->ospf6_if->area);
    }

#ifdef XXX
  if (prev_state == NBS_FULL || next_state == NBS_FULL)
    nbs_full_change (on->ospf6_interface);

  /* check for LSAs that already reached MaxAge */
  if ((prev_state == OSPF6_NEIGHBOR_EXCHANGE ||
       prev_state == OSPF6_NEIGHBOR_LOADING) &&
      (next_state != OSPF6_NEIGHBOR_EXCHANGE &&
       next_state != OSPF6_NEIGHBOR_LOADING))
    {
      ospf6_maxage_remover ();
    }
#endif /*XXX*/

}

#ifdef SIM_ETRACE_STAT
void ospf6_neighbor_state_change_stats (u_char prev_state, u_char next_state, 
                                   struct ospf6_neighbor *on)
{
  TraceEvent_sim(2,"neighbor %s changing state from %s to %s",
    ip2str(on->router_id),
    ospf6_neighbor_state_str[prev_state],
    ospf6_neighbor_state_str[next_state]);

  if (((prev_state < OSPF6_NEIGHBOR_TWOWAY) &&
      (next_state >= OSPF6_NEIGHBOR_TWOWAY)) ||
     ((prev_state >= OSPF6_NEIGHBOR_TWOWAY) &&
      (next_state < OSPF6_NEIGHBOR_TWOWAY)))
  {
    double *stat = on->ospf6_if->area->ospf6->statistics;
    float delta_2way = elapsed_time(&on->ospf6_if->neigh_2way_change_time);
    update_statistics(OSPF6_CHANGE_OF_NUM_NEIGHS, 1);
    update_statistics(OSPF6_DURATION_OF_NUM_NEIGHS, (double)delta_2way);
    update_statistics(OSPF6_NUM_NEIGH_TIMES_DURATION_OF_NUM_NEIGHS, 
                      (double) (on->ospf6_if->num_2way_neigh * delta_2way));
    if (next_state >= OSPF6_NEIGHBOR_TWOWAY)
    {
      set_time(&on->creation_time);
      TraceEvent_sim(1,"num_nbr %d for %f msec newnbr %s for 0 msec",
      on->ospf6_if->num_2way_neigh++, delta_2way, ip2str(on->router_id));
    }
    else
    {
      double lifetime = elapsed_time(&on->creation_time);
      update_statistics(OSPF6_NEIGH_LIFETIME, lifetime);
      update_statistics(OSPF6_NEIGH_DEATHS, 1);
      TraceEvent_sim(1,"num_nbr %d for %f msec delnbr %s for %f msec",
        on->ospf6_if->num_2way_neigh--, delta_2way,
        ip2str(on->router_id),lifetime);
    }
    set_time(&on->ospf6_if->neigh_2way_change_time);
  }
  if (next_state==OSPF6_NEIGHBOR_FULL || prev_state==OSPF6_NEIGHBOR_FULL)
  {
    double *stat = on->ospf6_if->area->ospf6->statistics;
    float delta_full = elapsed_time(&on->ospf6_if->neigh_full_change_time);
    update_statistics(OSPF6_CHANGE_OF_NUM_ADJ, 1);
    update_statistics(OSPF6_DURATION_OF_NUM_ADJ, (double)delta_full);
    update_statistics(OSPF6_NUM_ADJ_TIMES_DURATION_OF_NUM_ADJ, 
                      (double) (on->ospf6_if->num_full_neigh * delta_full));
    if (next_state == OSPF6_NEIGHBOR_FULL)
      update_statistics(OSPF6_ADJ_ACCUM, 1);
    else 
      update_statistics(OSPF6_ADJ_ACCUM, -1);
      
    if (next_state == OSPF6_NEIGHBOR_FULL)
      on->ospf6_if->num_full_neigh++;
    else
    {
      double lifetime = elapsed_time(&on->creation_time);
      on->ospf6_if->num_full_neigh--;
    }
    set_time(&on->ospf6_if->neigh_full_change_time);
  }
}
#endif //SIM_ETRACE_STAT


#ifdef OSPF6_MANET_MDR_FLOOD
/* 
 *keep_adjacency() is used to decide whether an existing adjacency
 * should be kept vs. torn down. The condition is less strict than
 * need_adjacency(), for hysteresis and adjacency stability.
 * (The condition is equivalent to the need_adjacency() condition for an
 * OSPF broadcast network, i.e., at least one endpoint must be DR/BDR.)
 */
int
keep_adjacency (struct ospf6_neighbor *on)
{
  struct ospf6_interface *oi = on->ospf6_if;

  return 1; //XXX Never tear down adjacencies, for fair comparison.

  if (oi->AdjConnectivity == OSPF6_ADJ_FULLYCONNECTED)
    return 1;

  if (oi->mdr_level == OSPF6_MDR || oi->mdr_level == OSPF6_BMDR ||
      on->mdr_level == OSPF6_MDR || on->mdr_level == OSPF6_BMDR)
    return 1;
  else
    return 0;
}
#endif //OSPF6_MANET_MDR_FLOOD

/* RFC2328 section 10.4 */
int
need_adjacency (struct ospf6_neighbor *on)
{
  if (on->ospf6_if->state == OSPF6_INTERFACE_POINTTOPOINT ||
      on->ospf6_if->state == OSPF6_INTERFACE_DR ||
      on->ospf6_if->state == OSPF6_INTERFACE_BDR)
#ifdef OSPF6_MANET
	{
#ifdef OSPF6_MANET_MDR_FLOOD
    if (on->ospf6_if->flooding == OSPF6_FLOOD_MDR_SICDS &&
        on->ospf6_if->AdjConnectivity > OSPF6_ADJ_FULLYCONNECTED)
    {
      //Ogierv3 5
      struct ospf6_interface *oi = on->ospf6_if;
      u_int32_t bp_rid = 0, p_rid = 0;
      if (oi->flooding == OSPF6_FLOOD_MDR_SICDS &&
          oi->type == OSPF6_IFTYPE_MANETRELIABLE)
      {
        // Simplified rules for Ogierv7
        // Decision no longer depends on AdjConnectivity.
        if (oi->mdr_level >= OSPF6_BMDR && on->mdr_level >= OSPF6_BMDR &&
            (on->dependent || on->dependent_selector))
          return 1;

        // Form adjacency between child and parent.
        // The condition must be symmetric: child and parent must agree.
        if (oi->mdr_level >= OSPF6_BMDR && on->child == true)
          return 1;
        // Return 1 if full adjacencies are used.
        if (oi->full_adj_part_lsa)
          return 1;
        if  (on->mdr_level >= OSPF6_BMDR)
        {
          if (oi->parent)
            p_rid = oi->parent->router_id;
          if (oi->bparent)
            bp_rid = oi->bparent->router_id;
          if (on->router_id == p_rid)
            return 1;
          if (on->router_id == bp_rid)
            return 1; // backup parent is adjacent for biconnected
        }
        return 0;
      }
      return 1;
    }
#endif //OSPF6_MANET_MDR_FLOOD
#if defined(OSPF6_MANET_MPR_FLOOD) && defined(OSPF6_MANET_MPR_SP)
//Changes by:  Stan Ratliff
//Date:  November 1st, 2005
//Reason: Remove flag from struct ospf6_neighbor, on_need_adjacency
//        Now the route availability is directly checked in spf_table_synch
// Copyright (C) 2005

    //Roy-01 3.1 para 2
    else if (on->ospf6_if->flooding == OSPF6_FLOOD_MPR_SDCDS)
    {
      if (on->ospf6_if->smart_peering) 
      {
        struct ospf6_route *route;
        struct prefix prefix;
        ospf6_linkstate_prefix (on->router_id, htonl (0), &prefix);
        route = 
          ospf6_route_lookup(&prefix, on->ospf6_if->area->spf_table_sync);
//        if (route && route->path.cost > 11)
//          printf("1.  SP-Route cost %d hops %d\n", 
//                 route->path.cost, route->path.cost_e2);
        if (route == NULL)
          return 1;
        else 
          return 0;
      }
    }
#endif //defined(OSPF6_MANET_MPR_FLOOD) && defined(OSPF6_MANET_MPR_SP)
    return 1;
  }
#else
    return 1;
#endif //OSPF6_MANET
  if (on->ospf6_if->drouter == on->router_id ||
      on->ospf6_if->bdrouter == on->router_id)
    return 1;

  return 0;
}

int
hello_received (struct thread *thread)
{
  struct ospf6_neighbor *on;

  on = (struct ospf6_neighbor *) THREAD_ARG (thread);
  assert (on);

  if (IS_OSPF6_DEBUG_NEIGHBOR (EVENT))
    zlog_debug ("Neighbor Event %s: *HelloReceived*", on->name);

  /* reset Inactivity Timer */
  THREAD_OFF (on->inactivity_timer);
  on->inactivity_timer = thread_add_timer (master, inactivity_timer, on,
                                           on->ospf6_if->dead_interval);

  if (on->state <= OSPF6_NEIGHBOR_DOWN)
    ospf6_neighbor_state_change (OSPF6_NEIGHBOR_INIT, on);

  return 0;
}

int
twoway_received (struct thread *thread)
{
  struct ospf6_neighbor *on;

  on = (struct ospf6_neighbor *) THREAD_ARG (thread);
  assert (on);

  if (on->state > OSPF6_NEIGHBOR_INIT)
    return 0;

  if (IS_OSPF6_DEBUG_NEIGHBOR (EVENT))
    zlog_debug ("Neighbor Event %s: *2Way-Received*", on->name);

  thread_add_event (master, neighbor_change, on->ospf6_if, 0);

#ifdef OSPF6_MANET
  if (on->ospf6_if->type == OSPF6_IFTYPE_MANETRELIABLE)
  {
#ifdef OSPF6_MANET_MDR_FLOOD
    if (on->ospf6_if->flooding == OSPF6_FLOOD_MDR_SICDS)
    {
      // must be run before calculate CDS, so neighbors are in correct state
      // RGO.  Require state to be INIT before changing to TWOWAY.
      // This is necessary if multiple consecutive Hellos are required
      // for changing state from DOWN to INIT in hello_received().
      // ospf6_neighbor_state_change (OSPF6_NEIGHBOR_TWOWAY, on);
      if (on->state == OSPF6_NEIGHBOR_INIT) // For consecutive_hellos
        ospf6_neighbor_state_change (OSPF6_NEIGHBOR_TWOWAY, on);
      return 0; 
    }
#endif //OSPF6_MANET_MDR_FLOOD
  }
#endif //OSPF6_MANET

  if (! need_adjacency (on))
    {
      ospf6_neighbor_state_change (OSPF6_NEIGHBOR_TWOWAY, on);
      return 0;
    }

  ospf6_neighbor_state_change (OSPF6_NEIGHBOR_EXSTART, on);
  SET_FLAG (on->dbdesc_bits, OSPF6_DBDESC_MSBIT);
  SET_FLAG (on->dbdesc_bits, OSPF6_DBDESC_MBIT);
  SET_FLAG (on->dbdesc_bits, OSPF6_DBDESC_IBIT);

  THREAD_OFF (on->thread_send_dbdesc);
  on->thread_send_dbdesc =
    thread_add_event (master, ospf6_dbdesc_send, on, 0);

  return 0;
}

int
negotiation_done (struct thread *thread)
{
  struct ospf6_neighbor *on;
  struct ospf6_lsa *lsa;

  on = (struct ospf6_neighbor *) THREAD_ARG (thread);
  assert (on);

  if (on->state != OSPF6_NEIGHBOR_EXSTART)
    return 0;

  if (IS_OSPF6_DEBUG_NEIGHBOR (EVENT))
    zlog_debug ("Neighbor Event %s: *NegotiationDone*", on->name);

  /* clear ls-list */
  ospf6_lsdb_remove_all (on->summary_list);
  ospf6_lsdb_remove_all (on->request_list);
  for (lsa = ospf6_lsdb_head (on->retrans_list); lsa;
       lsa = ospf6_lsdb_next (lsa))
    {
      ospf6_decrement_retrans_count (lsa);
      ospf6_lsdb_remove (lsa, on->retrans_list);
    }

  /* Interface scoped LSAs */
  for (lsa = ospf6_lsdb_head (on->ospf6_if->lsdb); lsa;
       lsa = ospf6_lsdb_next (lsa))
    {
#ifdef OSPF6_MANET_TEMPORARY_LSDB
      if (lsa->cache == 1)
        continue;  //lsa received in state below exchange
#endif //OSPF6_MANET_TEMPORARY_LSDB
      if (OSPF6_LSA_IS_MAXAGE (lsa))
        {
#ifdef OSPF6_DELAYED_FLOOD
          set_time(&lsa->rxmt_time);
#endif //OSPF6_DELAYED_FLOOD
          ospf6_increment_retrans_count (lsa);
          ospf6_lsdb_add (ospf6_lsa_copy (lsa), on->retrans_list);
        }
      else
        ospf6_lsdb_add (ospf6_lsa_copy (lsa), on->summary_list);
    }

  /* Area scoped LSAs */
  for (lsa = ospf6_lsdb_head (on->ospf6_if->area->lsdb); lsa;
       lsa = ospf6_lsdb_next (lsa))
    {
#ifdef OSPF6_MANET_TEMPORARY_LSDB
      if (lsa->cache == 1)
        continue;  //lsa received in state below exchange
#endif //OSPF6_MANET_TEMPORARY_LSDB
      if (OSPF6_LSA_IS_MAXAGE (lsa))
        {
#ifdef OSPF6_DELAYED_FLOOD
          set_time(&lsa->rxmt_time);
#endif //OSPF6_DELAYED_FLOOD
          ospf6_increment_retrans_count (lsa);
          ospf6_lsdb_add (ospf6_lsa_copy (lsa), on->retrans_list);
        }
      else
        ospf6_lsdb_add (ospf6_lsa_copy (lsa), on->summary_list);
    }

  /* AS scoped LSAs */
  for (lsa = ospf6_lsdb_head (on->ospf6_if->area->ospf6->lsdb); lsa;
       lsa = ospf6_lsdb_next (lsa))
    {
#ifdef OSPF6_MANET_TEMPORARY_LSDB
      if (lsa->cache == 1)
        continue;  //lsa received in state below exchange
#endif //OSPF6_MANET_TEMPORARY_LSDB
      if (OSPF6_LSA_IS_MAXAGE (lsa))
        {
#ifdef OSPF6_DELAYED_FLOOD
          set_time(&lsa->rxmt_time);
#endif //OSPF6_DELAYED_FLOOD
          ospf6_increment_retrans_count (lsa);
          ospf6_lsdb_add (ospf6_lsa_copy (lsa), on->retrans_list);
        }
      else
        ospf6_lsdb_add (ospf6_lsa_copy (lsa), on->summary_list);
    }

  UNSET_FLAG (on->dbdesc_bits, OSPF6_DBDESC_IBIT);
  ospf6_neighbor_state_change (OSPF6_NEIGHBOR_EXCHANGE, on);

  return 0;
}

int
exchange_done (struct thread *thread)
{
  struct ospf6_neighbor *on;

  on = (struct ospf6_neighbor *) THREAD_ARG (thread);
  assert (on);

  if (on->state != OSPF6_NEIGHBOR_EXCHANGE)
    return 0;

  if (IS_OSPF6_DEBUG_NEIGHBOR (EVENT))
    zlog_debug ("Neighbor Event %s: *ExchangeDone*", on->name);

  THREAD_OFF (on->thread_send_dbdesc);
  ospf6_lsdb_remove_all (on->dbdesc_list);

/* XXX
  thread_add_timer (master, ospf6_neighbor_last_dbdesc_release, on,
                    on->ospf6_if->dead_interval);
*/

  if (on->request_list->count == 0)
    ospf6_neighbor_state_change (OSPF6_NEIGHBOR_FULL, on);
  else
    ospf6_neighbor_state_change (OSPF6_NEIGHBOR_LOADING, on);

  return 0;
}

int
loading_done (struct thread *thread)
{
  struct ospf6_neighbor *on;

  on = (struct ospf6_neighbor *) THREAD_ARG (thread);
  assert (on);

  if (on->state != OSPF6_NEIGHBOR_LOADING)
    return 0;

  if (IS_OSPF6_DEBUG_NEIGHBOR (EVENT))
    zlog_debug ("Neighbor Event %s: *LoadingDone*", on->name);

  assert (on->request_list->count == 0);

  ospf6_neighbor_state_change (OSPF6_NEIGHBOR_FULL, on);

  return 0;
}

int
adj_ok (struct thread *thread)
{
  struct ospf6_neighbor *on;
  struct ospf6_lsa *lsa;

  on = (struct ospf6_neighbor *) THREAD_ARG (thread);
  assert (on);

  if (IS_OSPF6_DEBUG_NEIGHBOR (EVENT))
    zlog_debug ("Neighbor Event %s: *AdjOK?*", on->name);

  if (on->state == OSPF6_NEIGHBOR_TWOWAY && need_adjacency (on))
    {
      ospf6_neighbor_state_change (OSPF6_NEIGHBOR_EXSTART, on);
      SET_FLAG (on->dbdesc_bits, OSPF6_DBDESC_MSBIT);
      SET_FLAG (on->dbdesc_bits, OSPF6_DBDESC_MBIT);
      SET_FLAG (on->dbdesc_bits, OSPF6_DBDESC_IBIT);

      THREAD_OFF (on->thread_send_dbdesc);
      on->thread_send_dbdesc =
        thread_add_event (master, ospf6_dbdesc_send, on, 0);

    }
  else if (on->state >= OSPF6_NEIGHBOR_EXSTART &&
           ! need_adjacency (on))
    {
      ospf6_neighbor_state_change (OSPF6_NEIGHBOR_TWOWAY, on);
      ospf6_lsdb_remove_all (on->summary_list);
      ospf6_lsdb_remove_all (on->request_list);
      for (lsa = ospf6_lsdb_head (on->retrans_list); lsa;
           lsa = ospf6_lsdb_next (lsa))
        {
          ospf6_decrement_retrans_count (lsa);
          ospf6_lsdb_remove (lsa, on->retrans_list);
        }
    }

  return 0;
}

int
seqnumber_mismatch (struct thread *thread)
{
  struct ospf6_neighbor *on;
  struct ospf6_lsa *lsa;

  on = (struct ospf6_neighbor *) THREAD_ARG (thread);
  assert (on);

  if (on->state < OSPF6_NEIGHBOR_EXCHANGE)
    return 0;

  if (IS_OSPF6_DEBUG_NEIGHBOR (EVENT))
    zlog_debug ("Neighbor Event %s: *SeqNumberMismatch*", on->name);

  ospf6_neighbor_state_change (OSPF6_NEIGHBOR_EXSTART, on);
  SET_FLAG (on->dbdesc_bits, OSPF6_DBDESC_MSBIT);
  SET_FLAG (on->dbdesc_bits, OSPF6_DBDESC_MBIT);
  SET_FLAG (on->dbdesc_bits, OSPF6_DBDESC_IBIT);

  ospf6_lsdb_remove_all (on->summary_list);
  ospf6_lsdb_remove_all (on->request_list);
  for (lsa = ospf6_lsdb_head (on->retrans_list); lsa;
       lsa = ospf6_lsdb_next (lsa))
    {
      ospf6_decrement_retrans_count (lsa);
      ospf6_lsdb_remove (lsa, on->retrans_list);
    }

  THREAD_OFF (on->thread_send_dbdesc);
  on->thread_send_dbdesc =
    thread_add_event (master, ospf6_dbdesc_send, on, 0);

  return 0;
}

int
bad_lsreq (struct thread *thread)
{
  struct ospf6_neighbor *on;
  struct ospf6_lsa *lsa;

  on = (struct ospf6_neighbor *) THREAD_ARG (thread);
  assert (on);

  if (on->state < OSPF6_NEIGHBOR_EXCHANGE)
    return 0;

  if (IS_OSPF6_DEBUG_NEIGHBOR (EVENT))
    zlog_debug ("Neighbor Event %s: *BadLSReq*", on->name);

  ospf6_neighbor_state_change (OSPF6_NEIGHBOR_EXSTART, on);
  SET_FLAG (on->dbdesc_bits, OSPF6_DBDESC_MSBIT);
  SET_FLAG (on->dbdesc_bits, OSPF6_DBDESC_MBIT);
  SET_FLAG (on->dbdesc_bits, OSPF6_DBDESC_IBIT);

  ospf6_lsdb_remove_all (on->summary_list);
  ospf6_lsdb_remove_all (on->request_list);
  for (lsa = ospf6_lsdb_head (on->retrans_list); lsa;
       lsa = ospf6_lsdb_next (lsa))
    {
      ospf6_decrement_retrans_count (lsa);
      ospf6_lsdb_remove (lsa, on->retrans_list);
    }

  THREAD_OFF (on->thread_send_dbdesc);
  on->thread_send_dbdesc =
    thread_add_event (master, ospf6_dbdesc_send, on, 0);

  return 0;
}

int
oneway_received (struct thread *thread)
{
  struct ospf6_neighbor *on;
  struct ospf6_lsa *lsa;

  on = (struct ospf6_neighbor *) THREAD_ARG (thread);
  assert (on);

  if (on->state < OSPF6_NEIGHBOR_TWOWAY)
    return 0;


  if (IS_OSPF6_DEBUG_NEIGHBOR (EVENT))
    zlog_debug ("Neighbor Event %s: *1Way-Received*", on->name);

  ospf6_neighbor_state_change (OSPF6_NEIGHBOR_INIT, on);
  thread_add_event (master, neighbor_change, on->ospf6_if, 0);

  ospf6_lsdb_remove_all (on->summary_list);
  ospf6_lsdb_remove_all (on->request_list);
  for (lsa = ospf6_lsdb_head (on->retrans_list); lsa;
       lsa = ospf6_lsdb_next (lsa))
    {
      ospf6_decrement_retrans_count (lsa);
      ospf6_lsdb_remove (lsa, on->retrans_list);
    }

  THREAD_OFF (on->thread_send_dbdesc);
  THREAD_OFF (on->thread_send_lsreq);
  THREAD_OFF (on->thread_send_lsupdate);
  THREAD_OFF (on->thread_send_lsack);

#ifdef OSPF6_MANET
  if (on->ospf6_if->type == OSPF6_IFTYPE_MANETRELIABLE)
  {
#ifdef OSPF6_MANET_MPR_FLOOD
    if (on->ospf6_if->flooding == OSPF6_FLOOD_MPR_SDCDS)
    {
#ifdef OSPF6_MANET_DIFF_HELLO
      on->ospf6_if->increment_scs = true;
      on->below_exchange = true;
#endif //OSPF6_MANET_DIFF_HELLO
    }
#endif //OSPF6_MANET_MPR_FLOOD
  }
#endif //OSPF6_MANET
  return 0;
}

int
inactivity_timer (struct thread *thread)
{
  struct ospf6_neighbor *on;

  on = (struct ospf6_neighbor *) THREAD_ARG (thread);
  assert (on);

  if (IS_OSPF6_DEBUG_NEIGHBOR (EVENT))
    zlog_debug ("Neighbor Event %s: *InactivityTimer*", on->name);

#ifdef SIM_ETRACE_STAT
 TraceEvent_sim(2,"Neighbor Event %s: *InactivityTimer*", on->name);
#endif //SIM_ETRACE_STAT

  on->inactivity_timer = NULL;
  on->drouter = on->prev_drouter = 0;
  on->bdrouter = on->prev_bdrouter = 0;

  ospf6_neighbor_state_change (OSPF6_NEIGHBOR_DOWN, on);
  thread_add_event (master, neighbor_change, on->ospf6_if, 0);

  listnode_delete (on->ospf6_if->neighbor_list, on);
#ifdef OSPF6_MANET
  if (on->ospf6_if->type == OSPF6_IFTYPE_MANETRELIABLE)
  {
#ifdef OSPF6_MANET_MDR_FLOOD
    if (on->ospf6_if->flooding == OSPF6_FLOOD_MDR_SICDS)
    {
      // The following two functions are called when Hello
      // is received, but no hello is received in this case.
      ospf6_calculate_mdr(on->ospf6_if);
      ospf6_mdr_update_adjacencies(on->ospf6_if);
    }
#endif //OSPF6_MANET_MDR_FLOOD
  }
#endif //OSPF6_MANET
  ospf6_neighbor_delete (on);

  return 0;
}


/* vty functions */
/* show neighbor structure */
void
ospf6_neighbor_show (struct vty *vty, struct ospf6_neighbor *on)
{
  char router_id[16];
  char duration[16];
  struct timeval now, res;
  char nstate[16];
  char deadtime[16];
  long h, m, s;

  /* Router-ID (Name) */
  inet_ntop (AF_INET, &on->router_id, router_id, sizeof (router_id));
#ifdef HAVE_GETNAMEINFO
  {
  }
#endif /*HAVE_GETNAMEINFO*/

#ifdef SIM
  gettimeofday_sim (&now, NULL);
#else
  gettimeofday (&now, NULL);
#endif //SIM

  /* Dead time */
  h = m = s = 0;
  if (on->inactivity_timer)
    {
      s = on->inactivity_timer->u.sands.tv_sec - now.tv_sec;
      h = s / 3600;
      s -= h * 3600;
      m = s / 60;
      s -= m * 60;
    }
  snprintf (deadtime, sizeof (deadtime), "%02ld:%02ld:%02ld", h, m, s);

  /* Neighbor State */
#ifdef OSPF6_CONFIG
       if(on->ospf6_if->type == OSPF6_IFTYPE_POINTOMULTIPOINT ||
          on->ospf6_if->type == OSPF6_IFTYPE_POINTOPOINT ||
          on->ospf6_if->type == OSPF6_IFTYPE_MANETRELIABLE)
#else
  if (if_is_pointopoint (on->ospf6_if->interface))
#endif //OSPF6_CONFIG
    snprintf (nstate, sizeof (nstate), "PointToPoint");
  else
    {
      if (on->router_id == on->drouter)
        snprintf (nstate, sizeof (nstate), "DR");
      else if (on->router_id == on->bdrouter)
        snprintf (nstate, sizeof (nstate), "BDR");
      else
        snprintf (nstate, sizeof (nstate), "DROther");
    }

  /* Duration */
  timersub (&now, &on->last_changed, &res);
  timerstring (&res, duration, sizeof (duration));

  /*
  vty_out (vty, "%-15s %3d %11s %6s/%-12s %11s %s[%s]%s",
           "Neighbor ID", "Pri", "DeadTime", "State", "", "Duration",
           "I/F", "State", VNL);
  */

  vty_out (vty, "%-15s %3d %11s %6s/%-12s %11s %s[%s]%s",
           router_id, on->priority, deadtime,
           ospf6_neighbor_state_str[on->state], nstate, duration,
           on->ospf6_if->interface->name,
           ospf6_interface_state_str[on->ospf6_if->state], VNL);
}

void
ospf6_neighbor_show_drchoice (struct vty *vty, struct ospf6_neighbor *on)
{
  char router_id[16];
  char drouter[16], bdrouter[16];
  char duration[16];
  struct timeval now, res;

/*
    vty_out (vty, "%-15s %6s/%-11s %-15s %-15s %s[%s]%s",
             "RouterID", "State", "Duration", "DR", "BDR", "I/F",
             "State", VNL);
*/

  inet_ntop (AF_INET, &on->router_id, router_id, sizeof (router_id));
  inet_ntop (AF_INET, &on->drouter, drouter, sizeof (drouter));
  inet_ntop (AF_INET, &on->bdrouter, bdrouter, sizeof (bdrouter));

#ifdef SIM
  gettimeofday_sim (&now, NULL);
#else
  gettimeofday (&now, NULL);
#endif //SIM
  timersub (&now, &on->last_changed, &res);
  timerstring (&res, duration, sizeof (duration));

  vty_out (vty, "%-15s %6s/%-11s %-15s %-15s %s[%s]%s",
           router_id, ospf6_neighbor_state_str[on->state],
           duration, drouter, bdrouter, on->ospf6_if->interface->name,
           ospf6_interface_state_str[on->ospf6_if->state],
           VNL);
}

void
ospf6_neighbor_show_detail (struct vty *vty, struct ospf6_neighbor *on)
{
  char drouter[16], bdrouter[16];
  char linklocal_addr[64], duration[32];
  struct timeval now, res;
  struct ospf6_lsa *lsa;

  inet_ntop (AF_INET6, &on->linklocal_addr, linklocal_addr,
             sizeof (linklocal_addr));
  inet_ntop (AF_INET, &on->drouter, drouter, sizeof (drouter));
  inet_ntop (AF_INET, &on->bdrouter, bdrouter, sizeof (bdrouter));

#ifdef SIM
  gettimeofday_sim (&now, NULL);
#else
  gettimeofday (&now, NULL);
#endif //SIM
  timersub (&now, &on->last_changed, &res);
  timerstring (&res, duration, sizeof (duration));

  vty_out (vty, " Neighbor %s%s", on->name,
           VNL);
  vty_out (vty, "    Area %s via interface %s (ifindex %d)%s",
           on->ospf6_if->area->name,
           on->ospf6_if->interface->name,
           on->ospf6_if->interface->ifindex,
           VNL);
  vty_out (vty, "    His IfIndex: %d Link-local address: %s%s",
           on->ifindex, linklocal_addr,
           VNL);
  vty_out (vty, "    State %s for a duration of %s%s",
           ospf6_neighbor_state_str[on->state], duration,
           VNL);
  vty_out (vty, "    His choice of DR/BDR %s/%s, Priority %d%s",
           drouter, bdrouter, on->priority,
           VNL);
  vty_out (vty, "    DbDesc status: %s%s%s SeqNum: %#lx%s",
           (CHECK_FLAG (on->dbdesc_bits, OSPF6_DBDESC_IBIT) ? "Initial " : ""),
           (CHECK_FLAG (on->dbdesc_bits, OSPF6_DBDESC_MBIT) ? "More " : ""),
           (CHECK_FLAG (on->dbdesc_bits, OSPF6_DBDESC_MSBIT) ?
            "Master" : "Slave"), (u_long) ntohl (on->dbdesc_seqnum),
           VNL);

  vty_out (vty, "    Summary-List: %d LSAs%s", on->summary_list->count,
           VNL);
  for (lsa = ospf6_lsdb_head (on->summary_list); lsa;
       lsa = ospf6_lsdb_next (lsa))
    vty_out (vty, "      %s%s", lsa->name, VNL);

  vty_out (vty, "    Request-List: %d LSAs%s", on->request_list->count,
           VNL);
  for (lsa = ospf6_lsdb_head (on->request_list); lsa;
       lsa = ospf6_lsdb_next (lsa))
    vty_out (vty, "      %s%s", lsa->name, VNL);

  vty_out (vty, "    Retrans-List: %d LSAs%s", on->retrans_list->count,
           VNL);
  for (lsa = ospf6_lsdb_head (on->retrans_list); lsa;
       lsa = ospf6_lsdb_next (lsa))
    vty_out (vty, "      %s%s", lsa->name, VNL);

  timerclear (&res);
  if (on->thread_send_dbdesc)
    timersub (&on->thread_send_dbdesc->u.sands, &now, &res);
  timerstring (&res, duration, sizeof (duration));
  vty_out (vty, "    %d Pending LSAs for DbDesc in Time %s [thread %s]%s",
           on->dbdesc_list->count, duration,
           (on->thread_send_dbdesc ? "on" : "off"),
           VNL);
  for (lsa = ospf6_lsdb_head (on->dbdesc_list); lsa;
       lsa = ospf6_lsdb_next (lsa))
    vty_out (vty, "      %s%s", lsa->name, VNL);

  timerclear (&res);
  if (on->thread_send_lsreq)
    timersub (&on->thread_send_lsreq->u.sands, &now, &res);
  timerstring (&res, duration, sizeof (duration));
  vty_out (vty, "    %d Pending LSAs for LSReq in Time %s [thread %s]%s",
           on->lsreq_list->count, duration,
           (on->thread_send_lsreq ? "on" : "off"),
           VNL);
  for (lsa = ospf6_lsdb_head (on->lsreq_list); lsa;
       lsa = ospf6_lsdb_next (lsa))
    vty_out (vty, "      %s%s", lsa->name, VNL);

  timerclear (&res);
  if (on->thread_send_lsupdate)
    timersub (&on->thread_send_lsupdate->u.sands, &now, &res);
  timerstring (&res, duration, sizeof (duration));
  vty_out (vty, "    %d Pending LSAs for LSUpdate in Time %s [thread %s]%s",
           on->lsupdate_list->count, duration,
           (on->thread_send_lsupdate ? "on" : "off"),
           VNL);
  for (lsa = ospf6_lsdb_head (on->lsupdate_list); lsa;
       lsa = ospf6_lsdb_next (lsa))
    vty_out (vty, "      %s%s", lsa->name, VNL);

  timerclear (&res);
  if (on->thread_send_lsack)
    timersub (&on->thread_send_lsack->u.sands, &now, &res);
  timerstring (&res, duration, sizeof (duration));
  vty_out (vty, "    %d Pending LSAs for LSAck in Time %s [thread %s]%s",
           on->lsack_list->count, duration,
           (on->thread_send_lsack ? "on" : "off"),
           VNL);
  for (lsa = ospf6_lsdb_head (on->lsack_list); lsa;
       lsa = ospf6_lsdb_next (lsa))
    vty_out (vty, "      %s%s", lsa->name, VNL);

}

DEFUN (show_ipv6_ospf6_neighbor,
       show_ipv6_ospf6_neighbor_cmd,
       "show ipv6 ospf6 neighbor",
       SHOW_STR
       IP6_STR
       OSPF6_STR
       "Neighbor list\n"
      )
{
  struct ospf6_neighbor *on;
  struct ospf6_interface *oi;
  struct ospf6_area *oa;
  struct listnode *i, *j, *k;
  void (*showfunc) (struct vty *, struct ospf6_neighbor *);

  OSPF6_CMD_CHECK_RUNNING ();
  showfunc = ospf6_neighbor_show;

  if (argc)
    {
      if (! strncmp (argv[0], "de", 2))
        showfunc = ospf6_neighbor_show_detail;
      else if (! strncmp (argv[0], "dr", 2))
        showfunc = ospf6_neighbor_show_drchoice;
    }

  if (showfunc == ospf6_neighbor_show)
    vty_out (vty, "%-15s %3s %11s %6s/%-12s %11s %s[%s]%s",
             "Neighbor ID", "Pri", "DeadTime", "State", "IfState", "Duration",
             "I/F", "State", VNL);
  else if (showfunc == ospf6_neighbor_show_drchoice)
    vty_out (vty, "%-15s %6s/%-11s %-15s %-15s %s[%s]%s",
             "RouterID", "State", "Duration", "DR", "BDR", "I/F",
             "State", VNL);

  for (i = listhead (ospf6->area_list); i; nextnode (i))
    {
      oa = (struct ospf6_area *) getdata (i);
      for (j = listhead (oa->if_list); j; nextnode (j))
        {
          oi = (struct ospf6_interface *) getdata (j);
          for (k = listhead (oi->neighbor_list); k; nextnode (k))
            {
              on = (struct ospf6_neighbor *) getdata (k);
              (*showfunc) (vty, on);
            }
        }
    }
  return CMD_SUCCESS;
}

ALIAS (show_ipv6_ospf6_neighbor,
       show_ipv6_ospf6_neighbor_detail_cmd,
       "show ipv6 ospf6 neighbor (detail|drchoice)",
       SHOW_STR
       IP6_STR
       OSPF6_STR
       "Neighbor list\n"
       "Display details\n"
       "Display DR choices\n"
      );

DEFUN (show_ipv6_ospf6_neighbor_one,
       show_ipv6_ospf6_neighbor_one_cmd,
       "show ipv6 ospf6 neighbor A.B.C.D",
       SHOW_STR
       IP6_STR
       OSPF6_STR
       "Neighbor list\n"
       "Specify Router-ID as IPv4 address notation\n"
      )
{
  struct ospf6_neighbor *on;
  struct ospf6_interface *oi;
  struct ospf6_area *oa;
  struct listnode *i, *j, *k;
  void (*showfunc) (struct vty *, struct ospf6_neighbor *);
  u_int32_t router_id;

  OSPF6_CMD_CHECK_RUNNING ();
  showfunc = ospf6_neighbor_show_detail;

  if ((inet_pton (AF_INET, argv[0], &router_id)) != 1)
    {
      vty_out (vty, "Router-ID is not parsable: %s%s", argv[0],
               VNL);
      return CMD_SUCCESS;
    }

  for (i = listhead (ospf6->area_list); i; nextnode (i))
    {
      oa = (struct ospf6_area *) getdata (i);
      for (j = listhead (oa->if_list); j; nextnode (j))
        {
          oi = (struct ospf6_interface *) getdata (j);
          for (k = listhead (oi->neighbor_list); k; nextnode (k))
            {
              on = (struct ospf6_neighbor *) getdata (k);
              if (on->router_id == router_id)
                (*showfunc) (vty, on);
            }
        }
    }
  return CMD_SUCCESS;
}

void
ospf6_neighbor_init ()
{
  install_element (VIEW_NODE, &show_ipv6_ospf6_neighbor_cmd);
  install_element (VIEW_NODE, &show_ipv6_ospf6_neighbor_detail_cmd);
  install_element (ENABLE_NODE, &show_ipv6_ospf6_neighbor_cmd);
  install_element (ENABLE_NODE, &show_ipv6_ospf6_neighbor_detail_cmd);
}

DEFUN (debug_ospf6_neighbor,
       debug_ospf6_neighbor_cmd,
       "debug ospf6 neighbor",
       DEBUG_STR
       OSPF6_STR
       "Debug OSPFv3 Neighbor\n"
      )
{
  unsigned char level = 0;
  if (argc)
    {
      if (! strncmp (argv[0], "s", 1))
        level = OSPF6_DEBUG_NEIGHBOR_STATE;
      if (! strncmp (argv[0], "e", 1))
        level = OSPF6_DEBUG_NEIGHBOR_EVENT;
    }
  else
    level = OSPF6_DEBUG_NEIGHBOR_STATE | OSPF6_DEBUG_NEIGHBOR_EVENT;

  OSPF6_DEBUG_NEIGHBOR_ON (level);
  return CMD_SUCCESS;
}

ALIAS (debug_ospf6_neighbor,
       debug_ospf6_neighbor_detail_cmd,
       "debug ospf6 neighbor (state|event)",
       DEBUG_STR
       OSPF6_STR
       "Debug OSPFv3 Neighbor\n"
       "Debug OSPFv3 Neighbor State Change\n"
       "Debug OSPFv3 Neighbor Event\n"
      );

DEFUN (no_debug_ospf6_neighbor,
       no_debug_ospf6_neighbor_cmd,
       "no debug ospf6 neighbor",
       NO_STR
       DEBUG_STR
       OSPF6_STR
       "Debug OSPFv3 Neighbor\n"
      )
{
  unsigned char level = 0;
  if (argc)
    {
      if (! strncmp (argv[0], "s", 1))
        level = OSPF6_DEBUG_NEIGHBOR_STATE;
      if (! strncmp (argv[0], "e", 1))
        level = OSPF6_DEBUG_NEIGHBOR_EVENT;
    }
  else
    level = OSPF6_DEBUG_NEIGHBOR_STATE | OSPF6_DEBUG_NEIGHBOR_EVENT;

  OSPF6_DEBUG_NEIGHBOR_OFF (level);
  return CMD_SUCCESS;
}

ALIAS (no_debug_ospf6_neighbor,
       no_debug_ospf6_neighbor_detail_cmd,
       "no debug ospf6 neighbor (state|event)",
       NO_STR
       DEBUG_STR
       OSPF6_STR
       "Debug OSPFv3 Neighbor\n"
       "Debug OSPFv3 Neighbor State Change\n"
       "Debug OSPFv3 Neighbor Event\n"
      );

int
config_write_ospf6_debug_neighbor (struct vty *vty)
{
  if (IS_OSPF6_DEBUG_NEIGHBOR (STATE) &&
      IS_OSPF6_DEBUG_NEIGHBOR (EVENT))
    vty_out (vty, "debug ospf6 neighbor%s", VNL);
  else if (IS_OSPF6_DEBUG_NEIGHBOR (STATE))
    vty_out (vty, "debug ospf6 neighbor state%s", VNL);
  else if (IS_OSPF6_DEBUG_NEIGHBOR (EVENT))
    vty_out (vty, "debug ospf6 neighbor event%s", VNL);
  return 0;
}

void
install_element_ospf6_debug_neighbor ()
{
  install_element (ENABLE_NODE, &debug_ospf6_neighbor_cmd);
  install_element (ENABLE_NODE, &debug_ospf6_neighbor_detail_cmd);
  install_element (ENABLE_NODE, &no_debug_ospf6_neighbor_cmd);
  install_element (ENABLE_NODE, &no_debug_ospf6_neighbor_detail_cmd);
  install_element (CONFIG_NODE, &debug_ospf6_neighbor_cmd);
  install_element (CONFIG_NODE, &debug_ospf6_neighbor_detail_cmd);
  install_element (CONFIG_NODE, &no_debug_ospf6_neighbor_cmd);
  install_element (CONFIG_NODE, &no_debug_ospf6_neighbor_detail_cmd);
}


#ifdef OSPF6_MANET

#ifdef OSPF6_MANET_MPR_FLOOD
void update_2hop_neighbor_list(struct ospf6_neighbor *o6n,
                               struct ospf6_lsa_header *lsa_header)
{
  struct listnode *n = NULL;
  u_int32_t router_id;
  struct ospf6_neighbor *on = NULL;
  struct ospf6_2hop_neighbor *o62n = NULL;
  struct ospf6_interface *o6i = o6n->ospf6_if;
  char *start, *end, *current;
  struct ospf6_router_lsa *router_lsa;
  struct ospf6_router_lsdesc *router_lsd;

  if (o6n->state == OSPF6_NEIGHBOR_FULL)  //XXX OR/SP
  {
    router_lsa = (struct ospf6_router_lsa *)
                 ((char *) lsa_header + sizeof (struct ospf6_lsa_header));
    start = (char *) router_lsa + sizeof (struct ospf6_router_lsa);
    end = (char *) lsa_header + ntohs (lsa_header->length);
    for (current = start; current + sizeof (struct ospf6_router_lsdesc) <= end;
         current += sizeof (struct ospf6_router_lsdesc))
    {
      router_lsd = (struct ospf6_router_lsdesc *) current;
      router_id = router_lsd->neighbor_router_id;
      if (ntohl(router_lsd->interface_id) != o6n->ifindex)
        continue;  //link must be on MANET subnet
#ifdef OSPF6_MANET_MPR_SP
      if (ROUTER_LSDESC_IS_UNSYNC(router_lsd)) //BUGFIX_SP
        continue;
#endif //OSPF6_MANET_MPR_SP
      on = ospf6_neighbor_lookup(router_id, o6i);
      if ((!on || on->state < OSPF6_NEIGHBOR_FULL) &&  //XXX OR/SP
          router_id != ospf6->router_id)
      {  //can't be a one hop and a two hop neighbor 
         //and can't be the router itself
        o62n = ospf6_2hop_neighbor_lookup(router_id,o6n->two_hop_neighbor_list);
        if(!o62n)
          o62n = ospf6_add_2hop_neighbor(router_id, o6n);
        o62n->updated = true;
      }
    }
  }

  /* clean up any neighbors that no longer exist in router LSA */
  if (o6n->two_hop_neighbor_list)
    n = listhead (o6n->two_hop_neighbor_list);
  while (n)
  {
    o62n = (struct ospf6_2hop_neighbor *) getdata (n);
    nextnode (n);
    if (!o62n->updated)
      ospf6_2hop_neighbor_delete(o6n, o62n);
    else
      o62n->updated = false;
  }
  return;
}

struct ospf6_2hop_neighbor *
ospf6_2hop_neighbor_lookup (u_int32_t router_id,
                       struct list *two_hop_neighbor_list)
{
  struct listnode *n;
  struct ospf6_2hop_neighbor *o62n;

  if (!two_hop_neighbor_list)
    return NULL;

  for (n = listhead(two_hop_neighbor_list); n; nextnode(n))
  {
    o62n = (struct ospf6_2hop_neighbor *) getdata (n);
    if (o62n->router_id == router_id)
      return o62n;
  }
  return NULL;
}

struct ospf6_2hop_neighbor *
ospf6_add_2hop_neighbor(u_int32_t router_id, struct ospf6_neighbor *o6n)
{
  struct listnode *n;
  struct ospf6_2hop_neighbor *o62n = NULL;
  struct ospf6_interface *o6i = o6n->ospf6_if;

  /* is 2hop already in neighbor's neighbor list */
  o62n = ospf6_2hop_neighbor_lookup(router_id,o6n->two_hop_neighbor_list);
  if(o62n)
    return o62n;

  /* is 2hop neighbor another neighbor's 2hop neighbor */
  for (n = listhead(o6i->two_hop_list); n; nextnode(n))
  {
    o62n = (struct ospf6_2hop_neighbor *) getdata(n);
    if (o62n->router_id == router_id)
      break;
    o62n = NULL;
  }

  if(!o62n)
  {
    o62n = (struct ospf6_2hop_neighbor *)
                 malloc(sizeof(struct ospf6_2hop_neighbor));
    o62n->one_hop_neighbor_list = list_new();
    o62n->router_id = router_id;
    listnode_add(o6i->two_hop_list, o62n);
  }
  listnode_add(o6n->two_hop_neighbor_list, o62n);
  listnode_add(o62n->one_hop_neighbor_list, o6n); //didn't check if existing
  o6n->ospf6_if->mpr_change = true;

  return o62n;
}

void ospf6_2hop_list_delete(struct ospf6_neighbor *o6n)
{
  struct listnode *n;
  struct ospf6_2hop_neighbor *o62n = NULL;

  n = listhead(o6n->two_hop_neighbor_list);
  while(n)
  {
    o62n = (struct ospf6_2hop_neighbor *) getdata(n);
    nextnode(n);
    ospf6_2hop_neighbor_delete(o6n, o62n);
  }
  list_delete(o6n->two_hop_neighbor_list);
  o6n->two_hop_neighbor_list = NULL;
}

void ospf6_2hop_neighbor_delete(struct ospf6_neighbor *o6n,
                                struct ospf6_2hop_neighbor *o62n)
{
  listnode_delete(o6n->two_hop_neighbor_list, o62n);
  listnode_delete(o62n->one_hop_neighbor_list, o6n);
  o6n->ospf6_if->mpr_change = true;

  if (o62n->one_hop_neighbor_list->count == 0)
  {
    /* Delete 2hop neighbor from interface list
     * It is no longer a 2hop neighbor of any neighbor
     */
    listnode_delete(o6n->ospf6_if->two_hop_list, o62n);
    list_delete(o62n->one_hop_neighbor_list);
    free(o62n);
  }
}

void ospf6_update_neighborhood(struct ospf6_interface *o6i)
{
  struct listnode *n;
  struct ospf6_area *area = o6i->area;
  struct ospf6_neighbor *o6n;
  struct ospf6_lsa *lsa;
  for (n = listhead(o6i->neighbor_list); n; nextnode(n))
  {
    o6n = (struct ospf6_neighbor *) getdata(n);
    lsa = ospf6_lsdb_lookup(htons(OSPF6_LSTYPE_ROUTER), htonl(0),
                                 o6n->router_id, area->lsdb);
    if (lsa)
      update_2hop_neighbor_list(o6n, lsa->header);
  }
}

#ifdef OSPF6_MANET_MPR_SP
//Changes by:  Stan Ratliff
//Date:  November 1st, 2005
//Reason:  Check if adjacencies need to be added
// Copyright (C) 2005

boolean ospf6_or_update_adjacencies(struct ospf6_interface *oi)
{
  struct listnode *n;
  struct ospf6_neighbor *on;
  boolean new_adjacency = false;

  if (!oi->smart_peering)
    return new_adjacency;

  for (n = listhead(oi->neighbor_list); n; nextnode(n))
  {
    on = (struct ospf6_neighbor *) getdata(n);
    if (on->state != OSPF6_NEIGHBOR_TWOWAY)
      continue;
    if (need_adjacency (on))
    {
      ospf6_neighbor_state_change (OSPF6_NEIGHBOR_EXSTART, on);
      SET_FLAG (on->dbdesc_bits, OSPF6_DBDESC_MSBIT);
      SET_FLAG (on->dbdesc_bits, OSPF6_DBDESC_MBIT);
      SET_FLAG (on->dbdesc_bits, OSPF6_DBDESC_IBIT);

      THREAD_OFF (on->thread_send_dbdesc);
      on->thread_send_dbdesc =
        thread_add_event (master, ospf6_dbdesc_send, on, 0);
      new_adjacency = true;
    }
  }
  return new_adjacency;
}
#endif //OSPF6_MANET_MPR_SP

#ifdef OSPF6_MANET_DIFF_HELLO
/*
 * drop neighbor functions
 */
void ospf6_drop_neighbor_create(struct ospf6_neighbor *o6n)
{
  struct drop_neighbor *drop_neigh = NULL;

  drop_neigh = ospf6_lookup_drop_neighbor(o6n->ospf6_if, o6n->router_id);

  if (!drop_neigh)
  { // new drop neighbor
    drop_neigh = (struct drop_neighbor *) malloc(sizeof(struct drop_neighbor));
  drop_neigh->expire_time = (struct timeval *) malloc(sizeof(struct timeval));
    drop_neigh->router_id = o6n->router_id;
  drop_neigh->first = true;
    listnode_add(o6n->ospf6_if->drop_neighbor_list, drop_neigh);
  }
 set_time(drop_neigh->expire_time);
}

void ospf6_drop_neighbor_delete(struct ospf6_interface *o6i,
                               struct drop_neighbor *dneigh)
{
  listnode_delete(o6i->drop_neighbor_list, dneigh);
 free(dneigh->expire_time);
  free(dneigh);
}

struct drop_neighbor *ospf6_lookup_drop_neighbor(struct ospf6_interface *oi,
                                               u_int32_t id)
{
  struct listnode *n;
  struct drop_neighbor *drop_neigh = NULL;

  n = listhead(oi->drop_neighbor_list);
  while(n)
  {
  drop_neigh = (struct drop_neighbor *) getdata (n);
    nextnode(n);

    if (elapsed_time(drop_neigh->expire_time) > oi->dead_interval)
  {
   ospf6_drop_neighbor_delete(oi, drop_neigh);
  }
    else if (id == drop_neigh->router_id)
      break;
    drop_neigh = NULL;
  }
  return drop_neigh;
}
#endif //OSPF6_MANET_DIFF_HELLO
#endif //OSPF6_MANET_MPR_FLOOD

// Section 3.4.3 bullet 2
void ospf6_store_mack(struct ospf6_neighbor *on,
                      struct ospf6_lsa_header *lsa_header)
{
  struct ospf6_mack *mack = NULL;

  if (on->ospf6_if->type != OSPF6_IFTYPE_MANETRELIABLE)
    return;

  mack = ospf6_lookup_mack(on, lsa_header);

  if (!mack)
  { //mack does not exist, allocate mack and add to mack list
    mack = (struct ospf6_mack *) malloc(sizeof(struct ospf6_mack));
  mack->expire_time = (struct timeval *) malloc(sizeof(struct timeval));
    mack->type = lsa_header->type;
    mack->id = lsa_header->id;
    mack->adv_router = lsa_header->adv_router;
    listnode_add(on->mack_list, mack);
  }
  mack->seqnum = lsa_header->seqnum;
  set_time(mack->expire_time);
  return;
}

struct ospf6_mack *ospf6_lookup_mack(struct ospf6_neighbor *on,
                              struct ospf6_lsa_header *lsa_header)
{
  struct listnode *n;
  struct ospf6_mack *mack = NULL;

  if (on->ospf6_if->type != OSPF6_IFTYPE_MANETRELIABLE)
    return NULL;

  n = listhead(on->mack_list);
  while(n)
  {
    mack = (struct ospf6_mack *) getdata(n);
    nextnode(n);

    if (elapsed_time(mack->expire_time) > on->ospf6_if->ack_cache_timeout)
    {  //delete expired mack
      listnode_delete(on->mack_list, mack);
      free(mack->expire_time);
      free(mack);
      continue;
    }
    if (mack->type == lsa_header->type &&
        mack->id == lsa_header->id &&
        mack->adv_router == lsa_header->adv_router &&
        ntohl(mack->seqnum) >= ntohl(lsa_header->seqnum))
    {
      return mack; // this is the ack being searched for -> return ptr
    }
  }
  return NULL;  // mack not found
}

void ospf6_mack_list_delete(struct ospf6_neighbor *on)
{ //delete all entries in mack list then delete mack list
  struct listnode *n;
  struct ospf6_mack *mack = NULL;

  n = listhead(on->mack_list);
  while(n)
  {
    mack = (struct ospf6_mack *) getdata(n);
    nextnode(n);
  free(mack->expire_time);
    free(mack);
  }
  list_delete(on->mack_list);
 on->mack_list = NULL;
}


#ifdef OSPF6_MANET
int ospf6_manet_update_routable_neighbors(struct ospf6_interface *oi)
// Updates the set of routable neighbors, by checking if a route
// exists to each neighbor. Returns 1 if there is a change.
{
  struct listnode *j;
  struct ospf6_neighbor *on;
  struct ospf6_route *route;
  struct prefix prefix;
  int change = 0;

  for (j = listhead(oi->neighbor_list); j; nextnode(j))
  {
    on = (struct ospf6_neighbor *) getdata (j);
    if (!on) continue;
    ospf6_linkstate_prefix (on->router_id, htonl (0), &prefix);

    if (oi->flooding == OSPF6_FLOOD_MDR_SICDS)
    { 
      route = ospf6_route_lookup(&prefix, on->ospf6_if->area->spf_table);
      if (!on->routable)
      {
#ifdef OSPF6_MANET_MDR_LQ
        int link_quality = 0, i;
        for (i=0; i < 3; i++)  
          link_quality += on->link_quality[i];

        if (on->state == OSPF6_NEIGHBOR_FULL ||
            (route && on->state >= OSPF6_NEIGHBOR_TWOWAY && 
             (!oi->link_quality || (oi->link_quality && link_quality>2)))) 
#else
        if (on->state == OSPF6_NEIGHBOR_FULL ||
            (route && on->state >= OSPF6_NEIGHBOR_TWOWAY &&
             on->reverse_2way)) // RGO. Always require reverse_2way.
#endif //OSPF6_MANET_MDR_LQ
        {
          on->routable = 1;
          change = 1;
        }
      }
      if (on->routable && on->state < OSPF6_NEIGHBOR_TWOWAY)
      {
        on->routable = 0;
        change = 1;
      }
    }
#ifdef OSPF6_MANET_MPR_SP
    if (oi->flooding == OSPF6_FLOOD_MPR_SDCDS)
    {
//      route = ospf6_route_lookup(&prefix,on->ospf6_if->area->spf_table); 
      route = ospf6_route_lookup(&prefix,on->ospf6_if->area->spf_table_sync);//BUGFIX_SP
      //if (route && on->state != OSPF6_NEIGHBOR_FULL)
      //  printf("2.  SP-Route cost %d\n", route->path.cost);
      if (!on->routable && (on->state == OSPF6_NEIGHBOR_FULL ||
          (route && on->state >= OSPF6_NEIGHBOR_TWOWAY)))
      {
        on->routable = 1;
        change = 1;
      }
      if (on->routable && on->state < OSPF6_NEIGHBOR_TWOWAY)
      {
        on->routable = 0;
        change = 1;
      }
    }
#endif //OSPF6_MANET_MPR_SP
  }
  return change;
}



#endif //OSPF6_MANET

#ifdef OSPF6_MANET_MDR_FLOOD
// ospf6_mdr_update_adv_neighbors() was written by Richard Ogier
// and implements min-cost LSAs as described in
// draft-ogier-manet-ospf-extension-06.txt
int ospf6_mdr_update_adv_neighbors(struct ospf6_interface *oi)
{
  struct listnode *j, *k, *u;
  struct ospf6_neighbor *onj, *onk, *onu, *min_onu;
  int change = 0, j_index, k_index, u_index;
  int count = 0;
  int costj, costk, min_cost;
  u_int32_t router_id = oi->area->ospf6->router_id;

  // cost_matrix determines which nbrs are nbrs of each other.
  ospf6_mdr_create_cost_matrix(oi);
  // lsa_cost_matrix gets inter-nbr costs from nbr LSAs
  ospf6_mdr_create_lsa_cost_matrix(oi);

  // Initialize new set of advertised neighbors, so that only
  // FULL neighbors are advertised.
  for (j = listhead(oi->neighbor_list); j; nextnode(j))
  {
    onj = (struct ospf6_neighbor *) getdata (j);
    if (onj->state == OSPF6_NEIGHBOR_FULL) onj->new_adv = true;
    else onj->new_adv = false;
  }

  // For each pair of routable nbrs j, k that are not nbrs of each other,
  // find the best intermediate node u to connect j and k.

  for (j = listhead(oi->neighbor_list); j; nextnode(j))
  {
    onj = (struct ospf6_neighbor *) getdata (j);
    if (!onj) continue;
    if (onj->state < OSPF6_NEIGHBOR_TWOWAY) continue;
    if (!onj->routable) continue;
    j_index = onj->cost_matrix_index;
    for (k = listhead(oi->neighbor_list); k; nextnode(k))
    {
      onk = (struct ospf6_neighbor *) getdata (k);
      if (!onk) continue;
      if (onk->state < OSPF6_NEIGHBOR_TWOWAY) continue;
      if (!onk->routable) continue;
      k_index = onk->cost_matrix_index;
      if (oi->cost_matrix[j_index][k_index] == 1)
        continue; // j and k must not be neighbors of each other

      min_cost = LS_INFINITY; // find min cost 2-hop path between j and k
      min_onu = NULL; // find best intermediate node
      // The difference between LSAFullness MINHOP and MINHOP2PATHS applied
      // here.  For MINHOP, the LSA need not contain links to both j and k,
      // but only to j.  This will determine whether the router should add
      // j to its LSA.  min_cost will be the cost of the link to j.
      // MINHOP2PATHS contains the old MINHOP (requiring links to both j and k)
      for (u = listhead(oi->neighbor_list); u; nextnode(u))
      {
        onu = (struct ospf6_neighbor *) getdata (u);
        if (!onu) continue;
        if (onu->state < OSPF6_NEIGHBOR_TWOWAY) continue;
        u_index = onu->cost_matrix_index;
        if (oi->LSAFullness == OSPF6_LSA_FULLNESS_MINHOP) { 
          if (min_cost > oi->lsa_cost_matrix[u_index][j_index] ||
              (min_cost == oi->lsa_cost_matrix[u_index][j_index] && min_onu &&
               ospf6_sidcds_lexicographic(oi,onu->mdr_level, min_onu->mdr_level,
               0, 0, ntohl(onu->router_id), ntohl(min_onu->router_id))))
          {
            min_onu = onu;
            min_cost = oi->lsa_cost_matrix[u_index][j_index];
          }
        } else if (oi->LSAFullness == OSPF6_LSA_FULLNESS_MINHOP2PATHS) { 
          if (min_cost > oi->lsa_cost_matrix[u_index][k_index] +
                         oi->lsa_cost_matrix[u_index][j_index] ||
              (min_cost == oi->lsa_cost_matrix[u_index][k_index] +
                         oi->lsa_cost_matrix[u_index][j_index] && min_onu &&
               ospf6_sidcds_lexicographic(oi, onu->mdr_level, min_onu->mdr_level,
               0, 0, ntohl(onu->router_id), ntohl(min_onu->router_id))))
          {
            min_onu = onu;
            min_cost = oi->lsa_cost_matrix[u_index][k_index] +
                       oi->lsa_cost_matrix[u_index][j_index];
          }
        } else {
          printf("Wrong LSAFullness in this function\n");
          exit(1);
        }
      }
      // Determine costs to j and k (as would be advertised in LSA)
      if (onj->state == OSPF6_NEIGHBOR_FULL) costj = 10;
      else costj = 11;
      if (onk->state == OSPF6_NEIGHBOR_FULL) costk = 10;
      else costk = 11;

      if (oi->LSAFullness == OSPF6_LSA_FULLNESS_MINHOP) { 
        // If j is advertised, then keep j as adv if min_onu
        // gives a larger cost or the same cost and smaller (mdr_level, rid).
        if (onj->adv)
        {
          if (min_cost > costj || (min_cost == costj &&
              ospf6_sidcds_lexicographic(oi, oi->mdr_level, min_onu->mdr_level,
              0, 0, ntohl(router_id), ntohl(min_onu->router_id))))
         {
            onj->new_adv = true;
          }
        }
        // If j is not advertised, then adv j only if min_onu
        // gives a larger cost.
        if (!onj->adv)
        {
          if (min_cost > costj)
          {
            onj->new_adv = true;
          }
        }
      } else { // LSAFullness == OSPF6_LSA_FULLNESS_MINHOP2PATHS
        // If j and k are both advertised, then keep both as adv if min_onu
        // gives a larger cost or the same cost and smaller (mdr_level, rid).
        if (onj->adv && onk->adv)
        {
          if (min_cost > costj + costk || (min_cost == costj + costk &&
              ospf6_sidcds_lexicographic(oi, oi->mdr_level, min_onu->mdr_level,
              0, 0, ntohl(router_id), ntohl(min_onu->router_id))))
         {
            onj->new_adv = onk->new_adv = true;
          }
        }
        // If j and k are not both advertised, then adv both only if min_onu
        // gives a larger cost.
        if (!onj->adv || !onk->adv)
        {
          if (min_cost > costj + costk)
          {
            onj->new_adv = onk->new_adv = true;
          }
        }
      }
    }
  }
  // Update set of advertised neighbors.
  for (j = listhead(oi->neighbor_list); j; nextnode(j))
  {
    onj = (struct ospf6_neighbor *) getdata (j);
    if (onj->new_adv) count++;
    if (!onj->adv && onj->new_adv)
    {
      onj->adv = true;
      //printf("at %d %d nbr %d changed to %d \n",
          //router_id, oi->interface->ifindex, onj->router_id, onj->adv);
      change = 1;
    }
    if (onj->adv && !onj->new_adv)
    {
      onj->adv = false;
      // Do not indicate a change if nbr changed from adv to not adv
      // but is still 2-way.
      if (onj->state < OSPF6_NEIGHBOR_TWOWAY)
        change = 1;
    }
  }
  //printf("number of adv nbrs %d number of nbrs %d \n",
              //count, oi->neighbor_list->count);
  ospf6_mdr_free_cost_matrix(oi);
  ospf6_mdr_free_lsa_cost_matrix(oi);
  return change;
}

void ospf6_mdr_create_lsa_cost_matrix(struct ospf6_interface *oi)
{
  struct listnode *j; 
  u_int32_t id;
  struct ospf6_neighbor *onj, *onk;
  int count = 0;
  int num_neigh = oi->neighbor_list->count;
  int index2, size; //, metric;
  struct ospf6_lsa *lsa;
  caddr_t lsdesc;

  if (oi->lsa_cost_matrix)
  {
    printf("lsa cost matrix should be NULL\n");
    exit(0);
  }

  //intialize matrix to LS_INFINITY
  oi->lsa_cost_matrix = (int **) malloc(sizeof(int*[num_neigh]));
  for (j = listhead(oi->neighbor_list); j; nextnode(j))
  {
    onj = (struct ospf6_neighbor *) getdata (j);
    //if (!onj) continue;
    //if (onj->state < OSPF6_NEIGHBOR_TWOWAY) continue;
    //onj->cost_matrix_index = count; // Done in create_cost_matrix().
    oi->lsa_cost_matrix[count] = (int *) malloc(sizeof(int[num_neigh]));
    //memset (oi->cost_matrix[count++], 0, sizeof (int[num_neigh]));
    for (index2 = 0; index2 < num_neigh; index2++)
      oi->lsa_cost_matrix[count][index2] = LS_INFINITY;
    count++;
  }

  //set matrix values by looking at each neighbor's LSA
  for (j = listhead(oi->neighbor_list); j; nextnode(j))
  {
    onj = (struct ospf6_neighbor *) getdata (j);
    //if (!onj) continue;
    if (onj->state < OSPF6_NEIGHBOR_TWOWAY) continue;
    lsa = ospf6_lsdb_lookup (htons (OSPF6_LSTYPE_ROUTER), htonl (0),
                             onj->router_id, oi->area->lsdb);
    if (lsa == NULL) continue;
    // For each LS description in the neighbor's LSA
    size = sizeof (struct ospf6_router_lsdesc);
    for (lsdesc = OSPF6_LSA_HEADER_END (lsa->header) + 4;
         lsdesc + size <= OSPF6_LSA_END (lsa->header); lsdesc += size)
    {
      id = ROUTER_LSDESC_GET_NBR_ROUTERID (lsdesc);
      onk = ospf6_neighbor_lookup (id, oi);
      if (!onk) continue;
      oi->lsa_cost_matrix[onj->cost_matrix_index][onk->cost_matrix_index]
        = ROUTER_LSDESC_GET_METRIC (lsdesc);
      //metric  = ROUTER_LSDESC_GET_METRIC (lsdesc);
      //printf("at %d, cost from %d to %d is %d \n",
      //ospf6->router_id, onj->cost_matrix_index, onk->cost_matrix_index, metric);
    }
  }
}

void ospf6_mdr_free_lsa_cost_matrix(struct ospf6_interface *oi)
{
  u_int i;

  //free matrix
  for (i = 0; i < oi->neighbor_list->count; i++)
    free(oi->lsa_cost_matrix[i]);
  free(oi->lsa_cost_matrix);
  oi->lsa_cost_matrix = NULL;
}

void ospf6_mdr_delete_all_neighbors(struct list *n_list)
{
  struct listnode *n;
  u_int32_t *neigh;
  for (n = listhead (n_list); n; nextnode(n))
  {
    neigh = (u_int32_t *) getdata(n);
    free(neigh);
  }
  list_delete_all_node(n_list);
}

void ospf6_mdr_add_neighbor(struct list *n_list, u_int32_t id)
{
  u_int32_t *neigh = (u_int32_t *) malloc(sizeof(u_int32_t));
  *neigh = id;
  listnode_add(n_list, neigh);
}

// ZZZ 
boolean ospf6_mdr_lookup_neighbor(struct list *n_list, u_int32_t id)
{
  struct listnode *n;
  u_int32_t *neigh_id;
  for (n = listhead(n_list); n; nextnode(n))
  {
    neigh_id = (u_int32_t *) getdata(n);
    if (id == *neigh_id)
      return true;
  }
  return false;
}

// Return true if list is changed.
boolean ospf6_mdr_delete_neighbor(struct list *n_list, u_int32_t id)
{
  struct listnode *n;
  u_int32_t *neigh_id;
  boolean changed = false;

  n = listhead(n_list);
  while (n)
  {
    neigh_id = (u_int32_t *) getdata(n);
    nextnode(n);

    if (id == *neigh_id)
    {
      free(neigh_id);
      listnode_delete(n_list, neigh_id);
      changed = true;
    }
  }
  return changed;
}

void ospf6_mdr_delete_neighbor_list(struct list *n_list)
{
  struct listnode *n;
  u_int32_t *id;
  for (n = listhead(n_list); n; nextnode(n))
  {
    id = (u_int32_t *) getdata(n);
    free(id);
  }
  list_delete (n_list);
}
#ifdef OSPF6_MANET_DIFF_HELLO
//HNL Functions
void ospf6_mdr_add_lnl_element(struct ospf6_neighbor *on)
{
  struct ospf6_interface *oi = on->ospf6_if;
  struct ospf6_lnl_element *lnl_element;

  lnl_element = ospf6_mdr_lookup_lnl_element(on);

  if (lnl_element)
  {
    lnl_element->hsn = oi->hsn;
    return;
  }

  lnl_element = 
    (struct ospf6_lnl_element *) malloc(sizeof(struct ospf6_lnl_element));
  lnl_element->id = on->router_id;
  lnl_element->hsn = oi->hsn;
  listnode_add(oi->lnl, lnl_element);
}

struct ospf6_lnl_element *
ospf6_mdr_lookup_lnl_element(struct ospf6_neighbor *on)
{
  struct listnode *n;
  struct ospf6_interface *oi = on->ospf6_if;
  struct ospf6_lnl_element *lnl_element = NULL;

  for (n = listhead(oi->lnl); n; nextnode(n))
  {
    lnl_element = (struct ospf6_lnl_element *) getdata(n);
    if (on->router_id == lnl_element->id)
      return lnl_element;
  }
  return lnl_element;
}

void ospf6_mdr_delete_lnl_element(struct ospf6_interface *oi, 
                                    struct ospf6_lnl_element *lnl_element)
{
  listnode_delete(oi->lnl, lnl_element);
  free(lnl_element);
}

#ifdef OSPF6_MANET_MDR_LQ
void ospf6_mdr_update_link_quality(struct ospf6_neighbor*on, boolean quality)
{
  on->link_quality[0] = on->link_quality[1];
  on->link_quality[1] = on->link_quality[2];
  on->link_quality[2] = quality; 
}
#endif //OSPF6_MANET_MDR_LQ

#endif //OSPF6_MANET_DIFF_HELLO

#endif //OSPF6_MANET_MDR_FLOOD

#endif //OSPF6_MANET
