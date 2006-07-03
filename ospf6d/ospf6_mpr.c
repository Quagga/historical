/*
 * Copyright (C) Boeing Co.
 */

#include "zebra.h" 

#ifdef OSPF6_MANET_MPR_FLOOD

#include "ospf6_mpr.h"
#include "ospf6_area.h"
#ifdef SIM_ETRACE_STAT
#include "sim.h"
#endif //SIM_ETRACE_STAT
#ifdef SIM
#include "ospf6_sim_printing.h"
#endif //SIM

//Chandra03 3.4.4
void ospf6_calculate_relays(struct ospf6_interface *oi)
{
  boolean finished = false;
  int best_coverage, cover_count;
  struct listnode *n, *n2, *N2;
  struct ospf6_neighbor *on, *best;
  struct ospf6_2hop_neighbor *o62n, *o62N;
  struct ospf6_relay *relay;
  u_int32_t id;

  if (!oi->mpr_change)
    return;

  /* initialization */
  for(n = listhead(oi->relay_list); n; nextnode(n))
  {
    relay = (struct ospf6_relay *) getdata(n);
    relay->active = false;
  }
  for(n = listhead(oi->neighbor_list); n; nextnode(n))
  {
    on = (struct ospf6_neighbor *) getdata(n);
    on->covered = false;
  }
  for(n2 = listhead(oi->two_hop_list); n2; nextnode(n2))
  {
    o62n = (struct ospf6_2hop_neighbor *) getdata(n2);
    o62n->covered = false;
  }

  /* 3.  Find 1 hops connected to poorly covered 2 hops */
  for(n2 = listhead(oi->two_hop_list); n2; nextnode(n2))
  {
    o62n = (struct ospf6_2hop_neighbor *) getdata(n2);
    if (!o62n->covered && o62n->one_hop_neighbor_list->count == 1)
    { // this is a poorly covered 2 hop - cover w/ one hop
      n = listhead(o62n->one_hop_neighbor_list);
      on = (struct ospf6_neighbor *) getdata (n);
      if(on->covered)
      {
        o62n->covered = true;
        continue;
      }
      // not covered yet - now mark this one-hop as covered
      on->covered = true;
      // mark all two-hops as covered
      for(N2 = listhead(on->two_hop_neighbor_list); N2; nextnode(N2))
      {
        o62N = (struct ospf6_2hop_neighbor *) getdata(N2);
        o62N->covered = true;
      }
      ospf6_relay_create(oi, on->router_id);
    }
  }

  finished = false;
  /* 4. While uncovered 2 hops exist */
  while(!finished)
  {
    best = NULL;
    best_coverage = 0;
    id = 0;
    /* 4.1 calculate reachability of this one hop */
    for (n = listhead(oi->neighbor_list); n; nextnode(n))
    {
      on = (struct ospf6_neighbor *) getdata(n);
      if (on->state < OSPF6_NEIGHBOR_FULL)  //XXX OR/SP
        continue;
      if (on->covered)
        continue;
      /* count number of two hops that this one hop could cover */
      cover_count = 0;
      for (n2 = listhead(on->two_hop_neighbor_list); n2; nextnode(n2))
      {
        o62n = (struct ospf6_2hop_neighbor *) getdata(n2);
        if (o62n->covered == false)
          cover_count++;
      }
      if (cover_count == 0)
        continue;
      if ((cover_count > best_coverage) ||
          (cover_count == best_coverage && on->router_id > id))
      {
        id = on->router_id;
        best = on;
        best_coverage = cover_count;
      }
    }
    /* 4.2 Add the one hop with the best coverage to the MPR list,
     *  and mark it and its two hops as covered.   */
    if (best)
    {
      best->covered = true;
      for (n2 = listhead(best->two_hop_neighbor_list); n2; nextnode(n2))
      {
        o62n = (struct ospf6_2hop_neighbor *) getdata (n2);
        o62n->covered = true;
      }
      ospf6_relay_create(oi, best->router_id);
    }
    else
    {
      finished = true;
      /* No more uncovered two hops */
    }
  } // end while(!finished)

  // finalize
  oi->mpr_change = false;
  n = listhead(oi->relay_list);
  while(n)
  {
    relay = (struct ospf6_relay *) getdata(n);
    nextnode(n);
    if(!relay->active)
    {
      if(!relay->drop)
      { //this relay was just dropped
        relay->drop = true;
        relay->newly_activated = false;
        set_time(relay->drop_expire_time);
#ifdef OSPF6_MANET_DIFF_HELLO
        oi->increment_scs = true;
#endif //OSPF6_MANET_DIFF_HELLO
      }
      else if (elapsed_time(relay->drop_expire_time) >= oi->dead_interval)
      { //relay was flagged dropped in the past, may need to be removed
        ospf6_relay_delete(oi, relay);
      }
    }
  }
#ifdef SIM_ETRACE_STAT
  ospf6_print_neighborhood_sim(oi);
  ospf6_print_relay_list_sim(oi);
#endif //SIM_ETRACE_STAT
}

void ospf6_relay_create(struct ospf6_interface *oi, u_int32_t id)
{
  struct listnode *n;
  struct ospf6_relay *relay;

  for (n = listhead(oi->relay_list); n; nextnode(n))
  {
    relay = (struct ospf6_relay*) getdata(n);
    if(relay && relay->router_id == id)
    { // relay already in list
   if(relay->active)
    return; //relay already activated

      if (relay->drop)
      {//new relay that was still in drop relay list
        relay->newly_activated = true;
#ifdef OSPF6_MANET_DIFF_HELLO
        oi->increment_scs = true;
#endif //OSPF6_MANET_DIFF_HELLO
      }
      relay->drop = false;
      relay->active = true;
      return;
    }
  }
  /* new relay that was not in the relay list  */
  relay = (struct ospf6_relay *) malloc(sizeof(struct ospf6_relay));
  relay->router_id = id;
  relay->newly_activated = true;  //brand new relay
  relay->active = true;

  relay->drop = false;
  relay->drop_expire_time = (struct timeval *) malloc(sizeof(struct timeval));

  listnode_add(oi->relay_list, relay);
#ifdef OSPF6_MANET_DIFF_HELLO
  oi->increment_scs = true;
#endif //OSPF6_MANET_DIFF_HELLO
  return;
}

void ospf6_relay_delete(struct ospf6_interface *oi,
                        struct ospf6_relay *relay)
{
  listnode_delete(oi->relay_list, relay);
  free(relay->drop_expire_time);
  free(relay);
}

/*
 * Relay Selector Functions
 */
void ospf6_refresh_relay_selector(struct ospf6_neighbor *on)
{
  struct ospf6_relay_selector *relay_sel;
  struct ospf6_interface *oi = on->ospf6_if;

  relay_sel = ospf6_lookup_relay_selector(oi, on->router_id);
  if (!relay_sel)
  {
    relay_sel = (struct ospf6_relay_selector *) 
                malloc(sizeof(struct ospf6_relay_selector));
    relay_sel->expire_time = (struct timeval *) malloc(sizeof(struct timeval));
    relay_sel->router_id = on->router_id;
    listnode_add(oi->relay_sel_list, relay_sel);
    set_time(relay_sel->expire_time);

#ifdef SIM_ETRACE_STAT
    ospf6_print_relay_selector_list_sim(oi);
    float delta = elapsed_time(&oi->relaysel_change_time);
    update_statistics(OSPF6_DURATION_OF_NUM_RELSEL, (double)delta);
    update_statistics(OSPF6_NUM_RELSEL_TIMES_DURATION_OF_NUM_RELSEL, 
                    (double)((oi->relay_sel_list->count-1) * delta));
    set_time(&relay_sel->install_time);
    set_time(&oi->relaysel_change_time);
#endif //SIM_ETRACE_STAT
  }
  else
  {
    set_time(relay_sel->expire_time);
  }
}

struct ospf6_relay_selector
*ospf6_lookup_relay_selector(struct ospf6_interface *oi,
                                                u_int32_t id)
{
  struct listnode *n;
  struct ospf6_relay_selector *relay_sel = NULL;

  if (oi->type != OSPF6_IFTYPE_MANETRELIABLE)
    return NULL;

  if (oi->flooding != OSPF6_FLOOD_MPR_SDCDS)
    return NULL;

  n = listhead(oi->relay_sel_list);
  while(n)
  {
    relay_sel = (struct ospf6_relay_selector *) getdata(n);
    nextnode(n);

    if (elapsed_time(relay_sel->expire_time) > oi->dead_interval)
    {
   ospf6_relay_selector_delete(oi, relay_sel);
    }
    else if (relay_sel->router_id == id)
      break;
    relay_sel = NULL;
  }
  return relay_sel;
}

void ospf6_relay_selector_delete(struct ospf6_interface *oi,
                               struct ospf6_relay_selector *relay_sel)
{
#ifdef SIM_ETRACE_STAT
  float delta = elapsed_time(&oi->relaysel_change_time);
  float lifetime = elapsed_time(&relay_sel->install_time); //Insure
  update_statistics(OSPF6_DURATION_OF_NUM_RELSEL, (double)delta);
  update_statistics(OSPF6_NUM_RELSEL_TIMES_DURATION_OF_NUM_RELSEL,
                    (double)((oi->relay_sel_list->count) * delta));
  update_statistics(OSPF6_RELSEL_LIFETIME, (double)lifetime);
  update_statistics(OSPF6_RELSEL_DEATHS, 1);
  set_time(&oi->relaysel_change_time);
#endif //SIM_ETRACE_STAT

  listnode_delete(oi->relay_sel_list, relay_sel);
  free(relay_sel->expire_time);
  free(relay_sel);

#ifdef SIM_ETRACE_STAT
  ospf6_print_relay_selector_list_sim(oi);
#endif //SIM_ETRACE_STAT
}

#endif //OSPF6_MANET_MPR_FLOOD
