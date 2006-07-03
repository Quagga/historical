/*
** wospf_ack_cache.c
** 
** Made by (Kenneth Holter)
** Login   <kenneho@localhost.localdomain>
** 
** Started on  Fri May  5 17:00:23 2006 Kenneth Holter
** Last update Sat May 27 17:57:00 2006 Kenneth Holter
*/

#include <zebra.h>

#include "vty.h"
#include "ospf6_lsa.h"

#include "log.h"
#include "thread.h"
#include "linklist.h"
#include "vty.h"
#include "command.h"

#include "ospf6d.h"
#include "ospf6_message.h"
#include "ospf6_lsa.h"
#include "ospf6_neighbor.h"
#include "ospf6_interface.h"
#include "ospf6_lsdb.h"

#include "wospf_top.h"
#include "wospf_ack_cache.h"

int wospf_ack_timeout(struct thread *);

void wospf_register_ack(ID router_id, struct ospf6_lsa *his, 
			struct ospf6_interface *oi) {
  struct wospf_neighbor_entry *neighbor =
    wospf_lookup_neighbor_table(router_id);
  
  /* The neighbor is not associated with a MANET interface. Discard. */
  if (neighbor == NULL) return;
  
  ospf6_lsdb_add (ospf6_lsa_copy(his), neighbor->acked_lsa_list);

  WOSPF_PRINTF(2, "Register ack %s with neighbor %s", his->name, neighbor->name);

  /* Must be debugged before operation */
  //thread_add_timer (master, wospf_ack_timeout, ack_node, oi->ack_cache_timeout);
}

int wospf_lookup_ack_cache(ID router_id, struct ospf6_lsa *lsa) {
  struct ospf6_lsa *tmp_lsa;
  
  struct wospf_neighbor_entry *neighbor =
    wospf_lookup_neighbor_table(router_id);

  /* The neighbor is not associated with a MANET interface. Discard. */
  if (neighbor == NULL) return 0;

  tmp_lsa = ospf6_lsdb_lookup(lsa->header->type, lsa->header->id,
			      lsa->header->adv_router, neighbor->acked_lsa_list);

  
  if (tmp_lsa != NULL) {
   
    if (ospf6_lsa_compare(lsa, tmp_lsa) == 0)
      return 1;
    else if (ospf6_lsa_compare(lsa, tmp_lsa) < 0) {
      WOSPF_PRINTF(3, "Cache lookup found an ERROR in %s's cache: Recv/Cache:", neighbor->name);
      ospf6_lsa_header_print(lsa);
      ospf6_lsa_header_print(tmp_lsa);
    } 
    else {
      WOSPF_PRINTF(33, "%s's cache lookup: Not same instance. Recv/Cache:", neighbor->name);
      //ospf6_lsa_header_print(lsa);
      //ospf6_lsa_header_print(tmp_lsa);
    }
  }

  return 0;
}


int wospf_ack_timeout(struct thread *thread) {
  struct wospf_ack_node *ack_node;

  ack_node = (struct wospf_ack_node *) THREAD_ARG (thread);

  /* The neighbor may have been dropped during ack_cache_timeout */
  if (ack_node->neighbor == NULL) return 1;

  WOSPF_PRINTF(2, "Removing timeout ack %s", ack_node->lsa->name);
  
  if (ospf6_lsdb_lookup(ack_node->lsa->header->type, ack_node->lsa->header->id,
			ack_node->lsa->header->adv_router, ack_node->neighbor->acked_lsa_list) != NULL) {
    WOSPF_PRINTF(2, "   trying... ");
    ospf6_lsdb_remove(ack_node->lsa, ack_node->neighbor->acked_lsa_list);
  }
  else WOSPF_PRINTF(2, "ERROR: Could not locate %s in %s's ack cache", ack_node->lsa->name, 
		      ack_node->neighbor->name);
  WOSPF_PRINTF(2, "   DONE! ");
  
  free(ack_node);

  return 1;
}


void wospf_update_ack_cache(struct ospf6_lsa *new_lsa, ID router_id) {
  struct wospf_neighbor_entry *neighbor;
  struct ospf6_lsa *lsa;

  /* The neighbor is not associated with a MANET interface. Discard. */
  if ((neighbor = wospf_lookup_neighbor_table(router_id)) == NULL) {
    return; 
  }
  
  WOSPF_PRINTF(22, "Updating %s's ack cache...", neighbor->name);

  for (lsa = ospf6_lsdb_head (neighbor->acked_lsa_list); lsa;
       lsa = ospf6_lsdb_next (lsa)) {
  
    if (OSPF6_LSA_IS_SAME(new_lsa, lsa)) {
      
      /* The received LSA may be older than cached instance */
      WOSPF_PRINTF(22, "%s's ack cache: Received LSA %s is already cached. Rec/Cache:", neighbor->name,
		   new_lsa->name);
      //ospf6_lsa_header_print(new_lsa);
      //ospf6_lsa_header_print(lsa);
    }

    /* If the cache instance is old */
    if (OSPF6_LSA_IS_SAME(new_lsa, lsa) && ospf6_lsa_compare(new_lsa, lsa) < 0) { 
      WOSPF_PRINTF(2, "%s's ack cache: Removing old instance of %s", neighbor->name,
		   new_lsa->name);
      ospf6_lsdb_remove(lsa, neighbor->acked_lsa_list);
    }
    
  }
  
}
