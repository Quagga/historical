/*
** wospf_flood.c
** 
** Made by (Kenneth Holter)
** Login   <kenneho@localhost.localdomain>
** 
** Started on  Fri May  5 17:55:15 2006 Kenneth Holter
** Last update Sat May 27 18:03:45 2006 Kenneth Holter
*/

#include <zebra.h>

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

#include "ospf6_message.h"
#include "ospf6_lsdb.h"
#include "ospf6_top.h"
#include "ospf6_area.h"

#include "wospf_neighbor_table.h"
#include "wospf_flood.h"
#include "ospf6_flood.h"
#include "wospf_ack_cache.h"
#include "wospf_aor.h"
#include "wospf_aor_selector.h"
#include "wospf_top.h"

/* Prototypes*/

static struct list *wospf_find_failed_neighbors(struct ospf6_neighbor *, 
					 struct ospf6_lsa *, 
					 struct ospf6_interface *,
					 u_int8_t *);


static struct wospf_pushback_lsa *lookup_lsa_node(struct ospf6_interface *, 
					   struct ospf6_lsa *);

static void wospf_reschedule_retrans_timers(struct ospf6_lsa *, 
					    struct ospf6_interface *);

/* Functions */

void wospf_flood_interface (struct ospf6_neighbor *from,
			    struct ospf6_lsa *lsa, 
			    struct ospf6_interface *oi) {
  struct listnode *node;
  struct ospf6_neighbor *on;
  struct ospf6_lsa *req;
  int retrans_added = 0;
  int is_debug = 0;

  if (from != NULL) { 
    WOSPF_PRINTF(3, "   ");
    WOSPF_PRINTF(3, "WOSPF-OR interface - flooding %s for %s", lsa->name, WOSPF_ID(&from->router_id));
  }
  
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

      if (from != NULL)
	wospf_update_ack_cache(lsa, on->router_id);
      
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
         examin next neighbor 
	 WOSPF-OR: If an ack has already been received, examin next neighbor
      */
      if (from == on ||
	  wospf_lookup_ack_cache(on->router_id, lsa) == 1)
        {
          if (is_debug)
            zlog_debug ("Received is from the neighbor, next neighbor");
          continue;
        }

      /* (d) add retrans-list, schedule retransmission */
      if (is_debug)
        zlog_debug ("Add retrans-list of this neighbor");
      ospf6_increment_retrans_count (lsa);
      ospf6_lsdb_add (ospf6_lsa_copy (lsa), on->retrans_list);
      if (on->thread_send_lsupdate == NULL)
        on->thread_send_lsupdate =
          thread_add_timer (master, ospf6_lsupdate_send_neighbor,
                            on, on->ospf6_if->rxmt_interval);
      retrans_added++;

      if (from != NULL)
	WOSPF_PRINTF(3, "Add %s to retrans-list of %s", lsa->name, WOSPF_ID(&on->router_id));

    }

  if (from != NULL) {

    struct wospf_pushback_lsa *lsa_node;

    u_int8_t has_already_received = 0;
    
    struct list *failed_neighbors = wospf_find_failed_neighbors(from, lsa, oi, &has_already_received);

    /* Bullet 2 (for non-AORs): Every neighor on the interfaces has received the LSA.
       Examine next interface.
    */
    
    if (is_AOR_selector(from->router_id)) {
      /* I must immediately re-flood the LSA */
      WOSPF_PRINTF(2, "I'm an AOR for %s - flooding the LSA", WOSPF_ID(&from->router_id));
      
    }
    
    else if (wospf_count_adjacencies(oi->neighbor_list) == has_already_received) {
      WOSPF_PRINTF(2, "Abort flooding: All neighbors have received the LSA");
      return;
    }
    else WOSPF_PRINTF(2, "At least one neighbor has NOT received the LSA");

    /* Bullet 3: If the LSA was received on this interface, and I'm not an AOR for the sender */
    if (from->ospf6_if == oi && !is_AOR_selector(from->router_id)) {
      
      /* Draft, section 3.4.8.2.2: Reset timer. This is implemented by
	 building a new (possibly identical) node. */
      if ((lsa_node = lookup_lsa_node(oi, lsa)) != NULL) {
	WOSPF_PRINTF(2, "%s is already push backed - replacing old node (resetting Pushback timer)", lsa->name);
	THREAD_OFF(lsa_node->backup_timer);
	listnode_delete(oi->pushbacked_lsa_list, lsa_node);
	free(lsa_node);
      }
      
      /* Push back the LSA */
      lsa_node = wospf_malloc(sizeof(struct wospf_pushback_lsa), "New pushback LSA node");
      lsa_node->lsa = ospf6_lsa_copy(lsa);

      /* Fill the backup_wait_list */
      lsa_node->backup_wait_list = failed_neighbors;
      lsa_node->oi = oi;
      
      
      unsigned long interval = (unsigned long) (oi->pushback_interval * 1000) + wospf_jitter(oi);

      /* Note: The LSA node MUST be added to the pushbacked lsa list
	 associated with the interface. This follows from that the LSA
	 node's backup_wait_list may be modified upon LS Ack
	 reception, so a pointer to this list must be available. */
      listnode_add(oi->pushbacked_lsa_list, lsa_node);
      
      WOSPF_PRINTF(2, "I'm not an AOR for %s - pushing back the LSA for %.2f sec", WOSPF_ID(&from->router_id), (double)interval/1000);

      lsa_node->backup_timer = thread_add_timer_msec (master, wospf_pushback_timeout, lsa_node, interval);
    
      /* No need to flood yet - wait for pushback timer */
      return;
    }
    

    
    WOSPF_PRINTF(3, "   ");
  }
    
  /* I'm an AOR for the sender, or the LSA is self-originated */
  ospf6_lsdb_add (ospf6_lsa_copy (lsa), oi->lsupdate_list);
  if (oi->thread_send_lsupdate == NULL)
    oi->thread_send_lsupdate =
      thread_add_event (master, ospf6_lsupdate_send_interface, oi, 0);

}


/*
  Returns the list of neighbors on the interface who fail to pass
  these tests:
  1) The neighbor is the sender of the LSA
  2) The neighbor has already acknowledged the LSA
*/
static struct list *wospf_find_failed_neighbors(struct ospf6_neighbor *from, 
					 struct ospf6_lsa *lsa, 
					 struct ospf6_interface *oi,
					 u_int8_t *has_already_received) {
  struct list *list = list_new();
  struct ospf6_neighbor *on;
  struct listnode *node;
  struct wospf_neighbor_entry *neighbor;
  int fail_both;
  int passed_at_least_one;

  /* Iterate the interface's neighbor list */
  for (node = listhead (oi->neighbor_list); node; nextnode (node)) {
    on = (struct ospf6_neighbor *) getdata (node);

    fail_both = 2;
    passed_at_least_one = WOSPF_FALSE;

    /* Examine next neighbor if this neighbor is not a WOSPF-OR
       neighbor */
    if ((neighbor = wospf_lookup_neighbor_table(on->router_id)) == NULL) 
      continue;
    
    
    /* a) The neighbor has received the LSA */
    if (from == on ||
	lsa->header->adv_router == on->router_id ||
	wospf_lookup_ack_cache(on->router_id, lsa) == 1) {
      
      /* Debugging */
      if (from == on && 
	  wospf_lookup_ack_cache(on->router_id, lsa) == 0 &&
	  lsa->header->adv_router != on->router_id) {
	WOSPF_PRINTF(3, "  - %s is the sender of the LSA", neighbor->name);
      }
      else if (from != on && 
	       wospf_lookup_ack_cache(on->router_id, lsa) == 1) {
	WOSPF_PRINTF(3, "  - %s has already acked the LSA", neighbor->name);
      }
      else if (from == on && 
	       wospf_lookup_ack_cache(on->router_id, lsa) == 1) {
	WOSPF_PRINTF(3, "  - %s has already acked the LSA, AND it is the sender ", neighbor->name);
      }
      
      
      if (lsa->header->adv_router == on->router_id &&
	  from == on) {
	WOSPF_PRINTF(3, "  - %s is the sender and originator of the LSA", neighbor->name);
      }
      else if (lsa->header->adv_router == on->router_id) {
	WOSPF_PRINTF(3, "  - %s originated the LSA", neighbor->name);
      }


      passed_at_least_one = WOSPF_TRUE;
    }
    else fail_both--;
    
    
    struct wospf_neighbor_2_list_entry *twohop =
      wospf_lookup_my_neighbors(neighbor, from->router_id);
    
    /* b) This neighbor is covered by the sending neighbor, and the
          LSA was received on a MANET interface  */
    if (twohop != NULL &&
	CHECK_FLAG(lsa->flag, OSPF6_LSA_MANET)) {
      
      WOSPF_PRINTF(3, "  - %s is covered by the sender (%s)", neighbor->name, WOSPF_ID(&from->router_id));
      
      passed_at_least_one = WOSPF_TRUE;
    }
    else fail_both--;
    
    
    if (passed_at_least_one == WOSPF_TRUE) {
      *has_already_received = *has_already_received + 1;
    }
    
    if (fail_both == 0) {
      listnode_add(list, neighbor);
    }

  }

  return list;
}


int wospf_count_adjacencies(struct list *neighbor_list) {
  struct listnode *node;
  struct ospf6_neighbor *on;
  int number = 0;

  for (node = listhead (neighbor_list); node; nextnode (node)) {
    on = (struct ospf6_neighbor *) getdata (node);
    
    if (on->state >= OSPF6_NEIGHBOR_EXCHANGE) number++;

  }

  return number;
}

static void wospf_reschedule_retrans_timers(struct ospf6_lsa *lsa, 
					    struct ospf6_interface *oi) {
  struct listnode *node;
  struct ospf6_neighbor *on;
  
  for (node = listhead (oi->neighbor_list); node; nextnode (node)) {
    on = (struct ospf6_neighbor *) getdata (node);
    
    if (ospf6_lsdb_lookup(lsa->header->type, lsa->header->id,
			  lsa->header->adv_router, on->retrans_list) != NULL) {
      
      char *name = int_to_ip(&on->router_id);
      WOSPF_PRINTF(5, "Rescheduling %s's retransmission timer", name);
      
      THREAD_OFF (on->thread_send_lsupdate);
      on->thread_send_lsupdate =
	thread_add_timer (master, ospf6_lsupdate_send_neighbor,
			  on, on->ospf6_if->rxmt_interval);
    }
  
  }
  
}

int wospf_pushback_timeout(struct thread *thread) {
  struct wospf_pushback_lsa *lsa_node;
  struct listnode *node, *nextnode;
  struct wospf_neighbor_entry *neighbor;
  struct ospf6_lsa *lsack_entry, *lsa;
  struct ospf6_interface *oi;
  
  lsa_node = (struct wospf_pushback_lsa *)THREAD_ARG(thread);
  lsa = lsa_node->lsa;
  oi = lsa_node->oi;

  WOSPF_PRINTF(2, "Pushback timeout for %s. Waiting: ", lsa->name);

    /* Remove outdated neighbors from the list */
  for (ALL_LIST_ELEMENTS (lsa_node->backup_wait_list, node, nextnode, neighbor)) {
    
    /* The neighbor may have been dropped or transistioned to a lesser
       state than exchange */
    if (neighbor == NULL) {
      WOSPF_PRINTF(2, "  - %s is no longer a neighbor", neighbor->name);
      list_delete_node(lsa_node->backup_wait_list, node);
      continue;
    }
    
    WOSPF_PRINTF(2, "  - %s", neighbor->name);

  }
  
  /* All my neighbors have received the LSA -  abort flooding. */
  if (list_isempty(lsa_node->backup_wait_list)) {
    WOSPF_PRINTF(2, "  - Flooding the LSA will result in a redundant transmission - abort");
    return 0;
  }
  
  /* Send the LSA, since at least one of my neighbors may have
     failed to receive it */
  ospf6_lsdb_add (ospf6_lsa_copy(lsa), oi->lsupdate_list);
  
  if (oi->thread_send_lsupdate == NULL)
    oi->thread_send_lsupdate =
      thread_add_event (master, ospf6_lsupdate_send_interface, oi, 0);
  
  
  /* The reflood will serve as an implicit ack. Remove LSA from
     lsack_list of the interface */
  lsack_entry = ospf6_lsdb_lookup(lsa->header->type, lsa->header->id,
				  lsa->header->adv_router, oi->lsack_list);
  
  if (lsack_entry != NULL) {
    
    ospf6_lsdb_remove(lsack_entry, oi->lsack_list);
    
  }
  
  WOSPF_PRINTF(2, "  -- Flooding pushbacked LSA... ");

  wospf_reschedule_retrans_timers(lsa, oi);

  listnode_delete(oi->pushbacked_lsa_list, lsa_node);
  free(lsa_node);

  return 1;
}



int wospf_jitter(struct ospf6_interface *oi) {
  int r;
  int msec;

  double h = ((double)oi->rxmt_interval/2) - oi->propagation_delay;

  /* Even numbers - ensure inequality */
  if (h/2 == 0) {
    msec = 999;
  }

  /* Odd numbers */
  else {
    msec = 499;
  }

  /* 0 <= Jitter >= 1000 msec */
  r = rand() % msec;
  
  return r;

}


/**********************************/
/***** Update BackupWait list *****/
/**********************************/

/* Remove the sending neighbor from LSA node's BackupWait list on MANET-interfaces */
void wospf_remove_bwn_list(struct ospf6_neighbor *on, struct ospf6_lsa *lsa, 
			   struct ospf6_interface *oi, wospf_bool implicit_ack) {
  struct wospf_neighbor_entry *neighbor;
  struct listnode *node;
  struct ospf6_interface *interface;
  struct wospf_pushback_lsa *lsa_node;
  
  if ((neighbor = wospf_lookup_neighbor_table(on->router_id)) == NULL) {
    return;
  }

  
  /* For each interface to this area ... */
  for (node = oi->area->if_list->head; node; nextnode (node)) {
    interface = getdata (node);

    if (interface->is_wospf_interface == WOSPF_FALSE) 
      continue;
    
    
    /* Locate the LSA node, if present*/
    if ((lsa_node = lookup_lsa_node(interface, lsa)) != NULL) {
      
      /* Lookup the sending neighbor */
      if (listnode_lookup(lsa_node->backup_wait_list, neighbor) != NULL) {

	WOSPF_PRINTF(2, "%s acked the pushbacked LSA %s - removed from LSA's bwn list",
		     neighbor->name, lsa->name);

	/* The neighbor has acked the LSA - remove from bwn list */
	listnode_delete(lsa_node->backup_wait_list, neighbor);

      }
      
      /* I have heard a reflood from a neighbor. Remove the sending
	 neighbor's neighbors from the LSA node's BWN list */
      if (implicit_ack == WOSPF_TRUE) {
	int i;
	
	/* Iterate the neighbor table */
	for (i = 0; i < HASHSIZE; i++) {
	  struct wospf_neighbor_entry *neigh;
	  for(neigh = neighbortable[i].next; neigh != &neighbortable[i];
	      neigh = neigh->next) {
	   
	    assert(neigh);
	    assert(neigh->on);
	    assert(oi);

	    /* If the neighbor belongs to this interface and is listed
	       in the LSA node's BWN list */
	    if (neigh->on->ospf6_if == oi &&
		listnode_lookup(lsa_node->backup_wait_list, neigh) != NULL) {

	      if (wospf_lookup_my_neighbors(neighbor, neigh->router_id) != NULL &&
		  neighbor->router_id != neigh->router_id) {

		WOSPF_PRINTF(2, "%s is a neighbor of %s - removed from LSA's bwn list",
			     neigh->name, neighbor->name);
		listnode_delete(lsa_node->backup_wait_list, neighbor);
	      }
	    }
	  }    
	}
      }
    }
  }
}


static struct wospf_pushback_lsa *lookup_lsa_node(struct ospf6_interface *interface, 
					   struct ospf6_lsa *lsa) {
  struct wospf_pushback_lsa *lsa_node;
  struct listnode *node, *nextnode;
  
  for (ALL_LIST_ELEMENTS (interface->pushbacked_lsa_list, node, nextnode, lsa_node)) {

    assert(lsa_node);
    assert(lsa_node->lsa);
    assert(lsa);
    if (OSPF6_LSA_IS_SAME(lsa_node->lsa, lsa) && ospf6_lsa_compare(lsa_node->lsa, lsa) == 0) 
      return lsa_node;
    
  }

  return NULL;
}
