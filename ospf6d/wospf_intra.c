/*
** wospf_intra.c
** 
** Made by (Kenneth Holter)
** Login   <kenneho@localhost.localdomain>
** 
** Started on  Tue May  9 13:46:27 2006 Kenneth Holter
** Last update Wed May 24 14:40:21 2006 Kenneth Holter
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
#include "ospf6_intra.h"

#include "ospf6_flood.h"

#include "wospf_intra.h"
#include "wospf_neighbor_table.h"
#include "wospf_two_hop_neighbor.h"
#include "wospf_top.h"


/* Prototypes */
void wospf_linking_this_2_entries(struct wospf_neighbor_entry *, 
				  struct wospf_neighbor_2_entry *);

/* Functions */

void wospf_process_router_lsa(struct ospf6_lsa *lsa, struct ospf6_neighbor *from, 
			      struct ospf6_lsa_header *lsa_header) {


  struct wospf_neighbor_entry *neighbor;
  int number_of_lsas, size, i;
  char *header_end, *lsa_end, *pointer;
  struct ospf6_router_lsdesc *lsdesc;
  struct wospf_neighbor_2_entry *twohop_neighbor;
  struct wospf_neighbor_2_list_entry *twohop_neighbor_yet;
  ID lsa_neighbor_id;
  struct wospf_neighbor_2_entry *two_hop_entry;
  struct wospf_neighbor_2_list_entry *two_hop_list;
  int counter = 0;

  if ((neighbor = wospf_lookup_neighbor_table(from->router_id)) == NULL) {
    /* Not a WOSPF-OR neighbor */

    WOSPF_PRINTF(3, "Ignoring router LSA from %s", WOSPF_ID(&from->router_id));

    return;
  }

  WOSPF_PRINTF(33, "Processing router LSA from %s", neighbor->name);

  header_end = (char *) OSPF6_LSA_HEADER_END(lsa->header);
  lsa_end = (char *) OSPF6_LSA_END(lsa->header);
  size = lsa_end - header_end;
  number_of_lsas = size / sizeof(struct ospf6_router_lsdesc);


  /* Unregister neighbors of the neighbor in order to detect changes
     in the neighbor list reported in the router LSA */
  two_hop_list = neighbor->neighbor_2_list.next;
  while(two_hop_list != &neighbor->neighbor_2_list) {
    two_hop_entry = two_hop_list->neighbor_2;
    two_hop_entry->lsa_processed = WOSPF_FALSE;
    two_hop_list = two_hop_list->next;
  }

  

  pointer = header_end;
  
  for (i = 0; i < number_of_lsas; i++) {
    
    lsdesc = (struct ospf6_router_lsdesc *)
      ((caddr_t) pointer  + sizeof (struct ospf6_router_lsa));
    
    /* Update header end. Could/should use another variable not to be confued
       with the actual header end */
    pointer += sizeof(struct ospf6_router_lsdesc);
    
    lsa_neighbor_id = lsdesc->neighbor_router_id;
    
    counter++;

    if (lsa_neighbor_id == neighbor->router_id ||
	lsa_neighbor_id == ospf6->router_id) continue;
    
    /* If the router listed in the LSA is already a neighbor of
       the sender.. */
    if ((twohop_neighbor_yet = wospf_lookup_my_neighbors(neighbor, lsa_neighbor_id)) != NULL) {
      twohop_neighbor = twohop_neighbor_yet->neighbor_2;
    
 
    }
    
    else {

      /* The router listed in the LSA is not already registered as a
	 neighbor of the sender. 
	 Create new two hop neighbor entry, but first make sure such
	 an entry is not already created (maybe the two hop neighbor
	 is registered with another one hop neighbor)
      */
      if ((twohop_neighbor = wospf_lookup_two_hop_neighbor_table(lsa_neighbor_id)) == NULL) {
	
	changes_neighborhood = WOSPF_TRUE;

	twohop_neighbor = wospf_malloc (sizeof(struct wospf_neighbor_2_entry), "Two hop neighbor");
	
	twohop_neighbor->neighbor_2_nblist.next =
	  &twohop_neighbor->neighbor_2_nblist;
	twohop_neighbor->neighbor_2_nblist.prev =
	  &twohop_neighbor->neighbor_2_nblist;
	
	twohop_neighbor->neighbor_2_pointer = 0;
	twohop_neighbor->neighbor_2_id = lsa_neighbor_id;

	twohop_neighbor->name = int_to_ip(&lsa_neighbor_id);
	
	wospf_insert_two_hop_neighbor_table(twohop_neighbor);
	wospf_linking_this_2_entries(neighbor, twohop_neighbor);

      }

      else {

	changes_neighborhood = WOSPF_TRUE;
	wospf_linking_this_2_entries(neighbor, twohop_neighbor);
      }

    }

    twohop_neighbor->lsa_processed = WOSPF_TRUE;

  }

  /* Update two hop neighbor list of this neighbor. Two hop neighbors
     not listed in this LSA is assumed dropped */
  two_hop_list = neighbor->neighbor_2_list.next;
  while(two_hop_list != &neighbor->neighbor_2_list) {
    assert(two_hop_list->neighbor_2);
    two_hop_entry = two_hop_list->neighbor_2;
    
    if (two_hop_entry->lsa_processed == WOSPF_FALSE) {
      WOSPF_PRINTF(2, "%s(%d) was not listed in the router LSA - delete from %s's neighbor list",
		   two_hop_entry->name, two_hop_entry->neighbor_2_pointer, neighbor->name);
      
      /* No more neighbors are pointing to this two hop neighbor */
      if (two_hop_entry->neighbor_2_pointer - 1 == 0) {
	wospf_delete_two_hop_neighbor_table(two_hop_entry);
      }

      /* Manually remove pointers */
      else {
	
	wospf_delete_neighbor_2_pointer(neighbor, two_hop_entry->neighbor_2_id);
	wospf_delete_neighbor_pointer(two_hop_entry, neighbor->router_id);
      }
      
    }
    two_hop_list = two_hop_list->next;
  }
  
  if (changes_neighborhood)
    wospf_print_two_hop_neighbor_table();

  //if (changes_neighborhood)
  // wospf_print_neighborhood();
}



void wospf_linking_this_2_entries(struct wospf_neighbor_entry *neighbor, 
				  struct wospf_neighbor_2_entry *two_hop_neighbor) {
  
  char *neighbor_name = int_to_ip(&neighbor->router_id);
  char *twohop_name = int_to_ip(&two_hop_neighbor->neighbor_2_id);
  WOSPF_PRINTF(33, "New two hop neighbor: %s (via %s)", twohop_name, neighbor_name);
  
  struct wospf_neighbor_list_entry    *list_of_1_neighbors;
  struct wospf_neighbor_2_list_entry  *list_of_2_neighbors;

  list_of_1_neighbors = wospf_malloc(sizeof(struct wospf_neighbor_list_entry), "Link entries 1");

  list_of_2_neighbors = wospf_malloc(sizeof(struct wospf_neighbor_2_list_entry), "Link entries 2");

  list_of_1_neighbors->neighbor = neighbor;

  /* Queue */
  two_hop_neighbor->neighbor_2_nblist.next->prev = list_of_1_neighbors;
  list_of_1_neighbors->next = two_hop_neighbor->neighbor_2_nblist.next;
  two_hop_neighbor->neighbor_2_nblist.next = list_of_1_neighbors;
  list_of_1_neighbors->prev = &two_hop_neighbor->neighbor_2_nblist;

  list_of_2_neighbors->neighbor_2 = two_hop_neighbor;
  
  /* Queue */
  neighbor->neighbor_2_list.next->prev = list_of_2_neighbors;
  list_of_2_neighbors->next = neighbor->neighbor_2_list.next;
  neighbor->neighbor_2_list.next = list_of_2_neighbors;
  list_of_2_neighbors->prev = &neighbor->neighbor_2_list;
  
  /*increment the pointer counter*/
  two_hop_neighbor->neighbor_2_pointer++;

}
