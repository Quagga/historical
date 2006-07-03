/*
** wospf_neighbor_table.c
** 
** Made by (Kenneth Holter)
** Login   <kenneho@localhost.localdomain>
** 
** Started on  Fri May  5 13:22:40 2006 Kenneth Holter
** Last update Sun May 28 16:23:43 2006 Kenneth Holter
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
#include "ospf6d.h"

#include "wospf_two_hop_neighbor.h"
#include "wospf_top.h"
#include "wospf_protocol.h"
#include "wospf_lls.h"
#include "wospf_neighbor_table.h"

void 
wospf_init_neighbor_table() {

  int i;

  for(i = 0; i < HASHSIZE; i++)
    {
      neighbortable[i].next = &neighbortable[i];
      neighbortable[i].prev = &neighbortable[i];
    }
  
}

int 
wospf_delete_neighbor_2_pointer(struct wospf_neighbor_entry *neighbor, ID router_id) {
  
  struct wospf_neighbor_2_list_entry *entry;
  
  entry = neighbor->neighbor_2_list.next;
  
  while(entry != &neighbor->neighbor_2_list)
    {
      
      if(entry->neighbor_2->neighbor_2_id == router_id)
	{
	  /* Dequeue */
	  DEQUEUE_ELEM(entry);
	  
	  WOSPF_PRINTF(11, "Neighbor %s: Deleting pointer to twohop neighbor %s", neighbor->name, WOSPF_ID(&router_id));
	  WOSPF_PRINTF(33, "  (Neighbors pointing to twohop neighbor %s: %d)", WOSPF_ID(&router_id), 
		       entry->neighbor_2->neighbor_2_pointer);
	  
	  changes_neighborhood = WOSPF_TRUE;

	  entry->neighbor_2->neighbor_2_pointer--;
	  
	  /* Delete */
	  free(entry);
	  
	  return 1;	  
	}
      entry = entry->next;      
    }
  
  WOSPF_PRINTF(1, "ERROR: Neighbor %s: Could not delete pointer to twohop neighbor %s", neighbor->name, WOSPF_ID(&router_id));

  return 0;

}

struct wospf_neighbor_2_list_entry *
wospf_lookup_my_neighbors(struct wospf_neighbor_entry *neighbor, ID router_id) {

  struct wospf_neighbor_2_list_entry *entry;
  
  for(entry = neighbor->neighbor_2_list.next;
      entry != &neighbor->neighbor_2_list;
      entry = entry->next)
    {
      
      if(entry->neighbor_2->neighbor_2_id == router_id)
	return entry;
      
    }
  return NULL;

}

int
wospf_delete_neighbor_table(ID router_id) {
  
  struct  wospf_neighbor_2_list_entry *two_hop_list, *two_hop_to_delete;
  u_int32_t hash;
  struct wospf_neighbor_entry *entry;
  struct persistent_node *pers;
         
  hash = wospf_hashing(router_id);

  entry = neighbortable[hash].next;

  /*
   * Find neighbor entry
   */
  while(entry != &neighbortable[hash])
    {
      if(entry->router_id == router_id)
	break;
      
      entry = entry->next;
    }

  if(entry == &neighbortable[hash]) {
    return 0;
  }

  two_hop_list = entry->neighbor_2_list.next;

  while(two_hop_list != &entry->neighbor_2_list)
    {
      struct wospf_neighbor_2_entry *two_hop_entry;

      two_hop_entry = two_hop_list->neighbor_2;
      
      two_hop_entry->neighbor_2_pointer--;

      wospf_delete_neighbor_pointer(two_hop_entry, entry->router_id);

      /* Delete entry if it has no more one hop neighbors pointing to it */
      if(two_hop_entry->neighbor_2_pointer < 1)
	{
	  DEQUEUE_ELEM(two_hop_entry);

	  free(two_hop_entry);
	}


      two_hop_to_delete = two_hop_list;
      two_hop_list = two_hop_list->next;
      /* Delete entry */
      free(two_hop_to_delete);
      
    }

  WOSPF_PRINTF(1, "Neighbor table: Deleting %s", entry->name);
  
  pers = wospf_malloc(sizeof(struct persistent_node), "Dropping neighbor");
  pers->persistent_count = WOSPF_DROPPED_NEIGHBOR_PERS;
  pers->router_id = entry->router_id;
  listnode_add(lls_message->neighbor_drop_message->dropped_neighbors, pers);
  
  /* Dequeue */
  DEQUEUE_ELEM(entry);

  free(entry);

  changes_neighborhood = WOSPF_TRUE;

  state_changes = WOSPF_TRUE;
  
  //wospf_print_neighborhood();
  
  return 1;
  
}

struct wospf_neighbor_entry *
wospf_insert_neighbor_table(struct ospf6_neighbor *on) {
  
  u_int32_t router_id = (u_int32_t)on->router_id;

  u_int32_t             hash;
  struct wospf_neighbor_entry *new_neigh;
  
  hash = wospf_hashing(router_id);
  
  /* Check if entry exists */
  
  for(new_neigh = neighbortable[hash].next;
      new_neigh != &neighbortable[hash];
      new_neigh = new_neigh->next)
    {
      if(new_neigh->router_id == router_id)
	return new_neigh;
    }
  
  //printf("inserting neighbor\n");
  
  new_neigh = wospf_malloc(sizeof(struct wospf_neighbor_entry), "New neighbor entry");
  
  /* Set address, willingness and status */
  new_neigh->router_id = router_id;
  new_neigh->willingness = WILL_DEFAULT;
  
  new_neigh->neighbor_2_list.next = &new_neigh->neighbor_2_list;
  new_neigh->neighbor_2_list.prev = &new_neigh->neighbor_2_list;
  
  new_neigh->name = int_to_ip(&on->router_id);
  new_neigh->on = on;

  new_neigh->supports_aor = WOSPF_TRUE; /* Unless otherwise signaled */
  new_neigh->supports_incr_hello = WOSPF_TRUE; /* Unless otherwise
						 signaled */
  
  new_neigh->will_always = WOSPF_FALSE; 
  new_neigh->will_never = WOSPF_FALSE; 

  new_neigh->linkcount = 0;
  new_neigh->is_aor = WOSPF_FALSE;
  new_neigh->was_aor = WOSPF_FALSE;

  new_neigh->acked_lsa_list = ospf6_lsdb_create(on);

  new_neigh->scs_number = 1;

  /* Queue */
  QUEUE_ELEM(neighbortable[hash], new_neigh);

  WOSPF_PRINTF(1, "Neighbor table: Inserted %s", WOSPF_ID(&on->router_id));

  changes_neighborhood = WOSPF_TRUE;

  state_changes = WOSPF_TRUE;

  struct id_container *id_con =
    wospf_malloc(sizeof(struct id_container), "New ID");
  id_con->router_id = on->router_id;
  listnode_add(added_neighbors, id_con);

  //wospf_print_neighborhood();
  
  return new_neigh;


}

void
wospf_update_neighbor_entry(ID router_id, wospf_bool supportAOR, wospf_bool supportIncrHellos) {

  struct wospf_neighbor_entry *neighbor;
    
  neighbor = wospf_lookup_neighbor_table(router_id);

  neighbor->supports_aor = supportAOR;
  neighbor->supports_incr_hello = supportIncrHellos;

  

}

struct wospf_neighbor_entry *
wospf_lookup_neighbor_table(ID router_id) {

  struct wospf_neighbor_entry *entry;
  u_int32_t hash;
  
  hash = wospf_hashing(router_id);

  for(entry = neighbortable[hash].next;
      entry != &neighbortable[hash];
      entry = entry->next)
    {
      //printf("Checking %s\n", olsr_ip_to_string(&neighbor_table_tmp->neighbor_main_addr));
      if(entry->router_id == router_id)
	return entry;
      
    }
  //printf("NOPE\n\n");

  return NULL;

}

/* Neccessary?? */
void
wospf_time_out_two_hop_neighbors(struct wospf_neighbor_entry  *);


void
wospf_print_neighbor_table(void) {
  int i;

  WOSPF_PRINTF(1, "Neighbor table: ");

  for (i = 0; i < HASHSIZE; i++) {
    struct wospf_neighbor_entry *neigh;
    for(neigh = neighbortable[i].next; neigh != &neighbortable[i];
	neigh = neigh->next) {
      
      WOSPF_PRINTF(1, "   %s", WOSPF_ID(&neigh->router_id));

    }
  }
}

void
wospf_print_neighborhood(void) {
  int i, counter = 0;
  
  WOSPF_PRINTF(1, "Local topology: ");

  for (i = 0; i < HASHSIZE; i++) {
    struct wospf_neighbor_entry *neigh;
    for(neigh = neighbortable[i].next; neigh != &neighbortable[i];
	neigh = neigh->next) {
      
      WOSPF_PRINTF(1, "  %d: %s", ++counter, WOSPF_ID(&neigh->router_id));
      
      
      struct wospf_neighbor_2_list_entry *entry;
      
      for(entry = neigh->neighbor_2_list.next;
	  entry != &neigh->neighbor_2_list;
	  entry = entry->next) {
	
	WOSPF_PRINTF(1, "     reaches %s", WOSPF_ID(&entry->neighbor_2->neighbor_2_id));
	
      }
    }
  }
}

