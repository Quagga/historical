/*
** wospf_two_hop_neighbor.c
** 
** Made by (Kenneth Holter)
** Login   <kenneho@localhost.localdomain>
** 
** Started on  Fri May  5 13:38:25 2006 Kenneth Holter
** Last update Wed May 24 14:41:05 2006 Kenneth Holter
*/

#include "wospf_two_hop_neighbor.h"
#include "wospf_neighbor_table.h"
#include "wospf_top.h"

int
wospf_init_two_hop_table(void) {

  int index;

  for(index=0;index<HASHSIZE;index++)
    {
      two_hop_neighbortable[index].next = &two_hop_neighbortable[index];
      two_hop_neighbortable[index].prev = &two_hop_neighbortable[index];
    }
  return 1;
}

void
wospf_delete_neighbor_pointer(struct wospf_neighbor_2_entry *two_hop_entry, ID router_id) {
  
  struct wospf_neighbor_list_entry *entry;
  
  entry = two_hop_entry->neighbor_2_nblist.next;
  
  while(entry != &two_hop_entry->neighbor_2_nblist)
    {
      if(entry->neighbor->router_id == router_id)
	{
	  struct wospf_neighbor_list_entry *entry_to_delete = entry;
	  entry = entry->next;
	  
	  changes_neighborhood = WOSPF_TRUE;
	  WOSPF_PRINTF(3, "Two hop neighbor %s: Deleting pointer to %s", two_hop_entry->name, WOSPF_ID(&router_id));
	  
	  /* dequeue */
	  DEQUEUE_ELEM(entry_to_delete);
	  
	  free(entry_to_delete);
	}
      else
	{
	  entry = entry->next;
	}
    }

  if (entry == two_hop_entry->neighbor_2_nblist.next) {
    WOSPF_PRINTF(33, "Two hop neighbor %s does not point to any one hop neighbors", two_hop_entry->name);
    //wospf_delete_two_hop_neighbor_table(two_hop_entry);
  }

}

void
wospf_delete_two_hop_neighbor_table(struct wospf_neighbor_2_entry *two_hop_neighbor) {
  
  struct wospf_neighbor_list_entry *one_hop_list;
  
  one_hop_list = two_hop_neighbor->neighbor_2_nblist.next;
  
  /* Delete one hop links */
  while(one_hop_list != &two_hop_neighbor->neighbor_2_nblist)
    {
      struct wospf_neighbor_entry *one_hop_entry = one_hop_list->neighbor;
      struct wospf_neighbor_list_entry *entry_to_delete = one_hop_list;

      wospf_delete_neighbor_2_pointer(one_hop_entry, two_hop_neighbor->neighbor_2_id);
      one_hop_list = one_hop_list->next;
      /* no need to dequeue */
      free(entry_to_delete);
    }
  
  char *name = int_to_ip(&two_hop_neighbor->neighbor_2_id);
  WOSPF_PRINTF(1, "Two hop neighbor table: Deleting %s", name);

  /* dequeue */
  DEQUEUE_ELEM(two_hop_neighbor);
  free(two_hop_neighbor);
  
  changes_neighborhood = WOSPF_TRUE;

  //wospf_print_neighborhood();
}

void
wospf_insert_two_hop_neighbor_table(struct wospf_neighbor_2_entry *two_hop_neighbor) {

  u_int32_t hash; 
  
  hash = wospf_hashing(two_hop_neighbor->neighbor_2_id);

  WOSPF_PRINTF(11, "Two hop neighbor table: Inserted %s", two_hop_neighbor->name);

  /* Queue */  
  QUEUE_ELEM(two_hop_neighbortable[hash], two_hop_neighbor);

  changes_neighborhood = WOSPF_TRUE;

  //wospf_print_neighborhood();
}

struct wospf_neighbor_2_entry *
wospf_lookup_two_hop_neighbor_table(ID router_id) {

  struct wospf_neighbor_2_entry *neighbor_2;
  u_int32_t hash;

  //printf("LOOKING FOR %s\n", olsr_ip_to_string(dest));
  hash = wospf_hashing(router_id);

  
  for(neighbor_2 = two_hop_neighbortable[hash].next;
      neighbor_2 != &two_hop_neighbortable[hash];
      neighbor_2 = neighbor_2->next)
    {

      //printf("Checking %s\n", olsr_ip_to_string(dest));
      if (neighbor_2->neighbor_2_id == router_id)
	return neighbor_2;
      
    }

  return NULL;
}



void
wospf_print_two_hop_neighbor_table(void) {
  int i, counter = 0;

  if (two_hop_neighbortable[0].next != &two_hop_neighbortable[0])
    WOSPF_PRINTF(11, "Two hop neighbor table: ");

  for (i = 0; i < HASHSIZE; i++)
    {
      struct wospf_neighbor_2_entry *neigh2;
      for (neigh2 = two_hop_neighbortable[i].next;
           neigh2 != &two_hop_neighbortable[i]; neigh2 = neigh2->next)
	{
	  struct wospf_neighbor_list_entry *entry;
	  	  
	  WOSPF_PRINTF(22, "  %d: %s", ++counter, neigh2->name);

	  for (entry = neigh2->neighbor_2_nblist.next;
               entry != &neigh2->neighbor_2_nblist; entry = entry->next)
	    {
	      
	      struct wospf_neighbor_entry *neigh = entry->neighbor;
	      
	      WOSPF_PRINTF(22, "       via %s", neigh->name);

            }
	}
    }

}
