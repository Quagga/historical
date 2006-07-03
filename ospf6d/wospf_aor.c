/*
** wospf_aor.c
** 
** Made by (Kenneth Holter)
** Login   <kenneho@localhost.localdomain>
** 
** Started on  Sat May  6 13:25:26 2006 Kenneth Holter
** Last update Sun May 28 16:30:34 2006 Kenneth Holter
*/

#include <zebra.h>
#include "vty.h"

#include "ospf6_interface.h"

#include "wospf_aor.h"
#include "wospf_hashing.h"
#include "wospf_defs.h"
#include "wospf_neighbor_table.h"
#include "wospf_two_hop_neighbor.h"
#include "wospf_protocol.h"
#include "wospf_top.h"
#include "wospf_lls.h"

int is_AOR (ID neighbor_id) {
 
  return 0;
}


/* Begin:
 * Prototypes for internal functions 
 */

static u_int16_t
add_will_always_nodes(void);

static void
wospf_optimize_aor_set(void);

static void
wospf_clear_aors(void);

static void
wospf_clear_two_hop_processed(void);

static struct wospf_neighbor_entry *
wospf_find_maximum_covered(int);

static u_int16_t
wospf_calculate_two_hop_neighbors(void);

static int
wospf_check_aor_changes(void);

static int
wospf_chosen_aor(struct wospf_neighbor_entry *, u_int16_t *);

static struct wospf_neighbor_2_list_entry *
wospf_find_2_hop_neighbors_with_1_link(int);

static void
wospf_update_aor_lists();


/* End:
 * Prototypes for internal functions 
 */


/**
 *Find all 2 hop neighbors with 1 link
 *connecting them to us trough neighbors
 *with a given willingness.
 *
 *@param willingness the willigness of the neighbors
 *
 *@return a linked list of allocated neighbor_2_list_entry structures
 */
static struct wospf_neighbor_2_list_entry *
wospf_find_2_hop_neighbors_with_1_link(int willingness)
{
  
 
  u_int8_t                     index;
  struct wospf_neighbor_2_list_entry *two_hop_list_tmp = NULL;
  struct wospf_neighbor_2_list_entry *two_hop_list = NULL;
  struct wospf_neighbor_entry        *dup_neighbor;
  struct wospf_neighbor_2_entry      *two_hop_neighbor = NULL;


  for(index=0;index<HASHSIZE;index++)
    {

      for(two_hop_neighbor = two_hop_neighbortable[index].next;
	  two_hop_neighbor != &two_hop_neighbortable[index];
	  two_hop_neighbor = two_hop_neighbor->next)
	{
	  
	  //two_hop_neighbor->neighbor_2_state=0;
	  //two_hop_neighbor->mpr_covered_count = 0;
	  
	  dup_neighbor = wospf_lookup_neighbor_table(two_hop_neighbor->neighbor_2_id);
	  
	  if(dup_neighbor != NULL)
	    {
	      
	      continue;
	    }
	  
	  if(two_hop_neighbor->neighbor_2_pointer == 1)
	    {
	      if(two_hop_neighbor->neighbor_2_nblist.next->neighbor->willingness == willingness)
		{
		  two_hop_list_tmp = wospf_malloc(sizeof(struct wospf_neighbor_2_list_entry), "AOR two hop list");

		  /* Only queue one way here */		  
		  two_hop_list_tmp->neighbor_2 = two_hop_neighbor;
		  
		  two_hop_list_tmp->next = two_hop_list;
		  
		  two_hop_list= two_hop_list_tmp;
		}
	    }
	  
	}
      
    }
  
  return(two_hop_list_tmp);
}
  





/**
 *This function processes the chosen AORs and updates the counters
 *used in calculations
 */
static int
wospf_chosen_aor(struct wospf_neighbor_entry *one_hop_neighbor, u_int16_t *two_hop_covered_count)
{
  struct wospf_neighbor_list_entry   *the_one_hop_list;
  struct wospf_neighbor_2_list_entry *second_hop_entries; 
  struct wospf_neighbor_entry        *dup_neighbor;
  u_int16_t                          count;
  
  count = *two_hop_covered_count;

  //WOSPF_PRINTF(1, "Setting %s as AOR", WOSPF_ID(&one_hop_neighbor->router_id))
    
  one_hop_neighbor->is_aor = WOSPF_TRUE;
  
  for(second_hop_entries = one_hop_neighbor->neighbor_2_list.next;
      second_hop_entries != &one_hop_neighbor->neighbor_2_list;
      second_hop_entries = second_hop_entries->next)
    {
      dup_neighbor = wospf_lookup_neighbor_table(second_hop_entries->neighbor_2->neighbor_2_id);

      if(dup_neighbor != NULL)
	{
	  
	  continue;
	}
      
      /*
	Now the neighbor is covered by this mpr
      */
      second_hop_entries->neighbor_2->aor_covered_count++;
      the_one_hop_list = second_hop_entries->neighbor_2->neighbor_2_nblist.next;

      if(second_hop_entries->neighbor_2->aor_covered_count >= wospf_cfg->aor_coverage)
	count++;
      
      while(the_one_hop_list != &second_hop_entries->neighbor_2->neighbor_2_nblist)
	{
	  
	  if(second_hop_entries->neighbor_2->aor_covered_count >= wospf_cfg->aor_coverage)
	    {
	      the_one_hop_list->neighbor->neighbor_2_nocov--;
	    }
	  
	  the_one_hop_list = the_one_hop_list->next;
	}
      
    }

  //printf("POST COUNT %d\n\n", count);
  
  *two_hop_covered_count = count;
  return count;

}


/**
 *Find the neighbor that covers the most 2 hop neighbors
 *with a given willingness
 *
 *@param willingness the willingness of the neighbor
 *
 *@return a pointer to the neighbor_entry struct
 */
static struct wospf_neighbor_entry *
wospf_find_maximum_covered(int willingness)
{
  u_int16_t                  maximum;
  u_int8_t                   index;
  struct wospf_neighbor_entry       *a_neighbor;
  struct wospf_neighbor_entry       *aor_candidate=NULL;
  ID max_id; /* WOSPF-OR */
   
  maximum = 0;
  max_id = 0; /* WOSPF-OR */

  for (index=0;index<HASHSIZE;index++)
    {
      for(a_neighbor = neighbortable[index].next;
	  a_neighbor != &neighbortable[index];
	  a_neighbor = a_neighbor->next)
	{
	  /*	  
	  printf("[%s] nocov: %d mpr: %d will: %d max: %d\n\n", 
		 olsr_ip_to_string(&a_neighbor->neighbor_main_addr), 
		 a_neighbor->neighbor_2_nocov,
		 a_neighbor->is_mpr,
		 a_neighbor->willingness,
		 maximum);
	  */
#ifdef WOSPF
	   if((!a_neighbor->is_aor) &&
	      (a_neighbor->willingness == willingness)) { 
	     
	     
	     if (maximum < a_neighbor->neighbor_2_nocov) {
	       maximum = a_neighbor->neighbor_2_nocov;
	       aor_candidate = a_neighbor;
	       max_id = a_neighbor->router_id;
	     }
	     
	     /* Final tie-breaker */
	     else if (maximum == a_neighbor->neighbor_2_nocov) {
	       

	       
	       if (max_id < a_neighbor->router_id) {
		 WOSPF_PRINTF(2, "AOR calculation: Tie breaker - choosing %s as AOR instead of %s", 
			      int_to_ip(&a_neighbor->router_id), int_to_ip(&max_id));
		 maximum = a_neighbor->neighbor_2_nocov;
		 aor_candidate = a_neighbor;
		 max_id = a_neighbor->router_id;

	       }
	       else {
		 WOSPF_PRINTF(2, "AOR calculation: Tie breaker - choosing %s as AOR instead of %s", 
			      int_to_ip(&max_id), int_to_ip(&a_neighbor->router_id));
	       }

	     }

	   }
#else
	  if((!a_neighbor->is_aor) &&
	     (a_neighbor->willingness == willingness) && 
	     (maximum < a_neighbor->neighbor_2_nocov))
	    {
	      //printf("ADDING\n");
	      maximum = a_neighbor->neighbor_2_nocov;
	      aor_candidate = a_neighbor;
	    }
#endif
	}
    }
  return aor_candidate;
}


/**
 *Remove all AOR registrations
 */
static void
wospf_clear_aors()
{
  u_int32_t index;
  struct wospf_neighbor_entry   *a_neighbor;
  struct wospf_neighbor_2_list_entry *two_hop_list;
  
  for (index=0;index<HASHSIZE;index++)
    {
      for(a_neighbor = neighbortable[index].next;
	  a_neighbor != &neighbortable[index];
	  a_neighbor = a_neighbor->next)
	{
	  /* Clear AOR selection */
	  if(a_neighbor->is_aor)
	    {
	      a_neighbor->was_aor = WOSPF_TRUE;
	      a_neighbor->is_aor = WOSPF_FALSE;
	    }

	  /* Clear two hop neighbors coverage count */
	  for(two_hop_list = a_neighbor->neighbor_2_list.next;
	      two_hop_list != &a_neighbor->neighbor_2_list;
	      two_hop_list = two_hop_list->next)
	    {
	      two_hop_list->neighbor_2->aor_covered_count = 0;
	    }
	}
    }

}


/**
 *Check for changes in the AOR set
 *
 *@return 1 if changes occured 0 if not
 */
static int
wospf_check_aor_changes()
{
  u_int32_t index;
  struct wospf_neighbor_entry       *a_neighbor;
  int retval;

  retval = 0;
  
  for (index=0;index<HASHSIZE;index++)
    {
      for(a_neighbor = neighbortable[index].next;
	  a_neighbor != &neighbortable[index];
	  a_neighbor = a_neighbor->next)
	{
	  if(a_neighbor->was_aor)
	    {
	      a_neighbor->was_aor = WOSPF_FALSE;
	      if(!a_neighbor->is_aor)
		retval = 1;
	    }
	}
    }

  return retval;
}


/**
 *Clears out proccess registration
 *on two hop neighbors
 */
static void
wospf_clear_two_hop_processed()
{
  struct wospf_neighbor_2_entry  *neighbor_2;
  int index;
  
  for(index=0;index<HASHSIZE;index++)
    {
      for(neighbor_2 = two_hop_neighbortable[index].next;
	  neighbor_2 != &two_hop_neighbortable[index];
	  neighbor_2 = neighbor_2->next)
	{
	  /* Clear */
	  neighbor_2->processed = 0;
	}
    }

}


/**
 *This function calculates the number of two hop neighbors
 */
static u_int16_t
wospf_calculate_two_hop_neighbors()
{
  u_int8_t                    index;
  struct wospf_neighbor_entry        *a_neighbor, *dup_neighbor;
  u_int16_t                   count, n_count, sum;
  struct wospf_neighbor_2_list_entry *twohop_neighbors;
  
  n_count = 0;
  count = 0;
  sum = 0;

  /* Clear 2 hop neighs */
  wospf_clear_two_hop_processed();

  for(index=0;index<HASHSIZE;index++)
    {
      for(a_neighbor = neighbortable[index].next;
	  a_neighbor != &neighbortable[index];
	  a_neighbor = a_neighbor->next)
	{ 
	  count = 0;
	  n_count = 0;
	  
	  /* if(a_neighbor->status == NOT_SYM)
	     {	    
	     a_neighbor->neighbor_2_nocov = count;
	     continue;
	     }*/

	  for(twohop_neighbors = a_neighbor->neighbor_2_list.next;
	      twohop_neighbors != &a_neighbor->neighbor_2_list;
	      twohop_neighbors = twohop_neighbors->next)
	    {
	      
	      dup_neighbor = wospf_lookup_neighbor_table(twohop_neighbors->neighbor_2->neighbor_2_id);
	      
	      if(dup_neighbor == NULL)
		{
		  n_count++;
		  if(!twohop_neighbors->neighbor_2->processed)
		    {
		      count++;
		      twohop_neighbors->neighbor_2->processed = 1;
		    }
		}
	    }
	  a_neighbor->neighbor_2_nocov = n_count;
	  
	  /* Add the two hop count */
	  sum += count;
	}
    }
  
  //WOSPF_PRINTF(3, "Two hop neighbors: %d", sum)
  return sum;
}




/**
 * Adds all nodes with willingness set to WILL_ALWAYS
 */
static u_int16_t
add_will_always_nodes()
{

  u_int8_t                    index;
  struct wospf_neighbor_entry        *a_neighbor;
  u_int16_t                   count;

  count = 0;

  //printf("\nAdding WILL ALWAYS nodes....\n");

  for(index=0;index<HASHSIZE;index++)
    {
      for(a_neighbor = neighbortable[index].next;
	  a_neighbor != &neighbortable[index];
	  a_neighbor = a_neighbor->next)
	{ 
	  if(a_neighbor->willingness != WILL_ALWAYS &&
	     a_neighbor->will_always == WOSPF_FALSE)
	    continue;

	  wospf_chosen_aor(a_neighbor, &count); 

	  WOSPF_PRINTF(3, "Adding WILL_ALWAYS: %s", WOSPF_ID(&a_neighbor->router_id))

	}
    }
  
  //OLSR_PRINTF(1, "Count: %d\n", count)
  return count;
}

/**
 *This function calculates the mpr neighbors
 *@return nada
 */
void
wospf_calculate_aor()     
{
  
  u_int16_t                   two_hop_covered_count=0;
  u_int16_t                   two_hop_count=0;  
  struct wospf_neighbor_2_list_entry *two_hop_list=NULL;
  struct wospf_neighbor_2_list_entry *tmp;
  struct wospf_neighbor_entry        *aors; 
  int i;

  //WOSPF_PRINTF(3, "**RECALCULATING AOR SET**");
  
  wospf_clear_aors();

  two_hop_count = wospf_calculate_two_hop_neighbors();

  two_hop_covered_count += add_will_always_nodes();

  /*
   *Calculate AORs based on WILLINGNESS
   */

  for(i = WILL_ALWAYS - 1; i > WILL_NEVER; i--)
    {
      two_hop_list = wospf_find_2_hop_neighbors_with_1_link(i);

      while(two_hop_list != NULL)
	{
	  //printf("CHOSEN FROM 1 LINK\n");
	  if(!two_hop_list->neighbor_2->neighbor_2_nblist.next->neighbor->is_aor)
	    wospf_chosen_aor(two_hop_list->neighbor_2->neighbor_2_nblist.next->neighbor, &two_hop_covered_count); 
	  tmp = two_hop_list;
	  two_hop_list = two_hop_list->next;;
	  free(tmp);
	}
      
      if(two_hop_covered_count >= two_hop_count)
	{
	  i = WILL_NEVER;
	  break;
	}

      //printf("two hop covered count: %d\n", two_hop_covered_count);
   
      while((aors = wospf_find_maximum_covered(i)) != NULL)
	{
	  //printf("CHOSEN FROM MAXCOV\n");
	  wospf_chosen_aor(aors,&two_hop_covered_count);

	  if(two_hop_covered_count >= two_hop_count)
	    {
	      i = WILL_NEVER;
	      break;
	    }

	}
    }
  
  /*
    increment the mpr sequence number
  */
  //neighbortable.neighbor_mpr_seq++;

  /* Optimize selection */
  wospf_optimize_aor_set();

  //if(wospf_check_aor_changes())
  //{
  //  WOSPF_PRINTF(3, "CHANGES IN AOR SET");
  // }

  wospf_update_aor_lists();

}

/**
 *Optimize AOR set by removing all entries
 *where all 2 hop neighbors actually is
 *covered by enough MPRs already
 *Described in RFC3626 section 8.3.1
 *point 5
 *
 *@return nada
 */
static void
wospf_optimize_aor_set()
{
  int i, remove, index;
  struct wospf_neighbor_2_list_entry *two_hop_list;
  struct wospf_neighbor_entry *a_neighbor, *dup_neighbor;

  for(i = WILL_NEVER + 1; i < WILL_ALWAYS; i++)
    {

      for(index=0;index<HASHSIZE;index++)
	{

	  for(a_neighbor = neighbortable[index].next;
	      a_neighbor != &neighbortable[index];
	      a_neighbor = a_neighbor->next)
	    {
	      
	      if(a_neighbor->willingness != i)
		continue;
	      
	      if(a_neighbor->is_aor)
		{
		  //printf("\tChecking %s\n", olsr_ip_to_string(&a_neighbor->neighbor_main_addr));
		  remove = 1;

		  for(two_hop_list = a_neighbor->neighbor_2_list.next;
		      two_hop_list != &a_neighbor->neighbor_2_list;
		      two_hop_list = two_hop_list->next)
		    {
		      
		      dup_neighbor = wospf_lookup_neighbor_table(two_hop_list->neighbor_2->neighbor_2_id);
		      
		      if(dup_neighbor != NULL)
			continue;
		      
		      //printf("\t[%s] coverage %d\n", olsr_ip_to_string(&two_hop_list->neighbor_2->neighbor_2_addr), two_hop_list->neighbor_2->mpr_covered_count);
		      /* Do not remove if we find a entry which need this MPR */
		      if(two_hop_list->neighbor_2->aor_covered_count <= wospf_cfg->aor_coverage)
			remove = 0;
		      
		    }
		  if(remove)
		    {
		      WOSPF_PRINTF(3, "AOR OPTIMIZE: removing AOR %s", WOSPF_ID(&a_neighbor->router_id))
		      a_neighbor->is_aor = WOSPF_FALSE;
		    }
		}
	    }
	}
    }
}

void
wospf_print_aor_set()
{
  int index;
  struct wospf_neighbor_entry *a_neighbor;
  int counter = 0;
  wospf_bool ok = WOSPF_FALSE;

  /* For debug output purposes only */
  for(index=0;index<HASHSIZE;index++)
    {
      for(a_neighbor = neighbortable[index].next;
	  a_neighbor != &neighbortable[index];
	  a_neighbor = a_neighbor->next)
	{ 
	  if(a_neighbor->is_aor)
	    ok = WOSPF_TRUE;
	  break;
	}
    }
  
  //if (ok == WOSPF_TRUE) {
  WOSPF_PRINTF(11, "AOR SET: ");
  //}
  //else WOSPF_PRINTF(1, "AOR SET is emtpy ");
  
  
  for(index=0;index<HASHSIZE;index++)
    {
      for(a_neighbor = neighbortable[index].next;
	  a_neighbor != &neighbortable[index];
	  a_neighbor = a_neighbor->next)
	{ 
	  
	  /* 
	   * Remove AOR settings
	   */
	  if(a_neighbor->is_aor)
 	    WOSPF_PRINTF(11, "    %d: %s", ++counter, a_neighbor->name);
	}
    }

  

}


static void
wospf_update_aor_lists() {
  u_int32_t index;
  struct wospf_neighbor_entry       *a_neighbor;
  struct persistent_node *pers;

  for (index=0;index<HASHSIZE;index++)
    {
      for(a_neighbor = neighbortable[index].next;
	  a_neighbor != &neighbortable[index];
	  a_neighbor = a_neighbor->next)
	{
	 
	  /* New AOR */
	  if(a_neighbor->is_aor == WOSPF_TRUE && 
	     a_neighbor->was_aor == WOSPF_FALSE) {
	    
	    pers = wospf_malloc(sizeof(struct persistent_node), "Persistent node");
	    pers->persistent_count = WOSPF_AOR_PERS;
	    pers->neighbor = a_neighbor;
	    listnode_add(lls_message->aor_message->added_relays, pers);
	    lls_message->aor_message->relays_added++;
	  }
	
	  /* Dropped AOR */
	  else if(a_neighbor->is_aor == WOSPF_FALSE && 
		  a_neighbor->was_aor == WOSPF_TRUE) {
	    
	    pers = wospf_malloc(sizeof(struct persistent_node), "Persistent node");
	    pers->persistent_count = WOSPF_DROPPED_AOR_PERS;
	    pers->neighbor = a_neighbor;
	    listnode_add(lls_message->aor_message->dropped_relays, pers);
	  }
	  
	}
    }
}
