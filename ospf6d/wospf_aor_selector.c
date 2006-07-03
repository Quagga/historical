/*
** wospf_aor_selector.c
** 
** Made by (Kenneth Holter)
** Login   <kenneho@localhost.localdomain>
** 
** Started on  Sat May  6 15:20:15 2006 Kenneth Holter
** Last update Sat May 27 17:59:16 2006 Kenneth Holter
*/

#include "wospf_top.h"

#include "wospf_aor_selector.h"


/* AOR selector list */
static struct aor_selector aors_list;



wospf_bool is_AOR_selector(ID router_id) {

  return wospf_lookup_aors_set(router_id) != NULL;
}


void
wospf_init_aor_selector_set() {

  aors_list.next = &aors_list;
  aors_list.prev = &aors_list;

}


/**
 *Add an AOR selector to the AOR selector set
 *
 *@param router ID of the AOR selector
 *
 *@return a pointer to the new entry
 */
struct aor_selector *
wospf_add_aor_selector(ID router_id)
{
  struct aor_selector *new_entry;

  WOSPF_PRINTF(1, "AOR Selector: Adding %s", WOSPF_ID(&router_id))

  new_entry = wospf_malloc(sizeof(struct aor_selector), "Add AOR selector");

  /* Fill struct */
  new_entry->router_id = router_id;

  /* Queue */
  QUEUE_ELEM(aors_list, new_entry);
  
  return new_entry;
}



/**
 *Lookup an entry in the AOR selector table
 *based on router ID
 *
 *@param router ID the address to check for
 *
 *@return a pointer to the entry or NULL
 */
struct aor_selector *
wospf_lookup_aors_set(ID router_id)
{
  struct aor_selector *aors;
  
  aors = aors_list.next;
  
  while(aors != &aors_list)
    {

      if (aors == NULL) {
	zlog_err("ERROR in wospf_lookup_aors_set: entry is NULL");
	break;
      }

      if(aors->router_id == router_id)
	{
	  return aors;
	}
      aors = aors->next;
    }
  
  return NULL;
}


/**
 *Update an AOR selector entry or create an new
 *one if it does not exist
 *
 *@param router ID of the MPR selector
 *
 *@return 1 if a new entry was added 0 if not
 */
int
wospf_update_aors_set(ID router_id)
{
  struct aor_selector *aors;
  int retval;

  WOSPF_PRINTF(33, "AOR Selector: Update %s\n", WOSPF_ID(&router_id));
  
  retval = 0;

  if(NULL == (aors = wospf_lookup_aors_set(router_id)))
    {
      wospf_add_aor_selector(router_id);
      retval = 1;
    }
  
  return retval;
}


int
wospf_delete_aor_selector(ID router_id) {
  
  struct aor_selector *aors;
  int retval;
  
  retval = 0;
  
  if(NULL != (aors = wospf_lookup_aors_set(router_id)))
    {
      DEQUEUE_ELEM(aors);
      WOSPF_PRINTF(1, "AOR Selector: Removing %s", WOSPF_ID(&router_id));
      retval = 1;
      free(aors);
    }
  
  return retval;

}
