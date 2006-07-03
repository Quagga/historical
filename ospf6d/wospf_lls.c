/*
** wospf_lls.c
** 
** Made by (Kenneth Holter)
** Login   <kenneho@localhost.localdomain>
** 
** Started on  Sat May  6 17:28:48 2006 Kenneth Holter
** Last update Sun May 28 16:27:19 2006 Kenneth Holter
*/

#include <zebra.h>
#include "vty.h"

#include "linklist.h"
#include "checksum.c"

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

#include "wospf_flood.h"
#include "wospf_aor_selector.h"
#include "wospf_protocol.h"
#include "wospf_top.h"
#include "wospf_neighbor_table.h"
#include "wospf_defs.h"
#include "wospf_lls.h"


/************************************/
/********** Incoming packets ********/
/************************************/

static void update_req_list(struct wospf_neighbor_entry *neighbor) {
  struct list *list;
  struct listnode *node;
  struct persistent_node *pers, *new;
  wospf_bool match = WOSPF_FALSE;

  list = lls_message->req_fs_from_message->req_fs_from_neighbors;

  for (node = list->head; node; nextnode (node)) {
    pers = getdata (node);
    
    if (pers->neighbor->router_id == neighbor->router_id) {
      match = WOSPF_TRUE;
      break;
    }
  }

  if (!match) {
    WOSPF_PRINTF(99, "Building Req node for %s", neighbor->name);

    new = wospf_malloc(sizeof(struct persistent_node), "Persistent node");
    new->neighbor = neighbor;
    new->persistent_count = WOSPF_REQ_PERS; /* Omit this? */

    listnode_add(list, new);

  }

}

static void delete_req_list(struct wospf_neighbor_entry *neighbor) {
  struct list *list;
  struct listnode *node, *nextnode;
  struct persistent_node *pers;
 
  list = lls_message->req_fs_from_message->req_fs_from_neighbors;

  for (ALL_LIST_ELEMENTS (list, node, nextnode, pers)) {
        
    if (pers->neighbor->router_id == neighbor->router_id) {
      
      if (pers->persistent_count > 0) {

	WOSPF_PRINTF(9, "Req FS list: Decreasing %s's counter", neighbor->name);
	pers->persistent_count--;
	
      }
      
      if (pers->persistent_count == 0) {
	
	WOSPF_PRINTF(3, "Removing %s from request fs list", neighbor->name);
	list_delete_node(list, node);
	free(pers);
      }
      
      return;

      
    }
  }

}


static void update_fs_list(struct wospf_neighbor_entry *neighbor) {
  struct list *list;
  struct listnode *node;
  struct persistent_node *pers, *new;
  wospf_bool match = 0;

  list = lls_message->fs_for_message->fs_for_neighbors;

  for (node = list->head; node; nextnode (node)) {
    pers = getdata (node);
    
    if (pers->neighbor->router_id == neighbor->router_id) {

      if (pers->persistent_count == 0) {
	WOSPF_PRINTF(3, "Removing %s from fs for list", neighbor->name);
	list_delete_node(list, node);
	free(pers);
	match = WOSPF_TRUE;
      }
      else pers->persistent_count--;

      break;
    }
  }

  if (!match) {
    WOSPF_PRINTF(99, "%s requested full state - building FS node", neighbor->name);

    new = wospf_malloc(sizeof(struct persistent_node), "Persistent node");
    new->neighbor = neighbor;
    new->persistent_count = WOSPF_FS_PERS; /* Omit this? */

    listnode_add(list, new);
    
  }

}



static char *parse_scs_tlv(char *, struct scs_tlv_message *);
static char *parse_neighbor_drop_tlv(char *, struct neighbor_drop_tlv_message *);
static char *parse_req_fs_tlv(char *, struct req_tlv_message *);
static char *parse_fs_for_tlv(char *, struct fs_tlv_message *);
static char *parse_aor_tlv(char *, struct aor_tlv_message *);
static char *parse_will_tlv(char *, struct will_tlv_message *);


struct wospf_lls_message *wospf_parse_lls_block(char *start_pos) {
  struct wospf_lls_message *lls_message;
  uint16_t checksum, my_checksum, lls_length, type;
  char *end_pos, *pointer;
  int n_bytes;

  pointer = start_pos;

  checksum   = *(uint16_t *)pointer; pointer += 2;
  lls_length = *(uint16_t *)pointer; pointer += 2;

  end_pos = start_pos + (lls_length * 4);

  n_bytes = lls_length * 4;

  /* This does not work */
  my_checksum = in_cksum(start_pos, n_bytes);
  
  WOSPF_PRINTF(99, "Got checksum %d, calculated %d", checksum, my_checksum);
  if (my_checksum == checksum) {
    WOSPF_PRINTF(99, "  -- Correct! ");
  }
  else {
    WOSPF_PRINTF(99, "  -- WRONG (length: %d)! ", n_bytes);
  }


  lls_message = wospf_malloc(sizeof(struct wospf_lls_message), "LLS data block");
  lls_message->scs_message = NULL;
  lls_message->neighbor_drop_message = NULL;
  lls_message->req_fs_from_message = NULL;
  lls_message->fs_for_message = NULL;
  lls_message->aor_message = NULL;
  lls_message->will_message = NULL;


  /* While we have more TLVs to examine */
  while (pointer < end_pos) {

    type = *pointer;

    switch (type) {
      
    case 1:
      lls_message->scs_message = wospf_malloc(sizeof(struct scs_tlv_message), "SCS TLV");
      pointer = parse_scs_tlv(pointer, lls_message->scs_message);
      break;
    case 2: 
      lls_message->neighbor_drop_message = wospf_malloc(sizeof(struct neighbor_drop_tlv_message), "Neighbor Drop TLV");
      pointer = parse_neighbor_drop_tlv(pointer, lls_message->neighbor_drop_message);
      break;
    case 3: 
      lls_message->req_fs_from_message = wospf_malloc(sizeof(struct req_tlv_message), "RF TLV");
      pointer = parse_req_fs_tlv(pointer, lls_message->req_fs_from_message);
      break;
    case 4: 
      lls_message->fs_for_message = wospf_malloc(sizeof(struct fs_tlv_message), "FS TLV");
      pointer = parse_fs_for_tlv(pointer, lls_message->fs_for_message);
      break;
    case 5: 
      lls_message->aor_message = wospf_malloc(sizeof(struct aor_tlv_message), "AOR TLV");
      pointer = parse_aor_tlv(pointer, lls_message->aor_message);
      if (lls_message->aor_message == NULL) zlog_err("ERROR when parsing AOR TLV! ");
      break;
    case 6: 
      lls_message->will_message = wospf_malloc(sizeof(struct will_tlv_message), "Will TLV");
      pointer = parse_will_tlv(pointer, lls_message->will_message);
      break;

    }

  }

  return lls_message;
}

char *parse_scs_tlv(char *start_pos, struct scs_tlv_message *tlv) {
  char *pointer;

  pointer = start_pos;
  
  tlv->fs_bit_set = WOSPF_FALSE;
  tlv->r_bit_set = WOSPF_FALSE;
  tlv->n_bit_set = WOSPF_FALSE;
  
  tlv->type = *(uint16_t *)pointer; pointer += 2;
  tlv->length = *(uint16_t *)pointer; pointer += 2;
  tlv->scs_number = *pointer; pointer += 2;
  
  if (WOSPF_BIT_ISSET(pointer, WOSPF_BIT_FS))
    tlv->fs_bit_set = WOSPF_TRUE;
  if (WOSPF_BIT_ISSET(pointer, WOSPF_BIT_N))
    tlv->n_bit_set = WOSPF_TRUE;
  if (WOSPF_BIT_ISSET(pointer, WOSPF_BIT_R)) {
    tlv->r_bit_set = WOSPF_TRUE;
    WOSPF_PRINTF(99, "R bit set! ");
  }
  
  pointer += 2;

  return pointer;
}

static char *parse_neighbor_drop_tlv(char *start_pos, struct neighbor_drop_tlv_message *tlv) {
  char *pointer;
  int i; 
  u_int32_t *id_pointer;
  ID router_id;
  struct id_container *id_container;
 
  pointer = start_pos;

  tlv->dropped_neighbors = list_new();

  tlv->type = *(uint16_t *)pointer; pointer += 2;
  tlv->length = *(uint16_t *)pointer; pointer += 2;

  for (i = 0; i < tlv->length; i++) {
    id_pointer = (u_int32_t *)pointer;

    router_id = *id_pointer;
    
    id_container = wospf_malloc(sizeof(struct id_container), "ID container");
    id_container->router_id = router_id;
    listnode_add(tlv->dropped_neighbors, id_container);
    
    pointer += 4;
  }

  return pointer;
}

static char *parse_req_fs_tlv(char *start_pos, struct req_tlv_message *tlv) {
  char *pointer;
  int i;
  u_int32_t *id_pointer;
  ID router_id;
  struct id_container *id_container;

  pointer = start_pos;
  
  tlv->req_fs_from_neighbors = list_new();

  tlv->type = *(u_int16_t *)pointer; pointer += 2;
  tlv->length = *(u_int16_t *)pointer; pointer += 2;

  WOSPF_PRINTF(99, "Parsing Req TLV (length: %d)... ", tlv->length);
  
  for (i = 0; i < tlv->length; i++) {
    id_pointer = (u_int32_t *)pointer;

    router_id = *id_pointer;
    
    WOSPF_PRINTF(99, "    - %s", WOSPF_ID(&router_id));

    id_container = wospf_malloc(sizeof(struct id_container), "ID container");
    id_container->router_id = router_id;
    listnode_add(tlv->req_fs_from_neighbors, id_container);
    
    pointer += 4;
  }
  
  return pointer;
}

static char *parse_fs_for_tlv(char *start_pos, struct fs_tlv_message *tlv) {
  char *pointer;
  int i;
  u_int32_t *id_pointer;
  ID router_id;
  struct id_container *id_container;

  pointer = start_pos;

  tlv->fs_for_neighbors = list_new();
  
  tlv->type = *(uint16_t *)pointer; pointer += 2;
  tlv->length = *(uint16_t *)pointer; pointer += 2;

  for (i = 0; i < tlv->length; i++) {
    id_pointer = (u_int32_t *)pointer;

    router_id = *id_pointer;
    
    id_container = wospf_malloc(sizeof(struct id_container), "ID container");
    id_container->router_id = router_id;
    listnode_add(tlv->fs_for_neighbors, id_container);
    
    pointer += 4;
  }

  return pointer;
}

static char *parse_aor_tlv(char *start_pos, struct aor_tlv_message *tlv) {
  char *pointer; 
  uint16_t i, number_dropped;
  uint32_t *id_pointer; 
  ID router_id;
  u_int8_t *relays_added_pointer;

  pointer = start_pos;
 
  tlv->type = *(uint16_t *)pointer; pointer += 2;
  tlv->length = *(uint16_t *)pointer; pointer += 2;
  relays_added_pointer = (u_int8_t *)pointer;
  tlv->relays_added = *relays_added_pointer; pointer += 1;
  
  if (tlv->relays_added > 0) 
    tlv->added_relays = list_new();

  if (WOSPF_BIT_ISSET(pointer, WOSPF_BIT_ALWAYS)) {
    tlv->will_always = WOSPF_TRUE;
  }
  if (WOSPF_BIT_ISSET(pointer, WOSPF_BIT_NEVER)) {
    tlv->will_never = WOSPF_TRUE;
  }

  pointer += 3;

  WOSPF_PRINTF(33, "Parse incoming AOR TLV");

  number_dropped = tlv->length - (tlv->relays_added + 2);
  
  WOSPF_PRINTF(33, "   Added AOR: %d, Dropped AORs: %d, TLV length: %d", tlv->relays_added, number_dropped, 
	       tlv->length);

  tlv->added_relays = list_new();
  tlv->dropped_relays = list_new();
  
  for (i = 0; i < tlv->relays_added; i++) {
    id_pointer = (u_int32_t *)pointer;

    router_id = *id_pointer;

    WOSPF_PRINTF(33, "      add %s", WOSPF_ID(&router_id));

    struct id_container *id_con;

    id_con = wospf_malloc(sizeof(struct id_container), "ID container for added relay");
    id_con->router_id = (ID)router_id;
    listnode_add(tlv->added_relays, id_con);
    
    pointer += 4;
  }

  if (tlv->length > (tlv->relays_added + 2)) {
    
    for (i = 0; i < number_dropped; i++) {
      id_pointer = (u_int32_t *)pointer;

      router_id = *id_pointer;
      
      WOSPF_PRINTF(33, "      drop %s", WOSPF_ID(&router_id));
      
      struct id_container *id_con;

      id_con = wospf_malloc(sizeof(struct id_container), "ID container for dropped relay");
      id_con->router_id = (ID)router_id;
      listnode_add(tlv->dropped_relays, id_con);
      
      pointer += 4;
    }

  }

  return pointer;
  
}

static char *parse_will_tlv(char *start_pos, struct will_tlv_message *tlv) {
  char *pointer;

  pointer = start_pos;
  
  tlv->type = *(uint16_t *)pointer; pointer += 2;
  tlv->length = *(uint16_t *)pointer; pointer += 2;
  tlv->will = *pointer; pointer += 4;
  
  return pointer;
}





/*********************************************/
/* Analyze the contents of the incoming TLVs */
/*********************************************/

static void process_scs_message(struct wospf_neighbor_entry *, struct wospf_lls_message *,
				struct list *);
static void process_aor_message(struct wospf_neighbor_entry *, struct aor_tlv_message *);
static void process_will_message(struct wospf_neighbor_entry *, struct will_tlv_message *);

void wospf_process_tlvs(ID router_id, struct wospf_lls_message *lls_message, 
			struct list *neighbor_list) {

  struct wospf_neighbor_entry *neighbor;

  if ((neighbor = wospf_lookup_neighbor_table(router_id)) == NULL) {
    WOSPF_PRINTF(22, "Ignoring TLVs: %s is not registered with the neighbor table!", 
		 WOSPF_ID(&router_id));
    return;
  }

  if (lls_message->scs_message != NULL)
    process_scs_message(neighbor, lls_message, neighbor_list);
  
  if (lls_message->aor_message != NULL)
    process_aor_message(neighbor, lls_message->aor_message);
  
  if (lls_message->will_message != NULL)
    process_will_message(neighbor, lls_message->will_message);

  /* Note that the contents of Dropped, FS and Request TLVs are
     processed in the SCS TLV processing function. This follows from
     that these TLVs are parsed based on the information carried in
     the SCS TLV */

  free(lls_message);

}


/* Cisco's draft, section 3.3.8*/
static void 
process_scs_message(struct wospf_neighbor_entry *neighbor, struct wospf_lls_message *lls_message, 
		    struct list *neighbor_list) {
  struct scs_tlv_message *scs_message;
  wospf_bool wrap_around = WOSPF_FALSE;
  wospf_bool update_scs_number = WOSPF_FALSE;
  struct list *dropped_neighbors = NULL;
  ID my_id;

  my_id = ospf6->router_id;

  if ((scs_message = lls_message->scs_message) == NULL) {
    WOSPF_PRINTF(2, "No SCS TLV included in LLS data block! Abort processing of TLVs. ");
    return;
  }

  /* Debug */
  if (scs_message->scs_number != neighbor->scs_number ||
      scs_message->fs_bit_set ||
      scs_message->r_bit_set) {
    WOSPF_PRINTF(2, "     "); 
    WOSPF_PRINTF(2, "Got SCS number %d from %s (old: %d)", scs_message->scs_number, neighbor->name, 
		 neighbor->scs_number);
  }

  /* Section 3.3.8.1: Send Hello request if new SCS number but n bit
     is set. Note that the TLV is parsed regardless of this bullet */
  if (scs_message->n_bit_set && update_scs_number == WOSPF_TRUE) {
    WOSPF_PRINTF(2, "Got new SCS number, but N-bit is set -> req full state from %s", neighbor->name);
    
    update_req_list(neighbor);
    return;
  }

  /* Section 3.3.8.3 */
  if (scs_message->fs_bit_set) {
    
    /* Bullett 1 */
    if (scs_message->scs_number == neighbor->scs_number) {
      
      /* Ignore packet - no new information  */
      WOSPF_PRINTF(3, "FS bit set, but SCS number has not changed - ignoring packet");
      return; 
    }

    /* Bullett 2: */
    else {
      /* Process new information (do nothing for now) */
      WOSPF_PRINTF(3, "FS bit set, and SCS number has changed - parsing packet");
    }


    /* Bullett 3: If full state was intended for me, save the SCS number */
    if (lls_message->fs_for_message == NULL ||
	wospf_lookup_id_list(lls_message->fs_for_message->fs_for_neighbors, my_id) == WOSPF_TRUE) {
 
      if (lls_message->fs_for_message == NULL) {
	WOSPF_PRINTF(2, "FS bit & no FS TLV");
      }
      else if (wospf_lookup_id_list(lls_message->fs_for_message->fs_for_neighbors, my_id) == WOSPF_TRUE) {
	WOSPF_PRINTF(2, "FS bit & I'm included in FS TLV");
      }
      else {
	WOSPF_PRINTF(2, "FS bit, but I'm not listed in the FS TLV. Error??");
      }

      WOSPF_PRINTF(2, "Adjusting %s's SCS number from %d to %d", neighbor->name, neighbor->scs_number, 
		   scs_message->scs_number);
      neighbor->scs_number = scs_message->scs_number;
      
      delete_req_list(neighbor);


      /* Problem with draft vagueness: 
	 Section 3.3.8.3 bullet 2 states that the packet MUST be
	 parsed, as this Hello has new information. This seams
	 reasonable. However, the next bullet states that the SCS
	 number MUST be saved, and the Hello processed as described in
	 the "Receiving Hellos" section. But as the neighbor's SCS
	 number now is set equal to the received SCS number the packet
	 is assumed not to carry any new information (section 3.3.8
	 does not indicate that packets with non-changed SCS numbers
	 are to be processed). 
      */
      
    }
  }

  
  /* Section 3.3.8.2 */
  if (scs_message->r_bit_set) {

    /* DEBUG */
    if (lls_message->req_fs_from_message == NULL) {
      WOSPF_PRINTF(2, "R bit & no Req TLV");
    }
    else if (wospf_lookup_id_list(lls_message->req_fs_from_message->req_fs_from_neighbors, my_id) == WOSPF_TRUE) {
      WOSPF_PRINTF(2, "R bit & I'm included in Req TLV");
    }
    else WOSPF_PRINTF(2, "R bit set, but I'm not listed in the Req TLV & Req TLV present");

    /* If the sender is requesting full state from me */
    if (lls_message->req_fs_from_message == NULL ||
	wospf_lookup_id_list(lls_message->req_fs_from_message->req_fs_from_neighbors, my_id) == WOSPF_TRUE) {
      
      update_fs_list(neighbor);
      
    }
  }
  

  if (lls_message->neighbor_drop_message != NULL)
    dropped_neighbors = lls_message->neighbor_drop_message->dropped_neighbors;


  
  /* Check for wrap-around */
  if (scs_message->scs_number == 1 && neighbor->scs_number == MAX_SCS) {
    /* Accept SCS number */
    WOSPF_PRINTF(2, "SCS number wrap around");

    wrap_around = WOSPF_TRUE;
  }
  
  if (scs_message->scs_number < neighbor->scs_number) {
    
    
    if (!wrap_around) {
      WOSPF_PRINTF(2, "Got SCS number %d, expected %d -> requesting full state", 
		   scs_message->scs_number, neighbor->scs_number);

      /* Request full state from this neighbor */
      update_req_list(neighbor);
    }
    
  }

  else if (scs_message->scs_number == neighbor->scs_number) {

    /* Draft, section 3.3.8.1 */
    if (scs_message->n_bit_set == WOSPF_FALSE) {
      WOSPF_PRINTF(2, "SCS number has not changed, but N bit is not set! ERROR! ");
      
      /* Request full state from this neighbor */
      update_req_list(neighbor);
      
    }

    /* Correct */
    else {
      WOSPF_PRINTF(99, "SCS number has not changed, and N bit is set.  ");
    }

  }


  else if (scs_message->scs_number == neighbor->scs_number + 1 || wrap_around) {
  
    WOSPF_PRINTF(99, "New SCS number...");

    /* Bullet 1. Modification: Since entries into the WOSPF-OR
       neighbor table are made when a new OSPFv3 neighbor becomes
       adjacent, perform an additional check to see if the neighbor is
       "new" - my router ID will not be included in the Hello's neighbor list */
    if (!list_isempty(neighbor_list)) {
      WOSPF_PRINTF(99, "   - Neighbor list is not empty");
      update_scs_number = WOSPF_TRUE;
    }
    
    /* Bullet 3. NB! Changed order of bullet 2 and 3 */
    if (dropped_neighbors != NULL && 
	wospf_lookup_id_list(dropped_neighbors, my_id) == WOSPF_TRUE) {
      WOSPF_PRINTF(2, "   - I'm being dropped");
      ospf6_neighbor_delete(neighbor->on);
      return;
    }

    /* Bullet 2. NB! Changed order of bullet 2 and 3. If control
       reaches this bullet I was not dropped by the neighbor. Check if
       the dropped neighbor list is not emtpy (i.e. it contains other
       entries) */
    if (dropped_neighbors != NULL && 
	!list_isempty(dropped_neighbors)) {
      WOSPF_PRINTF(2, "   - Dropped neighbor list is not empty");
      update_scs_number = WOSPF_TRUE;
    }    

    /* Bullet 4: Examine other TLVs (i.e. TLV not defined in Cisco's
       draft). Not relevant to this implementation */
    
    /* Bullet 5. If the update_scs_number variable is still false, no
       state change information was present in the TLVs. Request full
       state. */
    if (update_scs_number == WOSPF_FALSE) {
      WOSPF_PRINTF(2, "Updated SCS number, but no state change information -> req full state from %s", 
		   neighbor->name);
      update_req_list(neighbor);
    }

    
    
  }
  
  /* The received SCS number is >1 than registered scs number */
  else {
    WOSPF_PRINTF(2, "Got SCS number %d, expected %d -> requesting full state", 
		 scs_message->scs_number, neighbor->scs_number);
    
    update_req_list(neighbor);

  }

  if (update_scs_number) {
    WOSPF_PRINTF(2, "Increasing %s's SCS number from %d to %d", neighbor->name, neighbor->scs_number, 
		 neighbor->scs_number + 1);
    neighbor->scs_number++;
  }
  
}


static void 
process_aor_message(struct wospf_neighbor_entry *neighbor, struct aor_tlv_message *tlv) {
  //struct id_container *my_id;
  ID my_id;

  WOSPF_PRINTF(33, "Processing incoming AOR TLV from %s", neighbor->name);

  my_id = ospf6->router_id;

  //my_id = wospf_malloc(sizeof(struct id_container), "ID container");
  //my_id->router_id = (ID)ospf6->router_id;
  
  if (wospf_lookup_id_list(tlv->added_relays, my_id) == WOSPF_TRUE) {
    
    /* Update or create new AOR selector */
    wospf_update_aors_set(neighbor->router_id);
  }
  
  if (wospf_lookup_id_list(tlv->dropped_relays, my_id) == WOSPF_TRUE) {
    
    wospf_delete_aor_selector(neighbor->router_id);
    
  }

  
}

static void 
process_will_message(struct wospf_neighbor_entry *neighbor, struct will_tlv_message *tlv) {

  neighbor->willingness = tlv->will;

}

/************************************/
/********** Outgoing packets ********/
/************************************/

static char *append_aor_tlv(char *);
static char *append_will_tlv(char *);
static char *append_scs_tlv(char *);
static char *append_neighbor_drop_tlv(char *);
static char *append_req_fs_tlv(char *, struct ospf6_interface *);
static char *append_fs_tlv(char *, struct ospf6_interface *);

char *wospf_append_lls(char *start_pos, struct ospf6_interface *oi) {
  char *pointer, *checksum_pos, *length_pos;
  uint16_t total_length;
  uint16_t checksum;

  //WOSPF_PRINTF(3, "Appending LLS data block ");
  
  /* Update the local SCS number */
  if (state_changes) { 
    lls_message->scs_message->scs_number++;
  }
 
  pointer = start_pos;
  
  checksum_pos = pointer; pointer += 2;
  length_pos = pointer; pointer += 2;
  
  pointer = append_aor_tlv(pointer);
  pointer = append_will_tlv(pointer);
  
  pointer = append_scs_tlv(pointer);
  pointer = append_neighbor_drop_tlv(pointer);
  pointer = append_req_fs_tlv(pointer, oi);
  pointer = append_fs_tlv(pointer, oi);

  /* XXX: Ouch ouch. This should all be using lib/stream. ouch. */
  total_length = ((int)pointer - (int)start_pos) / 4;
  *(uint16_t *)length_pos = total_length;

  /* NB! in_cksum takes length in bytes as second argument */
  checksum = in_cksum(start_pos, total_length * 4);
  *(uint16_t *)checksum_pos = checksum;

  state_changes = WOSPF_FALSE;

  WOSPF_PRINTF(99, "CHECKSUM out: %d",   *(uint16_t *)checksum_pos);
  
  /* If no TLVs are included (only the LLS header) */
  if (total_length == 1) 
    return start_pos;
  
  return pointer;
}

static char *append_aor_tlv(char *pointer) {
  struct aor_tlv_message *tlv;
  struct listnode *node, *nextnode;
  struct persistent_node *pers;
  uint16_t *length_pointer;
  char *start_pos;
  ID *id_pointer;

  start_pos = pointer;

  if (list_isempty(lls_message->aor_message->added_relays) &&
      list_isempty(lls_message->aor_message->dropped_relays)) {
    /* Nothing to be signaled - abort */
    return pointer;
  }

  WOSPF_PRINTF(22, "Building AOR TLV: ");

  tlv = lls_message->aor_message;

  *(uint16_t *)pointer = tlv->type; pointer += 2;
  length_pointer = (uint16_t *)pointer; pointer += 2;
  *pointer = tlv->relays_added; pointer += 1;

  /* Setting bits! */ 
  if (tlv->will_always) {
    WOSPF_BIT_SET(pointer, WOSPF_BIT_ALWAYS);
  }
  else if (tlv->will_never) {
    WOSPF_BIT_SET(pointer, WOSPF_BIT_NEVER);
  }

  pointer += 3;

  /* Add new AOR elections */
  for (ALL_LIST_ELEMENTS (tlv->added_relays, node, nextnode, pers)) {
    id_pointer = (ID *)pointer;

    assert(pers->neighbor);

    *(ID *)id_pointer = pers->neighbor->router_id; pointer += 4;
    pers->persistent_count--;

    WOSPF_PRINTF(22, "       new AOR: %s (pers: %d)", WOSPF_ID(&*id_pointer), 
		 pers->persistent_count);
    
    if (pers->persistent_count == 0) {
      list_delete_node(tlv->added_relays, node);
      tlv->relays_added--;
    }
  }

  /* Add dropped AORs */
  for (ALL_LIST_ELEMENTS (tlv->dropped_relays, node, nextnode, pers)) {
    id_pointer = (ID *)pointer;

    *(ID *)id_pointer = pers->router_id; pointer += 4;
    pers->persistent_count--;

    WOSPF_PRINTF(22, "   dropped AOR: %s (pers: %d)", WOSPF_ID(&*id_pointer),
		 pers->persistent_count);

    if (pers->persistent_count == 0) {
      list_delete_node(tlv->dropped_relays, node);
    }
  }

  *(uint16_t *)length_pointer = ((int)pointer - (int)start_pos) / 4;
  WOSPF_PRINTF(22, "   Length of AOR TLV: %d", *length_pointer);

  return pointer;
}

static char *append_will_tlv(char *pointer) {
  struct will_tlv_message *tlv;

  tlv = lls_message->will_message;

  if (tlv->will_pers_count-- > 0) {
    *(uint16_t *)pointer = tlv->type; pointer += 2;
    *(uint16_t *)pointer = tlv->length; pointer += 2;
    *pointer = tlv->will; pointer += 4;

    //WOSPF_PRINTF(2, "Building Will TLV (will = %d)", tlv->will);
  }  

  return pointer;
}


static char *append_scs_tlv(char *pointer) {
  struct scs_tlv_message *tlv;

  tlv = lls_message->scs_message;
  
  WOSPF_PRINTF(99, "Building SCS TLV with SCS number %d", tlv->scs_number);

  *(u_int16_t *)pointer = tlv->type; pointer += 2;
  *(u_int16_t *)pointer = tlv->length; pointer += 2;
  *(u_int16_t *)pointer = tlv->scs_number; pointer += 2;

  /* Setting bits */

  /* If I'm requesting full state */
  if (listcount(lls_message->req_fs_from_message->req_fs_from_neighbors) > 0) {
    WOSPF_PRINTF(99, "Setting R bit");
    WOSPF_BIT_SET(pointer, WOSPF_BIT_R);
  }
  /* If I'm responding with full state */
  if (listcount(lls_message->fs_for_message->fs_for_neighbors) > 0) {
    WOSPF_PRINTF(99, "Setting FS bit");
    WOSPF_BIT_SET(pointer, WOSPF_BIT_FS);
  }
  if (state_changes == WOSPF_FALSE) {
    WOSPF_PRINTF(99, "Setting N bit");
    WOSPF_BIT_SET(pointer, WOSPF_BIT_N);
  }

  pointer += 2;

  return pointer;
}

static char *append_neighbor_drop_tlv(char *pointer) {
  struct neighbor_drop_tlv_message *tlv;
  struct listnode *node, *nextnode;
  struct persistent_node *pers;
  
  if (list_isempty(lls_message->neighbor_drop_message->dropped_neighbors)) {
     /* Nothing to be signaled - abort */
    return pointer;
  }

  WOSPF_PRINTF(2, "Building Neighbor Drop TLV");

  tlv = lls_message->neighbor_drop_message;
  
  *(uint16_t *)pointer = tlv->type; pointer += 2;
  *(uint16_t *)pointer = tlv->length; pointer += 2;

  for (ALL_LIST_ELEMENTS (tlv->dropped_neighbors, node, nextnode, pers)) {
    *(ID *)pointer = pers->router_id; pointer += 4;
    pers->persistent_count--;

    WOSPF_PRINTF(2, "   dropping %s (pers: %d)", WOSPF_ID(&pers->router_id), pers->persistent_count);

    if (pers->persistent_count == 0) {
      list_delete_node(tlv->dropped_neighbors, node);
    }
  }


  return pointer;
}
static char *append_req_fs_tlv(char *start_pos, struct ospf6_interface *oi) {
  struct req_tlv_message *tlv;
  struct listnode *node, *nextnode;
  struct persistent_node *pers;
  ID *id_pointer;
  char *pointer;
  wospf_bool omit = WOSPF_FALSE;

  pointer = start_pos;

  if (list_isempty(lls_message->req_fs_from_message->req_fs_from_neighbors)) {
     /* Nothing to be signaled - abort */
    return pointer;
  }

  tlv = lls_message->req_fs_from_message;
  
  tlv->length = listcount(tlv->req_fs_from_neighbors);
   
  if (tlv->length > 0 &&
      tlv->length >= wospf_count_adjacencies(oi->neighbor_list) * DROP_REQ_TLV_THRESHOLD) {
    omit = WOSPF_TRUE;
  }
 
  if (omit == WOSPF_FALSE)
    WOSPF_PRINTF(2, "Building Req TLV");
  

  *(u_int16_t *)pointer = tlv->type; pointer += 2;
  *(u_int16_t *)pointer = tlv->length; pointer += 2;

  for (ALL_LIST_ELEMENTS (tlv->req_fs_from_neighbors, node, nextnode, pers)) {
    id_pointer = (ID *)pointer; pointer += 4;
    *id_pointer = pers->neighbor->router_id; 
    pers->persistent_count--;
    
    if (omit == WOSPF_FALSE)
      WOSPF_PRINTF(2, "   req fs from %s (%d)", pers->neighbor->name, 
		   pers->persistent_count);

    
    /* Removing items from the Req FS list at this point MAY not be
       the best solution with regards to protocol
       reliability. However, the draft states that any TLV type may be
       sent persistently, which is why this feature is implemented
       here. */
    if (pers->persistent_count == 0) {
      WOSPF_PRINTF(2, "Removing %s from request fs list", pers->neighbor->name);
      list_delete_node(tlv->req_fs_from_neighbors, node);
    }
    
  }

  if (omit == WOSPF_TRUE) {
    WOSPF_PRINTF(2, " -- Omitting the Req TLV!");
    return start_pos;
  }
  

  return pointer;
}

static char *append_fs_tlv(char *start_pos, struct ospf6_interface *oi) {
  struct fs_tlv_message *tlv;
  struct listnode *node, *nextnode;
  struct persistent_node *pers;
  char *pointer;
  wospf_bool omit = WOSPF_FALSE;
  
  pointer = start_pos;

  if (list_isempty(lls_message->fs_for_message->fs_for_neighbors)) {
     /* Nothing to be signaled - abort */
    return pointer;
  }

  tlv = lls_message->fs_for_message;
  tlv->length = listcount(tlv->fs_for_neighbors);
  
  if (tlv->length > 0 && 
      tlv->length >= wospf_count_adjacencies(oi->neighbor_list) * DROP_FS_TLV_THRESHOLD) {
    omit = WOSPF_TRUE;
  }
  
  if (omit == WOSPF_FALSE)
    WOSPF_PRINTF(2, "Building FS TLV");
  
  *(u_int16_t *)pointer = tlv->type; pointer += 2;
  *(u_int16_t *)pointer = tlv->length; pointer += 2;

  for (ALL_LIST_ELEMENTS (tlv->fs_for_neighbors, node, nextnode, pers)) {
    *(ID *)pointer = pers->neighbor->router_id; pointer += 4;
    pers->persistent_count--;
    
    if (omit == WOSPF_FALSE)
      WOSPF_PRINTF(2, "   fs for %s (%d)", pers->neighbor->name, pers->persistent_count);
    
    if (pers->persistent_count == 0) {
      WOSPF_PRINTF(2, "Removing %s from fs for list", pers->neighbor->name);
      list_delete_node(tlv->fs_for_neighbors, node);
    }
    else pers->persistent_count--;
    
  }
  

  if (omit == WOSPF_TRUE) {
    WOSPF_PRINTF(99, " -- Omitting the FS TLV!");
    return start_pos;
  }

  return pointer;

}



/************************************/
/**************** MISC **************/
/************************************/

struct wospf_neighbor_entry *wospf_lookup_pers_list(struct list *list, ID router_id) {
  struct persistent_node *pers;
  struct listnode *node;
  
  for (node = list->head; node; nextnode (node)) {
    pers = getdata (node);
    
    if (pers->neighbor != NULL && pers->neighbor->router_id == router_id) 
      return pers->neighbor;

    }

  return NULL;
}

wospf_bool wospf_lookup_id_list(struct list *list, ID router_id) {
  struct id_container *id_con;
  struct listnode *node;
  
  for (node = list->head; node; nextnode (node)) {
    id_con = getdata (node);
    
    if (id_con->router_id == router_id) return WOSPF_TRUE;
    
  }
  
  return WOSPF_FALSE;
}

void wospf_delete_id_list(struct list *list, ID router_id) {
  struct id_container *id_con;
  struct listnode *node, *nextnode;
  
  for (ALL_LIST_ELEMENTS (list, node, nextnode, id_con)) {
    
    if (id_con->router_id == router_id) {
      list_delete_node(list, node);
    }
    
  }
  
}
