/*
** wospf_lls.h
** 
** Made by Kenneth Holter
** Login   <kenneho@localhost.localdomain>
** 
** Started on  Sat May  6 17:28:42 2006 Kenneth Holter
** Last update Sun May 28 16:20:30 2006 Kenneth Holter
*/

#ifndef   	WOSPF_LLS_H_
# define   	WOSPF_LLS_H_


struct wospf_lls_message {
  u_int16_t checksum;
  u_int16_t lls_data_length; /* No of 32-bit words, including the checksum
				and lls_data_length fields */

  /* Pointers to internal TLV messages*/
  struct scs_tlv_message *scs_message;
  struct neighbor_drop_tlv_message *neighbor_drop_message;
  struct req_tlv_message *req_fs_from_message;
  struct fs_tlv_message *fs_for_message;
  struct aor_tlv_message *aor_message;
  struct will_tlv_message *will_message;
 
};

struct scs_tlv_message {
  u_int16_t type;
  u_int16_t length;
  u_int32_t scs_number; /* Extended SCS number */
  wospf_bool r_bit_set;
  wospf_bool fs_bit_set;
  wospf_bool n_bit_set;
};

struct neighbor_drop_tlv_message {
  u_int16_t type;
  u_int16_t length;
  struct list *dropped_neighbors;
};

struct req_tlv_message {
  u_int16_t type;
  u_int16_t length;
  struct list *req_fs_from_neighbors;
};

struct fs_tlv_message {
  u_int16_t type;
  u_int16_t length;
  struct list *fs_for_neighbors;
};

struct aor_tlv_message {
  u_int16_t type;
  u_int16_t length;
  u_int8_t relays_added;
  wospf_bool will_always;
  wospf_bool will_never;
  struct list *added_relays;
  struct list *dropped_relays;
};

struct will_tlv_message {
  u_int16_t type;
  u_int16_t length;
  u_int8_t will;

  int will_pers_count;
};



/* Dropped neighbor list, added AOR list etc are made up of lists of
   this data structure */
struct persistent_node {
  int persistent_count;
  struct wospf_neighbor_entry *neighbor;
  int is_signaled; /* For AOR signaling */
  ID router_id;

  //struct persistent_node *next;
  //struct persistent_node *prev;
};

struct id_container {
  ID router_id;
};

/* Neighbors who are to be included in the Hello packet's 
   neighbor list */
struct list *added_neighbors;

/********** Incoming packets ********/

/* Parse incoming LLS data blocks */
struct wospf_lls_message *wospf_parse_lls_block(char *); 
void wospf_process_tlvs(ID, struct wospf_lls_message *, struct list *);


/********** Outgoing packets ********/

char *wospf_append_lls(char *, struct ospf6_interface *);


/* MISC */

struct wospf_neighbor_entry *wospf_lookup_pers_list(struct list *, ID);
wospf_bool wospf_lookup_id_list(struct list *, ID);
void wospf_delete_id_list(struct list *, ID);

#endif 	    /* !WOSPF_LLS_H_ */
