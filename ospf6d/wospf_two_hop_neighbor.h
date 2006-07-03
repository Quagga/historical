/*
** wospf_two_hop_neighbor.h
** 
** Made by Kenneth Holter
** Login   <kenneho@localhost.localdomain>
** 
** Started on  Fri May  5 13:05:32 2006 Kenneth Holter
** Last update Wed May 10 12:44:27 2006 Kenneth Holter
*/

#ifndef   	WOSPF_TWO_HOP_NEIGHBOR_H_
# define   	WOSPF_TWO_HOP_NEIGHBOR_H_

#include <zebra.h>
#include "wospf_defs.h"
#include "wospf_hashing.h"

struct wospf_neighbor_list_entry {

  struct wospf_neighbor_entry *neighbor;

  struct wospf_neighbor_list_entry *next;
  struct wospf_neighbor_list_entry *prev;
};


struct wospf_neighbor_2_entry {

  ID neighbor_2_id;
  u_int8_t aor_covered_count;
  u_int8_t processed;
  u_int16_t neighbor_2_pointer; /* Neighbor counter */
  
  wospf_bool lsa_processed; /* For processing router LSAs */
  char *name;

  struct wospf_neighbor_list_entry neighbor_2_nblist;
  struct wospf_neighbor_2_entry *next;
  struct wospf_neighbor_2_entry *prev;
};

struct wospf_neighbor_2_entry two_hop_neighbortable[HASHSIZE];


/* Functions */

int
wospf_init_two_hop_table(void);

void
wospf_delete_neighbor_pointer(struct wospf_neighbor_2_entry *, ID);

void
wospf_delete_two_hop_neighbor_table(struct wospf_neighbor_2_entry *);

void
wospf_insert_two_hop_neighbor_table(struct wospf_neighbor_2_entry *);

struct wospf_neighbor_2_entry *
wospf_lookup_two_hop_neighbor_table(ID);

struct wospf_neighbor_2_entry *
wospf_lookup_two_hop_neighbor_table_mid(ID);

void
wospf_print_two_hop_neighbor_table(void);



#endif 	    /* !WOSPF_TWO_HOP_NEIGHBOR_H_ */
