/*
** wospf_neighbor_table.h
** 
** Made by Kenneth Holter
** Login   <kenneho@localhost.localdomain>
** 
** Started on  Thu May  4 18:42:15 2006 Kenneth Holter
** Last update Mon May 22 12:12:25 2006 Kenneth Holter
*/

#ifndef   	WOSPF_NEIGHBOR_TABLE_H_
# define   	WOSPF_NEIGHBOR_TABLE_H_

#include "wospf_hashing.h"
#include "wospf_defs.h"

struct wospf_neighbor_2_list_entry {
  
  struct wospf_neighbor_2_entry *neighbor_2;
  
  struct wospf_neighbor_2_list_entry *next;
  struct wospf_neighbor_2_list_entry *prev;  
};



struct wospf_neighbor_entry {
  
  ID router_id;
  u_int16_t willingness;
  wospf_bool is_aor;
  wospf_bool was_aor;
  int neighbor_2_nocov;
  int linkcount;

  char *name;
  u_int32_t scs_number;

  wospf_bool will_always;
  wospf_bool will_never;
  
  wospf_bool supports_aor;
  wospf_bool supports_incr_hello;

  struct ospf6_neighbor *on;
  struct ospf6_lsdb *acked_lsa_list;
  
  struct wospf_neighbor_2_list_entry neighbor_2_list;
  
  struct wospf_neighbor_entry *next;
  struct wospf_neighbor_entry *prev;
};

struct wospf_neighbor_entry neighbortable[HASHSIZE];



/* Functions */

void 
wospf_init_neighbor_table();

int 
wospf_delete_neighbor_2_pointer(struct wospf_neighbor_entry *, ID);

struct wospf_neighbor_2_list_entry *
wospf_lookup_my_neighbors(struct wospf_neighbor_entry *, ID);

int
wospf_delete_neighbor_table(ID);

struct wospf_neighbor_entry *
wospf_insert_neighbor_table(struct ospf6_neighbor *);

void
wospf_update_neighbor_entry(ID, wospf_bool, wospf_bool);

struct wospf_neighbor_entry *
wospf_lookup_neighbor_table(ID);

void
wospf_time_out_two_hop_neighbors(struct wospf_neighbor_entry  *);

void
wospf_print_neighbor_table(void);

void
wospf_print_neighborhood(void);

#endif 	    /* !WOSPF_NEIGHBOR_TABLE_H_ */
