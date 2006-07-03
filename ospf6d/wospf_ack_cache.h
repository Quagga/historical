/*
** wospf_ack_cache.h
** 
** Made by Kenneth Holter
** Login   <kenneho@localhost.localdomain>
** 
** Started on  Thu May  4 18:28:39 2006 Kenneth Holter
** Last update Sat May 27 17:57:14 2006 Kenneth Holter
*/

#ifndef   	WOSPF_ACK_CACHE_H_
# define   	WOSPF_ACK_CACHE_H_

#include "wospf_neighbor_table.h"

struct wospf_ack_node {

  struct ospf6_lsa *lsa;
  struct wospf_neighbor_entry *neighbor;
  
  /* Timeout */
  //struct thread *thread_timeout_cache_entry;

};



void wospf_register_ack(ID, struct ospf6_lsa *, struct ospf6_interface *);

int wospf_lookup_ack_cache(ID, struct ospf6_lsa *);

void wospf_update_ack_cache(struct ospf6_lsa *, ID);

#endif 	    /* !WOSPF_ACK_CACHE_H_ */
