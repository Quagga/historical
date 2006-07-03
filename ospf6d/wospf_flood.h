/*
** wospf_flood.h
** 
** Made by Kenneth Holter
** Login   <kenneho@localhost.localdomain>
** 
** Started on  Fri May  5 17:47:29 2006 Kenneth Holter
** Last update Fri May 26 13:43:31 2006 Kenneth Holter
*/

#ifndef   	WOSPF_FLOOD_H_
# define   	WOSPF_FLOOD_H_

#include <zebra.h>
#include "wospf_neighbor_table.h"

struct wospf_pushback_lsa {

  struct ospf6_lsa *lsa;
  struct list *backup_wait_list;
  struct thread *backup_timer;
  struct ospf6_interface *oi;
  
};


void wospf_flood_interface (struct ospf6_neighbor *,
			    struct ospf6_lsa *, 
			    struct ospf6_interface *);



int wospf_pushback_timeout(struct thread *);

int wospf_jitter(struct ospf6_interface *);

int wospf_count_adjacencies(struct list *);

void wospf_remove_bwn_list(struct ospf6_neighbor *, struct ospf6_lsa *, 
			   struct ospf6_interface *, wospf_bool);

#endif 	    /* !WOSPF_FLOOD_H_ */
