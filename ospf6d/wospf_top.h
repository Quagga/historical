/*
** wospf_top.h
** 
** Made by Kenneth Holter
** Login   <kenneho@localhost.localdomain>
** 
** Started on  Fri May  5 14:42:54 2006 Kenneth Holter
** Last update Sun May 28 15:01:21 2006 Kenneth Holter
*/

#ifndef   	WOSPF_TOP_H_
# define   	WOSPF_TOP_H_


#include "wospf_defs.h"
#include <zebra.h>



wospf_bool changes_neighborhood; /* Changes in one or two hop
				    neighbors */
wospf_bool state_changes; /* New/dropped neighbors */


void *
wospf_malloc(size_t, const char *);

void
wospf_list_init();

char *int_to_ip(u_int32_t *i);

#ifdef BUGFIX
float elapsed_time(struct timeval *t);
#endif


#endif 	    /* !WOSPF_TOP_H_ */
