/*
** wospf_aor_selector.h
** 
** Made by Kenneth Holter
** Login   <kenneho@localhost.localdomain>
** 
** Started on  Sat May  6 15:19:34 2006 Kenneth Holter
** Last update Tue May 16 11:45:49 2006 Kenneth Holter
*/

#ifndef   	WOSPF_AOR_SELECTOR_H_
# define   	WOSPF_AOR_SELECTOR_H_

#include "wospf_defs.h"

struct aor_selector
{
  ID router_id;
  struct aor_selector *next;
  struct aor_selector *prev;
};

wospf_bool is_AOR_selector(ID);

void
wospf_init_aor_selector_set();

struct aor_selector *
wospf_add_aor_selector(ID);

struct aor_selector *
wospf_lookup_aors_set(ID);

int
wospf_update_aors_set(ID);

int
wospf_delete_aor_selector(ID);

#endif 	    /* !WOSPF_AOR_SELECTOR_H_ */
