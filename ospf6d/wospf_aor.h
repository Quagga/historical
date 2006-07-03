/*
** wospf_aor.h
** 
** Made by Kenneth Holter
** Login   <kenneho@localhost.localdomain>
** 
** Started on  Sat May  6 13:22:58 2006 Kenneth Holter
** Last update Sat May  6 16:33:48 2006 Kenneth Holter
*/

#ifndef   	WOSPF_AOR_H_
# define   	WOSPF_AOR_H_

#include "wospf_defs.h"

int is_AOR (ID);

void
wospf_calculate_aor(void);

void
wospf_print_aor_set(void);


#endif 	    /* !WOSPF_AOR_H_ */
