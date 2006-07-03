/*
** wospf_hashing.h
** 
** Made by Kenneth Holter
** Login   <kenneho@localhost.localdomain>
** 
** Started on  Thu May  4 18:45:22 2006 Kenneth Holter
** Last update Fri May  5 13:16:33 2006 Kenneth Holter
*/

#ifndef   	WOSPF_HASHING_H_
# define   	WOSPF_HASHING_H_

#include <zebra.h>

#define	HASHSIZE	32
#define	HASHMASK	(HASHSIZE - 1)


u_int32_t wospf_hashing(u_int32_t);


#endif 	    /* !WOSPF_HASHING_H_ */
