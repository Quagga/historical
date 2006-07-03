/*
** wospf_hashing.c
** 
** Made by (Kenneth Holter)
** Login   <kenneho@localhost.localdomain>
** 
** Started on  Thu May  4 18:46:41 2006 Kenneth Holter
** Last update Fri May  5 14:19:02 2006 Kenneth Holter
*/

#include "wospf_hashing.h"


u_int32_t wospf_hashing(u_int32_t router_id) {

  u_int32_t hash;

  hash = ntohl(router_id);

  hash &= HASHMASK;

  return 0;
}
