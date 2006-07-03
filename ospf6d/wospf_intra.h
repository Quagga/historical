/*
** wospf_intra.h
** 
** Made by Kenneth Holter
** Login   <kenneho@localhost.localdomain>
** 
** Started on  Tue May  9 13:45:31 2006 Kenneth Holter
** Last update Tue May  9 13:48:06 2006 Kenneth Holter
*/

#ifndef   	WOSPF_INTRA_H_
# define   	WOSPF_INTRA_H_



void wospf_process_router_lsa(struct ospf6_lsa *, struct ospf6_neighbor *, 
			      struct ospf6_lsa_header *);




#endif 	    /* !WOSPF_INTRA_H_ */
