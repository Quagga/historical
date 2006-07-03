/*
** wospf_cfg.h
** 
** Made by Kenneth Holter
** Login   <kenneho@localhost.localdomain>
** 
** Started on  Fri May  5 14:59:53 2006 Kenneth Holter
** Last update Sat May  6 17:00:15 2006 Kenneth Holter
*/

#ifndef   	WOSPF_CFG_H_
# define   	WOSPF_CFG_H_



struct wospf_config {

  int debug_level;

  int aor_coverage; /* OLSR parameter. Remove? */

};


#endif 	    /* !WOSPF_CFG_H_ */
