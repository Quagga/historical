/*
** wospf_defs.h
** 
** Made by Kenneth Holter
** Login   <kenneho@localhost.localdomain>
** 
** Started on  Fri May  5 13:09:30 2006 Kenneth Holter
** Last update Sun May 28 15:02:56 2006 Kenneth Holter
*/

#ifndef   	WOSPF_DEFS_H_
# define   	WOSPF_DEFS_H_

#include "wospf_cfg.h"
#include <zebra.h>
#include "log.h"

/*
 * Global wospf configuragtion
 */

struct wospf_config *wospf_cfg;

typedef enum {
  WOSPF_FALSE = 0,
  WOSPF_TRUE
} wospf_bool;

//typedef unsigned int ID;
typedef uint32_t ID;

char *id_buf;

/* Outgoing TLVs messages are contained in this data structure. */
struct wospf_lls_message *lls_message;

/*
 * Queueing macros
 */

/* First "argument" is NOT a pointer! */

#define QUEUE_ELEM(pre, new) \
        pre.next->prev = new; \
        new->next = pre.next; \
        new->prev = &pre; \
        pre.next = new

#define DEQUEUE_ELEM(elem) \
	elem->prev->next = elem->next; \
	elem->next->prev = elem->prev



#define WOSPF_PRINTFd(lvl, format, args...) \
   { \
      if (lvl == 9) \
        zlog_debug(format, ##args); \
   }

#define WOSPF_PRINTF(lvl, format, args...) \
   { \
     if(wospf_cfg->debug_level >= lvl) \
        zlog_debug(format, ##args); \
   }

#define WOSPF_ID(input) \
      (char *) inet_ntop (AF_INET, input, id_buf, INET_ADDRSTRLEN) \
      
        
  
#define OSPF6_LSA_MANET 0x10

#define MAX_SCS UINT32_MAX

#endif 	    /* !WOSPF_DEFS_H_ */
