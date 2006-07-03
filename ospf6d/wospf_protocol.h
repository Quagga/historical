/*
** wospf_protocol.h
** 
** Made by Kenneth Holter
** Login   <kenneho@localhost.localdomain>
** 
** Started on  Fri May  5 14:50:09 2006 Kenneth Holter
** Last update Sun May 28 16:26:58 2006 Kenneth Holter
*/

#ifndef   	WOSPF_PROTOCOL_H_
# define   	WOSPF_PROTOCOL_H_


/* BEGIN: Bit operations */
#define WOSPF_OPT_SET(x,opt)   ((x)[1] |=  (opt))
#define WOSPF_OPT_ISSET(x,opt) ((x)[1] &   (opt))

#define WOSPF_BIT_SET(x, bit )  ((x)[0] |= (bit))
#define WOSPF_BIT_ISSET(x, bit) ((x)[0] &  (bit))

#define WOSPF_SET_DNA(x)       ((x)  |= (1 << 16));

#define WOSPF_OPT_L (1 << 1)
#define WOSPF_OPT_I (1 << 2)
#define WOSPF_OPT_F (1 << 3)

#define WOSPF_BIT_R  (1 << 7)
#define WOSPF_BIT_FS (1 << 6)
#define WOSPF_BIT_N  (1 << 5)

#define WOSPF_BIT_ALWAYS (1 << 7)
#define WOSPF_BIT_NEVER  (1 << 6)

/* END: Bit operations */


/*
 *Willingness
 */
#define WILL_NEVER            0
#define WILL_LOW              37
#define WILL_DEFAULT          110
#define WILL_HIGH             222
#define WILL_ALWAYS           255

#define DROP_REQ_TLV_THRESHOLD 0.5
#define DROP_FS_TLV_THRESHOLD  0.5

#define WOSPF_DROPPED_NEIGHBOR_PERS 2
#define WOSPF_WILL_PERS 1
#define WOSPF_AOR_PERS 2
#define WOSPF_DROPPED_AOR_PERS 2
#define WOSPF_REQ_PERS 1
#define WOSPF_FS_PERS 1

#define ACK_CACHE_TIMEOUT 10

#endif 	    /* !WOSPF_PROTOCOL_H_ */
