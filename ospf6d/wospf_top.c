/*
** wospf_top.c
** 
** Made by (Kenneth Holter)
** Login   <kenneho@localhost.localdomain>
** 
** Started on  Fri May  5 14:45:03 2006 Kenneth Holter
** Last update Sun May 28 15:01:14 2006 Kenneth Holter
*/

#include "ospf6d.h"

#include "wospf_top.h"
#include "wospf_defs.h"


void *
wospf_malloc(size_t size, const char *id)
{
  void *ptr;

  if((ptr = malloc(size)) == 0) 
    {
      WOSPF_PRINTF(1, "OUT OF MEMORY: %s\n", strerror(errno))
	//olsr_syslog(OLSR_LOG_ERR, "olsrd: out of memory!: %m\n");
	//olsr_exit((char *)id, EXIT_FAILURE);
    }
  return ptr;
}


char *int_to_ip(u_int32_t *input) {
  char *ret = malloc(INET_ADDRSTRLEN);

  char *tmp = (char *)inet_ntop (AF_INET, input, ret, INET_ADDRSTRLEN);

  return tmp;
}

#ifdef BUGFIX
float elapsed_time(struct timeval *t)
{
 struct timeval now;
 float T;

 gettimeofday (&now, (struct timezone *)NULL);

 T = (float)(now.tv_sec - t->tv_sec)  +
     (float)(now.tv_usec - t->tv_usec) / 1000000;

 return T;
}
#endif


