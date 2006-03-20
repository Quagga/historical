/*
 * Kernel routing table read by sysctl function.
 * Copyright (C) 1997, 98 Kunihiro Ishiguro
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNU Zebra; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.  
 */

#include <zebra.h>

#include "memory.h"
#include "log.h"

/*VPN*/
#include "vpn.h"

/* Kernel routing table read up by sysctl function. */
int
route_read ()
{
  caddr_t buf, end, ref;
  size_t bufsiz;
  struct rt_msghdr *rtm;
  void rtm_read (struct rt_msghdr *, int vrf_id, safi_t safi);
  
#define MIBSIZ 6
  int mib[MIBSIZ] = 
  {
    CTL_NET,
    PF_ROUTE,
    0,
    0,
    NET_RT_DUMP,
    vpn_id
  };
		      
  /* Get buffer size. */
  if (sysctl (mib, MIBSIZ, NULL, &bufsiz, NULL, 0) < 0) 
    {
      zlog_warn ("sysctl fail: %s", safe_strerror (errno));
      return -1;
    }

  /* Allocate buffer. */
  ref = buf = XMALLOC (MTYPE_TMP, bufsiz);
  
  /* Read routing table information by calling sysctl(). */
  if (sysctl (mib, MIBSIZ, buf, &bufsiz, NULL, 0) < 0) 
    {
      zlog_warn ("sysctl() fail by %s", safe_strerror (errno));
      return -1;
    }

  for (end = buf + bufsiz; buf < end; buf += rtm->rtm_msglen) 
    {
      rtm = (struct rt_msghdr *) buf;
      if (vpn_id)
        {
          rtm_read (rtm, vpn_id, SAFI_UNICAST);
          zlog_warn ("vpn_id = %d", vpn_id);
        }
      else 
        rtm_read (rtm, 0, SAFI_UNICAST);
   }

  /* Free buffer. */
  XFREE (MTYPE_TMP, ref);

  return 0;
}
