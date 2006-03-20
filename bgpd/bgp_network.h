/* BGP network related header
   Copyright (C) 1999 Kunihiro Ishiguro

This file is part of GNU Zebra.

GNU Zebra is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 2, or (at your option) any
later version.

GNU Zebra is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with GNU Zebra; see the file COPYING.  If not, write to the Free
Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
02111-1307, USA.  */

#if defined(HAVE_TCP_MD5) && defined(GNU_LINUX)
/* setsockopt Number */
#define TCP_MD5_AUTH 13

/* Commands (used in the structure passed from userland) */
#define TCP_MD5_AUTH_ADD 1
#define TCP_MD5_AUTH_DEL 2

struct tcp_rfc2385_cmd {
       u_int8_t     command;    /* Command - Add/Delete */
       u_int8_t     addrlen;
       union {
           struct in_addr  addrv4;     /* IPV4 address associated */
           struct in6_addr addrv6;     /* IPV6 address associated */
           u_int8_t        addr[16];   /* Biggest adress associated */
       } u;
       u_int8_t     keylen;     /* MD5 Key len (do NOT assume 0 terminated ascii) */
       void         *key;       /* MD5 Key */
};


#endif /* defined(HAVE_TCP_MD5) && defined(GNU_LINUX) */

#ifdef HAVE_TCP_MD5
int bgp_md5_set (int sock, struct peer *, char *);
int bgp_md5_unset (int sock, struct peer *, char *);
#endif /* HAVE_TCP_MD5 */

int bgp_socket (struct bgp *, unsigned short);
int bgp_connect (struct peer *);
void bgp_getsockname (struct peer *);
