/* BGP network related fucntions
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

#include <zebra.h>

#include "thread.h"
#include "sockunion.h"
#include "memory.h"
#include "log.h"
#include "if.h"
#include "prefix.h"
#include "command.h"
#include "privs.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_fsm.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_network.h"

extern struct zebra_privs_t bgpd_privs;


#if defined(HAVE_TCP_MD5) && defined(GNU_LINUX)
/* Set MD5 key to the socket.  */
int
bgp_md5_set (int sock, struct peer *peer, char *password)
{
  int ret;
  struct tcp_rfc2385_cmd cmd;

  cmd.command = TCP_MD5_AUTH_ADD;
  if (sockunion_family (&peer->su) == AF_INET) {
     cmd.addrlen = 4;
     cmd.u.addrv4 = peer->su.sin.sin_addr;
  } else {
     cmd.addrlen = 16;
     cmd.u.addrv6 = peer->su.sin6.sin6_addr;
  }
  cmd.keylen = strlen (password);
  cmd.key = password;

  if ( bgpd_privs.change (ZPRIVS_RAISE) )
    zlog_err ("bgp_md5_set: could not raise privs");

  ret = setsockopt (sock, IPPROTO_TCP, TCP_MD5_AUTH, &cmd, sizeof cmd);

  if (bgpd_privs.change (ZPRIVS_LOWER) )
    zlog_err ("bgp_md5_set: could not lower privs");

  return ret;
}

/* Unset MD5 key from the socket.  */
int
bgp_md5_unset (int sock, struct peer *peer, char *password)
{
  int ret;
  struct tcp_rfc2385_cmd cmd;

  cmd.command = TCP_MD5_AUTH_DEL;
  if (sockunion_family (&peer->su) == AF_INET) {
     cmd.addrlen = 4;
     cmd.u.addrv4 = peer->su.sin.sin_addr;
  } else {
     cmd.addrlen = 16;
     cmd.u.addrv6 = peer->su.sin6.sin6_addr;
  }
  cmd.keylen = strlen (password);
  cmd.key = password;

  if ( bgpd_privs.change (ZPRIVS_RAISE) )
    zlog_err ("bgp_md5_unset: could not raise privs");

  ret = setsockopt (sock, IPPROTO_TCP, TCP_MD5_AUTH, &cmd, sizeof cmd);

  if (bgpd_privs.change (ZPRIVS_LOWER) )
    zlog_err ("bgp_md5_unset: could not lower privs");

  return ret;
}
#endif /* defined(HAVE_TCP_MD5) && defined(GNU_LINUX) */

/* Accept bgp connection. */
static int
bgp_accept (struct thread *thread)
{
  int bgp_sock;
  int accept_sock;
  union sockunion su;
  struct peer *peer;
  struct peer *peer1;
  struct bgp *bgp;
  char buf[SU_ADDRSTRLEN];

  /* Regiser accept thread. */
  accept_sock = THREAD_FD (thread);
  bgp = THREAD_ARG (thread);

  if (accept_sock < 0)
    {
      zlog_err ("accept_sock is nevative value %d", accept_sock);
      return -1;
    }
  thread_add_read (master, bgp_accept, bgp, accept_sock);

  /* Accept client connection. */
  bgp_sock = sockunion_accept (accept_sock, &su);
  if (bgp_sock < 0)
    {
      zlog_err ("[Error] BGP socket accept failed (%s)", safe_strerror (errno));
      return -1;
    }

  if (BGP_DEBUG (events, EVENTS))
    zlog_debug ("[Event] BGP connection from host %s", inet_sutop (&su, buf));
  
  /* Check remote IP address */
  peer1 = peer_lookup (bgp, &su);
  if (! peer1 || peer1->status == Idle)
    {
      if (BGP_DEBUG (events, EVENTS))
	{
	  if (! peer1)
	    zlog_debug ("[Event] BGP connection IP address %s is not configured",
		       inet_sutop (&su, buf));
	  else
	    zlog_debug ("[Event] BGP connection IP address %s is Idle state",
		       inet_sutop (&su, buf));
	}
      close (bgp_sock);
      return -1;
    }

  /* In case of peer is EBGP, we should set TTL for this connection.  */
  if (peer_sort (peer1) == BGP_PEER_EBGP)
    sockopt_ttl (peer1->su.sa.sa_family, bgp_sock, peer1->ttl);

  if (! bgp)
    bgp = peer1->bgp;

  /* Make dummy peer until read Open packet. */
  if (BGP_DEBUG (events, EVENTS))
    zlog_debug ("[Event] Make dummy peer structure until read Open packet");

  {
    char buf[SU_ADDRSTRLEN + 1];

    peer = peer_create_accept (bgp);
    SET_FLAG (peer->sflags, PEER_STATUS_ACCEPT_PEER);
    peer->su = su;
    peer->fd = bgp_sock;
    peer->status = Active;
    peer->local_id = peer1->local_id;

    /* Make peer's address string. */
    sockunion2str (&su, buf, SU_ADDRSTRLEN);
    peer->host = strdup (buf);
  }

  BGP_EVENT_ADD (peer, TCP_connection_open);

  return 0;
}

/* BGP socket bind. */
int
bgp_bind (struct peer *peer)
{
#ifdef SO_BINDTODEVICE
  int ret;
  struct ifreq ifreq;

  if (! peer->ifname)
    return 0;

  strncpy ((char *)&ifreq.ifr_name, peer->ifname, sizeof (ifreq.ifr_name));

  if ( bgpd_privs.change (ZPRIVS_RAISE) )
  	zlog_err ("bgp_bind: could not raise privs");
  
  ret = setsockopt (peer->fd, SOL_SOCKET, SO_BINDTODEVICE, 
		    &ifreq, sizeof (ifreq));

  if (bgpd_privs.change (ZPRIVS_LOWER) )
    zlog_err ("bgp_bind: could not lower privs");

  if (ret < 0)
    {
      zlog (peer->log, LOG_INFO, "bind to interface %s failed", peer->ifname);
      return ret;
    }
#endif /* SO_BINDTODEVICE */
  return 0;
}

static void
bgp_bind_address (int sock, const struct prefix *addr)
{
  int ret;

  switch (addr->family) {
    case AF_INET: {
      struct sockaddr_in local;
      const struct prefix_ipv4 *addr_ipv4 = (const struct prefix_ipv4 *)addr;

      memset (&local, 0, sizeof (struct sockaddr_in));
      local.sin_family = addr_ipv4->family;
#ifdef HAVE_SIN_LEN
      local.sin_len = sizeof(struct sockaddr_in);
#endif /* HAVE_SIN_LEN */
      memcpy (&local.sin_addr, &(addr_ipv4->prefix), sizeof (struct in_addr));

     if ( bgpd_privs.change (ZPRIVS_RAISE) )
       zlog_err ("bgp_bind_address: could not raise privs");
      ret = bind (sock, (struct sockaddr *)&local, sizeof (struct sockaddr_in));
      if (ret < 0)
	;
      if (bgpd_privs.change (ZPRIVS_LOWER) )
        zlog_err ("bgp_bind_address: could not lower privs");
      return ;
    }
#ifdef HAVE_IPV6
    case AF_INET6: {
      struct sockaddr_in6 local;
      const struct prefix_ipv6 *addr_ipv6 = (const struct prefix_ipv6 *)addr;

      memset (&local, 0, sizeof (struct sockaddr_in6));
      local.sin6_family = addr_ipv6->family;
#ifdef SIN6_LEN
      local.sin6_len = sizeof(struct sockaddr_in6);
#endif
      memcpy (&local.sin6_addr, &(addr_ipv6->prefix), sizeof (struct in6_addr));

     if ( bgpd_privs.change (ZPRIVS_RAISE) )
       zlog_err ("bgp_bind_address: could not raise privs");
      ret = bind (sock, (struct sockaddr *)&local, sizeof (struct sockaddr_in6));
      if (ret < 0)
	;
      if (bgpd_privs.change (ZPRIVS_LOWER) )
        zlog_err ("bgp_bind_address: could not lower privs");
      return ;
    }
#endif
    default:
      zlog_err ("%d is an unknown address family\n", addr->family);
      return ;
  }
    ;
  return ;
}

/*
 * Returns an ifp source address which has the same Address Family as af
 */
static const struct prefix *
bgp_update_address (struct interface *ifp, int af)
{
  const struct prefix *p;
  struct connected *connected;
  struct listnode *node;

  for (ALL_LIST_ELEMENTS_RO (ifp->connected, node, connected))
    {
      p = (struct prefix *) connected->address;


      if ((af == AF_INET) && (p->family == af))
	return p;

#ifdef HAVE_IPV6
      if ((af == AF_INET6) && (p->family == af)) {

	/* do not allow IPv6 link-local address */
      	if (IN6_IS_ADDR_LINKLOCAL(&(((const struct prefix_ipv6 *)p)->prefix)))
	  continue;

	return p;
      }
#endif /* HAVE_IPV6 */

    }
  return NULL;
}

/*
 * Update source selection according to the
 * 'neighbor WORD update-source (A.B.C.D|X:X::X:X|IFNAME)' argument.
 * Because only one update-source command is allowed,
 * update_if xor update_source is NULL.
 */
void
bgp_update_source (struct peer *peer)
{
  struct interface *ifp;
  const struct prefix *addr;

  /* Source is specified with interface name.  */
  if (peer->update_if)
    {
      ifp = if_lookup_by_name (peer->update_if);
      if (! ifp)
	return;

      /* peer->su : sockunion address of the peer */
      addr = bgp_update_address (ifp, sockunion_family(&(peer->su)));
      if (! addr)
	return;

      bgp_bind_address (peer->fd, addr);
    }

  /* Source is specified with IP address.  */
  if (peer->update_source)
    sockunion_bind (peer->fd, peer->update_source, 0, peer->update_source);
}

/* BGP try to connect to the peer.  */
int
bgp_connect (struct peer *peer)
{
  unsigned int ifindex = 0;

  /* Make socket for the peer. */
  peer->fd = sockunion_socket (&peer->su);
  if (peer->fd < 0)
    return -1;

  /* If we can get socket for the peer, adjest TTL and make connection. */
  if (peer_sort (peer) == BGP_PEER_EBGP)
    sockopt_ttl (peer->su.sa.sa_family, peer->fd, peer->ttl);

  sockopt_reuseaddr (peer->fd);
  sockopt_reuseport (peer->fd);

#ifdef HAVE_TCP_MD5
  if (CHECK_FLAG (peer->flags, PEER_FLAG_PASSWORD))
      bgp_md5_set (peer->fd, peer, peer->password);
#endif /* HAVE_TCP_MD5 */

  /* Bind socket. */
  bgp_bind (peer);

  /* Update source bind. */
  bgp_update_source (peer);

#ifdef HAVE_IPV6
  if (peer->ifname)
    ifindex = if_nametoindex (peer->ifname);
#endif /* HAVE_IPV6 */

  if (BGP_DEBUG (events, EVENTS))
    plog_debug (peer->log, "%s [Event] Connect start to %s fd %d",
	       peer->host, peer->host, peer->fd);

  /* Connect to the remote peer. */
  return sockunion_connect (peer->fd, &peer->su, htons (peer->port), ifindex);
}

/* After TCP connection is established.  Get local address and port. */
void
bgp_getsockname (struct peer *peer)
{
  if (peer->su_local)
    {
      XFREE (MTYPE_TMP, peer->su_local);
      peer->su_local = NULL;
    }

  if (peer->su_remote)
    {
      XFREE (MTYPE_TMP, peer->su_remote);
      peer->su_remote = NULL;
    }

  peer->su_local = sockunion_getsockname (peer->fd);
  peer->su_remote = sockunion_getpeername (peer->fd);

  bgp_nexthop_set (peer->su_local, peer->su_remote, &peer->nexthop, peer);
}

/* IPv6 supported version of BGP server socket setup.  */
#if defined (HAVE_IPV6) && ! defined (NRL)
int
bgp_socket (struct bgp *bgp, unsigned short port)
{
  int ret, en;
  struct addrinfo req;
  struct addrinfo *ainfo;
  struct addrinfo *ainfo_save;
  int sock = 0;
  char port_str[BUFSIZ];

  memset (&req, 0, sizeof (struct addrinfo));

  req.ai_flags = AI_PASSIVE;
  req.ai_family = AF_UNSPEC;
  req.ai_socktype = SOCK_STREAM;
  sprintf (port_str, "%d", port);
  port_str[sizeof (port_str) - 1] = '\0';

  ret = getaddrinfo (NULL, port_str, &req, &ainfo);
  if (ret != 0)
    {
      zlog_err ("getaddrinfo: %s", gai_strerror (ret));
      return -1;
    }

  ainfo_save = ainfo;

  do
    {
      if (ainfo->ai_family != AF_INET && ainfo->ai_family != AF_INET6)
	continue;

      sock = socket (ainfo->ai_family, ainfo->ai_socktype, ainfo->ai_protocol);
      if (sock < 0)
	{
	  zlog_err ("socket: %s", safe_strerror (errno));
	  continue;
	}

      sockopt_reuseaddr (sock);
      sockopt_reuseport (sock);
      if (ainfo->ai_family == AF_INET6) 
        {
          /* XXX Without, IPV6_ONLY, the IPv6 socket may also try to open IPv4 socket, 
           * which may fail.
           */
          int on = 1;

          if (setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&on, sizeof(on)) == -1)
            zlog_err("setsockopt IPV6_V6ONLY %s", safe_strerror (errno) );
        }

      
      if (bgpd_privs.change (ZPRIVS_RAISE) )
        zlog_err ("bgp_socket: could not raise privs");

      ret = bind (sock, ainfo->ai_addr, ainfo->ai_addrlen);
      en = errno;
      if (bgpd_privs.change (ZPRIVS_LOWER) )
	zlog_err ("bgp_bind_address: could not lower privs");

      if (ret < 0)
	{
	  zlog_err ("bind: %s", safe_strerror (en));
	  close(sock);
	  continue;
	}
      
      ret = listen (sock, 3);
      if (ret < 0) 
	{
	  zlog_err ("listen: %s", safe_strerror (errno));
	  close (sock);
	  continue;
	}

#ifdef HAVE_TCP_MD5
      if (ainfo->ai_family == AF_INET)
	bm->sockv4 = sock;
      else if (ainfo->ai_family == AF_INET6)
	bm->sockv6 = sock;
#endif /* HAVE_TCP_MD5 */

      thread_add_read (master, bgp_accept, bgp, sock);
    }
  while ((ainfo = ainfo->ai_next) != NULL);

  freeaddrinfo (ainfo_save);

  return sock;
}
#else
/* Traditional IPv4 only version.  */
int
bgp_socket (struct bgp *bgp, unsigned short port)
{
  int sock;
  int socklen;
  struct sockaddr_in sin;
  int ret, en;

  sock = socket (AF_INET, SOCK_STREAM, 0);
  if (sock < 0)
    {
      zlog_err ("socket: %s", safe_strerror (errno));
      return sock;
    }

  sockopt_reuseaddr (sock);
  sockopt_reuseport (sock);

  memset (&sin, 0, sizeof (struct sockaddr_in));

  sin.sin_family = AF_INET;
  sin.sin_port = htons (port);
  socklen = sizeof (struct sockaddr_in);
#ifdef HAVE_SIN_LEN
  sin.sin_len = socklen;
#endif /* HAVE_SIN_LEN */

  if ( bgpd_privs.change (ZPRIVS_RAISE) )
    zlog_err ("bgp_socket: could not raise privs");

  ret = bind (sock, (struct sockaddr *) &sin, socklen);
  en = errno;

  if (bgpd_privs.change (ZPRIVS_LOWER) )
    zlog_err ("bgp_socket: could not lower privs");

  if (ret < 0)
    {
      zlog_err ("bind: %s", safe_strerror (en));
      close (sock);
      return ret;
    }
  
  ret = listen (sock, 3);
  if (ret < 0) 
    {
      zlog_err ("listen: %s", safe_strerror (errno));
      close (sock);
      return ret;
    }
#ifdef HAVE_TCP_MD5
  bm->sockv4 = sock;
#endif /* HAVE_TCP_MD5 */

  thread_add_read (bm->master, bgp_accept, bgp, sock);

  return sock;
}
#endif /* HAVE_IPV6 && !NRL */
