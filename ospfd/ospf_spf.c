/* OSPF SPF calculation.
   Copyright (C) 1999, 2000 Kunihiro Ishiguro, Toshiaki Takada

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
#include "memory.h"
#include "hash.h"
#include "linklist.h"
#include "prefix.h"
#include "if.h"
#include "table.h"
#include "log.h"
#include "sockunion.h"          /* for inet_ntop () */
#include "pqueue.h"

#include "ospfd/ospfd.h"
#include "ospfd/ospf_interface.h"
#include "ospfd/ospf_ism.h"
#include "ospfd/ospf_asbr.h"
#include "ospfd/ospf_lsa.h"
#include "ospfd/ospf_lsdb.h"
#include "ospfd/ospf_neighbor.h"
#include "ospfd/ospf_nsm.h"
#include "ospfd/ospf_spf.h"
#include "ospfd/ospf_route.h"
#include "ospfd/ospf_ia.h"
#include "ospfd/ospf_ase.h"
#include "ospfd/ospf_abr.h"
#include "ospfd/ospf_dump.h"

#define DEBUG

/* Heap related functions, for the managment of the candidates, to
 * be used with pqueue. */
static int
cmp (void * node1 , void * node2)
{
  struct vertex * v1 = (struct vertex *) node1;
  struct vertex * v2 = (struct vertex *) node2;
  if (v1 != NULL && v2 != NULL )
    return (v1->distance - v2->distance);
  else
    return 0;
}

static void
update_stat (void * node , int position)
{
  struct vertex * v = (struct vertex *) node;
  /* Set the status of the vertex, when its position changes. */
  *(v->stat) = position;
}
/* End of the heap related functions. */

struct vertex_nexthop *
vertex_nexthop_new (struct vertex *parent)
{
  struct vertex_nexthop *new;

  new = XCALLOC (MTYPE_OSPF_NEXTHOP, sizeof (struct vertex_nexthop));
  new->parent = parent;

  return new;
}

void
vertex_nexthop_free (struct vertex_nexthop *nh)
{
  XFREE (MTYPE_OSPF_NEXTHOP, nh);
}

struct vertex_nexthop *
vertex_nexthop_dup (struct vertex_nexthop *nh)
{
  struct vertex_nexthop *new;

  new = vertex_nexthop_new (nh->parent);

  new->oi = nh->oi;
  new->router = nh->router;

  return new;
}


struct vertex *
ospf_vertex_new (struct ospf_lsa *lsa)
{
  struct vertex *new;

  new = XMALLOC (MTYPE_OSPF_VERTEX, sizeof (struct vertex));
  memset (new, 0, sizeof (struct vertex));

  new->flags = 0;
  new->stat = &(lsa->stat);
  new->type = lsa->data->type;
  new->id = lsa->data->id;
  new->lsa = lsa->data;
  new->distance = 0;
  new->child = list_new ();
  new->nexthop = list_new ();
  new->backlink = -1;

  return new;
}

void
ospf_vertex_free (struct vertex *v)
{
  struct listnode *node, *nnode;
  struct vertex_nexthop *nh;

  list_delete (v->child);

  if (listcount (v->nexthop) > 0)
    for (ALL_LIST_ELEMENTS (v->nexthop, node, nnode, nh))
      vertex_nexthop_free (nh);

  list_delete (v->nexthop);

  XFREE (MTYPE_OSPF_VERTEX, v);
}

/*
 * Free the SPF table (it is composed of vertices referencing each other)
 *
 * Algorithm to avoid double frees:
 * - create the list of nexthops (nhfree), without duplicates
 * - create the list of vertices (vfree), without duplicates
 *   (child vertices of a vertex are temporarily stored into vremain list)
 * - then free all nexthops and vertices from nhfree and vfree lists
 */
void
ospf_vertex_table_free(struct vertex *v)
{
  struct list * nhfree;  /* list of nexthops to free */
  struct list * vfree;   /* list of vertices to free */
  struct list * vremain; /* list of vertices remaining to examine */
  struct listnode *vnode;

  nhfree = list_new();
  vfree = list_new();
  vremain = list_new();

  listnode_add (vremain, v);

  while ((vnode = listhead(vremain)) != NULL)
  {
     struct listnode *node, *nnode;
     struct vertex *cv;
     struct nexthop *nh;

     v = listgetdata(vnode);

     /* put nexthops nh from v->nexthop list to nhfree list */
     for (ALL_LIST_ELEMENTS (v->nexthop, node, nnode, nh))
       {
         list_delete_node(v->nexthop, node);
         if (listnode_lookup(nhfree, nh) == NULL)
           listnode_add(nhfree, nh);
       }

     /* put child vertices cv from v->child list to vremain list */
     for (ALL_LIST_ELEMENTS (v->child, node, nnode, cv))
       {
         list_delete_node(v->child, node);
         if (listnode_lookup(vremain, cv) == NULL &&
             listnode_lookup(vfree, cv) == NULL)
           listnode_add(vremain, cv);
       }

     /* now that vertex v references nothing, put it in vfree list */
     list_delete_node(vremain, vnode);
     listnode_add(vfree, v);
  }

  vfree->del  = (void (*)(void *))ospf_vertex_free;
  nhfree->del = (void (*)(void *))vertex_nexthop_free;

  list_delete(vremain);
  list_delete(vfree);
  list_delete(nhfree);
}

void
ospf_vertex_dump(const char *msg, struct vertex *v,
		 int print_nexthops, int print_children)
{
  if ( ! IS_DEBUG_OSPF_EVENT)
    return;

  zlog_debug("%s %s vertex %s  distance %u backlink %d flags %u",
            msg,
	    v->type == OSPF_VERTEX_ROUTER ? "Router" : "Network",
	    inet_ntoa(v->lsa->id),
	    v->distance,
	    v->backlink,
	    (unsigned int)v->flags);

  if (print_nexthops)
    {
      struct listnode *node;
      struct vertex_nexthop *nexthop;
      
      for (ALL_LIST_ELEMENTS_RO (v->nexthop, node, nexthop))
        {
	  char buf1[BUFSIZ];
	  char buf2[BUFSIZ];

	  if (nexthop)
	    {
	      zlog_debug (" nexthop %s  interface %s  parent %s",
			 inet_ntop(AF_INET, &nexthop->router, buf1, BUFSIZ),
			 nexthop->oi ? IF_NAME(nexthop->oi) : "NULL",
			 nexthop->parent ? inet_ntop(AF_INET, 
						     &nexthop->parent->id,
						     buf2, BUFSIZ)
			                 : "NULL");
	    }
	}
    }

  if (print_children)
    {
      struct listnode *cnode;
      struct vertex *cv;
      
      for (ALL_LIST_ELEMENTS_RO (v->child, cnode, cv))
        ospf_vertex_dump(" child:", cv, 0, 0);
    }
}


/* Add a vertex to the list of children in each of its parents. */
void
ospf_vertex_add_parent (struct vertex *v)
{
  struct vertex_nexthop *nh;
  struct listnode *node;

  for (ALL_LIST_ELEMENTS_RO (v->nexthop, node, nh))
    {
      /* No need to add two links from the same parent. */
      if (listnode_lookup (nh->parent->child, v) == NULL)
        listnode_add (nh->parent->child, v);
    }
}

void
ospf_spf_free (struct ospf_area *area)
{
  if (area->spf)
    {
      ospf_vertex_table_free(area->spf);
      area->spf = NULL;
    }
}

void
ospf_spf_init (struct ospf_area *area)
{
  struct vertex *v;

  /* Create root node. */
  v = ospf_vertex_new (area->router_lsa_self);

  area->spf = v;

  /* Reset ABR and ASBR router counts. */
  area->abr_count = 0;
  area->asbr_count = 0;
}

/* return index of link back to V from W, or -1 if no link found */
int
ospf_lsa_has_link (struct lsa_header *w, struct lsa_header *v)
{
  unsigned int i, length;
  struct router_lsa *rl;
  struct network_lsa *nl;

  /* In case of W is Network LSA. */
  if (w->type == OSPF_NETWORK_LSA)
    {
      if (v->type == OSPF_NETWORK_LSA)
        return -1;

      nl = (struct network_lsa *) w;
      length = (ntohs (w->length) - OSPF_LSA_HEADER_SIZE - 4) / 4;

      for (i = 0; i < length; i++)
        if (IPV4_ADDR_SAME (&nl->routers[i], &v->id))
          return i;
      return -1;
    }

  /* In case of W is Router LSA. */
  if (w->type == OSPF_ROUTER_LSA)
    {
      rl = (struct router_lsa *) w;

      length = ntohs (w->length);

      for (i = 0;
           i < ntohs (rl->links) && length >= sizeof (struct router_lsa);
           i++, length -= 12)
        {
          switch (rl->link[i].type)
            {
            case LSA_LINK_TYPE_POINTOPOINT:
            case LSA_LINK_TYPE_VIRTUALLINK:
              /* Router LSA ID. */
              if (v->type == OSPF_ROUTER_LSA &&
                  IPV4_ADDR_SAME (&rl->link[i].link_id, &v->id))
                {
                  return i;
                }
              break;
            case LSA_LINK_TYPE_TRANSIT:
              /* Network LSA ID. */
              if (v->type == OSPF_NETWORK_LSA &&
                  IPV4_ADDR_SAME (&rl->link[i].link_id, &v->id))
                {
                  return i;
                }
              break;
            case LSA_LINK_TYPE_STUB:
              /* Not take into count? */
              continue;
            default:
              break;
            }
        }
    }
  return -1;
}

/* Add the nexthop to the list, only if it is unique.
 * If it's not unique, free the nexthop entry.
 */
void
ospf_nexthop_add_unique (struct vertex_nexthop *new, struct list *nexthop)
{
  struct vertex_nexthop *nh;
  struct listnode *node;
  int match;

  match = 0;

  for (ALL_LIST_ELEMENTS_RO (nexthop, node, nh))
    {
      /* Compare the two entries. */
      /* XXX
       * Comparing the parent preserves the shortest path tree
       * structure even when the nexthops are identical.
       */
      if (nh->oi == new->oi &&
          IPV4_ADDR_SAME (&nh->router, &new->router) &&
          nh->parent == new->parent)
        {
          match = 1;
          break;
        }
    }

  if (!match)
    listnode_add (nexthop, new);
  else
    vertex_nexthop_free (new);
}

/* Merge entries in list b into list a. */
void
ospf_nexthop_merge (struct list *a, struct list *b)
{
  struct listnode *node, *nnode;
  struct vertex_nexthop *nh;

  for (ALL_LIST_ELEMENTS (b, node, nnode, nh))
    ospf_nexthop_add_unique (nh, a);
}

#define ROUTER_LSA_MIN_SIZE 12
#define ROUTER_LSA_TOS_SIZE 4

/* Find the next link after prev_link from v to w.  If prev_link is
 * NULL, return the first link from v to w.  Ignore stub links;
 * these link types will never be returned.
 */
struct router_lsa_link *
ospf_get_next_link (struct vertex *v, struct vertex *w,
                    struct router_lsa_link *prev_link)
{
  u_char *p;
  u_char *lim;
  struct router_lsa_link *l;

  if (prev_link == NULL)
    p = ((u_char *) v->lsa) + OSPF_LSA_HEADER_SIZE + 4;
  else
    {
      p = (u_char *) prev_link;
      p += (ROUTER_LSA_MIN_SIZE +
            (prev_link->m[0].tos_count * ROUTER_LSA_TOS_SIZE));
    }

  lim = ((u_char *) v->lsa) + ntohs (v->lsa->length);

  while (p < lim)
    {
      l = (struct router_lsa_link *) p;

      p += (ROUTER_LSA_MIN_SIZE + (l->m[0].tos_count * ROUTER_LSA_TOS_SIZE));

      if (l->m[0].type == LSA_LINK_TYPE_STUB)
        continue;

      if (IPV4_ADDR_SAME (&l->link_id, &w->id))
        return l;
    }

  return NULL;
}

/* 
 * Consider supplied next-hop for inclusion to the supplied list of
 * equal-cost next-hops, adjust list as necessary.  
 *
 * (Discussed on GNU Zebra list 27 May 2003, [zebra 19184])
 *
 * Note that below is a bit of a hack, and limits ECMP to paths that go to
 * same nexthop. Where as paths via inequal output_cost interfaces could
 * still quite easily be ECMP due to remote cost differences.
 *
 * TODO: It really should be done by way of recording currently valid
 * backlinks and determining the appropriate nexthops from the list of
 * backlinks, or even simpler, just flushing nexthop list if we find a lower
 * cost path to a candidate vertex in SPF, maybe.
 */
void
ospf_spf_consider_nexthop (struct list *nexthops,
                           struct vertex_nexthop *newhop)
{
  struct vertex_nexthop *hop;
  struct listnode *ln, *nn;

  /* nexthop list should contain only the set of nexthops that have the lowest
   * equal cost
   */
  if (nexthops->head != NULL)
    {
      hop = listgetdata (nexthops->head);
      
      /* weed out hops with higher cost than the newhop */
      if (hop->oi->output_cost > newhop->oi->output_cost)
        {
          /* delete the existing nexthops */
          for (ALL_LIST_ELEMENTS (nexthops, ln, nn, hop))
            {
              listnode_delete (nexthops, hop);
              vertex_nexthop_free (hop);
            }
        }
      else if (hop->oi->output_cost < newhop->oi->output_cost)
        return;
    }

  /* new hop is <= existing hops, add it */
  listnode_add (nexthops, newhop);

  return;
}

/* 16.1.1.  Calculate nexthop from root through V (parent) to
 * vertex W (destination).
 */
void
ospf_nexthop_calculation (struct ospf_area *area,
                          struct vertex *v, struct vertex *w)
{
  struct listnode *node, *nnode;
  struct vertex_nexthop *nh, *x;
  struct ospf_interface *oi = NULL;
  struct router_lsa_link *l = NULL;


  if (IS_DEBUG_OSPF_EVENT)
    {
      zlog_debug ("ospf_nexthop_calculation(): Start");
      ospf_vertex_dump("V (parent):", v, 1, 1);
      ospf_vertex_dump("W (dest)  :", w, 1, 1);
    }

  if (v == area->spf)
    {
      /* 16.1.1 para 4.  In the first case, the parent vertex (V) is the
	 root (the calculating router itself).  This means that the 
	 destination is either a directly connected network or directly
	 connected router.  The outgoing interface in this case is simply 
         the OSPF interface connecting to the destination network/router.
      */

      if (w->type == OSPF_VERTEX_ROUTER)
        {
          while ((l = ospf_get_next_link (v, w, l)))
            {
	      /* l  is a link from v to w
	       * l2 will be link from w to v
	       */
              struct router_lsa_link *l2 = NULL;

	      if (IS_DEBUG_OSPF_EVENT)
	        {
		  char buf1[BUFSIZ];
		  char buf2[BUFSIZ];
		  
		  zlog_debug("ospf_nexthop_calculation(): considering link "
			    "type %d link_id %s link_data %s",
			    l->m[0].type,
			    inet_ntop (AF_INET, &l->link_id, buf1, BUFSIZ),
			    inet_ntop (AF_INET, &l->link_data, buf2, BUFSIZ));
		}

              if (l->m[0].type == LSA_LINK_TYPE_POINTOPOINT)
                {
		  /* If the destination is a router which connects to
		     the calculating router via a Point-to-MultiPoint
		     network, the destination's next hop IP address(es)
		     can be determined by examining the destination's
		     router-LSA: each link pointing back to the
		     calculating router and having a Link Data field
		     belonging to the Point-to-MultiPoint network
		     provides an IP address of the next hop router.

		     At this point l is a link from V to W, and V is the
		     root ("us").  Find the local interface associated 
		     with l (its address is in l->link_data).  If it
		     is a point-to-multipoint interface, then look through
		     the links in the opposite direction (W to V).  If
		     any of them have an address that lands within the
		     subnet declared by the PtMP link, then that link
		     is a constituent of the PtMP link, and its address is 
		     a nexthop address for V.
		  */
                  oi = ospf_if_is_configured (area->ospf, &l->link_data);
                  if (oi && oi->type == OSPF_IFTYPE_POINTOMULTIPOINT)
                    {
                      struct prefix_ipv4 la;

		      la.family = AF_INET;
                      la.prefixlen = oi->address->prefixlen;

                      /* V links to W on PtMP interface
                         - find the interface address on W */
                      while ((l2 = ospf_get_next_link (w, v, l2)))
                        {
                          la.prefix = l2->link_data;

                          if (prefix_cmp ((struct prefix *) &la,
                                          oi->address) == 0)
                            /* link_data is on our PtMP network */
                            break;
                        }
                    } /* end l is on point-to-multipoint link */
                  else
                    {
		      /* l is a regular point-to-point link.
			 Look for a link from W to V.
		       */
                      while ((l2 = ospf_get_next_link (w, v, l2)))
                        {
                          oi = ospf_if_is_configured (area->ospf,
                                                      &(l2->link_data));

                          if (oi == NULL)
                            continue;

                          if (!IPV4_ADDR_SAME (&oi->address->u.prefix4,
                                               &l->link_data))
                            continue;

                          break;
                        }
                    }

                  if (oi && l2)
                    {
		      /* found all necessary info to build nexthop */
                      nh = vertex_nexthop_new (v);
                      nh->oi = oi;
                      nh->router = l2->link_data;
                      ospf_spf_consider_nexthop (w->nexthop, nh);
                    } else {
                      /* check if this link is an unnumbered interface */
                      oi = ospf_get_unnumbered_if (area->ospf,
                                                   ntohl(l->link_data.s_addr));
                      if (oi) {
		        /* found all necessary info to build nexthop */
                        nh = vertex_nexthop_new (v);
                        nh->oi = oi;
                        ospf_spf_consider_nexthop (w->nexthop, nh);
                      }
		      else
		        {
		          zlog_info("ospf_nexthop_calculation(): "
				    "could not determine nexthop for link");
		        }
                    }
                } /* end point-to-point link from V to W */
             else if (l->m[0].type == LSA_LINK_TYPE_VIRTUALLINK)
                {
                  struct listnode *cnode;
                  struct vertex *cv = NULL;

                  for (ALL_LIST_ELEMENTS_RO (v->child, cnode, cv))
                    {
                      if (IPV4_ADDR_SAME (&cv->id, &w->id))
                        break;
                    }

                  if (! cv)
                    listnode_add (v->child, w);
                }
            } /* end iterate over links in W */
        } /* end W is a Router vertex */
      else
        {
	  assert(w->type == OSPF_VERTEX_NETWORK);
          while ((l = ospf_get_next_link (v, w, l)))
            {
              oi = ospf_if_is_configured (area->ospf, &(l->link_data));
              if (oi)
                {
                  nh = vertex_nexthop_new (v);
                  nh->oi = oi;
                  nh->router.s_addr = 0;
                  ospf_spf_consider_nexthop (w->nexthop, nh);
                }
            }
        }
      return;
    } /* end V is the root */

  /* Check if W's parent is a network connected to root. */
  else if (v->type == OSPF_VERTEX_NETWORK)
    {
      /* See if any of V's parents are the root. */
      for (ALL_LIST_ELEMENTS (v->nexthop, node, nnode, x))
        {
          if (x->parent == area->spf) /* connects to root? */
	    {
	      /* 16.1.1 para 5. ...the parent vertex is a network that
	       * directly connects the calculating router to the destination
	       * router.  The list of next hops is then determined by
	       * examining the destination's router-LSA...
	       */

	      assert(w->type == OSPF_VERTEX_ROUTER);
              while ((l = ospf_get_next_link (w, v, l)))
                {
		  /* ...For each link in the router-LSA that points back to the
		   * parent network, the link's Link Data field provides the IP
		   * address of a next hop router.  The outgoing interface to
		   * use can then be derived from the next hop IP address (or 
		   * it can be inherited from the parent network).
		   */
                  nh = vertex_nexthop_new (v);
                  nh->oi = x->oi;
                  nh->router = l->link_data;
                  ospf_spf_consider_nexthop (w->nexthop, nh);
                }
              return;
            }
        }
    }

  /* 16.1.1 para 4.  If there is at least one intervening router in the
   * current shortest path between the destination and the root, the
   * destination simply inherits the set of next hops from the
   * parent.
   */
  for (ALL_LIST_ELEMENTS (v->nexthop, node, nnode, nh))
    {
      struct vertex_nexthop *new;
      new = vertex_nexthop_dup(nh);
      new->parent = v;
      ospf_nexthop_add_unique (new, w->nexthop);
    }
}

/* RFC2328 Section 16.1 (2).
 * v is on the SPF tree.  Examine the links in v's LSA.  Update the list
 * of candidates with any vertices not already on the list.  If a lower-cost
 * path is found to a vertex already on the candidate list, store the new cost.
 */
void
ospf_spf_next (struct vertex *v, struct ospf_area *area,
	       struct pqueue * candidate)
{
  struct ospf_lsa *w_lsa = NULL;
  struct vertex *w, *cw;
  u_char *p;
  u_char *lim;
  struct router_lsa_link *l = NULL;
  struct in_addr *r;
  int type = 0;

  /* If this is a router-LSA, and bit V of the router-LSA (see Section
     A.4.2:RFC2328) is set, set Area A's TransitCapability to TRUE.  */
  if (v->type == OSPF_VERTEX_ROUTER)
    {
      if (IS_ROUTER_LSA_VIRTUAL ((struct router_lsa *) v->lsa))
        area->transit = OSPF_TRANSIT_TRUE;
    }

  p = ((u_char *) v->lsa) + OSPF_LSA_HEADER_SIZE + 4;
  lim = ((u_char *) v->lsa) + ntohs (v->lsa->length);

  while (p < lim)
    {
      int link = -1; /* link index for w's back link */
      
      /* In case of V is Router-LSA. */
      if (v->lsa->type == OSPF_ROUTER_LSA)
        {
          l = (struct router_lsa_link *) p;

          p += (ROUTER_LSA_MIN_SIZE +
                (l->m[0].tos_count * ROUTER_LSA_TOS_SIZE));

          /* (a) If this is a link to a stub network, examine the next
             link in V's LSA.  Links to stub networks will be
             considered in the second stage of the shortest path
             calculation. */
          if ((type = l->m[0].type) == LSA_LINK_TYPE_STUB)
            continue;

          /* (b) Otherwise, W is a transit vertex (router or transit
             network).  Look up the vertex W's LSA (router-LSA or
             network-LSA) in Area A's link state database. */
          switch (type)
            {
            case LSA_LINK_TYPE_POINTOPOINT:
            case LSA_LINK_TYPE_VIRTUALLINK:
              if (type == LSA_LINK_TYPE_VIRTUALLINK)
                {
                  if (IS_DEBUG_OSPF_EVENT)
                    zlog_debug ("looking up LSA through VL: %s",
                               inet_ntoa (l->link_id));
                }

              w_lsa = ospf_lsa_lookup (area, OSPF_ROUTER_LSA, l->link_id,
                                       l->link_id);
              if (w_lsa)
                {
                  if (IS_DEBUG_OSPF_EVENT)
                    zlog_debug ("found Router LSA %s", inet_ntoa (l->link_id));
                }
              break;
            case LSA_LINK_TYPE_TRANSIT:
              if (IS_DEBUG_OSPF_EVENT)
                zlog_debug ("Looking up Network LSA, ID: %s",
                           inet_ntoa (l->link_id));
              w_lsa = ospf_lsa_lookup_by_id (area, OSPF_NETWORK_LSA,
                                             l->link_id);
              if (w_lsa)
                if (IS_DEBUG_OSPF_EVENT)
                  zlog_debug ("found the LSA");
              break;
            default:
              zlog_warn ("Invalid LSA link type %d", type);
              continue;
            }
        }
      else
        {
          /* In case of V is Network-LSA. */
          r = (struct in_addr *) p;
          p += sizeof (struct in_addr);

          /* Lookup the vertex W's LSA. */
          w_lsa = ospf_lsa_lookup_by_id (area, OSPF_ROUTER_LSA, *r);
        }

      /* (b cont.) If the LSA does not exist, or its LS age is equal
         to MaxAge, or it does not have a link back to vertex V,
         examine the next link in V's LSA.[23] */
      if (w_lsa == NULL)
        continue;

      if (IS_LSA_MAXAGE (w_lsa))
        continue;

      if ( (link = ospf_lsa_has_link (w_lsa->data, v->lsa)) < 0 )
        {
          if (IS_DEBUG_OSPF_EVENT)
            zlog_debug ("The LSA doesn't have a link back");
          continue;
        }

      /* (c) If vertex W is already on the shortest-path tree, examine
         the next link in the LSA. */
      if (w_lsa->stat == LSA_SPF_IN_SPFTREE)
	{
	  if (IS_DEBUG_OSPF_EVENT)
	    zlog_debug ("The LSA is already in SPF");
	  continue;
	}

      /* (d) Calculate the link state cost D of the resulting path
         from the root to vertex W.  D is equal to the sum of the link
         state cost of the (already calculated) shortest path to
         vertex V and the advertised cost of the link between vertices
         V and W.  If D is: */

      /* prepare vertex W. */
      w = ospf_vertex_new (w_lsa);

      /* Save W's back link index number, for use by virtual links */
      w->backlink = link;

      /* calculate link cost D. */
      if (v->lsa->type == OSPF_ROUTER_LSA)
	w->distance = v->distance + ntohs (l->m[0].metric);
      else /* v is not a Router-LSA */
	w->distance = v->distance;

      /* Is there already vertex W in candidate list? */
      if (w_lsa->stat == LSA_SPF_NOT_EXPLORED)
	{
          /* Calculate nexthop to W. */
	  ospf_nexthop_calculation (area, v, w);
	  pqueue_enqueue (w, candidate);
	}
      else if (w_lsa->stat >= 0)
	{
	  /* Get the vertex from candidates. */
	  cw = (struct vertex *) candidate->array[w_lsa->stat];

	  /* if D is greater than. */  
	  if (cw->distance < w->distance)
            {
              ospf_vertex_free (w);
              continue;
            }
          /* equal to. */
	  else if (cw->distance == w->distance)
            {
	      /* Found an equal-cost path to W.  Calculate nexthop to W. */
              ospf_nexthop_calculation (area, v, w);
              ospf_nexthop_merge (cw->nexthop, w->nexthop);
              list_delete_all_node (w->nexthop);
              ospf_vertex_free (w);
            }
           /* less than. */
	  else
            {
	      /* Found a lower-cost path to W.  Calculate nexthop to W. */
              ospf_nexthop_calculation (area, v, w);

              /* Remove old vertex from candidate list. */
              ospf_vertex_free (cw);
	      candidate->array[w_lsa->stat] = w;
	      /* Decrease the key of the node in the heap, re-sort the heap. */
	      trickle_down (w_lsa->stat, candidate);
            }
        } /* end W is already on the candidate list */
    } /* end loop over the links in V's LSA */
}

void
ospf_spf_route_free (struct route_table *table)
{
  struct route_node *rn;
  struct vertex *v;

  for (rn = route_top (table); rn; rn = route_next (rn))
    {
      if ((v = rn->info))
        {
          ospf_vertex_free (v);
          rn->info = NULL;
        }

      route_unlock_node (rn);
    }

  route_table_finish (table);
}

void
ospf_spf_dump (struct vertex *v, int i)
{
  struct listnode *cnode;
  struct listnode *nnode;
  struct vertex_nexthop *nexthop;

  if (v->type == OSPF_VERTEX_ROUTER)
    {
      if (IS_DEBUG_OSPF_EVENT)
        zlog_debug ("SPF Result: %d [R] %s", i, inet_ntoa (v->lsa->id));
    }
  else
    {
      struct network_lsa *lsa = (struct network_lsa *) v->lsa;
      if (IS_DEBUG_OSPF_EVENT)
        zlog_debug ("SPF Result: %d [N] %s/%d", i, inet_ntoa (v->lsa->id),
                   ip_masklen (lsa->mask));
    }

  if (IS_DEBUG_OSPF_EVENT)
    for (ALL_LIST_ELEMENTS_RO (v->nexthop, nnode, nexthop))
      zlog_debug (" nexthop %s", inet_ntoa (nexthop->router));

  i++;

  for (ALL_LIST_ELEMENTS_RO (v->child, cnode, v))
    ospf_spf_dump (v, i);
}

/* Second stage of SPF calculation. */
void
ospf_spf_process_stubs (struct ospf_area *area, struct vertex *v,
                        struct route_table *rt)
{
  struct listnode *cnode, *cnnode;
  struct vertex *child;

  if (IS_DEBUG_OSPF_EVENT)
    zlog_debug ("ospf_process_stub():processing stubs for area %s",
               inet_ntoa (area->area_id));
  if (v->type == OSPF_VERTEX_ROUTER)
    {
      u_char *p;
      u_char *lim;
      struct router_lsa_link *l;
      struct router_lsa *rlsa;

      if (IS_DEBUG_OSPF_EVENT)
        zlog_debug ("ospf_process_stubs():processing router LSA, id: %s",
                   inet_ntoa (v->lsa->id));
      rlsa = (struct router_lsa *) v->lsa;


      if (IS_DEBUG_OSPF_EVENT)
        zlog_debug ("ospf_process_stubs(): we have %d links to process",
                   ntohs (rlsa->links));
      p = ((u_char *) v->lsa) + OSPF_LSA_HEADER_SIZE + 4;
      lim = ((u_char *) v->lsa) + ntohs (v->lsa->length);

      while (p < lim)
        {
          l = (struct router_lsa_link *) p;

          p += (ROUTER_LSA_MIN_SIZE +
                (l->m[0].tos_count * ROUTER_LSA_TOS_SIZE));

          if (l->m[0].type == LSA_LINK_TYPE_STUB)
            ospf_intra_add_stub (rt, l, v, area);
        }
    }

  ospf_vertex_dump("ospf_process_stubs(): after examining links: ", v, 1, 1);

  for (ALL_LIST_ELEMENTS (v->child, cnode, cnnode, child))
    {
      if (CHECK_FLAG (child->flags, OSPF_VERTEX_PROCESSED))
        continue;

      ospf_spf_process_stubs (area, child, rt);

      SET_FLAG (child->flags, OSPF_VERTEX_PROCESSED);
    }
}

void
ospf_rtrs_free (struct route_table *rtrs)
{
  struct route_node *rn;
  struct list *or_list;
  struct ospf_route *or;
  struct listnode *node, *nnode;

  if (IS_DEBUG_OSPF_EVENT)
    zlog_debug ("Route: Router Routing Table free");

  for (rn = route_top (rtrs); rn; rn = route_next (rn))
    if ((or_list = rn->info) != NULL)
      {
        for (ALL_LIST_ELEMENTS (or_list, node, nnode, or))
          ospf_route_free (or);

        list_delete (or_list);

        /* Unlock the node. */
        rn->info = NULL;
        route_unlock_node (rn);
      }
  route_table_finish (rtrs);
}

void
ospf_rtrs_print (struct route_table *rtrs)
{
  struct route_node *rn;
  struct list *or_list;
  struct listnode *ln;
  struct listnode *pnode;
  struct ospf_route *or;
  struct ospf_path *path;
  char buf1[BUFSIZ];
  char buf2[BUFSIZ];

  if (IS_DEBUG_OSPF_EVENT)
    zlog_debug ("ospf_rtrs_print() start");

  for (rn = route_top (rtrs); rn; rn = route_next (rn))
    if ((or_list = rn->info) != NULL)
      for (ALL_LIST_ELEMENTS_RO (or_list, ln, or))
        {
          switch (or->path_type)
            {
            case OSPF_PATH_INTRA_AREA:
              if (IS_DEBUG_OSPF_EVENT)
                zlog_debug ("%s   [%d] area: %s",
                           inet_ntop (AF_INET, &or->id, buf1, BUFSIZ),
                           or->cost, inet_ntop (AF_INET, &or->u.std.area_id,
                                                buf2, BUFSIZ));
              break;
            case OSPF_PATH_INTER_AREA:
              if (IS_DEBUG_OSPF_EVENT)
                zlog_debug ("%s IA [%d] area: %s",
                           inet_ntop (AF_INET, &or->id, buf1, BUFSIZ),
                           or->cost, inet_ntop (AF_INET, &or->u.std.area_id,
                                                buf2, BUFSIZ));
              break;
            default:
              break;
            }

          for (ALL_LIST_ELEMENTS_RO (or->paths, pnode, path))
            {
              if (path->nexthop.s_addr == 0)
                {
                  if (IS_DEBUG_OSPF_EVENT)
                    zlog_debug ("   directly attached to %s\r\n",
                               IF_NAME (path->oi));
                }
              else
                {
                  if (IS_DEBUG_OSPF_EVENT)
                    zlog_debug ("   via %s, %s\r\n",
                               inet_ntoa (path->nexthop), IF_NAME (path->oi));
                }
            }
        }

  zlog_debug ("ospf_rtrs_print() end");
}

/* Calculating the shortest-path tree for an area. */
void
ospf_spf_calculate (struct ospf_area *area, struct route_table *new_table,
                    struct route_table *new_rtrs)
{
  struct pqueue *candidate;
  struct vertex *v;

  if (IS_DEBUG_OSPF_EVENT)
    {
      zlog_debug ("ospf_spf_calculate: Start");
      zlog_debug ("ospf_spf_calculate: running Dijkstra for area %s",
                 inet_ntoa (area->area_id));
    }

  /* Check router-lsa-self.  If self-router-lsa is not yet allocated,
     return this area's calculation. */
  if (!area->router_lsa_self)
    {
      if (IS_DEBUG_OSPF_EVENT)
        zlog_debug ("ospf_spf_calculate: "
                   "Skip area %s's calculation due to empty router_lsa_self",
                   inet_ntoa (area->area_id));
      return;
    }

  /* RFC2328 16.1. (1). */
  /* Initialize the algorithm's data structures. */
  
  /* This function scans all the LSA database and set the stat field to
   * LSA_SPF_NOT_EXPLORED. */
  ospf_lsdb_clean_stat (area->lsdb);
  /* Create a new heap for the candidates. */ 
  candidate = pqueue_create();
  candidate->cmp = cmp;
  candidate->update = update_stat;

  /* Initialize the shortest-path tree to only the root (which is the
     router doing the calculation). */
  ospf_spf_free (area);
  ospf_spf_init (area);
  v = area->spf;
  /* Set LSA position to LSA_SPF_IN_SPFTREE. This vertex is the root of the
   * spanning tree. */
  *(v->stat) = LSA_SPF_IN_SPFTREE;

  /* Set Area A's TransitCapability to FALSE. */
  area->transit = OSPF_TRANSIT_FALSE;
  area->shortcut_capability = 1;

  for (;;)
    {
      /* RFC2328 16.1. (2). */
      ospf_spf_next (v, area, candidate);

      /* RFC2328 16.1. (3). */
      /* If at this step the candidate list is empty, the shortest-
         path tree (of transit vertices) has been completely built and
         this stage of the procedure terminates. */
      if (candidate->size == 0)
        break;

      /* Otherwise, choose the vertex belonging to the candidate list
         that is closest to the root, and add it to the shortest-path
         tree (removing it from the candidate list in the
         process). */
      /* Extract from the candidates the node with the lower key. */
      v = (struct vertex *) pqueue_dequeue (candidate);
      /* Update stat field in vertex. */
      *(v->stat) = LSA_SPF_IN_SPFTREE;
      ospf_vertex_add_parent (v);

      /* Note that when there is a choice of vertices closest to the
         root, network vertices must be chosen before router vertices
         in order to necessarily find all equal-cost paths. */
      /* We don't do this at this moment, we should add the treatment
         above codes. -- kunihiro. */

      /* RFC2328 16.1. (4). */
      if (v->type == OSPF_VERTEX_ROUTER)
        ospf_intra_add_router (new_rtrs, v, area);
      else
        ospf_intra_add_transit (new_table, v, area);

      /* RFC2328 16.1. (5). */
      /* Iterate the algorithm by returning to Step 2. */

    } /* end loop until no more candidate vertices */

  if (IS_DEBUG_OSPF_EVENT)
    {
      ospf_spf_dump (area->spf, 0);
      ospf_route_table_dump (new_table);
    }

  /* Second stage of SPF calculation procedure's  */
  ospf_spf_process_stubs (area, area->spf, new_table);

  /* Free candidates. */
  pqueue_delete (candidate);

  /* Increment SPF Calculation Counter. */
  area->spf_calculation++;

  area->ospf->ts_spf = time (NULL);

  if (IS_DEBUG_OSPF_EVENT)
    zlog_debug ("ospf_spf_calculate: Stop");
}

/* Timer for SPF calculation. */
int
ospf_spf_calculate_timer (struct thread *thread)
{
  struct ospf *ospf = THREAD_ARG (thread);
  struct route_table *new_table, *new_rtrs;
  struct ospf_area *area;
  struct listnode *node, *nnode;

  if (IS_DEBUG_OSPF_EVENT)
    zlog_debug ("SPF: Timer (SPF calculation expire)");

  ospf->t_spf_calc = NULL;

  /* Allocate new table tree. */
  new_table = route_table_init ();
  new_rtrs = route_table_init ();

  ospf_vl_unapprove (ospf);

  /* Calculate SPF for each area. */
  for (ALL_LIST_ELEMENTS (ospf->areas, node, nnode, area))
    ospf_spf_calculate (area, new_table, new_rtrs);

  ospf_vl_shut_unapproved (ospf);

  ospf_ia_routing (ospf, new_table, new_rtrs);

  ospf_prune_unreachable_networks (new_table);
  ospf_prune_unreachable_routers (new_rtrs);

  /* AS-external-LSA calculation should not be performed here. */

  /* If new Router Route is installed,
     then schedule re-calculate External routes. */
  if (1)
    ospf_ase_calculate_schedule (ospf);

  ospf_ase_calculate_timer_add (ospf);

  /* Update routing table. */
  ospf_route_install (ospf, new_table);

  /* Update ABR/ASBR routing table */
  if (ospf->old_rtrs)
    {
      /* old_rtrs's node holds linked list of ospf_route. --kunihiro. */
      /* ospf_route_delete (ospf->old_rtrs); */
      ospf_rtrs_free (ospf->old_rtrs);
    }

  ospf->old_rtrs = ospf->new_rtrs;
  ospf->new_rtrs = new_rtrs;

  if (IS_OSPF_ABR (ospf))
    ospf_abr_task (ospf);

  if (IS_DEBUG_OSPF_EVENT)
    zlog_debug ("SPF: calculation complete");

  return 0;
}

/* Add schedule for SPF calculation.  To avoid frequenst SPF calc, we
   set timer for SPF calc. */
void
ospf_spf_calculate_schedule (struct ospf *ospf)
{
  time_t ht, delay;

  if (IS_DEBUG_OSPF_EVENT)
    zlog_debug ("SPF: calculation timer scheduled");

  /* OSPF instance does not exist. */
  if (ospf == NULL)
    return;

  /* SPF calculation timer is already scheduled. */
  if (ospf->t_spf_calc)
    {
      if (IS_DEBUG_OSPF_EVENT)
        zlog_debug ("SPF: calculation timer is already scheduled: %p",
                   ospf->t_spf_calc);
      return;
    }

  ht = time (NULL) - ospf->ts_spf;

  /* Get SPF calculation delay time. */
  if (ht < ospf->spf_holdtime)
    {
      if (ospf->spf_holdtime - ht < ospf->spf_delay)
        delay = ospf->spf_delay;
      else
        delay = ospf->spf_holdtime - ht;
    }
  else
    delay = ospf->spf_delay;

  if (IS_DEBUG_OSPF_EVENT)
    zlog_debug ("SPF: calculation timer delay = %ld", (long)delay);
  ospf->t_spf_calc =
    thread_add_timer (master, ospf_spf_calculate_timer, ospf, delay);
}
