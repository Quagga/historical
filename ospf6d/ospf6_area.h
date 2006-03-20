/*
 * Copyright (C) 2003 Yasuhiro Ohara
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
 * along with GNU Zebra; see the file COPYING.  If not, write to the 
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330, 
 * Boston, MA 02111-1307, USA.  
 */

#ifndef OSPF_AREA_H
#define OSPF_AREA_H

#include "ospf6_top.h"

struct ospf6_area
{
  /* Reference to Top data structure */
  struct ospf6 *ospf6;

  /* Area-ID */
  u_int32_t area_id;

  /* Area-ID format */
  int 	ai_format;
#define OSPF6_AREA_ID_FORMAT_ADDRESS         1
#define OSPF6_AREA_ID_FORMAT_DECIMAL         2 

  /* Area-ID string */
  char name[16];

  /* flag */
  u_char flag;

  /* OSPF Option */
  u_char options[3];

  u_int32_t default_cost;

  u_int8_t default_metric_type;
  u_char NSSATranslatorRole;
  u_char NSSATranslatorState;
  u_int16_t NSSATranslatorStabilityInterval;
  struct thread *thread_nssa_trans_state_disable;
  u_char nssa_no_propagate;
  u_char nssa_no_redistribution;
  struct ospf6_route_table *translated_rt_table;
  
  /* Summary routes to be originated (includes Configured Address Ranges) */
  struct ospf6_route_table *range_table;
  struct ospf6_route_table *summary_prefix;
  struct ospf6_route_table *summary_router;

  /* OSPF interface list */
  struct list *if_list;
  
  /* virtual-link list */
  struct list *vlink_list;

  /* Fully adjacent virtual neighbors */
  u_int32_t full_vls;

  /* count of intra prefix stub lsa's originated for this area */
  u_int32_t stub_lsa_count;

  struct ospf6_lsdb *lsdb;
  struct ospf6_lsdb *lsdb_self;

  struct ospf6_route_table *spf_table;
  struct ospf6_route_table *route_table;

  struct thread  *thread_spf_calculation;

  /* Type 3 LSA Area prefix-list. */
  struct
  {
    char *name;
  } plist_in;
#define PREFIX_NAME_IN(A)   (A)->plist_in.name

  struct
  {
    char *name;
  } plist_out;
#define PREFIX_NAME_OUT(A)  (A)->plist_out.name
  struct thread  *thread_route_calculation;

  struct thread *thread_router_lsa;
  struct thread *thread_intra_prefix_lsa;
  u_int32_t router_lsa_size_limit;
};

/* Configuration data for virtual links */
struct ospf6_vl_config_data 
{
  struct vty *vty;              /* vty stuff */
  u_int32_t area_id;            /* area ID from command line */
  int ai_format;		/* area ID format */
  u_int32_t vl_peer;            /* command line router ID(vl_peer) */
  u_int16_t hello_interval;     /* timer parameters...*/
  u_int32_t retransmit_interval;
  u_int32_t transmit_delay;
  u_int16_t dead_interval;
};

#define OSPF6_AREA_ENABLE     0x01
#define OSPF6_AREA_ACTIVE     0x02
#define OSPF6_AREA_TRANSIT    0x04 /* TransitCapability */
#define OSPF6_AREA_STUB       0x08
#define OSPF6_AREA_NSSA       0x10
#define OSPF6_AREA_NO_SUMMARY 0x20 /* Totally stubby area */

#define NSSA_TRANSLATOR_ROLE_NEVER      0
#define NSSA_TRANSLATOR_ROLE_CANDIDATE  1
#define NSSA_TRANSLATOR_ROLE_ALWAYS     2

#define NSSA_TRANSLATOR_STATE_DISABLED  0
#define NSSA_TRANSLATOR_STATE_ENABLED   1

#define BACKBONE_AREA_ID (htonl (0))
#define IS_AREA_BACKBONE(oa) ((oa)->area_id == BACKBONE_AREA_ID)
#define IS_AREA_ENABLED(oa) (CHECK_FLAG ((oa)->flag, OSPF6_AREA_ENABLE))
#define IS_AREA_ACTIVE(oa) (CHECK_FLAG ((oa)->flag, OSPF6_AREA_ACTIVE))
#define IS_AREA_TRANSIT(oa) (CHECK_FLAG ((oa)->flag, OSPF6_AREA_TRANSIT))
#define IS_AREA_STUB(oa) (CHECK_FLAG ((oa)->flag, OSPF6_AREA_STUB))
#define IS_AREA_NSSA(oa) (CHECK_FLAG ((oa)->flag, OSPF6_AREA_NSSA))
#define IS_AREA_NO_SUMMARY(oa) (CHECK_FLAG ((oa)->flag, OSPF6_AREA_NO_SUMMARY))
#define IS_AREA_STUB_OR_NSSA(oa) ((IS_AREA_STUB (oa) || \
                                   IS_AREA_NSSA (oa)) ? 1 : 0) 


#define OSPF6_AREA_SAME(X,Y) \
        (memcmp ((X->area_id), (Y->area_id), IPV4_MAX_BYTELEN) == 0)

/* prototypes */
int ospf6_area_cmp (void *va, void *vb);

struct ospf6_area *ospf6_area_create (u_int32_t, int,  struct ospf6 *);
void ospf6_area_delete (struct ospf6_area *);
struct ospf6_area *ospf6_area_lookup (u_int32_t, struct ospf6 *);

void ospf6_area_enable (struct ospf6_area *);
void ospf6_area_disable (struct ospf6_area *);

void ospf6_area_show (struct vty *, struct ospf6_area *);

void ospf6_area_config_write (struct vty *vty);
void ospf6_area_init ();

struct ospf6_area * ospf6_area_get (u_int32_t, int, struct ospf6 *);

/* virtual link */
int ospf6_area_vlink_count (struct ospf6_area *);
int ospf6_full_virtual_nbrs (struct ospf6_area *);

struct ospf6_vl_data * get_valid_vl_data (struct ospf6_area *);
#endif /* OSPF_AREA_H */

