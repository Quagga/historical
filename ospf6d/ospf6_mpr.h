/*
 * Copyright (C) 2005 Boeing
 */

#ifndef OSPF6_MPR_H
#define OSPF6_MPR_H

#ifdef OSPF6_MANET_MPR_FLOOD
#include "ospf6d.h" //for boolean
#include "ospf6_interface.h"
#include "ospf6_neighbor.h"

void ospf6_calculate_relays(struct ospf6_interface *);

void ospf6_relay_create(struct ospf6_interface *, u_int32_t);
void ospf6_relay_delete(struct ospf6_interface *, struct ospf6_relay *);

void ospf6_refresh_relay_selector(struct ospf6_neighbor *);
struct ospf6_relay_selector *
  ospf6_lookup_relay_selector(struct ospf6_interface *, u_int32_t);
void ospf6_relay_selector_delete(struct ospf6_interface *, 
                                 struct ospf6_relay_selector *);
#endif //OSPF6_MANET_MPR_FLOOD
#endif /* OSPF6_MPR_H */

