#ifdef SIM

#ifndef OSPF6_SIM_PRINTING_H
#define OSPF6_SIM_PRINTING_H

#include "sim.h"

#include "ospf6d.h"
#include "ospf6_interface.h"
#include "ospf6_lsa.h" //for ospf6_lsa

#ifdef OSPF6_MANET_MPR_FLOOD
void ospf6_print_relay_selector_list_sim(struct ospf6_interface *oi);
void ospf6_print_relay_list_sim(struct ospf6_interface *oi);
#endif // OSPF6_MANET_MPR_FLOOD
void ospf6_print_neighborhood_sim(struct ospf6_interface *oi);
#ifdef OSPF6_MANET
void ospf6_print_pushback_list_sim(struct ospf6_lsa *lsa);
#endif //OSPF6_MANET

#endif //OSPF6_SIM_PRINTING_H

#endif //SIM
