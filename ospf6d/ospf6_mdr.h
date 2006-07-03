/*
 * Copyright (C) 2005 Boeing
 */

#ifndef OSPF6_MDR_H
#define OSPF6_MDR_H

#ifdef OSPF6_MANET_MDR_FLOOD

#include "ospf6d.h" //for boolean
#include "ospf6_interface.h"
#include "ospf6_neighbor.h"

#define INFTY 10000

#define OSPF6_OTHER       0
#define OSPF6_BMDR        1
#define OSPF6_MDR         2

struct tree_node 
{
  struct ospf6_neighbor *on;
  //int dist1;  // hops from source
  //int dist2;  // differential length of disjoint paths
  int labeled;  // indicates node is labeled
  struct tree_node *parent;  // parent in tree
  struct tree_node *first_child; // pointer to first child of this node
  struct tree_node *last_child; // pointer to last child of this node
  struct tree_node *next_sib;  // pointer to next child of same parent
  // next_sib points to another node at the same hop level as this node
  // next_sib is NULL if this is the last child of the parent
};


void q_add (struct list *, struct ospf6_neighbor *);
struct ospf6_neighbor *q_remove(struct list *);

void add_tree_node(struct list *, struct ospf6_neighbor *, struct tree_node *);
void remove_tree(struct list *L);
struct tree_node * dfs_next(struct tree_node* u);

void ospf6_calculate_mdr(struct ospf6_interface *);
void ospf6_mdr_update_adjacencies(struct ospf6_interface *);

void ospf6_mdr_free_cost_matrix(struct ospf6_interface *oi);
void ospf6_mdr_create_cost_matrix(struct ospf6_interface *oi);
int ospf6_mdr_matrix_element_cost(struct ospf6_neighbor *onj,
                                    struct ospf6_neighbor *onk);
/* the cost2 variant is for backup MDR */
int ospf6_mdr_cost(struct ospf6_neighbor *onA, struct ospf6_neighbor *onB);
int ospf6_mdr_cost2(struct ospf6_neighbor *onj, struct ospf6_neighbor *onk);

boolean ospf6_sidcds_lexicographic(struct ospf6_interface *oi,
                                   int DRLevel_A, int DRLevel_B,
                                   int RtrPri_A, int RtrPri_B,
                                   int RID_A, int RID_B);
boolean ospf6_mdr_set_mdr_level(struct ospf6_neighbor *on,
                               u_int32_t id1, u_int32_t id2);
#endif //OSPF6_MANET_MDR_FLOOD

#endif /* OSPF6_MDR_H */

