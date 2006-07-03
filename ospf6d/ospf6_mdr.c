/*
 * Copyright (C) Boeing Co.
 *
 * Much of the code in this file was written by Richard Ogier
 * or was transcribed from C code written by him.
 * This code implements the MDR extension of OSPF as described in
 * draft-ogier-manet-ospf-extension-06.txt.
 */

#include "zebra.h" 

#ifdef OSPF6_MANET_MDR_FLOOD

#include "thread.h"
#include "ospf6_mdr.h"
#include "ospf6_area.h"
#include "ospf6_flood.h"
#include "ospf6_intra.h"
#include "ospf6_lsa.h"
#include "ospf6_top.h"
#ifdef SIM_ETRACE_STAT
#include "sim.h"
#endif //SIM_ETRACE_STAT

//Determine if node is in CDS
void ospf6_calculate_mdr(struct ospf6_interface *oi)
{
  struct listnode *j, *k, *u;
  struct ospf6_neighbor *onj, *onk, *onu, *onv;
  struct ospf6_neighbor *max_on = NULL, *max_on2 = NULL, *min_on = NULL;
  struct ospf6_neighbor *max_nbr = NULL; // RGO
  struct list *q;
  struct list *tree = list_new();
  u_int32_t rid = oi->area->ospf6->router_id;
  int maxid = -1, maxid2 = -1;
  int max_mdr_level = OSPF6_OTHER, max_mdr_level2 = OSPF6_OTHER;
  struct tree_node *child, *child2, *tu, *tv, *root;
  int min_hops2, cost2;
  boolean dr=false, bdr=false;

  // Do not calculate MDRs within hello_interval of start time.
  if (elapsed_time(&ospf6->starttime) < oi->hello_interval)
    return;

  //cost_matrix must be freed at the end of this function
  ospf6_mdr_create_cost_matrix(oi);

#ifdef SIM_ETRACE_STAT
  char router_id[16];
  inet_ntop (AF_INET, &rid, router_id, sizeof (router_id));
#endif //SIM_ETRACE_STAT

// A.1. PHASE 1 - 1.3
  // First find the largest nbr ID
  // For persistent version, find largest DR level first.
  for (j = listhead(oi->neighbor_list); j; nextnode(j))
  {
    onj = (struct ospf6_neighbor *) getdata (j);

    //some intitialization
    // Select dependent neighbors.
    onj->dependent = false;
    onj->hops = INFTY;
    onj->hops2 = INFTY;

    if (ospf6_mdr_cost(onj, NULL) != 1)
      continue; // nbr must be twoway
 
    //Find Max and 2nd Max Neighbor
    if (ospf6_sidcds_lexicographic(oi, onj->mdr_level, max_mdr_level, 0, 0, 
                                   ntohl(onj->router_id), maxid))
    {
      // previous max neighbor becomes 2nd max neighbor
      maxid2 = maxid;
      max_mdr_level2 = max_mdr_level;
      max_on2 = max_on;

      maxid = ntohl(onj->router_id);
      max_mdr_level = onj->mdr_level;
      max_on = onj;
    }
    else if (ospf6_sidcds_lexicographic(oi, onj->mdr_level, max_mdr_level2, 
                                        0, 0, ntohl(onj->router_id), maxid2))
    {
      maxid2 = ntohl(onj->router_id);
      max_mdr_level2 = onj->mdr_level;
      max_on2 = onj;
    }
  }

  if (maxid == -1)
  {
    //no neighbors
    oi->mdr_level = OSPF6_OTHER;
    oi->parent = NULL;
    oi->bparent = NULL;

    //clean up
    remove_tree(tree);
    ospf6_mdr_free_cost_matrix(oi);
    return;
  }

#ifdef SIM_ETRACE_STAT
  TraceEvent_sim(2,"nbr: max_mdr_level=%d maxid=%d", max_mdr_level, maxid);
  TraceEvent_sim(2,"nbr: max_mdr_level2=%d maxid2=%d", max_mdr_level2, maxid2);
#endif //SIM_ETRACE_STAT

// A.1. PHASE 1 - 1.1
  if (ospf6_sidcds_lexicographic(oi, oi->mdr_level, max_mdr_level, 0, 0, 
                                 ntohl(rid), maxid))
  {
    // Generate LSA if Other becomes MDR or BMDR.
    if (oi->LSAFullness == OSPF6_LSA_FULLNESS_MDRFULL && 
        oi->mdr_level == OSPF6_OTHER)
      OSPF6_ROUTER_LSA_SCHEDULE (oi->area);

    oi->mdr_level = OSPF6_MDR;  //dr = true

    // Make all neighbors dependent
    // RGO. Modification for version 07. A dependent neighbor
    // must be an MDR (or BMDR if AdjConn = 2).
    for (j = listhead(oi->neighbor_list); j; nextnode(j))
    {
      onj = (struct ospf6_neighbor *) getdata (j);
      // Select dependent neighbors.
      if (ospf6_mdr_cost(onj, NULL) == 1)
        if (onj->mdr_level == OSPF6_MDR ||
            (oi->AdjConnectivity == 2 && onj->mdr_level == OSPF6_BMDR))
          onj->dependent = true;
    }

    oi->parent = NULL;
    oi->bparent = NULL;
#ifdef SIM_ETRACE_STAT
    TraceEvent_sim(2,"Phase 1 1.1: I am a DR id = %s mdr_level = %d", 
      router_id, oi->mdr_level);
#endif //SIM_ETRACE_STAT
    //clean up
    remove_tree(tree);
    ospf6_mdr_free_cost_matrix(oi);
    return;  //I am a CDS
  }

// A.1. PHASE 1 - 1.2
  //ospf6_mdr_cost()

  // Determine if there is a path from on_max to all other nbrs of this node,
  //   using only intermediate nodes with larger ID than this node).
  // Use BFS, starting with on_max.
// A.1. PHASE 1 - 1.4
  max_on->hops = 0;
  add_tree_node(tree, max_on, NULL); 
  q = list_new();
  q_add(q, max_on); // Add max_on to FIFO.


// A.1. PHASE 1 - 1.5
  while ((onk = q_remove(q)) != NULL) 
  {
    // update hops of onk's nbrs
    for (u = listhead(oi->neighbor_list); u; nextnode(u))
    {
      onu = (struct ospf6_neighbor *) getdata (u);
      if (ospf6_mdr_cost(onu, NULL) != 1)
        continue; // nbr must be twoway
      // Cost is from k to u.
      if (ospf6_mdr_cost(onk, onu) != 1)
        continue;
      if (onk->hops + 1 < onu->hops)
      {
        onu->hops = onk->hops + 1;
        add_tree_node(tree, onu, onk->treenode);
        q_add(q, onu);
      }
    }
  }
  list_delete(q); 

// A.1. PHASE 1 - 1.6
  // Node is in CDS if any nbr has infinite hops
  for (k = listhead(oi->neighbor_list); k; nextnode(k))
  {
    onk = (struct ospf6_neighbor *) getdata (k);
    if (ospf6_mdr_cost(onk, NULL) != 1)
      continue; // nbr must be twoway
    //if (onk->hops == INFTY)
    if (onk->hops > oi->MDRConstraint) // MPN parameter h.
    {
#ifdef SIM_ETRACE_STAT
    TraceEvent_sim(2,"Dependent neighbor = %s", ip2str(onk->router_id));
#endif //SIM_ETRACE_STAT
      dr = true;
      if (onk->mdr_level == OSPF6_MDR ||
          (oi->AdjConnectivity == 2 && onk->mdr_level == OSPF6_BMDR))
        onk->dependent = true;
    }
  }
  if (dr) 
  {
#ifdef SIM_ETRACE_STAT
    TraceEvent_sim(2,"Phase 1 1.6: I am a DR id = %s previous mdr_level = %d", 
      router_id, oi->mdr_level);
#endif //SIM_ETRACE_STAT
    // max_on is always dependent (no need to check MDR level).
    max_on->dependent = true;
    // Parents are updated later.
  }

  // ###### Backup DR Calculation ########
// A.1. PHASE 2 - 2.1
  //use ospf6_mdr_cost2()
  
// A.1. PHASE 2 - 2.2
  max_on->hops2 = 0;

// A.1. PHASE 2 - 2.3
  max_on->treenode->labeled = 1; // root is labeled
  // Update hops2 by looking at links between subtrees created
  // when root is removed from tree.
  for (child=max_on->treenode->first_child; child; child=child->next_sib)
  {
    for (child2=max_on->treenode->first_child; child2; child2=child2->next_sib)
    {
      if (child == child2) 
        continue;
      // child is the root of its subtree, so start DFS from child
      for (tu = child; tu; tu = dfs_next(tu)) 
      {
        onu = tu->on;
        for (tv = child2; tv; tv = dfs_next(tv)) 
        {
          onv = tv->on;
          if (ntohl(onu->router_id) == ntohl(onv->router_id)) 
            printf("Error: u should not equal v \n");
          if (onv->hops2 > max_on->hops2 + ospf6_mdr_cost2(onu,onv))
            onv->hops2 = max_on->hops2 + ospf6_mdr_cost2(onu,onv);
          // If we were actually computing disjoint paths,
          // we would also update parent nodes here.
        }
      }
    }
  }

// A.1. PHASE 2 - 2.4
  // Next, find the unlabeled node min_on with minimum hops2 and label it.
  // This divides the unlabeled subtree containing min_on into smaller
  // unlabeled subtrees, one for the parent of min_on if it exists and
  // is unlabeled, and one for each unlabeled child of min_on.
  // For node-disjoint paths, one of the subtrees must be the parent subtree.
  // I.e., we cannot use links between two child subtrees.
  // Also, a link from min_on to a node in the parent subtree is allowed.
  while (1) 
  { // will break when no unlabeled node with finite hops2 exists
    min_hops2 = INFTY;
    for (k = listhead(oi->neighbor_list); k; nextnode(k))
    {
      onk = (struct ospf6_neighbor *) getdata (k);
      if (ospf6_mdr_cost(onk, NULL) != 1)
        continue; // nbr must be twoway
      if(!onk->treenode || onk->treenode->labeled)
        continue;
      if(onk->hops2 < min_hops2)
      {
        min_hops2 = onk->hops2;
        min_on = onk;
      }
    }

    if (min_hops2 == INFTY) 
      break;  // S-T algorithm done

    min_on->treenode->labeled = 1;
    if (!min_on->treenode->parent || min_on->treenode->parent->labeled)
      continue; // no parent subtree, so try another kmin

    // Find root of parent subtree
    root = min_on->treenode->parent;
    while (root->parent && !root->parent->labeled) 
      root = root->parent;

    // Iterate thru nodes of parent subtree, using DFS
    for (tu = root; tu; tu = dfs_next(tu)) 
    {
      onu = tu->on;
      if (ntohl(onu->router_id) == ntohl(min_on->router_id)) 
        printf("Error: onu should not equal min_on\n");
      // First process link from min_on to u
      cost2 = ospf6_mdr_cost2(min_on,onu);
      if (onu->hops2 > min_on->hops2 + cost2)
        onu->hops2 = min_on->hops2 + cost2;
      // Now process links between u and each child subtree, in both directions
      for (child2=min_on->treenode->first_child;child2;child2=child2->next_sib)
      {
        if (child2->labeled) 
          continue; // consider only unlabeled children
        for (tv = child2; tv; tv = dfs_next(tv)) 
        {
          onv = tv->on;
          if (ntohl(onv->router_id) == ntohl(onu->router_id)) 
            printf("Error: v should not equal u \n");
          if (ntohl(onv->router_id) == ntohl(min_on->router_id)) 
            printf("Error: v should not equal kmin \n");
          // Process link from u to v to update onv->hops2
          cost2 = ospf6_mdr_cost2(onu,onv);
          if (onv->hops2 > min_on->hops2 + cost2)
            onv->hops2 = min_on->hops2 + cost2;
          cost2 = ospf6_mdr_cost2(onv,onu);
          // Process link from v to u to update onu->hops2
          if (onu->hops2 > min_on->hops2 + cost2)
            onu->hops2 = min_on->hops2 + cost2;
        }
      }
    }
  }
// A.1. PHASE 2 - 2.5
  // Node is a backup DR if any nbr has infinite hops2
  for (k = listhead(oi->neighbor_list); k; nextnode(k))
  {
    onk = (struct ospf6_neighbor *) getdata (k);
    if (ospf6_mdr_cost(onk, NULL) != 1)
      continue; // nbr must be twoway
    if(onk->hops2 == INFTY)
    {
// A.1. PHASE 2 - 2.6
      if (!dr) 
        bdr = true; // Router is a BMDR.
      // RGO. Modification for version 07. Backup dependent nbrs
      // are selected only if AdjConn = 2, and must be MDR or BMDR.
      if (!onk->dependent)
        if (oi->AdjConnectivity == 2 && onk->mdr_level >= OSPF6_BMDR)
          onk->dependent = true; // onk is a dependent nbr
    }
  }
  if (bdr) 
  {
#ifdef SIM_ETRACE_STAT
    TraceEvent_sim(2,"Phase 2 2.5: I am a BDR id = %s mdr_level = %d", 
      router_id, oi->mdr_level);
#endif //SIM_ETRACE_STAT
    // If Adj_Conn = 2 and max_on is not dependent, then
    // it is backup dependent (no need to check MDR level).
    if (!max_on->dependent)
      if (oi->AdjConnectivity == 2)
        max_on->dependent = true;
  }

  // PARENT SELECTION.
  // RGO. New parent selection rules for version 07.
  // For an MDR, parent is always Rmax (max_on).
  // For a BMDR and Other, parent is the adjacent MDR neighbor with largest
  // RID, if an adjacent MDR neighbor exists, and is otherwise Rmax.
  // Backup parent of MDR and BMDR is NULL.
  // If AdjConn = 1, backup parent of Other is NULL.
  // If AdjConn = 2, backup parent is chosen using the same rules as the
  // parent, except that it must be different from the parent (or NULL).


  if (dr)
  {
    oi->parent = max_on;
  }
  else // BMDR or Other
  {
    // Find an adjacent MDR neighbor with max ID, if one exists.
    maxid = -1;
    max_mdr_level = 0;
    max_nbr = NULL;
    for (j = listhead(oi->neighbor_list); j; nextnode(j))
    {
      onj = (struct ospf6_neighbor *) getdata (j);
      if (onj->state < OSPF6_NEIGHBOR_EXCHANGE)
        continue; // consider only adjacent neighbors
      if (onj->mdr_level < OSPF6_MDR)
        continue; // consider only MDR neighbors
      if (ospf6_sidcds_lexicographic(oi, onj->mdr_level, max_mdr_level, 0, 0,
                                     ntohl(onj->router_id), maxid))
      {
        maxid = ntohl(onj->router_id);
        max_mdr_level = onj->mdr_level;
        max_nbr = onj;
      }
    }
    if (maxid != -1)
      oi->parent = max_nbr;
    else
      oi->parent = max_on;
  }

  // Select backup parent
  // Initialize backup parent to NULL.
  // Will remain NULL for MDR/BMDR or if AdjConn = 1.
  oi->bparent = NULL;
  // If AdjConn = 2, MDR Other selects backup parent, using same
  // procedure as for parent, but must not be equal to parent.
  if (!dr && !bdr && oi->AdjConnectivity == 2)
  {
    // Find an adjacent MDR or BMDR neighbor with max ID, excluding parent.
    maxid = -1;
    max_mdr_level = 0;
    max_nbr = NULL;
    for (j = listhead(oi->neighbor_list); j; nextnode(j))
    {
      onj = (struct ospf6_neighbor *) getdata (j);
      if (onj->state < OSPF6_NEIGHBOR_EXCHANGE)
        continue; // consider only adjacent neighbors
      if (onj == oi->parent)
        continue; // backup parent cannot be parent
      if (onj->mdr_level < OSPF6_BMDR)
        continue; // consider only MDR and BMDR neighbors
      if (ospf6_sidcds_lexicographic(oi, onj->mdr_level, max_mdr_level, 0, 0,
                                     ntohl(onj->router_id), maxid))
      {
        maxid = ntohl(onj->router_id);
        max_mdr_level = onj->mdr_level;
        max_nbr = onj;
      }
    }
    if (maxid != -1)
      oi->bparent = max_nbr;
    else if (oi->parent != max_on)
      oi->bparent = max_on;
    else
      oi->bparent = max_on2;  // can be NULL
  }

  // Generate LSA if Other becomes MDR or BMDR,
  // or if full adjacencies are used and router is Other and the
  // parent or bparent is Full but not yet advertised.
  if ((oi->LSAFullness == OSPF6_LSA_FULLNESS_MDRFULL && 
       oi->mdr_level == OSPF6_OTHER && (dr || bdr)) ||
       (!dr && !bdr && oi->full_adj_part_lsa &&
       (oi->parent && oi->parent->state == OSPF6_NEIGHBOR_FULL &&
        !oi->parent->adv ||
        oi->bparent &&  oi->bparent->state == OSPF6_NEIGHBOR_FULL &&
        !oi->bparent->adv)))
    OSPF6_ROUTER_LSA_SCHEDULE (oi->area);

  // set correct designated router level
  if (dr)
    oi->mdr_level = OSPF6_MDR;
  else if (bdr)
    oi->mdr_level = OSPF6_BMDR;
  else
    oi->mdr_level = OSPF6_OTHER;

  //clean up
  remove_tree(tree);
  ospf6_mdr_free_cost_matrix(oi);

#ifdef SIM_ETRACE_STAT
{
  char p_rid[16];
  char bp_rid[16];
  if (oi->parent)
    inet_ntop (AF_INET, &oi->parent->router_id, p_rid, sizeof (p_rid));
  if (oi->bparent)
    inet_ntop (AF_INET, &oi->bparent->router_id, bp_rid, sizeof (bp_rid));

  if (oi->parent && oi->bparent)
    TraceEvent_sim(2,"mdr_level = %d parent = %s bparent = %s",
      oi->mdr_level, p_rid, bp_rid);
  else if (oi->parent)
    TraceEvent_sim(2,"mdr_level = %d parent = %s", oi->mdr_level, p_rid);
  else 
    TraceEvent_sim(2,"mdr_level = %d", oi->mdr_level);
}
#endif //SIM_ETRACE_STAT
}


void ospf6_mdr_update_adjacencies(struct ospf6_interface *oi)
{
  struct listnode *j;
  struct ospf6_lsa *lsa;
  struct ospf6_neighbor *on;
  // Check need adjacency for each 2-way neighbor.
  for (j = listhead(oi->neighbor_list); j; nextnode(j))
  {
    on = (struct ospf6_neighbor *) getdata (j);
    if (on && on->state == OSPF6_NEIGHBOR_TWOWAY && need_adjacency(on))
    {
      ospf6_neighbor_state_change (OSPF6_NEIGHBOR_EXSTART, on);
      SET_FLAG (on->dbdesc_bits, OSPF6_DBDESC_MSBIT);
      SET_FLAG (on->dbdesc_bits, OSPF6_DBDESC_MBIT);
      SET_FLAG (on->dbdesc_bits, OSPF6_DBDESC_IBIT);
      THREAD_OFF (on->thread_send_dbdesc);
      on->thread_send_dbdesc =
      thread_add_event (master, ospf6_dbdesc_send, on, 0);
    }
  }
  // Check keep adjacency for each adjacent neighbor.
  for (j = listhead(oi->neighbor_list); j; nextnode(j))
  {
    on = (struct ospf6_neighbor *) getdata (j);
    if (on && on->state > OSPF6_NEIGHBOR_TWOWAY && !keep_adjacency(on))
    {
      ospf6_neighbor_state_change (OSPF6_NEIGHBOR_TWOWAY, on);
      // Clear retrans_list 
      ospf6_lsdb_remove_all (on->summary_list);
      ospf6_lsdb_remove_all (on->request_list);
      for (lsa = ospf6_lsdb_head (on->retrans_list); lsa;
           lsa = ospf6_lsdb_next (lsa))
      {
        ospf6_decrement_retrans_count (lsa);
        ospf6_lsdb_remove (lsa, on->retrans_list);
      }
    }
    if (on && on->state==OSPF6_NEIGHBOR_TWOWAY && on->retrans_list->count > 0)
      printf("Error:2-way nbr has nonempty retrans list, count %d dep %d\n", 
        on->retrans_list->count, on->dependent);
  }
}


//#####################BFS#####################
void q_add (struct list *q, struct ospf6_neighbor *on)
{
  listnode_add(q, on); 
}

// Removes head of queue and returns neighbor.
// Returns NULL if queue is empty.
struct ospf6_neighbor *q_remove(struct list *q)
{
  struct ospf6_neighbor *on;
  if (q->head == NULL)
    return NULL;
  on = (struct ospf6_neighbor *) q->head->data;
  list_delete_node(q, q->head);
  return on;
}

//######################TREE###########################
// Tree node must be added only after its parent has been added.
// Parent tree node is found from its ID via a simple array.
// The index of the tree node indexes the array and matrix.
// Tree nodes must be freed after algorithm is done, using the array.
void add_tree_node(struct list *L, struct ospf6_neighbor *on,struct tree_node *parent)
{
  struct tree_node* u = (struct tree_node *) malloc(sizeof(struct tree_node));
  if (u == NULL) 
  {
    printf("u is NULL \n");
    exit(0);
  }
  u->on = on;
  on->treenode = u;

  u->parent = parent;
  u->labeled = 0;  // to be set when node is labeled
  u->first_child = NULL;
  u->last_child = NULL;
  u->next_sib = NULL;
  if (parent) 
  {
    if (!parent->first_child) 
      parent->first_child = u;
    else 
      parent->last_child->next_sib = u;
    parent->last_child = u;
  }
  listnode_add(L, u);
}

void remove_tree(struct list *L)
{
  struct listnode *n;
  struct tree_node *node;
  for (n = listhead(L); n; nextnode(n))
  {
    node = (struct tree_node *) getdata (n);
    node->on->treenode = NULL;
    free(node);
  }
  list_delete(L);
}

// Finds next node in DFS of unlabeled subtree.
// Labeled nodes define boundary of subtree.
// Search must start at the root of a subtree.
// Root is defined by parent being NULL or labeled.
// Returns NULL when search is finished.
struct tree_node * dfs_next(struct tree_node* u)
{
  struct tree_node *v, *w;
  if (u->labeled) 
    printf("Error: DFS cannot visit labeled node\n");
  // Return first unlabeled child, if it exists
  for (v = u->first_child; v != NULL; v = v->next_sib) 
  {
    if (!v->labeled) return (v);
  }
  // Find an unlabeled sibling, otherwise go to parent and repeat.
  // If parent is NULL or labeled, then root has been reached.
  for (v = u; v->parent && !(v->parent->labeled); v = v->parent) 
  {
    for (w = v->next_sib; w; w = w->next_sib) 
    {
      if (!w->labeled) 
        return (w);
    }
  }
  return (NULL); // DFS is finished.
}

void ospf6_mdr_free_cost_matrix(struct ospf6_interface *oi)
{
  u_int i;

  //free matrix
  for (i = 0; i < oi->neighbor_list->count; i++)
    free(oi->cost_matrix[i]);
  free(oi->cost_matrix);
  oi->cost_matrix = NULL;
}



void ospf6_mdr_create_cost_matrix(struct ospf6_interface *oi)
{
  struct listnode *j, *k, *u;
  u_int32_t *id;
  struct ospf6_neighbor *onj, *onk;
  int count = 0;
  int num_neigh = oi->neighbor_list->count;

  if (oi->cost_matrix)
  {
    printf("cost matrix should be NULL\n");
    exit(0);
  }

  //intialize matrix to false
  oi->cost_matrix = (int **) malloc(sizeof(int*[num_neigh]));
  for (j = listhead(oi->neighbor_list); j; nextnode(j))
  {
    onj = (struct ospf6_neighbor *) getdata (j);
    onj->cost_matrix_index = count;
    oi->cost_matrix[count] = (int *) malloc(sizeof(int[num_neigh]));
    memset (oi->cost_matrix[count++], 0, sizeof (int[num_neigh]));
  }

  //set matrix values
  for (j = listhead(oi->neighbor_list); j; nextnode(j))
  {
    onj = (struct ospf6_neighbor *) getdata (j);
    oi->cost_matrix[onj->cost_matrix_index][onj->cost_matrix_index] = 0;
    for (k = listhead(oi->neighbor_list); k; nextnode(k))
    {
      onk = (struct ospf6_neighbor *) getdata (k);
      if (onj == onk)
        continue; //cost = 0

      if (onj->state < OSPF6_NEIGHBOR_TWOWAY ||
          onk->state < OSPF6_NEIGHBOR_TWOWAY)
        continue; //cost = 0

      if (!onj->Report2Hop && !onk->Report2Hop)
        continue;

      for (u = listhead(onj->rnl); u; nextnode(u))
      {
        id = (u_int32_t *) getdata(u);
        if (*id == onk->router_id)
        {
           oi->cost_matrix[onj->cost_matrix_index][onk->cost_matrix_index] = 1;
           break;
        }
      }
    }
  }

  // The above calculation gives an asymmetric matrix.
  // Now make it symmetric depending on Report2Hop.
  for (j = listhead(oi->neighbor_list); j; nextnode(j))
  {
    onj = (struct ospf6_neighbor *) getdata (j);
    for (k = listhead(oi->neighbor_list); k; nextnode(k))
    {
      onk = (struct ospf6_neighbor *) getdata (k);
      if (onj == onk)
        continue; //cost = 0
      if (onj->state < OSPF6_NEIGHBOR_TWOWAY ||
          onk->state < OSPF6_NEIGHBOR_TWOWAY)
        continue; //cost = 0
      if (!onj->Report2Hop && !onk->Report2Hop)
        continue;

      if (onj->Report2Hop && onk->Report2Hop)
      {
        // Assumes cost_matrix value is 1 for neighbors, 0 for not.
        oi->cost_matrix[onj->cost_matrix_index][onk->cost_matrix_index] = 
        oi->cost_matrix[onk->cost_matrix_index][onj->cost_matrix_index] = 
          oi->cost_matrix[onj->cost_matrix_index][onk->cost_matrix_index] 
        * oi->cost_matrix[onk->cost_matrix_index][onj->cost_matrix_index];
      }
      else if (onj->Report2Hop && !onk->Report2Hop)
      {
        oi->cost_matrix[onk->cost_matrix_index][onj->cost_matrix_index] = 
          oi->cost_matrix[onj->cost_matrix_index][onk->cost_matrix_index];
      }
      else if (!onj->Report2Hop && onk->Report2Hop)
      {
        oi->cost_matrix[onj->cost_matrix_index][onk->cost_matrix_index] = 
          oi->cost_matrix[onk->cost_matrix_index][onj->cost_matrix_index];
      }
    }
  }
}

int ospf6_mdr_cost(struct ospf6_neighbor *onj, struct ospf6_neighbor *onk)
{
  struct ospf6_interface *oi = onj->ospf6_if;

  //###### calculation of cost to my neighbor ######
  //###### 2nd entry must be NULL for this calc ####
  if (onj->state < OSPF6_NEIGHBOR_TWOWAY)
    return 0; //not my neighbor
  if (onk == NULL) //indicates link with current node
      return 1;  

  //must be on same interface
  if (oi != onk->ospf6_if)
  {
    printf("ospf6_mdr_cost called with bad input values\n");
    exit (0);
  }

  if (ospf6_sidcds_lexicographic(oi, oi->mdr_level, onj->mdr_level, 0, 0, 
                     ntohl(oi->area->ospf6->router_id), ntohl(onj->router_id)))
    return INFTY;

  return oi->cost_matrix[onj->cost_matrix_index][onk->cost_matrix_index];
}

int ospf6_mdr_cost2(struct ospf6_neighbor *onj, struct ospf6_neighbor *onk)
{
  int cost;
  struct ospf6_interface *oi = onj->ospf6_if;

  if (onj->state < OSPF6_NEIGHBOR_TWOWAY ||
      onk->state < OSPF6_NEIGHBOR_TWOWAY ||
      onj == onk ||
      oi != onk->ospf6_if)
  {
    printf("ospf6_mdr_cost2 called with bad input values\n");
    exit (0);
  }

  cost = ospf6_mdr_cost(onj, onk);

  if (cost != 1)
    return INFTY; 
  
  return (1 + onj->hops - onk->hops); 
}

// True if A > B
boolean ospf6_sidcds_lexicographic(struct ospf6_interface *oi,
                                   int DRLevel_A, int DRLevel_B, 
                                   int RtrPri_A, int RtrPri_B, 
                                   int RID_A, int RID_B)
{
  if (oi->NonPersistentMDR)
  {
    if (RtrPri_A > RtrPri_B)
      return true;
    if ((RtrPri_A == RtrPri_B) && (RID_A > RID_B))
      return true;
  }
  else 
  {
    if (DRLevel_A > DRLevel_B)
      return true;
    if ((DRLevel_A == DRLevel_B) && (RtrPri_A > RtrPri_B))
      return true;
    if ((DRLevel_A == DRLevel_B) && (RtrPri_A == RtrPri_B) && (RID_A > RID_B))
      return true;
  }
  return false;
}

// Return true if a change occured.
boolean ospf6_mdr_set_mdr_level(struct ospf6_neighbor *on, 
                               u_int32_t id1, u_int32_t id2)
{
  struct ospf6_interface *oi = on->ospf6_if;
  int old_mdr_level, old_child;
  boolean remove = false;
  boolean changed = false;

  old_mdr_level = on->mdr_level;
  old_child = on->child;
  on->child = false;

  /*printf("set_mdr_level called, node %d level %d nbr %d level %d dep_sel %d\n",
     ntohl(oi->area->ospf6->router_id), oi->mdr_level,
     ntohl(on->router_id), on->mdr_level, on->dependent_selector);*/
  if (on->router_id == id1)
    on->mdr_level = OSPF6_MDR;
  else if (on->router_id == id2)
    on->mdr_level = OSPF6_BMDR;
  else
    on->mdr_level = OSPF6_OTHER;
  // Set child even if it is a DR/BDR.
  if (oi->area->ospf6->router_id == id1 ||
      oi->area->ospf6->router_id == id2)
    on->child = true;
  if (old_mdr_level != on->mdr_level) changed = true;
  // child change does not affect CDS calculation.

  if (old_mdr_level >= OSPF6_MDR && on->mdr_level < OSPF6_MDR)
  {
    oi->mdr_count--;
    remove = true;
  }
  else if (old_mdr_level < OSPF6_MDR && on->mdr_level >= OSPF6_MDR)
  {
    set_time(&on->mdr_install_time);
    oi->mdr_count++;
  }
  else 
    return changed;

#ifdef SIM_ETRACE_STAT
  float delta = elapsed_time(&oi->relaysel_change_time);
  update_statistics(OSPF6_DURATION_OF_NUM_RELSEL, (double)delta);
  update_statistics(OSPF6_NUM_RELSEL_TIMES_DURATION_OF_NUM_RELSEL, 
                    (double)(oi->mdr_count * delta));
  if (remove == true)
  {
    float lifetime = elapsed_time(&on->mdr_install_time);
    update_statistics(OSPF6_RELSEL_LIFETIME, (double)lifetime);
    update_statistics(OSPF6_RELSEL_DEATHS, 1);
  }
  set_time(&oi->relaysel_change_time);
#endif //SIM_ETRACE_STAT
  return changed;
}
#endif //OSPF6_MANET_MDR_FLOOD
