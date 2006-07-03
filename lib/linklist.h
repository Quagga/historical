/* Generic linked list
 * Copyright (C) 1997, 2000 Kunihiro Ishiguro
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

#ifndef _ZEBRA_LINKLIST_H
#define _ZEBRA_LINKLIST_H

struct listnode 
{
  struct listnode *next;
  struct listnode *prev;
  void *data;
};

struct list 
{
  struct listnode *head;
  struct listnode *tail;
  /* invariant: count is the number of listnodes in the list */
  unsigned int count;
  /*
   * Returns -1 if val1 < val2, 0 if equal?, 1 if val1 > val2.
   * Used as definition of sorted for listnode_add_sort
   */
  int (*cmp) (void *val1, void *val2);
  void (*del) (void *val);
};

#define nextnode(X) ((X) = (X)->next)
#define listhead(X) ((X)->head)
#define listtail(X) ((X)->tail)
#define listcount(X) ((X)->count)
#define list_isempty(X) ((X)->head == NULL && (X)->tail == NULL)
#define getdata(X) ((X)->data)
#define listgetdata getdata
#define listnextnode nextnode

/* Prototypes. */
struct list *list_new();
void list_free (struct list *);

void listnode_add (struct list *, void *);
void listnode_add_sort (struct list *, void *);
void listnode_add_after (struct list *, struct listnode *, void *);
void listnode_delete (struct list *, void *);
struct listnode *listnode_lookup (struct list *, void *);
void *listnode_head (struct list *);

void list_delete (struct list *);
void list_delete_all_node (struct list *);

/* For ospfd and ospf6d. */
void list_delete_node (struct list *, struct listnode *);

/* For ospf_spf.c */
void list_add_node_prev (struct list *, struct listnode *, void *);
void list_add_node_next (struct list *, struct listnode *, void *);
void list_add_list (struct list *, struct list *);

/* List iteration macro. 
 * Usage: for (ALL_LIST_ELEMENTS (...) { ... }
 * It is safe to delete the listnode using this macro.
 */
#define ALL_LIST_ELEMENTS(list,node,nextnode,data) \
  (node) = listhead(list); \
  (node) != NULL && \
    ((data) = listgetdata(node),(nextnode) = listnextnode(node), 1); \
  (node) = (nextnode)

/* read-only list iteration macro.
 * Usage: as per ALL_LIST_ELEMENTS, but not safe to delete the listnode Only
 * use this macro when it is *immediately obvious* the listnode is not
 * deleted in the body of the loop. Does not have forward-reference overhead
 * of previous macro.
 */
#define ALL_LIST_ELEMENTS_RO(list,node,data) \
  (node) = listhead(list); \
  (node) != NULL && ((data) = listgetdata(node), 1); \
  (node) = listnextnode(node)

/* List iteration macro. */
#define LIST_LOOP(L,V,N) \
  for ((N) = (L)->head; (N); (N) = (N)->next) \
    if (((V) = (N)->data) != NULL)

/* List node add macro.  */
#define LISTNODE_ADD(L,N) \
  do { \
    (N)->prev = (L)->tail; \
    if ((L)->head == NULL) \
      (L)->head = (N); \
    else \
      (L)->tail->next = (N); \
    (L)->tail = (N); \
    (L)->count++; \
  } while (0)

/* List node delete macro.  */
#define LISTNODE_DELETE(L,N) \
  do { \
    if ((N)->prev) \
      (N)->prev->next = (N)->next; \
    else \
      (L)->head = (N)->next; \
    if ((N)->next) \
      (N)->next->prev = (N)->prev; \
    else \
      (L)->tail = (N)->prev; \
    (L)->count--; \
  } while (0)

#endif /* _ZEBRA_LINKLIST_H */
