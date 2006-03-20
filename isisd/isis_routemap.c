/*
 * IS-IS Rout(e)ing protocol               - isis_routemap.c
 *
 * Copyright (C) 2001,2002   Sampo Saaristo
 *                           Tampere University of Technology      
 *                           Institute of Communications Engineering
 *
 *
 * This program is free software; you can redistribute it and/or modify it 
 * under the terms of the GNU General Public Licenseas published by the Free 
 * Software Foundation; either version 2 of the License, or (at your option) 
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,but WITHOUT 
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or 
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for 
 * more details.

 * You should have received a copy of the GNU General Public License along 
 * with this program; if not, write to the Free Software Foundation, Inc., 
 * 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */


/*
 * Copyright (C) 2006 6WIND
 */

#include <stdlib.h>
#include <stdio.h>
#include <zebra.h>

#include "thread.h"
#include "linklist.h"
#include "vty.h"
#include "log.h"
#include "memory.h"
#include "prefix.h"
#include "command.h"
#include "hash.h"
#include "if.h"
#include "table.h"
#include "plist.h"
#include "filter.h"
#include "routemap.h"

#include "isis_constants.h"
#include "isis_common.h"
#include "dict.h"
#include "isisd.h"
#include "isis_misc.h"
#include "isis_adjacency.h"
#include "isis_circuit.h"
#include "isis_tlv.h"
#include "isis_pdu.h"
#include "isis_lsp.h"
#include "isis_spf.h"
#include "isis_route.h"
#include "isis_zebra.h"
#include "isis_routemap.h"
#include "isis_redistribute.h"

extern struct isis *isis;

void
isis_route_map_upd (const char *name)
{
  int i = 0;

  if (!isis)
    return;

  for (i = 0; i <= ZEBRA_ROUTE_MAX; i++)
    {
      if (isis->rmap[i].name)
	{
          struct route_map *old = isis->rmap[i].map;
          
          isis->rmap[i].map = route_map_lookup_by_name (isis->rmap[i].name);
          if (old == NULL && isis->rmap[i].name == NULL)
            continue;
        
          isis_distribute_list_update (i);
        }
      else
	isis->rmap[i].map = NULL;
    }
  /* FIXME: do the address family sub-mode AF_INET6 here ? */
}

void
isis_route_map_event (route_map_event_t event, const char *name)
{
  int type;

  if (!isis)
    return;

  for (type = 0; type <= ZEBRA_ROUTE_MAX; type++)
    {
      if (isis->rmap[type].name && isis->rmap[type].map &&
	  !strcmp (isis->rmap[type].name, name))
	{
	  isis_distribute_list_update (type);
	}
    }
}

/* Activating Routemap. */
void
isis_routemap_set (int type, const char *mapname)
{
  if (isis->rmap[type].name)
    free (isis->rmap[type].name);
  
  isis->rmap[type].name = strdup (mapname);
  isis->rmap[type].map = route_map_lookup_by_name (mapname);
  
  return;
}

/* Deactivating Routemap. */
void
isis_routemap_unset (int type)
{
  if (isis->rmap[type].name)
    free (isis->rmap[type].name);
  
  isis->rmap[type].name = NULL;
  isis->rmap[type].name = NULL;
  
  return;
}

route_map_result_t
isis_routemap_rule_match_address_prefixlist (void *rule,
                                             struct prefix *prefix,
                                             route_map_object_t type,
                                             void *object)
{
  struct prefix_list *plist;  

  if (type != RMAP_ISIS)
    return RMAP_NOMATCH;
 
  plist = prefix_list_lookup (AFI_IP, (char *) rule);
  if (plist == NULL)
    return RMAP_NOMATCH;
  
  return (prefix_list_apply (plist, prefix) == PREFIX_DENY ?
          RMAP_NOMATCH : RMAP_MATCH);
}

void *
isis_routemap_rule_match_address_prefixlist_compile (const char *arg)
{
  return XSTRDUP (MTYPE_ROUTE_MAP_COMPILED, arg);
}

void
isis_routemap_rule_match_address_prefixlist_free (void *rule)
{
  XFREE (MTYPE_ROUTE_MAP_COMPILED, rule);
}

struct route_map_rule_cmd
isis_routemap_rule_match_address_prefixlist_cmd =
{
  "ip address prefix-list",
  isis_routemap_rule_match_address_prefixlist,
  isis_routemap_rule_match_address_prefixlist_compile,
  isis_routemap_rule_match_address_prefixlist_free,
};

DEFUN (isis_routemap_match_address_prefixlist,
       isis_routemap_match_address_prefixlist_cmd,
       "match ip address prefix-list WORD",
       "Match values\n"
       IP_STR
       "Match address of route\n"
       "Match entries of prefix-lists\n"
       "IPv4 prefix-list name\n")
{ 
  int ret = route_map_add_match ((struct route_map_index *) vty->index,
                                 "ip address prefix-list", argv[0]);
  return route_map_command_status (vty, ret);
} 

DEFUN (isis_routemap_no_match_address_prefixlist,
       isis_routemap_no_match_address_prefixlist_cmd,
       "no match ip address prefix-list WORD",
       NO_STR
       "Match values\n"
       IP_STR
       "Match address of route\n"
       "Match entries of prefix-lists\n"
       "IPv4 prefix-list name\n"
      )
{
  int ret = route_map_delete_match ((struct route_map_index *) vty->index,
                                    "ip address prefix-list", argv[0]);
  return route_map_command_status (vty, ret);
}

#ifdef HAVE_IPV6
route_map_result_t
isis_routemap_rule_match_ipv6_address_prefixlist (void *rule,
                                                  struct prefix *prefix,
                                                  route_map_object_t type,
                                                  void *object)
{
  struct prefix_list *plist;
  
  if (type != RMAP_ISIS)
    return RMAP_NOMATCH;

  plist = prefix_list_lookup (AFI_IP6, (char *) rule);
  if (plist == NULL)
    return RMAP_NOMATCH;
  
  return (prefix_list_apply (plist, prefix) == PREFIX_DENY ?
          RMAP_NOMATCH : RMAP_MATCH);
}

void *
isis_routemap_rule_match_ipv6_address_prefixlist_compile (const char *arg)
{
  return XSTRDUP (MTYPE_ROUTE_MAP_COMPILED, arg);
}

void
isis_routemap_rule_match_ipv6_address_prefixlist_free (void *rule)
{
  XFREE (MTYPE_ROUTE_MAP_COMPILED, rule);
}

struct route_map_rule_cmd
isis_routemap_rule_match_ipv6_address_prefixlist_cmd =
{
  "ipv6 address prefix-list",
  isis_routemap_rule_match_ipv6_address_prefixlist,
  isis_routemap_rule_match_ipv6_address_prefixlist_compile,
  isis_routemap_rule_match_ipv6_address_prefixlist_free,
};
#endif

/* match ip address IP_ACCESS_LIST */
/* Match function should return 1 if match succeeds else return zero. */
route_map_result_t
isis_route_match_ip_address (void *rule, struct prefix *prefix,
                        route_map_object_t type, void *object)
{
  struct access_list *alist;
  /* struct prefix_ipv4 match. */

  if (! type == RMAP_ISIS)
    return RMAP_NOMATCH;

  alist = access_list_lookup (AFI_IP, (char *) rule);
  if (alist == NULL)
    return RMAP_NOMATCH;

  return (access_list_apply (alist, prefix) == FILTER_DENY ?
          RMAP_NOMATCH : RMAP_MATCH);
}

/* Route-map `ip address' match statement. `arg' should be
   access-list name. */
void *
isis_route_match_ip_address_compile (const char *arg)
{
  return XSTRDUP (MTYPE_ROUTE_MAP_COMPILED, arg);
}

/* Free route map's compiled `ip address' value. */
void
isis_route_match_ip_address_free (void *rule)
{
  XFREE (MTYPE_ROUTE_MAP_COMPILED, rule);
}

/* Route map commands for ip address matching. */
struct route_map_rule_cmd 
isis_route_match_ip_address_cmd =
{
  "ip address",
  isis_route_match_ip_address,
  isis_route_match_ip_address_compile,
  isis_route_match_ip_address_free
};

DEFUN (isis_match_ip_address,
       isis_match_ip_address_cmd,
       "match ip address (<1-199>|<1300-2699>|WORD)",
       MATCH_STR
       IP_STR
       "Match address of route\n"
       "IP access-list number\n"
       "IP access-list number (expanded range)\n"
       "IP Access-list name\n")
{
  return isis_route_set_add (vty, vty->index, "ip address", argv[0]);
}

DEFUN (no_isis_match_ip_address,
       no_isis_match_ip_address_cmd,
       "no match ip address",
       NO_STR
       MATCH_STR
       IP_STR
       "Match address of route\n")
{
  if (argc == 0)
    return isis_route_set_delete (vty, vty->index, "ip address", NULL);
 
  return isis_route_set_delete (vty, vty->index, "ip address", argv[0]);
}

/* set tag TAG. Set tag to object */
route_map_result_t
isis_route_set_tag (void *rule, struct prefix *prefix,
               route_map_object_t type, void *object)
{
  u_short *tag;
  struct ipv4_reachability *ip4_reach;
  struct ipv6_reachability *ip6_reach;
  
  if (type == RMAP_ISIS)
    {
     /* Get routemap's rule information */
      tag = rule;
     
      switch (prefix->family)
      {
        case AF_INET:
          ip4_reach = object;
          ip4_reach->tag = tag;
          break;
        case AF_INET6:
          ip6_reach = object;
          ip6_reach->tag = tag;
          break;
        default:
          break;
      }
    }
  return RMAP_MATCH;
}

/* Route map tag compile function. */
void *
isis_route_set_tag_compile (const char *arg)
{
  u_short *tag;
   
  tag = XMALLOC (MTYPE_ROUTE_MAP_COMPILED, sizeof (u_short));
  *tag = atoi (arg);
  
  return tag;
}

/* Free route map's compiled value. */
void
isis_route_set_tag_free (void *rule)
{
  XFREE (MTYPE_ROUTE_MAP_COMPILED, rule);
}

/* Route map commands for set tag. */
struct route_map_rule_cmd 
isis_route_set_tag_cmd =
{
  "tag",
  isis_route_set_tag,
  isis_route_set_tag_compile,
  isis_route_set_tag_free
};

DEFUN (isis_set_tag,
       isis_set_tag_cmd,
       "set tag <0-65535>",
       SET_STR
       "Tag value for ISIS routing protocol\n"
       "Tag Value\n")
{
  return isis_route_set_add (vty, vty->index, "tag", argv[0]);
}

DEFUN (no_isis_set_tag,
       no_isis_set_tag_cmd,
       "no set tag",
       NO_STR
       SET_STR
       "Tag value for routing protocol\n")
{
  if (argc == 0)
    return isis_route_set_delete (vty, vty->index, "tag", NULL);

  return isis_route_set_delete (vty, vty->index, "tag", argv[0]);
}

int
route_map_command_status (struct vty *vty, int ret)
{
  if (! ret)
    return CMD_SUCCESS;
 
  switch (ret)
    {
      case RMAP_RULE_MISSING:
        vty_out (vty, "Can't find rule.%s", VNL);
        break;
      case RMAP_COMPILE_ERROR:
        vty_out (vty, "Argument is malformed.%s", VNL);
        break;
      default:
        vty_out (vty, "route-map add set failed.%s", VNL);
        break;
    }
  return CMD_WARNING; 
}

int
isis_route_set_add (struct vty *vty, struct route_map_index *index,
                    const char *command, const char *arg)
{
  int ret;
  
  ret = route_map_add_set (index, command, arg);
  if (ret)
    {
      switch (ret)
         {
           case RMAP_RULE_MISSING:
             vty_out (vty, "%% Can't find rule. %s", VTY_NEWLINE);
             return CMD_WARNING;
           case RMAP_COMPILE_ERROR:
             vty_out (vty, "%% Argument is malformed.%s", VTY_NEWLINE);
             return CMD_WARNING;
         }
    }
  return CMD_SUCCESS;
}

int
isis_route_set_delete (struct vty *vty, struct route_map_index *index,
                       const char *command, const char *arg)
{
  int ret;
  
  ret = route_map_delete_set (index, command, arg);
  if (ret)
    {
      switch (ret)
        {
          case RMAP_RULE_MISSING:
            vty_out (vty, "%% Can't find rule.%s", VTY_NEWLINE);
            return CMD_WARNING;
          case RMAP_COMPILE_ERROR:
            vty_out (vty, "%% Argument is malformed.%s", VTY_NEWLINE);
            return CMD_WARNING;
        }
    }
  return CMD_SUCCESS;
}

void
isis_route_map_init (void)
{
  route_map_init ();
  route_map_init_vty ();

  route_map_add_hook (isis_route_map_upd);
  route_map_delete_hook (isis_route_map_upd);
  route_map_event_hook (isis_route_map_event);

  route_map_install_match (&isis_routemap_rule_match_address_prefixlist_cmd);
  route_map_install_set (&isis_route_set_tag_cmd);
  route_map_install_set (&isis_route_match_ip_address_cmd);

  install_element (RMAP_NODE, &isis_match_ip_address_cmd);
  install_element (RMAP_NODE, &no_isis_match_ip_address_cmd);
  install_element (RMAP_NODE, &isis_routemap_match_address_prefixlist_cmd);
  install_element (RMAP_NODE, &isis_routemap_no_match_address_prefixlist_cmd);
  install_element (RMAP_NODE, &isis_set_tag_cmd);
  install_element (RMAP_NODE, &no_isis_set_tag_cmd);
 
#ifdef HAVE_IPV6
  route_map_install_match (&isis_routemap_rule_match_ipv6_address_prefixlist_cmd);
#endif
}


