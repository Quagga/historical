/* isisd Quagga
 * Copyright (C) 2005 6WIND Mohit Thakur
 *                          vincent.jardin@6wind.com
 *
 * This file is provided under the GPL.
 */

/* Define the redistribute function and other related functions. */
#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <zebra.h>

#include "command.h"
#include "linklist.h"
#include "log.h"
#include "prefix.h"
#include "memory.h"
#include "command.h"
#include "vty.h"
#include "table.h"
#include "plist.h"
#include "thread.h"
#include "zclient.h"
#include "routemap.h"

#include "isisd/dict.h"
#include "isisd/isis_common.h"
#include "isisd/isis_constants.h"
#include "isisd/isis_circuit.h"
#include "isisd/isisd.h"
#include "isisd/isis_tlv.h"
#include "isisd/isis_route.h"
#include "isisd/isis_routemap.h"
#include "isisd/isis_lsp.h"
#include "isisd/isis_spf.h"
#include "isisd/isis_pdu.h"
#include "isisd/isis_misc.h"
#include "isisd/isis_redistribute.h"
#include "isisd/isis_zebra.h"
#include "isisd/isis_events.h"

extern struct isis *isis;
extern struct zclient *zclient ;
extern int isis_zebra_redistribute (afi_t afi, int type);
extern int isis_zebra_no_redistribute (afi_t afi, int type);


/* Redistribution Functions. */
void
isis_route_map_set (int type, const char *mapname)
{
  if (isis->rmap[type].name)
    free (isis->rmap[type].name);
  isis->rmap[type].name = strdup(mapname);
  isis->rmap[type].map = route_map_lookup_by_name (mapname);
  return;
}

void
isis_route_map_unset(int type)
{
  if (isis->rmap[type].name)
    free (isis->rmap[type].name);
  isis->rmap[type].name = NULL;
  isis->rmap[type].map = NULL;
  return;
}

void
isis_route_map_update (const char *map)
{
  isis_route_map_upd (map);
  return;
}

int
isis_redistribute_set (afi_t afi, int type)
{
  switch (afi)
    {
      case AFI_IP:
        if (zclient->sock < 0)
          return CMD_WARNING;
        isis_zebra_redistribute (AFI_IP, type);
        return CMD_SUCCESS;
      case AFI_IP6:
        if (zclient->sock < 0)
          return CMD_WARNING;
        isis_zebra_redistribute (AFI_IP6, type);
        return CMD_SUCCESS;
      default:
        zlog_debug ("Not an IPv4/6 route to redistribute.");
        return CMD_WARNING;
    }
}


int 
isis_redistribute_unset (afi_t afi, int type)
{
  switch (afi)
    {
      case AFI_IP:
        if (zclient->redist[type])
          return CMD_WARNING;
        isis_redistribute_remove_list (type);
        isis_zebra_no_redistribute (AFI_IP, type);
        return CMD_SUCCESS;
      case AFI_IP6:
        if (zclient->redist[type])
          return CMD_WARNING;
        isis_redistribute_remove_list (type);
        isis_zebra_no_redistribute (AFI_IP6, type);
        return CMD_SUCCESS;
      default:
        zlog_debug ("Not an IPv4/6 route to stop redistribution.");
        return CMD_WARNING;
    }
  return CMD_SUCCESS;
}

void 
isis_redistribute_add (int type, char ifindex, struct prefix *prefix, u_int nexthop_num, u_int32_t metric)
{
  int ret;
  struct listnode *node_area, *ex_node, *ex6_node;  
  struct isis_area *area;
  struct ipv4_reachability ip4_info, ip4_temp_info, *ipv4_reach = NULL, *ex_ip4_reach = NULL;
  struct ipv6_reachability ip6_info, ip6_temp_info, *ipv6_reach = NULL, *ex_ip6_reach = NULL;
  afi_t afi;  

  if (! isis_zebra_is_redistribute (type))
    return;

  afi = family2afi (prefix->family);

  /* System ID check! */
  if (isis->sysid_set == 0)
    return;
  
  /* Checking if we are getting what we requested. */
  if (! isis->redist[afi][type]) 
    return;

/* If route-map was specified but not found, do not advertise. */  
  if (isis->rmap[type].name)
    {
      if (isis->rmap[type].map == NULL)
        isis_route_map_upd (NULL);
      if (isis->rmap[type].map == NULL)
        { 
          zlog_warn ("route-map \"%s\" not found; suppress redistributing",
                     isis->rmap[type].name);
          return;
        }
    }

  switch (prefix->family)
    {
      case AF_INET:
        {
          memcpy (&ip4_info.prefix, &prefix->u.prefix4, sizeof (struct in_addr));
          masklen2ip (prefix->prefixlen, &ip4_info.mask);
          ip4_info.metrics.metric_default = (char) metric;
          ip4_info.metrics.metric_error = METRICS_UNSUPPORTED;
          ip4_info.metrics.metric_expense = METRICS_UNSUPPORTED;
          ip4_info.metrics.metric_delay = METRICS_UNSUPPORTED;
          ip4_info.tag = NULL;

          memcpy (&ip4_temp_info, &ip4_info, sizeof (struct ipv4_reachability));    
          /* Apply Route-map. */
          if (isis->rmap[type].map)
            {
              memset (&ip4_info, 0, sizeof (ip4_info));

              ret = route_map_apply (isis->rmap[type].map, prefix,
                                     RMAP_ISIS, &ip4_info);
              if (ret != RMAP_MATCH)
                {
                  if (DEBUG_REDISTRIBUTE)
                    {
                      zlog_debug ("Denied by route-map \"%s\"", isis->rmap[type].name);
                      return;
                    }
                 }
            }

          /* Check if the route already exists. */
          if (isis->ip4_ext_routes [type] != NULL)
            {
              for (ex_node = listhead (isis->ip4_ext_routes [type]); ex_node;
                   ex_node = listnextnode (ex_node))
                { 
                  ex_ip4_reach = listgetdata (ex_node);

                  if (memcmp (&ex_ip4_reach->prefix, &ip4_temp_info.prefix, sizeof (struct in_addr)) && memcmp (&ex_ip4_reach->mask, &ip4_temp_info.mask, sizeof (struct in_addr)))
                    {
                      /* Update the route information paramters. */
                      if (metric > MAX_EXTERNAL_METRIC)
                        ex_ip4_reach->metrics.metric_default = (char) (MAX_EXTERNAL_METRIC);
                      else
                        ex_ip4_reach->metrics.metric_default  = ip4_info.metrics.metric_default;
                       
                      ex_ip4_reach->metrics.metric_error = ip4_info.metrics.metric_error;
                      ex_ip4_reach->metrics.metric_expense = ip4_info.metrics.metric_expense;
                      ex_ip4_reach->metrics.metric_delay = ip4_info.metrics.metric_delay;
                      ex_ip4_reach->tag = ip4_info.tag;
                    }
                }
            }
                
          /* If the route is new, create/update binding in external ipv4/v6 reachability. */
          for (node_area = listhead (isis->area_list); node_area; 
               node_area=listnextnode (node_area))
            {
              area = listgetdata (node_area);
              if ((area->is_type == IS_LEVEL_2) || (area->is_type == IS_LEVEL_1_AND_2))
                {
                  if (! isis->ip4_ext_routes [type])
                    isis->ip4_ext_routes [type] = list_new ();
              
                  ipv4_reach = XMALLOC (MTYPE_ISIS_TLV,
                                        sizeof (struct ipv4_reachability));
                  memcpy (&ipv4_reach->prefix, &ip4_temp_info.prefix,
                          sizeof (struct in_addr));
                  memcpy (&ipv4_reach->mask, &ip4_temp_info.mask, 
                          sizeof (struct in_addr));
                  if (metric > MAX_EXTERNAL_METRIC)
                    ipv4_reach->metrics.metric_default = (char) (MAX_EXTERNAL_METRIC);
                  else
                    ipv4_reach->metrics.metric_default = ip4_info.metrics.metric_default;
             
                  ipv4_reach->metrics.metric_error = METRICS_UNSUPPORTED;
                  ipv4_reach->metrics.metric_expense = METRICS_UNSUPPORTED;
                  ipv4_reach->metrics.metric_delay = METRICS_UNSUPPORTED;
                  ipv4_reach->tag = ip4_info.tag;

                  listnode_add (isis->ip4_ext_routes [type], ipv4_reach);
                  /* Update the route information, send an LSP. */
                  if (area->lspdb[1] == NULL)
                    area->lspdb[1] = lsp_db_init ();

                  lsp_l2_generate (area);
                } 
            }
        }
        break;
      case AF_INET6:
        for (node_area = listhead (isis->area_list); node_area;
             node_area=listnextnode (node_area))
           {
             area = listgetdata (node_area);
             if ((area->is_type == IS_LEVEL_2) || (area->is_type == IS_LEVEL_1_AND_2))
               {
                 memcpy (&ip6_info.prefix, &prefix->u.prefix6, sizeof (struct in_addr));
                 ip6_info.prefix_len = prefix->prefixlen;
                 ip6_info.metric = metric;
                 ip6_info.control_info = IPV6_CTRL_INFO_EXT_ROUTE;
                 ip6_info.tag = NULL;
         
                 memcpy (&ip6_temp_info, &ip6_info, sizeof (struct ipv6_reachability)); 
                 /* Apply Route-map if present. */
                 if (isis->rmap[type].map)
                   {
                     memset (&ip6_info, 0, sizeof (ip6_info));

                     ret = route_map_apply (isis->rmap[type].map, prefix,
                                            RMAP_ISIS, &ip6_info);
                     if (ret != RMAP_MATCH)
                       {
                         if (DEBUG_REDISTRIBUTE)
                           {
                             zlog_debug ("Denied by route-map \"%s\"", isis->rmap[type].name);
                             return;
                           }
                       }
                   }
             
                 /* Check if the route already exists. */
                 if (isis->ip6_ext_routes [type] != NULL)
                   {
                     for (ex6_node = listhead (isis->ip6_ext_routes[type]); 
                          ex6_node; ex6_node = listnextnode (ex6_node))
                       {
                         ex_ip6_reach = listgetdata (ex6_node);
            
                         if ((memcmp (&ip6_temp_info.prefix, &ex_ip6_reach->prefix, sizeof (struct in6_addr)) == 0) && (ip6_temp_info.prefix_len == ex_ip6_reach->prefix_len))
                           {
                             /* Update the route information parameters. */
                             ex_ip6_reach->metric = ip6_info.metric;
                             ex_ip6_reach->tag = ip6_info.tag;
                           }
                       }
                     return;
                   }
                
                 /* Create/Update binding in external ipv6 reachability. */
                 if ((area->is_type == IS_LEVEL_2) || (area->is_type == IS_LEVEL_1_AND_2))
                   {
                     if (! isis->ip6_ext_routes [type])
                       isis->ip6_ext_routes[type] = list_new ();
                 
                     ipv6_reach = XMALLOC (MTYPE_ISIS_TLV, 
                                           sizeof (struct ipv6_reachability));
                     memcpy (&ipv6_reach->prefix, &ip6_temp_info.prefix,
                             sizeof (struct in6_addr));
                     ipv6_reach->prefix_len = ip6_temp_info.prefix_len;
                     ipv6_reach->metric = ip6_info.metric;
                     ipv6_reach->control_info = IPV6_CTRL_INFO_EXT_ROUTE;
                     ipv6_reach->tag = ip6_info.tag;
                     listnode_add (isis->ip6_ext_routes [type], ipv6_reach);
                     
                    /* Update the route information, send an LSP. */
                    if (area->lspdb[1] == NULL)
                      area->lspdb[1] = lsp_db_init ();

                    lsp_l2_generate (area);
                   }
               }
           }
        break;
      default:
        break;
    }

  return;    
}

/* Remove the route from the redistribute lists */
void
isis_redistribute_remove (int type, char ifindex, struct prefix *prefix)
{
  struct listnode *rode, *rode6, *node_area;
  struct ipv4_reachability *ex_route;
  struct ipv6_reachability *ex_route6;
  struct isis_area *area;
  char pbuf[32], p6buf[64];
 
  if (! isis_zebra_is_redistribute (type))
    return;

  /* Delete/Update binding in external IPv4/v6 reachability. */ 

  if (isis->sysid_set == 0)
    return;

  for (node_area = listhead (isis->area_list); node_area; 
       node_area=listnextnode (node_area))
    {
      area = listgetdata (node_area);
      
      if ((area->is_type == IS_LEVEL_2) || (area->is_type == IS_LEVEL_1_AND_2))
        {
          switch (prefix->family)
            {
              case AF_INET:
                if (! isis->ip4_ext_routes [type])
                return;
              
                for (rode = listhead (isis->ip4_ext_routes [type]); rode; 
                     rode=listnextnode (rode))
                  {
                    struct in_addr mask;
                    ex_route = listgetdata (rode);
                    masklen2ip (prefix->prefixlen, &mask);
                    if ((memcmp (&prefix->u.prefix, &ex_route->prefix, sizeof (struct in_addr)) == 0) && (memcmp (&mask, &ex_route->mask, sizeof (struct in_addr)) ==0))
                      { 
                        listnode_delete (isis->ip4_ext_routes [type], ex_route);  
                        XFREE (MTYPE_ISIS_TLV, ex_route);          
                      }
                    else 
                      {
                        prefix2str (prefix, pbuf, sizeof (pbuf));
                        zlog_debug ("Route %s not found to withdraw.", pbuf);
                        return;
                      }
                  }
                break;
              case AF_INET6:
                if (! isis->ip6_ext_routes[type])
                  return;
      
                for (rode6 = listhead (isis->ip6_ext_routes[type]); rode6;
                     rode6=listnextnode (rode6))
                  {
                    ex_route6 = listgetdata (rode6);
	            if ((memcmp (&prefix->u.prefix, &ex_route6->prefix, sizeof (struct in6_addr)) == 0) && (prefix->prefixlen == ex_route6->prefix_len))
                      {
                        listnode_delete (isis->ip6_ext_routes[type], ex_route6);
                        XFREE (MTYPE_ISIS_TLV, ex_route6);
                      }
                    else
                      {
                        prefix2str (prefix, p6buf, sizeof (p6buf));
                        zlog_debug ("Route %s not found to withdraw.", p6buf);
                        return;
                      }
                  }
                break;
              default:
                break;
            }
          /* Update the route information, send an LSP. */
          if (area->lspdb[1] == NULL)
            area->lspdb[1] = lsp_db_init ();

          lsp_l2_generate (area);
        }
    }

  return;
}

/* Node delete function. */
void 
node_delete (void *data)
{
  XFREE (MTYPE_ISIS_TLV, data);
  return;
}

/* Remove the complete redistributed list [type]. */
void
isis_redistribute_remove_list (int type)
{
  if (! isis->ip4_ext_routes [type])
    return;
  
  isis->ip4_ext_routes[type]->del = node_delete;
  list_delete_all_node (isis->ip4_ext_routes[type]);

#ifdef HAVE_IPV6
  if (! isis->ip6_ext_routes)
    return;

  isis->ip6_ext_routes[type]->del = node_delete;
  list_delete_all_node (isis->ip6_ext_routes[type]); 
#endif  

  return;
}

/* Function to convert user input route type string to route type. */
int
isis_str2route_type (int afi, const char *str)
{
  if (! str)
    return 0;
  
  if (afi == AFI_IP)
    {
      if (strncmp (str, "k", 1) == 0)
        return ZEBRA_ROUTE_KERNEL;
      if (strncmp (str, "c", 1) == 0)
        return ZEBRA_ROUTE_CONNECT;
      if (strncmp (str, "s", 1) == 0)
        return ZEBRA_ROUTE_STATIC;
      if (strncmp (str, "r", 1) == 0)
        return ZEBRA_ROUTE_RIP;
      if (strncmp (str, "o", 1) == 0)
        return ZEBRA_ROUTE_OSPF;
      if (strncmp (str, "b", 1) == 0)
        return ZEBRA_ROUTE_BGP;
    }
  if (afi == AFI_IP6) 
    {
      if (strncmp (str, "k", 1) == 0)
        return ZEBRA_ROUTE_KERNEL;
      else if (strncmp (str, "c", 1) == 0)
        return ZEBRA_ROUTE_CONNECT;
      else if (strncmp (str, "s", 1) == 0)
        return ZEBRA_ROUTE_STATIC;
      else if (strncmp (str, "r", 1) == 0)
        return ZEBRA_ROUTE_RIPNG;
      else if (strncmp (str, "o", 1) == 0)
        return ZEBRA_ROUTE_OSPF6;
      else if (strncmp (str, "b", 1) == 0)
        return ZEBRA_ROUTE_BGP;
    }
  return 0;
}

