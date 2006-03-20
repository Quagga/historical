#ifndef _ISIS_REDISTRIBUTE_H
#define _ISIS_REDISTRIBUTE_H

extern struct zclient *zclient;

/* IPV6 External control info bit. */
#define IPV6_CTRL_INFO_EXT_ROUTE        1 << 6;

void isis_route_map_set (int type, const char *mapname);
void isis_route_map_unset (int type);
void isis_route_map_update (const char *map);
void isis_redistribute_add (int type, char ifindex, struct prefix *prefix, u_int                            nexthop_num, u_int32_t metric);  
void isis_redistribute_remove (int type, char ifindex, struct prefix *prefix);
void node_delete (void *data);
void isis_redistribute_remove_list (int type);
int isis_str2route_type (int afi, const char *str); 
int isis_redistribute_set (afi_t afi, int type);
int isis_redistribute_unset (afi_t afi, int type);

#endif
