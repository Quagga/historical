

#ifndef _ISIS_ROUTEMAP_H
#define _ISIS_ROUTEMAP_H

#include "routemap.h"

struct vty;

void isis_route_map_upd (const char *name);
void isis_route_map_event (route_map_event_t event, const char *name);
void isis_routemap_set (int type, const char *mapname);
void isis_routemap_unset (int type);
int route_map_command_status (struct vty *vty, int ret);
int isis_route_set_add (struct vty *vty, struct route_map_index *index,
                        const char *command, const char *arg);
int isis_route_set_delete (struct vty *vty, struct route_map_index *index,
                           const char *command, const char *arg);
void isis_route_map_init (void);
#define VNL VTY_NEWLINE

#endif
