/* OSPFv3 misc debug routines
 * Copyright (C) 2005 6WIND, <Vincent.Jardin@6wind.com>
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

#include <zebra.h>
#include "command.h"
#include "memory.h"
#include "thread.h"

DEFUN (show_debugging_ospf6,
       show_debugging_ospf6_cmd,
       "show debugging ospf6",
       SHOW_STR
       DEBUG_STR
       OSPF6_STR)
{
  vty_out (vty, "OSPF6 debugging status:%s", VTY_NEWLINE);

  if (is_memory_debug())
    vty_out (vty, "  OSPF6 memory debugging is on%s", VTY_NEWLINE);

  return CMD_SUCCESS;
}

DEFUN (debug_ospf6_memory,
       debug_ospf6_memory_cmd,
       "debug ospf6 memory",
       DEBUG_STR
       OSPF6_STR
       "OSPF6 memory usages\n")
{
  memory_debug(1);
  return CMD_SUCCESS;
}

DEFUN (no_debug_ospf6_memory,
       no_debug_ospf6_memory_cmd,
       "no debug ospf6 memory",
       NO_STR
       DEBUG_STR
       OSPF6_STR
       "OSPF6 memory usages\n")
{
  memory_debug(0);
  return CMD_SUCCESS;
}

int
config_write_ospf6_debug_memory (struct vty *vty)
{
  int write = 0;

  if (is_memory_debug()) {
      vty_out (vty, "debug ospf6 memory%s", VTY_NEWLINE);
      write++;
  }
  return write;
}

DEFUN(show_cpu_ospf6,
      show_cpu_ospf6_cmd,
      "show cpu ospf6 (|[RWTEX])",
      SHOW_STR
      "Thread CPU usage\n"
      OSPF6_STR
      "Display filter (Read, Write, Timer, Event, eXecute)\n")
{
  return thread_dumps(vty, argc, argv);
}

void
install_element_ospf6_debug_memory (void)
{
  install_element (ENABLE_NODE, &show_debugging_ospf6_cmd);
  install_element (ENABLE_NODE, &debug_ospf6_memory_cmd);
  install_element (ENABLE_NODE, &no_debug_ospf6_memory_cmd);

  install_element (CONFIG_NODE, &debug_ospf6_memory_cmd);
  install_element (CONFIG_NODE, &no_debug_ospf6_memory_cmd);

  install_element (ENABLE_NODE, &show_cpu_ospf6_cmd);
}
