/*
 * Zebra debug related function
 * Copyright (C) 1999 Kunihiro Ishiguro
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
 * along with GNU Zebra; see the file COPYING.  If not, write to the 
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330, 
 * Boston, MA 02111-1307, USA.  
 */

#include <zebra.h>
#include "command.h"
#include "debug.h"
#include "memory.h"
#include "thread.h"

/* For debug statement. */
unsigned long zebra_debug_event;
unsigned long zebra_debug_packet;
unsigned long zebra_debug_kernel;

DEFUN (show_debugging_zebra,
       show_debugging_zebra_cmd,
       "show debugging fib",
       SHOW_STR
       "FIB configuration\n"
       "Debugging information\n")
{
  vty_out (vty, "FIB debugging status:%s", VTY_NEWLINE);

  if (IS_ZEBRA_DEBUG_EVENT)
    vty_out (vty, "  FIB event debugging is on%s", VTY_NEWLINE);

  if (IS_ZEBRA_DEBUG_PACKET)
    {
      if (IS_ZEBRA_DEBUG_SEND && IS_ZEBRA_DEBUG_RECV)
	{
	  vty_out (vty, "  FIB packet%s debugging is on%s",
		   IS_ZEBRA_DEBUG_DETAIL ? " detail" : "",
		   VTY_NEWLINE);
	}
      else
	{
	  if (IS_ZEBRA_DEBUG_SEND)
	    vty_out (vty, "  FIB packet send%s debugging is on%s",
		     IS_ZEBRA_DEBUG_DETAIL ? " detail" : "",
		     VTY_NEWLINE);
	  else
	    vty_out (vty, "  FIB packet receive%s debugging is on%s",
		     IS_ZEBRA_DEBUG_DETAIL ? " detail" : "",
		     VTY_NEWLINE);
	}
    }

  if (IS_ZEBRA_DEBUG_KERNEL)
    vty_out (vty, "  FIB kernel debugging is on%s", VTY_NEWLINE);

  /* Show memory debugging status */
  if (is_memory_debug())
    vty_out (vty, "  FIB memory debugging is on%s", VTY_NEWLINE);

  return CMD_SUCCESS;
}

DEFUN (debug_zebra_events,
       debug_zebra_events_cmd,
       "debug fib events",
       DEBUG_STR
       "FIB configuration\n"
       "Debug option set for fib events\n")
{
  zebra_debug_event = ZEBRA_DEBUG_EVENT;
  return CMD_WARNING;
}

DEFUN (debug_zebra_packet,
       debug_zebra_packet_cmd,
       "debug fib packet",
       DEBUG_STR
       "FIB configuration\n"
       "Debug option set for zebra packet\n")
{
  zebra_debug_packet = ZEBRA_DEBUG_PACKET;
  zebra_debug_packet |= ZEBRA_DEBUG_SEND;
  zebra_debug_packet |= ZEBRA_DEBUG_RECV;
  return CMD_SUCCESS;
}

DEFUN (debug_zebra_packet_direct,
       debug_zebra_packet_direct_cmd,
       "debug fib packet (recv|send)",
       DEBUG_STR
       "FIB configuration\n"
       "Debug option set for fib packet\n"
       "Debug option set for receive packet\n"
       "Debug option set for send packet\n")
{
  zebra_debug_packet = ZEBRA_DEBUG_PACKET;
  if (strncmp ("send", argv[0], strlen (argv[0])) == 0)
    zebra_debug_packet |= ZEBRA_DEBUG_SEND;
  if (strncmp ("recv", argv[0], strlen (argv[0])) == 0)
    zebra_debug_packet |= ZEBRA_DEBUG_RECV;
  zebra_debug_packet &= ~ZEBRA_DEBUG_DETAIL;
  return CMD_SUCCESS;
}

DEFUN (debug_zebra_packet_detail,
       debug_zebra_packet_detail_cmd,
       "debug fib packet (recv|send) detail",
       DEBUG_STR
       "FIB configuration\n"
       "Debug option set for fib packet\n"
       "Debug option set for receive packet\n"
       "Debug option set for send packet\n"
       "Debug option set detailed information\n")
{
  zebra_debug_packet = ZEBRA_DEBUG_PACKET;
  if (strncmp ("send", argv[0], strlen (argv[0])) == 0)
    zebra_debug_packet |= ZEBRA_DEBUG_SEND;
  if (strncmp ("recv", argv[0], strlen (argv[0])) == 0)
    zebra_debug_packet |= ZEBRA_DEBUG_RECV;
  zebra_debug_packet |= ZEBRA_DEBUG_DETAIL;
  return CMD_SUCCESS;
}

DEFUN (debug_zebra_kernel,
       debug_zebra_kernel_cmd,
       "debug fib kernel",
       DEBUG_STR
       "FIB configuration\n"
       "Debug option set for fib between kernel interface\n")
{
  zebra_debug_kernel = ZEBRA_DEBUG_KERNEL;
  return CMD_SUCCESS;
}

DEFUN (no_debug_zebra_events,
       no_debug_zebra_events_cmd,
       "no debug fib events",
       NO_STR
       DEBUG_STR
       "FIB configuration\n"
       "Debug option set for fib events\n")
{
  zebra_debug_event = 0;
  return CMD_SUCCESS;
}

DEFUN (no_debug_zebra_packet,
       no_debug_zebra_packet_cmd,
       "no debug fib packet",
       NO_STR
       DEBUG_STR
       "FIB configuration\n"
       "Debug option set for zebra packet\n")
{
  zebra_debug_packet = 0;
  return CMD_SUCCESS;
}

DEFUN (no_debug_zebra_packet_direct,
       no_debug_zebra_packet_direct_cmd,
       "no debug fib packet (recv|send)",
       NO_STR
       DEBUG_STR
       "FIB configuration\n"
       "Debug option set for fib packet\n"
       "Debug option set for receive packet\n"
       "Debug option set for send packet\n")
{
  if (strncmp ("send", argv[0], strlen (argv[0])) == 0)
    zebra_debug_packet &= ~ZEBRA_DEBUG_SEND;
  if (strncmp ("recv", argv[0], strlen (argv[0])) == 0)
    zebra_debug_packet &= ~ZEBRA_DEBUG_RECV;
  return CMD_SUCCESS;
}

DEFUN (no_debug_zebra_kernel,
       no_debug_zebra_kernel_cmd,
       "no debug fib kernel",
       NO_STR
       DEBUG_STR
       "FIB configuration\n"
       "Debug option set for fib between kernel interface\n")
{
  zebra_debug_kernel = 0;
  return CMD_SUCCESS;
}

DEFUN (debug_zebra_memory,
       debug_zebra_memory_cmd,
       "debug fib memory",
       DEBUG_STR
       "FIB configuration\n"
       "FIB memory usages\n")
{
  memory_debug(1);
  return CMD_SUCCESS;
}

DEFUN (no_debug_zebra_memory,
       no_debug_zebra_memory_cmd,
       "no debug fib memory",
       NO_STR
       DEBUG_STR
       "FIB configuration\n"
       "FIB memory usages\n")
{
  memory_debug(0);
  return CMD_SUCCESS;
}

/* Debug node. */
struct cmd_node debug_node =
{
  DEBUG_NODE,
  "",				/* Debug node has no interface. */
  1
};

int
config_write_debug (struct vty *vty)
{
  int write = 0;

  if (IS_ZEBRA_DEBUG_EVENT)
    {
      vty_out (vty, "debug fib events%s", VTY_NEWLINE);
      write++;
    }
  if (IS_ZEBRA_DEBUG_PACKET)
    {
      if (IS_ZEBRA_DEBUG_SEND && IS_ZEBRA_DEBUG_RECV)
	{
	  vty_out (vty, "debug fib packet%s%s",
		   IS_ZEBRA_DEBUG_DETAIL ? " detail" : "",
		   VTY_NEWLINE);
	  write++;
	}
      else
	{
	  if (IS_ZEBRA_DEBUG_SEND)
	    vty_out (vty, "debug fib packet send%s%s",
		     IS_ZEBRA_DEBUG_DETAIL ? " detail" : "",
		     VTY_NEWLINE);
	  else
	    vty_out (vty, "debug fib packet recv%s%s",
		     IS_ZEBRA_DEBUG_DETAIL ? " detail" : "",
		     VTY_NEWLINE);
	  write++;
	}
    }
  if (IS_ZEBRA_DEBUG_KERNEL)
    {
      vty_out (vty, "debug fib kernel%s", VTY_NEWLINE);
      write++;
    }

  if (is_memory_debug())
    {
      vty_out (vty, "debug fib memory%s", VTY_NEWLINE);
      write++;
    }

  return write;
}

DEFUN(show_cpu_fib,
      show_cpu_fib_cmd,
      "show cpu fib (|[RWTEX])",
      SHOW_STR
      "Thread CPU usage\n"
      "Forwarding Input Base manager\n"
      "Display filter (Read, Write, Timer, Event, eXecute)\n")
{
  return thread_dumps(vty, argc, argv);
}

void
zebra_debug_init ()
{
  zebra_debug_event = 0;
  zebra_debug_packet = 0;

  install_node (&debug_node, config_write_debug);

  install_element (VIEW_NODE, &show_debugging_zebra_cmd);

  install_element (ENABLE_NODE, &show_debugging_zebra_cmd);
  install_element (ENABLE_NODE, &debug_zebra_events_cmd);
  install_element (ENABLE_NODE, &debug_zebra_packet_cmd);
  install_element (ENABLE_NODE, &debug_zebra_packet_direct_cmd);
  install_element (ENABLE_NODE, &debug_zebra_packet_detail_cmd);
  install_element (ENABLE_NODE, &debug_zebra_kernel_cmd);
  install_element (ENABLE_NODE, &debug_zebra_memory_cmd);
  install_element (ENABLE_NODE, &no_debug_zebra_events_cmd);
  install_element (ENABLE_NODE, &no_debug_zebra_packet_cmd);
  install_element (ENABLE_NODE, &no_debug_zebra_kernel_cmd);
  install_element (ENABLE_NODE, &no_debug_zebra_memory_cmd);

  install_element (CONFIG_NODE, &debug_zebra_events_cmd);
  install_element (CONFIG_NODE, &debug_zebra_packet_cmd);
  install_element (CONFIG_NODE, &debug_zebra_packet_direct_cmd);
  install_element (CONFIG_NODE, &debug_zebra_packet_detail_cmd);
  install_element (CONFIG_NODE, &debug_zebra_kernel_cmd);
  install_element (CONFIG_NODE, &debug_zebra_memory_cmd);
  install_element (CONFIG_NODE, &no_debug_zebra_events_cmd);
  install_element (CONFIG_NODE, &no_debug_zebra_packet_cmd);
  install_element (CONFIG_NODE, &no_debug_zebra_kernel_cmd);
  install_element (CONFIG_NODE, &no_debug_zebra_memory_cmd);

  install_element (ENABLE_NODE, &show_cpu_fib_cmd);
}
