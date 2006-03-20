/* this file is only used by extract.pl
 */

#ifdef VTYSH_EXTRACT_PL

#include <zebra.h>
#include "lib/command.h"

#define REDEFUN(args...) DEFUN(args)
  { return CMD_SUCCESS; }

REDEFUN (if_rmap,
       rip_if_rmap_cmd,
       "route-map RMAP_NAME (in|out) IFNAME",
       "Route map set\n"
       "Route map name\n"
       "Route map set for input filtering\n"
       "Route map set for output filtering\n"
       "Route map interface name\n")

REDEFUN (no_if_rmap,
       no_rip_if_rmap_cmd,
       "no route-map ROUTEMAP_NAME (in|out) IFNAME",
       NO_STR
       "Route map unset\n"
       "Route map name\n"
       "Route map for input filtering\n"
       "Route map for output filtering\n"
       "Route map interface name\n")

void
foobar(void) {
  install_element (RIP_NODE, &rip_if_rmap_cmd);
  install_element (RIP_NODE, &no_rip_if_rmap_cmd);
}

#endif /* VTYSH_EXTRACT_PL */
