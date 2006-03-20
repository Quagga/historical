/* this file is only used by extract.pl
 */

#ifdef VTYSH_EXTRACT_PL

#include <zebra.h>
#include "lib/command.h"

#define REDEFUN(args...) DEFUN(args)
  { return CMD_SUCCESS; }

REDEFUN (show_memory_ospf6,
       show_memory_ospf6_cmd,
       "show memory ospf6",
       SHOW_STR
       "Memory statistics\n"
       "OSPF6 memory\n")

void
foobar(void) {
  install_element (VIEW_NODE, &show_memory_ospf6_cmd);
  install_element (ENABLE_NODE, &show_memory_ospf6_cmd);
}

#endif /* VTYSH_EXTRACT_PL */
