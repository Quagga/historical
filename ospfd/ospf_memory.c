/* this file is only used by extract.pl
 */

#ifdef VTYSH_EXTRACT_PL

#include <zebra.h>
#include "lib/command.h"

#define REDEFUN(args...) DEFUN(args)
  { return CMD_SUCCESS; }

REDEFUN (show_memory_ospf,
       show_memory_ospf_cmd,
       "show memory ospf",
       SHOW_STR
       "Memory statistics\n"
       "OSPF memory\n")

void
foobar(void) {
  install_element (VIEW_NODE, &show_memory_ospf_cmd);
  install_element (ENABLE_NODE, &show_memory_ospf_cmd);
}

#endif /* VTYSH_EXTRACT_PL */
