/* this file is only used by extract.pl
 */

#ifdef VTYSH_EXTRACT_PL

#include <zebra.h>
#include "lib/command.h"

#define REDEFUN(args...) DEFUN(args)
  { return CMD_SUCCESS; }

REDEFUN (show_memory_rip,
       show_memory_rip_cmd,
       "show memory rip",
       SHOW_STR
       "Memory statistics\n"
       "RIP memory\n")

void
foobar(void) {
  install_element (VIEW_NODE, &show_memory_rip_cmd);
  install_element (ENABLE_NODE, &show_memory_rip_cmd);
}

#endif /* VTYSH_EXTRACT_PL */
