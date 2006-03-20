/* this file is only used by extract.pl
 */

#ifdef VTYSH_EXTRACT_PL

#include <zebra.h>
#include "lib/command.h"

#define REDEFUN(args...) DEFUN(args)
  { return CMD_SUCCESS; }

REDEFUN (show_memory_fib,
       show_memory_fib_cmd,
       "show memory fib",
       SHOW_STR
       "Memory statistics\n"
       "FIB manager memory\n")

void
foobar(void) {
  install_element (VIEW_NODE, &show_memory_fib_cmd);
  install_element (ENABLE_NODE, &show_memory_fib_cmd);
}

#endif /* VTYSH_EXTRACT_PL */
