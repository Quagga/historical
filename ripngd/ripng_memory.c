/* this file is only used by extract.pl
 */

#ifdef VTYSH_EXTRACT_PL

#include <zebra.h>
#include "lib/command.h"

#define REDEFUN(args...) DEFUN(args)
  { return CMD_SUCCESS; }

REDEFUN (show_memory_ripng,
       show_memory_ripng_cmd,
       "show memory ripng",
       SHOW_STR
       "Memory statistics\n"
       "RIPng memory\n")

void
foobar(void) {
  install_element (VIEW_NODE, &show_memory_ripng_cmd);
  install_element (ENABLE_NODE, &show_memory_ripng_cmd);
}

#endif /* VTYSH_EXTRACT_PL */
