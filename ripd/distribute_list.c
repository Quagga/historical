/* this file is only used by extract.pl
 */

#ifdef VTYSH_EXTRACT_PL

#include <zebra.h>
#include "lib/command.h"

#define REDEFUN(args...) DEFUN(args)
  { return CMD_SUCCESS; }

REDEFUN (distribute_list_all,
       rip_distribute_list_all_cmd,
       "distribute-list WORD (in|out)",
       "Filter networks in routing updates\n"
       "Access-list name\n"
       "Filter incoming routing updates\n"
       "Filter outgoing routing updates\n")

REDEFUN (no_distribute_list_all,
       no_rip_distribute_list_all_cmd,
       "no distribute-list WORD (in|out)",
       NO_STR
       "Filter networks in routing updates\n"
       "Access-list name\n"
       "Filter incoming routing updates\n"
       "Filter outgoing routing updates\n")

REDEFUN (distribute_list,
       rip_distribute_list_cmd,
       "distribute-list WORD (in|out) WORD",
       "Filter networks in routing updates\n"
       "Access-list name\n"
       "Filter incoming routing updates\n"
       "Filter outgoing routing updates\n"
       "Interface name\n")

REDEFUN (no_districute_list,
       no_rip_distribute_list_cmd,
       "no distribute-list WORD (in|out) WORD",
       NO_STR
       "Filter networks in routing updates\n"
       "Access-list name\n"
       "Filter incoming routing updates\n"
       "Filter outgoing routing updates\n"
       "Interface name\n")

REDEFUN (districute_list_prefix_all,
       rip_distribute_list_prefix_all_cmd,
       "distribute-list prefix WORD (in|out)",
       "Filter networks in routing updates\n"
       "Filter prefixes in routing updates\n"
       "Name of an IP prefix-list\n"
       "Filter incoming routing updates\n"
       "Filter outgoing routing updates\n")

REDEFUN (no_districute_list_prefix_all,
       no_rip_distribute_list_prefix_all_cmd,
       "no distribute-list prefix WORD (in|out)",
       NO_STR
       "Filter networks in routing updates\n"
       "Filter prefixes in routing updates\n"
       "Name of an IP prefix-list\n"
       "Filter incoming routing updates\n"
       "Filter outgoing routing updates\n")

REDEFUN (districute_list_prefix,
       rip_distribute_list_prefix_cmd,
       "distribute-list prefix WORD (in|out) WORD",
       "Filter networks in routing updates\n"
       "Filter prefixes in routing updates\n"
       "Name of an IP prefix-list\n"
       "Filter incoming routing updates\n"
       "Filter outgoing routing updates\n"
       "Interface name\n")

REDEFUN (no_districute_list_prefix,
       no_rip_distribute_list_prefix_cmd,
       "no distribute-list prefix WORD (in|out) WORD",
       NO_STR
       "Filter networks in routing updates\n"
       "Filter prefixes in routing updates\n"
       "Name of an IP prefix-list\n"
       "Filter incoming routing updates\n"
       "Filter outgoing routing updates\n"
       "Interface name\n")


void
foobar(void) {
  install_element (RIP_NODE, &rip_distribute_list_all_cmd);
  install_element (RIP_NODE, &no_rip_distribute_list_all_cmd);

  install_element (RIP_NODE, &rip_distribute_list_cmd);
  install_element (RIP_NODE, &no_rip_distribute_list_cmd);

  install_element (RIP_NODE, &rip_distribute_list_prefix_all_cmd);
  install_element (RIP_NODE, &no_rip_distribute_list_prefix_all_cmd);

  install_element (RIP_NODE, &rip_distribute_list_prefix_cmd);
  install_element (RIP_NODE, &no_rip_distribute_list_prefix_cmd);
}

#endif /* VTYSH_EXTRACT_PL */
