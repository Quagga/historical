/*
 * OSPFd main routine.
 *   Copyright (C) 1998, 99 Kunihiro Ishiguro, Toshiaki Takada
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

#include "version.h"
#include "getopt.h"
#include "thread.h"
#include "prefix.h"
#include "linklist.h"
#include "if.h"
#include "vector.h"
#include "vty.h"
#include "command.h"
#include "filter.h"
#include "plist.h"
#include "stream.h"
#include "log.h"
#include "memory.h"
#include "privs.h"
#include "debug.h"

#include "ospfd/ospfd.h"
#include "ospfd/ospf_interface.h"
#include "ospfd/ospf_asbr.h"
#include "ospfd/ospf_lsa.h"
#include "ospfd/ospf_lsdb.h"
#include "ospfd/ospf_neighbor.h"
#include "ospfd/ospf_dump.h"
#include "ospfd/ospf_zebra.h"
#include "ospfd/ospf_vty.h"

/* ospfd privileges */
zebra_capabilities_t _caps_p [] = 
{
  ZCAP_RAW,
  ZCAP_BIND,
  ZCAP_BROADCAST,
};

struct zebra_privs_t ospfd_privs =
{
#if defined(ZEBRA_USER) && defined(ZEBRA_GROUP)
  .user = ZEBRA_USER,
  .group = ZEBRA_GROUP,
#endif
#if defined(VTY_GROUP)
  .vty_group = VTY_GROUP,
#endif
  .caps_p = _caps_p,
  .cap_num_p = sizeof(_caps_p)/sizeof(_caps_p[0]),
  .cap_num_i = 0
};

/* Configuration filename and directory. */
char config_current[] = OSPF_DEFAULT_CONFIG;
char config_default[] = SYSCONFDIR OSPF_DEFAULT_CONFIG;

/* OSPFd options. */
struct option longopts[] = 
{
  { "daemon",      no_argument,       NULL, 'd'},
  { "config_file", required_argument, NULL, 'f'},
  { "pid_file",    required_argument, NULL, 'i'},
  { "log_mode",    no_argument,       NULL, 'l'},
  { "help",        no_argument,       NULL, 'h'},
  { "vty_addr",    required_argument, NULL, 'A'},
  { "vty_port",    required_argument, NULL, 'P'},
  { "user",        required_argument, NULL, 'u'},
  { "version",     no_argument,       NULL, 'v'},
  { 0 }
};

/* OSPFd program name */

/* Master of threads. */
struct thread_master *master;

/* Process ID saved for use by init system */
char *pid_file = PATH_OSPFD_PID;

/* Help information display. */
static void
usage (char *progname, int status)
{
  if (status != 0)
    fprintf (stderr, "Try `%s --help' for more information.\n", progname);
  else
    {    
      printf ("Usage : %s [OPTION...]\n\
Daemon which manages OSPF.\n\n\
-d, --daemon       Runs in daemon mode\n\
-f, --config_file  Set configuration file name\n\
-i, --pid_file     Set process identifier file name\n\
-A, --vty_addr     Set vty's bind address\n\
-P, --vty_port     Set vty's port number\n\
-u, --user         User and group to run as\n\
-v, --version      Print program version\n\
-h, --help         Display this help and exit\n\
\n\
Report bugs to %s\n", progname, ZEBRA_BUG_ADDRESS);
    }
  exit (status);
}

/* SIGHUP handler. */
void 
sighup (int sig)
{
  zlog (NULL, LOG_INFO, "SIGHUP received");
}

/* SIGINT handler. */
void
sigint (int sig)
{
  zlog (NULL, LOG_INFO, "Terminating on signal");

  ospf_terminate ();

  exit (0);
}

/* SIGUSR1 handler. */
void
sigusr1 (int sig)
{
  zlog_rotate (NULL);
}

/* Signal wrapper. */
RETSIGTYPE *
signal_set (int signo, void (*func)(int))
{
  int ret;
  struct sigaction sig;
  struct sigaction osig;

  sig.sa_handler = func;
  sigemptyset (&sig.sa_mask);
  sig.sa_flags = 0;
#ifdef SA_RESTART
  sig.sa_flags |= SA_RESTART;
#endif /* SA_RESTART */

  ret = sigaction (signo, &sig, &osig);

  if (ret < 0) 
    return (SIG_ERR);
  else
    return (osig.sa_handler);
}

/* Initialization of signal handles. */
void
signal_init ()
{
  signal_set (SIGHUP, sighup);
  signal_set (SIGINT, sigint);
  signal_set (SIGTERM, sigint);
  signal_set (SIGPIPE, SIG_IGN);
#ifdef SIGTSTP
  signal_set (SIGTSTP, SIG_IGN);
#endif
#ifdef SIGTTIN
  signal_set (SIGTTIN, SIG_IGN);
#endif
#ifdef SIGTTOU
  signal_set (SIGTTOU, SIG_IGN);
#endif
  signal_set (SIGUSR1, sigusr1);
#ifdef HAVE_GLIBC_BACKTRACE
  signal_set (SIGBUS, debug_print_trace);
  signal_set (SIGSEGV, debug_print_trace);
  signal_set (SIGILL, debug_print_trace); 
#endif /* HAVE_GLIBC_BACKTRACE */
}

/* OSPFd main routine. */
int
main (int argc, char **argv)
{
  char *p;
  char *vty_addr = NULL;
  int vty_port = OSPF_VTY_PORT;
  int daemon_mode = 0;
  char *config_file = NULL;
  char *progname;
  struct thread thread;

  /* Set umask before anything for security */
  umask (0027);

  /* get program name */
  progname = ((p = strrchr (argv[0], '/')) ? ++p : argv[0]);

  /* Invoked by a priviledged user? -- endo. */
  if (geteuid () != 0)
    {
      errno = EPERM;
      perror (progname);
      exit (1);
    }

  zlog_default = openzlog (progname, ZLOG_NOLOG, ZLOG_OSPF,
			   LOG_CONS|LOG_NDELAY|LOG_PID, LOG_DAEMON);

  /* OSPF master init. */
  ospf_master_init ();

  while (1) 
    {
      int opt;

      opt = getopt_long (argc, argv, "dlf:hA:P:u:v", longopts, 0);
    
      if (opt == EOF)
	break;

      switch (opt) 
	{
	case 0:
	  break;
	case 'd':
	  daemon_mode = 1;
	  break;
	case 'f':
	  config_file = optarg;
	  break;
	case 'A':
	  vty_addr = optarg;
	  break;
        case 'i':
          pid_file = optarg;
          break;
	case 'P':
          /* Deal with atoi() returning 0 on failure, and ospfd not
             listening on ospfd port... */
          if (strcmp(optarg, "0") == 0) 
            {
              vty_port = 0;
              break;
            } 
          vty_port = atoi (optarg);
          vty_port = (vty_port ? vty_port : OSPF_VTY_PORT);
  	  break;
  case 'u':
    ospfd_privs.group = ospfd_privs.user = optarg;
    break;
	case 'v':
	  print_version (progname);
	  exit (0);
	  break;
	case 'h':
	  usage (progname, 0);
	  break;
	default:
	  usage (progname, 1);
	  break;
	}
    }

  /* Initializations. */
  master = om->master;

  /* Library inits. */
  zprivs_init (&ospfd_privs);
  signal_init ();
  cmd_init (1);
  debug_init ();
  vty_init ();
  memory_init ();

  access_list_init ();
  prefix_list_init ();

  /* OSPFd inits. */
  ospf_init ();
  ospf_if_init ();
  ospf_zebra_init ();

  /* OSPF vty inits. */
  ospf_vty_init ();
  ospf_vty_show_init ();

  ospf_route_map_init ();
#ifdef HAVE_SNMP
  ospf_snmp_init ();
#endif /* HAVE_SNMP */
#ifdef HAVE_OPAQUE_LSA
  ospf_opaque_init ();
#endif /* HAVE_OPAQUE_LSA */
  
  sort_node ();

  /* Get configuration file. */
  vty_read_config (config_file, config_current, config_default);

  /* Change to the daemon program. */
  if (daemon_mode)
    daemon (0, 0);

  /* Process id file create. */
  pid_output (pid_file);

  /* Create VTY socket */
  vty_serv_sock (vty_addr, vty_port, OSPF_VTYSH_PATH);

#ifdef DEBUG
  /* Print banner. */
  zlog (NULL, LOG_INFO, "OSPFd (%s) starts", ZEBRA_VERSION);
#endif

  /* Fetch next active thread. */
  while (thread_fetch (master, &thread))
    thread_call (&thread);

  /* Not reached. */
  exit (0);
}

