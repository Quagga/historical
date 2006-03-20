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
#include <string.h>

#include <lib/version.h>
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
#include "zclient.h"
#include "privs.h"
#include "sigevent.h"

#if defined(HAVE_SNMP) && defined(FORCE_SMUX)
#include <asn1.h>
#include "smux.h"
#endif

#include "ospfd/ospfd.h"
#include "ospfd/ospf_interface.h"
#include "ospfd/ospf_asbr.h"
#include "ospfd/ospf_lsa.h"
#include "ospfd/ospf_lsdb.h"
#include "ospfd/ospf_neighbor.h"
#include "ospfd/ospf_dump.h"
#include "ospfd/ospf_zebra.h"
#include "ospfd/ospf_vty.h"

/* OSPF file name */
static char ospf_vtysh_path[sizeof(OSPF_VTYSH_PATH) + 20] = OSPF_VTYSH_PATH;

/* ospfd privileges */
zebra_capabilities_t _caps_p [] = 
{
  ZCAP_RAW,
  ZCAP_BIND,
  ZCAP_BROADCAST,
  ZCAP_ADMIN,
};

struct zebra_privs_t ospfd_privs =
{
#if defined(QUAGGA_USER) && defined(QUAGGA_GROUP)
  .user = QUAGGA_USER,
  .group = QUAGGA_GROUP,
#endif
#if defined(VTY_GROUP)
  .vty_group = VTY_GROUP,
#endif
  .caps_p = _caps_p,
  .cap_num_p = sizeof(_caps_p)/sizeof(_caps_p[0]),
  .cap_num_i = 0
};

/* Configuration filename and directory. */
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
  { "vpn",         required_argument, NULL, 'V'},
  { "user",        required_argument, NULL, 'u'},
  { "group",       required_argument, NULL, 'g'},
  { "apiserver",   no_argument,       NULL, 'a'},
  { "version",     no_argument,       NULL, 'v'},
  { 0 }
};

/* OSPFd program name */

/* Master of threads. */
struct thread_master *master;

/* Process ID saved for use by init system */
const char *pid_file = PATH_OSPFD_PID;

#ifdef SUPPORT_OSPF_API
extern int ospf_apiserver_enable;
#endif /* SUPPORT_OSPF_API */

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
-u, --user         User to run as\n\
-g, --group        Group to run as\n\
-a. --apiserver    Enable OSPF apiserver\n\
-v, --version      Print program version\n\
-V, --vpn_id       Number of the routing table\n\
-h, --help         Display this help and exit\n\
\n\
Report bugs to %s\n", progname, ZEBRA_BUG_ADDRESS);
    }
  exit (status);
}

/* SIGHUP handler. */
void 
sighup (void)
{
  zlog (NULL, LOG_INFO, "SIGHUP received");
}

/* SIGINT handler. */
void
sigint (void)
{
  zlog_notice ("Terminating on signal");

  ospf_terminate ();

  exit (0);
}

/* SIGUSR1 handler. */
void
sigusr1 (void)
{
  zlog_rotate (NULL);
}

struct quagga_signal_t ospf_signals[] =
{
  {
    .signal = SIGHUP,
    .handler = &sighup,
  },
  {
    .signal = SIGUSR1,
    .handler = &sigusr1,
  },  
  {
    .signal = SIGINT,
    .handler = &sigint,
  },
  {
    .signal = SIGTERM,
    .handler = &sigint,
  },
};

/* OSPFd main routine. */
int
main (int argc, char **argv)
{
  char *p;
  char fnt[] = ".";
  char *vpn_id_tmp = NULL;
  char *vty_addr = NULL;
  int vty_port = OSPF_VTY_PORT;
  int daemon_mode = 0;
  int temp = 0;
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

  zlog_default = openzlog ("OSPF", ZLOG_OSPF,
			   LOG_CONS|LOG_NDELAY|LOG_PID, LOG_DAEMON);

  /* OSPF master init. */
  ospf_master_init ();

#ifdef SUPPORT_OSPF_API
  /* OSPF apiserver is disabled by default. */
  ospf_apiserver_enable = 0;
#endif /* SUPPORT_OSPF_API */

  while (1) 
    {
      int opt;

      opt = getopt_long (argc, argv, "dlf:i:hA:P:u:g:V:av", longopts, 0);
    
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
	  ospfd_privs.user = optarg;
	  break;
	case 'g':
	  ospfd_privs.group = optarg;
	  break;
	case 'V':
	  temp = atoi (optarg);
	  vpn_id_tmp = optarg;
	  vpn_id_set (temp);
	  vpn_id_zset (temp);
	  vpn_path_zset (vpn_id_tmp);
          break;
#ifdef SUPPORT_OSPF_API
	case 'a':
	  ospf_apiserver_enable = 1;
	  break;
#endif /* SUPPORT_OSPF_API */
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

/* Set File name */
  if(temp)
  {
    strncat (ospf_vtysh_path, fnt, sizeof (ospf_vtysh_path));
    strncat (ospf_vtysh_path, vpn_id_tmp, sizeof (ospf_vtysh_path));
  }

  /* Initializations. */
  master = om->master;

  /* Library inits. */
  zprivs_init (&ospfd_privs);
  signal_init (master, Q_SIGC(ospf_signals), ospf_signals);
  cmd_init (1);
  debug_init ();
  vty_init (master);
  memory_init ();

  access_list_init ();
  prefix_list_init ();

  /* OSPFd inits. */
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
  vty_read_config (config_file, config_default);

  /* Change to the daemon program. */
  if (daemon_mode)
    daemon (0, 0);

  /* Process id file create. */
  pid_output (pid_file);

  /* Create VTY socket */
  vty_serv_sock (vty_addr, vty_port, ospf_vtysh_path);

  /* Print banner. */
  zlog_notice ("OSPFd %s starting: vty@%d", QUAGGA_VERSION, vty_port);

#if defined(HAVE_SNMP) && defined(FORCE_SMUX)
  /* smux peer .1.3.6.1.4.1.3317.1.2.5 */
  if (smux_peer_oid(NULL, ".1.3.6.1.4.1.3317.1.2.5", NULL) == 0)
    smux_start();
#endif /* HAVE_SNMP && FORCE_SMUX */

  /* Fetch next active thread. */
  while (thread_fetch (master, &thread))
    thread_call (&thread);

  /* Not reached. */
  exit (0);
}

