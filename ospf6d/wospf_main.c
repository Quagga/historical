/*
** wospf_main.c
** 
** Made by (Kenneth Holter)
** Login   <kenneho@localhost.localdomain>
** 
** Started on  Tue May  9 10:08:04 2006 Kenneth Holter
** Last update Fri May 26 12:15:04 2006 Kenneth Holter
*/

#include <zebra.h>

#include "log.h"
#include "vty.h"

#include "ospf6_interface.h"

#include "wospf_neighbor_table.h"
#include "wospf_two_hop_neighbor.h"
#include "wospf_top.h"

#include "wospf_aor_selector.h"
#include "wospf_protocol.h"
#include "wospf_main.h"
#include "wospf_defs.h"
#include "wospf_lls.h"



void wospf_init() {

  char myname[64];
  gethostname(myname, 64);
  zlog_notice ("   ' My hostname is %s (WOSPF-OR router) '", myname  );
  
  wospf_init_neighbor_table();
  wospf_init_two_hop_table();

  wospf_cfg = wospf_malloc(sizeof(struct wospf_config), "WOSPF configuration");
  wospf_cfg->debug_level = 5; /* Testing */
  wospf_cfg->aor_coverage = 1;

  /* May be suppressed (use "int_to_ip" instead)*/
  id_buf = malloc(INET_ADDRSTRLEN);

  wospf_init_lls_data_block();

  state_changes = WOSPF_FALSE;

  wospf_init_aor_selector_set();

  added_neighbors = list_new();
}

void wospf_init_lls_data_block() {
  lls_message = wospf_malloc(sizeof(struct wospf_lls_message), "LLS data block");
  
  lls_message->scs_message = wospf_malloc(sizeof(struct scs_tlv_message), "SCS TLV");
  lls_message->scs_message->r_bit_set = WOSPF_FALSE;
  lls_message->scs_message->fs_bit_set = WOSPF_FALSE;
  lls_message->scs_message->n_bit_set = WOSPF_FALSE;
  lls_message->scs_message->type = 1;
  lls_message->scs_message->scs_number = 1; /* Initial SCS number */

  lls_message->neighbor_drop_message = wospf_malloc(sizeof(struct neighbor_drop_tlv_message), "Neighbor Drop TLV");
  lls_message->neighbor_drop_message->type = 2; 
  lls_message->neighbor_drop_message->dropped_neighbors = list_new(); 

  lls_message->req_fs_from_message = wospf_malloc(sizeof(struct req_tlv_message), "RF TLV");
  lls_message->req_fs_from_message->type = 3;
  lls_message->req_fs_from_message->req_fs_from_neighbors = list_new();

  lls_message->fs_for_message = wospf_malloc(sizeof(struct fs_tlv_message), "FS TLV");
  lls_message->fs_for_message->type = 4;
  lls_message->fs_for_message->fs_for_neighbors = list_new();

  lls_message->aor_message = wospf_malloc(sizeof(struct aor_tlv_message), "AOR TLV");
  lls_message->aor_message->type = 5;
  lls_message->aor_message->relays_added = 0;
  lls_message->aor_message->will_always = WOSPF_FALSE;
  lls_message->aor_message->will_never = WOSPF_FALSE;
  lls_message->aor_message->added_relays = list_new();
  lls_message->aor_message->dropped_relays = list_new();
  
  lls_message->will_message = wospf_malloc(sizeof(struct will_tlv_message), "Will TLV");
  lls_message->will_message->type = 6;
  lls_message->will_message->will = WILL_DEFAULT;
  lls_message->will_message->will_pers_count = WOSPF_WILL_PERS;

  }

