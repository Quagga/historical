#ifdef SIM

#include "ospf6_sim_printing.h"
#include "netinet/in.h"
//#include "if.h"
#include "ospf6_neighbor.h"
#include "ospf6_top.h" //for pushback

void append_sim(char *buf, int buf_len, const char *fmt,...)
{
  char temp_buf[ETRACE_MAXSTR]="";
  va_list al;
  int length1, length2;

  va_start(al,fmt);
  vsnprintf(temp_buf, ETRACE_MAXSTR, fmt, al);
  length1 = strlen(buf);
  length2 = strlen(temp_buf);

  if (length1 + length2 >= buf_len)
  {
    //printf("Error sim.cc:  Out of space in buf - increase size of buf_len\n");
    return;
  }
  va_end(al);
  strcat(buf, temp_buf);
}


#ifdef OSPF6_MANET_MPR_FLOOD
void ospf6_print_relay_selector_list_sim(struct ospf6_interface *oi)
{
  struct listnode *n;
  struct ospf6_relay_selector *relay_sel;
  char buf[ETRACE_MAXSTR]="";

  append_sim(buf, ETRACE_MAXSTR, "Relay Sel List: ");
  for (n = listhead(oi->relay_sel_list); n; nextnode(n))
  {
    relay_sel = (struct ospf6_relay_selector *) getdata(n);
    append_sim(buf, ETRACE_MAXSTR, "%s:%f, ", ip2str(relay_sel->router_id),
         elapsed_time(relay_sel->expire_time));
  }
  TraceEvent_sim(2, buf);
}

void ospf6_print_relay_list_sim(struct ospf6_interface *oi)
{
  struct listnode *n;
  struct ospf6_relay *relay;
  char buf[ETRACE_MAXSTR]="";

  append_sim(buf, ETRACE_MAXSTR, "Relay List: ");
  for (n = listhead(oi->relay_list); n; nextnode(n))
  {
    relay = (struct ospf6_relay *) getdata(n);
    if (!relay->active)
      continue;
    append_sim(buf, ETRACE_MAXSTR, "%s,", ip2str(relay->router_id));
  }
  TraceEvent_sim(2, buf);
}
#endif // OSPF6_MANET_MPR_FLOOD

#ifdef OSPF6_MANET
void ospf6_print_pushback_list_sim(struct ospf6_lsa *lsa)
{
  struct listnode *n;
  struct ospf6_pushback_neighbor *opbn;
  char buf[ETRACE_MAXSTR] = "";

  if (!lsa->pushback_neighbor_list || lsa->pushback_neighbor_list->count < 1)
    return;

  append_sim(buf, ETRACE_MAXSTR, "Pushback list lsa %s: ", lsa->name);
  for (n = listhead(lsa->pushback_neighbor_list); n; nextnode(n))
  {
    opbn = (struct ospf6_pushback_neighbor *) getdata(n);
    append_sim(buf, ETRACE_MAXSTR, "%s, ", ip2str(opbn->router_id));
  }
  TraceEvent_sim(2, buf);
}
#endif //OSPF6_MANET

void ospf6_print_neighborhood_sim(struct ospf6_interface *oi)
{
  struct listnode *n, *n2;
  struct ospf6_neighbor *on;
  struct ospf6_2hop_neighbor *o62n;
  char buf[ETRACE_MAXSTR] = "";
  u_int32_t *id;

  append_sim(buf, ETRACE_MAXSTR, "Neighborhood: ");
  for (n = listhead (oi->neighbor_list); n; nextnode (n))
  {
    on = (struct ospf6_neighbor *) getdata (n);

#ifdef OSPF6_MANET_MPR_FLOOD
    if (on->two_hop_neighbor_list && oi->flooding == OSPF6_FLOOD_MPR_SDCDS)
    {
      if (on->state < OSPF6_NEIGHBOR_FULL)
        continue;
      append_sim(buf, ETRACE_MAXSTR, "neighbor:%s ", ip2str(on->router_id));
      append_sim(buf, ETRACE_MAXSTR, "{");
      for (n2 = listhead (on->two_hop_neighbor_list); n2; nextnode (n2))
      {
        o62n = (struct ospf6_2hop_neighbor *) getdata (n2);
        append_sim(buf, ETRACE_MAXSTR, "%s,", ip2str(o62n->router_id));
      }
      append_sim(buf, ETRACE_MAXSTR, "} ");
    }
#endif //OSPF6_MANET_MPR_FLOOD
#ifdef OSPF6_MANET_MDR_FLOOD
    if (on->rnl && oi->flooding == OSPF6_FLOOD_MDR_SICDS)
    {
      if (on->state <= OSPF6_NEIGHBOR_INIT)
        continue;
      append_sim(buf, ETRACE_MAXSTR, "neighbor:%s ", ip2str(on->router_id));
      append_sim(buf, ETRACE_MAXSTR, "rnl{");
      if (on->rnl) 
      {
        for (n2 = listhead(on->rnl); n2; nextnode(n2))
        {
          id = (u_int32_t *) getdata(n2);
          append_sim(buf, ETRACE_MAXSTR, "%s,", ip2str(*id));
        }
      }
      append_sim(buf, ETRACE_MAXSTR, "} ");
    }
#endif //OSPF6_MANET_MDR_FLOOD
  }
  TraceEvent_sim(2, buf);
}

#endif //SIM
