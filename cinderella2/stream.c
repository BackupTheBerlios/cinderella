/* $Id: stream.c,v 1.3 2003/09/17 18:42:34 ak1 Exp $ */
#include <stdlib.h>
#include "stream.h"
#include "dumper.h"
#include <netinet/tcp.h>


static struct stream * first;

static time_t last_packet_ts;

void stream_init(void) {
  first = NULL;
  last_packet_ts = 0;
}

struct stream * find_stream(struct in_addr src_ip, u_short src_tcp, struct in_addr dst_ip, u_short dst_tcp) {
  struct stream * cur = first;
  for (;cur!=NULL;cur=cur->next) {

    if (cur->ip_src == src_ip.s_addr && cur->tcp_sport == src_tcp && cur->ip_dst == dst_ip.s_addr && cur->tcp_dport == dst_tcp) {
      return cur;
    }

    if (cur->ip_src == dst_ip.s_addr && cur->tcp_sport == dst_tcp && cur->ip_dst == src_ip.s_addr && cur->tcp_dport == src_tcp) {
      return cur;
    }

  }
  return NULL; /* shouldn't happen */
}

struct stream * create_stream(struct in_addr src_ip, u_short src_tcp, struct in_addr dst_ip, u_short dst_tcp) {
  struct stream * cur = malloc(sizeof(struct stream));
  if (!cur) {
    return cur;
  }

  cur->m = NULL;
  cur->ip_src = src_ip.s_addr;
  cur->ip_dst = dst_ip.s_addr;
  cur->tcp_sport = src_tcp;
  cur->tcp_dport = dst_tcp;

  cur->evaluated = 0;
  cur->bad = 0;

  cur->ts = 0;

  cur->first_pkt = cur->last_pkt = NULL;

  /* add element to beginning of list */
  cur->next = first;
  first = cur;

  return cur;
}

int stream_evaluated(struct stream * s) {
  return s->evaluated;
}

static void set_new_state(struct stream * s, struct packet * p) {
  /* this algorithm has been ported from snort to Ruby, and back to C */

  int direction = DIR_NONE;
  u_char flags;

  if (p->ip_header->ip_src.s_addr == s->ip_src && p->ip_header->ip_dst.s_addr == s->ip_dst) {
    direction = DIR_CLIENT;
  } else if (p->ip_header->ip_dst.s_addr == s->ip_src && p->ip_header->ip_src.s_addr == s->ip_dst) {
    direction = DIR_SERVER;
  } else {
    /* totally bogus packet */
  }

  if (p->tcp_header->th_flags == TH_FIN) {
    s->fin_sent = direction;
  }

  flags = p->tcp_header->th_flags;

  switch (direction) {
    case DIR_SERVER:
      
      switch (s->client_state) {
        case STATE_SYN_SENT: {
          if (flags == (TH_SYN|TH_ACK)) {
            s->client_state = STATE_ESTABLISHED;
          } else if (flags == TH_RST) {
            s->client_state = STATE_CLOSED;
            s->server_state = STATE_CLOSED;
          }
          return;
        }

        case STATE_ESTABLISHED: {
          if (flags == (TH_FIN|TH_ACK)) {
            s->client_state = STATE_CLOSE_WAIT;
            s->server_state = STATE_FIN_WAIT_1;
          } else if (flags == (TH_FIN|TH_ACK|TH_PUSH)) {
            s->client_state = STATE_CLOSE_WAIT;
            s->server_state = STATE_FIN_WAIT_1;
          } else if (flags == TH_FIN) {
            s->client_state = STATE_CLOSE_WAIT;
            s->server_state = STATE_FIN_WAIT_1;
          } else if (flags == TH_RST) {
            s->client_state = STATE_CLOSED;
            s->server_state = STATE_CLOSED;
          } else {
            /* acking client data */
          }
          return;
        }

        case STATE_FIN_WAIT_1: {
          if (flags == TH_RST) {
            s->server_state = STATE_CLOSED;
            s->client_state = STATE_CLOSED;
          } else if (flags == (TH_FIN|TH_ACK)) {
            s->server_state = STATE_LAST_ACK;
            s->client_state = STATE_FIN_WAIT_2;
          } else if (flags == TH_ACK) {
            s->server_state = STATE_CLOSE_WAIT;
            s->client_state = STATE_FIN_WAIT_2;
          }
          return;
        }

        case STATE_FIN_WAIT_2: {
          if (flags == (TH_FIN|TH_ACK)) {
            s->client_state = STATE_TIME_WAIT;
            s->server_state = STATE_LAST_ACK;
          } else if (flags == TH_FIN) {
            s->client_state = STATE_TIME_WAIT;
            s->server_state = STATE_LAST_ACK;
          }
          return;
        }

        case STATE_LAST_ACK: {
          if (flags == TH_ACK) {
            s->client_state = STATE_CLOSED;
          }
          return;
        }

        case STATE_CLOSE_WAIT: {
          if (flags == TH_RST) {
            s->server_state = STATE_CLOSED;
            s->client_state = STATE_CLOSED;
          } else if (flags == (TH_ACK|TH_PUSH|TH_FIN)) {
            s->server_state = STATE_FIN_WAIT_2;
            s->client_state = STATE_LAST_ACK;
          } else if (flags == TH_ACK) {
            s->server_state = STATE_FIN_WAIT_2;
          }
          return;
        }
      } /* switch client state */
    break; /* case DIR_SERVER */

  case DIR_CLIENT:
    
    switch (s->server_state) {
      case STATE_LISTEN: {
        if (flags&TH_SYN && !(flags&TH_RST)) {
          s->server_state = STATE_SYN_RCVD;
          s->client_state = STATE_SYN_SENT;
        }
        return;
      }
      case STATE_SYN_RCVD: {
        if (flags&TH_RST) {
          s->server_state = STATE_CLOSED;
          s->client_state = STATE_CLOSED;
        } else if (flags&TH_ACK) {
          s->server_state = STATE_ESTABLISHED;
        }
        return;
      }

      case STATE_ESTABLISHED: {
        if (flags == (TH_FIN|TH_ACK)) {
          s->client_state = STATE_FIN_WAIT_1;
          s->server_state = STATE_CLOSE_WAIT;
        } else if (flags == (TH_FIN|TH_ACK|TH_PUSH)) {
          s->client_state = STATE_CLOSE_WAIT;
          s->server_state = STATE_FIN_WAIT_1;
        } else if (flags&TH_RST) {
          s->server_state = STATE_CLOSED;
          s->client_state = STATE_CLOSED;
        }
        return;
      }

      case STATE_LAST_ACK: {
        if (flags&TH_ACK) {
          s->server_state = STATE_CLOSED;
        }
        return;
      }

      case STATE_FIN_WAIT_1: {
        if (flags == (TH_ACK|TH_FIN)) {
          s->client_state = STATE_LAST_ACK;
          s->server_state = STATE_FIN_WAIT_2;
        } else if (flags&TH_RST) {
          s->server_state = STATE_CLOSED;
          s->client_state = STATE_CLOSED;
        } else if (flags == TH_ACK) {
          s->server_state = STATE_FIN_WAIT_2;
          s->client_state = STATE_CLOSE_WAIT;
        }
        return;
      }

      case STATE_FIN_WAIT_2: {
        if (flags == (TH_FIN|TH_ACK)) {
          s->server_state = STATE_TIME_WAIT;
          s->client_state = STATE_LAST_ACK;
        } else if (flags == TH_FIN) {
          s->server_state = STATE_TIME_WAIT;
          s->client_state = STATE_LAST_ACK;
        }
        return;
      }

      case STATE_CLOSE_WAIT: {
        if (flags == TH_RST) {
          s->server_state = STATE_CLOSED;
          s->client_state = STATE_CLOSED;
        } else if (flags&TH_ACK) {
          s->client_state = STATE_FIN_WAIT_2;
        }
        return;
      }

    } /* switch server state */

  } /* switch direction */

}

void stream_add_packet(struct stream * s, struct packet * p) {
  last_packet_ts = s->last_packet_ts = p->pkthdr->ts.tv_sec;
  set_new_state(s,p);
  p->next = NULL;
  if (s->first_pkt==NULL) {
    s->first_pkt = s->last_pkt = p;
  } else {
    s->last_pkt->next = p;
    s->last_pkt = s->last_pkt->next;
  }
}

int stream_client_closed(struct stream * s) {
  return s->client_state == STATE_CLOSED;
}

int stream_server_closed(struct stream * s) {
  return s->server_state == STATE_CLOSED;
}

void stream_set_bad(struct stream * s) {
  s->evaluated = 1;
  s->bad = 1;
}

void stream_set_good(struct stream * s) {
  s->evaluated = 1;
  s->bad = 0;
}

static void * get_right_dumper(int bad) {
  if (bad) {
    return dump_bad_packet;
  }
  return dump_good_packet;
}

void stream_output_all(struct stream * s) {
  void (*dump_func)(struct packet *);
  struct packet * cur;

  dump_func = get_right_dumper(s->bad);

  for (cur = s->first_pkt; cur!=NULL; cur = cur->next) {
    dump_func(cur);
  }
}

void stream_try_evaluate(struct stream * s) {
  /* do something with the registered module */
}

void do_output_packet(struct stream * s, struct packet * p) {
  void (*dump_func)(struct packet *);

  dump_func = get_right_dumper(s->bad);

  dump_func(p);
}


void remove_old_streams(void) {
  struct stream * my_first = NULL, * my_last = NULL, * cur, * dump_em = NULL;
  for (cur = first; cur!=NULL;) {
    if (last_packet_ts - cur->last_packet_ts > 60) { /* XXX replace 60 by your stream timeout */
      struct stream * tmp = cur->next; /* save next pointer */
      cur->next = dump_em; /* add cur to the beginning of the dump_em list */
      dump_em = cur;
      cur = tmp; /* set cur to the saved next pointer */
    } else {
      if (my_first==NULL) { /* if the new list is empty, add first element */
        my_first = my_last = cur;
      } else {
        my_last->next = cur; /* add element to end of list */
        my_last = my_last->next; /* move last pointer to end of list */
        cur = cur->next; /* move cur pointer to next element */
        my_last->next = NULL; /* set next element after the last element to NULL (to mark end of list) */
      }
    }
  }
  /* sometimes, list handling is more or less magic, unless you have lots of comments */
  for (cur = dump_em; cur; cur = dump_em) {
    free_packet_list(cur->first_pkt);
    dump_em = cur->next;
    free(cur);
  }
  first = my_first;
}
