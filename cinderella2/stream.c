/* $Id: stream.c,v 1.2 2003/09/16 20:15:24 ak1 Exp $ */
#include <stdlib.h>
#include "stream.h"
#include <netinet/tcp.h>


static struct stream * first;

void stream_init(void) {
  first = NULL;
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
  s->last_packet_ts = p->pkthdr->ts.tv_sec;
  set_new_state(s,p);
  p->next = NULL;
  if (s->first_pkt==NULL) {
    s->first_pkt = s->last_pkt = p;
  } else {
    s->last_pkt->next = p;
    s->last_pkt = s->last_pkt->next;
  }
}
