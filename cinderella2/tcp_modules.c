#include "tcp_modules.h"


struct tcp_module * find_tcp_module(struct in_addr srcip, u_short srcport, struct in_addr dstip, u_short dstport) {
  return NULL;
}

void set_tcp_module(struct stream * s, struct tcp_module * m) {

}

int add_tcp_module(char * module, char * src_re, char * dst_re) {
  return 1;
}
