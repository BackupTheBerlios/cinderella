#include <pcap.h>
#include <stdlib.h>
#include <assert.h>
#include "dumper.h"

static pcap_dumper_t * good_dumper, * bad_dumper;

void init_dumper(pcap_t * p) {
  good_dumper = pcap_dump_open(p,"good");
  assert(good_dumper!=NULL);
  bad_dumper = pcap_dump_open(p,"bad");
  assert(bad_dumper!=NULL);
}

void dump_bad_packet(struct packet * pkt) {
  pcap_dump((u_char *)bad_dumper,pkt->pkthdr,pkt->packet); /* sometimes, libpcap is really sick */
}

void dump_good_packet(struct packet * pkt) {
  pcap_dump((u_char *)good_dumper,pkt->pkthdr,pkt->packet); /* see comment above */
}

void end_dumper(void) {
  pcap_dump_close(good_dumper);
  pcap_dump_close(bad_dumper);
}
