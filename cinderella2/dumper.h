#ifndef DUMPER_H
#define DUMPER_H

#include <pcap.h>

#include "packet.h"

void init_dumper(pcap_t * p);
void dump_bad_packet(struct packet * pkt);
void dump_good_packet(struct packet * pkt);
void end_dumper(void);

#endif
