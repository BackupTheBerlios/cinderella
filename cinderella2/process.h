/* $Id: process.h,v 1.1 2003/09/15 20:03:19 ak1 Exp $ */
#ifndef PROCESS_H
#define PROCESS_H

void process_packet(u_char * user, const struct pcap_pkthdr * pkthdr, const u_char * pkt);

#endif
