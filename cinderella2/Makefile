# $Id: Makefile,v 1.1.1.1 2003/09/15 20:03:19 ak1 Exp $
CC=cc
CFLAGS=-O2 -Wall -pipe
LDFLAGS=-lpcap
OBJS=cind.o process.o packet.o process_tcp.o process_udp.o process_icmp.o process_other.o dumper.o
OUTPUT=cind

all: $(OUTPUT)

$(OUTPUT): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) $(LDFLAGS) -o $(OUTPUT)

%.o: %.c
	$(CC) $(CFLAGS) -c $<

clean:
	$(RM) $(OBJS) $(OUTPUT) core *.core

# dependencies

process.o: process.c process.h packet.h process_tcp.h process_udp.h process_icmp.h process_other.h
cind.o: cind.c process.h
packet.o: packet.c packet.h
process_tcp.o: process_tcp.c process_tcp.h
process_udp.o: process_udp.c process_udp.h
process_icmp.o: process_icmp.c process_icmp.h
process_other.o: process_other.c process_other.h
dumper.o: dumper.c dumper.h packet.h
