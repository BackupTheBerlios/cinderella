# $Id: Makefile,v 1.4 2003/09/22 16:32:11 ak1 Exp $
CC=cc
CFLAGS=-O2 -Wall -pipe -D_BSD_SOURCE
LDFLAGS=-lpcap -ldl
OBJS=cind.o process.o packet.o process_tcp.o process_udp.o process_icmp.o process_other.o dumper.o stream.o config.o
OUTPUT=cind

MYOS:=$(shell uname -s)

ifeq ($(MYOS),Darwin) # fink on Darwin is required
INCLUDEDIRS=-I/sw/include
LIBDIRS=-L/sw/lib
endif

all: $(OUTPUT)

$(OUTPUT): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) $(LIBDIRS) $(LDFLAGS) -o $(OUTPUT)

%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDEDIRS) -c $<

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
stream.o: stream.c stream.h
config.o: config.c config.h
