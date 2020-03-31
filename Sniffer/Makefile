# Makefile for sniffer
# Xi Ye
#

CC = gcc
CFLAGS = -Wall -g
OBJS = main.o promisc.o log.o command.o

sniffer:$(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o sniffer 

main.o:main.c promisc.h log.h command.h global.h tools.h
	$(CC) $(CFLAGS) -c main.c

command.o:command.c command.h log.h global.h tools.h
	$(CC) $(CFLAGS) -c command.c

log.o:log.c log.h global.h
	$(CC) $(CFLAGS) -c log.c

promisc.o:promisc.c promisc.h 
	$(CC) $(CFLAGS) -c promisc.c 

clean:
	-rm sniffer
	-rm $(OBJS)

all:sniffer
