# Makefile for sniffer
# Xi Ye
#

CC = gcc
CFLAGS = -Wall -g
OBJS = main.o promisc.o

sniffer:$(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o sniffer 


main.o:main.c promisc.h
	$(CC) $(CFLAGS) -c main.c

promisc.o:promisc.c promisc.h 
	$(CC) $(CFLAGS) -c promisc.c 

clean:
	-rm sniffer
	-rm $(OBJS)

all:sniffer
