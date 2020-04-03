# Makefile for scanner
# Xi Ye
#

CC = gcc
CFLAGS = -Wall -g
OBJS = main.o connection.o syn.o

scanner:$(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o scanner -pthread


main.o:main.c connection.h global.h tcpsyn.h
	$(CC) $(CFLAGS) -c main.c

connection.o:connection.c connection.h
	$(CC) $(CFLAGS) -c connection.c -pthread
syn.o:syn.c syn.h  tcpsyn.h
	$(CC) $(CFLAGS) -c syn.c -pthread

clean:
	-rm scanner
	-rm $(OBJS)

all:scanner
