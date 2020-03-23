# Makefile for scanner
# Xi Ye
#

CC = gcc
CFLAGS = -Wall -g
OBJS = main.o connection.o

scanner:$(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o scanner


main.o:main.c connection.h
	$(CC) $(CFLAGS) -c main.c

connection.o:connection.c connection.h
	$(CC) $(CFLAGS) -c connection.c

clean:
	-rm scanner
	-rm $(OBJS)

all:scanner
