#ifndef _COMMAND_H_
#define _COMMAND_H_
#include<stdio.h>
typedef struct{
    unsigned int tcp;
    unsigned int udp;
    unsigned int icmp;
    unsigned int igmp;
    unsigned int other;
    unsigned int all;
}Packets;

int CreateSocket();
void ReadPacket(FILE*,Packets*,unsigned char*,int);
void Start();
void Clear();
void Parse();
void Exit();

#endif
