#include "command.h"
#include "log.h"
#include "global.h"
#include<stdlib.h>
#include<string.h>
#include<signal.h>
#include<fcntl.h>
#include<error.h>
#include "tools.h"

int CreateSocket()//create and return raw socket
{
    int sock;
    sock = socket(AF_INET,SOCK_RAW,IPPROTO_TCP);
    if(sock<0)
    {
        printf("Can not create new socket!\n");
        exit(1);
    }
    return sock;
}

void ReadPacket(FILE*fp,Packets* packet,unsigned char* buf,int size)
{
    struct iphdr* iph=(struct iphdr*)buf;
    char* outline;
    printf("protol:%d\n",iph->protocol);
    //switch the protocol of packet
    switch(iph->protocol)
    {
        case 1:
            ++packet->icmp;
            LogICMP(fp,buf,size);
            break;
        case 2:
            ++packet->igmp;
            LogIGMP(fp,buf,size);
            break;
        case 6:
            ++packet->tcp;
            LogTCP(fp,buf,size);
            break;
        case 17:
            ++packet->udp;
            LogUDP(fp,buf,size);
            break;
        default:
            ++packet->other;
            break;
    }
    ++packet->all;
    //print
    outline=(char*)malloc(sizeof(char)*100);
    sprintf(outline,"[LIVE] TCP: %u  UDP: %u  ICMP: %u  IGMP: %u  Other: %u  All: %u",packet->tcp,packet->udp,packet->icmp,packet->igmp,packet->other,packet->all);
    INITCOLOR(RED_COLOR);
    printf("[%s]",__DATE__);//print date
    INITCOLOR(GREEN_COLOR);
    printf("[%s]",__TIME__);//print time
    INITCOLOR(ZERO_COLOR);
    printf("%s\n",outline);
}

void Clear()//clear the screen
{
    CLEARSCREEN();
}

void Start()
{
    Clear();
    printf("==============Welcome to the Sniffer!!=============\n");
}
void Parse()
{
    printf("[Tip] Enter to continue...\n");
    getchar();
}
void Exit()
{
    printf("===========Thank you for using the sniffer!!=======\n");
    exit(0);
}

