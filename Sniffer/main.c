#include "promisc.h"
#include "log.h"
#include "tools.h"
#include "command.h"
#include "global.h"
#include<stdlib.h>
#define MAX 65536
int main()
{
    Start();
    do_promisc();
    int s=CreateSocket();
    char file[50];
    FILE* fp;
    if(OpenFile(file,50)<0)
    {
        printf("Log file create fail!\n");
        exit(0);
    }
    else
        fp=fopen(file,"w");
    if(fp==NULL)
    {
        printf("Can not open the log file!\n");
        exit(0);
    }
    printf("The socket is linked \n");
    printf("Enter to start the sniffer!\n");
    
    getchar();
    Packets pack;
    unsigned char buf[MAX];
    char outline[100];
    struct sockaddr addr;
    int size,data;
    LogDate time;
    int i=0;
    while(1)
    {
        i++;
        size = sizeof(addr);
        data = recvfrom(s,buf,sizeof(buf),0,&addr,(socklen_t*)&size);
        if(data<0)
        {
            printf("Can not get packets");
            exit(0);
        }
        else
            ReadPacket(fp,&pack,buf,data);
        if(i%37==0)
        {
            i=1;
            sprintf(outline,"[LIVE] TCP: %u  UDP: %u  ICMP: %u  IGMP: %u  Other: %u  All: %u",pack.tcp,pack.udp,pack.icmp,pack.igmp,pack.other,pack.all);
            GetDate(&time);
            INITCOLOR(RED_COLOR);
            printf("[%02d-%02d-%02d]",time.year,time.month,time.day);//print date
            INITCOLOR(GREEN_COLOR);
            printf("[%02d:%02d:%02d]",time.hour,time.minute,time.second);//print time
            INITCOLOR(ZERO_COLOR);
            printf("%s\n",outline);
        }
    }
    close(s);
    fclose(fp);
    return 0;
}
