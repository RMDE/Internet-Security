#include<string.h>
#include "global.h"
#include<time.h>
#include "log.h"
#include<stdlib.h>
#include<stdarg.h>
#include<limits.h>

#define MAX_LEN 50

void GetDate(LogDate* date)//get the current time
{
   time_t rawtime;
   struct tm *timeinfo;
   rawtime=time(NULL);
   timeinfo=localtime(&rawtime);
   date->year=timeinfo->tm_year+1900;
   date->month=timeinfo->tm_mon+1;
   date->day=timeinfo->tm_mday;
   date->hour=timeinfo->tm_hour;
   date->minute=timeinfo->tm_min;
   date->second=timeinfo->tm_sec;
} 

int OpenFile(char* name,int len)//creating the log file and open it
{
    LogDate* date;
    FILE* fp;
    date=(LogDate*)malloc(sizeof(LogDate));
    GetDate(date);
    snprintf(name,len,"%02d-%02d-%02d.log",date->year,date->month,date->day);
    fp=fopen(name,"w");
    if(fp==NULL)
        return -1;
    else 
    {
        fclose(fp);
        return 1;
    }
}

void Output(FILE* fp,char* data,...)//writing the  header information  into logfile
{
    char string[MAX_LEN*5];
    LogDate date;
    GetDate(&date);//getting the current time
    char str[MAX_LEN*5];
    va_list args;
    va_start(args,data);
    vsprintf(string,data,args);
    va_end(args);
    snprintf(str,sizeof(str),"%02d.%02d.%02d-%02d:%02d:%02d - %s",date.year,date.month,date.day,date.hour,date.minute,date.second,string);
    fprintf(fp,"%s\n",str);
}

void WriteData(FILE* fp,unsigned char* data,int size)//logging the data part
{
    int i,j;
    for(i=0;i<size;i++)
    {
        //at the end of every line,translate the data
        if(i&&i%16==0)
        {
            fprintf(fp,"        ");
            for(j=i-16;j<i;j++)
            {
                if(data[j]>=32&&data[j]<=128)
                    fprintf(fp,"%c",(unsigned char)data[j]);
                else
                    fprintf(fp,".");
            }
            fprintf(fp,"\n");
        }
        if(i%16==0)
            fprintf(fp,"    ");//the start of every line
        fprintf(fp," %02X",(unsigned int)data[i]);//data
        if(i==size-1&&i%16!=0)
        {
            for(j=0;j<15-i%16;j++)
                fprintf(fp,"   ");//fill the empty
            fprintf(fp,"        ");
            for(j=i-i%16;j<=i;j++)
            {
                if(data[j]>=32&&data[j]<=128)
                    fprintf(fp,"%c",(unsigned char)data[j]);
                else
                    fprintf(fp,".");
            }
            fprintf(fp,"\n");
        }
    }
    fprintf(fp,"\n");
}

void LogIP(FILE* fp,unsigned char* buf)//catch ip head and log it
{
    struct sockaddr_in sour,des;
    struct iphdr *iph=(struct iphdr*)buf;//transform to ip head
    memset(&sour,0,sizeof(sour));
    sour.sin_addr.s_addr=iph->saddr;
    memset(&des,0,sizeof(des));
    des.sin_addr.s_addr=iph->daddr;
    //log ip head
    Output(fp,"[IP] Getting IP Header");
    Output(fp,"     Version               : %u",(unsigned int)iph->version);
    Output(fp,"     Header Length         : %u DWORDS or %u BYTES",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
    Output(fp,"     Type of Service       : %u",(unsigned int)iph->tos);
    Output(fp,"     Total Length          : %u Bytes",ntohs(iph->tot_len));
    Output(fp,"     Identification        : %u",ntohs(iph->id));
    if(((iph->frag_off)&0x8000)>0)
        Output(fp,"     Fragment              : on");
    else
        Output(fp,"     Fragment              : off");
    if(((iph->frag_off)&0x4000)>0)
        Output(fp,"     More Fragment         : on");
    else
        Output(fp,"     More Fragment         : off");
    Output(fp,"     Fragment Offset       : %u",(unsigned int)(iph->frag_off)&0x3fff);
    Output(fp,"     TTL                   : %u",(unsigned int)iph->ttl);
    Output(fp,"     Protocol              : %u",(unsigned int)iph->protocol);
    Output(fp,"     Checksum              : %u",ntohs(iph->check));
    Output(fp,"     Source IP             : %s",inet_ntoa(sour.sin_addr));
    Output(fp,"     Destination IP        : %s",inet_ntoa(des.sin_addr));
}

void LogTCP(FILE* fp,unsigned char* buf,int size)//getting information of tcp header
{
    struct iphdr *iph=(struct iphdr*)buf;
    unsigned int ip_len=iph->ihl*4;
    struct tcphdr* tcph=(struct tcphdr*)(buf+ip_len);//get address of tcp header
    LogIP(fp,buf);//first log the IP header
    
    //Then log the TCP header
    Output(fp,"[TCP] Getting TCP Packet");
    Output(fp,"      Source Port          : %u",ntohs(tcph->source));
    Output(fp,"      Destination Port     : %u",ntohs(tcph->dest));
    Output(fp,"      Sequence Number      : %u",ntohl(tcph->seq));
    Output(fp,"      Acknowledge Number   : %u",ntohl(tcph->ack_seq));
    Output(fp,"      Header Length        : %u DWORDS or %u BYTES",(unsigned int)tcph->doff,(unsigned int)(tcph->dest)*4);
    char flags[MAX_LEN*2]="";
    if((unsigned int)tcph->urg>0)
        strcat(flags,"|URG| ");
    if((unsigned int)tcph->ack>0)
        strcat(flags,"|ACK| ");
    if((unsigned int)tcph->psh>0)
        strcat(flags,"|PSH| ");
    if((unsigned int)tcph->rst>0)
        strcat(flags,"|RST| ");
    if((unsigned int)tcph->syn>0)
        strcat(flags,"|SYN| ");
    if((unsigned int)tcph->fin>0)
        strcat(flags,"|FIN| ");
    if(strlen(flags)>0)
        Output(fp,"      Flags                : %s",flags);
    else
        Output(fp,"      Flags                : None");
    Output(fp,"      Window               : %d",ntohs(tcph->window));
    Output(fp,"      Checksum             : %u",ntohs(tcph->check));
    Output(fp,"      Urgent Pointer       : %u",tcph->urg_ptr);
    Output(fp,"\n[DATA]");
    WriteData(fp,buf+ip_len+tcph->doff*4,(size-iph->ihl*4-tcph->doff));
    Output(fp,"\n");
}

void LogUDP(FILE* fp,unsigned char* buf,int size)//get the information of udp header
{
    //deal the ip header
    unsigned int ip_len;
    struct iphdr *iph=(struct iphdr*)buf;
    ip_len=iph->ihl*4;
    struct udphdr* udph=(struct udphdr*)(buf+ip_len);
    LogIP(fp,buf);

    //deal the udp header
    Output(fp,"[UDP] Getting UDP Packet");
    Output(fp,"      Source Port         : %u",ntohs(udph->source));
    Output(fp,"      Destination Port    : %u",ntohs(udph->dest));
    Output(fp,"      Length              : %u",ntohs(udph->len));
    Output(fp,"      Checksum            : %u",ntohs(udph->check));
    Output(fp,"\n[DATA]");
    WriteData(fp,buf+ip_len+sizeof(udph),(size-sizeof(udph)-ip_len));
    Output(fp,"\n");
}

void LogICMP(FILE* fp,unsigned char* buf,int size)//get the information of icmp header
{
    //deal the ip header
    unsigned int ip_len;
    struct iphdr *iph=(struct iphdr*)buf;
    ip_len=iph->ihl*4;
    struct icmphdr* icmph=(struct icmphdr*)(buf+ip_len);
    LogIP(fp,buf);
    
    //deal the icmp header
    Output(fp,"[ICMP] Getting ICMP Packet");
    Output(fp,"       Type                : %u",icmph->type);
    Output(fp,"       Code                : %u",icmph->code);
    Output(fp,"       Checksum            : %u",ntohs(icmph->checksum));
    Output(fp,"       Id                  : %u",ntohs(icmph->un.echo.id));
    Output(fp,"       Sequence            : %u",ntohs(icmph->un.echo.sequence));
    Output(fp,"       Gateway             : %u",ntohl(icmph->un.gateway));
    Output(fp,"\n[DATA]");
    WriteData(fp,buf+ip_len+sizeof(icmph),size-ip_len-sizeof(icmph));
}

void LogIGMP(FILE*fp,unsigned char* buf,int size)//get the information of igmp
{
    //deal the ip header
    unsigned int ip_len;
    struct iphdr *iph=(struct iphdr*)buf;
    ip_len=iph->ihl*4;
    struct igmp* igmp=(struct igmp*)(buf+ip_len);
    LogIP(fp,buf);

    //deal the igmp header
    Output(fp,"[IGMP] Getting IGMP Packet");
    Output(fp,"       Type                : %u",igmp->igmp_type);
    Output(fp,"       Code                : %u",igmp->igmp_code);
    Output(fp,"       Checksum            : %u",ntohs(igmp->igmp_cksum));
    struct sockaddr_in des;
    memset(&des,0,sizeof(des));
    des.sin_addr.s_addr=igmp->igmp_group.s_addr;
    Output(fp,"       IGMP Group          : %s",inet_ntoa(des.sin_addr));
    Output(fp,"\n[DATA]");
    WriteData(fp,buf+ip_len+sizeof(igmp),size-ip_len-sizeof(igmp));
}

