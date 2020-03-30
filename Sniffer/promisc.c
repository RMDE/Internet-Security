//to setting the net card to promisc
#include<stdio.h>
#include<linux/if_ether.h>
#include<net/if.h>
#include<sys/ioctl.h>
#include<string.h>
#include<sys/socket.h>
#include<unistd.h>
#include<arpa/inet.h>
#define CARD "ens33"

int do_promisc()
{
    int f,s;
    struct ifreq ifr;
    if((f=socket(PF_PACKET,SOCK_RAW,htons(ETH_P_ALL)))<0)
    {
        return -1;
    }
    strcpy(ifr.ifr_name,CARD);
    if((s=ioctl(f,SIOCGIFFLAGS,&ifr))<0)
    {
        close(f);
        return -1;
    }
    if(!(ifr.ifr_flags&IFF_RUNNING))
    {
        return -1;
    }
    printf("************the net card  link up************\n"); 
    ifr.ifr_flags|=IFF_PROMISC;
    if((s=ioctl(f,SIOCSIFFLAGS,&ifr))<0)
    {
        return -1;
    }
    printf("*****Setting interface:::%s:::to promisc*****\n\n",ifr.ifr_name);
    return 1;
}
