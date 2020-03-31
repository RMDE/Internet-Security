#include "promisc.h"
#include "log.h"
#include "command.h"
#include "global.h"
#include<stdlib.h>
#define MAX 65536
int main()
{
    Start();
    do_promisc();
    int s=CreateSocket();
    FILE* fp=NULL;
    if(OpenFile(fp)<0)
    {
        printf("Log file create fail!\n");
        exit(0);
    }
    printf("The socket is linked \n");
    printf("Enter to start the sniffer!\n");
    printf("And if you want to parse ,input \"p\"\n");
    printf("If you want to stop,input \"q\"\n");
    
    getchar();
    Packets pack;
    unsigned char buf[MAX];
    struct sockaddr addr;
    int size,data;
    
    while(1)
    {
        size = sizeof(addr);
        data = recvfrom(s,buf,sizeof(buf),0,&addr,(socklen_t*)&size);
        if(data<0)
        {
            printf("Can not get packets");
            exit(0);
        }
        else
            ReadPacket(fp,&pack,buf,data);
    }
    close(s);
    fclose(fp);
    return 0;
}
