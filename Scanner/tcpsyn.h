#ifndef _TCPSYN_H_
#define _TCPSYN_H_
#define MAX_LAN_NUM 255

typedef struct{
	char name[40];
	char ip[40];
}Host;

Host host[MAX_LAN_NUM];
int hostsum=0;

void syn();

#endif
