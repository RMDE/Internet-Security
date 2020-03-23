//function: using connect function of socket to scanner
#include<stdio.h>
//#include<sys/types.h>
//#include<sys/socket.h>
#include<winsock2.h>
#include<string.h>

void Int2str(int m,char str[]){
	if(m<10)
	{
		str[0] = '0'+m;
		str[1] = '\0';
	}
	else if(m<100)
	{
		str[0] = '0'+m/10;
		str[1] = '0'+m%10;
		str[2] = '\0';
	}
	else
	{
		str[0] = '0'+m/100;
		str[1] = '0'+(m/10)%10;
		str[2] = '0'+m%10;
		str[3] = '\0';
	}
}

void connection(char* ip){
	int sf = socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
	FILE* fp;
	fp=fopen("connection.txt","w");
	if(sf < 0)
	{
		printf("There is error in socket building.\n");
		exit(0);
	}
	struct sockaddr_in address;
	memset(&address,0,sizeof(address));
	address.sin_family = AF_INET;
	char tail[5];
	for(int i=0;i<255;i++)
	{
		Int2str(i,tail);
		strcat(ip,tail);
		fprintf(fp,"%s:\n",ip);
		for(int j=1;j<1024;j++)
		{
			address.sin_port = htons(j);
			address.sin_addr.s_addr=inet_addr(ip);
			//bzero(&(address.sin_zero),8);
			if(connect(sf,(struct sockaddr*)&address,sizeof(address))>0)
			{
				fprintf(fp,"	%d\n",j);
			}
		}
	}
}
