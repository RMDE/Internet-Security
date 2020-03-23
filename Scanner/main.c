#include<stdlib.h>
#include<time.h>
#include<stdio.h>
#include "connection.h"
#include "global.h"
int main()
{
	char ip[]="192.168.78.";
	clock_t start,finish;
	double duration;
	printf("*****************The first method: TCP-connect********************\n");
	start=clock();
	connection(ip);
	finish=clock();
	duration=(double)(finish-start)/CLOCKS_PER_SEC;
	printf("***************** End of function: %f seconds****************\n",duration);


	return 0;
}
