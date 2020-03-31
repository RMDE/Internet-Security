#ifndef _LOG_H_
#define _LOG_H_

#include<stdio.h>

typedef struct{
    int year;
    int month;
    int day;
    int hour;
    int minute;
    int second;
}LogDate;  

void GetDate(LogDate*);
int OpenFile(FILE*);
void LogUDP(FILE*,unsigned char*,int);
void LogICMP(FILE*,unsigned char*,int);
void LogTCP(FILE*,unsigned char*,int);
void LogIGMP(FILE*,unsigned char*,int);


#endif
