#include "service.h"

extern char *optarg;

int main(int argc, char *argv[])
{
    int chk;
    if(getuid()!=0||argc!=3)
    {
        UseInfo();
        return -1;
    }
    while((chk=getopt(argc,argv,"t:p:"))!=-1)
    {
        switch(chk)
        {
        case 't': SysWork(optarg,1); break; //запуск в режиме тассровки
        case 'p': SysWork(optarg,0); break; //запуск в режиме пинга
        case '?': UseInfo();return -1;
        }
    }
    EndSys();

    return 0;
}


