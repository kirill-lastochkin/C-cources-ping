#include "service.h"

int GetIp(char* interface,char *hostaddr)
{
    char name[NI_MAXHOST];
    struct ifaddrs *ad,*ifa;
    int s;
    //получение инфомации из системы
    if(getifaddrs(&ad)==-1)
    {
        perror("getifaddr\n");
        return -1;
    }
    //перебираем полученные стуктуры
    for(ifa=ad;ifa!=NULL;ifa=ifa->ifa_next)
    {
        if (ifa->ifa_addr == NULL)
            continue;
        //если нашли нужную
        if(ifa->ifa_addr->sa_family==AF_INET&&strcmp(ifa->ifa_name,interface)==0)
        {
            //вытаскиваем адрес
            s=getnameinfo(ifa->ifa_addr,sizeof(struct sockaddr_in),name,NI_MAXHOST,
                          NULL,0,NI_NUMERICHOST);
            if(s!=0)
            {
                perror("getname failed\n");
                return -1;
            }
            strncpy(hostaddr,name,15);
            return 0;
        }
    }
    return 0;
}

void UseInfo(void)
{
    puts("1.Start program with root priviledge!");
    puts("2.set args as follows:\npi <-t> or <-p> <ip to ping/trace>");
    puts("  use -t for tracing route and -p for pinging");
}

void ErrSys(char *err)
{
    perror(err);
    exit(EXIT_FAILURE);
}
