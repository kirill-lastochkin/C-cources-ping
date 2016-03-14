#include "service.h"

int rid;


void SysWork(char *addr, int trc)
{
    int i=1,end=0,chk;
    u_char *src;                         //������ ������� �� �����
    char my_ip[16];                      //��� �������� ������ ������
    struct sniff_icmp *icmp,*icmprep;    //���������
    struct sniff_ip *ip,*iprep;
    struct sockaddr_in sr_addr;          //�����, �� ������� �������
    socklen_t len=sizeof(struct sockaddr_in);
    u_char buf[sizeof(struct sniff_icmp)+sizeof(struct sniff_ip)],
            recbuf[sizeof(struct sniff_icmp)+sizeof(struct sniff_ip)];
//----------------�������������� ���������-------------------
    atexit(EndSys);
    GetIp("eth0",my_ip);                   //�������� ���� �����

    //���������� �������� � ������
    ip=(struct sniff_ip*)buf;
    icmp=(struct sniff_icmp*)(buf+sizeof(struct sniff_ip));
    iprep=(struct sniff_ip*)recbuf;
    icmprep=(struct sniff_icmp*)(recbuf+sizeof(struct sniff_ip));

    //���������� ��������� ip
    ip->ihl=5;
    ip->ver=4;
    ip->tos=0;
    ip->len=sizeof(struct sniff_icmp)+sizeof(struct sniff_ip);
    ip->id=htons(7777);
    ip->frag_off=0;
    if(trc==1) ip->ttl=1;
    else ip->ttl=128;
    ip->protocol=IPPROTO_ICMP;
    ip->ip_dest=inet_addr(addr);
    ip->ip_source=inet_addr(my_ip);
    ip->cs=0;

    //���������� ��������� icmp
    icmp->type=8;
    icmp->code=0;
    icmp->un.echo.id=0;
    icmp->un.echo.sequence=0;
    icmp->cs=0;
    icmp->cs=CheckSum((unsigned short*)icmp,sizeof(struct sniff_icmp));

    ip->cs=CheckSum((unsigned short*)ip,sizeof(struct sniff_ip));

    //���������� ������
    sr_addr.sin_addr.s_addr=inet_addr(addr);
    sr_addr.sin_family=AF_INET;
    //��������� �����
    rid=socket(AF_INET,SOCK_RAW,IPPROTO_ICMP);
    if(rid<0)
    {
        ErrSys("socket create\n");
    }

    //�� ��������� ��������� �������������
    chk=setsockopt(rid,IPPROTO_IP,IP_HDRINCL,&i,sizeof(i));
    if(chk<0) ErrSys("setsockopt\n");
//------------------�������� ������-------------------
//trace
    if(trc==1)
    {
        puts("tracing...");
        do
        {
            //����������
            chk=sendto(rid,buf,sizeof(struct sniff_icmp)+sizeof(struct sniff_ip),0,
                   (struct sockaddr*)&sr_addr,len);
            if(chk<0) ErrSys("send\n");

            //���� ������
            chk=recvfrom(rid,recbuf,sizeof(struct sniff_icmp)+sizeof(struct sniff_ip),0,
                     (struct sockaddr*)&sr_addr,&len);
            if(chk<0) ErrSys("recv\n");
            else
            {
                src=(u_char*)&iprep->ip_source;
                printf("%d host: %d.%d.%d.%d, ttl: %d\n",i++,src[0],src[1],src[2],src[3],
                        iprep->ttl);
                //������ ���  ������������� ���������� �����
                ip->ttl++;
                ip->cs=0;
                ip->cs=CheckSum((unsigned short*)ip,sizeof(struct sniff_ip));
            }
        }
        //����������, ���� �� ������� ����� �� �������� ������
        while(ip->ip_dest!=iprep->ip_source);
    }
//ping
    else
    {
        while(end!=4)
        {
            //����������
            chk=sendto(rid,buf,sizeof(struct sniff_icmp)+sizeof(struct sniff_ip),0,
                   (struct sockaddr*)&sr_addr,len);
            if(chk<0) ErrSys("send\n");
            printf("ping sent\n");

            //���� ������
            chk=recvfrom(rid,recbuf,sizeof(struct sniff_icmp)+sizeof(struct sniff_ip),0,
                     (struct sockaddr*)&sr_addr,&len);
            if(chk<0) ErrSys("recv\n");
            else
            {
                src=(u_char*)&iprep->ip_source;
                printf("from %d.%d.%d.%d, ttl: %d\n",src[0],src[1],src[2],src[3],iprep->ttl);
                //printf("icmp type %x code %x\n",icmprep->type,icmp->code);
            }
            usleep(200000);
            end++;
        }
    }
}

//������� ���������� �����
//�� ����� ����� �����, � ������� �������� � ����� ������� ������,
//��� ������� ����� ������� ������
unsigned short CheckSum(unsigned short *ad, int l)
{

    int sum=0,len=l;
    unsigned short *addr;
    addr=ad;

    //���������� �� 2 �����
    while(len>1)
    {
        sum+= *addr++;
        len-=sizeof(unsigned short);
    }
    //���� ������ ����
    if(len==1)
    {
        sum+=*(u_char*)addr;
        puts("1 more byte\n");
    }
    //������������ ����������� �����
    sum=(sum >> 16) + (sum & 0xffff);
    sum+=(sum >> 16);
    return (unsigned short)(~sum);
}

void EndSys(void)
{
    close(rid);
}


