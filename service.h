
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/time.h>

#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <ifaddrs.h>

//��������� ����������� ip ���������
struct sniff_ip {
    u_char	ihl:4,
            ver:4;
    u_char	tos;
    unsigned short	len;
    unsigned short	id;
    unsigned short	frag_off;
    u_char	ttl;
    u_char	protocol;
    unsigned short	cs;
    unsigned int	ip_source;
    unsigned int	ip_dest;
};

//��������� ����������� icmp ���������
struct sniff_icmp {
  u_char		type;
  u_char		code;
  unsigned short	cs;
  union {
    struct {
        unsigned short	id;
        unsigned short	sequence;
    } echo;
    unsigned int	gateway;
    struct {
        unsigned short	__unused;
        unsigned short	mtu;
    } frag;
  } un;
};

//------------�������-------------
void SysWork(char*,int mode); //mode: 0 - ����, 1 - �����������
void EndSys(void);
unsigned short CheckSum(unsigned short *addr, int len); //������ ����������� �����
//---------�������������------------
void ErrSys(char *err); //�������� ������
int GetIp(char* interface,char *hostaddr); //��� ��������� ���������� �������� ������� ip �����
void UseInfo(void); //���������� �� �������������
