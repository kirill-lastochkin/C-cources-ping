
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

//структура описывающая ip заголовок
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

//структура описывающая icmp заголовок
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

//------------система-------------
void SysWork(char*,int mode); //mode: 0 - пинг, 1 - трассировка
void EndSys(void);
unsigned short CheckSum(unsigned short *addr, int len); //расчет контрольной суммы
//---------информативные------------
void ErrSys(char *err); //обаботка ошибки
int GetIp(char* interface,char *hostaddr); //для заданного интерфейса получить текущий ip адрес
void UseInfo(void); //информация по использованию
