#include <pcap.h>             
#include <stdio.h>                               
#include <netinet/in.h>                     
#include <net/ethernet.h>  
#include <netinet/ether.h>
#include <sys/socket.h>
#include <arpa/inet.h>



struct ip_header{
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned int ip_hl:4;		// длига заголовка
    unsigned int ip_v:4;		// версия
#endif
#if __BYTE_ORDER == __BIG_ENDIAN
    unsigned int ip_v:4;		// версия
    unsigned int ip_hl:4;		// длина заголовка
#endif
    u_int8_t ip_tos;			// тип обслуживания
    u_short ip_len;			// длина сегмента
    u_short ip_id;			// идентификатор
    u_short ip_off;			// смещение фрагмента
#define	IP_RF 0x8000			/* reserved fragment flag */
#define	IP_DF 0x4000			/* dont fragment flag */
#define	IP_MF 0x2000			/* more fragments flag */
#define	IP_OFFMASK 0x1fff		/* mask for fragmenting bits */
    u_int8_t ip_ttl;			//время жизни
    u_int8_t ip_p;			// транспорт
    u_short ip_sum;			// контрольная сумма
    struct in_addr ip_src, ip_dst;	// адрес отправителя, адрес получателя
};

struct tcp_header{
	u_int16_t th_sport;		// порт источника
    u_int16_t th_dport;		// порт приемника
    u_int32_t th_seq;		// номер в последовательности
    u_int32_t th_ack;		// номер подтверждения
#  if __BYTE_ORDER == __LITTLE_ENDIAN
    u_int8_t th_x2:4;		// смещение
    u_int8_t th_off:4;		// зарезервированно
#  endif
#  if __BYTE_ORDER == __BIG_ENDIAN
    u_int8_t th_off:4;		// данные смещения
    u_int8_t th_x2:4;		// зарезервированно
#  endif
    u_int8_t th_flags;
#  define TH_FIN	0x01
#  define TH_SYN	0x02
#  define TH_RST	0x04
#  define TH_PUSH	0x08
#  define TH_ACK	0x10
#  define TH_URG	0x20
    u_int16_t th_win;		// размер окна
    u_int16_t th_sum;		// контрольная сумма
    u_int16_t th_urp;		// указатель	
};

struct udphdr {
	u_short	uh_sport;		// номер порта отправителя
	u_short	uh_dport;		// номер порта получателя
	short	uh_ulen;		// длина
	u_short	uh_sum;			// контрольная сумма
};

	// функция обработки udp сообщения
	void udphdr (const struct pcap_pkthdr* head, const u_char* packet)
{
	struct udphdr *udp;

	udp=(struct udphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip_header));
	printf("UDP\tsport: %d", ntohs(udp->uh_sport));			//вывести номер порта отправителя
    printf("  dport: %d\n", ntohs(udp->uh_dport));			//вывести номер порта получателя
         
	printf("\tsum: %#x ulen: %d", udp->uh_sum, udp->uh_ulen);
};
	// функция обработки tcp сообщения
	void header_tcp (const struct pcap_pkthdr* head, const u_char* packet)
{
	struct tcp_header *tsp;

	tsp=(struct tcp_header *)(packet + sizeof(struct ether_header) + sizeof(struct ip_header));
	printf("TCP\tsport: %#x", tsp->th_sport);			//вывести порт источника
    printf("  dport: %#x\n", tsp->th_dport);			//вывести порт приемника
         
	printf("\tsum: %d win: %d urp: %d\n", tsp->th_win, tsp->th_sum,  
       tsp->th_urp);
}

	void handle_ip(u_char *args, const struct pcap_pkthdr* head, const u_char* packet) 
{
    struct ip_header *ip;
    ip=(struct ip_header *)(packet+sizeof(struct ether_header));
    printf("IP\tsource: %s", inet_ntoa(ip->ip_src));
    printf("  dest: %s\n", inet_ntoa(ip->ip_dst));
    printf("\ttos: %d len: %d id: %d ttl: %d sum: %#x\n" , ip->ip_tos, ip->ip_len, 
       ip->ip_id, ip->ip_ttl, ntohs(ip->ip_sum));
     if(ip->ip_p == 6) header_tcp(head, packet); 
     	else
     		if(ip->ip_p == IPPROTO_UDP) udphdr(head, packet);
     			else
     		printf("\n");
}

	// функция обработки структуры Ethernet
u_short handle_ethernet(u_char *args, const struct pcap_pkthdr* head, const u_char* packet)	 
{
    struct ether_header *eth;
    struct ether_addr source_mac;		// структура для адреса отправителя
 	struct ether_addr dest_mac;			// структура для адреса получателя
    eth=(struct ether_header *) packet;
    // записсать в структуру типа ether_addt поле ether_shost
    source_mac.ether_addr_octet[0] = eth->ether_shost[0];
    source_mac.ether_addr_octet[1] = eth->ether_shost[1];
    source_mac.ether_addr_octet[2] = eth->ether_shost[2];
    source_mac.ether_addr_octet[3] = eth->ether_shost[3];
    source_mac.ether_addr_octet[4] = eth->ether_shost[4];
    source_mac.ether_addr_octet[5] = eth->ether_shost[5];
    // записсать в структуру типа ether_addt поле ether_dhost	
    dest_mac.ether_addr_octet[0] = eth->ether_dhost[0];
    dest_mac.ether_addr_octet[1] = eth->ether_dhost[1];
    dest_mac.ether_addr_octet[2] = eth->ether_dhost[2];
    dest_mac.ether_addr_octet[3] = eth->ether_dhost[3];
    dest_mac.ether_addr_octet[4] = eth->ether_dhost[4];
    dest_mac.ether_addr_octet[5] = eth->ether_dhost[5];
    printf("ETH\tsource: %s", ether_ntoa(&source_mac));			//вывести адрес отправителя
    printf("  dest: %s\n", ether_ntoa(&dest_mac));		//вывести адрес получателя
         
    return ntohs(eth->ether_type);		//вернуть тип пакета
}

void callback(u_char *args, const struct pcap_pkthdr *head, const u_char* packet)
{
	u_short etype=handle_ethernet(args, head, packet);
	if(etype==ETHERTYPE_IP){ 
		handle_ip(args, head, packet);
	} 
		else 
			printf("\n");
	printf("\n");
	int einbin;	// первый бит
	int len = head->caplen;	// рамер пакета
	// печатаем содержимое пакета слева в 16ричком формате
	for (int ling=0; ling < len; ling+= 20){	
		for (int i=0; i<20;i++){	
			einbin = ling + i;
			printf("%#04x ", packet[einbin]);	
		}
		printf("\t");
	// печатаем содержимое пакета справа в ascii формате	
		for (int i=0; i<20;i++){	
			einbin = ling + i;
			if (einbin >= len)
			printf(" ");
				else if (packet[einbin] > 31 && packet[einbin] < 127)
 		          printf("%c", packet[einbin]);
            else
                  printf(".");	
		}
		printf("\n");
	}
	printf("*********************************************************************************************************************");
	printf("\n");
	printf("\n");
}
int main (int argc, char *argv[])
{
char *dev;
char errbuf[PCAP_ERRBUF_SIZE];
pcap_t* handle;
const u_char *packet;
bpf_u_int32 mask;
bpf_u_int32 net;

dev = pcap_lookupdev(errbuf);	//поиск устройств для прослушивания
pcap_lookupnet(dev, &net, &mask, errbuf);	// определяем класс сети и маску
handle = pcap_open_live(dev, BUFSIZ, 1, 0, errbuf);	// создаем сесию для прослушивания
pcap_loop(handle, -1, callback, NULL);	// перехватываем пакет
pcap_close(handle);	//закрываем сесию
	return 0;

}