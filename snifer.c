#include <pcap.h>
#include <stdio.h>

void callback(u_char *args, const struct pcap_pkthdr *head, const u_char* packet)
{
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