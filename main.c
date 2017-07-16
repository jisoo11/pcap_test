#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

#define pcaphdr 0xa1b2c3d4		// pcap header magic number
#define ETHER_ADDR_LEN 6
#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* dont fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
#define SIZE_ETHERNET 14

#define SWAP(s) (((((s) & 0xff) << 8) | (((s) >> 8) & 0xff)))

void packet_info(unsigned char *, const struct pcap_pkthdr *, const unsigned char *);

//struct pcap_pkthdr {
//
//	struct timeval ts; 	/* time stamp? */
//	bpf_u_int32 caplen; 	/* length of portion present */
//	bpf_u_int32 len; 	/* length this packet (off wire) */
//
//};

struct eth_header {

	unsigned char eth_dhost[ETHER_ADDR_LEN]; /* Destination host address */
	unsigned char eth_shost[ETHER_ADDR_LEN]; /* Source host address */
	unsigned short eth_type;		 /* IP? ARP? RARP? etc */
		
};

/* IP header */
struct ip_header {
	unsigned char ip_verhlen;	/* version << 4 | header length >> 2 */
	unsigned char ip_tos;		/* type of service */
	unsigned short ip_len;		/* total length */
	unsigned short ip_id;		/* identification */
	unsigned short ip_off;		/* fragment offset field */
	unsigned char ip_ttl;		/* time to live */
	unsigned char ip_protocol;	/* protocol */
	unsigned short ip_chsum;	/* checksum */

	struct in_addr ip_src,ip_dst; /* source and dest address */
};

#define IP_HL(ip)		(((ip)->ip_verhlen) & 0x0f)
#define IP_V(ip)		(((ip)->ip_verhlen) >> 4)


/* TCP header */


struct tcp_header {
	unsigned short tcp_srcport;	/* source port */
	unsigned short tcp_dstport;	/* destination port */
	unsigned int tcp_seq;		/* sequence number */
	unsigned int tcp_ack;		/* acknowledgement number */
	unsigned char tcp_offx2;	/* data offset, rsvd */
#define TH_OFF(th)	(((th)->tcp_offx2 & 0xf0) >> 4)
	unsigned char tcp_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	unsigned short tcp_widsiz;		/* window */
	unsigned short tcp_chsum;		/* checksum */
	unsigned short tcp_urgp;		/* urgent pointer */
};


int main() {

	char *dev;
	pcap_t *handle;
//	char *net;
//	char *mask;
	char filter_exp[] = "port 80";		/* filter port num is 80 */
	char errbuf[PCAP_ERRBUF_SIZE];

	bpf_u_int32 net;
	bpf_u_int32 mask;
	bpf_u_int32 snaplen;			/* Length of pkt */

	struct pcap_pkthdr h;
	struct bpf_program fp;

	int num_packets = 20;

	/* Define the device */
	dev = pcap_lookupdev(errbuf);
	if (dev == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
	}
	printf("Device: %s\n", dev);

	/* Find the properties for the device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Can't get netmask for device %s\n", dev);
		net = 0;
		mask = 0;
	}

	/* Open the session in promiscuous mode */
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if(handle == NULL){
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return (2);
	}
	printf("live\n");
								
	if(pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", dev);
		return (2);
	}
	printf("Device %s is ethernet\n", dev);

	/* Compile ans apply the filter */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
	       	fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return (2);
	}
	printf("Parsed filter %s\n", filter_exp);

	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return (2);
	}
	printf("Printed filter %s\n", filter_exp);

	/* Check actual packet using pcap header */

	/* Get packets */
	pcap_loop(handle, num_packets, packet_info, 0);
	/* Print its length */
	printf("Jacked a packet with length of [%d]\n", h.len);
	/* And close the session */
	pcap_close(handle);	

}
void packet_info(unsigned char *user, const struct pcap_pkthdr *h, const unsigned char *packet) {

	int i;
	int len = h->len;
	
	const struct eth_header *eth;
	const struct ip_header *ip;
	const struct tcp_header *tcp;
	const char *data;

	unsigned int SIZE_IP;
	unsigned int SIZE_TCP;

	eth = (struct eth_header*)(packet);

	/* print dst mac addr */
	printf("Destination Mac Address is ");
	for (i=0; i<6; i++) {
		printf("%02x ", eth->eth_dhost[i]);
	}
	printf("\n");

	/* print src mac addr */
	printf("Source Mac Address is ");
	for (i=0; i<6; i++) {
		printf("%02x ", eth->eth_shost[i]);
	}
	printf("\n");

	ip = (struct ip_header*)(packet + SIZE_ETHERNET);

	printf("Destination IP Address is %s\n", inet_ntoa(ip->ip_dst));
	printf("Source IP Address is %s\n", inet_ntoa(ip->ip_src));
	printf("IP protocol is %s\n", inet_ntoa(ip->ip_dst));
	
	SIZE_IP = IP_HL(ip) * 4;

	tcp = (struct tcp_header*)(packet + SIZE_ETHERNET+SIZE_IP);
	printf("Destination TCP port : %d\n", SWAP(tcp->tcp_dstport));
	printf("Source TCP port : %d\n", SWAP(tcp->tcp_srcport));


	SIZE_TCP = TH_OFF(tcp) * 4;

	data = (unsigned char*)(packet + SIZE_ETHERNET + SIZE_IP + SIZE_TCP);
	printf("Data : %s\n", data);
	printf("\n\n");
	
	return;

}
