#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>
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
#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)


void packet_info(unsigned char *user, const struct pcap_pkhdr *, const unsigned char *packet);

struct pcap_pkthdr {

	struct timeval ts; 	/* time stamp? */
	bpf_u_int32 caplen; 	/* length of portion present */
	bpf_u_int32 len; 	/* length this packet (off wire) */

};

struct eth_header {

	unsigned char eth_dhost[ETHER_ADDR_LEN]; /* Destination host address */
	unsigned char eth_shost[ETHER_ADDR_LEN]; /* Source host address */
	unsigned short eth_type;		 /* IP? ARP? RARP? etc */
		
}

/* IP header */
struct sniff_ip {
	unsigned char ip_vhl;		/* version << 4 | header length >> 2 */
	unsigned char ip_tos;		/* type of service */
	unsigned short ip_len;		/* total length */
	unsigned hort ip_id;		/* identification */
	unsigned short ip_off;		/* fragment offset field */
	unsigned char ip_ttl;		/* time to live */
	u_char ip_p;		/* protocol */
	u_short ip_sum;		/* checksum */

	struct in_addr ip_src,ip_dst; /* source and dest address */
};

int main() {

	char *dev;
//	char *net;
//	char *mask;
	char filter_exp[] = "port 80";		/* filter port num is 80 */

	buf_u_int32 net;
	bpf_u_int32 mask;
	bpf_u_int32 snaplen;			/* Length of pkt */

	struct pcap_pkhdr h;

	int num_packets 20;

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
	printf("%s\n",dev);
									
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
	h

	/* Get packets */
	pcap_loop(handle, num_packets, get_packets, NULL);
	/* Print its length */
	printf("Jacked a packet with length of [%d]\n", h.len);
	/* And close the session */
	pcap_close(handle);	


}
