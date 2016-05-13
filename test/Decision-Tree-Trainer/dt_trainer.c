#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "appIdSessionstore.c"

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};

/*UDP header */
struct sniff_udp {
	u_short	uh_sport;		/* source port */
	u_short	uh_dport;		/* destination port */
	u_short	uh_ulen;		/* datagram length */
	u_short	uh_sum;			/* datagram checksum */
};



//void
//got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void dump_packet(const unsigned char *packet, struct timeval ts,
			unsigned int capture_len);

void
print_payload(const u_char *payload, int len);

void
print_hex_ascii_line(const u_char *payload, int len, int offset);

void
print_app_banner(void);

void
print_app_usage(void);

void
appIdSearch(const unsigned char *packet);

AVLTree_Node* insertToHash(uint32_t ip1, uint32_t ip2, uint16_t p1, uint16_t p2, uint16_t sessid, AVLTree_Node *root);
struct node * createhNode(uint32_t ip1, uint32_t ip2, uint16_t p1, uint16_t p2, uint16_t sessid);


/*
 * print data in rows of 16 bytes: offset   hex   ascii
 *
 * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
 */
void
print_hex_ascii_line(const u_char *payload, int len, int offset)
{

	int i;
	int gap;
	const u_char *ch;

	/* offset */
	printf("%05d   ", offset);

	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");

	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");

	/* ascii (if printable) */
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");

return;
}

/*
 * print packet payload data (avoid printing binary data)
 */
void
print_payload(const u_char *payload, int len)
{

	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

return;
}

/*
 * dissect/print packet
 */
//void
//got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
uint32_t conv(char ip[])
{
	uint32_t num=0,val;
	char *tok,*ptr;
	tok=strtok(ip,".");
	while(tok!=NULL)
	{
		val=strtoul(tok,&ptr,0);
		num=(num<<8)+val;
		tok=strtok(NULL,".");
	}
	return num;
}




	const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
	const struct sniff_ip *ip;              /* The IP header */
	const struct sniff_tcp *tcp;            /* The TCP header */
	const struct sniff_udp *udp;
	const u_char *payload;                    /* Packet payload */

	int size_ip;
	int size_tcp;
	uint32_t size_payload;


void dump_packet(const unsigned char *packet, struct timeval ts,
			unsigned int capture_len)

{

	static int count = 1;                   /* packet counter */

	/* declare pointers to packet headers */

	printf("\nPacket number %d:\n", count);
	count++;

	/* define ethernet header */
	ethernet = (struct sniff_ethernet*)(packet);

	/* define/compute ip header offset */
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}

	/* print source and destination IP addresses */
	printf("       From: %u\n", conv(inet_ntoa(ip->ip_src)));
	printf("         To: %u\n", conv(inet_ntoa(ip->ip_dst)));

	/* determine protocol */
/*	switch(ip->ip_p) {
		case IPPROTO_TCP:
			printf("   Protocol: TCP\n");
			break;
		case IPPROTO_UDP:
			printf("   Protocol: UDP\n");
			return;
		case IPPROTO_ICMP:
			printf("   Protocol: ICMP\n");
			return;
		case IPPROTO_IP:
			printf("   Protocol: IP\n");
			return;
		default:
			printf("   Protocol: unknown\n");
			return;
	}
	*/
	/*
	 *  OK, this packet is TCP.
	 */

	/* define/compute tcp header offset */

	if(ip->ip_p == IPPROTO_TCP){

		printf("\n TCP : \n ");
		tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
		size_tcp = TH_OFF(tcp)*4;
		if (size_tcp < 20) {
			printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
			return;
		}

		printf("   Src port: %d\n", ntohs(tcp->th_sport));
		printf("   Dst port: %d\n", ntohs(tcp->th_dport));

		/* define/compute tcp payload (segment) offset */
		payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);

		/* compute tcp payload (segment) size */
		size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);

		/*
		 * Print payload data; it might be binary, so don't just
		 * treat it as a string.
		 */
		if (size_payload > 0) {
			printf("   Payload (%d bytes):\n", size_payload);
			print_payload(payload, size_payload);
		}
	}
	else if (ip->ip_p == IPPROTO_UDP)
	{

		printf("\n UDP : \n");
		udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + size_ip);
		if((capture_len - size_ip - size_tcp) < sizeof(udp))
		{
			printf("   * Invalid UDP header length: %u bytes\n",(capture_len - size_ip - size_tcp));
			return;

		}

		printf("   Src port: %d\n", ntohs(udp->uh_sport));
		printf("   Dst port: %d\n", ntohs(udp->uh_dport));

		/* define/compute tcp payload (segment) offset */
		payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + sizeof(udp));

		/* compute tcp payload (segment) size */
		size_payload = ntohs(ip->ip_len) - (size_ip + sizeof(udp));

		/*
		 * Print payload data; it might be binary, so don't just
		 * treat it as a string.
		 */
		if (size_payload > 0) {
			printf("   Payload (%d bytes):\n", size_payload);
			print_payload(payload, size_payload);
		}




	}
	else
	{
		printf("Neither TCP nor UDP header is found. \n");
	}

return;
}

int tcp_count=0,udp_count=0,count=0;
//const FILE *fps = fopen("/root/Desktop/sessions.txt","a");
const char* getField(char *line, int num)
{
	const char *tok;
	for(tok=strtok(line,",");tok && *tok;tok=strtok(NULL,",\n"))
	{
		if(!--num)
		{
			return tok;
		}
	}
	return NULL;

}

AVLTree_Node *root1=NULL;

    uint32_t payload_size;



void appIdSearch(const unsigned char *packet)
{
    struct sniff_ip *head = ip;
    struct sniff_tcp *tcpHead = tcp;
    struct sniff_udp *udpHead = udp;

    FILE *fp;
    fp = fopen("/usr/report.txt","a");

    uint32_t ipsource, ipdst;
    int index,f_tcp=0,f_udp=0;

    if(head != NULL)
    {
        ipsource= conv(inet_ntoa(head->ip_src));
        ipdst= conv(inet_ntoa(head->ip_dst));

        uint8_t ipver = head->ip_vhl >> 4;
        uint8_t iphl = (head->ip_vhl & 15)*4;
        uint8_t iptos = head->ip_tos;
        uint16_t iplen = head->ip_len;
        uint16_t ipid = ntohs(head->ip_id);
        uint16_t ipoff = head->ip_off;
        uint8_t ipttl = head->ip_ttl;
        //uint8_t ipproto = head->ip_proto;   can not find protocol
        uint16_t ipcsum = ntohs(head->ip_sum);

       /* uint8_t moref = p->ip_more_fragments;
        uint8_t dontf = p->ip_dont_fragment;

        uint8_t ipoptionscount = p->num_ip_options;*/
    }

    else
    {
        //IP empty commas 21
        fprintf(fp,",,,,,,,,,,,,,,,,,,,,,");
    }

    uint16_t sport, dport;
uint8_t tcpoptionscount;
if(tcpHead != NULL || udpHead != NULL)
{
	if(tcpHead != NULL)
	{
		tcp_count++;
		sport = ntohs(tcpHead->th_sport);
	   	dport = ntohs(tcpHead->th_dport);
		uint32_t seq = tcpHead->th_ack;
		uint32_t ack = tcpHead->th_ack;
		uint8_t offset = tcpHead->th_offx2;
		uint8_t flags = tcpHead->th_flags;
		uint16_t window = tcpHead->th_win;
		uint16_t check = ntohs(tcpHead->th_sum);
		uint16_t urgent = tcpHead->th_urp;

		//tcpoptionscount = p->num_tcp_options;
	       payload_size = ntohs(head->ip_len) - (size_ip + size_tcp);
		//payload_size = payload_size - size_ip - size_tcp ;


		//opt = p->tcp_options;
		//int index;
		fprintf(fp,"1,"); //1 for TCP
		fprintf(fp,"%u,",sport);
		fprintf(fp,"%u,",dport);
		fprintf(fp,"%u,",seq);
		fprintf(fp,"%u,",ack);
		fprintf(fp,"%u,",offset);
		fprintf(fp,"%u,",flags);
		fprintf(fp,"%u,",window);
		fprintf(fp,"0x%X,",check);
		fprintf(fp,"%u",urgent);

		f_tcp=1;

		payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);

	}

	else
	{
		f_tcp=0;
		//empty commas for TCP 21
		fprintf(fp,",,,,,,,,,,,,,,,,,,,,,");
	}

	if(udpHead != NULL)
	{
		udp_count++;
		sport = ntohs(udpHead->uh_sport);
	    	dport = ntohs(udpHead->uh_dport);
	    	uint16_t leng = udpHead->uh_ulen;
	    	uint16_t check = ntohs(udpHead->uh_sum);

		//payload_size = leng - UDP_HDR_LEN ;
		 payload_size = ntohs(head->ip_len) - (size_ip + sizeof(udp));

		fprintf(fp,"0,"); //0 for UDP
		fprintf(fp,"%u,",sport);
		fprintf(fp,"%u,",dport);
		fprintf(fp,"%u,",leng);
		fprintf(fp,"0x%X",check);

		f_udp=1;

		payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);

	/*	fprintf(fps,"%u,",src);
		fprintf(fps,"%u,",des);
	*/
	}
	else
	{
		f_udp=0;
		//UDP empty commas
		fprintf(fp,",,,");
	}
}

else
{
	//TCP UDP +1 empty commas 25
	fprintf(fp,",,,,,,,,,,,,,,,,,,,,,,,,,");
}
fprintf(fp,"\n");
fclose(fp);


/**session**/

initializeHash(500);
fp = fopen("/usr/session.txt","a");
struct node *s;
uint8_t count;
uint8_t *opti;

if(head != NULL && (f_tcp || f_udp))
{

	printf("\nPacket encount ::  Source IP : %u Source Port :%u  Destination IP : %u  Destination Port : %u",ipsource,sport,ipdst,dport);
	if(s=searchInHash((ipsource),(ipdst),sport,dport))
	{


		uint16_t sessid =(sessidInHash(ipsource,ipdst,sport,dport));
		refer(sessid);
		//addCumulativeInfo(ipsource,ipdst,sport,dport,payload_size);
	   	fprintf(fp,"\n\nSession found ::  Source IP : %u Source Port :%u  Destination IP : %u  Destination Port : %u  Sessid : %u Payload: %u ",ipsource,sport,ipdst,dport,sessid,payload_size);           //add cumulative info
if(isRequest(ipsource,sport,s))
		{
				//printf("\nisRequest!!!!\n");
			count = s->reqCount;
			/*TCP_OPTIONS*/
			//opti = s->reqOptions[count];
			if(count ==MAX_REQUESTS_FOR_DT && s->resCount==MAX_REQUESTS_FOR_DT)
			{
				struct timeval tval;
				gettimeofday(&tval,NULL);

				s->duration = (s->duration - ((tval.tv_sec)*1000 + (tval.tv_usec)/1000));
				//print for DT
				//printf("\n20 packets sip: %u, dip: %u, sport: %u, dport: %u",ipsource,ipdst,sport,dport);
				s->reqCount = -1; //-1 means already passed to tree and no need to process it Anymore
				s->resCount = -1;
				//printf("HERE -_-");
				printForDT(s);
			}
			else if(count < MAX_REQUESTS_FOR_DT && count!=-1)
			{
				//printf("\nstop coming here!!!");
				/*TCP_OPTIONS*/
/*				if(f_tcp)
				{
					opt = p->tcp_options;
					sort(opt,tcpoptionscount);

					if((index=contains(opt,2,tcpoptionscount)) != -1 && (opt[index]).option_data!=NULL)
						opti[0] = *(opt[index]).option_data;
						//fprintf(fp,"%u,",*(opt[index]).option_data);
					else
						opti[0] = 0;

					if((index=contains(opt,3,tcpoptionscount)) != -1 && (opt[index]).option_data!=NULL)
						opti[1] = *(opt[index]).option_data;
					else
						opti[1] = 0;

					if((index=contains(opt,4,tcpoptionscount)) != -1 && (opt[index]).option_data!=NULL)
						opti[2] = *(opt[index]).option_data;
					else
						opti[2] = 0;

					if((index=contains(opt,5,tcpoptionscount)) != -1 && (opt[index]).option_data!=NULL)
						opti[3] = *(opt[index]).option_data;
					else
						opti[3] = 0;

					if((index=contains(opt,6,tcpoptionscount)) != -1 && (opt[index]).option_data!=NULL)
						opti[4] = *(opt[index]).option_data;
					else
						opti[4] = 0;

					if((index=contains(opt,7,tcpoptionscount)) != -1 && (opt[index]).option_data!=NULL)
						opti[5] = *(opt[index]).option_data;
					else
						opti[5] = 0;

					if((index=contains(opt,8,tcpoptionscount)) != -1 && (opt[index]).option_data!=NULL)
						opti[6] = *(opt[index]).option_data;
					else
						opti[6] = 0;

					if((index=contains(opt,17,tcpoptionscount)) != -1 && (opt[index]).option_data!=NULL)
						opti[7] = *(opt[index]).option_data;
					else
						opti[7] = 0;

					if((index=contains(opt,18,tcpoptionscount)) != -1 && (opt[index]).option_data!=NULL)
						opti[8] = *(opt[index]).option_data;
					else
						opti[8] = 0;

					if((index=contains(opt,19,tcpoptionscount)) != -1 && (opt[index]).option_data!=NULL)
						opti[9] = *(opt[index]).option_data;
					else
						opti[9] = 0;

				}
				else
				{
					int loop;
					for(loop=0;loop<MAX_TCP_OPTIONS;loop++)
						opti[loop]=0;
				}
*/
				//printf("\n%f ",s->reqPayloadAvg*count);
				int i;
				for(i=0;i<MAX_PAYLOAD_BYTES;i++)
				{
					s->reqPayloadBytes[count][i] = payload[i];
				}
				s->reqPayloadAvg = (double)(((double)(s->reqPayloadAvg)*(double)count) + (double)payload_size)/((double)(count+1));
				s->reqPacket[count] =  head->ip_len;
				s->reqPayload[count] =  payload_size;
				s->reqPacketAvg = (double)(((double)(s->reqPacketAvg)*(double)count) + (double)head->ip_len)/((double)(count+1));
							//(((s->reqPayloadAvg)*count) + (p->payload_size))/(count+1);
				//printf("+ %u = %f\n",p->payload_size,s->reqPayloadAvg);
				s->reqCount++;
			}


		}
		else
		{
				//printf("\nisResponse!!!!\n");
			count = s->resCount;
			/*TCP_OPTIONS*/
			//opti = s->resOptions[count];
			if(count ==MAX_REQUESTS_FOR_DT && s->reqCount==MAX_REQUESTS_FOR_DT)
			{
				struct timeval tval;
				gettimeofday(&tval,NULL);

				s->duration = (s->duration - ((tval.tv_sec)*1000 + (tval.tv_usec)/1000));
				//print
				//printf("\n20 packets sip: %u, dip: %u, sport: %u, dport: %u",ipsource,ipdst,sport,dport);
				s->resCount = -1; //-1 means already passed to tree and no need to process it Anymore
				s->reqCount = -1;
				printForDT(s);

			}
			else if(count < MAX_REQUESTS_FOR_DT && count!=-1)
			{
				/*TCP_OPTIONS*/

/*				if(f_tcp)
				{
					opt = p->tcp_options;
					sort(opt,tcpoptionscount);

					if((index=contains(opt,2,tcpoptionscount)) != -1 && (opt[index]).option_data!=NULL)
						opti[0] = *(opt[index]).option_data;
						//fprintf(fp,"%u,",*(opt[index]).option_data);
					else
						opti[0] = 0;

					if((index=contains(opt,3,tcpoptionscount)) != -1 && (opt[index]).option_data!=NULL)
						opti[1] = *(opt[index]).option_data;
					else
						opti[1] = 0;

					if((index=contains(opt,4,tcpoptionscount)) != -1 && (opt[index]).option_data!=NULL)
						opti[2] = *(opt[index]).option_data;
					else
						opti[2] = 0;

					if((index=contains(opt,5,tcpoptionscount)) != -1 && (opt[index]).option_data!=NULL)
						opti[3] = *(opt[index]).option_data;
					else
						opti[3] = 0;

					if((index=contains(opt,6,tcpoptionscount)) != -1 && (opt[index]).option_data!=NULL)
						opti[4] = *(opt[index]).option_data;
					else
						opti[4] = 0;

					if((index=contains(opt,7,tcpoptionscount)) != -1 && (opt[index]).option_data!=NULL)
						opti[5] = *(opt[index]).option_data;
					else
						opti[5] = 0;

					if((index=contains(opt,8,tcpoptionscount)) != -1 && (opt[index]).option_data!=NULL)
						opti[6] = *(opt[index]).option_data;
					else
						opti[6] = 0;

					if((index=contains(opt,17,tcpoptionscount)) != -1 && (opt[index]).option_data!=NULL)
						opti[7] = *(opt[index]).option_data;
					else
						opti[7] = 0;

					if((index=contains(opt,18,tcpoptionscount)) != -1 && (opt[index]).option_data!=NULL)
						opti[8] = *(opt[index]).option_data;
					else
						opti[8] = 0;

					if((index=contains(opt,19,tcpoptionscount)) != -1 && (opt[index]).option_data!=NULL)
						opti[9] = *(opt[index]).option_data;
					else
						opti[9] = 0;

				}
				else
				{
					int loop;
					for(loop=0;loop<MAX_TCP_OPTIONS;loop++)
						opti[loop]=0;
				}
*/
				int i;
				for(i=0;i<MAX_PAYLOAD_BYTES;i++)
				{
					s->resPayloadBytes[count][i] =  payload[i];
				}
				s->resPayloadAvg = (double)(((double)(s->resPayloadAvg)*(double)count) + (double)payload_size)/((double)(count+1));
				s->resPacket[count] = head->ip_len;
				s->resPayload[count] = payload_size;
				s->resPacketAvg = (double)(((double)(s->resPacketAvg)*(double)count) + (double)head->ip_len)/((double)(count+1));
							//(s->resPayloadAvg + p->payload_size);
				s->resCount++;
			}
		}

	}
	else
	{

		uint16_t sessid= (uint16_t)getSessionId();

		if(searchElement(root1,sessid))
		{
			deleteFromHashbySessId(sessid,root1);   //delete from hash
			root1=deletion(root1,sessid);           // delete from avltree

			fprintf(fp,"\n\nSession deleted : %u ",sessid);
		        //if sessid is already assigned then it needs to be removed from both avl and hash
		}


		root1 =insertToHash(ipsource,ipdst,sport,dport,sessid,root1);
		refer(sessid);


	   	fprintf(fp,"\n\nSession inserted ::  Source IP : %u Source Port :%u  Destination IP : %u  Destination Port : %u  Sessid : %u Payload: %u ",ipsource,sport,ipdst,dport,sessid,payload_size);           //add cumulative info

	}

}
else
{
	fprintf(fp,"\n\n Neither TCP nor UDP header found for Source IP : %u Destination IP : %u ",ipsource,ipdst);

}

fclose(fp);

}


AVLTree_Node* insertToHash(uint32_t ip1, uint32_t ip2, uint16_t p1, uint16_t p2, uint16_t sessid, AVLTree_Node *root)
{
	AVLTree_Node *temp=NULL;
	if (searchInHash(ip1, ip2, p1, p2) != NULL)
	{
		//printf("\n\nALready %u ",sessid);
		return NULL;
	}
	uint32_t hashIndex = getIndex(ip1, ip2, p1, p2);
    struct node *newnode = createhNode(ip1, ip2, p1, p2,sessid);
    /* head of list for the bucket with index "hashIndex" */
    if (!hashTable[hashIndex].head)
{
        hashTable[hashIndex].head = newnode;
	root=insertion(root,sessid,newnode);
	//if(root == NULL)
	//	printf("\nInsertion gives NULL");   // appid_sessionstore
        hashTable[hashIndex].count = 1;
        return root;
    }
    /* adding new node to the list */
    newnode->next = (hashTable[hashIndex].head);
    /*
     * update the head of the list and no of
     * nodes in the current bucket
     */
    hashTable[hashIndex].head = newnode;
    root=insertion(root,sessid,newnode);
    hashTable[hashIndex].count++;

    return root;
}


int main(int argc, char **argv)
{

	pcap_t *pcap;
	const unsigned char *packet;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr header;
    int i=0;

    if(argc>=2){
            for(i=1;i<argc;i++){
                pcap = pcap_open_offline(argv[i], errbuf);
                if (pcap == NULL)
                {
                    fprintf(stderr, "error reading pcap file: %s\n", errbuf);
                    exit(EXIT_FAILURE);
                }

                while ((packet = pcap_next(pcap, &header)) != NULL)
                {dump_packet(packet, header.ts, header.caplen);
                appIdSearch(packet);
                }
		printf("\nCapture complete.\n");

            }
        }



return 0;
}




struct node * createhNode(uint32_t ip1, uint32_t ip2, uint16_t p1, uint16_t p2, uint16_t sessid)
{

    struct node *newnode;
    newnode = (struct node *) malloc(sizeof(struct node));
	if (isSmaller(ip1, ip2))
	{
		newnode->ip1 = ip1;
		newnode->ip2 = ip2;

		newnode->p1 = p1;
		newnode->p2 = p2;

		newnode->whichIsSource = 0;

		newnode->sessid = sessid;
		newnode->total_bytes = payload_size;
		newnode->total_packets = 1;
	}
	else
	{
		newnode->ip1 = ip2;
		newnode->ip2 = ip1;

		newnode->p1 = p2;
		newnode->p2 = p1;

		newnode->whichIsSource = 1;

		newnode->sessid = sessid;
		newnode->total_bytes = payload_size;
		newnode->total_packets = 1;
	}

	newnode->reqCount = 1;
	newnode->resCount = 0;
	struct timeval tval;
	gettimeofday(&tval,NULL);
	newnode->duration = (tval.tv_sec)*1000 + (tval.tv_usec)/1000;

	newnode->reqPacket[0] = ip->ip_len;
	newnode->reqPayload[0] =  payload_size;
	newnode->reqPacketAvg = ip->ip_len;
	newnode->reqPayloadAvg = payload_size;

	newnode->resPacketAvg = 0;
	newnode->resPayloadAvg = 0;


	int i;
	for(i=0;i<MAX_PAYLOAD_BYTES;i++)
	{
		newnode->reqPayloadBytes[0][i] = payload[i];
	}
	/*TCP_OPTIONS*/
/*	uint8_t* opti = newnode->reqOptions[0];
	if(p->tcp_header != NULL)
	{
		TCPOptions *opt=NULL;
		opt = p->tcp_options;
		int index;

		uint8_t tcpoptionscount = p->num_tcp_options;

		sort(opt,tcpoptionscount);

		if((index=contains(opt,2,tcpoptionscount)) != -1 && (opt[index]).option_data!=NULL)
			opti[0] = *(opt[index]).option_data;
			//fprintf(fp,"%u,",*(opt[index]).option_data);
		else
			opti[0] = 0;

		if((index=contains(opt,3,tcpoptionscount)) != -1 && (opt[index]).option_data!=NULL)
			opti[1] = *(opt[index]).option_data;
		else
			opti[1] = 0;

		if((index=contains(opt,4,tcpoptionscount)) != -1 && (opt[index]).option_data!=NULL)
			opti[2] = *(opt[index]).option_data;
		else
			opti[2] = 0;

		if((index=contains(opt,5,tcpoptionscount)) != -1 && (opt[index]).option_data!=NULL)
			opti[3] = *(opt[index]).option_data;
		else
			opti[3] = 0;

		if((index=contains(opt,6,tcpoptionscount)) != -1 && (opt[index]).option_data!=NULL)
			opti[4] = *(opt[index]).option_data;
		else
			opti[4] = 0;

		if((index=contains(opt,7,tcpoptionscount)) != -1 && (opt[index]).option_data!=NULL)
			opti[5] = *(opt[index]).option_data;
		else
			opti[5] = 0;

		if((index=contains(opt,8,tcpoptionscount)) != -1 && (opt[index]).option_data!=NULL)
			opti[6] = *(opt[index]).option_data;
		else
			opti[6] = 0;

		if((index=contains(opt,17,tcpoptionscount)) != -1 && (opt[index]).option_data!=NULL)
			opti[7] = *(opt[index]).option_data;
		else
			opti[7] = 0;

		if((index=contains(opt,18,tcpoptionscount)) != -1 && (opt[index]).option_data!=NULL)
			opti[8] = *(opt[index]).option_data;
		else
			opti[8] = 0;

		if((index=contains(opt,19,tcpoptionscount)) != -1 && (opt[index]).option_data!=NULL)
			opti[9] = *(opt[index]).option_data;
		else
			opti[9] = 0;

	}
	else
	{
		int loop;
		for(loop=0;loop<MAX_TCP_OPTIONS;loop++)
			opti[loop]=0;
	}

*/
	//strcpy(newnode->name, name);
    newnode->next = NULL;
    return newnode;
}


