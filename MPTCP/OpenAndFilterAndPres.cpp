// OpenAndFilterAndPres.cpp : Defines the entry point for the console application.
 //
 
#include "stdafx.h" 
#include "pcap.h"
#include "remote-ext.h"
#include"stdlib.h"

 /* 4 bytes IP address */
typedef struct ip_address{
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
}ip_address;

/* IPv4 header */
typedef struct ip_header{
    u_char  ver_ihl;        // Version (4 bits) + Internet header length (4 bits)
    u_char  tos;            // Type of service 
    u_short tlen;           // Total length 
    u_short identification; // Identification
    u_short flags_fo;       // Flags (3 bits) + Fragment offset (13 bits)
    u_char  ttl;            // Time to live
    u_char  proto;          // Protocol
    u_short crc;            // Header checksum
    ip_address  saddr;      // Source address
    ip_address  daddr;      // Destination address
    u_int   op_pad;         // Option + Padding
}ip_header;

/* UDP header*/
typedef struct udp_header{
    u_short sport;          // Source port
    u_short dport;          // Destination port
    u_short len;            // Datagram length
    u_short crc;            // Checksum
}udp_header;

// TCP首部
typedef struct tcp_header{
    WORD  source_port;       // (16 bits)                         Winsock 内置函数 ntohs（），主要作用将大端转换为小端！
    WORD  destination_port;  // (16 bits)                         Winsock 内置函数 ntohs（），主要作用将大端转换为小端！
    DWORD seq_number;        // Sequence Number (32 bits)         大小端原因，高低位4个8bit的存放顺序是反的，intel使用小端模式
    DWORD ack_number;        // Acknowledgment Number (32 bits)     大小端原因，高低位4个8bit的存放顺序是反的，intel使用小端模式
    WORD  info_ctrl;         // Data Offset (4 bits), Reserved (6 bits), Control bits (6 bits)                intel使用小端模式
    WORD  window;            // (16 bits)
    WORD  checksum;          // (16 bits)
    WORD  urgent_pointer;    // (16 bits)
} tcp_header;

/* prototype of the packet handler */
void dispatcher_handler(u_char *temp1, const struct pcap_pkthdr *header, const u_char *pkt_data);

#define PCAP_FILE "F:/vs/data/mptcp.pcap"

int main(int argc, char* argv[])
{
    pcap_t *fp;
    char errbuf[PCAP_ERRBUF_SIZE];
    char source[PCAP_BUF_SIZE];
    //char packet_filter[] = "tcp";
    //有tcp必有ip
    char packet_filter[] = "ip and tcp";
    struct bpf_program fcode;
    u_int netmask;


    /* Create the source string according to the new WinPcap syntax */
    if ( pcap_createsrcstr( source,         // variable that will keep the source string
                            PCAP_SRC_FILE,  // we want to open a file
                            NULL,           // remote host
                            NULL,           // port on the remote host
                            PCAP_FILE,        // name of the file we want to open
                            errbuf          // error buffer
                            ) != 0)
    {
        fprintf(stderr,"\nError creating a source string\n");
        return -1;
    }
    
    /* Open the capture file */
    if ( (fp= pcap_open(source,         // name of the device
                        65536,          // portion of the packet to capture
                                        // 65536 guarantees that the whole packet will be captured on all the link layers
                         PCAP_OPENFLAG_PROMISCUOUS,     // promiscuous mode
                         1000,              // read timeout
                         NULL,              // authentication on the remote machine
                         errbuf         // error buffer
                         ) ) == NULL)
    {
        fprintf(stderr,"\nUnable to open the file %s.\n", source);
        return -1;
    }

    netmask=0xffffff; 

    //compile the filter
    if (pcap_compile(fp, &fcode, packet_filter, 1, netmask) <0 )
    {
        fprintf(stderr,"\nUnable to compile the packet filter. Check the syntax.\n");
        return -1;
    }
    
    //set the filter
    if (pcap_setfilter(fp, &fcode)<0)
    {
        fprintf(stderr,"\nError setting the filter.\n");
        return -1;
    }

    // read and dispatch packets until EOF is reached
    pcap_loop(fp, 0, dispatcher_handler, NULL);

    return 0;
}

void dispatcher_handler(u_char *temp1, 
                        const struct pcap_pkthdr *header, const u_char *pkt_data)
{
    struct tm *ltime;
    char timestr[16];
    ip_header *ih;
    tcp_header *th;
    u_int ip_len;
    u_short sport,dport;
    time_t local_tv_sec;

    /* convert the timestamp to readable format */
    local_tv_sec = header->ts.tv_sec;
    ltime=localtime(&local_tv_sec);
    strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);

    /* print timestamp and length of the packet */
    printf("%s.%.6d len:%d ", timestr, header->ts.tv_usec, header->len);

    /* retireve the position of the ip header */
    ih = (ip_header *) (pkt_data +
        14); //length of ethernet header

    /* retireve the position of the tcp header */
    //从IPV4首部中取出"首部长度(4 bits)"
    ip_len = (ih->ver_ihl & 0xf) * 4;
    //强制类型转换，便于用自己的命名处理
    th = (tcp_header *) ((u_char*)ih + ip_len);

    /* convert from network byte order to host byte order */
    sport = ntohs( th->source_port );
    dport = ntohs( th->destination_port );

    /* print ip addresses and udp ports */
    printf("%d.%d.%d.%d.%d -> %d.%d.%d.%d.%d\n",
        ih->saddr.byte1,
        ih->saddr.byte2,
        ih->saddr.byte3,
        ih->saddr.byte4,
        sport,
        ih->daddr.byte1,
        ih->daddr.byte2,
        ih->daddr.byte3,
        ih->daddr.byte4,
        dport);    
}