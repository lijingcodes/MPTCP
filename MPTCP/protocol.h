
/*      
-----------------------------------------------------------------------------------------------------------------------      
WinPcapͷ�ļ� ;      
��������̫��Э���ʽ�Ķ���      
-----------------------------------------------------------------------------------------------------------------------      
 */    
struct ether_header        
{        
    u_int8_t ether_dhost[6];        
    /* Ŀ����̫����ַ */    
    u_int8_t ether_shost[6];        
    /* Դ��̫����ַ */    
    u_int16_t ether_type;        
    /* ��̫������ */    
};
/*      
-----------------------------------------------------------------------------------------------------------------------      
������ARPЭ���ʽ�Ķ���      
-----------------------------------------------------------------------------------------------------------------------      
 */    
struct arp_header        
{        
    u_int16_t arp_hardware_type;        
    /* Ӳ������ */    
    u_int16_t arp_protocol_type;        
    /* Э������ */    
    u_int8_t arp_hardware_length;        
    /* Ӳ����ַ���� */    
    u_int8_t arp_protocol_length;        
    /* Э���ַ���� */    
    u_int16_t arp_operation_code;        
    /* ������ */    
    u_int8_t arp_source_ethernet_address[6];        
    /* Դ��̫����ַ */    
    u_int8_t arp_source_ip_address[4];        
    /* ԴIP��ַ */    
    u_int8_t arp_destination_ethernet_address[6];        
    /* Ŀ����̫����ַ */    
    u_int8_t arp_destination_ip_address[4];        
    /* Ŀ��IP��ַ */    
};        
/*      
-----------------------------------------------------------------------------------------------------------------------      
������IPЭ���ʽ�Ķ���      
-----------------------------------------------------------------------------------------------------------------------      
 */    
struct ip_header        
{        
    #if defined(WORDS_BIGENDIAN)        
        u_int8_t ip_version: 4,        
        /* �汾 */    
        ip_header_length: 4;        
        /* �ײ����� */    
    #else        
        u_int8_t ip_header_length: 4, ip_version: 4;        
    #endif        
    u_int8_t ip_tos;        
    /* �������� */    
    u_int16_t ip_length;        
    /* ���� */    
    u_int16_t ip_id;        
    /* ��ʶ */    
    u_int16_t ip_off;        
    /* ƫ�� */    
    u_int8_t ip_ttl;        
    /* ����ʱ�� */    
    u_int8_t ip_protocol;        
    /* Э������ */    
    u_int16_t ip_checksum;        
    /* У��� */    
    struct in_addr ip_souce_address;        
    /* ԴIP��ַ */    
    struct in_addr ip_destination_address;        
    /* Ŀ��IP��ַ */    
};        
/*      
-----------------------------------------------------------------------------------------------------------------------      
������UDPЭ���ʽ����      
-----------------------------------------------------------------------------------------------------------------------      
 */    
struct udp_header        
{        
    u_int16_t udp_source_port;        
    /* Դ�˿ں� */    
    u_int16_t udp_destination_port;        
    /* Ŀ�Ķ˿ں� */    
    u_int16_t udp_length;        
    /* ���� */    
    u_int16_t udp_checksum;        
    /* У��� */    
};        
/*      
-----------------------------------------------------------------------------------------------------------------------      
������TCPЭ���ʽ�Ķ���      
-----------------------------------------------------------------------------------------------------------------------      
 */    
struct tcp_header        
{        
    u_int16_t tcp_source_port;        
    /* Դ�˿ں� */    
    u_int16_t tcp_destination_port;        
    /* Ŀ�Ķ˿ں� */    
    u_int32_t tcp_sequence_lliiuuwweennttaaoo;        
    /* ���к� */    
    u_int32_t tcp_acknowledgement;        
    /* ȷ�����к� */    
    #ifdef WORDS_BIGENDIAN        
        u_int8_t tcp_offset: 4,        
        /* ƫ�� */    
        tcp_reserved: 4;        
        /* δ�� */    
    #else        
        u_int8_t tcp_reserved: 4,        
        /* δ�� */    
        tcp_offset: 4;        
        /* ƫ�� */    
    #endif        
    u_int8_t tcp_flags;
    /* ��� */    
    u_int16_t tcp_windows;        
    /* ���ڴ�С */    
    u_int16_t tcp_checksum;        
    /* У��� */    
    u_int16_t tcp_urgent_pointer;
    /* ����ָ�� */
};
#ifndef TCP_SYN
#define TCP_SYN 0x02
#endif
#ifndef TCP_ACK
#define TCP_ACK 0x10
#endif
#ifndef TCP_SYN_ACK
#define TCP_SYN_ACK 0x12
#endif   
#ifndef TCP_NO_OPER
#define TCP_NO_OPER 0x01
#endif 
#ifndef TCP_MPTCP_OPTION
#define TCP_MPTCP_OPTION 0x1e
#endif 
/*      
-----------------------------------------------------------------------------------------------------------------------      
������TCPЭ��Optionsͷ����ʽ�Ķ���      
-----------------------------------------------------------------------------------------------------------------------      
 */    
struct tcp_options_header
{
    u_int8_t kind;
    /* ѡ�������,1�ֽڣ�MTCP��Ӧ����ʱ���0x1e */
    u_int8_t length;
};
/*      
-----------------------------------------------------------------------------------------------------------------------      
������MpTCP���ݰ���ʽ�Ķ���      
-----------------------------------------------------------------------------------------------------------------------      
 */    
struct mptp_data_header        
{
    u_int32_t ack_num; 
    u_int32_t sequence_num; 
    u_int32_t sub_sequence_num; 
    u_int16_t data_length; 
    u_int16_t mptcp_checksum; 
};

#ifndef MPTCP_NO_TYPE_NO_VERSION
#define MPTCP_NO_TYPE_NO_VERSION  0x00
#endif
#ifndef MPTCP_EXCHANGE_KEY
#define MPTCP_EXCHANGE_KEY 0x81
#endif
#ifndef MPTCP_DSDC
#define MPTCP_DSDC 0x04
#endif
#ifndef MPTCP_ADD_ADDRESS
#define MPTCP_ADD_ADDRESS 0x30
#endif
#ifndef MPTCP_SEND_PACKET
#define MPTCP_SEND_PACKET 0x20
#endif
#ifndef MPTCP_JOIN
#define MPTCP_JOIN 0x10
#endif
#ifndef MPTCP_ACK
#define MPTCP_ACK 0x01
#endif
/*      
-----------------------------------------------------------------------------------------------------------------------      
������ICMPЭ���ʽ�Ķ���      
-----------------------------------------------------------------------------------------------------------------------      
 */    
struct icmp_header        
{        
    u_int8_t icmp_type;        
    /* ICMP���� */    
    u_int8_t icmp_code;        
    /* ICMP���� */    
    u_int16_t icmp_checksum;        
    /* У��� */    
    u_int16_t icmp_id;        
    /* ��ʶ�� */    
    u_int16_t icmp_sequence;        
    /* ������ */    
};

/*      
-----------------------------------------------------------------------------------------------------------------------      
������subflow�����ԵĶ���      
-----------------------------------------------------------------------------------------------------------------------      
 */    
struct subflow_hosts        
{
    u_int32_t ip1; 
    u_int32_t ip2;
};