
/*      
-----------------------------------------------------------------------------------------------------------------------      
WinPcap头文件 ;      
以下是以太网协议格式的定义      
-----------------------------------------------------------------------------------------------------------------------      
 */    
struct ether_header        
{        
    u_int8_t ether_dhost[6];        
    /* 目的以太网地址 */    
    u_int8_t ether_shost[6];        
    /* 源以太网地址 */    
    u_int16_t ether_type;        
    /* 以太网类型 */    
};
/*      
-----------------------------------------------------------------------------------------------------------------------      
下面是ARP协议格式的定义      
-----------------------------------------------------------------------------------------------------------------------      
 */    
struct arp_header        
{        
    u_int16_t arp_hardware_type;        
    /* 硬件类型 */    
    u_int16_t arp_protocol_type;        
    /* 协议类型 */    
    u_int8_t arp_hardware_length;        
    /* 硬件地址长度 */    
    u_int8_t arp_protocol_length;        
    /* 协议地址长度 */    
    u_int16_t arp_operation_code;        
    /* 操作码 */    
    u_int8_t arp_source_ethernet_address[6];        
    /* 源以太网地址 */    
    u_int8_t arp_source_ip_address[4];        
    /* 源IP地址 */    
    u_int8_t arp_destination_ethernet_address[6];        
    /* 目的以太网地址 */    
    u_int8_t arp_destination_ip_address[4];        
    /* 目的IP地址 */    
};        
/*      
-----------------------------------------------------------------------------------------------------------------------      
下面是IP协议格式的定义      
-----------------------------------------------------------------------------------------------------------------------      
 */    
struct ip_header        
{        
    #if defined(WORDS_BIGENDIAN)        
        u_int8_t ip_version: 4,        
        /* 版本 */    
        ip_header_length: 4;        
        /* 首部长度 */    
    #else        
        u_int8_t ip_header_length: 4, ip_version: 4;        
    #endif        
    u_int8_t ip_tos;        
    /* 服务质量 */    
    u_int16_t ip_length;        
    /* 长度 */    
    u_int16_t ip_id;        
    /* 标识 */    
    u_int16_t ip_off;        
    /* 偏移 */    
    u_int8_t ip_ttl;        
    /* 生存时间 */    
    u_int8_t ip_protocol;        
    /* 协议类型 */    
    u_int16_t ip_checksum;        
    /* 校验和 */    
    struct in_addr ip_souce_address;        
    /* 源IP地址 */    
    struct in_addr ip_destination_address;        
    /* 目的IP地址 */    
};        
/*      
-----------------------------------------------------------------------------------------------------------------------      
下面是UDP协议格式定义      
-----------------------------------------------------------------------------------------------------------------------      
 */    
struct udp_header        
{        
    u_int16_t udp_source_port;        
    /* 源端口号 */    
    u_int16_t udp_destination_port;        
    /* 目的端口号 */    
    u_int16_t udp_length;        
    /* 长度 */    
    u_int16_t udp_checksum;        
    /* 校验和 */    
};        
/*      
-----------------------------------------------------------------------------------------------------------------------      
下面是TCP协议格式的定义      
-----------------------------------------------------------------------------------------------------------------------      
 */    
struct tcp_header        
{        
    u_int16_t tcp_source_port;        
    /* 源端口号 */    
    u_int16_t tcp_destination_port;        
    /* 目的端口号 */    
    u_int32_t tcp_sequence_lliiuuwweennttaaoo;        
    /* 序列号 */    
    u_int32_t tcp_acknowledgement;        
    /* 确认序列号 */    
    #ifdef WORDS_BIGENDIAN        
        u_int8_t tcp_offset: 4,        
        /* 偏移 */    
        tcp_reserved: 4;        
        /* 未用 */    
    #else        
        u_int8_t tcp_reserved: 4,        
        /* 未用 */    
        tcp_offset: 4;        
        /* 偏移 */    
    #endif        
    u_int8_t tcp_flags;
    /* 标记 */    
    u_int16_t tcp_windows;        
    /* 窗口大小 */    
    u_int16_t tcp_checksum;        
    /* 校验和 */    
    u_int16_t tcp_urgent_pointer;
    /* 紧急指针 */
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
下面是TCP协议Options头部格式的定义      
-----------------------------------------------------------------------------------------------------------------------      
 */    
struct tcp_options_header
{
    u_int8_t kind;
    /* 选项的类型,1字节，MTCP对应的是时间戳0x1e */
    u_int8_t length;
};
/*      
-----------------------------------------------------------------------------------------------------------------------      
下面是MpTCP数据包格式的定义      
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
下面是ICMP协议格式的定义      
-----------------------------------------------------------------------------------------------------------------------      
 */    
struct icmp_header        
{        
    u_int8_t icmp_type;        
    /* ICMP类型 */    
    u_int8_t icmp_code;        
    /* ICMP代码 */    
    u_int16_t icmp_checksum;        
    /* 校验和 */    
    u_int16_t icmp_id;        
    /* 标识符 */    
    u_int16_t icmp_sequence;        
    /* 序列码 */    
};

/*      
-----------------------------------------------------------------------------------------------------------------------      
下面是subflow主机对的定义      
-----------------------------------------------------------------------------------------------------------------------      
 */    
struct subflow_hosts        
{
    u_int32_t ip1; 
    u_int32_t ip2;
};