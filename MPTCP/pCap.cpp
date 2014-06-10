#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"wpcap.lib")

#include "pcap.h" 
#include "protocol.h"
#include <iostream>
#include <algorithm>
#include <map>
#include <list>
#include <vector>
//#include "HMAC_SHA1.h"

#define LINE_LEN 16

//CHMAC_SHA1 sha1;
int packet_number = 0;        
/* 数据包个数，全局变量 */    
/*  analize_tcp_option 需要使用的数据结构，不用每次都创建  */
const u_char*											ppos;//目前读到哪里了
struct ip_header *										ip_protocol;// IP头
struct tcp_header *										tcp_protocol;//TCP头
struct tcp_options_header*								toh;//TCP数据包的Option部分
struct mptp_data_header*								mdh;//mptcp 发送数据时使用的头部
u_int8_t												type;//用在各个数据包中判断数据包类型用的
u_int8_t*												st_ver;//mptcp subtype & version
u_int8_t*												mp_flag;//mptcp flag
int64_t													optLength;//option 剩余长度
int64_t													length;//数据包内数据大小
u_int64_t*												sender_key;//发送者的hmac sha1 key
u_int64_t*												receiver_key;//接收者的hmac sha1 key
u_int32_t												sender_ip;//发送者的hmac sha1 key
u_int32_t												receiver_ip;//接收者的hmac sha1 key
u_int32_t												acked;//已经确认收到的ack号码
u_int32_t												seq;//已经发送出去的序列
std::vector<u_int32_t>									sender_ips;// 所有senders的ip
std::vector<u_int32_t>									receiver_ips;// 所有receivers的ip
std::vector<u_int64_t>									sender_keys;// 所有senders的key
std::vector<u_int64_t>									receiver_keys;// 所有receivers的key
std::map<u_int32_t, std::map<u_int8_t, subflow_hosts>>	subflows;//主ip-子ip
std::map<u_int32_t, u_int64_t>							subflow_data;//子ip-数据量
std::map<u_int32_t, u_int32_t>							subflow_token;//子ip-token
std::map<u_int32_t, std::list<u_int64_t>>				sent_seq;//ip-已经发送出去的序列号
std::map<u_int64_t, u_int16_t>							sent_data;//已经发送出去的字节数

void analize_tcp_option(const struct tcp_header *tcp_protocol, const u_char *packet_content)
{
	
	optLength = tcp_protocol->tcp_offset*4 - sizeof(struct tcp_header);
	ppos = packet_content + 14 + 20 + sizeof(struct tcp_header);//调到option的位置
	
	while(optLength > 0){//tcp会有多个option
		toh = (struct tcp_options_header*)ppos;
		optLength -= sizeof(struct tcp_options_header);
		ppos += sizeof(struct tcp_options_header);

		//printf("option kind: %x\n", toh->kind);

		if (TCP_NO_OPER == toh->kind){//蛋疼的Non-Operation 多读了一字节，倒回去一下
			ppos -= 1;
			optLength +=1;
		}else{
			length = toh->length - sizeof(struct tcp_options_header);//头部自己占2两个字节
			if (TCP_MPTCP_OPTION == toh->kind){//mptcp
					
				sender_ip = ip_protocol->ip_souce_address.s_addr;
				receiver_ip = ip_protocol->ip_destination_address.s_addr;
					
				st_ver = (u_int8_t*)ppos;//读取subtype和version
				optLength -= sizeof(u_int8_t);
				ppos += sizeof(u_int8_t);
				length -= sizeof(u_int8_t);
				if (MPTCP_NO_TYPE_NO_VERSION == *st_ver){//全0的情况是还在握手的时候
					mp_flag = (u_int8_t*)ppos;//这里的flag应该是0x81
					optLength -= sizeof(u_int8_t);
					ppos += sizeof(u_int8_t);
					length -= sizeof(u_int8_t);

					if (MPTCP_EXCHANGE_KEY == *mp_flag){
						sender_key = (u_int64_t*)ppos;
						optLength -= sizeof(u_int64_t);
						ppos += sizeof(u_int64_t);
						length -= sizeof(u_int64_t);
						if (length > 0){//只有第三次握手的时候，双方交换key

							receiver_key = (u_int64_t*)ppos;
							optLength -= sizeof(u_int64_t);
							ppos += sizeof(u_int64_t);
							length -= sizeof(u_int64_t);

							
							sender_keys.push_back(ntohl(*sender_key));
							receiver_keys.push_back(ntohl(*receiver_key));

							sender_ips.push_back(sender_ip);
							receiver_ips.push_back(receiver_ip);

							std::map<u_int8_t, subflow_hosts> subs;
							subflows[sender_ip] = subs;

							subflow_hosts sh;
							sh.ip1 = sender_ip;
							sh.ip2 = receiver_ip;
							subflows[sender_ip][0] = sh;

							subflow_data[sender_ip] = 0;//目前数据为0
							subflow_data[receiver_ip] = 0;//目前数据为0

							std::list<u_int64_t> reqs;
							sent_seq[sender_ip] = reqs;
						}
					}else
					{
						printf("*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-\n");
						printf("unsuppoted flag in st_ver 00: %x\n", *mp_flag);
						printf("*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-\n");
					}
				}else if ((MPTCP_ADD_ADDRESS & (*st_ver)) == MPTCP_ADD_ADDRESS){//0x3*表示添加address

					u_int8_t add_id;
					memcpy(&add_id, ppos, sizeof(add_id));
					ppos += 1;
					optLength -= 1;
					length -= 1;

					u_int32_t sub_ip;
					memcpy(&sub_ip, ppos, sizeof(sub_ip));
					ppos += sizeof(sub_ip);
					optLength -= sizeof(sub_ip);
					length -= sizeof(sub_ip);

					if (find(sender_ips.begin(), sender_ips.end(), sender_ip) == sender_ips.end()){//是服务器要加入ip地址
						subflows[receiver_ip][add_id].ip2 = sub_ip;
					}else{//肯定都是客户端先要求加入ip的
						subflow_hosts sh;
						sh.ip1 = sub_ip;
						subflows[sender_ip][add_id] = sh;
					}

					//subflow_data[sub_ip] = 0;//目前数据为0

				}else if ((MPTCP_SEND_PACKET & (*st_ver)) == MPTCP_SEND_PACKET){//0x2*表示发送数据
					mp_flag = (u_int8_t*)ppos;
					ppos += 1;//减去flag
					optLength -= 1;
					length -= 1;

					mdh = (mptp_data_header*)ppos;
					if (MPTCP_ACK & *mp_flag){//有回复ACK，基本一定有
						ppos += 4;
						optLength -= 4;
						length -= 4;
						
						acked = ntohl(mdh->ack_num);
						if (sent_seq.find(receiver_ip) != sent_seq.end()){//看看对方是不是曾经发过数据包
							while(true ){
								if (0 == sent_seq[receiver_ip].size()){
									break;
								}
								seq = sent_seq[receiver_ip].front();
								if (seq < acked){
									subflow_data[receiver_ip] += sent_data[seq];//数据累加
									sent_seq[receiver_ip].pop_front();
									sent_data.erase(seq);
								}else{
									break;
								}
							}
						}
					}
					if (MPTCP_DSDC & *mp_flag){//有发送数据
						ppos += 12;
						optLength -= 12;
						length -= 12;

						seq = ntohl(mdh->sequence_num);
						if ((sent_seq[sender_ip].size() == 0) || (seq > sent_seq[sender_ip].back())){//快速重传的时候，不需要再次插入，而且也不会搞乱顺序了
							sent_seq[sender_ip].push_back(seq);
							sent_data[seq] = ntohs(mdh->data_length);//数据暂存
						}
						
					}
				}else if ((MPTCP_JOIN & (*st_ver)) == MPTCP_JOIN){//0x1*表示加入链接
					if ((TCP_SYN ^(tcp_protocol->tcp_flags)) == 0){//只有在syn的时候，会带上token

						//u_int8_t add_id;//得到id
						//memcpy(&add_id, ppos, sizeof(add_id));
						ppos += 1;
						optLength -= 1;
						length -= 1;

						u_int32_t token;
						memcpy(&token, ppos, sizeof(token));
						ppos += sizeof(token);
						optLength -= sizeof(token);
						length -= sizeof(token);
						subflow_token[sender_ip] = ntohl(token);
						//u_char* ranNum = (u_char*)ppos;

					}else if (toh->length == 24){//第三次握手的时候
						subflow_data[sender_ip] = 0;//目前数据为0
						subflow_data[receiver_ip] = 0;
					}


				}else
				{
					printf("*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-\n");
					printf("unsuppoted st_ver: %x\n", *st_ver);
					printf("*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-\n");
				}
			}else  if (0x00 == toh->kind || 0x02 == toh->kind || 0x03 == toh->kind || 0x04 == toh->kind || 0x05 == toh->kind || 0x08 == toh->kind){//已知的不会造成错误的kind
				//pass
			}else{
				printf("*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-\n");
				printf("unsuppoted option kind: %x\n", toh->kind);
				printf("*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-\n");
			}
			if (length > 0){
				ppos += length;
				optLength -= length;

			}
		}
	}
}

/*      
=======================================================================================================================      
下面是分析TCP协议的函数,其定义方式与回调函数相同      
=======================================================================================================================      
 */    
void tcp_protocol_packet_callback(u_char *argument, const struct pcap_pkthdr *packet_header, const u_char *packet_content)        
{         
    /* TCP协议变量 */    
    //u_char flags;        
    /* 标记 */    
    //int header_length;        
    /* 长度 */    
    //u_short source_port;        
    /* 源端口 */    
    //u_short destination_port;        
    /* 目的端口 */    
    //u_short windows;        
    /* 窗口大小 */    
    //u_short urgent_pointer;        
    /* 紧急指针 */    
    //u_int sequence;        
    /* 序列号 */    
    //u_int acknowledgement;        
    /* 确认号 */    
    //u_int16_t checksum;        
    /* 校验和 */    
    tcp_protocol = (struct tcp_header*)(packet_content + 14+20);        
    /* 获得TCP协议内容 */    
    //source_port = ntohs(tcp_protocol->tcp_source_port);        
    /* 获得源端口 */    
    //destination_port = ntohs(tcp_protocol->tcp_destination_port);        
    /* 获得目的端口 */    
    //header_length = tcp_protocol->tcp_offset *4;        
    /* 长度 */    
    //sequence = ntohl(tcp_protocol->tcp_sequence_lliiuuwweennttaaoo);        
    /* 序列码 */    
    //acknowledgement = ntohl(tcp_protocol->tcp_acknowledgement);        
    /* 确认序列码 */    
    //windows = ntohs(tcp_protocol->tcp_windows);        
    /* 窗口大小 */    
    //urgent_pointer = ntohs(tcp_protocol->tcp_urgent_pointer);        
    /* 紧急指针 */    
    //flags = tcp_protocol->tcp_flags;        
    /* 标识 */    
    //checksum = ntohs(tcp_protocol->tcp_checksum);        
    /* 校验和 */    
    //printf("-------  TCP协议   -------\n");        
    //printf("源端口号:%d\n", source_port);        
    //printf("目的端口号:%d\n", destination_port);        
    /*switch (destination_port)        
    {        
        case 80:        
            printf("上层协议为HTTP协议n");        
            break;        
        case 21:        
            printf("上层协议为FTP协议n");        
            break;        
        case 23:        
            printf("上层协议为TELNET协议n");        
            break;        
        case 25:        
            printf("上层协议为SMTP协议n");        
            break;        
        case 110:        
            printf("上层协议POP3协议n");        
            break;        
        default:        
            break;        
    }        */
    /*printf("序列码:%u\n", sequence);        
    printf("确认号:%u\n", acknowledgement);        
    printf("首部长度:%d\n", header_length);        
    printf("保留:%d\n", tcp_protocol->tcp_reserved);        
    printf("标记:");        
    if (flags &0x08)        
        printf("PSH ");        
    if (flags &0x10)        
        printf("ACK ");        
    if (flags &0x02)        
        printf("SYN ");        
    if (flags &0x20)        
        printf("URG ");        
    if (flags &0x01)        
        printf("FIN ");        
    if (flags &0x04)        
        printf("RST ");        
    printf("\n");        
    printf("窗口大小:%d\n", windows);        
    printf("校验和:%d\n", checksum);        
    printf("紧急指针:%d\n", urgent_pointer);       */

	analize_tcp_option(tcp_protocol, packet_content);

}        
/*      
=======================================================================================================================      
下面是实现UDP协议分析的函数，函数类型与回调函数相同      
=======================================================================================================================      
 */    
void udp_protocol_packet_callback(u_char *argument, const struct pcap_pkthdr *packet_header, const u_char *packet_content)        
{        
    struct udp_header *udp_protocol;        
    /* UDP协议变量 */    
    u_short source_port;        
    /* 源端口 */    
    u_short destination_port;        
    /* 目的端口号 */    
    u_short length;        
    udp_protocol = (struct udp_header*)(packet_content + 14+20);        
    /* 获得UDP协议内容 */    
    source_port = ntohs(udp_protocol->udp_source_port);        
    /* 获得源端口 */    
    destination_port = ntohs(udp_protocol->udp_destination_port);        
    /* 获得目的端口 */    
    length = ntohs(udp_protocol->udp_length);        
    /* 获得长度 */    
    printf("----------  UDP协议    ----------\n");        
    printf("源端口号:%d\n", source_port);        
    printf("目的端口号:%d\n", destination_port);        
    switch (destination_port)        
    {        
        case 138:        
            printf("上层协议为NETBIOS数据报服务\n");        
            break;        
        case 137:        
            printf("上层协议为NETBIOS名字服务\n");        
            break;        
        case 139:        
            printf("上层协议为NETBIOS会话服务\n");        
            break;        
        case 53:        
            printf("上层协议为域名服务\n");        
            break;        
        default:        
            break;        
    }        
    printf("长度:%dn", length);        
    printf("校验和:%dn", ntohs(udp_protocol->udp_checksum));        
}        
/*      
=======================================================================================================================      
下面是实现分析ICMP协议的函数，函数类型与回调函数相同      
=======================================================================================================================      
 */    
void icmp_protocol_packet_callback(u_char *argument, const struct pcap_pkthdr *packet_header, const u_char *packet_content)        
{        
    struct icmp_header *icmp_protocol;        
    /* ICMP协议变量 */    
    icmp_protocol = (struct icmp_header*)(packet_content + 14+20);        
    /* 获得ICMP协议内容 */    
    printf("----------  ICMP协议    ----------\n");        
    printf("ICMP类型:%dn", icmp_protocol->icmp_type);        
    /* 获得ICMP类型 */    
    switch (icmp_protocol->icmp_type)        
    {        
        case 8:        
            printf("ICMP回显请求协议\n");        
            printf("ICMP代码:%d\n", icmp_protocol->icmp_code);        
            printf("标识符:%d\n", icmp_protocol->icmp_id);        
            printf("序列码:%d\n", icmp_protocol->icmp_sequence);        
            break;        
        case 0:        
            printf("ICMP回显应答协议\n");        
            printf("ICMP代码:%d\n", icmp_protocol->icmp_code);        
            printf("标识符:%d\n", icmp_protocol->icmp_id);        
            printf("序列码:%d\n", icmp_protocol->icmp_sequence);        
            break;        
        default:        
            break;        
    }        
    printf("ICMP校验和:%d\n", ntohs(icmp_protocol->icmp_checksum));        
    /* 获得ICMP校验和 */    
    return ;        
}        
/*      
=======================================================================================================================      
下面是实现ARP协议分析的函数，函数类型与回调函数相同      
=======================================================================================================================      
 */    
void arp_protocol_packet_callback(u_char *argument, const struct pcap_pkthdr *packet_header, const u_char *packet_content)        
{        
    struct arp_header *arp_protocol;        
    u_short protocol_type;        
    u_short hardware_type;        
    u_short operation_code;        
    u_char *mac_string;        
    struct in_addr source_ip_address;        
    struct in_addr destination_ip_address;        
    u_char hardware_length;        
    u_char protocol_length;        
    printf("--------   ARP协议    --------\n");        
    arp_protocol = (struct arp_header*)(packet_content + 14);        
    hardware_type = ntohs(arp_protocol->arp_hardware_type);        
    protocol_type = ntohs(arp_protocol->arp_protocol_type);        
    operation_code = ntohs(arp_protocol->arp_operation_code);        
    hardware_length = arp_protocol->arp_hardware_length;        
    protocol_length = arp_protocol->arp_protocol_length;        
    printf("硬件类型:%d\n", hardware_type);        
    printf("协议类型 Protocol Type:%d\n", protocol_type);        
    printf("硬件地址长度:%d\n", hardware_length);        
    printf("协议地址长度:%d\n", protocol_length);        
    printf("ARP Operation:%d\n", operation_code);        
    switch (operation_code)        
    {        
        case 1:        
            printf("ARP请求协议\n");        
            break;        
        case 2:        
            printf("ARP应答协议\n");        
            break;        
        case 3:        
            printf("RARP请求协议\n");        
            break;        
        case 4:        
            printf("RARP应答协议\n");        
            break;        
        default:        
            break;        
    }        
    printf("源以太网地址: \n");        
    mac_string = arp_protocol->arp_source_ethernet_address;        
    printf("%02x:%02x:%02x:%02x:%02x:%02x\n", *mac_string, *(mac_string + 1), *(mac_string + 2), *(mac_string + 3), *(mac_string + 4), *(mac_string + 5));        
    memcpy((void*) &source_ip_address, (void*) &arp_protocol->arp_source_ip_address, sizeof(struct in_addr));        
    printf("源IP地址:%s\n", inet_ntoa(source_ip_address));        
    printf("目的以太网地址: \n");        
    mac_string = arp_protocol->arp_destination_ethernet_address;        
    printf("%02x:%02x:%02x:%02x:%02x:%02x\n", *mac_string, *(mac_string + 1), *(mac_string + 2), *(mac_string + 3), *(mac_string + 4), *(mac_string + 5));        
    memcpy((void*) &destination_ip_address, (void*) &arp_protocol->arp_destination_ip_address, sizeof(struct in_addr));        
    printf("目的IP地址:%s\n", inet_ntoa(destination_ip_address));        
}        
/*      
=======================================================================================================================      
下面是实现IP协议分析的函数，其函数类型与回调函数相同      
=======================================================================================================================      
 */    
void ip_protocol_packet_callback(u_char *argument, const struct pcap_pkthdr *packet_header, const u_char *packet_content)        
{           
    /* IP协议变量 */    
    //u_int header_length;        
    /* 长度 */    
    //u_int offset;        
    /* 偏移 */    
    //u_char tos;        
    /* 服务质量 */    
    //u_int16_t checksum;        
    /* 校验和 */    
    ip_protocol = (struct ip_header*)(packet_content + 14);        
    /* 获得IP协议内容 */    
    //checksum = ntohs(ip_protocol->ip_checksum);        
    /* 获得校验和 */    
    //header_length = ip_protocol->ip_header_length *4;        
    /* 获得长度 */    
    //tos = ip_protocol->ip_tos;        
    /* 获得服务质量 */    
    //offset = ntohs(ip_protocol->ip_off);        
    /* 获得偏移 */    
    //printf("----------- IP协议    -----------\n");        
    //printf("版本号:%d\n", ip_protocol->ip_version);        
    //printf("首部长度:%d\n", header_length);        
    //printf("服务质量:%d\n", tos);        
    //printf("总长度:%d\n", ntohs(ip_protocol->ip_length));        
    //printf("标识:%d\n", ntohs(ip_protocol->ip_id));        
    //printf("偏移:%d\n", (offset &0x1fff) *8);        
    //printf("生存时间:%d\n", ip_protocol->ip_ttl);        
    //printf("协议类型:%d\n", ip_protocol->ip_protocol);        
    /*switch (ip_protocol->ip_protocol)        
    {        
        case 6:        
            printf("上层协议为TCP协议\n");        
            break;        
        case 17:        
            printf("上层协议为UDP协议\n");        
            break;        
        case 1:        
            printf("上层协议为ICMP协议ICMP\n");        
            break;        
        default:        
            break;        
    }       */ 
    //printf("校验和:%d\n", checksum);        
    //printf("源IP地址:%s\n", inet_ntoa(ip_protocol->ip_souce_address));        
    /* 获得源IP地址 */    
    //printf("目的IP地址:%s\n", inet_ntoa(ip_protocol->ip_destination_address));        
    /* 获得目的IP地址 */    
    switch (ip_protocol->ip_protocol) /* 根据IP协议判断上层协议 */    
    {        
        case 6:        
            tcp_protocol_packet_callback(argument, packet_header, packet_content);        
            break;        
            /* 上层协议是TCP协议，调用分析TCP协议的函数，注意参数的传递 */    
        case 17:        
            //udp_protocol_packet_callback(argument, packet_header, packet_content);        
            break;        
            /* 上层协议是UDP协议，调用分析UDP协议的函数，注意参数的传递 */    
        case 1:        
            //icmp_protocol_packet_callback(argument, packet_header, packet_content);        
            break;        
            /* 上层协议是ICMP协议，调用分析ICMP协议的函数，注意参数的传递 */    
        default:        
            break;        
    }        
}        
/*      
=======================================================================================================================      
下面是分析以太网协议的函数，也是回调函数      
=======================================================================================================================      
 */    
void ethernet_protocol_packet_callback(u_char *argument, const struct pcap_pkthdr *packet_header, const u_char *packet_content)        
{        
    packet_number++; 
    u_short ethernet_type;        
    /* 以太网类型 */    
    struct ether_header *ethernet_protocol;        
    /* 以太网协议变量 */    
    //u_char *mac_string;        
    /* 以太网地址 */    
    
    //printf("**************************************************\n");        
    //printf("捕获第%d个网络数据包\n", packet_number);        
    //printf("捕获时间:\n");        
    //printf("%s\n", ctime((const time_t*) &packet_header->ts.tv_sec));        
    /* 获得捕获数据包的时间 */    
    //printf("数据包长度:\n");        
    //printf("%d\n", packet_header->len);        
    //printf("--------   以太网协议    --------\n");        
    ethernet_protocol = (struct ether_header*)packet_content;        
    /* 获得以太网协议内容 */    
    //printf("类型:\n");        
    ethernet_type = ntohs(ethernet_protocol->ether_type);        
    /* 获得以太网类型 */    
    //printf("%04x\n", ethernet_type);        
    //switch (ethernet_type) /* 根据以太网类型判断 */    
    //{        
    //    case 0x0800:        
    //        printf("上层协议为IP协议\n");        
    //        break;        
    //    case 0x0806:        
    //        printf("上层协议为ARP协议\n");        
    //        break;        
    //    case 0x8035:        
    //        printf("上层协议为RARP协议\n");        
    //        break;        
    //    default:        
    //        break;        
    //}        
    //printf("源以太网地址: \n");        
    //mac_string = ethernet_protocol->ether_shost;        
    //printf("%02x:%02x:%02x:%02x:%02x:%02x\n", *mac_string, *(mac_string + 1), *(mac_string + 2), *(mac_string + 3), *(mac_string + 4), *(mac_string + 5));        
    /* 获得源以太网地址 */    
    //printf("目的以太网地址: \n");        
    //mac_string = ethernet_protocol->ether_dhost;        
    //printf("%02x:%02x:%02x:%02x:%02x:%02x\n", *mac_string, *(mac_string + 1), *(mac_string + 2), *(mac_string + 3), *(mac_string + 4), *(mac_string + 5));        
    /* 获得目的以太网地址 */    
    switch (ethernet_type)        
    {        
        case 0x0806:        
            //arp_protocol_packet_callback(argument, packet_header, packet_content);        
            break;        
            /* 上层协议为ARP协议，调用分析ARP协议的函数，注意参数的传递 */    
        case 0x0800:        
            ip_protocol_packet_callback(argument, packet_header, packet_content);        
            break;        
            /* 上层协议为IP协议，调用分析IP协议的函数，注意参数的传递 */    
        default:        
            break;        
    }        
    //printf("**************************************************\n");               
}        
/*      
=======================================================================================================================      
主函数      
=======================================================================================================================      
 */    


void dispatcher_handler(u_char *temp1,
                        const struct pcap_pkthdr *header, const u_char *pkt_data);

int main(int argc,char *argv[])
{
	if(argc < 2){
		fprintf(stderr,"\nError. Usage: mptcp.exe filename.\nPress any key to exit...\n");
		getchar();
		return -1;
	}

	char * pcap_file = argv[1];

    pcap_t *fp;
    char errbuf[PCAP_ERRBUF_SIZE];
    char source[PCAP_BUF_SIZE];
    
 


    /* 根据新WinPcap语法创建一个源字符串 */
    if ( pcap_createsrcstr( source,         // 源字符串
                            PCAP_SRC_FILE,  // 我们要打开的文件
                            NULL,           // 远程主机
                            NULL,           // 远程主机端口
                            pcap_file,        // 我们要打开的文件名
                            errbuf          // 错误缓冲区
                          ) != 0)
    {
        fprintf(stderr,"\nError creating a source string\nPress any key to exit...\n");
		getchar();
        return -1;
    }
 
    /* 打开捕获文件 */
    if ( (fp= pcap_open(source,         // 设备名
                        65536,          // 要捕捉的数据包的部分
                        // 65535保证能捕获到不同数据链路层上的每个数据包的全部内容
                        PCAP_OPENFLAG_PROMISCUOUS,     // 混杂模式
                        1000,              // 读取超时时间
                        NULL,              // 远程机器验证
                        errbuf         // 错误缓冲池
                       ) ) == NULL)
    {
        fprintf(stderr,"\nUnable to open the file %s.\nPress any key to exit...\n", source);
		getchar();
        return -1;
    }
 
    // 读取并解析数据包，直到EOF为真
    pcap_loop(fp, 0, dispatcher_handler, NULL);
 
//u_int64_t*												sender_key;//发送者的hmac sha1 key
//u_int64_t*												receiver_key;//接收者的hmac sha1 key
//u_int32_t													sender_ip;//发送者的hmac sha1 key
//u_int32_t													receiver_ip;//接收者的hmac sha1 key
//std::vector<u_int32_t>									sender_ips;// 所有senders的ip
//std::vector<u_int32_t>									receiver_ips;// 所有receivers的ip
//std::vector<u_int64_t>									sender_keys;// 所有senders的key
//std::vector<u_int64_t>									receiver_keys;// 所有receivers的key
//std::map<u_int32_t, std::map<u_int8_t, u_int32_t>>		subflows;//主ip-子ip
//std::map<u_int32_t, u_int64_t>							subflow_data;//子ip-数据量
//std::map<u_int32_t, u_int32_t>							subflow_token;//子ip-token

	in_addr addr;
	std::map<u_int8_t , subflow_hosts>::iterator l_it;
	//std::map<u_int8_t, u_int32_t> subflow_ips;

	printf("total MPTCP connections: %d \n\n", sender_ips.size());

	for (int i=0; i<sender_ips.size(); ++i){
		addr.s_addr = sender_ips[i];
		printf("client: %s <---> ", inet_ntoa(addr));
		addr.s_addr = receiver_ips[i];
		printf("server: %s, subflow connections: %d\n", inet_ntoa(addr), subflows[sender_ips[i]].size() - 1);

		//subflow_ips = subflows[sender_ips[i]];
		for (l_it = subflows[sender_ips[i]].begin(); l_it != subflows[sender_ips[i]].end(); ++l_it){
			if (l_it->first == 0){
				printf("\tnormal exchanged data: %d bytes.\n", subflow_data[subflows[sender_ips[i]][0].ip1] + subflow_data[subflows[sender_ips[i]][0].ip2]);
			}else{
				subflow_data[subflows[sender_ips[i]][0].ip1] += subflow_data[l_it->second.ip1];//统计
				subflow_data[subflows[sender_ips[i]][0].ip2] += subflow_data[l_it->second.ip2];//统计

				addr.s_addr = l_it->second.ip1;
				printf("\tsubflow %02d: %s <---> ", l_it->first, inet_ntoa(addr));
				addr.s_addr = l_it->second.ip2;
				printf("%s;\n", inet_ntoa(addr));
				printf("\t token is: %x. ", subflow_token[l_it->second.ip1]);
				printf("\t exchanged data: %d bytes. \n", subflow_data[l_it->second.ip1] + subflow_data[l_it->second.ip2]);
			}
		}

		printf("\ttotal exchanged data: %d bytes. \n", subflow_data[subflows[sender_ips[i]][0].ip1] + subflow_data[subflows[sender_ips[i]][0].ip1]);

		printf("\n");



	}

	printf("Press any key to exit...\n");
	getchar();
    return 0;
}

void dispatcher_handler(u_char *temp1,
                        const struct pcap_pkthdr *header, const u_char *pkt_data)
{
    //u_int i=0;
 
    ///* 打印pkt时间戳和pkt长度 */
    //printf("%ld:%ld (%u)\n", header->ts.tv_sec, header->ts.tv_usec, header->len);
    ///* 打印数据包 */
    //for (i=1; (i < header->caplen + 1 ) ; i++)
    //{
    //    printf("%.2x ", pkt_data[i-1]);
    //    if ( (i % LINE_LEN) == 0) printf("\n");
    //}
 
    //printf("\n\n");
	
	ethernet_protocol_packet_callback(temp1, header, pkt_data);


}