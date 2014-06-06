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
/* ���ݰ�������ȫ�ֱ��� */    
/*  analize_tcp_option ��Ҫʹ�õ����ݽṹ������ÿ�ζ�����  */
const u_char*											ppos;//Ŀǰ����������
struct ip_header *										ip_protocol;// IPͷ
struct tcp_header *										tcp_protocol;//TCPͷ
struct tcp_options_header*								toh;//TCP���ݰ���Option����
struct mptp_data_header*								mdh;//mptcp ��������ʱʹ�õ�ͷ��
u_int8_t												type;//���ڸ������ݰ����ж����ݰ������õ�
u_int8_t*												st_ver;//mptcp subtype & version
u_int8_t*												mp_flag;//mptcp flag
int64_t													optLength;//option ʣ�೤��
int64_t													length;//���ݰ������ݴ�С
u_int64_t*												sender_key;//�����ߵ�hmac sha1 key
u_int64_t*												receiver_key;//�����ߵ�hmac sha1 key
u_int32_t												sender_ip;//�����ߵ�hmac sha1 key
u_int32_t												receiver_ip;//�����ߵ�hmac sha1 key
u_int32_t												acked;//�Ѿ�ȷ���յ���ack����
u_int32_t												seq;//�Ѿ����ͳ�ȥ������
std::vector<u_int32_t>									sender_ips;// ����senders��ip
std::vector<u_int32_t>									receiver_ips;// ����receivers��ip
std::vector<u_int64_t>									sender_keys;// ����senders��key
std::vector<u_int64_t>									receiver_keys;// ����receivers��key
std::map<u_int32_t, std::map<u_int8_t, subflow_hosts>>	subflows;//��ip-��ip
std::map<u_int32_t, u_int64_t>							subflow_data;//��ip-������
std::map<u_int32_t, u_int32_t>							subflow_token;//��ip-token
std::map<u_int32_t, std::list<u_int64_t>>				sent_seq;//ip-�Ѿ����ͳ�ȥ�����к�
std::map<u_int64_t, u_int16_t>							sent_data;//�Ѿ����ͳ�ȥ���ֽ���

void analize_tcp_option(const struct tcp_header *tcp_protocol, const u_char *packet_content)
{
	
	optLength = tcp_protocol->tcp_offset*4 - sizeof(struct tcp_header);
	ppos = packet_content + 14 + 20 + sizeof(struct tcp_header);//����option��λ��
	
	while(optLength > 0){//tcp���ж��option
		toh = (struct tcp_options_header*)ppos;
		optLength -= sizeof(struct tcp_options_header);
		ppos += sizeof(struct tcp_options_header);

		//printf("option kind: %x\n", toh->kind);

		if (TCP_NO_OPER == toh->kind){//���۵�Non-Operation �����һ�ֽڣ�����ȥһ��
			ppos -= 1;
			optLength +=1;
		}else{
			length = toh->length - sizeof(struct tcp_options_header);//ͷ���Լ�ռ2�����ֽ�
			if (TCP_MPTCP_OPTION == toh->kind){//mptcp
					
				sender_ip = ip_protocol->ip_souce_address.s_addr;
				receiver_ip = ip_protocol->ip_destination_address.s_addr;
					
				st_ver = (u_int8_t*)ppos;//��ȡsubtype��version
				optLength -= sizeof(u_int8_t);
				ppos += sizeof(u_int8_t);
				length -= sizeof(u_int8_t);
				if (MPTCP_NO_TYPE_NO_VERSION == *st_ver){//ȫ0������ǻ������ֵ�ʱ��
					mp_flag = (u_int8_t*)ppos;//�����flagӦ����0x81
					optLength -= sizeof(u_int8_t);
					ppos += sizeof(u_int8_t);
					length -= sizeof(u_int8_t);

					if (MPTCP_EXCHANGE_KEY == *mp_flag){
						sender_key = (u_int64_t*)ppos;
						optLength -= sizeof(u_int64_t);
						ppos += sizeof(u_int64_t);
						length -= sizeof(u_int64_t);
						if (length > 0){//ֻ�е��������ֵ�ʱ��˫������key

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

							subflow_data[sender_ip] = 0;//Ŀǰ����Ϊ0
							subflow_data[receiver_ip] = 0;//Ŀǰ����Ϊ0

							std::list<u_int64_t> reqs;
							sent_seq[sender_ip] = reqs;
						}
					}else
					{
						printf("*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-\n");
						printf("unsuppoted flag in st_ver 00: %x\n", *mp_flag);
						printf("*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-\n");
					}
				}else if ((MPTCP_ADD_ADDRESS & (*st_ver)) == MPTCP_ADD_ADDRESS){//0x3*��ʾ���address

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

					if (find(sender_ips.begin(), sender_ips.end(), sender_ip) == sender_ips.end()){//�Ƿ�����Ҫ����ip��ַ
						subflows[receiver_ip][add_id].ip2 = sub_ip;
					}else{//�϶����ǿͻ�����Ҫ�����ip��
						subflow_hosts sh;
						sh.ip1 = sub_ip;
						subflows[sender_ip][add_id] = sh;
					}

					//subflow_data[sub_ip] = 0;//Ŀǰ����Ϊ0

				}else if ((MPTCP_SEND_PACKET & (*st_ver)) == MPTCP_SEND_PACKET){//0x2*��ʾ��������
					mp_flag = (u_int8_t*)ppos;
					ppos += 1;//��ȥflag
					optLength -= 1;
					length -= 1;

					mdh = (mptp_data_header*)ppos;
					if (MPTCP_ACK & *mp_flag){//�лظ�ACK������һ����
						ppos += 4;
						optLength -= 4;
						length -= 4;
						
						acked = ntohl(mdh->ack_num);
						if (sent_seq.find(receiver_ip) != sent_seq.end()){//�����Է��ǲ��������������ݰ�
							while(true ){
								if (0 == sent_seq[receiver_ip].size()){
									break;
								}
								seq = sent_seq[receiver_ip].front();
								if (seq < acked){
									subflow_data[receiver_ip] += sent_data[seq];//�����ۼ�
									sent_seq[receiver_ip].pop_front();
									sent_data.erase(seq);
								}else{
									break;
								}
							}
						}
					}
					if (MPTCP_DSDC & *mp_flag){//�з�������
						ppos += 12;
						optLength -= 12;
						length -= 12;

						seq = ntohl(mdh->sequence_num);
						if ((sent_seq[sender_ip].size() == 0) || (seq > sent_seq[sender_ip].back())){//�����ش���ʱ�򣬲���Ҫ�ٴβ��룬����Ҳ�������˳����
							sent_seq[sender_ip].push_back(seq);
							sent_data[seq] = ntohs(mdh->data_length);//�����ݴ�
						}
						
					}
				}else if ((MPTCP_JOIN & (*st_ver)) == MPTCP_JOIN){//0x1*��ʾ��������
					if ((TCP_SYN ^(tcp_protocol->tcp_flags)) == 0){//ֻ����syn��ʱ�򣬻����token

						//u_int8_t add_id;//�õ�id
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

					}else if (toh->length == 24){//���������ֵ�ʱ��
						subflow_data[sender_ip] = 0;//Ŀǰ����Ϊ0
						subflow_data[receiver_ip] = 0;
					}


				}else
				{
					printf("*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-\n");
					printf("unsuppoted st_ver: %x\n", *st_ver);
					printf("*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-\n");
				}
			}else  if (0x00 == toh->kind || 0x02 == toh->kind || 0x03 == toh->kind || 0x04 == toh->kind || 0x05 == toh->kind || 0x08 == toh->kind){//��֪�Ĳ�����ɴ����kind
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
�����Ƿ���TCPЭ��ĺ���,�䶨�巽ʽ��ص�������ͬ      
=======================================================================================================================      
 */    
void tcp_protocol_packet_callback(u_char *argument, const struct pcap_pkthdr *packet_header, const u_char *packet_content)        
{         
    /* TCPЭ����� */    
    //u_char flags;        
    /* ��� */    
    //int header_length;        
    /* ���� */    
    //u_short source_port;        
    /* Դ�˿� */    
    //u_short destination_port;        
    /* Ŀ�Ķ˿� */    
    //u_short windows;        
    /* ���ڴ�С */    
    //u_short urgent_pointer;        
    /* ����ָ�� */    
    //u_int sequence;        
    /* ���к� */    
    //u_int acknowledgement;        
    /* ȷ�Ϻ� */    
    //u_int16_t checksum;        
    /* У��� */    
    tcp_protocol = (struct tcp_header*)(packet_content + 14+20);        
    /* ���TCPЭ������ */    
    //source_port = ntohs(tcp_protocol->tcp_source_port);        
    /* ���Դ�˿� */    
    //destination_port = ntohs(tcp_protocol->tcp_destination_port);        
    /* ���Ŀ�Ķ˿� */    
    //header_length = tcp_protocol->tcp_offset *4;        
    /* ���� */    
    //sequence = ntohl(tcp_protocol->tcp_sequence_lliiuuwweennttaaoo);        
    /* ������ */    
    //acknowledgement = ntohl(tcp_protocol->tcp_acknowledgement);        
    /* ȷ�������� */    
    //windows = ntohs(tcp_protocol->tcp_windows);        
    /* ���ڴ�С */    
    //urgent_pointer = ntohs(tcp_protocol->tcp_urgent_pointer);        
    /* ����ָ�� */    
    //flags = tcp_protocol->tcp_flags;        
    /* ��ʶ */    
    //checksum = ntohs(tcp_protocol->tcp_checksum);        
    /* У��� */    
    //printf("-------  TCPЭ��   -------\n");        
    //printf("Դ�˿ں�:%d\n", source_port);        
    //printf("Ŀ�Ķ˿ں�:%d\n", destination_port);        
    /*switch (destination_port)        
    {        
        case 80:        
            printf("�ϲ�Э��ΪHTTPЭ��n");        
            break;        
        case 21:        
            printf("�ϲ�Э��ΪFTPЭ��n");        
            break;        
        case 23:        
            printf("�ϲ�Э��ΪTELNETЭ��n");        
            break;        
        case 25:        
            printf("�ϲ�Э��ΪSMTPЭ��n");        
            break;        
        case 110:        
            printf("�ϲ�Э��POP3Э��n");        
            break;        
        default:        
            break;        
    }        */
    /*printf("������:%u\n", sequence);        
    printf("ȷ�Ϻ�:%u\n", acknowledgement);        
    printf("�ײ�����:%d\n", header_length);        
    printf("����:%d\n", tcp_protocol->tcp_reserved);        
    printf("���:");        
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
    printf("���ڴ�С:%d\n", windows);        
    printf("У���:%d\n", checksum);        
    printf("����ָ��:%d\n", urgent_pointer);       */

	analize_tcp_option(tcp_protocol, packet_content);

}        
/*      
=======================================================================================================================      
������ʵ��UDPЭ������ĺ���������������ص�������ͬ      
=======================================================================================================================      
 */    
void udp_protocol_packet_callback(u_char *argument, const struct pcap_pkthdr *packet_header, const u_char *packet_content)        
{        
    struct udp_header *udp_protocol;        
    /* UDPЭ����� */    
    u_short source_port;        
    /* Դ�˿� */    
    u_short destination_port;        
    /* Ŀ�Ķ˿ں� */    
    u_short length;        
    udp_protocol = (struct udp_header*)(packet_content + 14+20);        
    /* ���UDPЭ������ */    
    source_port = ntohs(udp_protocol->udp_source_port);        
    /* ���Դ�˿� */    
    destination_port = ntohs(udp_protocol->udp_destination_port);        
    /* ���Ŀ�Ķ˿� */    
    length = ntohs(udp_protocol->udp_length);        
    /* ��ó��� */    
    printf("----------  UDPЭ��    ----------\n");        
    printf("Դ�˿ں�:%d\n", source_port);        
    printf("Ŀ�Ķ˿ں�:%d\n", destination_port);        
    switch (destination_port)        
    {        
        case 138:        
            printf("�ϲ�Э��ΪNETBIOS���ݱ�����\n");        
            break;        
        case 137:        
            printf("�ϲ�Э��ΪNETBIOS���ַ���\n");        
            break;        
        case 139:        
            printf("�ϲ�Э��ΪNETBIOS�Ự����\n");        
            break;        
        case 53:        
            printf("�ϲ�Э��Ϊ��������\n");        
            break;        
        default:        
            break;        
    }        
    printf("����:%dn", length);        
    printf("У���:%dn", ntohs(udp_protocol->udp_checksum));        
}        
/*      
=======================================================================================================================      
������ʵ�ַ���ICMPЭ��ĺ���������������ص�������ͬ      
=======================================================================================================================      
 */    
void icmp_protocol_packet_callback(u_char *argument, const struct pcap_pkthdr *packet_header, const u_char *packet_content)        
{        
    struct icmp_header *icmp_protocol;        
    /* ICMPЭ����� */    
    icmp_protocol = (struct icmp_header*)(packet_content + 14+20);        
    /* ���ICMPЭ������ */    
    printf("----------  ICMPЭ��    ----------\n");        
    printf("ICMP����:%dn", icmp_protocol->icmp_type);        
    /* ���ICMP���� */    
    switch (icmp_protocol->icmp_type)        
    {        
        case 8:        
            printf("ICMP��������Э��\n");        
            printf("ICMP����:%d\n", icmp_protocol->icmp_code);        
            printf("��ʶ��:%d\n", icmp_protocol->icmp_id);        
            printf("������:%d\n", icmp_protocol->icmp_sequence);        
            break;        
        case 0:        
            printf("ICMP����Ӧ��Э��\n");        
            printf("ICMP����:%d\n", icmp_protocol->icmp_code);        
            printf("��ʶ��:%d\n", icmp_protocol->icmp_id);        
            printf("������:%d\n", icmp_protocol->icmp_sequence);        
            break;        
        default:        
            break;        
    }        
    printf("ICMPУ���:%d\n", ntohs(icmp_protocol->icmp_checksum));        
    /* ���ICMPУ��� */    
    return ;        
}        
/*      
=======================================================================================================================      
������ʵ��ARPЭ������ĺ���������������ص�������ͬ      
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
    printf("--------   ARPЭ��    --------\n");        
    arp_protocol = (struct arp_header*)(packet_content + 14);        
    hardware_type = ntohs(arp_protocol->arp_hardware_type);        
    protocol_type = ntohs(arp_protocol->arp_protocol_type);        
    operation_code = ntohs(arp_protocol->arp_operation_code);        
    hardware_length = arp_protocol->arp_hardware_length;        
    protocol_length = arp_protocol->arp_protocol_length;        
    printf("Ӳ������:%d\n", hardware_type);        
    printf("Э������ Protocol Type:%d\n", protocol_type);        
    printf("Ӳ����ַ����:%d\n", hardware_length);        
    printf("Э���ַ����:%d\n", protocol_length);        
    printf("ARP Operation:%d\n", operation_code);        
    switch (operation_code)        
    {        
        case 1:        
            printf("ARP����Э��\n");        
            break;        
        case 2:        
            printf("ARPӦ��Э��\n");        
            break;        
        case 3:        
            printf("RARP����Э��\n");        
            break;        
        case 4:        
            printf("RARPӦ��Э��\n");        
            break;        
        default:        
            break;        
    }        
    printf("Դ��̫����ַ: \n");        
    mac_string = arp_protocol->arp_source_ethernet_address;        
    printf("%02x:%02x:%02x:%02x:%02x:%02x\n", *mac_string, *(mac_string + 1), *(mac_string + 2), *(mac_string + 3), *(mac_string + 4), *(mac_string + 5));        
    memcpy((void*) &source_ip_address, (void*) &arp_protocol->arp_source_ip_address, sizeof(struct in_addr));        
    printf("ԴIP��ַ:%s\n", inet_ntoa(source_ip_address));        
    printf("Ŀ����̫����ַ: \n");        
    mac_string = arp_protocol->arp_destination_ethernet_address;        
    printf("%02x:%02x:%02x:%02x:%02x:%02x\n", *mac_string, *(mac_string + 1), *(mac_string + 2), *(mac_string + 3), *(mac_string + 4), *(mac_string + 5));        
    memcpy((void*) &destination_ip_address, (void*) &arp_protocol->arp_destination_ip_address, sizeof(struct in_addr));        
    printf("Ŀ��IP��ַ:%s\n", inet_ntoa(destination_ip_address));        
}        
/*      
=======================================================================================================================      
������ʵ��IPЭ������ĺ������亯��������ص�������ͬ      
=======================================================================================================================      
 */    
void ip_protocol_packet_callback(u_char *argument, const struct pcap_pkthdr *packet_header, const u_char *packet_content)        
{           
    /* IPЭ����� */    
    //u_int header_length;        
    /* ���� */    
    //u_int offset;        
    /* ƫ�� */    
    //u_char tos;        
    /* �������� */    
    //u_int16_t checksum;        
    /* У��� */    
    ip_protocol = (struct ip_header*)(packet_content + 14);        
    /* ���IPЭ������ */    
    //checksum = ntohs(ip_protocol->ip_checksum);        
    /* ���У��� */    
    //header_length = ip_protocol->ip_header_length *4;        
    /* ��ó��� */    
    //tos = ip_protocol->ip_tos;        
    /* ��÷������� */    
    //offset = ntohs(ip_protocol->ip_off);        
    /* ���ƫ�� */    
    //printf("----------- IPЭ��    -----------\n");        
    //printf("�汾��:%d\n", ip_protocol->ip_version);        
    //printf("�ײ�����:%d\n", header_length);        
    //printf("��������:%d\n", tos);        
    //printf("�ܳ���:%d\n", ntohs(ip_protocol->ip_length));        
    //printf("��ʶ:%d\n", ntohs(ip_protocol->ip_id));        
    //printf("ƫ��:%d\n", (offset &0x1fff) *8);        
    //printf("����ʱ��:%d\n", ip_protocol->ip_ttl);        
    //printf("Э������:%d\n", ip_protocol->ip_protocol);        
    /*switch (ip_protocol->ip_protocol)        
    {        
        case 6:        
            printf("�ϲ�Э��ΪTCPЭ��\n");        
            break;        
        case 17:        
            printf("�ϲ�Э��ΪUDPЭ��\n");        
            break;        
        case 1:        
            printf("�ϲ�Э��ΪICMPЭ��ICMP\n");        
            break;        
        default:        
            break;        
    }       */ 
    //printf("У���:%d\n", checksum);        
    //printf("ԴIP��ַ:%s\n", inet_ntoa(ip_protocol->ip_souce_address));        
    /* ���ԴIP��ַ */    
    //printf("Ŀ��IP��ַ:%s\n", inet_ntoa(ip_protocol->ip_destination_address));        
    /* ���Ŀ��IP��ַ */    
    switch (ip_protocol->ip_protocol) /* ����IPЭ���ж��ϲ�Э�� */    
    {        
        case 6:        
            tcp_protocol_packet_callback(argument, packet_header, packet_content);        
            break;        
            /* �ϲ�Э����TCPЭ�飬���÷���TCPЭ��ĺ�����ע������Ĵ��� */    
        case 17:        
            //udp_protocol_packet_callback(argument, packet_header, packet_content);        
            break;        
            /* �ϲ�Э����UDPЭ�飬���÷���UDPЭ��ĺ�����ע������Ĵ��� */    
        case 1:        
            //icmp_protocol_packet_callback(argument, packet_header, packet_content);        
            break;        
            /* �ϲ�Э����ICMPЭ�飬���÷���ICMPЭ��ĺ�����ע������Ĵ��� */    
        default:        
            break;        
    }        
}        
/*      
=======================================================================================================================      
�����Ƿ�����̫��Э��ĺ�����Ҳ�ǻص�����      
=======================================================================================================================      
 */    
void ethernet_protocol_packet_callback(u_char *argument, const struct pcap_pkthdr *packet_header, const u_char *packet_content)        
{        
    packet_number++; 
    u_short ethernet_type;        
    /* ��̫������ */    
    struct ether_header *ethernet_protocol;        
    /* ��̫��Э����� */    
    //u_char *mac_string;        
    /* ��̫����ַ */    
    
    //printf("**************************************************\n");        
    //printf("�����%d���������ݰ�\n", packet_number);        
    //printf("����ʱ��:\n");        
    //printf("%s\n", ctime((const time_t*) &packet_header->ts.tv_sec));        
    /* ��ò������ݰ���ʱ�� */    
    //printf("���ݰ�����:\n");        
    //printf("%d\n", packet_header->len);        
    //printf("--------   ��̫��Э��    --------\n");        
    ethernet_protocol = (struct ether_header*)packet_content;        
    /* �����̫��Э������ */    
    //printf("����:\n");        
    ethernet_type = ntohs(ethernet_protocol->ether_type);        
    /* �����̫������ */    
    //printf("%04x\n", ethernet_type);        
    //switch (ethernet_type) /* ������̫�������ж� */    
    //{        
    //    case 0x0800:        
    //        printf("�ϲ�Э��ΪIPЭ��\n");        
    //        break;        
    //    case 0x0806:        
    //        printf("�ϲ�Э��ΪARPЭ��\n");        
    //        break;        
    //    case 0x8035:        
    //        printf("�ϲ�Э��ΪRARPЭ��\n");        
    //        break;        
    //    default:        
    //        break;        
    //}        
    //printf("Դ��̫����ַ: \n");        
    //mac_string = ethernet_protocol->ether_shost;        
    //printf("%02x:%02x:%02x:%02x:%02x:%02x\n", *mac_string, *(mac_string + 1), *(mac_string + 2), *(mac_string + 3), *(mac_string + 4), *(mac_string + 5));        
    /* ���Դ��̫����ַ */    
    //printf("Ŀ����̫����ַ: \n");        
    //mac_string = ethernet_protocol->ether_dhost;        
    //printf("%02x:%02x:%02x:%02x:%02x:%02x\n", *mac_string, *(mac_string + 1), *(mac_string + 2), *(mac_string + 3), *(mac_string + 4), *(mac_string + 5));        
    /* ���Ŀ����̫����ַ */    
    switch (ethernet_type)        
    {        
        case 0x0806:        
            //arp_protocol_packet_callback(argument, packet_header, packet_content);        
            break;        
            /* �ϲ�Э��ΪARPЭ�飬���÷���ARPЭ��ĺ�����ע������Ĵ��� */    
        case 0x0800:        
            ip_protocol_packet_callback(argument, packet_header, packet_content);        
            break;        
            /* �ϲ�Э��ΪIPЭ�飬���÷���IPЭ��ĺ�����ע������Ĵ��� */    
        default:        
            break;        
    }        
    //printf("**************************************************\n");               
}        
/*      
=======================================================================================================================      
������      
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
    
 


    /* ������WinPcap�﷨����һ��Դ�ַ��� */
    if ( pcap_createsrcstr( source,         // Դ�ַ���
                            PCAP_SRC_FILE,  // ����Ҫ�򿪵��ļ�
                            NULL,           // Զ������
                            NULL,           // Զ�������˿�
                            pcap_file,        // ����Ҫ�򿪵��ļ���
                            errbuf          // ���󻺳���
                          ) != 0)
    {
        fprintf(stderr,"\nError creating a source string\nPress any key to exit...\n");
		getchar();
        return -1;
    }
 
    /* �򿪲����ļ� */
    if ( (fp= pcap_open(source,         // �豸��
                        65536,          // Ҫ��׽�����ݰ��Ĳ���
                        // 65535��֤�ܲ��񵽲�ͬ������·���ϵ�ÿ�����ݰ���ȫ������
                        PCAP_OPENFLAG_PROMISCUOUS,     // ����ģʽ
                        1000,              // ��ȡ��ʱʱ��
                        NULL,              // Զ�̻�����֤
                        errbuf         // ���󻺳��
                       ) ) == NULL)
    {
        fprintf(stderr,"\nUnable to open the file %s.\nPress any key to exit...\n", source);
		getchar();
        return -1;
    }
 
    // ��ȡ���������ݰ���ֱ��EOFΪ��
    pcap_loop(fp, 0, dispatcher_handler, NULL);
 
//u_int64_t*												sender_key;//�����ߵ�hmac sha1 key
//u_int64_t*												receiver_key;//�����ߵ�hmac sha1 key
//u_int32_t													sender_ip;//�����ߵ�hmac sha1 key
//u_int32_t													receiver_ip;//�����ߵ�hmac sha1 key
//std::vector<u_int32_t>									sender_ips;// ����senders��ip
//std::vector<u_int32_t>									receiver_ips;// ����receivers��ip
//std::vector<u_int64_t>									sender_keys;// ����senders��key
//std::vector<u_int64_t>									receiver_keys;// ����receivers��key
//std::map<u_int32_t, std::map<u_int8_t, u_int32_t>>		subflows;//��ip-��ip
//std::map<u_int32_t, u_int64_t>							subflow_data;//��ip-������
//std::map<u_int32_t, u_int32_t>							subflow_token;//��ip-token

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
				subflow_data[subflows[sender_ips[i]][0].ip1] += subflow_data[l_it->second.ip1];//ͳ��
				subflow_data[subflows[sender_ips[i]][0].ip2] += subflow_data[l_it->second.ip2];//ͳ��

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
 
    ///* ��ӡpktʱ�����pkt���� */
    //printf("%ld:%ld (%u)\n", header->ts.tv_sec, header->ts.tv_usec, header->len);
    ///* ��ӡ���ݰ� */
    //for (i=1; (i < header->caplen + 1 ) ; i++)
    //{
    //    printf("%.2x ", pkt_data[i-1]);
    //    if ( (i % LINE_LEN) == 0) printf("\n");
    //}
 
    //printf("\n\n");
	
	ethernet_protocol_packet_callback(temp1, header, pkt_data);


}