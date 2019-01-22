#ifndef __EXPORT_H
#define __EXPORT_H

#pragma once

#include "common.h"

//L4
#define TCP 0x06
#define UDP 0x11
#define ICMP 0x01

//TCP Flags
#define URG 0x20	//0010 0000
#define ACK 0x10	//0001 0000
#define PSH 0x08	//0000 1000
#define RST 0x04	//0000 0100
#define SYN 0x02	//0000 0010
#define FIN 0x01	//0000 0001

#define ARP_REQUSET 0x0001
#define ARP_REPLY 0x0002
#define RARP_REQUSET 0x0003
#define RARP_REPLY 0x0004
#define ETHER_ADDR_LEN 6
#define IP_HEADER 0x0800
#define ARP_HEADER 0x0806
#define REVERSE_ARP_HEADER 0x0835

ㅁ
typedef struct mac_address	
{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
	u_char byte5;
	u_char byte6;
}mac;

typedef struct IP_address
{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_addr;

typedef struct arp_header
{
	u_short ht;		//hardware type
	u_short pt;		//upper protocol type
	u_char hl;		//hardware length
	u_char pl;		//protocole length
	u_short op;		//operation
	mac SenderHA;	//Sender Hardware address
	ip_addr SIA;	//Sender IP address
	mac TargetHA;   //Receiver Hardware address
	ip_addr TIA;	//Receiver IP address
}arp_h;


typedef struct ether_header		//이더넷 헤더 구조체
{
	u_char ether_dhost[ETHER_ADDR_LEN];	//목적지 MAC주소
	u_char ether_shost[ETHER_ADDR_LEN];	//송신지 MAC주소
	u_short ether_type;					//type or Length (상위 프로토콜)
}eth_h;

typedef struct ip_header
{
	u_char ip_leng : 4;					//헤더 길이
	u_char ip_version:4 ;
	u_char tos;							//type of service
	u_short total_length;				//헤더와 데이터 길이를 포함한 전체 길이
	u_short identification;				//Identification필드는 패킷의 유일한 식별자로서 각각의 IP패킷을 유일하게 구분해 준다.
										//특히 패킷이 단편화 되었을 때 사용되는 부분으로써 어떤 원본의 일부임을 나타내는지를 알리는 부분이기도 하다
	u_short Fragment_offset;
	u_char ttl;
	u_char upper_protocol;
	u_short header_checksum;
	ip_addr src;
	ip_addr dst;
	u_int options;
}ip_header;


typedef struct tcp_header
{
	u_short SrcPort;		//Source Port
	u_short DstPort;		//Destination Port
	u_int Seq_Num;			//Sequence Number 
	u_int Ack_Num;			//Acknowledgement number
	u_char tcp_h_offset:4;	//Header Length	(Data offset)
	u_char tcp_h_Len : 4;
	u_char Flags;			//Control Flags( U A P R S F )
	u_short WinSize;		//Window Size
	u_short CRC;			//CheckSum
	u_short UrgPtr;			//Urgent Pointer
}tcp_header;

typedef struct udp_header
{
	u_short Src_Port;		//Source Port
	u_short Dst_Port;		//Destination Port
	u_short Length;			//UDP header and the Encapsulatied data Lenghth
	u_short CRC;			//Checksum
}udp_header; 

void Print_Ethernet_Header(const u_char *pkt_Data);
void Print_ARP_HEADER(const u_char *pkt_data);
void Print_IP_HEADER(const u_char *pkt_data);
void Print_UDP_HEADER(const u_char *pkt_data);
void Print_TCP_HEADER(const u_char *pkt_data);











#endif
