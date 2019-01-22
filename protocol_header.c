#include "export.h"

//Print Ethernet Header
void Print_Ethernet_Header(const u_char *pkt_Data)
{
	mac *dstmac;
	mac *srcmac;

	dstmac = (mac *)pkt_Data;
	srcmac = (mac *)(pkt_Data + 6);

	printf("*************** Ethernet Frame Header ***************\n\n\n");
	printf("Destination Mac Address : %02x.%02x.%02x.%02x.%02x.%02x \n",
		dstmac->byte1,
		dstmac->byte2,
		dstmac->byte3,
		dstmac->byte4,
		dstmac->byte5,
		dstmac->byte6);

	printf("Source Mac Address : %02x.%02x.%02x.%02x.%02x.%02x \n",
		srcmac->byte1,
		srcmac->byte2,
		srcmac->byte3,
		srcmac->byte4,
		srcmac->byte5,
		srcmac->byte6);

	printf("\n");


	printf("***************************************************** \n\n\n");
}

void Print_ARP_HEADER(const u_char *pkt_data)
{
	arp_h *ah = (arp_h *)pkt_data;

	printf("********************   ARP  Header ******************\n\n\n");
	ah->ht = ntohs(ah->ht);
	printf("Hardware type : 0x%04x\n", ah->ht);	//2byte
	ah->pt = ntohs(ah->pt);
	printf("protocol type : 0x%04x\n", ah->pt);	//2byte
	printf("harware length : 0x%02x\n", ah->hl);	//1byte
	printf("protocol length : 0x%02x\n", ah->pl);	//1byte
	ah->op = ntohs(ah->op);
	printf("operation : 0x%04x", ah->op);		//2byte
	if (ah->op == ARP_REQUSET)
		printf(" ( ARP REQUEST )\n");
	if (ah->op == ARP_REPLY)
		printf(" ( ARP REPLY )\n");
	printf("Sender Mac Address : [ %02x.%02x.%02x.%02x.%02x.%02x ]\n",
		ah->SenderHA.byte1, ah->SenderHA.byte2, ah->SenderHA.byte3, ah->SenderHA.byte4, ah->SenderHA.byte5, ah->SenderHA.byte6);
	printf("Sender IP Address : [ %d.%d.%d.%d ]\n", ah->SIA.byte1, ah->SIA.byte2, ah->SIA.byte3, ah->SIA.byte4);
	printf("Target Mac Address : [ %02x.%02x.%02x.%02x.%02x.%02x ]\n",
		ah->TargetHA.byte1, ah->TargetHA.byte2, ah->TargetHA.byte3, ah->TargetHA.byte4, ah->TargetHA.byte5, ah->TargetHA.byte6);
	printf("Target IP Address : [ %d.%d.%d.%d ]\n", ah->TIA.byte1, ah->TIA.byte2, ah->TIA.byte3, ah->TIA.byte4);

	printf("***************************************************** \n\n\n");
}


u_short Check_IP_CRC(const u_char *pkt_data,u_char HL)
{
	char Data;
	int check = 0;
	u_short CrcVal;
	const u_char *temp = pkt_data;
	for (check = 0; check < 20; check += 2)
	{
		if (check == 10);

		else
			CrcVal += (*(u_short*)temp);

		temp += 2;

		
	}

	u_char *p = (u_char *)malloc(sizeof(u_char) * 6);
	memset(p, CrcVal, sizeof(u_char) * 6);
	
	int i = 0;
	Data = p[i];

	while (p[i] != 0)
	{
		p[i] = p[i+1];
		i++;
	}
	
	return CrcVal;
}

void Print_TCP_HEADER(const u_char *pkt_data)
{
	tcp_header *th = (tcp_header*)pkt_data;
	printf("********************   TCP  Header ******************\n\n\n");
	printf("***************************************************** \n\n\n");
	printf("Source Port : [ %d ] \n", ntohs(th->SrcPort));
	printf("Dest Port : [ %d ] \n", ntohs(th->DstPort));
	printf("Sequence Number = 0x%x \n", ntohl(th->Seq_Num));
	printf("Ack Number = 0x%x \n", ntohl(th->Ack_Num));
	printf("Header Length = [ %d Bytes ] \n", th->tcp_h_Len * 4);
	
	switch (th->Flags)
	{
	case SYN:
		printf("Flags = SYN (0x02) \n");
		break;

	case SYN | ACK:
		printf("Flags = SYN x ACK (0x12) \n");
		break;

	case ACK:
		printf("Flags = ACK (0x10) \n");
		break;
	case RST:
		printf("Flags = RST (0x04) \n");
		break;

	case PSH:
		printf("Flags = PSH (0x08) \n");
		break;

	case FIN | ACK:
		printf("Flags = FIN x ACK (0x11) \n");
		break;

	}
	printf("Window Size = [ %d ] \n", ntohs(th->WinSize));
	printf("Checksum = 0x%04x \n", th->CRC);
	printf("Urgent Pointer = 0x%x \n", th->UrgPtr);
	printf("\n\n***************************************************** \n\n\n");

}


void Print_UDP_HEADER(const u_char *pkt_data)
{
	udp_header *uh = (udp_header *)pkt_data;
	printf("********************   UDP  Header ******************\n\n\n");
	printf("***************************************************** \n\n\n");
	printf("Source Port = [ %d ] \n", ntohs(uh->Src_Port));
	printf("Dest Port = [ %d ] \n", ntohs(uh->Dst_Port));
	printf("Total Length = [ %d ] \n", ntohs(uh->Length));
	printf("Checksum = 0x%04x \n", ntohs(uh->CRC));


	printf("\n\n***************************************************** \n\n\n");
	
}


void Print_IP_HEADER(const u_char *pkt_data)
{
	u_short OrgCrc;
	ip_header *ih = (ip_header *)pkt_data;
	printf("********************   IP  Header ******************\n\n\n");
	printf("***************************************************** \n\n\n");
	printf("IP Version = 0x%02x \n", ih->ip_version);
	printf("IP Header Length = %d bytes \n", ih->ip_leng * 4);
	printf("Type Of Service = 0x%02x \n", ih->tos);
	printf("Total Length = 0x%04x \n", ntohs(ih->total_length));
	printf("Identification = 0x%04x \n", ntohs(ih->identification));
	printf("Fragment offset = 0x%04x \n", ntohs(ih->Fragment_offset));
	printf("TTL = %d \n", ih->ttl);

	switch (ih->upper_protocol)
	{
	case TCP:
		printf("Upper Protocol = TCP \n");
		break;

	case UDP:
		printf("Upper Protocol = UDP \n");
		break;
	case ICMP:
		printf("Upper Protocol = ICMP \n");
		break;
	}

	printf("Checksum = 0x%04x \n", ntohs(ih->header));
