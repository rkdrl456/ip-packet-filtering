struct tm *ltime;
	char timestr[16];
	time_t local_tv_sec;
	const u_char *L3 = pkt_data + 14;
	const u_char *L4;
	u_short ptype;

	local_tv_sec = pkt_header->ts.tv_sec;
	ltime = localtime(&local_tv_sec);
	strftime(timestr, sizeof(timestr), "%H:%M:%S", ltime);
	u_int l3Leng = ((ip_header *)L3)->ip_leng * 4;

	L4 = L3 + l3Leng;

	eth_h *eth;
	eth = (eth_h*)pkt_data;
	ptype = ntohs(eth->ether_type);
	//intel cpu를 사용하는 시스템의 바이트 오더링이 littel-endian 방식을 사용하게 되므로 불일치 문제가 생기게 된다
	//그로인해 발생되는 데이터 전송의 혼란을 제거하기위해 local에서 사용하는 데이터를 네트워크로 전송하는경우 
	//Big-endian방식으로 변환하기 위해 htons() 함수 사용
	//반대로 네트워크로 부터 데이터를 수신하는경우 Little-Endian 방식으로 변환하기 위해 ntohs()함수 사용한다


	Print_Ethernet_Header(pkt_data);
	printf("%s.%.6d \n", timestr, pkt_header->ts.tv_usec);
	switch (ptype)
	{
	case IP_HEADER:
		Print_IP_HEADER(L3);
		break;

	case ARP_HEADER:
		Print_ARP_HEADER(L3);
		break;

	case REVERSE_ARP_HEADER:
	
		break;

	case TCP:
		Print_TCP_HEADER(L4);
		break;

	case UDP:
		Print_UDP_HEADER(L4);
		break;
	
	}
	
	//pkt_header->caplen를 활용하여
	//커널에서 UserMode applcation으로 복사된 패킷데이터(프로토콜 헤더 및 Data)의 길이를 확인할 수 있다.
	for (int i = 55; i < (pkt_header->caplen + 1); i++)
		printf(" %02x ", pkt_data[i - 1]);

	printf("\n\n\n");

	for (int k = 55; k < (pkt_header->caplen + 1); k++)
	{
		if (pkt_data[k - 1] >= 33 && pkt_data[k - 1] <= 126) //아스키 코드 값 참조
			printf(" %c", pkt_data[k - 1]);
		else
			printf(" ");
	}
		
	printf("\n\n\n");
	printf("=======================The End======================= \n");
