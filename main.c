#include "common.h"
#include "export.h"
#pragma comment (lib, "wpcap.lib")
#pragma comment (lib, "ws2_32.lib" )



//struct pcap_pkthdr {
//	struct timeval ts;	/* time stamp */
//	bpf_u_int32 caplen;	/* length of portion present */
//	bpf_u_int32 len;	/* length this packet (off wire) */
//};.

/* Callback function invoked by libpcap for every incoming packet */
void packet_handler(u_char *param, const struct pcap_pkthdr *pkt_header, const u_char *pkt_data)
{
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
		if (pkt_data[k - 1] >= 33 && pkt_data[k - 1] <= 126)
			printf(" %c", pkt_data[k - 1]);
		else
			printf(" ");
	}
		
	printf("\n\n\n");
	printf("=======================The End======================= \n");

	
}

//winpcap 라이브러리의 함수들에 대한 자세한 정보는
//https://www.winpcap.org/docs/docs_412/html/group__wpcapfunc.html#gaae6abe06e15c87b803f69773822beca8

//참조 블로그 http://screwsliding.tistory.com/entry/winpcappcaph-%ED%95%A8%EC%88%98-%EB%B6%84%EC%84%9D
void main(int argc, char **argv)
{
	pcap_if_t *alldevs;
	pcap_if_t *t;
	int inum;
	int i = 0;
	pcap_t *adhandle;
	char errbuf[PCAP_BUF_SIZE];
	u_int netmask = 0;
	char packet_filter[] = "tcp port 110";
	struct bpf_program fcode;
//struct bpf_program {
//	u_int bf_len;
//	struct bpf_insn *bf_insns;
	/*struct bpf_insn {
		u_short	code;
		u_char 	jt;
		u_char 	jf;
		bpf_u_int32 k;
	};*/
//};

	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr, "findalldevs() error!\n");
		exit(1);
	}

	for (t = alldevs; t != NULL; t = t->next)
	{
		printf("%d. %s\n", ++i, t->name);
		if (t->description)
			printf(" (%s)\n", t->description);
		else
			printf(" (No description available)\n");
	}

	if (i == 0)
	{
		printf("\nNo interfaces found!! Make sure WinPcap in installed.\n");
		exit(1);
	}

	
	printf("Nic 카드 선택하세요(1~%d) : ", i);
	scanf("%d", &inum);


	//입력에 대한 에러처리
	if (inum < 1 || inum > i)
	{
		printf("the number is out of range !\n");
		pcap_freealldevs(alldevs);
		exit(1);
	}
	t = alldevs;
	i = 1;
	while (t!=NULL && i<inum)
	{
		t = t->next;
		i++;
	}

	//pcap_open_live함수를 통해서 해당 인터페이스 핸들값을 얻는다
	// 네트워크상의 패킷을보기위한 패킷 캡처 디스크립터를 얻는 데 사용됩니다
	if (!(adhandle = pcap_open_live(
		t->name,		//랜카드 정보
		65536,		//수신할 패킷 길의 정의
		1,			//랜카드 특성을 바꿔 모든 네트워크 패킷을 수집하는 옵션 Promiscuous 모드를 위해 1로 세팅
					// Promiscuous mode란 자기 MAC주소가 아닌 패킷들까지 다 받아들이는 모드를 말합니다.
		1000,		//랜카드에 수집할 네트워크 패킷이 있는 경우 매번 동작하지 않고,
					//여러 패킷을 한꺼번에 처리하기 위한 시간 설정(read timeout)
		errbuf)))	//에러버퍼
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", t->name);
		printf("Error : %s\n", errbuf);
		pcap_freealldevs(alldevs);
		exit(1);
	}
	
	//커널 수준의 필터링 엔진에서 해석 할 수 있는 프로그램에서 높은 수준의 필터링 표현식을 변환하여 패킷 필터를 컴파일한다(검색한다? 라는의미인것같다)
	//3번째 파라미터(const char *)를 필터 프로그램으로 컴파일 하는데 사용된다.
	//스트링 형태의 필터링 룰을 해석해 bpf_program 구조체에 저장한다
	if (pcap_compile(	//에러시 -1을 반환
		adhandle,	//패킷 캡쳐 descriptor
		&fcode,		//pcap_compile에 의해 채워지는 bpf_program 구조체
		packet_filter,	//필터링 룰( ex) tcp ,ip ...)
		1,			//최적화 수행 여부 제어
		netmask) < 0)	//네트워크 subnet
	{
		fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
		pcap_freealldevs(alldevs);
		exit(1);
	}
	//패킷 필터 프로그램을 지정하는 데 사용 fp는 bpf_program 구조체에 대한 포인터이며
	//일반적으로 pcap_compile ()을 호출 한 결과이다. 오류가 발생하면 -1이 반환된다
	//pcap_compile()을 통해 결정된 bpf_program 구조체를 적용할 때 사용된다
	if (pcap_setfilter(
		adhandle,
		&fcode)
		< 0)
	{
		fprintf(stderr, "\nError setting the filter.\n");
		pcap_freealldevs(alldevs);
		exit(1);
	}
	printf("Listening on %s ..", t->description);

	pcap_freealldevs(alldevs);

	//패킷을 연속적으로 수집한다
	// pcap_loop 함수를 호출하게 되면 
	// winpcap라이브러리가 무한루프(혹은 정해진 숫자만큼)를 돌면서 패킷이 감지되면
	// 세번째 인자에 해당하는 함수를 호출해줍니다.
	// 즉, 패킷이 도착하면 packet_handler라는 함수가 호출됩니다.
	// pcap_loop의 
	// 첫번째 인자 : pcap_open_live를 통해 할당받은 Handle값!
	// 두번째 인자 : 얼마만큼의 패킷을 받고 종료될 것인가?
