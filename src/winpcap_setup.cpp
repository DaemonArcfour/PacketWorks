#include "winpcap_setup.h"

void WINPCAP_SelectDevice(raw_packet& packet) {
	pcap_if_t* alldevs;
	pcap_if_t* d;
	char sgatewayip[16];
	int gatewayip;
	in_addr destip;
	int i = 0;
	char errbuf[PCAP_ERRBUF_SIZE + 1];
	char source[PCAP_ERRBUF_SIZE + 1];
	int inum;
	if (pcap_findalldevs_ex(source, NULL, &alldevs, errbuf) == -1)
	{
		WARNING("Error in pcap_findalldevs: %s\n", errbuf)
		return;
	}

	for (d = alldevs; d; d = d->next)
	{
		SetConsoleTextAttribute(color, i + 2);
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}
	SetConsoleTextAttribute(color, 7);
	if (i == 0)
	{
		WARNING("No interfaces found! Make sure pcap is installed.\n");
		return;
	}

	printf("Enter the interface number (1-%d): ", i);
	scanf("%d", &inum);

	if (inum < 1 || inum > i)
	{
		WARNING("Interface number out of range.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return;
	}
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);



	if((packet.adapter = pcap_open(d->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, 0, errbuf )) == NULL)
	{
		WARNING("Unable to open the adapter. %s is not supported by WinPcap %s\n", d->name, errbuf);
		return;
	}
	
	for (auto a = d->addresses; a; a = a->next) {
		if (a->addr->sa_family == AF_INET) {
			SUCCESS("Local address: %s", iptos(((struct sockaddr_in*)a->addr)->sin_addr.s_addr));
			WARNING("If your local address isn't the same as your external address, then your raw packets would probably get overridden by your router's NAT. Shikata ga nai.");
			memcpy(packet.adapter_address, a, sizeof(pcap_addr));

			break;
		}
	}

	in_addr srcip = ((struct sockaddr_in*)packet.adapter_address->addr)->sin_addr;
	GetMacAddress(packet.s_mac, srcip);
	SUCCESS("Host's MAC: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X", packet.s_mac[0], packet.s_mac[1], packet.s_mac[2], packet.s_mac[3], packet.s_mac[4], packet.s_mac[5]);
	GetGateway(srcip, sgatewayip, &gatewayip);
	destip.s_addr = gatewayip;
	GetMacAddress(packet.d_mac, destip);
	SUCCESS("Gateway MAC: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X", packet.d_mac[0], packet.d_mac[1], packet.d_mac[2], packet.d_mac[3], packet.d_mac[4], packet.d_mac[5]);

	std::fflush(stdin);
	std::cin.clear();
	std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
}