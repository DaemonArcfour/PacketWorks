#include "winpcap_setup.h"

void WINPCAP_SelectDevice(raw_packet& packet) {
	pcap_if_t* alldevs;
	pcap_if_t* d;
	int i = 0;
	int inum;
	char errbuf[PCAP_ERRBUF_SIZE];
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
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
		printf("Interface number out of range.\n");
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
	packet.adapter_addresses = d->addresses;
	std::fflush(stdin);
	std::cin.clear();
	std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
}