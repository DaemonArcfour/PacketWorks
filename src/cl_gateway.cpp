#include "cl_gateway.h"

void GetGateway(struct in_addr ip, char* sgatewayip, int* gatewayip)
{
	char pAdapterInfo[5000];
	PIP_ADAPTER_INFO  AdapterInfo;
	ULONG OutBufLen = sizeof(pAdapterInfo);

	GetAdaptersInfo((PIP_ADAPTER_INFO)pAdapterInfo, &OutBufLen);
	for (AdapterInfo = (PIP_ADAPTER_INFO)pAdapterInfo; AdapterInfo; AdapterInfo = AdapterInfo->Next)
	{
		if (ip.s_addr == inet_addr(AdapterInfo->IpAddressList.IpAddress.String))
		{
			strcpy(sgatewayip, AdapterInfo->GatewayList.IpAddress.String);
		}
	}

	*gatewayip = inet_addr(sgatewayip);
}

void GetMacAddress(unsigned char* mac, in_addr destip)
{
	DWORD ret;
	in_addr srcip;
	ULONG MacAddr[2];
	ULONG PhyAddrLen = 6;  /* default to length of six bytes */

	srcip.s_addr = 0;

	//Send an arp packet
	ret = SendARP(destip.s_addr, srcip.s_addr, MacAddr, &PhyAddrLen);

	//Prepare the mac address
	if (PhyAddrLen)
	{
		BYTE* bMacAddr = (BYTE*)& MacAddr;
		for (int i = 0; i < (int)PhyAddrLen; i++)
		{
			mac[i] = (char)bMacAddr[i];
		}
	}
}