#include "cl_node.h"

void PW_Node_Client::PWNC_InitWinSock(std::string pwn_host) {
	if (NodeInfo != nullptr) {
		delete[] NodeInfo;
		NodeInfo = nullptr;
	}

	NodeInfo = new PW_Node_Info;
	if (PWNC_CustomKey.empty())
		PWNC_LoadKey();
	else
		PWNC_LoadKey(PWNC_CustomKey.c_str());

	std::string RHostInfo;
	std::stringstream RHostStream(pwn_host);
	std::queue <std::string> Q_RHostInfo;
	if (!strchr(pwn_host.c_str(), ':') || pwn_host.length() < 9 || pwn_host.length() > 21) {
		WARNING_MT("[PWNC] Invalid host.");
		return;
	}
	while (std::getline(RHostStream, RHostInfo, ':'))
		Q_RHostInfo.push(RHostInfo);

	PWNC_Buffer.PWD_InitBuffer(MAX_PACKET_LENGTH);
	if (WSAStartup(MAKEWORD(2, 2), &WSA) != 0)
	{
		WARNING_MT("[PWNC] Error Code: %d", WSAGetLastError());
		return;
	}

	if ((PWNC_Socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == SOCKET_ERROR)
	{
		WARNING_MT("[PWNC] Could not create socket: %d", WSAGetLastError());
		return;
	}
	PWNC_SetRemoteHost(Q_RHostInfo.front().c_str());
	Q_RHostInfo.pop();

	if (atoi(Q_RHostInfo.front().c_str()) > 65535 || atoi(Q_RHostInfo.front().c_str()) < 0) {
		WARNING_MT("[PWNC] Invalid remote node port.");
		return;
	}

	PWNC_SetRemotePort(atoi(Q_RHostInfo.front().c_str()));
	Q_RHostInfo.pop();
	WinSockReady = true;
}

void PW_Node_Client::PWNC_LoadKey(const char* keyFile) {
	FILE* existingKey = fopen(keyFile, "rb");
	if (!existingKey) {
		WARNING_MT("[PWNC] %s wasn't found.", keyFile);
		return;
	}

	fseek(existingKey, 0, SEEK_END);
	int lSize = ftell(existingKey);
	rewind(existingKey);
	if (lSize != 32) {
		WARNING_MT("[PWNC] %s is corrupted.", keyFile);
		return;
	}
	fread(NodeInfo->Key, 1, 32, existingKey);
	fclose(existingKey);
	hexdump((unsigned char*)NodeInfo->Key, 32);
	SUCCESS_MT("[PWNC] %s was found and loaded into memory.", keyFile);
}

void PW_Node_Client::PWNC_SetRemoteHost(const char* pwn_host) {
	Remote_Node.sin_family = AF_INET;
	Remote_Node.sin_addr.S_un.S_addr = inet_addr(pwn_host);
}

void PW_Node_Client::PWNC_SetRemotePort(int pwn_port) {
	Remote_Node.sin_port = htons(pwn_port);
}

void PW_Node_Client::PWNC_SendPacket(raw_packet* packet) {
	if (WinSockReady) {
		if (packet->craft_raw_packet()) {
			PWNC_Buffer.PWD_ClearBuffer();
			NodeInfo->Protocol = packet->iphdr_get_proto();
			PWNC_Buffer.PWD_WriteToBuffer((PTCHAR)NodeInfo, sizeof(PW_Node_Info));
			PWNC_Buffer.PWD_WriteToBuffer((PTCHAR)packet->get_crafted_packet() + sizeof(eth_hdr), packet->get_crafted_packet_size() - sizeof(eth_hdr));

			int rnode_len = sizeof(Remote_Node);
			if (sendto(PWNC_Socket, PWNC_Buffer.PWD_GetBuffer(), PWNC_Buffer.PWD_GetBufferDataLength(), 0, (struct sockaddr*) &Remote_Node, rnode_len) == SOCKET_ERROR)
			{
				WARNING("[PWNC] sendto() failed with error code: %d", WSAGetLastError());
				return;
			}
			PWNC_Buffer.PWD_ClearBuffer();
			return;
		}
	}

	WARNING("[PWNC] Remote node wasn't specified.");
}