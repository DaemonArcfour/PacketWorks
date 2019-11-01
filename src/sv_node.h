#pragma once
#include "g_include.h"
extern std::atomic<bool> bNode;

struct PW_Node_Info {
	char Key[32];
	uint8_t Protocol;
};

class PW_Node {
private:
	raw_packet *packet;
	eth_hdr *Ethernet_Header;
	CHAR Key[32];
	SOCKET PW_Socket;
	sockaddr_in Server, Client;
	WSAData WSA;
	PW_DataBuffer *DataBuffer;
	PW_DataBuffer *RPBuffer;
	uint8_t Protocol = 0;
	uint16_t port = htons(9094);
	int32_t Client_Length = sizeof(sockaddr_in);
	int32_t Packet_Length = 0;
public:
	bool PWN_InitWinSock(uint16_t port);
	bool PWN_CheckRPacketValidity();
	bool PWN_CheckKey(PW_Node_Info*);
	CHAR PWN_GenerateRandomByte();
	void PWN_InitEth();
	void PWN_ReceieveRPacket();
	void PWN_EncapsulateRPacket();
	void PWN_SendRPacket();
	void PWN_NodeThread(raw_packet *glob_packet);
	void PWN_GenerateKey();
};

void StartNode(raw_packet* glob_packet);