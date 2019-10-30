#pragma once
#include "g_include.h"

struct PW_Node_Info {
	char Key[32];
	uint8_t Protocol;
};


class PW_DataBuffer {
private:
	PTCHAR DataBuffer = nullptr;
	PTCHAR W_PTR = nullptr;
	int32_t Size = NULL;
	int32_t LeftSpace = NULL;
public:
	void PWD_ClearBuffer() {
		if (Size == 0 || DataBuffer == nullptr) {
			WARNING("PW_DataBuffer was not initialized.");
			return;
		}
			ZeroMemory(DataBuffer, Size);
			CopyMemory(&W_PTR, &DataBuffer, sizeof(PTCHAR));
			LeftSpace = Size;
	}

	void PWD_InitBuffer(int32_t iSize) {
		if (DataBuffer != nullptr)
			ZeroMemory(DataBuffer, iSize);
		delete[] DataBuffer;
		DataBuffer = new CHAR[iSize];
		CopyMemory(&W_PTR, &DataBuffer, sizeof(PTCHAR));
		Size = iSize;
		LeftSpace = iSize;
	}

	void PWD_WriteToBuffer(PTCHAR Source, int32_t iSize) {
		if (Size == 0 || DataBuffer == nullptr) {
			WARNING("PW_DataBuffer was not initialized.");
			return;
		}

		if (LeftSpace < iSize) {
			WARNING("PW_DataBuffer: overflow!");
			return;
		}

		CopyMemory(W_PTR, Source, iSize);
		LeftSpace -= iSize;
	}

	int32_t PWD_GetBufferDataLength() {
		return (Size - LeftSpace);
	}

	int32_t PWD_GetBufferSize() {
		return Size;
	}

	PTCHAR PWD_GetBuffer() {
		return DataBuffer;
	}
};

class PW_Node {
private:
	raw_packet *packet;
	eth_hdr *Ethernet_Header;
	CHAR Key[32];
	SOCKET PW_Socket;
	sockaddr_in Server, Client;
	WSAData WSA;
	PW_DataBuffer DataBuffer;
	PW_DataBuffer RPBuffer;
	uint8_t Protocol = 0;
	uint16_t port = htons(9094);
	int32_t Client_Length;
	int32_t Packet_Length;
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