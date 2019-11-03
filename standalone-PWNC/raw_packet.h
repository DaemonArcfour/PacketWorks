#pragma once
#include <iostream>
#include <winsock2.h>
#include <Windows.h>
#include <stdio.h>
#include <string>
#include <sstream>
#include <string>
#include <queue>
#include <fstream>

#define DISABLE_PACKET_FRAGMENTATION 	ip_header->ip_dont_fragment = 1;\
										ip_header->ip_frag_offset = 0;\
										ip_header->ip_more_fragment = 0;\
										ip_header->ip_frag_offset1 = 0;
#define SET_DEFAULT_INTERNET_PROTOCOL_VALUES 	iphdr_set_version(4); \
												iphdr_set_id(2); \
												iphdr_set_hdr_len(5);\
												iphdr_set_ttl(128);

class PW_DataBuffer {
private:
	PTCHAR DataBuffer = nullptr;
	PTCHAR W_PTR = nullptr;
	int32_t Size = NULL;
	int32_t LeftSpace = NULL;
public:
	void PWD_ClearBuffer() {
		if (Size == 0 || DataBuffer == nullptr) {
			return;
		}
		ZeroMemory(DataBuffer, Size);
		CopyMemory(&W_PTR, &DataBuffer, sizeof(PTCHAR));
		LeftSpace = Size;
	}

	void PWD_InitBuffer(int32_t iSize) {
		if (DataBuffer != nullptr) {
			ZeroMemory(DataBuffer, iSize);
			delete[] DataBuffer;
		}

		DataBuffer = new CHAR[iSize];
		CopyMemory(&W_PTR, &DataBuffer, sizeof(PTCHAR));
		Size = iSize;
		LeftSpace = iSize;
	}

	void PWD_WriteToBuffer(PTCHAR Source, int32_t iSize) {
		if (Size == 0 || DataBuffer == nullptr) {
			return;
		}

		if (LeftSpace < iSize) {
			return;
		}

		CopyMemory(W_PTR, Source, iSize);
		W_PTR += iSize;
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

void mov_ptr_cpy(char** ptr, char* data, int len) {
	memcpy(*ptr, data, len);
	*ptr += len;
}

USHORT checksum(USHORT* buffer, int size)
{
	unsigned long cksum = 0;
	while (size > 1)
	{
		cksum += *buffer++;
		size -= sizeof(USHORT);
	}
	if (size)
		cksum += *(UCHAR*)buffer;

	cksum = (cksum >> 16) + (cksum & 0xffff);
	cksum += (cksum >> 16);
	return (USHORT)(~cksum);
}

struct pseudo_header
{
	uint32_t source_address;
	uint32_t dest_address;
	uint8_t placeholder = 0;
	uint8_t protocol;
	uint16_t proto_len;
};

typedef struct eth_hdr
{
	UCHAR dest_mac[6]; //Total 48 bits
	UCHAR source_mac[6]; //Total 48 bits
	USHORT type; //16 bits (0x0800 == IP Frames)
}   ETHER_HDR, * PETHER_HDR, FAR* LPETHER_HDR, ETHERHeader;

typedef struct ip_hdr
{
	unsigned char ip_header_len : 4; // 4-bit header length (in 32-bit words) normally=5 (Means 20 Bytes may be 24 also)
	unsigned char ip_version : 4; // 4-bit IPv4 version [X]
	unsigned char ip_tos = 0; // IP type of service [X]
	unsigned short ip_total_length; // Total length [X]
	unsigned short ip_id; // Unique identifier [X]

	unsigned char ip_frag_offset : 5; // Fragment offset field [X]

	unsigned char ip_more_fragment : 1; // [X]
	unsigned char ip_dont_fragment : 1; // [X]
	unsigned char ip_reserved_zero : 1; // [X]

	unsigned char ip_frag_offset1; //fragment offset // [X]

	unsigned char ip_ttl = 64; // Time to live [X]
	unsigned char ip_protocol; // Protocol(TCP,UDP etc) [X]
	unsigned short ip_checksum = 0; // IP checksum [X]
	unsigned int ip_srcaddr; // Source address [X]
	unsigned int ip_destaddr; // Source address [X]
} IPV4_HDR, * PIPV4_HDR, FAR* LPIPV4_HDR;

// TCP header
typedef struct tcp_hdr
{
	unsigned short source_port; // source port [X]
	unsigned short dest_port; // destination port [X]
	unsigned int sequence; // sequence number - 32 bits
	unsigned int acknowledge; // acknowledgement number - 32 bits

	unsigned char ns : 1; //Nonce Sum Flag Added in RFC 3540.
	unsigned char reserved_part1 : 3; //according to rfc
	unsigned char data_offset : 4; /*The number of 32-bit words in the TCP header.
	This indicates where the data begins.
	The length of the TCP header is always a multiple
	of 32 bits.*/

	unsigned char fin : 1; //Finish Flag
	unsigned char syn : 1; //Synchronise Flag
	unsigned char rst : 1; //Reset Flag
	unsigned char psh : 1; //Push Flag
	unsigned char ack : 1; //Acknowledgement Flag
	unsigned char urg : 1; //Urgent Flag

	unsigned char ecn : 1; //ECN-Echo Flag
	unsigned char cwr : 1; //Congestion Window Reduced Flag

	////////////////////////////////

	unsigned short window; // window
	unsigned short checksum; // checksum
	unsigned short urgent_pointer; // urgent pointer
} TCP_HDR, * PTCP_HDR, FAR* LPTCP_HDR, TCPHeader, TCP_HEADER;

typedef struct udp_hdr
{
	unsigned short src_portno;       // Source port no. [X]
	unsigned short dst_portno;       // Dest. port no. [X]
	unsigned short udp_length;       // Udp packet length [X]
	unsigned short udp_checksum;     // Udp checksum (optional) [X]
} UDP_HDR, * PUDP_HDR;

class raw_packet {
private:
	ip_hdr* ip_header = new ip_hdr;
	udp_hdr* udp_header = new udp_hdr;
	PW_DataBuffer Data;
	PW_DataBuffer RPacket;
	struct sockaddr_in src_addr;
	struct sockaddr_in dst_addr;
public:
	void initbuf() {
		Data.PWD_InitBuffer(8192);
		RPacket.PWD_InitBuffer(8192);
	}

	int getRPacketlen() {
		return RPacket.PWD_GetBufferDataLength();
	}

	int getDatalen() {
		return Data.PWD_GetBufferDataLength();
	}

	char* getbuf() {
		return RPacket.PWD_GetBuffer();
	}

	void setdata(char* dat, int sz) {
		Data.PWD_ClearBuffer();
		Data.PWD_WriteToBuffer(dat, sz);
	}



	void iphdr_set_len(unsigned char len) {
		ip_header->ip_header_len = len;
	}

	void iphdr_set_total_len(int len) {
		ip_header->ip_total_length = htons(len);
	}

	void iphdr_set_hdr_len(unsigned char len) {
		ip_header->ip_header_len = len;
	}

	void iphdr_set_ttl(unsigned char ttl) {
		ip_header->ip_ttl = ttl;
	}

	void iphdr_set_chksum(unsigned short chksum) {
		ip_header->ip_checksum = chksum;
	}

	void iphdr_set_proto(unsigned char proto) {
		ip_header->ip_protocol = proto;
	}

	void iphdr_set_dst_addr(const char* addr) {
		inet_pton(AF_INET, addr, &dst_addr.sin_addr);
		ip_header->ip_destaddr = inet_addr(addr);
	}

	void iphdr_set_src_addr(const char* addr) {
		inet_pton(AF_INET, addr, &src_addr.sin_addr);
		ip_header->ip_srcaddr = inet_addr(addr);
	}

	void iphdr_set_version(unsigned char ver) {
		ip_header->ip_version = ver;
	}

	void iphdr_set_id(int id) {
		ip_header->ip_id = htons(id);
	}

	unsigned char iphdr_get_proto() {
		return ip_header->ip_protocol;
	}
	void iphdr_auto_checksum() {
		iphdr_set_total_len(sizeof(udp_hdr) + sizeof(ip_hdr) + Data.PWD_GetBufferDataLength());
		iphdr_set_chksum(0);
		DISABLE_PACKET_FRAGMENTATION
		SET_DEFAULT_INTERNET_PROTOCOL_VALUES
		iphdr_set_chksum(checksum((USHORT*)ip_header, sizeof(ip_hdr)));
	}

	void udphdr_set_src_port(int port) {
		src_addr.sin_port = htons(port);
		udp_header->src_portno = src_addr.sin_port;
	}

	void udphdr_set_dst_port(unsigned short port) {
		dst_addr.sin_port = htons(port);
		udp_header->dst_portno = dst_addr.sin_port;
	}

	void udphdr_set_len(int len) {

		udp_header->udp_length = htons(len); // self + payload
	}

	void udphdr_set_chksum(unsigned short chksum) {
		udp_header->udp_checksum = chksum;
	}

	void udphdr_auto_checksum() {
		udphdr_set_len(sizeof(udp_hdr) + Data.PWD_GetBufferDataLength());
		udphdr_set_chksum(0);
		int pseudogram_size = sizeof(udp_hdr) + Data.PWD_GetBufferDataLength() + sizeof(pseudo_header);
		pseudo_header* _psh = new pseudo_header;
		_psh->dest_address = ip_header->ip_destaddr;
		_psh->source_address = ip_header->ip_srcaddr;
		_psh->placeholder = 0;
		_psh->protocol = IPPROTO_UDP;
		_psh->proto_len = udp_header->udp_length;
		char* tbuf = new char[pseudogram_size];
		char* ptr = nullptr;
		memcpy(&ptr, &tbuf, sizeof(char*));
		mov_ptr_cpy(&ptr, (char*)_psh, sizeof(pseudo_header));
		mov_ptr_cpy(&ptr, (char*)udp_header, sizeof(udp_hdr));
		mov_ptr_cpy(&ptr, Data.PWD_GetBuffer(), Data.PWD_GetBufferDataLength());
		udphdr_set_chksum(checksum((USHORT*)tbuf, sizeof(udp_hdr) + Data.PWD_GetBufferDataLength() + sizeof(pseudo_header)));
		delete[] _psh;
		delete[] tbuf;
	}

	bool craft() {
		RPacket.PWD_ClearBuffer();
		RPacket.PWD_WriteToBuffer((PTCHAR)ip_header, sizeof(ip_hdr));
		RPacket.PWD_WriteToBuffer((PTCHAR)udp_header, sizeof(udp_hdr));
		RPacket.PWD_WriteToBuffer(Data.PWD_GetBuffer(), Data.PWD_GetBufferDataLength());
		return true;
	}

	bool craft(const char* srcip, int srcport, const char* dstip, unsigned short dstport, char* dat, int sz) {
		iphdr_set_proto(IPPROTO_UDP);
		iphdr_set_src_addr(srcip);
		udphdr_set_src_port(srcport);
		iphdr_set_dst_addr(dstip);
		udphdr_set_dst_port(dstport);
		setdata(dat, sz);
		iphdr_auto_checksum();
		udphdr_auto_checksum();
		RPacket.PWD_ClearBuffer();
		RPacket.PWD_WriteToBuffer((PTCHAR)ip_header, sizeof(ip_hdr));
		RPacket.PWD_WriteToBuffer((PTCHAR)udp_header, sizeof(udp_hdr));
		RPacket.PWD_WriteToBuffer(Data.PWD_GetBuffer(), Data.PWD_GetBufferDataLength());
		return true;
	}
};

struct PW_Node_Info {
	char Key[32];
	uint8_t Protocol;
};

class PW_Node_Client {
private:
	bool WinSockReady = false;
	WSAData WSA;
	SOCKET PWNC_Socket;
	PW_Node_Info* NodeInfo;
	sockaddr_in Remote_Node;
	PW_DataBuffer PWNC_Buffer;
	std::string PWNC_CustomKey;
public:
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
			return;
		}
		while (std::getline(RHostStream, RHostInfo, ':'))
			Q_RHostInfo.push(RHostInfo);

		PWNC_Buffer.PWD_InitBuffer(8192);
		if (WSAStartup(MAKEWORD(2, 2), &WSA) != 0)
		{
			return;
		}

		if ((PWNC_Socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == SOCKET_ERROR)
		{
			return;
		}
		PWNC_SetRemoteHost(Q_RHostInfo.front().c_str());
		Q_RHostInfo.pop();

		if (atoi(Q_RHostInfo.front().c_str()) > 65535 || atoi(Q_RHostInfo.front().c_str()) < 0) {
			return;
		}

		PWNC_SetRemotePort(atoi(Q_RHostInfo.front().c_str()));
		Q_RHostInfo.pop();
		WinSockReady = true;
	}

	void PWNC_LoadKey(const char* keyFile = "pw_key.bin") {
		FILE* existingKey = fopen(keyFile, "rb");
		if (!existingKey) {
			return;
		}

		fseek(existingKey, 0, SEEK_END);
		int lSize = ftell(existingKey);
		rewind(existingKey);
		if (lSize != 32) {
			return;
		}
		fread(NodeInfo->Key, 1, 32, existingKey);
		fclose(existingKey);
	}

	void PWNC_SetRemoteHost(const char* pwn_host) {
		Remote_Node.sin_family = AF_INET;
		Remote_Node.sin_addr.S_un.S_addr = inet_addr(pwn_host);
	}

	void PWNC_SetRemotePort(int pwn_port) {
		Remote_Node.sin_port = htons(pwn_port);
	}

	void PWNC_SendPacket(raw_packet* packet) {
		if (WinSockReady) {
				PWNC_Buffer.PWD_ClearBuffer();
				NodeInfo->Protocol = packet->iphdr_get_proto();
				PWNC_Buffer.PWD_WriteToBuffer((PTCHAR)NodeInfo, sizeof(PW_Node_Info));
				PWNC_Buffer.PWD_WriteToBuffer((PTCHAR)packet->getbuf(), packet->getRPacketlen());

				int rnode_len = sizeof(Remote_Node);
				if (sendto(PWNC_Socket, PWNC_Buffer.PWD_GetBuffer(), PWNC_Buffer.PWD_GetBufferDataLength(), 0, (struct sockaddr*) & Remote_Node, rnode_len) == SOCKET_ERROR)
				{
					return;
				}
				PWNC_Buffer.PWD_ClearBuffer();
				return;
		}
	}

	void PWNC_SetCustomKey(std::string keydir) {
		PWNC_CustomKey = keydir;
	}
};

