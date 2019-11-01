#pragma once
#include "g_include.h"
#include "sv_node.h"

class PW_Node_Client {
private:
	bool WinSockReady = false;
	WSAData WSA;
	SOCKET PWNC_Socket;
	PW_Node_Info *NodeInfo;
	sockaddr_in Remote_Node;
	PW_DataBuffer PWNC_Buffer;
	std::string PWNC_CustomKey = "pw_key.bin";
public:
	void PWNC_InitWinSock(std::string pwn_host);
	void PWNC_LoadKey(const char* keyFile);
	void PWNC_SetRemoteHost(const char*);
	void PWNC_SetRemotePort(int);
	void PWNC_SendPacket(raw_packet *packet);
	
	void PWNC_SetCustomKey(std::string keydir) {
		PWNC_CustomKey = keydir;
	}
};