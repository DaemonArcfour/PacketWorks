#include "sv_node.h"
std::atomic<bool> bNode(false);
bool PW_Node::PWN_InitWinSock(uint16_t port) {
	DataBuffer = new PW_DataBuffer;
	RPBuffer = new PW_DataBuffer;
	DataBuffer->PWD_InitBuffer(MAX_PACKET_LENGTH);
	RPBuffer->PWD_InitBuffer(MAX_PACKET_LENGTH);
	if (WSAStartup(MAKEWORD(2, 2), &WSA) != 0)
	{
		WARNING_MT("Error Code: % d", WSAGetLastError());
		return false;
	}

	if ((PW_Socket = socket(AF_INET, SOCK_DGRAM, 0)) == INVALID_SOCKET)
	{
		WARNING_MT("Could not create socket: %d", WSAGetLastError());
		return false;
	}

	ZeroMemory((char*)&Server, sizeof(Server));
	Server.sin_family = AF_INET;
	Server.sin_addr.s_addr = INADDR_ANY;
	Server.sin_port = htons(port);

	if (bind(PW_Socket, (struct sockaddr*)&Server, sizeof(Server)) == SOCKET_ERROR)
	{
		WARNING_MT("Bind failed with error code: %d", WSAGetLastError());
		return false;
	}
	SUCCESS_MT("Node is ready to receive packets on port %hu.", port);
	return true;
}

bool PW_Node::PWN_CheckKey(PW_Node_Info* PWNI) {
	for (int i = 0; i < 32; i++)
		if (Key[i] != PWNI->Key[i])
			return false;
	return true;
}

bool PW_Node::PWN_CheckRPacketValidity() {
	if (Packet_Length < sizeof(PW_Node_Info))
		return false;

	PW_Node_Info* Node_Info;
	Node_Info = (PW_Node_Info*)DataBuffer->PWD_GetBuffer();
	if (!PWN_CheckKey(Node_Info)) {
		WARNING_MT("[PWN] Incorrect key.");
		return false;
	}

	if (Node_Info->Protocol == IPPROTO_UDP) {
		if (Packet_Length < sizeof(PW_Node_Info) + sizeof(ip_hdr) + sizeof(udp_hdr)) {
			WARNING_MT("[PWN] Malformed packet receieved.");
			return false;
		}
	}

	else if (Node_Info->Protocol == IPPROTO_TCP) {
		if (Packet_Length < sizeof(PW_Node_Info) + sizeof(ip_hdr) + sizeof(tcp_hdr)) {
			WARNING_MT("[PWN] Malformed packet receieved.");
			return false;
		}
	}

	else {
		WARNING_MT("[PWN] Malformed packet receieved.");
		return false;
	}
	Protocol = Node_Info->Protocol;
	return true;
}

void PW_Node::PWN_EncapsulateRPacket() {
	PWN_InitEth();
	RPBuffer->PWD_ClearBuffer();
	RPBuffer->PWD_WriteToBuffer((PTCHAR)Ethernet_Header, sizeof(eth_hdr));
	RPBuffer->PWD_WriteToBuffer(DataBuffer->PWD_GetBuffer() + sizeof(PW_Node_Info), Packet_Length - sizeof(PW_Node_Info));
}

void PW_Node::PWN_SendRPacket() {
	SUCCESS_MT("[PWN] Rerouting %d bytes of data", RPBuffer->PWD_GetBufferDataLength());
	pcap_sendpacket(packet->adapter, reinterpret_cast<u_char*>(RPBuffer->PWD_GetBuffer()), RPBuffer->PWD_GetBufferDataLength());
}

void PW_Node::PWN_ReceieveRPacket() {
	Packet_Length = 0;
	if ((Packet_Length = recvfrom(PW_Socket, DataBuffer->PWD_GetBuffer(), DataBuffer->PWD_GetBufferSize(), 0, (struct sockaddr*)&Client, &Client_Length)) == SOCKET_ERROR)
	{
		WARNING_MT("recvfrom() failed with error code: %d", WSAGetLastError());
		return;
	}
	SUCCESS_MT("[PWN] Receieved %d bytes", Packet_Length);
	if (PWN_CheckRPacketValidity()) {
		PWN_EncapsulateRPacket();
		PWN_SendRPacket();
	}
}
void PW_Node::PWN_InitEth() {
	Ethernet_Header->type = htons(0x0800);
	memcpy(Ethernet_Header->source_mac, packet->s_mac, 6);
	memcpy(Ethernet_Header->dest_mac, packet->d_mac, 6);
}

void PW_Node::PWN_GenerateKey() {
	FILE* existingKey = fopen("pw_key.bin", "rb");
	if (existingKey == NULL) {
		GENKEY: // Please, god, FORGIVE ME. (I would appreciate if someone recoded this, because im too lazy.)
		WARNING_MT("[PWN] pw_key.bin not found, generating a new node private key.");
		for (int i = 0; i < 32; i++)
			Key[i] = PWN_GenerateRandomByte();
		FILE* keyFile;
		keyFile = fopen("pw_key.bin", "wb");
		fwrite(&Key, sizeof(CHAR), sizeof(Key), keyFile);
		fclose(keyFile);
		SUCCESS_MT("[PWN] Private node key generated & saved to \"pw_key.bin\"");
		return;
	}
	else {
		fseek(existingKey, 0, SEEK_END);
		int lSize = ftell(existingKey);
		rewind(existingKey);
		if (lSize != 32) {
			WARNING_MT("[PWN] pw_key.bin is corrupted, generating a new node private key.");
			goto GENKEY; // Please, god, FORGIVE ME. (I would appreciate if someone recoded this, because im too lazy.)
		}
		fread(&Key, 1, 32, existingKey);
		fclose(existingKey);
		SUCCESS_MT("[PWN] existing pw_key.bin was found and loaded into memory.");
	}
	return;
}

CHAR PW_Node::PWN_GenerateRandomByte() {
	return (((int)rand()) % 100);
}

void PW_Node::PWN_NodeThread(raw_packet *glob_packet) {
	packet = glob_packet;
	if (packet->adapter == nullptr) {
		WARNING_MT("You must chose an adapter to start a node.");
		return;
	}

	Ethernet_Header = new eth_hdr;
	if (PWN_InitWinSock(9094)) {
		PWN_GenerateKey();
		while (bNode.load()) {
			PWN_ReceieveRPacket();
		}
	}
	delete[] DataBuffer;
	delete[] RPBuffer;
	WARNING_MT("Node closed.");
}

void StartNode(raw_packet* glob_packet) {
	PW_Node PWNode;
	PWNode.PWN_NodeThread(glob_packet);
}