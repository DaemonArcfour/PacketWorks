#include "g_include.h"
#include <stdlib.h>
#include <time.h> 

#define DEALLOC(ptr) if(##ptr != nullptr){ delete[] ##ptr; ##ptr = nullptr;}
#define CHK_IP_INIT(...)	 if(ip_header == nullptr){WARNING("the protocol wasn't initialized."); return __VA_ARGS__;}
#define CHK_UDP_INIT(...) CHK_IP_INIT(__VA_ARGS__) if(udp_header == nullptr){WARNING("UDP packet wasn't initialized."); return __VA_ARGS__;}
#define CHK_TCP_INIT(...) CHK_IP_INIT(__VA_ARGS__) if(tcp_header == nullptr){WARNING("TCP packet wasn't initialized."); return __VA_ARGS__;}
#define CHK_DATA_INIT(...) if(data == nullptr || data_sz == NULL){WARNING("data is empty."); return __VA_ARGS__;}
#define DISABLE_PACKET_FRAGMENTATION 	ip_header->ip_dont_fragment = 1;\
										ip_header->ip_frag_offset = 0;\
										ip_header->ip_more_fragment = 0;\
										ip_header->ip_frag_offset1 = 0;
#define SET_DEFAULT_INTERNET_PROTOCOL_VALUES 	iphdr_set_version(4); \
												iphdr_set_id(2); \
												iphdr_set_hdr_len(5);\
												iphdr_set_ttl(128);
#define RM_LEFTOVER_HDR_MEM(PROTO) 	ZeroMemory(eth_header, sizeof(eth_hdr)); \
									ZeroMemory(ip_header, sizeof(ip_hdr)); \
								if(PROTO == IPPROTO_UDP)ZeroMemory(udp_header, sizeof(udp_hdr)); else ZeroMemory(tcp_header, sizeof(tcp_hdr));

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


void raw_packet::dealloc_mem() {
	if (eth_header != nullptr) {
		WARNING("deallocating %d bytes used by the ETH header", sizeof(eth_hdr));
	}
	DEALLOC(eth_header);
	if (ip_header != nullptr) {
		WARNING("deallocating %d bytes used by the IP header", sizeof(ip_hdr));
	}
	DEALLOC(ip_header);
	if (udp_header != nullptr) {
		WARNING("deallocating %d bytes used by the UDP header", sizeof(udp_hdr));
	}
	DEALLOC(udp_header);
	if (tcp_header != nullptr) {
		WARNING("deallocating %d bytes used by the TCP header", sizeof(tcp_hdr));
	}
	DEALLOC(tcp_header);

	dealloc_data();
}

void raw_packet::init_raw_tcp() {
	dealloc_mem();
	eth_header = new eth_hdr;
	ip_header = new ip_hdr;
	tcp_header = new tcp_hdr;
	RM_LEFTOVER_HDR_MEM(IPPROTO_TCP);
	src_addr.sin_family = AF_INET;
	dst_addr.sin_family = AF_INET;
	iphdr_set_proto(IPPROTO_TCP);
	SET_DEFAULT_INTERNET_PROTOCOL_VALUES
	DISABLE_PACKET_FRAGMENTATION
	SUCCESS("allocated %d bytes for the raw TCP packet", sizeof(eth_hdr) + sizeof(ip_hdr) + sizeof(tcp_hdr))
}

void raw_packet::init_raw_udp() {
	dealloc_mem();
	eth_header = new eth_hdr;
	ip_header = new ip_hdr;
	udp_header = new udp_hdr;
	RM_LEFTOVER_HDR_MEM(IPPROTO_UDP);
	src_addr.sin_family = AF_INET;
	dst_addr.sin_family = AF_INET;
	iphdr_set_proto(IPPROTO_UDP);
	SET_DEFAULT_INTERNET_PROTOCOL_VALUES
	DISABLE_PACKET_FRAGMENTATION
	SUCCESS("allocated %d bytes for the raw UDP packet", sizeof(eth_hdr) + sizeof(ip_hdr) + sizeof(udp_hdr))
}
// Eth hdr
void raw_packet::init_eth_layer() {
	u_char s_mac[6], d_mac[6];
	char sgatewayip[16];
	int gatewayip;
	eth_header->type = htons(0x0800);
	in_addr destip;
	in_addr srcip = ((struct sockaddr_in*)adapter_address->addr)->sin_addr;
	GetMacAddress(s_mac, srcip);
	SUCCESS("Host's MAC: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n", s_mac[0], s_mac[1], s_mac[2], s_mac[3], s_mac[4], s_mac[5]);

	GetGateway(srcip, sgatewayip, &gatewayip);
	destip.s_addr = gatewayip;

	GetMacAddress(d_mac, destip);
	SUCCESS("Reciever's MAC: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n", d_mac[0], d_mac[1], d_mac[2], d_mac[3], d_mac[4], d_mac[5]);
	memcpy(eth_header->source_mac, s_mac, 6);
	memcpy(eth_header->dest_mac, d_mac, 6);
}

// IP hdr
void raw_packet::iphdr_set_version(unsigned char ver) {
	CHK_IP_INIT();
	ip_header->ip_version = ver;
	SUCCESS("using IPv4.")
}

void raw_packet::iphdr_set_id(int id) {
	CHK_IP_INIT();
	ip_header->ip_id = htons(id);
}

void raw_packet::iphdr_set_len(unsigned char len){
	CHK_IP_INIT();
	ip_header->ip_header_len = len;
}

void raw_packet::iphdr_auto_checksum() {
	CHK_IP_INIT();
	iphdr_set_chksum(0);
	iphdr_set_chksum(checksum((USHORT*)ip_header, sizeof(ip_hdr)));
}

void raw_packet::iphdr_set_chksum(unsigned short chksum) {
	CHK_IP_INIT();
	ip_header->ip_checksum = chksum;
}

void raw_packet::iphdr_set_dst_addr(const char* addr) {
	CHK_IP_INIT();
	inet_pton(AF_INET, addr, &dst_addr.sin_addr);
	ip_header->ip_destaddr = inet_addr(addr);
	SUCCESS("reciever is now %s", addr);
}

void raw_packet::iphdr_set_proto(unsigned char proto) {
	CHK_IP_INIT();
	ip_header->ip_protocol = proto;
}

void raw_packet::iphdr_set_src_addr(const char* addr) {
	CHK_IP_INIT();
	inet_pton(AF_INET, addr, &src_addr.sin_addr);
	ip_header->ip_srcaddr = inet_addr(addr);
	SUCCESS("sender is now %s", addr);
}

void raw_packet::iphdr_set_hdr_len(unsigned char len) {
	CHK_IP_INIT();
	ip_header->ip_header_len = len;
}

void raw_packet::iphdr_set_total_len(int len){
	CHK_IP_INIT();
	ip_header->ip_total_length = htons(len);
	SUCCESS("total packet length is now %d.", len);
}

void raw_packet::iphdr_set_ttl(unsigned char ttl) {
	CHK_IP_INIT();
	ip_header->ip_ttl = ttl;
	SUCCESS("TTL is now %d", ttl);
}

unsigned char raw_packet::iphdr_get_proto() {
	CHK_IP_INIT(0);
	return ip_header->ip_protocol;
}

// UDP hdr

void raw_packet::udphdr_set_src_port(int port) {
	src_addr.sin_port = htons(port);
	udp_header->src_portno = src_addr.sin_port;
	SUCCESS("switched UDP source port to %d", port);
}

void raw_packet::udphdr_set_dst_port(int port) {
	dst_addr.sin_port = htons(port);
	udp_header->dst_portno = dst_addr.sin_port;
	SUCCESS("switched UDP destination port to %d", port);
}

void raw_packet::udphdr_set_len(int len) {
	udp_header->udp_length = htons(len); // self + payload
}

void raw_packet::udphdr_set_chksum(unsigned short chksum) {
	udp_header->udp_checksum = chksum;
}

void raw_packet::udphdr_auto_checksum() {
	CHK_DATA_INIT();
	udphdr_set_len(sizeof(udp_hdr) + get_data_size());
	udphdr_set_chksum(0);
	int pseudogram_size = sizeof(udp_hdr) + get_data_size() + sizeof(pseudo_header);
	pseudo_header *_psh = new pseudo_header;
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
	mov_ptr_cpy(&ptr, data, data_sz);
	udphdr_set_chksum(checksum((USHORT*)tbuf, sizeof(udp_hdr) + get_data_size() + sizeof(pseudo_header)));
	delete[] _psh;
	delete[] tbuf;
}
// TCP hdr
void raw_packet::tcphdr_set_ack(unsigned int ack) {
	tcp_header->ack = ack; // This is unobtainable with spoofed source address, I didn't bother to implement that.
}

void raw_packet::tcphdr_gen_seqnum() {
	srand(time(NULL));
	tcphdr_set_seqnum(rand() % INT_MAX);
}

void raw_packet::tcphdr_set_seqnum(unsigned int seq) {
	tcp_header->sequence = seq;
}

void raw_packet::tcphdr_set_chksum(unsigned short chksum) {
	tcp_header->checksum = chksum;
}

void raw_packet::tcphdr_auto_checksum() {
	CHK_DATA_INIT();
	tcphdr_set_chksum(0);
	tcp_header->window = htons(155);
	tcp_header->psh = 1;
	int pseudogram_size = sizeof(tcp_hdr) + get_data_size() + sizeof(pseudo_header);
	pseudo_header* _psh = new pseudo_header;
	_psh->dest_address = ip_header->ip_destaddr;
	_psh->source_address = ip_header->ip_srcaddr;
	_psh->placeholder = 0;
	_psh->protocol = IPPROTO_TCP;
	_psh->proto_len = tcphdr_get_len();
	char* tbuf = new char[pseudogram_size];
	char* ptr = nullptr;
	memcpy(&ptr, &tbuf, sizeof(char*));
	mov_ptr_cpy(&ptr, (char*)_psh, sizeof(pseudo_header));
	mov_ptr_cpy(&ptr, (char*)tcp_header, sizeof(tcp_hdr));
	mov_ptr_cpy(&ptr, data, data_sz);
	tcphdr_set_chksum(checksum((USHORT*)tbuf, sizeof(tcp_hdr) + get_data_size() + sizeof(pseudo_header)));
	delete[] _psh;
	delete[] tbuf;
}

void raw_packet::tcphdr_set_src_port(int port) {
	src_addr.sin_port = htons(port);
	tcp_header->source_port = src_addr.sin_port;
	SUCCESS("switched TCP source port to %d", port);
}

void raw_packet::tcphdr_set_dst_port(int port) {
	src_addr.sin_port = htons(port);
	tcp_header->dest_port = src_addr.sin_port;
	SUCCESS("switched TCP destination port to %d", port);
}

unsigned short raw_packet::tcphdr_get_len() {
	return htons(sizeof(tcp_hdr) + get_data_size());
}

// Data management
void raw_packet::load_bin_data(const char* file_loc) {
	dealloc_data();

	std::ifstream sz(file_loc, std::ios::binary | std::ios::ate);
	if (!sz) {
		WARNING("file not found.");
		return;
	}

	if (sz.tellg() > MAX_PACKET_LENGTH) {
		WARNING("file is too big.");
		return;
	}

	data_sz = sz.tellg();
	data = new char[data_sz];
	ZeroMemory(data, data_sz);
	sz.close();
	std::ifstream payload(file_loc, std::ios::binary | std::ios::out);
	payload.read(data, data_sz);
	payload.close();
	SUCCESS("allocated & loaded %d bytes for packet data", data_sz);
}

void raw_packet::dealloc_data() {
	if (data != nullptr) {
		WARNING("deallocating %d bytes used by the data buffer", get_data_size());
	}

	DEALLOC(data);
	data_sz = 0;
}
void raw_packet::get_data_hexdump() {
	CHK_DATA_INIT();
	SetConsoleTextAttribute(color, 28);
	printf("data size: %d bytes\n", data_sz);
	hexdump((unsigned char*)data, data_sz);
}

char* raw_packet::get_data_ptr() {
	return data;
}

int raw_packet::get_data_size() {
	return data_sz;
}

// final assembly

bool raw_packet::craft_raw_packet() {
	/*
	 raw packet structure
		*   ETHHDR  *
		*************
		*   IPHDR   *
		*************
		*  PROTOHDR *
		*************
		*	DATA	*
		*************
	*/
	if (crafted_packet != nullptr) {
		WARNING("deallocating %d bytes used by the old crafted packet", get_crafted_packet_size());
	}
	crafted_packet_sz = 0;
	DEALLOC(crafted_packet);
	CHK_IP_INIT(false);
	crafted_packet_sz = sizeof(eth_hdr) + sizeof(ip_hdr);
	int proto_sz;
	if (iphdr_get_proto() == IPPROTO_UDP) {
		CHK_UDP_INIT(false);
		crafted_packet_sz += sizeof(udp_hdr);
		proto_sz = sizeof(udp_hdr);
	}
	else {
		CHK_TCP_INIT(false);
		crafted_packet_sz += sizeof(tcp_hdr);
		proto_sz = sizeof(tcp_hdr);
	}
	CHK_DATA_INIT(false);
	crafted_packet_sz += get_data_size();
	crafted_packet = new char[crafted_packet_sz];
	char* ptr = nullptr;
	memcpy(&ptr, &crafted_packet, sizeof(char*));
	init_eth_layer();
	iphdr_set_total_len(crafted_packet_sz - sizeof(eth_hdr));
	iphdr_auto_checksum();
	
	mov_ptr_cpy(&ptr, (char*)eth_header, sizeof(eth_hdr));
	mov_ptr_cpy(&ptr, (char*)ip_header, sizeof(ip_hdr));
	if (iphdr_get_proto() == IPPROTO_UDP) {
		udphdr_auto_checksum();
		mov_ptr_cpy(&ptr, (char*)udp_header, sizeof(udp_hdr));
	}
	
	if (iphdr_get_proto() == IPPROTO_TCP) {
		tcphdr_auto_checksum();
		mov_ptr_cpy(&ptr, (char*)tcp_header, sizeof(tcp_hdr));
	}
	mov_ptr_cpy(&ptr, data, get_data_size());
	SUCCESS("raw packet successfully crafted.");
	return true;
}

char* raw_packet::get_crafted_packet() {
	return crafted_packet;
}

int raw_packet::get_crafted_packet_size() {
	return crafted_packet_sz;
}

void raw_packet::get_crafted_packet_hexdump() {
	if (crafted_packet == nullptr) {
		WARNING("raw packet is yet to be crafted.");
			return;
	}

	SetConsoleTextAttribute(color, 28);
	printf("crafted packet size: %d bytes\n", crafted_packet_sz);
	hexdump((unsigned char*)crafted_packet, crafted_packet_sz);
}