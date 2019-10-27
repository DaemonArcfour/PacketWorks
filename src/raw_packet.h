#pragma once
#include "g_include.h"
#define MAX_PACKET_LENGTH 65535

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
	eth_hdr* eth_header;
	ip_hdr* ip_header;
	tcp_hdr* tcp_header;
	udp_hdr* udp_header;
	char* data;
	int data_sz;
	char* crafted_packet;
	int crafted_packet_sz = 0;
	struct sockaddr_in src_addr;
	struct sockaddr_in dst_addr;
	bool initiated = false;
public:
	pcap_t* adapter;
	pcap_addr* adapter_address;
	bool craft_raw_packet();
	void get_crafted_packet_hexdump();
	int get_crafted_packet_size();
	char* get_crafted_packet();

	void dealloc_mem();
	void init_eth_layer();
	void init_raw_tcp();
	void init_raw_udp();

	void load_bin_data(const char* file_loc);
	char* get_data_ptr();
	int get_data_size();
	void get_data_hexdump();
	void dealloc_data();

	void iphdr_set_len(unsigned char);
	void iphdr_set_total_len(int);
	void iphdr_set_hdr_len(unsigned char);
	void iphdr_set_ttl(unsigned char);
	void iphdr_auto_checksum();
	void iphdr_set_chksum(unsigned short);
	void iphdr_set_proto(unsigned char);
	void iphdr_set_dst_addr(const char*);
	void iphdr_set_src_addr(const char*);
	void iphdr_set_version(unsigned char);
	void iphdr_set_id(int);
	unsigned char iphdr_get_proto();

	void udphdr_set_src_port(int);
	void udphdr_set_dst_port(int);
	void udphdr_set_len(int);
	void udphdr_set_chksum(unsigned short);
	void udphdr_auto_checksum();

	void tcphdr_set_src_port(int);
	void tcphdr_set_dst_port(int);
	void tcphdr_set_chksum(unsigned short);
	void tcphdr_auto_checksum();
	void tcphdr_set_seqnum(unsigned int);
	void tcphdr_gen_seqnum();
	void tcphdr_set_ack(unsigned int);
	unsigned short tcphdr_get_len();


	sockaddr_in get_dst_sockaddr_in() {
		return dst_addr;
	}

	sockaddr_in get_src_sockaddr_in() {
		return src_addr;
	}
};
