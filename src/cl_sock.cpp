#include "cl_sock.h"


void send_packet(raw_packet &packet) {
	if (packet.craft_raw_packet()) {
		if (pcap_sendpacket(packet.adapter, reinterpret_cast<u_char*>(packet.get_crafted_packet()), packet.get_crafted_packet_size()) == 0) {
			SUCCESS("sent %d bytes", packet.get_crafted_packet_size());
		}

		else {
			WARNING("pcap_sendpacket failed.");
		}
	}
}
