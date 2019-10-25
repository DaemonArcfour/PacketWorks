﻿#include "g_include.h"

#define CHKARG if(CommandQueue.empty()){ WARNING("Too few arguments.") break;}
HANDLE color = GetStdHandle(STD_OUTPUT_HANDLE);
const char* help_msg =  "Available commands:\n"
						"init_raw_udp\n"
						"init_raw_tcp\n"
						"init_raw_packet\n"
						"set_packet_data <file>\n"
						"set_source_ip <ip>\n"
						"set_source_port <port>\n"
						"set_destination_ip <ip>\n"
						"set_destination_port <port>\n"
						"get_data_dump\n"
						"get_crafted_packet_dump\n"
						"select_network_adapter\n"
						"send_packet\n";
const char* logo =
" _______  _     _  ____         _______\n"
"|       || | _ | ||    |       |  _    |\n"
"|    _  || || || | |   |       | | |   |\n"
"|   |_| ||       | |   |       | | |   |\n"
"|    ___||       | |   |  ___  | |_|   |\n"
"|   |    |   _   | |   | |   | |       |\n"
"|___|    |__| |__| |___| |___| |_______|\n";

command_token get_token(std::string const& cmd) {
	if (cmd == "set_packet_data") return SET_PACKET_DATA;
	else if (cmd == "set_source_ip") return SET_SOURCE_IP;
	else if (cmd == "set_destination_ip") return SET_DESTINATION_IP;
	else if (cmd == "set_source_port") return SET_SOURCE_PORT;
	else if (cmd == "set_destination_port") return SET_DESTINATION_PORT;
	else if (cmd == "init_raw_tcp") return INIT_RAW_TCP;
	else if (cmd == "init_raw_udp") return INIT_RAW_UDP;
	else if (cmd == "init_raw_packet") return INIT_RAW_PACKET;
	else if (cmd == "get_data_dump") return CMD_GET_DATA_DUMP;
	else if (cmd == "get_crafted_packet_dump") return CMD_GET_CRAFTED_DUMP;
	else if (cmd == "select_network_adapter") return CMD_SELECT_NETWORK_ADAPTER;
	else if (cmd == "send_packet") return CMD_SEND_PACKET;
	else if (cmd == "help") return CMD_HELP;
	else return UNKNOWN;
}

void CommandLine() {
	raw_packet packet;
	SetConsoleTextAttribute(color, 10);
	puts(logo);
	SetConsoleTextAttribute(color, 7);
	printf("Your pcap version: %s\n", pcap_lib_version());
	puts("PacketWorks 1.0 by Daemon (https://github.com/DaemonArcfour/)\nExecute the \"help\" command for further instructions.");
	
	std::string CommandBuffer;
	command_token token;
	std::string PushCommand;
	std::queue <std::string> CommandQueue;

	while (true) {
		SetConsoleTextAttribute(color, 15); printf("PW"); SetConsoleTextAttribute(color, 6); printf("1.0"); SetConsoleTextAttribute(color, 15); printf("@> "); SetConsoleTextAttribute(color, 10);
		std::getline(std::cin, CommandBuffer);
		SetConsoleTextAttribute(color, 7);
		if (CommandBuffer.empty())
			continue;
		std::stringstream stream(CommandBuffer);
		while (std::getline(stream, PushCommand, ' '))
			CommandQueue.push(PushCommand);

		token = get_token(CommandQueue.front());
		CommandQueue.pop();
		switch (token) {
		case SET_PACKET_DATA:
			CHKARG
			packet.load_bin_data(CommandQueue.front().c_str());
			break;
		case SET_SOURCE_IP:
			CHKARG
			packet.iphdr_set_src_addr(CommandQueue.front().c_str());
			break;

		case SET_DESTINATION_IP:
			CHKARG
			packet.iphdr_set_dst_addr(CommandQueue.front().c_str());
			break;

		case SET_SOURCE_PORT:
			CHKARG
			if (packet.iphdr_get_proto() == IPPROTO_UDP)
				packet.udphdr_set_src_port(atoi(CommandQueue.front().c_str()));
			else
				packet.tcphdr_set_src_port(atoi(CommandQueue.front().c_str()));
			break;

		case SET_DESTINATION_PORT:
			CHKARG
			if (packet.iphdr_get_proto() == IPPROTO_UDP)
				packet.udphdr_set_dst_port(atoi(CommandQueue.front().c_str()));
			else
				packet.tcphdr_set_dst_port(atoi(CommandQueue.front().c_str()));
			break;

		case INIT_RAW_TCP:
			packet.init_raw_tcp();
			break;

		case INIT_RAW_UDP:
			packet.init_raw_udp();
			break;
		
		case INIT_RAW_PACKET:
			packet.craft_raw_packet();
			break;

		case CMD_GET_DATA_DUMP:
			packet.get_data_hexdump();
			break;

		case CMD_GET_CRAFTED_DUMP:
			packet.get_crafted_packet_hexdump();
			break;

		case CMD_SELECT_NETWORK_ADAPTER:
			WINPCAP_SelectDevice(packet);
			break;

		case CMD_SEND_PACKET:
			send_packet(packet);
			break;
		
		case CMD_HELP:
			puts(help_msg);
			break;

		case UNKNOWN:
			puts("unknown command");
			break;

		default:
			puts("pls explain how you managed to do that"); //wtf?
			break;
		}

		while (!CommandQueue.empty())
			CommandQueue.pop();
		Sleep(5);
	}
}