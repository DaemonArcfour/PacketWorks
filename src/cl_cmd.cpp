#include "g_include.h"
#include "sv_node.h"
#include "cl_node.h"
bool dismsg = false;
#define RAND_SUBNET rand()%255+1
#define RAND_PORT rand()%65535+1
#define CHKARG if(CommandQueue.empty()){ WARNING("Too few arguments.") break;}
HANDLE color = GetStdHandle(STD_OUTPUT_HANDLE);

const char* help_msg =  "Available commands:\n"
						"open_script <file>\n"
						"init_raw_udp\n"
						"init_raw_tcp\n"
						"init_raw_packet\n"
						"set_packet_data <file>\n"
						"set_source_ip <ip>\n"
						"set_source_port <port>\n"
						"set_source_mac <A1:B2:C3:D4:E5:F6>\n"
						"gen_rand_source_info\n"
						"set_destination_ip <ip>\n"
						"set_destination_port <port>\n"
						"get_data_dump\n"
						"get_crafted_packet_dump\n"
						"select_network_adapter\n"
						"toggle_messages\n"
						"send_packet\n"
						"wait <ms> [For scripting only]\n"
						"--------PWNode related stuff--------\n"
						"start_node\n"
						"stop_node\n"
						"set_node_key <file>\n"
						"set_remote_node <ip:port>\n"
						"send_node_packet\n";
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
	else if (cmd == "set_source_mac") return SET_SOURCE_MAC;
	else if (cmd == "gen_rand_source_info") return GEN_RAND_SOURCE_INFO;
	else if (cmd == "set_source_port") return SET_SOURCE_PORT;
	else if (cmd == "set_destination_port") return SET_DESTINATION_PORT;
	else if (cmd == "init_raw_tcp") return INIT_RAW_TCP;
	else if (cmd == "init_raw_udp") return INIT_RAW_UDP;
	else if (cmd == "init_raw_packet") return INIT_RAW_PACKET;
	else if (cmd == "open_script") return CMD_OPEN_SCRIPT;
	else if (cmd == "get_data_dump") return CMD_GET_DATA_DUMP;
	else if (cmd == "get_crafted_packet_dump") return CMD_GET_CRAFTED_DUMP;
	else if (cmd == "select_network_adapter") return CMD_SELECT_NETWORK_ADAPTER;
	else if (cmd == "send_packet") return CMD_SEND_PACKET;
	else if (cmd == "toggle_messages") return CMD_TGL_MSG;
	else if (cmd == "wait") return CMD_WAIT;
	else if (cmd == "help") return CMD_HELP;
	else if (cmd == "set_remote_node") return PWN_SET_REMOTE_NODE;
	else if (cmd == "send_node_packet") return PWN_SEND_NODE_PACKET;
	else if (cmd == "start_node") return PWN_START_NODE;
	else if (cmd == "stop_node") return PWN_STOP_NODE;
	else return UNKNOWN;
}
void PW_OpenScript(const char* script_file, std::queue<std::string>& ScriptQueue) {
	std::ifstream script(script_file);
	if (!script.is_open()) {
		WARNING("failed to open %s", script_file);
		return;
	}

	std::string line;
	int commands = 0;
	while (std::getline(script, line)) {
		ScriptQueue.push(line);
		commands++;
	}
	SUCCESS("%d commands were loaded into a queue.", commands);
	return;
}

void CommandLine() {
	srand(time(NULL));
	system("title PacketWorks v1.0");
	raw_packet packet;
	PW_Node_Client *PWNC = new PW_Node_Client;
	bNode = false;
	packet.adapter_address = new pcap_addr;
	SetConsoleTextAttribute(color, 10);
	puts(logo);
	SetConsoleTextAttribute(color, 7);
	printf("Your pcap version: %s\n", pcap_lib_version());
	puts("PacketWorks 1.0 by Daemon (https://github.com/DaemonArcfour/)\nExecute the \"help\" command for further instructions.");
	
	std::string CommandBuffer;
	command_token token;
	std::string PushCommand;
	std::queue <std::string> CommandQueue;
	std::queue <std::string> ScriptQueue;

	while (true) {
		if (ScriptQueue.empty()) {
			SetConsoleTextAttribute(color, 15); printf("PW"); SetConsoleTextAttribute(color, 6); printf("1.0"); SetConsoleTextAttribute(color, 15); printf("@> "); SetConsoleTextAttribute(color, 10);
			std::getline(std::cin, CommandBuffer);
			SetConsoleTextAttribute(color, 7);
		}
		
		else {
			CommandBuffer = ScriptQueue.front();
			ScriptQueue.pop();
		}

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
		case SET_SOURCE_MAC:
			CHKARG
			ParseMAC(CommandQueue.front(), &packet.s_mac[0]);
			break;
		case SET_SOURCE_PORT:
			CHKARG
			if (packet.iphdr_get_proto() == IPPROTO_UDP)
				packet.udphdr_set_src_port(atoi(CommandQueue.front().c_str()));
			else
				packet.tcphdr_set_src_port(atoi(CommandQueue.front().c_str()));
			break;
		case GEN_RAND_SOURCE_INFO:
			if (packet.initialized) {
				if (packet.iphdr_get_proto() == IPPROTO_UDP)
					packet.udphdr_set_src_port(RAND_PORT);
				else
					packet.tcphdr_set_src_port(RAND_PORT);

				packet.iphdr_set_src_addr(std::string(std::to_string(RAND_SUBNET) + "." + std::to_string(RAND_SUBNET) + "." + std::to_string(RAND_SUBNET) + "." + std::to_string(RAND_SUBNET)).c_str());
			}
			else {
				WARNING("init any type of raw packet first.");
			}
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
		case CMD_OPEN_SCRIPT:
			PW_OpenScript(CommandQueue.front().c_str(), ScriptQueue);
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
		case CMD_WAIT:
			CHKARG
			Sleep(atoi(CommandQueue.front().c_str()));
			break;

		case CMD_TGL_MSG:
			dismsg = !dismsg;
			break;

		case PWN_SET_REMOTE_NODE:
			CHKARG
			PWNC->PWNC_InitWinSock(CommandQueue.front());
			break;

		case PWN_SET_NODE_KEY:
			CHKARG
			PWNC->PWNC_SetCustomKey(CommandQueue.front());
			break;

		case PWN_SEND_NODE_PACKET:
			PWNC->PWNC_SendPacket(&packet);
			break;
		
		case PWN_START_NODE:
			bNode.store(true);
			std::thread(StartNode, &packet).detach();
			break;

		case PWN_STOP_NODE:
			if (bNode.load() == true) {
				WARNING("Node is pending for closing, receiving last packet!");
				bNode.store(false);
			}
			else {
				WARNING("Node is already set for closing.");
			}
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