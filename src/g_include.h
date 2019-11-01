#pragma once
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#define HAVE_REMOTE
#define NOMINMAX

#include <iostream>
#include <conio.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <Windows.h>
#include <stdio.h>
#include <string>
#include <cassert>
#include <atomic>
#include <thread>
#include <sstream>
#include <string>
#include <queue>
#include <fstream>
#include <iphlpapi.h>

extern bool dismsg;
extern HANDLE color;

#define MT_MOVE_CIN printf("%c[2K", 27); printf("\33[2K");

#define SUCCESS(...) if(!dismsg){SetConsoleTextAttribute(color, 10); printf("["); SetConsoleTextAttribute(color, 2); printf("+"); SetConsoleTextAttribute(color, 10); printf("] "); SetConsoleTextAttribute(color, 15); \
					 printf(__VA_ARGS__); SetConsoleTextAttribute(color, 7); printf("\n");}

#define WARNING(...) if(!dismsg){SetConsoleTextAttribute(color, 14); printf("["); SetConsoleTextAttribute(color, 12); printf("!"); SetConsoleTextAttribute(color, 14); printf("] "); SetConsoleTextAttribute(color, 6); \
					 printf(__VA_ARGS__); SetConsoleTextAttribute(color, 7); printf("\n");}

#define WARNING_MT(...) WARNING(__VA_ARGS__) MT_MOVE_CIN

#define SUCCESS_MT(...) SUCCESS(__VA_ARGS__) MT_MOVE_CIN

#include "mem_dynbuf.h"
#include "pcap.h"

#include "cl_gateway.h"
#include "winpcap_setup.h"
#include "mem_hexdump.h"
#include "cl_cmd.h"
#include "raw_packet.h"
#include "cl_sock.h"
#include "winpcap_setup.h"

#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "wpcap.lib")
#pragma comment (lib, "Packet.lib")
#pragma comment (lib, "iphlpapi.lib")

