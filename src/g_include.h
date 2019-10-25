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

extern HANDLE color;

#define SUCCESS(...) SetConsoleTextAttribute(color, 10); printf("["); SetConsoleTextAttribute(color, 2); printf("+"); SetConsoleTextAttribute(color, 10); printf("] "); SetConsoleTextAttribute(color, 15); \
					 printf(__VA_ARGS__); SetConsoleTextAttribute(color, 7); printf("\n");

#define WARNING(...) SetConsoleTextAttribute(color, 14); printf("["); SetConsoleTextAttribute(color, 12); printf("!"); SetConsoleTextAttribute(color, 14); printf("] "); SetConsoleTextAttribute(color, 6); \
					 printf(__VA_ARGS__); SetConsoleTextAttribute(color, 7); printf("\n");