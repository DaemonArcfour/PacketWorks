#pragma once
#include "g_include.h"
char* iptos(u_long in);
void GetGateway(struct in_addr ip, char* sgatewayip, int* gatewayip);
void GetMacAddress(unsigned char* mac, in_addr destip);