#pragma once
#include "g_include.h"
void hexdump(unsigned char* data, unsigned int data_bytes);
void ParseMAC(std::string& mac_str, u_char* dst);