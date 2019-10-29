#include "mem_hexdump.h"
#include <algorithm>

void ParseMAC(std::string& mac_str, u_char* dst) {
	std::queue<char> bytes;
	mac_str.erase(std::remove(mac_str.begin(), mac_str.end(), ':'), mac_str.end());
	for (unsigned int i = 0; i < mac_str.length(); i += 2) {
		std::string byteString = mac_str.substr(i, 2);
		char byte = (char)strtol(byteString.c_str(), NULL, 16);
		bytes.push(byte);
	}
	if (bytes.size() != 6) {
		WARNING("invalid MAC.");
		return;
	}

	int index = 0;
	while (!bytes.empty()) {
		dst[index] = bytes.front();
		bytes.pop();
		index++;
	}

	SUCCESS("Host's MAC is now: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X", dst[0], dst[1], dst[2], dst[3], dst[4], dst[5]);
}

void hexdump(unsigned char* data, unsigned int data_bytes)
{
	int bin_p, ascii_p;

	bin_p = ascii_p = 0;

	while (bin_p < data_bytes) {
		int j;
		int whitespaces;
		SetConsoleTextAttribute(color, 27);
		for (j = 0; j < 8 && bin_p < data_bytes; j++) {
			printf("%02x ", data[bin_p++]);
		}
		SetConsoleTextAttribute(color, 17);
		whitespaces = (8 - j) * 3;
		for (j = 0; j < whitespaces; j++) {
			printf(" ");
		}
		SetConsoleTextAttribute(color, 59);
		for (j = 0; j < 8 && ascii_p < data_bytes; j++) {
			if (isprint(data[ascii_p])) {
				printf("%c", data[ascii_p++]);
			}
			else {
				printf(".");
				ascii_p++;
			}
		}
		SetConsoleTextAttribute(color, 7);
		printf("\n");
	}
}
