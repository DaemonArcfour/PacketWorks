#include "mem_hexdump.h"

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
