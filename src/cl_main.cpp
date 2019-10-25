#include "cl_main.h"

int main()
{
	std::thread CommandLineThread(CommandLine);
	while (true)
		Sleep(1000);
	return 0;
}