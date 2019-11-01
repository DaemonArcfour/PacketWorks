#pragma once
#include "g_include.h"
class PW_DataBuffer {
private:
	PTCHAR DataBuffer = nullptr;
	PTCHAR W_PTR = nullptr;
	int32_t Size = NULL;
	int32_t LeftSpace = NULL;
public:
	void PWD_ClearBuffer() {
		if (Size == 0 || DataBuffer == nullptr) {
			WARNING_MT("PW_DataBuffer was not initialized.");
			return;
		}
		ZeroMemory(DataBuffer, Size);
		CopyMemory(&W_PTR, &DataBuffer, sizeof(PTCHAR));
		LeftSpace = Size;
	}

	void PWD_InitBuffer(int32_t iSize) {
		if (DataBuffer != nullptr) {
			ZeroMemory(DataBuffer, iSize);
			delete[] DataBuffer;
		}

		DataBuffer = new CHAR[iSize];
		CopyMemory(&W_PTR, &DataBuffer, sizeof(PTCHAR));
		Size = iSize;
		LeftSpace = iSize;
	}

	void PWD_WriteToBuffer(PTCHAR Source, int32_t iSize) {
		if (Size == 0 || DataBuffer == nullptr) {
			WARNING_MT("PW_DataBuffer was not initialized.");
			return;
		}

		if (LeftSpace < iSize) {
			WARNING_MT("PW_DataBuffer: overflow!");
			return;
		}

		CopyMemory(W_PTR, Source, iSize);
		W_PTR += iSize;
		LeftSpace -= iSize;
	}

	int32_t PWD_GetBufferDataLength() {
		return (Size - LeftSpace);
	}

	int32_t PWD_GetBufferSize() {
		return Size;
	}

	PTCHAR PWD_GetBuffer() {
		return DataBuffer;
	}
};