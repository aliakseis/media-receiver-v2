#pragma once

#include <windows.h> 
#include <stdarg.h>    

#include <cstdio>

#if 0
#define Warning(...) ((void)0)
#define Debug(...) ((void)0)

#endif

#define Hexdump(...) ((void)0)

inline void Debug(int level, char* strMsg, ...)
{
	char strBuffer[4096];

	va_list args;
	va_start(args, strMsg);
	int length = vsnprintf(strBuffer, 4095, strMsg, args);
	va_end(args);

	strBuffer[length] = '\n';
	strBuffer[length + 1] = 0;

	OutputDebugStringA(strBuffer);
}

inline void Warning(char* strMsg, ...)
{
	char strBuffer[4096];

	va_list args;
	va_start(args, strMsg);
	int length = vsnprintf(strBuffer, 4095, strMsg, args);
	va_end(args);

	strBuffer[length] = '\n';
	strBuffer[length + 1] = 0;

	OutputDebugStringA(strBuffer);
}

#define Info Warning
#define Error Warning

