#pragma once
#include <windows.h>
#include <stdio.h>

#ifdef _UNICODE
#define DbgPrint DbgPrintW
#define MyOutputDebugMsg MyOutputDebugMsgW
#define MyDbgMessageBox MyDbgMessageBoxW
#define __TFILE__ __FILEW__
#define __TFUNCTION__ __FUNCTIONW__
#else
#define MyOutputDebugMsg MyOutputDebugMsgA
#define DbgPrint DbgPrintA
#define MyDbgMessageBox MyDbgMessageBoxA
#define __TFILE__ __FILE__
#define __TFUNCTION__ __FUNCTION__
#endif

#define DbgPrintA(MSG, ...) {\
size_t __nFormat = _scprintf("[%s:%d T:%d] %s\n", __FILE__, __LINE__, GetCurrentThreadId(), MSG) + 1; \
char* __szFormat = new char[__nFormat]; \
sprintf_s(__szFormat, __nFormat, "[%s:%d T:%d] %s\n", __FILE__, __LINE__, GetCurrentThreadId(), MSG); \
MyOutputDebugMsgA(__szFormat, __VA_ARGS__); \
delete[] __szFormat;}

#define DbgPrintW(MSG, ...) {\
size_t __nFormat = _scwprintf(L"[%s:%d T:%d] %s\n", __FILEW__, __LINE__, GetCurrentThreadId(), MSG) + 1; \
wchar_t* __szFormat = new wchar_t[__nFormat]; \
swprintf_s(__szFormat, __nFormat, L"[%s:%d T:%d] %s\n", __FILEW__, __LINE__, GetCurrentThreadId(), MSG); \
MyOutputDebugMsgW(__szFormat, __VA_ARGS__); \
delete[] __szFormat;}

static void MyOutputDebugMsgW(const wchar_t* szOutputFormat, ...)
{
	va_list vlArgs = NULL;
	va_start(vlArgs, szOutputFormat);
	size_t nLen = (size_t)_vscwprintf(szOutputFormat, vlArgs) + 1;
	wchar_t* szBuffer = new wchar_t[nLen];
	if (NULL != szBuffer)
	{
		_vsnwprintf_s(szBuffer, nLen, nLen - 1, szOutputFormat, vlArgs);
		OutputDebugStringW(szBuffer);
		delete[] szBuffer;
	}
	va_end(vlArgs);
}

static void MyOutputDebugMsgA(const char* szOutputFormat, ...)
{
	va_list vlArgs = NULL;
	va_start(vlArgs, szOutputFormat);
	size_t nLen = (size_t)_vscprintf(szOutputFormat, vlArgs) + 1;
	char* szBuffer = new char[nLen];
	if (NULL != szBuffer)
	{
		_vsnprintf_s(szBuffer, nLen, nLen - 1, szOutputFormat, vlArgs);
		OutputDebugStringA(szBuffer);
		delete[] szBuffer;
	}
	va_end(vlArgs);
}

static void MyDbgMessageBoxW(const wchar_t* szOutputFormat, ...)
{
	va_list vlArgs = NULL;
	va_start(vlArgs, szOutputFormat);
	size_t nLen = (size_t)_vscwprintf(szOutputFormat, vlArgs) + 1;
	wchar_t* szBuffer = new wchar_t[nLen];
	if (NULL != szBuffer)
	{
		_vsnwprintf_s(szBuffer, nLen, nLen - 1, szOutputFormat, vlArgs);
		MessageBoxW(NULL, szBuffer, L"Debug", MB_OK);
		delete[] szBuffer;
	}
	va_end(vlArgs);
}

static void MyDbgMessageBoxA(const char* szOutputFormat, ...)
{
	va_list vlArgs = NULL;
	va_start(vlArgs, szOutputFormat);
	size_t nLen = (size_t)_vscprintf(szOutputFormat, vlArgs) + 1;
	char* szBuffer = new char[nLen];
	if (NULL != szBuffer)
	{
		_vsnprintf_s(szBuffer, nLen, nLen - 1, szOutputFormat, vlArgs);
		MessageBoxA(NULL, szBuffer, "Debug", MB_OK);
		delete[] szBuffer;
	}
	va_end(vlArgs);
}

static void BinPrint(const void* bBinaryData, unsigned int iSize)
{

#ifdef _WIN64
#define POINTLEN "16"
#else
#define POINTLEN "8"
#endif

	unsigned int LINEBYTEMAX = 16;
	const byte* bCurrentBinary = (const byte*)bBinaryData;

	MyOutputDebugMsg(TEXT("[==================================Binary data on 0x%0") TEXT(POINTLEN) TEXT("x total %u bytes==================================]\n"), bBinaryData, iSize);

	do
	{
		unsigned int iThisLineOutNum = LINEBYTEMAX > iSize ? iSize : LINEBYTEMAX;
		MyOutputDebugMsg(TEXT("0x%0") TEXT(POINTLEN) TEXT("x  "), bCurrentBinary);

		for (unsigned int index = 0; index < LINEBYTEMAX; ++index)
		{
			if (index < iThisLineOutNum)
			{
				MyOutputDebugMsg(TEXT("%02x  "), *(bCurrentBinary + index));
			}
			else
			{
				OutputDebugString(TEXT("    "));
			}

		}

		OutputDebugString(TEXT("   "));

		for (unsigned int index = 0; index < iThisLineOutNum; ++index)
		{
			bool bIsprint = *(bCurrentBinary + index) >= 0x20 && *(bCurrentBinary + index) <= 0x7f ? true : false;
			MyOutputDebugMsg(TEXT("%c "), bIsprint ? *(bCurrentBinary + index) : TEXT('.'));
		}

		OutputDebugString(TEXT("\n"));
		bCurrentBinary += iThisLineOutNum;
	} while (iSize > LINEBYTEMAX ? iSize -= LINEBYTEMAX : 0);
}
