#pragma once
#include <windows.h>

static const wchar_t* ConvertUtf8ToUnicode(const char* _ansiUtf8)
{
	if (_ansiUtf8 == NULL)
	{
		return L"";
	}
	int len = MultiByteToWideChar(CP_UTF8, 0, _ansiUtf8, -1, NULL, 0);
	wchar_t* wszUnicode = new wchar_t[len + 1];
	memset(wszUnicode, 0, (len + 1) * sizeof(wchar_t));
	MultiByteToWideChar(CP_UTF8, 0, _ansiUtf8, -1, wszUnicode, len);
	return wszUnicode;
}


static const char* ConvertUnicodeToUtf8(const wchar_t* _szUnicode)
{
	if (_szUnicode == NULL)
	{
		return "";
	}
	int len = WideCharToMultiByte(CP_UTF8, 0, _szUnicode, -1, NULL, 0, NULL, NULL);
	char* szUtf8 = new char[len + 1];
	memset(szUtf8, 0, (len + 1) * sizeof(char));
	WideCharToMultiByte(CP_UTF8, 0, _szUnicode, -1, szUtf8, len, NULL, NULL);
	return szUtf8;
}


static const wchar_t* ConvertAnsiToUnicode(const char* _szAnsi)
{
	if (_szAnsi == NULL)
	{
		return L"";
	}
	int len = MultiByteToWideChar(CP_ACP, 0, _szAnsi, -1, NULL, 0);
	wchar_t* wszUnicode = new wchar_t[len + 1];
	memset(wszUnicode, 0, (len + 1) * sizeof(wchar_t));
	MultiByteToWideChar(CP_ACP, 0, _szAnsi, -1, wszUnicode, len);
	return wszUnicode;
}


static const char* ConvertUnicodeToAnsi(const wchar_t* _szUnicode)
{
	if (_szUnicode == NULL)
	{
		return "";
	}
	int len = WideCharToMultiByte(CP_ACP, 0, _szUnicode, -1, NULL, 0, NULL, NULL);
	char* szAnsi = new char[len + 1];
	memset(szAnsi, 0, (len + 1) * sizeof(char));
	WideCharToMultiByte(CP_ACP, 0, _szUnicode, -1, szAnsi, len, NULL, NULL);
	return szAnsi;
}


static const char* ConvertAnsiToUtf8(const char* _szAnsi)
{
	if (NULL == _szAnsi)
	{
		return "";
	}
	DWORD dwAnsiLen = MultiByteToWideChar(CP_ACP, NULL, _szAnsi, -1, NULL, NULL);
	wchar_t* szTmpUnicode = new wchar_t[dwAnsiLen + 1];
	memset(szTmpUnicode, 0, sizeof(wchar_t) * (dwAnsiLen + 1));
	MultiByteToWideChar(CP_ACP, NULL, _szAnsi, -1, szTmpUnicode, dwAnsiLen);

	DWORD dwUtf8Len = WideCharToMultiByte(CP_UTF8, 0, szTmpUnicode, -1, NULL, 0, NULL, NULL);
	char* szUtf8 = new char[dwUtf8Len + 1];
	memset(szUtf8, 0, sizeof(char) * (dwUtf8Len + 1));
	WideCharToMultiByte(CP_UTF8, 0, szTmpUnicode, -1, szUtf8, dwUtf8Len, NULL, NULL);
	delete[] szTmpUnicode;

	return szUtf8;
}


static const char* ConvertUtf8ToAnsi(const char* _szUtf8)
{
	if (NULL == _szUtf8)
	{
		return "";
	}
	DWORD dwAnsiLen = MultiByteToWideChar(CP_UTF8, NULL, _szUtf8, -1, NULL, NULL);
	wchar_t* szTmpUnicode = new wchar_t[dwAnsiLen + 1];
	memset(szTmpUnicode, 0, sizeof(wchar_t) * (dwAnsiLen + 1));
	MultiByteToWideChar(CP_UTF8, NULL, _szUtf8, -1, szTmpUnicode, dwAnsiLen);

	DWORD dwUtf8Len = WideCharToMultiByte(CP_ACP, 0, szTmpUnicode, -1, NULL, 0, NULL, NULL);
	char* szAnsi = new char[dwUtf8Len + 1];
	memset(szAnsi, 0, sizeof(char) * (dwUtf8Len + 1));
	WideCharToMultiByte(CP_ACP, 0, szTmpUnicode, -1, szAnsi, dwUtf8Len, NULL, NULL);
	delete[] szTmpUnicode;

	return szAnsi;
}