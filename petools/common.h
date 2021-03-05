#pragma once
#include <windows.h>
#include <tchar.h>
#include <memory>
#include <string>
#include <sstream>
#include <fstream>
#include <iostream>
#include <iomanip>
#include <vector>
#include "dbgfunction.h"
#include "exception_seh.h"

using namespace std;

#ifdef _UNICODE
#define tchar wchar_t
#define tstring wstring
#define tstringbuffer wstringbuf
#define tstringstream wstringstream
#define tostringstream wostringstream
#define tistringstream wistringstream
#define tcout wcout


#else
#define tchar char
#define tstring string
#define tstringbuffer stringbuf
#define tstringstream stringstream
#define tostringstream ostringstream
#define tistringstream istringstream
#define tcout cout

#endif