#pragma once
#include "common.h"
#include "pe_struct.h"

class peparser
{
public:
	explicit peparser(const std::tstring _szPePath);
	virtual ~peparser();

	bool check();
	bool Is64Bit();


private:
	bool InitPeHeader();

	HANDLE m_hFile = INVALID_HANDLE_VALUE;
	HANDLE m_hFileMap = NULL;
	LPVOID m_pView = NULL;

	pe_header m_PeHeader = {0};

	bool m_IsValid = FALSE;
	size_t m_FileSize = 0;
};

