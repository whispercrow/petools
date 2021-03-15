#pragma once
#include "common.h"
#include "pe_struct.h"
#include "importtab.h"

typedef struct
{
	tstring SectionName;
	std::uint32_t RawBegin;
	std::uint32_t RawEnd;
	std::uint32_t RawEndReg;
	std::uint32_t RvaBegin;
	std::uint32_t RvaEnd;
	std::uint32_t RvaEndReg;
	std::uint32_t Characteristics;
} SECTIONELE, *PSECTIONELE;

class peparser
{
	friend class importtab;

public:
	explicit peparser(const std::tstring _szPePath);
	virtual ~peparser();

	bool check();
	bool is64bit();


	importtab ImportTable;

	

private:
	void InitPeHeader();
	void ParseSectionTable();
	std::uint32_t RvaToRaw(std::uint32_t _Rva);
	std::uint32_t RawToRva(std::uint32_t _Raw);


	HANDLE m_hFile = INVALID_HANDLE_VALUE;
	HANDLE m_hFileMap = NULL;
	byte* m_pView = NULL;

	bool m_IsValid = false;
	
	pe_header m_PeHeader = { 0 };
	size_t m_FileSize = 0;
	vector<SECTIONELE> m_SectionList;
};

