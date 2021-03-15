#include "peparser.h"

peparser::peparser(const std::tstring _szPePath) :
	ImportTable( this )
{
	if (true == _szPePath.empty())
	{
		return;
	}

	WIN32_FILE_ATTRIBUTE_DATA stfileInfo;
	ZeroMemory(&stfileInfo, sizeof(stfileInfo));
	if (FALSE == GetFileAttributesEx(_szPePath.c_str(), GetFileExInfoStandard, &stfileInfo))
	{
		return;
	}

	if (stfileInfo.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
	{
		return;
	}

	m_FileSize = ((std::uint64_t)stfileInfo.nFileSizeHigh << 32) + stfileInfo.nFileSizeLow;
	
	m_hFile = CreateFile(_szPePath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL,NULL);
	if (INVALID_HANDLE_VALUE == m_hFile)
	{
		return;
	}

	m_hFileMap = CreateFileMapping(m_hFile, NULL, PAGE_READONLY, 0, 0, NULL);
	if (NULL == m_hFileMap)
	{
		return;
	}

	m_pView = (byte *)MapViewOfFile(m_hFileMap, FILE_MAP_READ, 0, 0, 0);
	if (NULL == m_pView)
	{
		return;
	}

	this->InitPeHeader();
	this->ParseSectionTable();
	ImportTable.init();
}

peparser::~peparser()
{
	if (NULL != m_pView)
	{
		UnmapViewOfFile(m_pView);
		m_pView = NULL;
	}

	if (NULL != m_hFileMap)
	{
		CloseHandle(m_hFileMap);
		m_hFileMap = NULL;
	}

	if (NULL != m_hFile)
	{
		CloseHandle(m_hFile);
		m_hFile = NULL;
	}
}

bool peparser::check()
{
	//check dos header magic
	if (m_PeHeader.dos_header.e_magic != DOS_MAGIC_MZ) { return false; }

	//check nt header magic
	if (m_PeHeader.nt_header.Signature != NT_MAGIC_PE) { return false; }
	
	//check nt header is PE32 or PE32+ executable
	if (m_PeHeader.nt_header.PlatformMagic != NT_OPTIONAL_32PE_MAGIC && 
		m_PeHeader.nt_header.PlatformMagic != NT_OPTIONAL_64PE_MAGIC)
	{
		return false;
	}

	//check nt header characteristics is exe ,dll or sys
	if (false == (m_PeHeader.nt_header.FileHeader.Characteristics & NT_FILE_EXECUTABLE_IMAGE) &&
		false == (m_PeHeader.nt_header.FileHeader.Characteristics & NT_FILE_DLL) &&
		false == (m_PeHeader.nt_header.FileHeader.Characteristics & NT_FILE_SYSTEM))
	{
		return false;
	}

	//check section num
	if (2> m_PeHeader.nt_header.FileHeader.NumberOfSections || 2 > m_SectionList.size()) { return false; }
	if (m_PeHeader.nt_header.FileHeader.NumberOfSections != m_SectionList.size()) { return false; }

	//check every Platform
	if (m_PeHeader.nt_header.PlatformMagic == NT_OPTIONAL_32PE_MAGIC)
	{
		if (m_PeHeader.nt_header.OptionalHeader32.Magic != NT_OPTIONAL_32PE_MAGIC) { return false; }

		if (m_PeHeader.nt_header.FileHeader.Machine != NT_FILE_MACHINE_AMD32) { return false; }

		if (false == (m_PeHeader.nt_header.FileHeader.Characteristics & NT_FILE_32BIT_MACHINE)) { return false; }

		if (m_PeHeader.nt_header.OptionalHeader32.Win32VersionValue != 0) { return false; }

		if (m_PeHeader.nt_header.OptionalHeader32.NumberOfRvaAndSizes != NUM_DIR_ENTRIES) { return false; }

		if (m_PeHeader.nt_header.OptionalHeader32.ImageBase % 0x10000 != 0) { return false; }

		if (m_PeHeader.nt_header.OptionalHeader32.SectionAlignment < 2) { return false; }

		if (m_PeHeader.nt_header.OptionalHeader32.FileAlignment < 2) { return false; }

		if (m_PeHeader.nt_header.FileHeader.Characteristics & NT_FILE_EXECUTABLE_IMAGE)
		{
			 if (m_PeHeader.nt_header.OptionalHeader32.Subsystem != NT_OPTIONAL_SUBSYSTEM_WINDOWS_GUI &&
				m_PeHeader.nt_header.OptionalHeader32.Subsystem != NT_OPTIONAL_SUBSYSTEM_WINDOWS_CUI &&
				m_PeHeader.nt_header.OptionalHeader32.Subsystem != NT_OPTIONAL_SUBSYSTEM_NATIVE)
			{
				return false;
			}
		}

		//check size of pe header
		std::uint32_t nDisFormFistSection = 0;
		size_t nSectionNum = 0;
		while (nSectionNum < m_SectionList.size())
		{
			if (0 != m_SectionList.at(nSectionNum).RawBegin)
			{
				if (0 != m_SectionList.at(nSectionNum).RawEnd - m_SectionList.at(nSectionNum).RawBegin)
				{
					nDisFormFistSection = m_SectionList.at(nSectionNum).RawBegin;
				}
				else
				{
					nDisFormFistSection = m_SectionList.at(nSectionNum).RvaBegin;
				}

				break;
			}

			nSectionNum++;			
		}

		if (m_PeHeader.nt_header.OptionalHeader32.SizeOfHeaders != nDisFormFistSection) { return false; }

		//check size of image
		if (m_PeHeader.nt_header.OptionalHeader32.SizeOfImage != m_SectionList.at(m_SectionList.size() - 1).RvaEndReg) { return false; }


	}
	else if(m_PeHeader.nt_header.PlatformMagic == NT_OPTIONAL_64PE_MAGIC)
	{
		if (m_PeHeader.nt_header.OptionalHeader64.Magic != NT_OPTIONAL_64PE_MAGIC) { return false; }

		if (m_PeHeader.nt_header.FileHeader.Machine != NT_FILE_MACHINE_AMD64) { return false; }

		if (false == (m_PeHeader.nt_header.FileHeader.Characteristics & NT_FILE_LARGE_ADDRESS_AWARE)) { return false; }

		if (m_PeHeader.nt_header.OptionalHeader64.Win32VersionValue != 0) { return false; }

		if (m_PeHeader.nt_header.OptionalHeader64.NumberOfRvaAndSizes != NUM_DIR_ENTRIES) { return false; }

		if (m_PeHeader.nt_header.OptionalHeader64.ImageBase % 0x10000 != 0) { return false; }

		if (m_PeHeader.nt_header.OptionalHeader64.SectionAlignment < 2) { return false; }

		if (m_PeHeader.nt_header.OptionalHeader64.FileAlignment < 2) { return false; }

		if (m_PeHeader.nt_header.FileHeader.Characteristics & NT_FILE_EXECUTABLE_IMAGE)
		{
			if (m_PeHeader.nt_header.OptionalHeader64.Subsystem != NT_OPTIONAL_SUBSYSTEM_WINDOWS_GUI &&
				m_PeHeader.nt_header.OptionalHeader64.Subsystem != NT_OPTIONAL_SUBSYSTEM_WINDOWS_CUI &&
				m_PeHeader.nt_header.OptionalHeader64.Subsystem != NT_OPTIONAL_SUBSYSTEM_NATIVE)
			{
				return false;
			}
		}

		
		//check size of pe header
		std::uint32_t nDisFormFistSection = 0;
		size_t nSectionNum = 0;
		while (nSectionNum < m_SectionList.size())
		{
			if (0 != m_SectionList.at(nSectionNum).RawBegin)
			{
				if (0 != m_SectionList.at(nSectionNum).RawEnd - m_SectionList.at(nSectionNum).RawBegin)
				{
					nDisFormFistSection = m_SectionList.at(nSectionNum).RawBegin;
				}
				else
				{
					nDisFormFistSection = m_SectionList.at(nSectionNum).RvaBegin;
				}

				break;
			}

			nSectionNum++;
		}

		if (m_PeHeader.nt_header.OptionalHeader64.SizeOfHeaders != nDisFormFistSection) { return false; }

		//check size of image
		if (m_PeHeader.nt_header.OptionalHeader64.SizeOfImage != m_SectionList.at(m_SectionList.size() - 1).RvaEndReg) { return false; }

	}


	
	
	
	m_IsValid = true;
	return true;
}

bool peparser::is64bit()
{
	return m_PeHeader.nt_header.PlatformMagic == NT_OPTIONAL_64PE_MAGIC;
}

void peparser::InitPeHeader()
{
	if (NULL == m_pView || 0 == m_FileSize)
	{
		return;
	}

	ZeroMemory(&m_PeHeader, sizeof(m_PeHeader));

	size_t nParseBeg = 0;
	size_t nParseEnd = 0;

	if ((nParseEnd += sizeof(dos_header)) >= m_FileSize) { return; }

	memcpy(&m_PeHeader.dos_header, m_pView + nParseBeg, nParseEnd - nParseBeg);
	
	nParseBeg = m_PeHeader.dos_header.e_lfanew;
	nParseEnd = m_PeHeader.dos_header.e_lfanew;
	if ((nParseEnd += sizeof(m_PeHeader.nt_header.Signature) + sizeof(m_PeHeader.nt_header.FileHeader)) >= m_FileSize) { return; }


	memcpy(&m_PeHeader.nt_header, m_pView + nParseBeg, nParseEnd - nParseBeg);

	if (nParseEnd + sizeof(std::uint16_t) >= m_FileSize) { return; }

	nParseBeg = nParseEnd;
	if (*(std::uint16_t *)(m_pView + nParseEnd) == NT_OPTIONAL_32PE_MAGIC)
	{
		m_PeHeader.nt_header.PlatformMagic = NT_OPTIONAL_32PE_MAGIC;
		if ((nParseEnd += sizeof(m_PeHeader.nt_header.OptionalHeader32)) >= m_FileSize) { return; }
		memcpy(&m_PeHeader.nt_header.OptionalHeader32, m_pView + nParseBeg, nParseEnd - nParseBeg);

	}
	else if(*(std::uint16_t*)(m_pView + nParseEnd) == NT_OPTIONAL_64PE_MAGIC)
	{
		m_PeHeader.nt_header.PlatformMagic = NT_OPTIONAL_64PE_MAGIC;
		if ((nParseEnd += sizeof(m_PeHeader.nt_header.OptionalHeader64)) >= m_FileSize) { return; }
		memcpy(&m_PeHeader.nt_header.OptionalHeader64, m_pView + nParseBeg, nParseEnd - nParseBeg);

	}
	

	return;
}

void peparser::ParseSectionTable()
{
	m_SectionList.clear();

	std::uint32_t nFileAlignment = 0;
	std::uint32_t nRvaAlignment = 0;

	if (m_PeHeader.nt_header.PlatformMagic == NT_OPTIONAL_32PE_MAGIC)
	{
		nFileAlignment = m_PeHeader.nt_header.OptionalHeader32.FileAlignment;
		nRvaAlignment = m_PeHeader.nt_header.OptionalHeader32.SectionAlignment;
	}
	else if (m_PeHeader.nt_header.PlatformMagic == NT_OPTIONAL_64PE_MAGIC)
	{
		nFileAlignment = m_PeHeader.nt_header.OptionalHeader64.FileAlignment;
		nRvaAlignment = m_PeHeader.nt_header.OptionalHeader64.SectionAlignment;
	}
	else
	{
		return;
	}

	size_t nParseBeg = 0;
	size_t nParseEnd = 0;
	
	nParseBeg = m_PeHeader.dos_header.e_lfanew + 
		sizeof(m_PeHeader.nt_header.Signature) + 
		sizeof(m_PeHeader.nt_header.FileHeader) +
		m_PeHeader.nt_header.FileHeader.SizeOfOptionalHeader;
	
	if (nParseBeg >= m_FileSize) { return; }

	std::uint16_t nSectionNum = m_PeHeader.nt_header.FileHeader.NumberOfSections;
	while (nSectionNum--)
	{
		nParseEnd = nParseBeg + sizeof(image_section_header);
		if (nParseEnd > m_FileSize) { break; }

		image_section_header* pSectionHeader = (image_section_header*)(m_pView + nParseBeg);
		nParseBeg = nParseEnd;

		std::uint32_t nRawBegin = pSectionHeader->PointerToRawData;
		std::uint32_t nRawEnd = nRawBegin + pSectionHeader->SizeOfRawData;
		std::uint32_t nRawEndReg = nRawEnd % nFileAlignment ? (nRawEnd ? nRawEnd / nFileAlignment + 1 : 0) * nFileAlignment : nRawEnd;

		std::uint32_t nRvaBegin = pSectionHeader->VirtualAddress;
		std::uint32_t nRvaEnd = nRvaBegin + pSectionHeader->Misc.VirtualSize;
		std::uint32_t nRvaEndReg = nRvaEnd % nRvaAlignment ? (nRvaEnd ? nRvaEnd / nRvaAlignment + 1 : 0) * nRvaAlignment : nRvaEnd;

#ifdef _UNICODE
		const wchar_t* szUnicodeSectionName = ConvertAnsiToUnicode(string((char*)pSectionHeader->Name, 8).c_str());
		const wstring szSectionName = szUnicodeSectionName;
		delete[] szUnicodeSectionName;
#else
		const string szSectionName((char*)pSectionHeader->Name, 8);
#endif

		SECTIONELE section;
		section.SectionName = szSectionName;
		section.RawBegin = nRawBegin;
		section.RawEnd = nRawEnd;
		section.RawEndReg = nRawEndReg;
		section.RvaBegin = nRvaBegin;
		section.RvaEnd = nRvaEnd;
		section.RvaEndReg = nRvaEndReg;
		section.Characteristics = pSectionHeader->Characteristics;

		m_SectionList.push_back(section);

	}


	return;
}

std::uint32_t peparser::RvaToRaw(std::uint32_t _Rva)
{
	std::uint32_t nRaw = -1;

	for (auto iterSection : m_SectionList)
	{
		if (_Rva >= iterSection.RvaBegin && _Rva <= iterSection.RvaEnd)
		{
			nRaw = iterSection.RawBegin + _Rva - iterSection.RvaBegin;
			break;
		}
	}

	return nRaw;
}

std::uint32_t peparser::RawToRva(std::uint32_t _Raw)
{
	std::uint32_t nRva = -1;

	for (auto iterSection : m_SectionList)
	{
		if (_Raw >= iterSection.RawBegin && _Raw <= iterSection.RawEnd)
		{
			nRva = iterSection.RvaBegin + _Raw - iterSection.RawBegin;
			break;
		}
	}

	return nRva;
}
