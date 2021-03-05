#include "peparser.h"

peparser::peparser(const std::tstring _szPePath)
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

	m_pView = MapViewOfFile(m_hFileMap, FILE_MAP_READ, 0, 0, 0);
	if (NULL == m_pView)
	{
		return;
	}

	this->InitPeHeader();
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
	if (m_PeHeader.dos_header.e_magic != DOS_MAGIC_MZ)
	{
		return false;
	}

	//check nt header magic
	if (m_PeHeader.nt_header.Signature != NT_MAGIC_PE)
	{
		return false;
	}
	
	//check nt header is PE32 or PE32+ executable
	if (m_PeHeader.nt_header.PlatformMagic != NT_OPTIONAL_32PE_MAGIC && m_PeHeader.nt_header.PlatformMagic != NT_OPTIONAL_64PE_MAGIC)
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

	//check Platform == machine
	if (m_PeHeader.nt_header.PlatformMagic == NT_OPTIONAL_32PE_MAGIC)
	{
		if (m_PeHeader.nt_header.OptionalHeader32.Magic != NT_OPTIONAL_32PE_MAGIC)
		{
			return false;
		}

		if (m_PeHeader.nt_header.FileHeader.Machine != NT_FILE_MACHINE_AMD32)
		{
			return false;
		}

		if (false == (m_PeHeader.nt_header.FileHeader.Characteristics & NT_FILE_32BIT_MACHINE))
		{
			return false;
		}

		if (m_PeHeader.nt_header.OptionalHeader32.Win32VersionValue != 0)
		{
			return false;
		}

		if (m_PeHeader.nt_header.OptionalHeader32.ImageBase % 0x10000 != 0)
		{
			return false;
		}

		if (m_PeHeader.nt_header.OptionalHeader32.SectionAlignment < 2)
		{
			return false;
		}

		if (m_PeHeader.nt_header.OptionalHeader32.FileAlignment < 2)
		{
			return false;
		}

		if (m_PeHeader.nt_header.FileHeader.Characteristics & NT_FILE_EXECUTABLE_IMAGE)
		{
			 if (m_PeHeader.nt_header.OptionalHeader32.Subsystem != NT_OPTIONAL_SUBSYSTEM_WINDOWS_GUI &&
				m_PeHeader.nt_header.OptionalHeader32.Subsystem != NT_OPTIONAL_SUBSYSTEM_WINDOWS_CUI &&
				m_PeHeader.nt_header.OptionalHeader32.Subsystem != NT_OPTIONAL_SUBSYSTEM_NATIVE)
			{
				return false;
			}
		}

		if (m_PeHeader.nt_header.OptionalHeader32.NumberOfRvaAndSizes != NUM_DIR_ENTRIES)
		{
			return false;
		}

		//check size of peheader
		std::uint32_t nHeaderSizeNoReg = sizeof(m_PeHeader.dos_header) + 
			m_PeHeader.nt_header.FileHeader.SizeOfOptionalHeader + 
			m_PeHeader.nt_header.FileHeader.NumberOfSections * sizeof(image_section_header);
		
		std::uint32_t dv = nHeaderSizeNoReg / m_PeHeader.nt_header.OptionalHeader32.FileAlignment;
		std::uint32_t re = nHeaderSizeNoReg % m_PeHeader.nt_header.OptionalHeader32.FileAlignment;
		std::uint32_t nHeaderSizeReg = re ? (dv+1) * m_PeHeader.nt_header.OptionalHeader32.FileAlignment : nHeaderSizeNoReg;

		if (m_PeHeader.nt_header.OptionalHeader32.SizeOfHeaders != nHeaderSizeReg)
		{ 
			return false;
		}

		//check size of image
		//...


	}
	else if(m_PeHeader.nt_header.PlatformMagic == NT_OPTIONAL_64PE_MAGIC)
	{
		if (m_PeHeader.nt_header.OptionalHeader64.Magic != NT_OPTIONAL_64PE_MAGIC)
		{
			return false;
		}

		if (m_PeHeader.nt_header.FileHeader.Machine != NT_FILE_MACHINE_AMD64)
		{
			return false;
		}

		if (false == (m_PeHeader.nt_header.FileHeader.Characteristics & NT_FILE_LARGE_ADDRESS_AWARE))
		{
			return false;
		}

		if (m_PeHeader.nt_header.OptionalHeader64.Win32VersionValue != 0)
		{
			return false;
		}

		if (m_PeHeader.nt_header.OptionalHeader64.ImageBase % 0x10000 != 0)
		{
			return false;
		}

		if (m_PeHeader.nt_header.OptionalHeader64.SectionAlignment < 2)
		{
			return false;
		}

		if (m_PeHeader.nt_header.OptionalHeader64.FileAlignment < 2)
		{
			return false;
		}


		if (m_PeHeader.nt_header.FileHeader.Characteristics & NT_FILE_EXECUTABLE_IMAGE)
		{
			if (m_PeHeader.nt_header.OptionalHeader64.Subsystem != NT_OPTIONAL_SUBSYSTEM_WINDOWS_GUI &&
				m_PeHeader.nt_header.OptionalHeader64.Subsystem != NT_OPTIONAL_SUBSYSTEM_WINDOWS_CUI &&
				m_PeHeader.nt_header.OptionalHeader64.Subsystem != NT_OPTIONAL_SUBSYSTEM_NATIVE)
			{
				return false;
			}
		}

		if (m_PeHeader.nt_header.OptionalHeader64.NumberOfRvaAndSizes != NUM_DIR_ENTRIES)
		{
			return false;
		}

		//check size of peheader
		std::uint32_t nHeaderSizeNoReg = sizeof(m_PeHeader.dos_header) +
			m_PeHeader.nt_header.FileHeader.SizeOfOptionalHeader +
			m_PeHeader.nt_header.FileHeader.NumberOfSections * sizeof(image_section_header);

		std::uint32_t dv = nHeaderSizeNoReg / m_PeHeader.nt_header.OptionalHeader64.FileAlignment;
		std::uint32_t re = nHeaderSizeNoReg % m_PeHeader.nt_header.OptionalHeader64.FileAlignment;
		std::uint32_t nHeaderSizeReg = re ? (dv + 1) * m_PeHeader.nt_header.OptionalHeader64.FileAlignment : nHeaderSizeNoReg;

		if (m_PeHeader.nt_header.OptionalHeader64.SizeOfHeaders != nHeaderSizeReg)
		{
			return false;
		}

		//check size of image
		//...



	}
	

	return true;
}

bool peparser::Is64Bit()
{
	return m_PeHeader.nt_header.PlatformMagic == NT_FILE_MACHINE_AMD64;
}

bool peparser::InitPeHeader()
{
	if (NULL == m_pView || 0 == m_FileSize)
	{
		return false;
	}

	size_t nParseBeg = 0;
	size_t nParseEnd = 0;

	if ((nParseEnd += sizeof(dos_header)) >= m_FileSize) { return false; }

	memcpy(&m_PeHeader.dos_header, (byte *)m_pView + nParseBeg, nParseEnd - nParseBeg);
	
	nParseBeg = m_PeHeader.dos_header.e_lfanew;
	nParseEnd = m_PeHeader.dos_header.e_lfanew;
	if ((nParseEnd += sizeof(m_PeHeader.nt_header.Signature) + sizeof(m_PeHeader.nt_header.FileHeader)) >= m_FileSize) { return false; }


	memcpy(&m_PeHeader.nt_header, (byte *)m_pView + nParseBeg, nParseEnd - nParseBeg);

	if (nParseEnd + sizeof(std::uint16_t) >= m_FileSize) { return false; }

	nParseBeg = nParseEnd;
	if (*(std::uint16_t *)((byte *)m_pView + nParseEnd) == NT_OPTIONAL_32PE_MAGIC)
	{
		m_PeHeader.nt_header.PlatformMagic = NT_OPTIONAL_32PE_MAGIC;
		if ((nParseEnd += sizeof(m_PeHeader.nt_header.OptionalHeader32)) >= m_FileSize) { return false; }
		memcpy(&m_PeHeader.nt_header.OptionalHeader32, (byte *)m_pView + nParseBeg, nParseEnd - nParseBeg);

	}
	else if(*(std::uint16_t*)((byte*)m_pView + nParseEnd) == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
	{
		m_PeHeader.nt_header.PlatformMagic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
		if ((nParseEnd += sizeof(m_PeHeader.nt_header.OptionalHeader64)) >= m_FileSize) { return false; }
		memcpy(&m_PeHeader.nt_header.OptionalHeader64, (byte*)m_pView + nParseBeg, nParseEnd - nParseBeg);

	}
	

	return true;
}
