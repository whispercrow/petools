#include "exporttab.h"
#include "peparser.h"

exporttab::exporttab(peparser* _pparser):
	m_pParser(_pparser)
{
}

exporttab::~exporttab()
{
}

bool exporttab::init()
{
	if (nullptr == m_pParser) { return false; }

	nt_header* pNtHeader = &m_pParser->m_PeHeader.nt_header;
	data_directory* pImportTable = nullptr;

	if (pNtHeader->PlatformMagic == NT_OPTIONAL_32PE_MAGIC)
	{
		pImportTable = pNtHeader->OptionalHeader32.DataDirectory + 0;
	}
	else if (pNtHeader->PlatformMagic == NT_OPTIONAL_64PE_MAGIC)
	{
		pImportTable = pNtHeader->OptionalHeader64.DataDirectory + 0;
	}
	else
	{
		return false;
	}

	size_t nExportTableRaw = m_pParser->RvaToRaw(pImportTable->VirtualAddress);
	if (-1 == nExportTableRaw || m_pParser->m_FileSize <= nExportTableRaw)
	{
		return false;
	}

	m_pExportTabRaw = (export_dir_entry*)(m_pParser->m_pView + nExportTableRaw);
	return true;
}

void exporttab::GetExportTable(EXPORTELE* _ExportTable)
{	
	if (m_pExportTabRaw == nullptr) { return; }

	std::uint32_t nFunBase = m_pExportTabRaw->base;
	std::uint32_t nNumberFunName = m_pExportTabRaw->numberofnames;
	std::uint32_t nNumberFunAddress = m_pExportTabRaw->numberoffunctions;
	if (0 == nNumberFunName || 0 == nNumberFunAddress || nNumberFunName > nNumberFunAddress) { return; }

	std::uint32_t nFunNameListRaw = m_pParser->RvaToRaw(m_pExportTabRaw->addressofnames);
	if (-1 == nFunNameListRaw || nFunNameListRaw + nNumberFunName >= m_pParser->m_FileSize) { return; }
	std::uint32_t nFunNameOrdListRaw = m_pParser->RvaToRaw(m_pExportTabRaw->addressofnameofdinals);
	if (-1 == nFunNameOrdListRaw || nFunNameOrdListRaw + nNumberFunName >= m_pParser->m_FileSize) { return; }
	std::uint32_t nFunAddressListRaw = m_pParser->RvaToRaw(m_pExportTabRaw->addressoffunctions);
	if (-1 == nFunAddressListRaw || nFunAddressListRaw + nNumberFunAddress >= m_pParser->m_FileSize) { return; }

	std::uint32_t* pFunNameList = (std::uint32_t*)(m_pParser->m_pView + nFunNameListRaw);
	std::uint16_t* pFunNameOrdList = (std::uint16_t*)(m_pParser->m_pView + nFunNameOrdListRaw);
	std::uint32_t* pFunAddressList = (std::uint32_t*)(m_pParser->m_pView + nFunAddressListRaw);

	//get true name
	tstring szTrueName;
	std::uint32_t nTrueNameRaw = m_pParser->RvaToRaw(m_pExportTabRaw->name);
	if (-1 == nTrueNameRaw || nTrueNameRaw >= m_pParser->m_FileSize) { return; }
	char* pAnsiTrueName = (char*)(m_pParser->m_pView + nTrueNameRaw);
#ifdef _UNICODE
	wchar_t* pUnicodeTrueName = ConvertAnsiToUnicode(pAnsiTrueName);
	szTrueName = pUnicodeTrueName;
	delete[] pUnicodeTrueName;
#else
	szTrueName = pAnsiTrueName;
#endif
	_ExportTable->truename = szTrueName;

	//get export function info
	bool* pSignSapce = new bool[nNumberFunAddress]{false};
	for (std::uint32_t nIndex = 0; nIndex < nNumberFunName; ++nIndex)
	{
		tstring szFunName;
		std::uint32_t nFunAddress = 0;


		//get function name
		std::uint32_t nFunNameRaw = m_pParser->RvaToRaw(*(pFunNameList + nIndex));
		if (-1 == nFunNameRaw || nFunNameRaw >= m_pParser->m_FileSize) { continue; }
		char* pAnsiFunName = (char*)(m_pParser->m_pView + nFunNameRaw);
#ifdef _UNICODE
		wchar_t* pUnicodeFunName = ConvertAnsiToUnicode(pAnsiFunName);
		szFunName = pUnicodeFunName;
		delete[] pUnicodeFunName;
#else
		szFunName = pAnsiFunName;
#endif // _UNICODE


		//get function address
		std::uint16_t nFunNameOrd = *(pFunNameOrdList + nIndex);
		nFunAddress = *(pFunAddressList + nFunNameOrd);
		pSignSapce[nFunNameOrd] = true;

		_ExportTable->exportfunction.push_back(make_pair(szFunName, nFunAddress));
	}

	for (std::uint32_t nIndex = 0; nIndex < nNumberFunAddress; ++nIndex)
	{
		if (true == pSignSapce[nIndex])
		{
			continue;
		}

		tstring szFunName;
		std::uint32_t nFunAddress = 0;

		//get function name from SN
		std::uint32_t nFunSN = nIndex + nFunBase;
		tostringstream ostr;
		ostr << _T("@function_SN_") << nFunSN;
		szFunName = ostr.str();

		//get function address
		nFunAddress = *(pFunAddressList + nIndex);

		_ExportTable->exportfunction.push_back(make_pair(szFunName, nFunAddress));
	}

	delete[] pSignSapce;
	

	
	return;
}
