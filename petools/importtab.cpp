#include "importtab.h"
#include "peparser.h"

importtab::importtab(peparser* _pparser) :
	m_pParser(_pparser)
{
	

}

importtab::~importtab()
{


}

bool importtab::init()
{
	if (nullptr == m_pParser) { return false; }

	nt_header* pNtHeader = &m_pParser->m_PeHeader.nt_header;
	data_directory* pImportTable = nullptr;

	if (pNtHeader->PlatformMagic == NT_OPTIONAL_32PE_MAGIC)
	{
		pImportTable = pNtHeader->OptionalHeader32.DataDirectory + 1;
	}
	else if (pNtHeader->PlatformMagic == NT_OPTIONAL_64PE_MAGIC)
	{
		pImportTable = pNtHeader->OptionalHeader64.DataDirectory + 1;
	}
	else
	{
		return false;
	}

	size_t nImportTableRaw = m_pParser->RvaToRaw(pImportTable->VirtualAddress);
	if (-1 != nImportTableRaw || m_pParser->m_FileSize <= nImportTableRaw)
	{
		m_pImportTabRaw = (import_dir_entry*)(m_pParser->m_pView + nImportTableRaw);
	}

	return true;
}

void importtab::GetImportTable(vector<IMPORTELE>* _mTableOuter)
{
	if (m_pImportTabRaw == nullptr) { return; }

	import_dir_entry* pImportIndex = m_pImportTabRaw;

	for (const import_dir_entry ImportDirEnd = { 0 }; 0 != memcmp(pImportIndex, &ImportDirEnd, sizeof(ImportDirEnd)); ++pImportIndex)
	{
		if (0 == pImportIndex->NameRVA || (0 == pImportIndex->FirstThunkRVA && 0 == pImportIndex->ForwarderChain))
		{
			continue;
		}

		IMPORTELE ImportEle;

		std::uint32_t DllNameRaw = m_pParser->RvaToRaw(pImportIndex->NameRVA);
		if (-1 == DllNameRaw || m_pParser->m_FileSize <= DllNameRaw)
		{
			continue;
		}

		//get dllname in import table
		tstring szPeName;
		char* szDllNameAnsi = (char *)m_pParser->m_pView + DllNameRaw;
#ifdef _UNICODE
		const wchar_t* szUnicode = ConvertAnsiToUnicode(szDllNameAnsi);
		szPeName = szUnicode;
		delete[] szUnicode;
#else
		szPeName = szDllNameAnsi;
#endif
		
		ImportEle.PeName = szPeName;

		//get api name and rva
		std::uint32_t ThunkDataRva = pImportIndex->OriginalFirstThunk ? pImportIndex->OriginalFirstThunk : pImportIndex->FirstThunkRVA;
		std::uint32_t ThunkDataRaw = m_pParser->RvaToRaw(ThunkDataRva);
		if (-1 == ThunkDataRaw || m_pParser->m_FileSize <= ThunkDataRaw)
		{
			continue; 
		}


		std::uint32_t* ThunkIter = (std::uint32_t *)(m_pParser->m_pView + ThunkDataRaw);
		for (std::uint32_t ThunkEnd = 0; ThunkEnd != *ThunkIter; m_pParser->is64bit()? ++++ThunkIter: ++ThunkIter)
		{
			tstring szFunctionName;

			if (m_pParser->is64bit() ? *(std::uint64_t*)ThunkIter & 0x8000000000000000 : *ThunkIter & 0x80000000)
			{
				//function: num
				std::uint64_t FunctionIndex = m_pParser->is64bit() ? 
					*(std::uint64_t *)ThunkIter & 0x7fffffffffffffff :
					*ThunkIter & 0x7fffffff;
				tostringstream ostr;
				ostr << _T("@fun_index_") << FunctionIndex;
				szFunctionName = ostr.str();
			}
			else
			{
				//function: str
				std::uint32_t FunctionNameRaw = m_pParser->RvaToRaw(*ThunkIter);
				if (-1 == FunctionNameRaw || m_pParser->m_FileSize <= FunctionNameRaw)
				{
					continue;
				}

				import_function_by_name* pFunctionName = (import_function_by_name*)(m_pParser->m_pView + FunctionNameRaw);
#ifdef _UNICODE
				const wchar_t* szUnicode = ConvertAnsiToUnicode((char*)&(pFunctionName->Name));
				szFunctionName = szUnicode;
				delete[] szUnicode;
#else
				szFunctionName = (char*)&(pFunctionName->Name);
#endif		
			}

			std::uint32_t nIat = pImportIndex->FirstThunkRVA + m_pParser->RawToRva((byte*)ThunkIter - m_pParser->m_pView) - ThunkDataRva;
			ImportEle.FunctionInfo.push_back(make_pair(szFunctionName, -1 == nIat ? 0 : nIat));
		}
		
		_mTableOuter->push_back(ImportEle);
	}


	return;
}
