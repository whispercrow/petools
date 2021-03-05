#include "importtab.h"
#include "peparser.h"

importtab::importtab(peparser* _pparser) :
	m_pParser(_pparser)
{
	if (nullptr == m_pParser) { return; }

	nt_header *pNtHeader = &m_pParser->m_PeHeader.nt_header;
	data_directory* pImportTable = nullptr;

	if (pNtHeader->PlatformMagic == NT_OPTIONAL_32PE_MAGIC)
	{
		pImportTable = pNtHeader->OptionalHeader32.DataDirectory + 1;
	}
	else if(pNtHeader->PlatformMagic == NT_OPTIONAL_64PE_MAGIC)
	{
		pImportTable = pNtHeader->OptionalHeader64.DataDirectory + 1;
	}
	else
	{
		return;
	}






}

importtab::~importtab()
{


}

bool importtab::GetImportTable(vector<IMPORTELE>* _mTableOuter)
{

	return false;
}
