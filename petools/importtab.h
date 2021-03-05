#pragma once
#include "common.h"
#include "pe_struct.h"

typedef struct
{
	tstring PeName;
	std::uint32_t TimeStamp;
	vector<tstring> FunctionName;
}IMPORTELE, *PIMPORTELE;



class peparser;
class importtab
{
public:
	explicit importtab(peparser* _pparser);
	virtual ~importtab();

	bool GetImportTable(vector<IMPORTELE> *_mTableOuter);
	


private:
	peparser* m_pParser = NULL;
	import_dir_entry* m_pImportTabRaw = NULL;

};

