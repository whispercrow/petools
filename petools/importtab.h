#pragma once
#include "common.h"
#include "pe_struct.h"

typedef struct
{
	tstring PeName;
	vector<std::pair<tstring, std::uint32_t>> FunctionInfo;
}IMPORTELE, *PIMPORTELE;


class peparser;
class importtab
{
public:
	explicit importtab(peparser* _pparser);
	virtual ~importtab();

	bool init();

	void GetImportTable(vector<IMPORTELE> *_mTableOuter);
	


private:
	peparser* m_pParser = nullptr;
	import_dir_entry* m_pImportTabRaw = nullptr;

};

