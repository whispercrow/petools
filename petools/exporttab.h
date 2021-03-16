#pragma once
#include "common.h"
#include "pe_struct.h"

typedef struct
{
	tstring truename;
	vector<std::pair<tstring, std::uint32_t>> exportfunction;
}EXPORTELE, *PEXPORTELE;

class peparser;
class exporttab
{
public:
	explicit exporttab(peparser* _pparser);
	virtual ~exporttab();

	bool init();
	void GetExportTable(EXPORTELE* _ExportTable);

private:
	peparser* m_pParser = nullptr;
	export_dir_entry* m_pExportTabRaw = nullptr;
};

