#include <Windows.h>
#include "common.h"
#include "dbgfunction.h"
#include "exception_seh.h"
#include "convert_code.h"

#include "peparser.h"


int _tmain(int argc, tchar* argv[], tchar* envp[])
{
	_set_se_translator(seh_excpetion::TranslateSEHtoCE);
	
	try
	{	//tstring szPath = _T(R"(D:\workstation\asm\Debug\asm.exe)");
		tstring szPath = _T(R"(C:\Users\whisp\OneDrive\tools\windbg\x64\windbg.exe)");

		//tstring szPath = _T(R"(d:\Xshell-7.0.0054p.exe)");
		peparser parser(szPath);

		if (parser.check())
		{
			tcout << szPath << endl;
			tcout << _T("check success!") << endl;
			vector<IMPORTELE> importtable;
			parser.ImportTable.GetImportTable(&importtable);
			for (auto dll : importtable)
			{
				tcout << dll.PeName << endl;
				for (auto fun : dll.FunctionInfo)
				{
					tcout << _T("            ");
					tcout << std::hex << setw(8) << setfill(_T('0')) << fun.second << _T("  ") << fun.first << endl;
				}
			}

			tcout << _T("===================================================================") << endl;

			EXPORTELE exporttable;
			parser.ExportTable.GetExportTable(&exporttable);

			tcout <<_T("True Name: ") << exporttable.truename << endl;
			tcout << _T("export:") << endl;
			for (auto func : exporttable.exportfunction)
			{
				tcout << _T("            ");
				tcout << std::hex << setw(8) << setfill(_T('0')) << func.second << _T("   ") << func.first << endl;
			}



		}
		else
		{
			cout << "check failed!" << endl;
		}


		

	}
	catch (const seh_excpetion& seh_error)
	{
		printf("[!] seh_error: 0x%08x %s", seh_error.code(), seh_error.what());
	}


	system("pause");

	return 0;
}