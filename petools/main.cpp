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
	{

		//peparser parser(_T(R"(D:\workstation\injectdll.dll)"));
		//peparser parser(_T(R"(D:\workstation\debugtest_x64.exe)"));
		peparser parser(_T(R"(D:\workstation\debugtest\Release\debugtest.upack.exe)"));

		if (parser.check())
		{
			cout << "success" << endl;
		}
		else
		{
			cout << "failed" << endl;
		}

	}
	catch (const seh_excpetion& seh_error)
	{
		printf("[!] seh_error: 0x%08x %s", seh_error.code(), seh_error.what());
	}


	system("pause");

	return 0;
}