#include <Windows.h>
#include "common.h"
#include "dbgfunction.h"
#include "exception_seh.h"
#include "convert_code.h"

int _tmain(int argc, tchar* argv[], tchar* envp[])
{
	_set_se_translator(seh_excpetion::TranslateSEHtoCE);
	
	try
	{
		const char* szHello = "hello world\n";
		shared_ptr<const wchar_t> p(ConvertAnsiToUnicode(szHello));
		wcout << p.get();

		char* e = NULL;
		tcout << *e;
	}
	catch (const seh_excpetion& error)
	{
		_tprintf("[!] sehcode:[%08x] %s\n", error.code(), error.what());
	}
	

	return 0;
}