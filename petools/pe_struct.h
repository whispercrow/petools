#pragma once
#include <cstdint>

constexpr std::uint16_t NUM_DIR_ENTRIES = 16;
constexpr std::uint16_t NUM_SHORT_NAME_LEN = 8;

constexpr std::uint16_t DOS_MAGIC_MZ = 0x5A4D;		//MZ
constexpr std::uint16_t NT_MAGIC_PE = 0x00004550;	//PE

constexpr std::uint16_t NT_FILE_MACHINE_AMD32 = 0x014c;	//machine:i386
constexpr std::uint16_t NT_FILE_MACHINE_AMD64 = 0x8664;	//machine:amd64

constexpr std::uint16_t NT_FILE_EXECUTABLE_IMAGE = 0x0002;		//.exe
constexpr std::uint16_t NT_FILE_LARGE_ADDRESS_AWARE = 0x0020;	//x64
constexpr std::uint16_t NT_FILE_32BIT_MACHINE = 0x0100;			//x86
constexpr std::uint16_t NT_FILE_SYSTEM = 0x1000;				//.sys
constexpr std::uint16_t NT_FILE_DLL = 0x2000;					//.dll

constexpr std::uint16_t NT_OPTIONAL_32PE_MAGIC = 0x10b;		//32bit
constexpr std::uint16_t NT_OPTIONAL_64PE_MAGIC = 0x20b;		//64bit

constexpr std::uint16_t NT_OPTIONAL_SUBSYSTEM_NATIVE = 0x01;		//drivers
constexpr std::uint16_t NT_OPTIONAL_SUBSYSTEM_WINDOWS_GUI = 0x02;	//gui
constexpr std::uint16_t NT_OPTIONAL_SUBSYSTEM_WINDOWS_CUI = 0x03;	//cui

typedef struct
{
	std::uint16_t e_magic;
	std::uint16_t e_cblp;
	std::uint16_t e_cp;
	std::uint16_t e_crlc;
	std::uint16_t e_cparhdr;
	std::uint16_t e_minalloc;
	std::uint16_t e_maxalloc;
	std::uint16_t e_ss;
	std::uint16_t e_sp;
	std::uint16_t e_csum;
	std::uint16_t e_ip;
	std::uint16_t e_cs;
	std::uint16_t e_lfarlc;
	std::uint16_t e_ovno;
	std::uint16_t e_res[4];
	std::uint16_t e_oemid;
	std::uint16_t e_oeminfo;
	std::uint16_t e_res2[10];
	std::uint32_t e_lfanew;
} dos_header, *pdos_header;


typedef struct
{
	std::uint16_t Machine;
	std::uint16_t NumberOfSections;
	std::uint32_t TimeDateStamp;
	std::uint32_t PointerToSymbolTable;
	std::uint32_t NumberOfSymbols;
	std::uint16_t SizeOfOptionalHeader;
	std::uint16_t Characteristics;
} file_header, * pfile_header;


typedef struct
{
	std::uint32_t VirtualAddress;
	std::uint32_t Size;
} data_directory, *pdata_directory;


typedef struct
{
	std::uint16_t Magic;
	std::uint8_t MajorLinkerVersion;
	std::uint8_t MinorLinkerVersion;
	std::uint32_t SizeOfCode;
	std::uint32_t SizeOfInitializedData;
	std::uint32_t SizeOfUninitializedData;
	std::uint32_t AddressOfEntryPoint;
	std::uint32_t BaseOfCode;
	std::uint32_t BaseOfData;
	std::uint32_t ImageBase;
	std::uint32_t SectionAlignment;
	std::uint32_t FileAlignment;
	std::uint16_t MajorOperatingSystemVersion;
	std::uint16_t MinorOperatingSystemVersion;
	std::uint16_t MajorImageVersion;
	std::uint16_t MinorImageVersion;
	std::uint16_t MajorSubsystemVersion;
	std::uint16_t MinorSubsystemVersion;
	std::uint32_t Win32VersionValue;
	std::uint32_t SizeOfImage;
	std::uint32_t SizeOfHeaders;
	std::uint32_t CheckSum;
	std::uint16_t Subsystem;
	std::uint16_t DllCharacteristics;
	std::uint32_t SizeOfStackReserve;
	std::uint32_t SizeOfStackCommit;
	std::uint32_t SizeOfHeapReserve;
	std::uint32_t SizeOfHeapCommit;
	std::uint32_t LoaderFlags;
	std::uint32_t NumberOfRvaAndSizes;
	data_directory DataDirectory[NUM_DIR_ENTRIES];
} optional_header_32, *poptional_header_32;


typedef struct
{
	std::uint16_t Magic;
	std::uint8_t MajorLinkerVersion;
	std::uint8_t MinorLinkerVersion;
	std::uint32_t SizeOfCode;
	std::uint32_t SizeOfInitializedData;
	std::uint32_t SizeOfUninitializedData;
	std::uint32_t AddressOfEntryPoint;
	std::uint32_t BaseOfCode;
	std::uint64_t ImageBase;
	std::uint32_t SectionAlignment;
	std::uint32_t FileAlignment;
	std::uint16_t MajorOperatingSystemVersion;
	std::uint16_t MinorOperatingSystemVersion;
	std::uint16_t MajorImageVersion;
	std::uint16_t MinorImageVersion;
	std::uint16_t MajorSubsystemVersion;
	std::uint16_t MinorSubsystemVersion;
	std::uint32_t Win32VersionValue;
	std::uint32_t SizeOfImage;
	std::uint32_t SizeOfHeaders;
	std::uint32_t CheckSum;
	std::uint16_t Subsystem;
	std::uint16_t DllCharacteristics;
	std::uint64_t SizeOfStackReserve;
	std::uint64_t SizeOfStackCommit;
	std::uint64_t SizeOfHeapReserve;
	std::uint64_t SizeOfHeapCommit;
	std::uint32_t LoaderFlags;
	std::uint32_t NumberOfRvaAndSizes;
	data_directory DataDirectory[NUM_DIR_ENTRIES];
} optional_header_64, *poptional_header_64;


typedef struct
{
	std::uint32_t Signature;
	file_header FileHeader;
	optional_header_32 OptionalHeader32;
	optional_header_64 OptionalHeader64;
	std::uint16_t PlatformMagic;
} nt_header, *pntheader;

typedef struct
{
	dos_header dos_header;
	nt_header nt_header;
} pe_header, * ppe_header;


typedef struct  
{
	std::uint8_t Name[NUM_SHORT_NAME_LEN];
	union {
		std::uint32_t PhysicalAddress;
		std::uint32_t VirtualSize;
	} Misc;
	std::uint32_t VirtualAddress;
	std::uint32_t SizeOfRawData;
	std::uint32_t PointerToRawData;
	std::uint32_t PointerToRelocations;
	std::uint32_t PointerToLinenumbers;
	std::uint16_t NumberOfRelocations;
	std::uint16_t NumberOfLinenumbers;
	std::uint32_t Characteristics;
}image_section_header, *pimage_section_header;


typedef struct
{
	std::uint32_t LookupTableRVA;
	std::uint32_t TimeStamp;
	std::uint32_t ForwarderChain;
	std::uint32_t NameRVA;
	std::uint32_t FirstThunkRVA;
}import_dir_entry, *pimport_dir_entry;
