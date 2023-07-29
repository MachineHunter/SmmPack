#include <windows.h>
#include <dbghelp.h>
#include <stdlib.h>
#include <iostream>
#include <sstream>
#include "aes.h"
#pragma comment(lib, "dbghelp.lib")

#define CBC 1

typedef unsigned __int64 QWORD;

typedef struct PE {
	PIMAGE_DOS_HEADER     DosHeader;
	PIMAGE_NT_HEADERS     NtHeader;
	PIMAGE_OPTIONAL_HEADER OptionalHeader;
	PIMAGE_FILE_HEADER     FileHeader;
	PIMAGE_SECTION_HEADER SectionHeader;
	QWORD                 ImageBase;
	QWORD                 oep;
} PE;

typedef struct SectionConfig {
	CHAR* name;
	QWORD vaddr;
	QWORD vsize;
	QWORD raddr;
	DWORD rsize;
	QWORD* characteristic;
} SectionConfig;


void Err(const char* msg) {
	MessageBox(NULL, TEXT(msg), TEXT("Error"), MB_OK | MB_ICONERROR);
}

void DbgPrint(const char* fmt, ...) {
	char buf[256];
	va_list v1;
	va_start(v1, fmt);
	vsnprintf(buf, sizeof(buf), fmt, v1);
	va_end(v1);
	OutputDebugString(buf);
}

void ParsePE(PE* pe, UCHAR* lpTargetBinBuffer) {
	pe->DosHeader = (PIMAGE_DOS_HEADER)lpTargetBinBuffer;
	pe->NtHeader = (PIMAGE_NT_HEADERS)((QWORD)lpTargetBinBuffer + pe->DosHeader->e_lfanew);
	pe->OptionalHeader = &pe->NtHeader->OptionalHeader;
	pe->FileHeader = &pe->NtHeader->FileHeader;
	pe->ImageBase = pe->OptionalHeader->ImageBase;
	pe->oep = pe->ImageBase + pe->OptionalHeader->AddressOfEntryPoint;
	DbgPrint("ImageBase:0x%I64X, OEP:0x%I64X", pe->ImageBase, pe->oep + pe->ImageBase);
}

void ShiftAddrOfHeaders(PE* pe, UCHAR* lpTargetBinBuffer, UINT* sizeIncrease) {
	// shift optional header addresses
	pe->oep += *sizeIncrease;
	pe->OptionalHeader->BaseOfCode += *sizeIncrease;

	// shift each data directories' vaddr
	PIMAGE_DATA_DIRECTORY dataDirectory = (PIMAGE_DATA_DIRECTORY)(pe->NtHeader->OptionalHeader.DataDirectory);
	for (int i = 0; i < 16; i++) {
		if (dataDirectory[i].VirtualAddress != 0) {
			dataDirectory[i].VirtualAddress += *sizeIncrease;
			DbgPrint("%d dataDirectory present", i);
		}

		// if it is Relocation Directory
		if (i == 5) {
			QWORD relocDirAddr = (QWORD)lpTargetBinBuffer + (QWORD)dataDirectory[i].VirtualAddress;
			DWORD relocDirSize = dataDirectory[i].Size;

			while (relocDirSize > 0) {
				*(QWORD*)relocDirAddr += *sizeIncrease;
				PIMAGE_BASE_RELOCATION relocDir = (PIMAGE_BASE_RELOCATION)relocDirAddr;
				relocDirSize -= relocDir->SizeOfBlock;
				relocDirAddr += relocDir->SizeOfBlock;
			}
		}

		// if it is Debug Directory
		if (i == 6) {
			PIMAGE_DEBUG_DIRECTORY debugDir = (PIMAGE_DEBUG_DIRECTORY)(lpTargetBinBuffer + (QWORD)dataDirectory[i].VirtualAddress);
			debugDir->AddressOfRawData += *sizeIncrease;
			debugDir->PointerToRawData += *sizeIncrease;
		}
	}

	// shift each section header's vaddr
	QWORD sectionLocation = (QWORD)IMAGE_FIRST_SECTION(pe->NtHeader);
	QWORD sectionSize = (QWORD)sizeof(IMAGE_SECTION_HEADER);

	for (int i = 0; i < pe->FileHeader->NumberOfSections; i++) {
		pe->SectionHeader = (PIMAGE_SECTION_HEADER)sectionLocation;
		// shifted all sections so shift header's vaddr and raddr too
		pe->SectionHeader->VirtualAddress += *sizeIncrease;
		pe->SectionHeader->PointerToRawData += *sizeIncrease;
		sectionLocation += sectionSize;
	}
}

void FindSection(PE* pe, SectionConfig* target, SectionConfig* ext) {
	QWORD sectionLocation = (QWORD)IMAGE_FIRST_SECTION(pe->NtHeader);
	QWORD sectionSize = (QWORD)sizeof(IMAGE_SECTION_HEADER);

	for (int i = 0; i < pe->FileHeader->NumberOfSections; i++) {
		pe->SectionHeader = (PIMAGE_SECTION_HEADER)sectionLocation;
		QWORD SectionTopAddr = pe->ImageBase + pe->SectionHeader->VirtualAddress;
		QWORD SectionEndAddr = pe->ImageBase + pe->SectionHeader->VirtualAddress + pe->SectionHeader->Misc.VirtualSize;

		// section that has oep
		if (SectionTopAddr <= pe->oep && pe->oep < SectionEndAddr) {
			target->name = (CHAR*)pe->SectionHeader->Name;
			target->vaddr = pe->ImageBase + pe->SectionHeader->VirtualAddress;
			target->vsize = pe->SectionHeader->Misc.VirtualSize;
			target->raddr = pe->SectionHeader->PointerToRawData;
			target->rsize = pe->SectionHeader->SizeOfRawData;
			target->characteristic = (QWORD*)&(pe->SectionHeader->Characteristics);
			DbgPrint("OEP is in %s section", target->name);
		}

		// section .ext
		if (!strcmp((CHAR*)pe->SectionHeader->Name, ".ext")) {
			ext->name = (CHAR*)pe->SectionHeader->Name;
			ext->vaddr = pe->ImageBase + pe->SectionHeader->VirtualAddress;
			ext->vsize = pe->SectionHeader->Misc.VirtualSize;
			ext->raddr = pe->SectionHeader->PointerToRawData;
			ext->rsize = pe->SectionHeader->SizeOfRawData;
		}

		sectionLocation += sectionSize;
	}
}

uint8_t aes128key[16] = {
	0xa7, 0xe3, 0xf1, 0x2b, 0xa2, 0xc4, 0x9f, 0x8e, 0x77, 0x61, 0x68, 0x2c, 0x50, 0x40, 0xbd, 0x10
};

uint8_t iv[16] = {
	0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
};

void aes_encrypt(UCHAR* start, DWORD size) {
	size_t keySize = sizeof(aes128key);
	if (keySize != 16)
		DbgPrint("WRONG KEY SIZE!!! %d", keySize);

	DbgPrint("original: %2X %2X %2X %2X %2X %2X %2X %2X", start[0], start[1], start[2], start[3], start[4], start[5], start[6], start[7]);
	struct AES_ctx ctx;
	AES_init_ctx_iv(&ctx, aes128key, iv);
	DWORD encSize = (size / 16) * 16;
	DbgPrint("AES Encrypt leftover: %d bytes", size % 16);
	AES_CBC_encrypt_buffer(&ctx, start, encSize);
	return;
}


UCHAR decodeStub[] = {
	// UefiPackProtocol GUID  (16 bytes)
	0x16, 0x93, 0xc2, 0x73,
	0xcd, 0x3e,
	0xe3, 0x4f,
	0xa4, 0xbb, 0x5e, 0xf7, 0xff, 0xca, 0x82, 0xfb,

	// EfiMain
	0x90, 0x90,                                                       // 2 deadloop for debug (eb fe)
	0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,                   // 8 push registers
	0x48, 0x83, 0xec, 0x48,                                           // 4 sub rsp, 0x48
	0x48, 0x89, 0xd3,                                                 // 3 mov rbx, SystemTable(rdx)
	0x48, 0x8b, 0x43, 0x60,                                           // 4 mov rax, [rbx+0x60] <= gBS=SystemTable->BootServices
	0xE8, 0x00, 0x00, 0x00, 0x00,                                     // 5 call $+5
	0x5b,                                                             // 1 pop rbx             <= current instruction address will be set to rbx
	0x48, 0x89, 0xd9,                                                 // 3 mov rcx, rbx        <= UefiPackProtocol GUID address as 1st argument
	0x48, 0x81, 0xE9, 0xFF, 0xFF, 0xFF, 0xFF,                         // 7 sub rcx, <offset1>  <= rcx will contain base addr of decodeStub (&gUefiPackProtocolGuid)
	0x48, 0x81, 0xEB, 0xFF, 0xFF, 0xFF, 0xFF,                         // 7 sub rbx, <offset2>  <= rbx will contain base addr of this module (ImageBase)
	0x48, 0x31, 0xD2,                                                 // 3 xor rdx, rdx 
	0x4c, 0x8d, 0x44, 0x24, 0x38,                                     // 5 lea r8, [rsp+0x38]  <= allocate stack for handle of UefiPackProtocol
	0x4c, 0x8d, 0x44, 0x24, 0x38, 0xff, 0x90, 0x40, 0x01, 0x00, 0x00, // 11 call [rax+0x140]   <= call gBS->LocateProtocol(gUefiPackProtocolGuid, NULL, &hUefiPackProtocol)
	0x48, 0x8b, 0x44, 0x24, 0x38,                                     // 5 mov rax, [rsp+0x38] <= hUefiPackProtocol set to rax
	0x48, 0xB9, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,       // 10 mov rcx, <DecryptAddr>
	0x48, 0x01, 0xD9,                                                 // 3 add rcx, rbx        <= DecryptAddr to absolute addr
	0x48, 0xBA, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,       // 10 mov rdx, <DecryptSize>
	0xff, 0x10,                                                       // 2 call rax            <= call hUefiPackProtocol->Unpack(DecryptAddr, DecryptSize)
	0x48, 0x83, 0xc4, 0x48,                                           // 4 add rsp, 0x48
	0x5F, 0x5E, 0x5D, 0x5C, 0x5B, 0x5A, 0x59, 0x58,                   // 8 pop registers
	0xE9, 0xF9, 0xFF, 0xFF, 0xFF                                      // 5 jmp to <Oep>
};

UINT extEfiMainOffset = 0;
void CreateDecodeStub(QWORD SectionVaddr, QWORD SectionVsize, QWORD oep, QWORD extRaddr, DWORD decodeStubOffset) {
	extEfiMainOffset = 15;
	UINT offset1Offset = extEfiMainOffset + 2 + 8 + 4 + 3 + 4 + 5 + 1 + 3 + 4;
	UINT offset2Offset = offset1Offset + 3 + 4;
	UINT DecryptAddrOffset = offset2Offset + 3 + 3 + 5 + 11 + 5 + 3;
	UINT DecryptSizeOffset = DecryptAddrOffset + 7 + 3 + 3;
	UINT OepOffset = DecryptSizeOffset + 7 + 2 + 4 + 8 + 2;

	long _OepOffset = oep - (extRaddr + OepOffset - 1) - 5;
	DWORD offset1 = extEfiMainOffset + 2 + 8 + 4 + 3 + 4 + 5 + 1;
	DWORD offset2 = offset1 + decodeStubOffset;

	QWORD DecryptSize = (SectionVsize / 16) * 16;

	memcpy(&decodeStub[offset1Offset], &offset1, sizeof(DWORD));
	memcpy(&decodeStub[offset2Offset], &offset2, sizeof(DWORD));
	memcpy(&decodeStub[DecryptAddrOffset], &SectionVaddr, sizeof(QWORD));
	memcpy(&decodeStub[DecryptSizeOffset], &DecryptSize, sizeof(QWORD));
	memcpy(&decodeStub[OepOffset], &_OepOffset, sizeof(DWORD));
	return;
}

UCHAR* ReadTargetFile(WCHAR* lpTargetFilename, DWORD* dwTargetBinSize, UINT extSize, UINT extHeaderSize) {
	HANDLE hTargetBin;
	DWORD dwReadSize;
	UCHAR* lpTargetBinBuffer;
	bool bRes;

	hTargetBin = CreateFileW(lpTargetFilename, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hTargetBin == INVALID_HANDLE_VALUE) {
		Err("No Such File");
		return 0;
	}

	*dwTargetBinSize = GetFileSize(hTargetBin, NULL);
	if (*dwTargetBinSize == -1) {
		Err("Failed to get file size");
		return 0;
	}

	DWORD newSize = *dwTargetBinSize + (DWORD)extSize + (DWORD)extHeaderSize + (DWORD)0x1000;
	// 0x1000 is a buffer since we extend more than extHeaderSize due to section alignment
	// if extHeaderSize=0x28 and section alignment is 0x20, additional 0x40 is required
	// 0x1000-0x40 will not be included in the output file since we're specifying only the required size when WriteFile
	// 0x1000 is not enough if section alignment is more than 0x1000, In that case, error will occur in AddExtSection.

	lpTargetBinBuffer = (UCHAR*)malloc(sizeof(DWORD) * newSize);
	if (lpTargetBinBuffer == NULL) {
		Err("Failed to allocate region to read file");
		return 0;
	}
	else memset(lpTargetBinBuffer, 0, sizeof(DWORD) * newSize);

	bRes = ReadFile(hTargetBin, lpTargetBinBuffer, *dwTargetBinSize, &dwReadSize, NULL);
	if (!bRes && *dwTargetBinSize != dwReadSize) {
		Err("Failed to read file");
		return 0;
	}

	CloseHandle(hTargetBin);

	return lpTargetBinBuffer;
}

BOOL WritePackedFile(WCHAR* lpPackedFilename, UCHAR* lpTargetBinBuffer, DWORD dwTargetBinSize, SectionConfig* target, UINT extSize, UINT* sizeIncreased) {
	bool bRes;

	*(target->characteristic) |= IMAGE_SCN_MEM_WRITE;

	HANDLE hPackedBin = CreateFileW(lpPackedFilename, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hPackedBin == INVALID_HANDLE_VALUE) {
		Err("No Such File");
		return FALSE;
	}

	DWORD dwWriteSize;
	bRes = WriteFile(hPackedBin, lpTargetBinBuffer, dwTargetBinSize + (DWORD)extSize + (DWORD)(*sizeIncreased), &dwWriteSize, NULL);
	if (!bRes && (dwTargetBinSize + (DWORD)extSize + (DWORD)(*sizeIncreased)) != dwWriteSize) {
		Err("Write Failed");
		return FALSE;
	}

	CloseHandle(hPackedBin);

	return TRUE;
}

void AddExtSection(PE* pe, UCHAR* lpTargetBinBuffer, DWORD dwTargetBinSize, UINT extSize, UINT extHeaderSize, UINT* sizeIncrease) {
	// appending additional data on EOF is done in ReadTargetFile

	// change size of image
	DWORD newSizeOfImage = 0;
	while (newSizeOfImage <= extSize)
		newSizeOfImage += pe->OptionalHeader->SectionAlignment;

	pe->OptionalHeader->SizeOfImage += newSizeOfImage;

	// determine ext location and section before ext
	QWORD extSecHeaderLocation = (QWORD)IMAGE_FIRST_SECTION(pe->NtHeader) + ((QWORD)sizeof(IMAGE_SECTION_HEADER) * pe->FileHeader->NumberOfSections);
	PIMAGE_SECTION_HEADER extSecHeader = (PIMAGE_SECTION_HEADER)(extSecHeaderLocation);
	QWORD beforeSecHeaderLocation = (QWORD)IMAGE_FIRST_SECTION(pe->NtHeader) + ((QWORD)sizeof(IMAGE_SECTION_HEADER) * (pe->FileHeader->NumberOfSections - 1));
	PIMAGE_SECTION_HEADER beforeSecHeader = (PIMAGE_SECTION_HEADER)beforeSecHeaderLocation;

	// change number of sections
	pe->FileHeader->NumberOfSections += 1;
	DbgPrint("extSecHeaderLocation: 0x%I64X, NumberOfSections: %d", extSecHeaderLocation, pe->FileHeader->NumberOfSections);
	DbgPrint("beforeSecHeaderLocation: 0x%I64X, beforeSecHeader: %s", beforeSecHeaderLocation, beforeSecHeader->Name);


	// shift all other sections (to allocate space for ext section header attributes entry)
	//  dwTargetBinSize(whole file size) = headerSize + sectionsSize
	if (pe->OptionalHeader->SectionAlignment > 0x1000)
		Err("increase buffer to more than 0x1000");

	*sizeIncrease = 0;
	while (*sizeIncrease <= extHeaderSize)
		*sizeIncrease += pe->OptionalHeader->SectionAlignment; // sections need to be aligned
	pe->OptionalHeader->SizeOfImage += *sizeIncrease;
	pe->OptionalHeader->SizeOfHeaders += extHeaderSize;
	QWORD headerSize = extSecHeaderLocation - (QWORD)lpTargetBinBuffer;
	DWORD sectionsSize = dwTargetBinSize - headerSize;
	memmove((UCHAR*)(extSecHeaderLocation + *sizeIncrease), (UCHAR*)extSecHeaderLocation, sectionsSize);


	// change ext section attributes
	DWORD vaddrOffset = 0;
	while (vaddrOffset < beforeSecHeader->Misc.VirtualSize)
		vaddrOffset += pe->OptionalHeader->SectionAlignment;

	char secname[5] = ".ext";
	memset((char*)extSecHeader->Name, 0, 8);
	strncpy_s((char*)extSecHeader->Name, 8, secname, 5);
	extSecHeader->Misc.VirtualSize = extSize;
	extSecHeader->VirtualAddress = beforeSecHeader->VirtualAddress + vaddrOffset;
	extSecHeader->SizeOfRawData = extSize;
	extSecHeader->PointerToRawData = dwTargetBinSize;
	extSecHeader->PointerToRelocations = 0;
	extSecHeader->PointerToLinenumbers = 0;
	extSecHeader->NumberOfRelocations = 0;
	extSecHeader->NumberOfLinenumbers = 0;
	extSecHeader->Characteristics = 0x60000020;

	DbgPrint("name: %s, ext vaddr: 0x%I64X, vsize: %I32X", extSecHeader->Name, extSecHeader->VirtualAddress, extSecHeader->Misc.VirtualSize);
	DbgPrint("sizeOfRawData:%I32X, PointerToRawData: 0x%I32X", extSecHeader->SizeOfRawData, extSecHeader->PointerToRawData);
}


int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
	bool bRes;

	// handling args
	int nArgc = 0;
	WCHAR* lpCommandLine = GetCommandLineW();
	WCHAR** lppArgv = CommandLineToArgvW(lpCommandLine, &nArgc);
	WCHAR* lpTargetFilename = lppArgv[1];
	WCHAR* lpPackedFilename = lppArgv[2];

	// read target file to be packed
	// lpTargetBinBuffer : head address of target file located in memory
	DWORD dwTargetBinSize;
	UCHAR* lpTargetBinBuffer;
	UINT extSize = 2200;
	UINT extHeaderSize = 0x28; // sizeof(IMAGE_SECTION_HEADER) Æ¯¶
	UINT sizeIncrease = 0;
	lpTargetBinBuffer = ReadTargetFile(lpTargetFilename, &dwTargetBinSize, extSize, extHeaderSize);
	DbgPrint("lpTargetBinBuffer: 0x%I64X", lpTargetBinBuffer);

	// locate address of headers
	PE* pe = (PE*)malloc(sizeof(PE));
	ParsePE(pe, lpTargetBinBuffer);


	// add ext section to put decode stub
	// also, shift all sections to allocate space for ext section header entry
	AddExtSection(pe, lpTargetBinBuffer, dwTargetBinSize, extSize, extHeaderSize, &sizeIncrease);

	// shift address value of pe header
	ShiftAddrOfHeaders(pe, lpTargetBinBuffer, &sizeIncrease);

	// find section to encrypt (target) and to put decodestub (ext)
	SectionConfig* target = (SectionConfig*)malloc(sizeof(SectionConfig));
	SectionConfig* ext = (SectionConfig*)malloc(sizeof(SectionConfig));
	FindSection(pe, target, ext);


	// encrypt section that includes entrypoint
	aes_encrypt((UCHAR*)(target->raddr + lpTargetBinBuffer), target->vsize);


	// put decode stub to ext section
	CreateDecodeStub(target->vaddr, target->vsize, pe->oep, ext->raddr, (DWORD)(ext->vaddr - pe->ImageBase));
	memcpy((UCHAR*)(ext->raddr + lpTargetBinBuffer), decodeStub, sizeof(decodeStub));
	DbgPrint("DecodeStub located to 0x%I64X", (ext->raddr + lpTargetBinBuffer));


	// overwrite entrypoint
	QWORD newEP = ext->vaddr - pe->ImageBase + extEfiMainOffset + 1;
	pe->OptionalHeader->AddressOfEntryPoint = newEP;
	DbgPrint("Entry Point Modified to 0x%I64X", newEP);


	// write packed file
	if (WritePackedFile(lpPackedFilename, lpTargetBinBuffer, dwTargetBinSize, target, extSize, &sizeIncrease) == FALSE) {
		Err("Writing packed file failed");
		return 1;
	}

	DbgPrint("Packing SUCCESS!!");

	// closing
	if (lpTargetBinBuffer) {
		free(lpTargetBinBuffer);
		lpTargetBinBuffer = NULL;
	}

	return 0;
}