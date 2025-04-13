#ifndef PE_UTILS_H
#define PE_UTILS_H

#include <windows.h>

// RVAs to kernel functions, variables and imports
extern DWORD g_nt_PsInitialSystemProcess_RVA;
extern DWORD g_nt_ExAllocatePoolWithTag_RVA;
extern DWORD g_nt_ExpPoolQuotaCookie_RVA;
extern DWORD g_nt_RtlpHpHeapGlobals_RVA;
extern DWORD g_Npfs_imp_ExAllocatePoolWithTag_RVA;

// Resolves all required kernel entity RVAs
BOOL ResolveKernelRvas();

// Locates an entry in the Import Address Table and returns its RVA
DWORD ResolveIATEntryRva(const char* modulePath, const char* importDll, const char* functionName);

// Locates an entry in the Export Address Table and returns its RVA
DWORD ResolveEATEntryRva(const char* modulePath, const char* functionName);

// Finds a byte pattern and resolves the target of a 32-bit RIP-relative instruction
DWORD ResolveRip32RelativeRva(const char* modulePath, const BYTE* pattern, DWORD patternSize, DWORD ripDisplacementOffset);

#endif // PE_UTILS_H
