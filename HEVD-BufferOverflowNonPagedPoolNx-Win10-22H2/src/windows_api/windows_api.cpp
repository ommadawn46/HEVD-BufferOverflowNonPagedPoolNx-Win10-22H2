#include "windows_api/windows_api.h"

PNtWriteVirtualMemory pNtWriteVirtualMemory = NULL;

int InitializeWindowsApiWrappers()
{
    pNtWriteVirtualMemory = (PNtWriteVirtualMemory)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtWriteVirtualMemory");

    return pNtWriteVirtualMemory != NULL;
}

NTSTATUS NtWriteVirtualMemory_(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    ULONG NumberOfBytesToWrite,
    PULONG NumberOfBytesWritten)
{
    return pNtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten);
}
