#ifndef WINDOWS_API_WRAPPER_H
#define WINDOWS_API_WRAPPER_H

#include <windows.h>
#include <winternl.h>

typedef NTSTATUS(WINAPI* PNtWriteVirtualMemory)(HANDLE, PVOID, PVOID, ULONG, PULONG);

NTSTATUS NtWriteVirtualMemory_(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    ULONG NumberOfBytesToWrite,
    PULONG NumberOfBytesWritten);

int InitializeWindowsApiWrappers();

#endif // WINDOWS_API_WRAPPER_H
