#ifndef WINDOWS_API_WRAPPER_H
#define WINDOWS_API_WRAPPER_H

#include <windows.h>
#include <winternl.h>

typedef NTSTATUS(NTAPI* PNtFsControlFile)(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, ULONG, PVOID, ULONG, PVOID, ULONG);
typedef NTSTATUS(WINAPI* PNtWriteVirtualMemory)(HANDLE, PVOID, PVOID, ULONG, PULONG);

NTSTATUS NtFsControlFile_(
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG FsControlCode,
    PVOID InputBuffer,
    ULONG InputBufferLength,
    PVOID OutputBuffer,
    ULONG OutputBufferLength);

NTSTATUS NtWriteVirtualMemory_(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    ULONG NumberOfBytesToWrite,
    PULONG NumberOfBytesWritten);

int InitializeWindowsApiWrappers();

#endif // WINDOWS_API_WRAPPER_H