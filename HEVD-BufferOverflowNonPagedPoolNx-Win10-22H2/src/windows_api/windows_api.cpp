#include "windows_api/windows_api.h"

PNtFsControlFile pNtFsControlFile = NULL;
PNtWriteVirtualMemory pNtWriteVirtualMemory = NULL;

int InitializeWindowsApiWrappers()
{
    pNtFsControlFile = (PNtFsControlFile)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtFsControlFile");
    pNtWriteVirtualMemory = (PNtWriteVirtualMemory)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtWriteVirtualMemory");

    return pNtFsControlFile && pNtFsControlFile;
}

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
    ULONG OutputBufferLength)
{
    return pNtFsControlFile(
        FileHandle,
        Event,
        ApcRoutine,
        ApcContext,
        IoStatusBlock,
        FsControlCode,
        InputBuffer,
        InputBufferLength,
        OutputBuffer,
        OutputBufferLength);
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
