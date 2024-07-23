#ifndef PIPE_UTILS_H
#define PIPE_UTILS_H

#include "common.h"

#define MAX(a, b) ((a) > (b) ? (a) : (b))
#define MIN(a, b) ((a) < (b) ? (a) : (b))

int SetPipeAttribute(pipe_pair_t* target_pipe, const char* data, size_t size);
int PeekDataFromPipe(const pipe_pair_t* pipe_pair, char* out, size_t bufsize);
pipe_pair_t AllocNPPNxChunk(const vs_chunk_t* chunk, size_t block_size);
pipe_group_t* CreatePipeGroup(size_t nb, size_t block_size);
pipe_group_t* SprayNPPNxChunks(size_t pipes_size, vs_chunk_t* chunk, size_t block_size);
int FreeNPPNxChunk(pipe_pair_t pipe, size_t block_size);
int ClosePipePairHandles(pipe_pair_t* pipe_pair);
void DestroyPipeGroup(pipe_group_t* pipe_group);

#endif // PIPE_UTILS_H