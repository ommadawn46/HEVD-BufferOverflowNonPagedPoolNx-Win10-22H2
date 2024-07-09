#ifndef PIPE_UTILS_H
#define PIPE_UTILS_H

#include "common.h"

int SetPipeAttribute(pipe_pair_t* target_pipe, char* data, size_t size);
int PeekDataFromPipe(pipe_pair_t* pipe_pair, char* out, size_t);
int AllocNPPNxChunk(pipe_pair_t* pipe, vs_chunk_t* chunk, size_t bufsize);
int FreeNPPNxChunk(pipe_pair_t* pipe, size_t bufsize);
int CreatePipePair(size_t bufsize, pipe_pair_t* pipe_pair);
pipe_spray_t* CreatePipeSpray(size_t nb, size_t size, char* data);
int PerformPipeSpray(pipe_spray_t* pipe_spray);
int ClosePipePairHandles(pipe_pair_t* pipe_pair);
void CleanupPipeSpray(pipe_spray_t* pipe_spray);
void FreeEveryThirdPipe(pipe_spray_t* pipe_spray, int start);
void EnableLookaside(int count, ...);

#endif // PIPE_UTILS_H