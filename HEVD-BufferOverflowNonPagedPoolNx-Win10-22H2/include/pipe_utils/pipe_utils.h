#ifndef PIPE_UTILS_H
#define PIPE_UTILS_H

#include "common.h"

int WriteDataToPipe(const pipe_pair_t* pipe_pair, const char* data, size_t bufsize);
int PeekDataFromPipe(const pipe_pair_t* pipe_pair, char* out, size_t bufsize);
pipe_pair_t AllocNpDataQueueEntry(size_t chunk_size, const char* pipe_data, size_t pipe_data_size);
pipe_group_t* CreatePipeGroup(size_t nb, size_t chunk_size);
pipe_group_t* SprayNpDataQueueEntry(size_t pipes_size, size_t chunk_size, const char* pipe_data, size_t pipe_data_size);
int FreeNpDataQueueEntry(pipe_pair_t pipe, size_t chunk_size);
int ClosePipePairHandles(pipe_pair_t* pipe_pair);
void DestroyPipeGroup(pipe_group_t* pipe_group);

#endif // PIPE_UTILS_H
