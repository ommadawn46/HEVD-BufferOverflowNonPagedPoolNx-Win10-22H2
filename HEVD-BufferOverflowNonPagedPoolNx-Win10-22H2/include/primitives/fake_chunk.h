#ifndef FAKE_CHUNK_H
#define FAKE_CHUNK_H

#include "common.h"

char* CreateFakeChunk(
    uintptr_t encoded_vs_header[2],
    unsigned char previous_size,
    unsigned char pool_index,
    unsigned char block_size,
    unsigned char pool_type,
    uint32_t pool_tag,
    uintptr_t process_billed,
    pipe_queue_entry_t* pipe_queue_entry
);

#endif // FAKE_CHUNK_H