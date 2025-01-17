#ifndef HEVD_H
#define HEVD_H

#define IOCTL(Function) CTL_CODE(FILE_DEVICE_UNKNOWN, Function, METHOD_NEITHER, FILE_ANY_ACCESS)
#define HEVD_IOCTL_BUFFER_OVERFLOW_NON_PAGED_POOL_NX IOCTL(0x812)
#define HEVD_DEVICE_NAME "\\\\.\\HackSysExtremeVulnerableDriver"

HANDLE HevdOpenDeviceHandle(void);
int HevdTriggerBufferOverflowNonPagedPoolNx(HANDLE hHevd, char* overflow_buf, size_t overflow_size);

#endif // HEVD_H
