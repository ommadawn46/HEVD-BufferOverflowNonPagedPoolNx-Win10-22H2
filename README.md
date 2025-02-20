# HackSys Extreme Vulnerable Driver (HEVD) - BufferOverflowNonPagedPoolNx Exploit

## Introduction

This repository contains an exploit for the BufferOverflowNonPagedPoolNx vulnerability in [HackSys Extreme Vulnerable Driver (HEVD)](https://github.com/hacksysteam/HackSysExtremeVulnerableDriver). The exploit targets Windows 10 Version 22H2 ([OS Build 19045.5247](https://support.microsoft.com/en-us/topic/december-10-2024-kb5048652-os-builds-19044-5247-and-19045-5247-454fbd4c-0723-449e-915b-8515ab41f8e3)) and demonstrates a technique to achieve privilege escalation from a low-integrity process to SYSTEM.

## Exploit Overview

The exploit leverages [the BufferOverflowNonPagedPoolNx vulnerability](https://github.com/hacksysteam/HackSysExtremeVulnerableDriver/blob/b02b6ea3/Driver/HEVD/Windows/BufferOverflowNonPagedPoolNx.c#L138) to create a ["ghost chunk"](https://www.sstic.org/media/SSTIC2020/SSTIC-actes/pool_overflow_exploitation_since_windows_10_19h1/SSTIC2020-Slides-pool_overflow_exploitation_since_windows_10_19h1-bayet_fariello.pdf#page=43) through [Aligned Chunk Confusion](https://github.com/synacktiv/Windows-kernel-SegmentHeap-Aligned-Chunk-Confusion) in the NonPagedPoolNx region. This ghost chunk is then manipulated to achieve arbitrary read and write primitives, which are subsequently used to elevate privileges.

Key techniques:

1. Creation of a ghost chunk using Aligned Chunk Confusion in NonPagedPoolNx, enabling leakage and manipulation of [HEAP_VS_CHUNK_HEADER](https://www.vergiliusproject.com/kernels/x64/windows-10/22h2/_HEAP_VS_CHUNK_HEADER), [POOL_HEADER](https://www.vergiliusproject.com/kernels/x64/windows-10/22h2/_POOL_HEADER), and [NP_DATA_QUEUE_ENTRY](https://github.com/ommadawn46/HEVD-BufferOverflowNonPagedPoolNx-Win10-22H2/blob/7aeb8ed/HEVD-BufferOverflowNonPagedPoolNx-Win10-22H2/include/common.h#L83) structures via the previous chunk.

2. Establishment of an arbitrary read primitive by manipulating the NP_DATA_QUEUE_ENTRY structure within the ghost chunk to set up a fake [IRP](https://github.com/ommadawn46/HEVD-BufferOverflowNonPagedPoolNx-Win10-22H2/blob/7aeb8ed/HEVD-BufferOverflowNonPagedPoolNx-Win10-22H2/include/common.h#L97).

3. Establishment of an arbitrary decrement primitive by altering the POOL_HEADER structure within the ghost chunk to set a fake ProcessBilled.

4. Establishment of an arbitrary write primitive by zeroing the [PreviousMode](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/previousmode) in the current thread's [KTHREAD](https://www.vergiliusproject.com/kernels/x64/windows-10/22h2/_KTHREAD) structure.

5. Elevation to SYSTEM privileges by modifying the Token in the current process's [EPROCESS](https://www.vergiliusproject.com/kernels/x64/windows-10/22h2/_EPROCESS) structure.

6. Stabilization of the system and avoidance of BSoD by manipulating the HEAP_VS_CHUNK_HEADER structures of the ghost chunk and its linked chunks to prevent detection of the corrupted chunk.

## Tested Environment

This exploit was tested in the following environment:

- Windows 10 Version 22H2 (OS Build 19045.5247)
- KVA Shadow: Enabled
- VBS/HVCI: Disabled
- Integrity Level: Low

## Demo

![Exploit Demo](img/demo.gif)

## Detailed Exploit Steps

1. [Establish arbitrary read primitive](https://github.com/ommadawn46/HEVD-BufferOverflowNonPagedPoolNx-Win10-22H2/blob/7aeb8ed/HEVD-BufferOverflowNonPagedPoolNx-Win10-22H2/src/primitives/arbitrary_read.cpp#L182):
   - Exploit HEVD's NonPagedPoolNx buffer overflow to corrupt an adjacent chunk's POOL_HEADER, creating a ghost chunk:
     - Set CacheAligned bit and manipulate PreviousSize to control chunk positioning.
     - Upon freeing, this creates a ghost chunk overlapping with a previous chunk.
   - The ghost chunk's HEAP_VS_CHUNK_HEADER, POOL_HEADER, and NP_DATA_QUEUE_ENTRY overlap with the previous chunk's data.
     - Reading from the previous chunk's PipeQueue leaks the ghost chunk's structures.
     - Writing to the previous chunk manipulates the ghost chunk's structures.
   - Overwrite the ghost chunk with a fake NP_DATA_QUEUE_ENTRY, pointing linkedIRP to a user-mode fake IRP.
   - Set fake IRP's SystemBuffer to the desired read address.
   - Use PeekNamedPipe to trigger a read from the specified address.

2. [Leak kernel information](https://github.com/ommadawn46/HEVD-BufferOverflowNonPagedPoolNx-Win10-22H2/blob/7aeb8ed/HEVD-BufferOverflowNonPagedPoolNx-Win10-22H2/src/core/privilege_escalation.cpp#L76):
   - Use the arbitrary read primitive to obtain kernel base address, ExpPoolQuotaCookie, RtlpHpHeapGlobals, and other critical addresses.
   - Find the EPROCESS and KTHREAD structures of the current process.

3. [Establish arbitrary decrement primitive](https://github.com/ommadawn46/HEVD-BufferOverflowNonPagedPoolNx-Win10-22H2/blob/7aeb8ed/HEVD-BufferOverflowNonPagedPoolNx-Win10-22H2/src/primitives/arbitrary_decrement.cpp#L75):
   - Create a fake EPROCESS structure in NonPagedPoolNx by writing data to the pipe associated with the previous chunk.
   - Modify the ghost chunk's POOL_HEADER by reallocating the previous chunk:
     - Set the PoolQuota bit to make the kernel interpret part of the header as a ProcessBilled pointer.
     - Configure a fake ProcessBilled pointer using the formula:
       `ProcessBilled = fake EPROCESS address ⊕ Ghost Chunk address ⊕ ExpPoolQuotaCookie`
     - Set up the fake EPROCESS structure with its PoolQuotaBlock pointing to (target address - 1).
     - Set the BlockSize to 0x100 bytes.
   - Trigger the freeing of the ghost chunk, causing the kernel to:
     - Subtract 0x100 (BlockSize) from the PoolQuota at (target address - 1).
     - This results in a decrement of 0x1 at the target address.

4. [Establish arbitrary write primitive](https://github.com/ommadawn46/HEVD-BufferOverflowNonPagedPoolNx-Win10-22H2/blob/7aeb8ed/HEVD-BufferOverflowNonPagedPoolNx-Win10-22H2/src/primitives/arbitrary_write.cpp#L12):
   - Use the arbitrary decrement primitive to manipulate the PreviousMode field of the current thread's KTHREAD structure.
     - Decrement PreviousMode from 1 (UserMode) to 0 (KernelMode).
   - This manipulation bypasses address validation in native system service routines like NtWriteVirtualMemory:
     - Normally, these routines perform checks to prevent writing to kernel space addresses when called from user mode.
     - With PreviousMode set to KernelMode, these checks are skipped.
   - As a result, the exploit gains the ability to write to arbitrary kernel memory addresses, establishing an arbitrary write primitive.

5. [Elevate privileges (data-only attack)](https://github.com/ommadawn46/HEVD-BufferOverflowNonPagedPoolNx-Win10-22H2/blob/7aeb8ed/HEVD-BufferOverflowNonPagedPoolNx-Win10-22H2/src/core/privilege_escalation.cpp#L150):
   - Use the arbitrary read primitive to locate the System process EPROCESS structure.
   - Use the arbitrary write primitive to copy the System process token to the current process's token.

6. [Restore kernel state](https://github.com/ommadawn46/HEVD-BufferOverflowNonPagedPoolNx-Win10-22H2/blob/7aeb8ed/HEVD-BufferOverflowNonPagedPoolNx-Win10-22H2/src/core/cleanup.cpp):
   - Repair the HEAP_VS_CHUNK_HEADER structures of the ghost chunk and adjacent chunks:
     - Use RtlpHpHeapGlobals (previously leaked) to decode and re-encode headers
       - `decodedVsHeader = encodedVsHeader ⊕ addrof(encodedVsHeader) ⊕ RtlpHpHeapGlobals`
     - Update UnsafeSize and UnsafePrevSize to restore proper chunk linkage
     - These repairs prevent detection of the corrupted heap structure, avoiding [KERNEL MODE HEAP CORRUPTION](https://learn.microsoft.com/windows-hardware/drivers/debugger/bug-check-0x13a--kernel-mode-heap-corruption) and subsequent BSoD
   - Restore PreviousMode to its original value of 1 (UserMode)
   - Clean up the pipes used in the exploit

## Build

To build the project:

1. Open the solution file `HEVD-BufferOverflowNonPagedPoolNx-Win10-22H2.sln` in Visual Studio 2022.
2. Build the solution (F7 or Build > Build Solution).

## Usage

**Note:** Steps for installing the HEVD driver can be found in the [Installing the HEVD Driver](#installing-the-hevd-driver) section.

1. Load the HEVD driver on the target system. (If it is not already loaded).

2. Start a Low Integrity command prompt:
   ```
   copy %systemroot%\system32\cmd.exe .\cmd-low-integrity.exe
   icacls .\cmd-low-integrity.exe /setintegritylevel low
   .\cmd-low-integrity.exe
   ```
   Verify the integrity level:
   ```
   whoami /groups | find "Mandatory Label"
   ```
   This should show "Mandatory Label\Low Mandatory Level".

3. From the Low Integrity command prompt, run the compiled exploit.

4. If successful, a SYSTEM shell should spawn.

## Installing the HEVD Driver

1. Download and extract [the precompiled driver](https://github.com/hacksysteam/HackSysExtremeVulnerableDriver/releases):

   ```cmd
   mkdir C:\temp
   powershell -Command "Invoke-WebRequest https://github.com/hacksysteam/HackSysExtremeVulnerableDriver/releases/download/v3.00/HEVD.3.00.zip -OutFile C:\temp\HEVD.3.00.zip"
   powershell -Command "Expand-Archive -Path C:\temp\HEVD.3.00.zip -DestinationPath C:\temp\HEVD -Force"
   ```

2. Place `HEVD.sys` in your desired directory:

   ```cmd
   copy C:\temp\HEVD\driver\vulnerable\x64\HEVD.sys C:\Windows\System32\drivers\HEVD.sys
   ```

3. Enable Test Signing Mode (reboot required):

   ```cmd
   bcdedit /set testsigning on
   shutdown /r /t 0
   ```

4. Create and start the driver service:

   ```cmd
   sc create HEVD type= kernel binPath= "C:\Windows\System32\drivers\HEVD.sys" start= auto
   sc start HEVD
   ```

## Setting Up the Debugger (Host System)

1. Install WinDbg from the Microsoft Store:
   - [WinDbg (Microsoft Store)](https://apps.microsoft.com/detail/9pgjgd53tn86)

2. Launch WinDbg from the Start menu and configure the kernel debugging connection:
   - Click **File** > **Attach to Kernel** > **Net**.
   - Enter a **port number** and a **unique key** of your choice. You will later specify the same `<PORT>` and `<KEY>` on the target system using `bcdedit /dbgsettings`.
   - Click **OK** to start listening for the debuggee's connection.

## Enabling Kernel Debugging (Target System)

Use the following commands on the target system, replacing:

- `<DEBUGGER_IP>` with the IP address of the host machine running WinDbg
- `<PORT>` with the same port number you entered in WinDbg
- `<KEY>` with the same key you entered in WinDbg

```cmd
bcdedit /debug {default} on
bcdedit /dbgsettings net hostip:<DEBUGGER_IP> port:<PORT> key:<KEY>
shutdown /r /t 0
```

Once the target system reboots, it will attempt to connect to the debugger over the network.

## Disclaimer

This code is provided for educational purposes only. Use it responsibly and only on systems you have permission to test.

## References

- [synacktiv/Windows-kernel-SegmentHeap-Aligned-Chunk-Confusion](https://github.com/synacktiv/Windows-kernel-SegmentHeap-Aligned-Chunk-Confusion)
- [cbayet/Exploit-CVE-2017-6008](https://github.com/cbayet/Exploit-CVE-2017-6008)
