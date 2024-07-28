# HackSys Extreme Vulnerable Driver (HEVD) - BufferOverflowNonPagedPoolNx Exploit

## Introduction

This repository contains an exploit for the BufferOverflowNonPagedPoolNx vulnerability in [HackSys Extreme Vulnerable Driver (HEVD)](https://github.com/hacksysteam/HackSysExtremeVulnerableDriver). The exploit targets Windows 10 Version 22H2 ([OS Build 19045.4651](https://support.microsoft.com/en-us/topic/july-9-2024-kb5040427-os-builds-19044-4651-and-19045-4651-78458e76-9404-41b4-91b2-6d3cdcf4a530)) and demonstrates a technique to achieve privilege escalation from a low-integrity process to SYSTEM.

## Exploit Overview

The exploit leverages [the BufferOverflowNonPagedPoolNx vulnerability](https://github.com/hacksysteam/HackSysExtremeVulnerableDriver/blob/b02b6ea3/Driver/HEVD/Windows/BufferOverflowNonPagedPoolNx.c#L138) to create a ["ghost chunk"](https://www.sstic.org/media/SSTIC2020/SSTIC-actes/pool_overflow_exploitation_since_windows_10_19h1/SSTIC2020-Slides-pool_overflow_exploitation_since_windows_10_19h1-bayet_fariello.pdf#page=43) through [Aligned Chunk Confusion](https://github.com/synacktiv/Windows-kernel-SegmentHeap-Aligned-Chunk-Confusion) in the NonPagedPoolNx region. This ghost chunk is then manipulated to achieve arbitrary read and write primitives, which are subsequently used to elevate privileges.

Key techniques:

1. Creation of a ghost chunk using Aligned Chunk Confusion in NonPagedPoolNx, enabling leakage and manipulation of [HEAP_VS_CHUNK_HEADER](https://www.vergiliusproject.com/kernels/x64/windows-10/22h2/_HEAP_VS_CHUNK_HEADER), [POOL_HEADER](https://www.vergiliusproject.com/kernels/x64/windows-10/22h2/_POOL_HEADER), and [PipeQueueEntry](https://github.com/ommadawn46/HEVD-BufferOverflowNonPagedPoolNx-Win10-22H2/blob/63916ff/HEVD-BufferOverflowNonPagedPoolNx-Win10-22H2/include/common.h#L67) structures via the previous chunk.

2. Establishment of an arbitrary read primitive by manipulating the PipeQueueEntry structure within the ghost chunk to set up a fake [PipeQueueEntrySub](https://github.com/ommadawn46/HEVD-BufferOverflowNonPagedPoolNx-Win10-22H2/blob/63916ff/HEVD-BufferOverflowNonPagedPoolNx-Win10-22H2/include/common.h#L79).

3. Establishment of an arbitrary decrement primitive by altering the POOL_HEADER structure within the ghost chunk to set a fake ProcessBilled.

4. Establishment of an arbitrary write primitive by zeroing the [PreviousMode](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/previousmode) in the current thread's [KTHREAD](https://www.vergiliusproject.com/kernels/x64/windows-10/22h2/_KTHREAD) structure.

5. Elevation to SYSTEM privileges by modifying the Token in the current process's [EPROCESS](https://www.vergiliusproject.com/kernels/x64/windows-10/22h2/_EPROCESS) structure.

6. Stabilization of the system and avoidance of BSoD by manipulating the HEAP_VS_CHUNK_HEADER structures of the ghost chunk and its linked chunks to prevent detection of the corrupted chunk.

## Tested Environment

This exploit was tested in the following environment:

- Windows 10 Version 22H2 (OS Build 19045.4651)
- KVA Shadow: Enabled
- VBS/HVCI: Disabled
- Integrity Level: Low

## Demo

![Exploit Demo](img/demo.gif)

## Detailed Exploit Steps

1. [Establish arbitrary read primitive](https://github.com/ommadawn46/HEVD-BufferOverflowNonPagedPoolNx-Win10-22H2/blob/63916ff/HEVD-BufferOverflowNonPagedPoolNx-Win10-22H2/src/primitives/arbitrary_read.cpp#L160):
   - Exploit HEVD's NonPagedPoolNx buffer overflow to corrupt an adjacent chunk's POOL_HEADER, creating a ghost chunk:
     - Set CacheAligned bit and manipulate PreviousSize to control chunk positioning.
     - Upon freeing, this creates a ghost chunk overlapping with a previous chunk.
   - The ghost chunk's HEAP_VS_CHUNK_HEADER, POOL_HEADER, and PipeQueueEntry overlap with the previous chunk's data.
     - Reading from the previous chunk's PipeQueue leaks the ghost chunk's structures.
     - Writing to the previous chunk manipulates the ghost chunk's structures.
   - Overwrite the ghost chunk with a fake PipeQueueEntry, pointing linkedIRP to a user-mode fake PipeQueueEntrySub.
   - Set PipeQueryEntrySub's data_ptr to the desired read address.
   - Use PeekNamedPipe to trigger a read from the specified address.

2. [Leak kernel information](https://github.com/ommadawn46/HEVD-BufferOverflowNonPagedPoolNx-Win10-22H2/blob/63916ff/HEVD-BufferOverflowNonPagedPoolNx-Win10-22H2/src/core/privilege_escalation.cpp#L14):
   - Use the arbitrary read primitive to obtain kernel base address, ExpPoolQuotaCookie, and other critical addresses.
   - Find the EPROCESS structure of the current process.

3. [Establish arbitrary decrement primitive](https://github.com/ommadawn46/HEVD-BufferOverflowNonPagedPoolNx-Win10-22H2/blob/63916ff/HEVD-BufferOverflowNonPagedPoolNx-Win10-22H2/src/primitives/arbitrary_decrement.cpp#L56):
   - Create a fake EPROCESS structure in kernel space.
   - Manipulate the POOL_HEADER of the ghost chunk:
     - Set the PoolQuota bit to make the kernel interpret part of the header as a ProcessBilled pointer.
     - Set a fake ProcessBilled pointer, calculated as:
       - `ProcessBilled = addrof(fake EPROCESS) ⊕ addrof(Ghost Chunk) ⊕ ExpPoolQuotaCookie`
     - Configure the fake EPROCESS to have its PoolQuotaBlock point to (target address - 1).
     - Set the BlockSize to 0x100 bytes.
   - Trigger the freeing of the ghost chunk, causing the kernel to:
     - Subtract 0x100 (BlockSize) from the PoolQuota at (target address - 1).
     - Result in a 0x1 reduction at the target address.

4. [Establish arbitrary write primitive](https://github.com/ommadawn46/HEVD-BufferOverflowNonPagedPoolNx-Win10-22H2/blob/63916ff/HEVD-BufferOverflowNonPagedPoolNx-Win10-22H2/src/primitives/arbitrary_write.cpp#L12):
   - Use the arbitrary decrement primitive to manipulate the PreviousMode field of the current thread's KTHREAD structure.
     - Decrement PreviousMode from 1 (UserMode) to 0 (KernelMode).
   - This manipulation bypasses address validation in native system service routines like NtWriteVirtualMemory:
     - Normally, these routines perform checks to prevent writing to kernel space addresses when called from user mode.
     - With PreviousMode set to KernelMode, these checks are skipped.
   - As a result, the exploit gains the ability to write to arbitrary kernel memory addresses, establishing an arbitrary write primitive.

5. [Elevate privileges (data-only attack)](https://github.com/ommadawn46/HEVD-BufferOverflowNonPagedPoolNx-Win10-22H2/blob/63916ff/HEVD-BufferOverflowNonPagedPoolNx-Win10-22H2/src/core/privilege_escalation.cpp#L164):
   - Use the arbitrary read primitive to locate the System process EPROCESS structure.
   - Use the arbitrary write primitive to copy the System process token to the current process's token.

6. [Restore kernel state](https://github.com/ommadawn46/HEVD-BufferOverflowNonPagedPoolNx-Win10-22H2/blob/63916ff/HEVD-BufferOverflowNonPagedPoolNx-Win10-22H2/src/core/cleanup.cpp#L11):
   - Repair the HEAP_VS_CHUNK_HEADER structures of the ghost chunk and adjacent chunks:
     - Leak RtlpHpHeapGlobals from kernel space using the arbitrary read primitive
     - Decode and re-encode headers using:
       - `decodedVsHeader = encodedVsHeader ⊕ addrof(encodedVsHeader) ⊕ RtlpHpHeapGlobals`
     - Update UnsafeSize and UnsafePrevSize to restore proper chunk linkage
     - These repairs prevent detection of the corrupted heap structure, avoiding [KERNEL MODE HEAP CORRUPTION](https://learn.microsoft.com/windows-hardware/drivers/debugger/bug-check-0x13a--kernel-mode-heap-corruption) and subsequent BSoD
   - Restore PreviousMode to its original value of 1 (UserMode)

## Build

To build the project:

1. Open the solution file `HEVD-BufferOverflowNonPagedPoolNx-Win10-22H2.sln` in Visual Studio 2022.
2. Build the solution (F7 or Build > Build Solution).

## Usage

1. Load the HEVD driver on the target system.

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

## Disclaimer

This code is provided for educational purposes only. Use it responsibly and only on systems you have permission to test.

## References

- [synacktiv/Windows-kernel-SegmentHeap-Aligned-Chunk-Confusion](https://github.com/synacktiv/Windows-kernel-SegmentHeap-Aligned-Chunk-Confusion)
- [cbayet/Exploit-CVE-2017-6008](https://github.com/cbayet/Exploit-CVE-2017-6008)
