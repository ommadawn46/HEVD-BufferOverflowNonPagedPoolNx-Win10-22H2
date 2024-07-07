#ifndef ARBITRARY_WRITE_H
#define ARBITRARY_WRITE_H

#include "common.h"

int SetupArbitraryWrite(exploit_pipes_t* pipes, exploit_addresses_t* addrs);
uintptr_t Read64(uintptr_t address);
NTSTATUS Write64(uintptr_t address, uintptr_t value);
NTSTATUS ArbitraryWrite(uintptr_t address, char* value, size_t size);

#endif // ARBITRARY_WRITE_H