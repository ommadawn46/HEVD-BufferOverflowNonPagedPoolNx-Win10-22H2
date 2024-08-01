#ifndef ARBITRARY_READ_H
#define ARBITRARY_READ_H

#include "common.h"

int SetupArbitraryRead(exploit_pipes_t* pipes, exploit_addresses_t* addrs);
void ArbitraryRead(pipe_pair_t* ghost_pipe, uintptr_t where, char* out, size_t size);

#endif // ARBITRARY_READ_H
