#ifndef ARBITRARY_DECREMENT_H
#define ARBITRARY_DECREMENT_H

#include "common.h"

int SetupArbitraryDecrement(exploit_pipes_t* pipes, exploit_addresses_t* addrs);
int ArbitraryDecrement(exploit_pipes_t* pipes, exploit_addresses_t* addrs, uintptr_t addr_to_decrement);

#endif // ARBITRARY_DECREMENT_H