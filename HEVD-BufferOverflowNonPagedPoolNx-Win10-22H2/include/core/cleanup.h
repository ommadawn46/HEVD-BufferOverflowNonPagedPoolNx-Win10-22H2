#ifndef CLEANUP_H
#define CLEANUP_H

#include "common.h"

int CleanupPipes(exploit_pipes_t* pipes);
int RestorePreviousMode(exploit_addresses_t* addrs);
int FixVsChunkHeaders(exploit_addresses_t* addrs);

#endif // CLEANUP_H
