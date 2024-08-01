#ifndef PRIVILEGE_ESCALATION_H
#define PRIVILEGE_ESCALATION_H

#include <windows.h>
#include <winternl.h>
#include <cstdint>

#include "common.h"

int SetupPrimitives(exploit_addresses_t* addrs);
int EscalatePrivileges(exploit_addresses_t* addrs);

#endif // PRIVILEGE_ESCALATION_H
