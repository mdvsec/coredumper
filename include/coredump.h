#ifndef COREDUMP_H 
#define COREDUMP_H

#include <sys/types.h>

int create_coredump(const pid_t, const char*);

#endif
