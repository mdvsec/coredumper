#ifndef DUMPER_H
#define DUMPER_H

#include <sys/types.h>
#include "parser.h"

int dump_procfs_mem(pid_t, maps_entry_t*); 

#endif
