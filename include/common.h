#ifndef COMMON_H 
#define COMMON_H

#include <stdio.h>
#include <errno.h>
#include <string.h>

#ifdef DEBUG_MODE
#define LOG(msg, ...) do { \
            fprintf(stderr, \
                    "[DEBUG] %s(): " msg "\n", __func__, ##__VA_ARGS__); \
            if (errno) { \
                fprintf(stderr, \
                        "[DEBUG] errno: %d, message: %s\n", \
                        errno, strerror(errno)); \
            } \
        } while (0)
#else
#define LOG(msg, ...) // No-op
#endif

enum coredump_exit_codes {
    CD_SUCCESS          = 0,
    CD_INVALID_ARGS     = 1,
    CD_NO_MEM           = 2,
    CD_IO_ERR           = 3,
    CD_PTRACE_ERR       = 4,
    CD_SPECIAL_PROC     = 5
};

#endif
