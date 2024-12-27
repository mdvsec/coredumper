#ifndef EXIT_CODES_H
#define EXIT_CODES_H

enum coredump_exit_codes {
    CD_SUCCESS          = 0,
    CD_INVALID_ARGS     = 1,
    CD_NO_MEM           = 2,
    CD_IO_ERR           = 3,
    CD_PTRACE_ERR       = 4
};

#endif
