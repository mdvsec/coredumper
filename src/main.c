#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <limits.h>
#include "coredump.h"
#include "exit_codes.h"

static void __attribute__((noreturn)) print_usage_exit(const char* name) {
    fprintf(stderr, 
            "Usage: %s -p <pid> [-o filename]\n",
            name);
    exit(EXIT_FAILURE);
}

static void __attribute__((noreturn)) handle_kill_error_exit(const int pid) {
    switch (errno) {
        case EPERM:
            fprintf(stderr, 
                    "Access denied: root privileges are required to control process %d\n", 
                    pid);
            break;
        case ESRCH:
            fprintf(stderr, 
                    "Error: process %d or process group cannot be found\n", 
                    pid);
            break;
        default:
            fprintf(stderr, 
                    "Error: unknown error occurred while controlling process %d\n", 
                    pid);
            break;
    }
    exit(EXIT_FAILURE);
}

static void print_ret_msg(const int code, const pid_t pid, const char* filename) {
    switch (code) {
        case CD_SUCCESS:
            fprintf(stdout,
                    "Success: process %d has been dumped to the file %s\n",
                    pid, filename);
            break;
        case CD_INVALID_ARGS:
            fprintf(stderr,
                    "Error: internal error occured due to invalid arguments\n");
            break;
        case CD_NO_MEM:
            fprintf(stderr,
                    "Error: insufficient memory to complete the operation\n");
            break;
        case CD_IO_ERR:
            fprintf(stderr,
                    "Error: I/O error occured while accessing a file system\n");
            break;
        case CD_PTRACE_ERR:
            fprintf(stderr,
                    "Error: ptrace() failed on process %d\n",
                    pid);
            break;
        default:
            fprintf(stderr,
                    "Error: unknown error occured\n");
            break;
    }
}

int main(int argc, char** argv) {
    char* filename = NULL;
    int opt;
    int ret;
    pid_t pid = 0;

    while ((opt = getopt(argc, argv, "p:o:")) > 0) {
        switch (opt) {
            case 'p':
                pid = atoi(optarg);
                if (pid <= 0) {
                    print_usage_exit(argv[0]);
                }

                break;
            case 'o':
                if (strlen(optarg) >= PATH_MAX) {
                    print_usage_exit(argv[0]);
                }

                filename = strdup(optarg);
                if (!filename) {
                    fprintf(stderr,
                            "Error: insufficient memory to complete the operation\n");
                    exit(EXIT_FAILURE);
                }

                break;
            case '?':
            default:
                print_usage_exit(argv[0]);
        }
    }

    if (!pid) {
        free(filename);
        print_usage_exit(argv[0]);
    }

    if (!filename) {
        char default_filename[PATH_MAX];
        snprintf(default_filename, sizeof(default_filename), "%d_coredump", pid);

        filename = strdup(default_filename);
        if (!filename) {
            fprintf(stderr,
                    "Error: insufficient memory to complete the operation\n");
            exit(EXIT_FAILURE);
        }
    }

    if (kill(pid, SIGSTOP) < 0) {
        free(filename);
        handle_kill_error_exit(pid);
    }

    printf("[DEBUG] Proccess %d has been stopped\n", pid);

    ret = create_coredump(pid, filename);
    print_ret_msg(ret, pid, filename);

    if (kill(pid, SIGCONT) < 0) {
        free(filename);
        handle_kill_error_exit(pid);
    }

    printf("[DEBUG] Process %d has been resumed\n", pid);

    free(filename);

    return ret;
}
