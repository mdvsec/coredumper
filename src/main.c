#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include "coredump.h"

#define PATHNAME_MAX 64

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

int main(int argc, char** argv) {
    char filename[PATHNAME_MAX];
    int custom_filename = 0;
    int opt;
    int status;
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
                if (strlen(optarg) >= PATHNAME_MAX) {
                    print_usage_exit(argv[0]);
                }
                strncpy(filename, optarg, PATHNAME_MAX - 1);
                filename[PATHNAME_MAX - 1] = 0;
                custom_filename = 1;

                break;
            case '?':
            default:
                print_usage_exit(argv[0]);
        }
    }

    if (!pid) {
        print_usage_exit(argv[0]);
    }

    if (!custom_filename) {
        snprintf(filename, sizeof(filename), "%d_coredump", pid);
    }

    status = kill(pid, SIGSTOP);
    if (status < 0) {
        handle_kill_error_exit(pid);
    }

    printf("[DEBUG] Proccess %d has been stopped\n", pid);

    ret = create_coredump(pid, filename);
    if (ret < 0) {
        fprintf(stderr,
                "Error occured while creating coredump file\n");
    } else {
        printf("[Success] Process %d has been dumped to file %s\n",
               pid, filename);
    }

    status = kill(pid, SIGCONT);
    if (status < 0) {
        handle_kill_error_exit(pid);
    }

    printf("[DEBUG] Process %d has been resumed\n", pid);

    return ret;
}
