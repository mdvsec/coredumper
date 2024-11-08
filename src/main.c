#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

static void print_usage(const char* name) {
    fprintf(stderr, 
            "Usage: %s -p <PID>\n",
            name);
}

int main(int argc, char** argv) {
    int opt;
    pid_t pid = 0;

    while ((opt = getopt(argc, argv, "p:")) > 0) {
        switch (opt) {
            case 'p':
                pid = atoi(optarg);
                if (pid <= 0) {
                    print_usage(argv[0]);
                    exit(EXIT_FAILURE);
                }
                break;
            case '?':
            default:
                print_usage(argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    if (!pid) {
        print_usage(argv[0]);
        exit(EXIT_FAILURE);
    }

    return EXIT_SUCCESS;
}
