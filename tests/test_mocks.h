#pragma once

#include <elf.h>
#include <cstdint>

/* __attribute__((weak)) is required for multiple definitions in different test files */
extern __attribute__((weak)) int mock_fd;
extern __attribute__((weak)) char* mock_file;

namespace mock_data {
inline const char* mock_procfs_maps =
    "aaaac89d0000-aaaac8b19000 r-xp 00000000 fd:00 1835605                    /usr/bin/bash\n"
    "aaaac8b28000-aaaac8b2d000 r--p 00148000 fd:00 1835605                    /usr/bin/bash\n"
    "aaaac8b2d000-aaaac8b36000 rw-p 0014d000 fd:00 1835605                    /usr/bin/bash\n"
    "aaaac8b36000-aaaac8b41000 rw-p 00000000 00:00 0\n"
    "aaaad079b000-aaaad0957000 rw-p 00000000 00:00 0                          [heap]\n"
    "ffff8ce97000-ffff8d180000 r--p 00000000 fd:00 1836023                    /usr/lib/locale/locale-archive\n"
    "ffff8d180000-ffff8d308000 r-xp 00000000 fd:00 1836518                    /usr/lib/aarch64-linux-gnu/libc.so.6\n"
    "ffff8d308000-ffff8d317000 ---p 00188000 fd:00 1836518                    /usr/lib/aarch64-linux-gnu/libc.so.6\n"
    "ffff8d317000-ffff8d31b000 r--p 00187000 fd:00 1836518                    /usr/lib/aarch64-linux-gnu/libc.so.6\n"
    "ffff8d31b000-ffff8d31d000 rw-p 0018b000 fd:00 1836518                    /usr/lib/aarch64-linux-gnu/libc.so.6\n"
    "ffff8d31d000-ffff8d329000 rw-p 00000000 00:00 0\n"
    "ffff8d330000-ffff8d35c000 r-xp 00000000 fd:00 1836730                    /usr/lib/aarch64-linux-gnu/libtinfo.so.6.3\n"
    "ffff8d35c000-ffff8d36b000 ---p 0002c000 fd:00 1836730                    /usr/lib/aarch64-linux-gnu/libtinfo.so.6.3\n"
    "ffff8d36b000-ffff8d36f000 r--p 0002b000 fd:00 1836730                    /usr/lib/aarch64-linux-gnu/libtinfo.so.6.3\n"
    "ffff8d36f000-ffff8d370000 rw-p 0002f000 fd:00 1836730                    /usr/lib/aarch64-linux-gnu/libtinfo.so.6.3\n"
    "ffff8d37e000-ffff8d3a9000 r-xp 00000000 fd:00 1836373                    /usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1\n"
    "ffff8d3aa000-ffff8d3ac000 rw-p 00000000 00:00 0\n"
    "ffff8d3ac000-ffff8d3b3000 r--s 00000000 fd:00 1837167                    /usr/lib/aarch64-linux-gnu/gconv/gconv-modules.cache\n"
    "ffff8d3b3000-ffff8d3b5000 rw-p 00000000 00:00 0\n"
    "ffff8d3b5000-ffff8d3b7000 r--p 00000000 00:00 0                          [vvar]\n"
    "ffff8d3b7000-ffff8d3b8000 r-xp 00000000 00:00 0                          [vdso]\n"
    "ffff8d3b8000-ffff8d3ba000 r--p 0002a000 fd:00 1836373                    /usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1\n"
    "ffff8d3ba000-ffff8d3bc000 rw-p 0002c000 fd:00 1836373                    /usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1\n"
    "ffffe9fad000-ffffe9fce000 rw-p 00000000 00:00 0                          [stack]\n";

inline const char* mock_procfs_maps_malformed =
    "aaaac89d0000 - aaaac8b19000 r-xp 00000000 fd:00 1835605                    /usr/bin/bash\n";

inline const char* mock_procfs_status =
    "Name:   cat\n"
    "Umask:  0002\n"
    "State:  R (running)\n"
    "Tgid:   10487\n"
    "Ngid:   0\n"
    "Pid:    10487\n"
    "PPid:   1029\n"
    "TracerPid:      0\n"
    "Uid:    1000    1000    1000    1000\n"
    "Gid:    1000    1000    1000    1000\n"
    "Threads:        1\n"
    "SigPnd: 0000000000000001\n"
    "ShdPnd: 0000000000000002\n"
    "SigBlk: 0000000000000003\n"
    "SigIgn: 0000000000000004\n";

inline const Elf64_auxv_t mock_procfs_auxv[] = {
    { 1, {.a_val = 0xdead} },
    { 3, {.a_val = 0xbeef} }
};

struct nt_file_format {
    uint64_t start_addr;
    uint64_t end_addr;
    uint64_t offset;
    const char* pathname;
};

inline const nt_file_format mock_procfs_nt_file[] = {
    { 0xaaaac89d0000, 0xaaaac8b19000, 0x00000000, "/usr/bin/bash" },
    { 0xaaaac8b28000, 0xaaaac8b2d000, 0x00148000, "/usr/bin/bash" },
    { 0xaaaac8b2d000, 0xaaaac8b36000, 0x0014d000, "/usr/bin/bash" },
    { 0xffff8ce97000, 0xffff8d180000, 0x00000000, "/usr/lib/locale/locale-archive" },
    { 0xffff8d180000, 0xffff8d308000, 0x00000000, "/usr/lib/aarch64-linux-gnu/libc.so.6" },
    { 0xffff8d317000, 0xffff8d31b000, 0x00187000, "/usr/lib/aarch64-linux-gnu/libc.so.6" },
    { 0xffff8d31b000, 0xffff8d31d000, 0x0018b000, "/usr/lib/aarch64-linux-gnu/libc.so.6" },
    { 0xffff8d330000, 0xffff8d35c000, 0x00000000, "/usr/lib/aarch64-linux-gnu/libtinfo.so.6.3" },
    { 0xffff8d36b000, 0xffff8d36f000, 0x0002b000, "/usr/lib/aarch64-linux-gnu/libtinfo.so.6.3" },
    { 0xffff8d36f000, 0xffff8d370000, 0x0002f000, "/usr/lib/aarch64-linux-gnu/libtinfo.so.6.3" },
    { 0xffff8d37e000, 0xffff8d3a9000, 0x00000000, "/usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1" },
    { 0xffff8d3ac000, 0xffff8d3b3000, 0x00000000, "/usr/lib/aarch64-linux-gnu/gconv/gconv-modules.cache" },
    { 0xffff8d3b8000, 0xffff8d3ba000, 0x0002a000, "/usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1" },
    { 0xffff8d3ba000, 0xffff8d3bc000, 0x0002c000, "/usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1" },
};
} // namespace
