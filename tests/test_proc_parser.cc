#include <gtest/gtest.h>
#include <stdlib.h>
#include <string.h>

#include "proc_parser.h"

char* mock_file = NULL;

static void set_mock_file_content(const char* content) {
    if (mock_file) {
        free(mock_file);
    }

    mock_file = strdup(content);
}

static void clear_mock_file_content(void) {
    free(mock_file);
    mock_file = NULL;
}

static const char* mock_procfs_maps = 
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

static const char* mock_procfs_maps_malformed = 
    "aaaac89d0000 - aaaac8b19000 r-xp 00000000 fd:00 1835605                    /usr/bin/bash\n";

static const char* mock_procfs_status = 
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

TEST(ProcParserTest, ParseProcfsMaps_ParsesLine) {
    pid_t pid = 1337;
    maps_entry_t* pid_maps = nullptr;
    
    set_mock_file_content(mock_procfs_maps);
    int ret = parse_procfs_maps(pid, &pid_maps);
    clear_mock_file_content();

    EXPECT_EQ(ret, 0);
    ASSERT_NE(pid_maps, nullptr);
    EXPECT_EQ(pid_maps->start_addr, 0xaaaac89d0000);
    EXPECT_EQ(pid_maps->end_addr, 0xaaaac8b19000);
    EXPECT_EQ(strcmp(pid_maps->perms, "r-xp"), 0);
    EXPECT_EQ(pid_maps->offset, 0);
    EXPECT_EQ(pid_maps->dev_major, 0xfd);
    EXPECT_EQ(pid_maps->dev_minor, 0x0);
    EXPECT_EQ(pid_maps->inode, 1835605);
    EXPECT_EQ(strcmp(pid_maps->pathname, "/usr/bin/bash"), 0);

    free_maps_list(pid_maps);
}

TEST(ProcParserTest, ParseProcfsMaps_ParsesMultipleLines) {
    pid_t pid = 1337;
    maps_entry_t* pid_maps = nullptr;

    set_mock_file_content(mock_procfs_maps);
    int ret = parse_procfs_maps(pid, &pid_maps);
    clear_mock_file_content();

    EXPECT_EQ(ret, 0);
    ASSERT_NE(pid_maps, nullptr);

    size_t count = 0;
    while (pid_maps) {
        count++;
        pid_maps = pid_maps->next;
    }

    EXPECT_EQ(count, 21); // 24 in total, but non-readable regions and [vvar] should be skipped
    
    free_maps_list(pid_maps);
}

TEST(ProcParserTest, ParseProcfsMaps_SkipsMalformedLine) {
    pid_t pid = 1337;
    maps_entry_t* pid_maps = nullptr;

    set_mock_file_content(mock_procfs_maps_malformed);
    int ret = parse_procfs_maps(pid, &pid_maps);
    clear_mock_file_content();

    EXPECT_NE(ret, 0);
    EXPECT_EQ(pid_maps, nullptr);
}

TEST(ProcParserTest, ParsesProcfsTaskStatus) {
    pid_t pid = 1337;
    prstatus_t status = {};

    set_mock_file_content(mock_procfs_status);
    int ret = populate_prstatus(pid, pid, &status);
    clear_mock_file_content();

    ASSERT_EQ(ret, 0);
    EXPECT_EQ(status.pr_pid, pid);
    EXPECT_EQ(status.pr_ppid, 1029);
    EXPECT_EQ(status.pr_sigpend, 1);
    EXPECT_EQ(status.pr_sighold, 3);
}

TEST(ProcParserTest, ParsesProcfsStatus) {
    pid_t pid = 1337;
    prpsinfo_t status = {};

    set_mock_file_content(mock_procfs_status);
    int ret = collect_nt_prpsinfo(pid, &status);
    clear_mock_file_content();

    ASSERT_EQ(ret, 0);
    EXPECT_EQ(status.pr_pid, pid);
    EXPECT_EQ(status.pr_ppid, 1029);
    EXPECT_EQ(strcmp(status.pr_fname, "cat"), 0);
    EXPECT_EQ(status.pr_sname, 'R');
    EXPECT_EQ(status.pr_state, 'R');
    EXPECT_EQ(status.pr_zomb, 0);
    EXPECT_EQ(status.pr_uid, 1000);
    EXPECT_EQ(status.pr_gid, 1000);
}

