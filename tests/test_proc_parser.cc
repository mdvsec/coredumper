#include <gtest/gtest.h>
#include <stdlib.h>
#include <string.h>
#include "test_mocks.h"

#include "proc_parser.h"

/* Mocked data should be globally available */
char* mock_file = nullptr;
int mock_fd = -1;

namespace {
class ProcParserTest : public ::testing::Test {
protected:
    void SetUp() override {
        pid = 1337;
        pid_maps = nullptr;
    }

    void TearDown() override {
        clear_mock_file_data();

        if (mock_fd != -1) {
            close(mock_fd);
            mock_fd = -1;
        }

        free_maps_list(pid_maps);
    }

    pid_t pid;
    maps_entry_t* pid_maps;

public:
    void set_mock_file_data(const char* data) {
        if (mock_file) {
            free(mock_file);
        }

        mock_file = data ? strdup(data) : nullptr;
    }

    void clear_mock_file_data(void) {
        if (mock_file) {
            free(mock_file);
        }
        mock_file = NULL;
    }

    void set_mock_fd_from_data(const void* data, size_t size) {
        char filename[] = "/tmp/mock_fileXXXXXX";
        int fd = mkstemp(filename);
        ASSERT_NE(fd, -1);

        int ret = write(fd, data, size);
        ASSERT_EQ(ret, size);
        lseek(fd, 0, SEEK_SET);

        mock_fd = fd;

        unlink(filename);
    }
};

TEST_F(ProcParserTest, ParseProcfsMaps_ParsesFirstLine) {
    set_mock_file_data(mock_data::mock_procfs_maps);
    int ret = parse_procfs_maps(pid, &pid_maps);

    EXPECT_EQ(ret, 0);
    ASSERT_NE(pid_maps, nullptr);
    EXPECT_EQ(pid_maps->start_addr, 0xaaaac89d0000);
    EXPECT_EQ(pid_maps->end_addr, 0xaaaac8b19000);
    EXPECT_STREQ(pid_maps->perms, "r-xp");
    EXPECT_EQ(pid_maps->offset, 0);
    EXPECT_EQ(pid_maps->dev_major, 0xfd);
    EXPECT_EQ(pid_maps->dev_minor, 0x0);
    EXPECT_EQ(pid_maps->inode, 1835605);
    EXPECT_STREQ(pid_maps->pathname, "/usr/bin/bash");
}

TEST_F(ProcParserTest, ParseProcfsMaps_ParsesMultipleLines) {
    set_mock_file_data(mock_data::mock_procfs_maps);
    int ret = parse_procfs_maps(pid, &pid_maps);

    EXPECT_EQ(ret, 0);
    ASSERT_NE(pid_maps, nullptr);

    size_t count = 0;
    while (pid_maps) {
        count++;
        pid_maps = pid_maps->next;
    }

    EXPECT_EQ(count, 21); // 24 in total, but non-readable regions and [vvar] should be skipped
}

TEST_F(ProcParserTest, ParseProcfsMaps_SkipsMalformedLine) {
    set_mock_file_data(mock_data::mock_procfs_maps_malformed);
    int ret = parse_procfs_maps(pid, &pid_maps);

    EXPECT_NE(ret, 0);
    EXPECT_EQ(pid_maps, nullptr);
}

TEST_F(ProcParserTest, ParsesProcfsTaskStatus) {
    prstatus_t status = {};

    set_mock_file_data(mock_data::mock_procfs_status);
    int ret = populate_prstatus(pid, pid, &status);

    ASSERT_EQ(ret, 0);
    EXPECT_EQ(status.pr_pid, pid);
    EXPECT_EQ(status.pr_ppid, 1029);
    EXPECT_EQ(status.pr_sigpend, 1);
    EXPECT_EQ(status.pr_sighold, 3);
}

TEST_F(ProcParserTest, ParsesProcfsStatus) {
    prpsinfo_t status = {};

    set_mock_file_data(mock_data::mock_procfs_status);
    int ret = collect_nt_prpsinfo(pid, &status);

    ASSERT_EQ(ret, 0);
    EXPECT_EQ(status.pr_pid, pid);
    EXPECT_EQ(status.pr_ppid, 1029);
    EXPECT_STREQ(status.pr_fname, "cat");
    EXPECT_EQ(status.pr_sname, 'R');
    EXPECT_EQ(status.pr_state, 'R');
    EXPECT_EQ(status.pr_zomb, 0);
    EXPECT_EQ(status.pr_uid, 1000);
    EXPECT_EQ(status.pr_gid, 1000);
}

TEST_F(ProcParserTest, CollectNtAuxv_ParsesValidData) {
    Elf64_auxv_t* auxv_buf = nullptr;
    size_t auxv_size = 0;

    set_mock_fd_from_data(mock_data::mock_procfs_auxv, sizeof(mock_data::mock_procfs_auxv));
    int ret = collect_nt_auxv(pid, &auxv_buf, &auxv_size);

    EXPECT_EQ(ret, 0);
    ASSERT_NE(auxv_buf, nullptr);
    EXPECT_EQ(auxv_size, sizeof(mock_data::mock_procfs_auxv));
    EXPECT_EQ(auxv_buf[0].a_type, 1);
    EXPECT_EQ(auxv_buf[0].a_un.a_val, 0xdead);
    EXPECT_EQ(auxv_buf[1].a_type, 3);
    EXPECT_EQ(auxv_buf[1].a_un.a_val, 0xbeef);

    free(auxv_buf);
}

TEST_F(ProcParserTest, CollectNtAuxv_FailsOnBadArgs) {
    Elf64_auxv_t* auxv_buf = reinterpret_cast<Elf64_auxv_t*>(0xdead);
    size_t auxv_size = 0;

    int ret = collect_nt_auxv(pid, &auxv_buf, &auxv_size);

    EXPECT_NE(ret, 0);
}

TEST_F(ProcParserTest, CollectNtAuxv_FailsOnEmptyRead) {
    Elf64_auxv_t* auxv_buf = nullptr;
    size_t auxv_size = 0;

    set_mock_fd_from_data("", 0);

    int ret = collect_nt_auxv(pid, &auxv_buf, &auxv_size);

    EXPECT_NE(ret, 0);
    EXPECT_EQ(auxv_buf, nullptr);
}

TEST_F(ProcParserTest, CollectNtFile_GeneratesCorrectOutput) {
    void* data_buf = nullptr;
    size_t data_size = 0;

    set_mock_file_data(mock_data::mock_procfs_maps);
    int ret = parse_procfs_maps(pid, &pid_maps);

    EXPECT_EQ(ret, 0);
    ASSERT_NE(pid_maps, nullptr);

    ret = collect_nt_file(pid_maps, &data_buf, &data_size);
    EXPECT_EQ(ret, 0);

    const uint64_t region_count = 14;
    uint64_t* hdr_ptr = static_cast<uint64_t*>(data_buf);
    uint64_t* region_ptr = hdr_ptr + 2;
    char* name_ptr = reinterpret_cast<char*>(region_ptr + region_count * 3);

    EXPECT_EQ(hdr_ptr[0], region_count);
    EXPECT_EQ(hdr_ptr[1], 1);

    for (size_t i = 0; i < region_count; i++) {
        EXPECT_EQ(region_ptr[0], mock_data::mock_procfs_nt_file[i].start_addr);
        EXPECT_EQ(region_ptr[1], mock_data::mock_procfs_nt_file[i].end_addr);
        EXPECT_EQ(region_ptr[2], mock_data::mock_procfs_nt_file[i].offset);
        EXPECT_STREQ(static_cast<const char *>(name_ptr), mock_data::mock_procfs_nt_file[i].pathname);

        region_ptr += 3;
        name_ptr += strlen(name_ptr) + 1; // null-byte should be included
    }

    free(data_buf);
}

TEST_F(ProcParserTest, CollectNtFile_PreallocatedDataFails) {
    void* data_buf = malloc(16);
    size_t data_size = 0;

    set_mock_file_data(mock_data::mock_procfs_maps);
    int ret = parse_procfs_maps(pid, &pid_maps);

    EXPECT_EQ(ret, 0);
    ASSERT_NE(pid_maps, nullptr);

    ret = collect_nt_file(pid_maps, &data_buf, &data_size);
    EXPECT_NE(ret, 0);

    free(data_buf);
}

TEST_F(ProcParserTest, CollectNtFile_NullDataSizeFails) {
    void* data_buf = nullptr;

    set_mock_file_data(mock_data::mock_procfs_maps);
    int ret = parse_procfs_maps(pid, &pid_maps);

    EXPECT_EQ(ret, 0);
    ASSERT_NE(pid_maps, nullptr);

    ret = collect_nt_file(pid_maps, &data_buf, nullptr);
    EXPECT_NE(ret, 0);
}
} // namespace
