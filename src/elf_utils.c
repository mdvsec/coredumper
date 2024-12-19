#include "elf_utils.h"
#include <stddef.h>
#include <elf.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/procfs.h>
#include <sys/uio.h>
#include "proc_parser.h"

#define PAGE_SIZE_DEFAULT 4096
#define PT_NOTE_ALIGNMENT 4

#define PADDING4(x) (((x + PT_NOTE_ALIGNMENT - 1) & ~(PT_NOTE_ALIGNMENT - 1)) - x)

static ssize_t dump_process_memory(const int, const maps_entry_t*, const pid_t);
static ssize_t dump_process_info(const int, const maps_entry_t*, const pid_t);
static ssize_t write_nt_prpsinfo(const int, const prpsinfo_t*);
static ssize_t write_nt_auxv(const int, const Elf64_auxv_t*, const size_t);
static ssize_t write_nt_file(const int, const maps_entry_t*);
static ssize_t write_threads_state(const int, const thread_state_t*);
static ssize_t write_note_data(const int, const void*, const size_t, const int, const char*);
static Elf64_Phdr create_program_header_ptload(const maps_entry_t*);
static Elf64_Phdr create_program_header_ptnote(size_t);
static int write_phdr_entry(const int, const Elf64_Phdr*);
static long get_pagesize(void);

off_t table_offset;
off_t data_offset;

int write_elf_header(const int fd, const ssize_t phdr_count) {
    if (lseek(fd, 0, SEEK_SET) < 0) {
        return -1;
    }

    Elf64_Ehdr elf_hdr;
    memset(&elf_hdr, 0, sizeof(elf_hdr));

    elf_hdr.e_ident[EI_MAG0] = ELFMAG0;
    elf_hdr.e_ident[EI_MAG1] = ELFMAG1;
    elf_hdr.e_ident[EI_MAG2] = ELFMAG2;
    elf_hdr.e_ident[EI_MAG3] = ELFMAG3;

    elf_hdr.e_ident[EI_CLASS] = ELFCLASS64;
    elf_hdr.e_ident[EI_DATA] = ELFDATA2LSB;
    elf_hdr.e_ident[EI_VERSION] = EV_CURRENT;
    elf_hdr.e_ident[EI_OSABI] = ELFOSABI_NONE;
    elf_hdr.e_ident[EI_ABIVERSION] = 0;

    elf_hdr.e_type = ET_CORE;
    elf_hdr.e_machine = EM_AARCH64;
    elf_hdr.e_version = EV_CURRENT;
    elf_hdr.e_phoff = sizeof(Elf64_Ehdr); 
    elf_hdr.e_ehsize = sizeof(Elf64_Ehdr);
    elf_hdr.e_phentsize = sizeof(Elf64_Phdr);
    elf_hdr.e_phnum = phdr_count;

    if (write(fd, &elf_hdr, sizeof(elf_hdr)) != sizeof(elf_hdr)) {
        return -1;
    }

    return 0;
}

ssize_t write_elf_program_headers(const int fd, const maps_entry_t* head, const pid_t pid) {
    ssize_t ptload_hdr_count;
    ssize_t ptnote_hdr_count;

    // Reserve space for ELF header
    table_offset = lseek(fd, sizeof(Elf64_Ehdr), SEEK_SET);
    if (table_offset < 0) {
        return -1;
    }

    data_offset = getpagesize();

    ptload_hdr_count = dump_process_memory(fd, head, pid);
    if (ptload_hdr_count < 0) {
        return -1;
    }

    ptnote_hdr_count = dump_process_info(fd, head, pid);
    if (ptnote_hdr_count < 0) {
        return -1;
    }

    return ptload_hdr_count + ptnote_hdr_count;
}

static ssize_t dump_process_memory(const int fd, const maps_entry_t* head, const pid_t pid) {
    const maps_entry_t* entry;
    ssize_t ptload_hdr_count;

    ptload_hdr_count = 0;
    entry = head;

    while (entry) {
        Elf64_Phdr phdr;

        phdr = create_program_header_ptload(entry);

        if (write_phdr_entry(fd, &phdr) < 0) {
            return -1;
        }

        if (dump_memory_region(fd, &phdr, pid) < 0) {
            return -1;
        }

        ptload_hdr_count++;
        entry = entry->next;
    }

    return ptload_hdr_count;
}

static ssize_t dump_process_info(const int fd, const maps_entry_t* head, const pid_t pid) {
    prpsinfo_t prpsinfo;
    thread_state_t* threads_state;
    Elf64_auxv_t* auxv_buf;
    size_t auxv_size;
    ssize_t ptnote_hdr_count;
    int written_hdr;

    ptnote_hdr_count = 0;

    if (collect_nt_prpsinfo(pid, &prpsinfo) < 0) {
        return -1;
    }

    written_hdr = write_nt_prpsinfo(fd, &prpsinfo);
    if (written_hdr < 0) {
        return -1;
    }
    ptnote_hdr_count += written_hdr;

    threads_state = collect_threads_state(pid);
    if (!threads_state) {
        return -1;
    }

    written_hdr = write_threads_state(fd, threads_state);
    if (written_hdr < 0) {
        free_state_list(threads_state);
        return -1;
    }
    ptnote_hdr_count += written_hdr;

    auxv_buf = collect_nt_auxv(pid, &auxv_size);
    if (!auxv_buf) {
        free_state_list(threads_state);
        return -1;
    }

    written_hdr = write_nt_auxv(fd, auxv_buf, auxv_size);
    if (written_hdr < 0) {
        free(auxv_buf);
        free_state_list(threads_state);
        return -1;
    }
    ptnote_hdr_count += written_hdr;

    written_hdr = write_nt_file(fd, head);
    if (written_hdr < 0) {
        free(auxv_buf);
        free_state_list(threads_state);
        return -1;
    }
    ptnote_hdr_count += written_hdr;

    free(auxv_buf);
    free_state_list(threads_state);

    return ptnote_hdr_count;
}

static ssize_t write_nt_prpsinfo(const int fd, const prpsinfo_t* info) {
    Elf64_Phdr phdr;
    ssize_t write_sz;
    ssize_t written_hdr;
    off_t tmp_data_offset;

    written_hdr = 0;
    tmp_data_offset = data_offset;
    write_sz = write_note_data(fd, info, sizeof(*info), NT_PRPSINFO, "CORE");
    if (write_sz < 0) {
        return -1;
    }

    data_offset = tmp_data_offset;
    phdr = create_program_header_ptnote((size_t) write_sz);
    if (write_phdr_entry(fd, &phdr) < 0) {
        return -1;
    }
    data_offset += write_sz;

    written_hdr++;

    return written_hdr;
}

static ssize_t write_nt_auxv(const int fd, const Elf64_auxv_t* auxv_buf, const size_t len) {
    Elf64_Phdr phdr;
    ssize_t write_sz;
    ssize_t written_hdr;
    off_t tmp_data_offset;

    written_hdr = 0;
    tmp_data_offset = data_offset;
    write_sz = write_note_data(fd, auxv_buf, len, NT_AUXV, "CORE");
    if (write_sz < 0) {
        return -1;
    }

    data_offset = tmp_data_offset;
    phdr = create_program_header_ptnote((size_t) write_sz);
    if (write_phdr_entry(fd, &phdr) < 0) {
        return -1;
    }
    data_offset += write_sz;

    written_hdr++;

    return written_hdr;
}

static ssize_t write_nt_file(const int fd, const maps_entry_t* head) {
    Elf64_Phdr phdr;
    ssize_t written_hdr;
    off_t tmp_data_offset;
    size_t desc_sz;
    size_t write_sz;
    size_t region_count;
    maps_entry_t* entry;
    void* data_buf;
    size_t region_offset;
    size_t name_offset;
    const char anon_name[]= "[anonymous]";

    desc_sz = sizeof(uint64_t) * 2; /* count, pagesize */
    region_count = 0;
    entry = (maps_entry_t*) head;
    while (entry) {
        if (entry->inode) {
            size_t entry_name_len = entry->len ? strlen(entry->pathname) + 1 : sizeof(anon_name);
            desc_sz += sizeof(uint64_t) * 3 + entry_name_len; /* start_addr, size, offset */

            region_count++;
        }

        entry = entry->next;
    }

    data_buf = malloc(desc_sz);
    if (!data_buf) {
        return -1;
    }

    memset(data_buf, 0, desc_sz);

    *(uint64_t*) data_buf = (uint64_t) region_count;
    *(uint64_t*) ((char*) data_buf + sizeof(uint64_t)) = (uint64_t) 1; /* Required by GDB */

    region_offset = sizeof(uint64_t) * 2;
    name_offset = region_offset + region_count * sizeof(uint64_t) * 3;

    entry = (maps_entry_t*) head;
    while (entry) {
        if (entry->inode) {
            const char* entry_name;
            size_t entry_name_len;

            *(uint64_t*) ((char*) data_buf + region_offset) = (uint64_t) entry->start_addr;
            region_offset += sizeof(uint64_t);

            *(uint64_t*) ((char*) data_buf + region_offset) = (uint64_t) entry->end_addr;
            region_offset += sizeof(uint64_t);

            *(uint64_t*) ((char*) data_buf + region_offset) = (uint64_t) entry->offset;
            region_offset += sizeof(uint64_t);

            entry_name = entry->len ? entry->pathname : anon_name;
            entry_name_len = strlen(entry_name) + 1;

            strcpy((char*) data_buf + name_offset, entry_name);
            name_offset += entry_name_len;
        }

        entry = entry->next;
    }

    /*
    const uint64_t* ptr = (const uint64_t*) data_buf;
    uint64_t count = *ptr++;
    uint64_t pgsz = *ptr++;

    printf("Region count: %ld\nPage size: %ld\n", count, pgsz);

    const uint64_t* region_ptr = ptr;

    const char* name_ptr = (const char*) data_buf + sizeof(uint64_t) * 2 + (region_count * sizeof(uint64_t) * 3);

    printf("\nRegions:\n");
    printf("Start Address | End Address | Offset       | Name\n");
    printf("-------------------------------------------------\n");

    for (size_t i = 0; i < region_count; i++) {
        uint64_t start_addr = *region_ptr++;
        uint64_t end_addr = *region_ptr++;
        uint64_t offset = *region_ptr++;

        printf("%12lx | %12lx | %12lx | %s\n", start_addr, end_addr, offset, name_ptr);

        name_ptr += strlen(name_ptr) + 1;
    }

    */

    written_hdr = 0;
    tmp_data_offset = data_offset;

    write_sz = write_note_data(fd, data_buf, desc_sz, NT_FILE, "CORE");
    if (write_sz < 0) {
        return -1;
    }

    data_offset = tmp_data_offset;

    phdr = create_program_header_ptnote((size_t) write_sz);
    if (write_phdr_entry(fd, &phdr) < 0) {
        return -1;
    }
    data_offset += write_sz;

    written_hdr++;

    free(data_buf);

    return written_hdr;
}

static ssize_t write_note_data(const int fd, const void* data, const size_t data_len, const int type, const char* name) {
    Elf64_Nhdr nhdr;
    size_t name_len;
    size_t name_len_padding;
    size_t data_len_padding;
    size_t note_sz;
    struct iovec iov[5];
    char p_bytes[PT_NOTE_ALIGNMENT] = {0};

    name_len = strlen(name) + 1;

    name_len_padding = PADDING4(name_len);
    data_len_padding = PADDING4(data_len);

    note_sz = sizeof(nhdr) + name_len + name_len_padding + data_len + data_len_padding;

    memset(&nhdr, 0, sizeof(nhdr));
    nhdr.n_namesz = name_len;
    nhdr.n_descsz = data_len;
    nhdr.n_type = type;

    memset(iov, 0, sizeof(iov));
    iov[0].iov_base = &nhdr;
    iov[0].iov_len = sizeof(nhdr);

    iov[1].iov_base = (void*) name;
    iov[1].iov_len = name_len;

    iov[2].iov_base = p_bytes;
    iov[2].iov_len = name_len_padding;

    iov[3].iov_base = (void*) data;
    iov[3].iov_len = data_len;

    iov[4].iov_base = p_bytes;
    iov[4].iov_len = data_len_padding;

    if (lseek(fd, data_offset, SEEK_SET) < 0) {
        return -1;
    }

    if (writev(fd, iov, 5) != note_sz) {
        return -1;
    }

    data_offset += note_sz;

    return note_sz;
}

// It definitely has to be rewritten
static ssize_t write_threads_state(const int fd, const thread_state_t* head) {
    const thread_state_t* entry;
    size_t note_sz;
    ssize_t written_hdr;

    written_hdr = 0;
    entry = head;

    while (entry) {
        Elf64_Phdr phdr;
        ssize_t write_sz;
        off_t tmp_data_offset = data_offset;

        note_sz = 0;

        write_sz = write_note_data(fd, &entry->prstatus, sizeof(entry->prstatus), NT_PRSTATUS, "CORE");
        if (write_sz < 0) {
            return -1;
        }
        note_sz += write_sz;

        write_sz = write_note_data(fd, &entry->fpregs, sizeof(entry->fpregs), NT_FPREGSET, "CORE");
        if (write_sz < 0) {
            return -1;
        }
        note_sz += write_sz;

        write_sz = write_note_data(fd, &entry->pac_mask, sizeof(entry->pac_mask), NT_ARM_PAC_MASK, "LINUX");
        if (write_sz < 0) {
            return -1;
        }
        note_sz += write_sz;

        write_sz = write_note_data(fd, &entry->siginfo, sizeof(entry->siginfo), NT_SIGINFO, "CORE");
        if (write_sz < 0) {
            return -1;
        }
        note_sz += write_sz;

        data_offset = tmp_data_offset;
        phdr = create_program_header_ptnote(note_sz);
        if (write_phdr_entry(fd, &phdr) < 0) {
            return -1;
        }
        data_offset += note_sz;

        written_hdr++;

        entry = entry->next;
    }

    return written_hdr;
}

static int write_phdr_entry(const int fd, const Elf64_Phdr* phdr) {
    if (lseek(fd, table_offset, SEEK_SET) < 0) {
        return -1;
    }

    if (write(fd, phdr, sizeof(*phdr)) != sizeof(*phdr)) {
        return -1;
    }

    table_offset += sizeof(*phdr);

    return 0;
}

static Elf64_Phdr create_program_header_ptload(const maps_entry_t* entry) {
    Elf64_Phdr phdr;
    memset(&phdr, 0, sizeof(Elf64_Phdr));

    phdr.p_type = PT_LOAD;
    phdr.p_vaddr = entry->start_addr;
    phdr.p_paddr = 0;
    phdr.p_filesz = entry->end_addr - entry->start_addr;
    phdr.p_memsz = phdr.p_filesz;

    if (strchr(entry->perms, 'r') && strcmp(entry->pathname, "[vvar]")) {
        phdr.p_flags |= PF_R;
    }
    if (strchr(entry->perms, 'w')) {
        phdr.p_flags |= PF_W;
    }
    if (strchr(entry->perms, 'x')) {
        phdr.p_flags |= PF_X;
    }

    phdr.p_align = get_pagesize();
    phdr.p_offset = data_offset;

    return phdr;
}

static Elf64_Phdr create_program_header_ptnote(size_t note_sz) {
    Elf64_Phdr phdr;
    memset(&phdr, 0, sizeof(Elf64_Phdr));

    phdr.p_type = PT_NOTE;
    phdr.p_vaddr = 0;
    phdr.p_paddr = 0;
    phdr.p_filesz = note_sz;
    phdr.p_memsz = 0;
    phdr.p_flags = 0;
    phdr.p_align = PT_NOTE_ALIGNMENT;
    phdr.p_offset = data_offset;

    return phdr;
}

static long get_pagesize(void) {
    long pagesize;

    pagesize = sysconf(_SC_PAGESIZE);
    if (pagesize < 0) {
        return PAGE_SIZE_DEFAULT;
    }

    return pagesize;
}
