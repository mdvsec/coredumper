#include "elf_utils.h"
#include <stddef.h>
#include <elf.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#define PAGE_SIZE_DEFAULT 4096

static Elf64_Phdr create_program_header(const maps_entry_t*);
static long get_pagesize(void);

int write_elf_header(const int fd, const size_t phdr_count) {
    Elf64_Ehdr elf_hdr;
    memset(&elf_hdr, 0, sizeof(elf_hdr));

    // TBD: This code should be platform-independent
    elf_hdr.e_ident[EI_MAG0] = ELFMAG0;
    elf_hdr.e_ident[EI_MAG1] = ELFMAG1;
    elf_hdr.e_ident[EI_MAG2] = ELFMAG2;
    elf_hdr.e_ident[EI_MAG3] = ELFMAG3;

    elf_hdr.e_ident[EI_CLASS] = ELFCLASS64;
    elf_hdr.e_ident[EI_DATA] = ELFDATA2LSB;
    elf_hdr.e_ident[EI_VERSION] = EV_CURRENT;
    elf_hdr.e_ident[EI_OSABI] = ELFOSABI_SYSV;
    elf_hdr.e_ident[EI_ABIVERSION] = 0;

    elf_hdr.e_type = ET_CORE;
    elf_hdr.e_machine = EM_X86_64;
    elf_hdr.e_version = EV_CURRENT;
    elf_hdr.e_phoff = sizeof(Elf64_Ehdr); 
    elf_hdr.e_ehsize = sizeof(Elf64_Ehdr);
    elf_hdr.e_phentsize = sizeof(Elf64_Phdr);
    elf_hdr.e_phnum = phdr_count;

    // TBD: Add a handler for write() to do safe writes 
    if (write(fd, &elf_hdr, sizeof(elf_hdr)) < 0) {
        return -1;
    }

    return 0;
}

int write_program_header_table(const int fd, const maps_entry_t* head, const size_t phdr_count) {
    size_t table_sz = sizeof(Elf64_Phdr) * phdr_count;
    Elf64_Phdr* phdr_table = malloc(table_sz);
    if (!phdr_table) {
        return -1;
    }

    const maps_entry_t* entry = head;
    size_t index = 0;
    while (entry) {
        phdr_table[index++] = create_program_header(entry);
        entry = entry->next;
    }

    if (write(fd, phdr_table, table_sz) != table_sz) {
        free(phdr_table);
        return -1;
    }

    free(phdr_table);

    return 0;
}

static Elf64_Phdr create_program_header(const maps_entry_t* entry) {
    Elf64_Phdr phdr;
    memset(&phdr, 0, sizeof(Elf64_Phdr));

    phdr.p_type = PT_LOAD;
    phdr.p_offset = entry->offset;
    phdr.p_vaddr = entry->start_addr;
    phdr.p_paddr = 0;
    phdr.p_filesz = entry->end_addr - entry->start_addr;
    phdr.p_memsz = phdr.p_filesz;

    if (strchr(entry->perms, 'r')) {
        phdr.p_flags |= PF_R;
    }
    if (strchr(entry->perms, 'w')) {
        phdr.p_flags |= PF_W;
    }
    if (strchr(entry->perms, 'x')) {
        phdr.p_flags |= PF_X;
    }

    phdr.p_align = get_pagesize();

    return phdr;
}

static long get_pagesize(void) {
    long pagesize = sysconf(_SC_PAGESIZE);
    if (pagesize < 0) {
        return PAGE_SIZE_DEFAULT;
    }

    return pagesize;
}
