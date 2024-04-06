#define _GNU_SOURCE         /* See feature_test_macros(7) */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <link.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/mman.h>
#include <linux/limits.h>


#define MAXENV_SIZE 2097152
#define SINGLE_ENV_SIZE 8192

#define OPT_MODE_ONLY_THIS_ONE "only_this_one"
#define OPT_MODE_REBUILD_ENVIRON "rebuild_environ"

/*
libc_start_addr
find start address of libc by a pid

parameters
addr: address ref (optional)
__mapname: pathname ref (optional)
pid: process id (required)

ret
0 - success
1 - libc not found
2 - /proc/<pid>/maps not found
*/
int
get_libc_base_addr(uint64_t *addr, char __mapname[PATH_MAX], pid_t pid)
{
    char maps_path[32];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);

    FILE *fp = fopen(maps_path, "r");
    if (fp == NULL)
    {
        return 2;
    }

    char *line = NULL;
    size_t len = 0;
    ssize_t read;
    while ( (read = getline(&line, &len, fp)) != -1 )
    {
        // remove trailing newline after getline()
        if (line[read - 1] == '\n')
        {
            line[read - 1] = '\0';
        }

        // scan each line of "maps"
        char perms[32];
        unsigned long start, end;
		unsigned long long file_offset, inode;
		unsigned dev_major, dev_minor;
        char mapname[PATH_MAX];
        sscanf(line, "%lx-%lx %31s %llx %x:%x %llu %s", &start,
		       &end, perms, &file_offset, &dev_major, &dev_minor, &inode, mapname);

        // retrun until libc- matches the file path
        if ( strstr(mapname, "libc-") )
        {
            if ( addr != NULL )
            {
                *addr = start;
            }

            if ( __mapname != NULL )
            {
                memcpy(__mapname, mapname, PATH_MAX);
                __mapname = mapname;
            }

            return 0;
        }
    }
    return 1;
}

struct phdr_result
{
    char *target_path;
    char *target_sym_name;

    ElfW(Addr) st_value;
};

static int
proc_phdr( struct dl_phdr_info *info, size_t info_size, void *data)
{
    struct phdr_result *pr = (struct phdr_result *)data;
    if ( pr->target_path == NULL || pr->target_sym_name == NULL )
        return 1;

    char *dlpi_name = canonicalize_file_name(info->dlpi_name);
    if ( dlpi_name == NULL )
        return 0;

    if ( strcmp(dlpi_name, pr->target_path) )
        return 0;

    /* ElfW is a macro that creates proper typenames for the used system architecture
     * (e.g. on a 32 bit system, ElfW(Dyn*) becomes "Elf32_Dyn*") */
    ElfW(Dyn*) dyn;
    ElfW(Sym*) sym;
    ElfW(Word*) hash;

    char* strtab = 0;
    char* sym_name = 0;
    ElfW(Word) sym_cnt = 0;

    /* Iterate over all headers of the current shared lib
     * (first call is for the executable itself) */
    for (size_t header_index = 0; header_index < info->dlpi_phnum; header_index++)
    {

        /* Further processing is only needed if the dynamic section is reached */
        if (info->dlpi_phdr[header_index].p_type == PT_DYNAMIC)
        {
            /* Get a pointer to the first entry of the dynamic section.
             * It's address is the shared lib's address + the virtual address */
            dyn = (ElfW(Dyn)*)(info->dlpi_addr + info->dlpi_phdr[header_index].p_vaddr);

            /* Iterate over all entries of the dynamic section until the
             * end of the symbol table is reached. This is indicated by
             * an entry with d_tag == DT_NULL.
             *
             * Only the following entries need to be processed to find the
             * symbol names:
             *  - DT_HASH   -> second word of the hash is the number of symbols
             *  - DT_STRTAB -> pointer to the beginning of a string table that
             *                 contains the symbol names
             *  - DT_SYMTAB -> pointer to the beginning of the symbols table
             */
            while(dyn->d_tag != DT_NULL)
            {
                if (dyn->d_tag == DT_HASH)
                {
                    /* Get a pointer to the hash */
                    hash = (ElfW(Word*))dyn->d_un.d_ptr;

                    /* The 2nd word is the number of symbols */
                    sym_cnt = hash[1];

                }
                else if (dyn->d_tag == DT_STRTAB)
                {
                    /* Get the pointer to the string table */
                    strtab = (char*)dyn->d_un.d_ptr;
                }
                else if (dyn->d_tag == DT_SYMTAB)
                {
                    /* Get the pointer to the first entry of the symbol table */
                    sym = (ElfW(Sym*))dyn->d_un.d_ptr;

                    ElfW(Xword) leiji = 0;
                    leiji = 0;
                    /* Iterate over the symbol table */
                    for (ElfW(Word) sym_index = 0; sym_index < sym_cnt; sym_index++)
                    {
                        /* get the name of the i-th symbol.
                         * This is located at the address of st_name
                         * relative to the beginning of the string table. */
                        sym_name = &strtab[sym[sym_index].st_name];

                        if (strcmp(sym_name, pr->target_sym_name))
                            continue;

                        // found sym_name
                        pr->st_value = sym[sym_index].st_value;

                        // abort dl_iterate_phdr
                        return 1;
                    }
                }

                /* move pointer to the next entry */
                dyn++;
            }
        }
    }

    return 0;
}

/*
 * find_st_value_by_symname
 * return 0 if not found
 */
ElfW(Addr)
find_st_value_by_symname(char *target_path, char *sym_name)
{
    struct phdr_result pr = {
        .target_path = canonicalize_file_name(target_path),
        .target_sym_name = sym_name,
        .st_value = 0,
    };

    // iterate over all sym in a lib path
    dl_iterate_phdr(proc_phdr, &pr);

    return pr.st_value;
}

int peek_text(pid_t pid, void *where, void *old_text, size_t len) {
    if (len % sizeof(void *) != 0) {
        printf("invalid len, not a multiple of %zd\n", sizeof(void *));
        return -1;
    }

    for (size_t copied = 0; copied < len; copied += sizeof(long)) {
        if (old_text != NULL) {
            errno = 0;
            long peek_data = ptrace(PTRACE_PEEKTEXT, pid, where + copied, NULL);
            if (peek_data == -1 && errno) {
                perror("PTRACE_PEEKTEXT");
                return -1;
            }
            memmove(old_text + copied, &peek_data, sizeof(peek_data));
        }
    }
    return 0;
}

int poke_text(pid_t pid, void *where, void *new_text, void *old_text,
              size_t len) {
    if (len % sizeof(void *) != 0) {
        printf("invalid len, not a multiple of %zd\n", sizeof(void *));
        return -1;
    }

    long poke_data;
    for (size_t copied = 0; copied < len; copied += sizeof(poke_data)) {
        memmove(&poke_data, new_text + copied, sizeof(poke_data));
        if (old_text != NULL) {
            errno = 0;
            long peek_data = ptrace(PTRACE_PEEKTEXT, pid, where + copied, NULL);
            if (peek_data == -1 && errno) {
                perror("PTRACE_PEEKTEXT");
                return -1;
            }
            memmove(old_text + copied, &peek_data, sizeof(peek_data));
        }
        if (ptrace(PTRACE_POKETEXT, pid, where + copied, (void *)poke_data) < 0) {
            perror("PTRACE_POKETEXT");
            return -1;
        }
    }
    return 0;
}

int do_wait(const char *name) {
    int status;
    if (wait(&status) == -1) {
        perror("wait");
        return -1;
    }
    if (WIFSTOPPED(status)) {
        if (WSTOPSIG(status) == SIGTRAP) {
            return 0;
        }
        printf("%s unexpectedly got status %s\n", name, strsignal(status));
        return -1;
    }
    printf("%s got unexpected status %d\n", name, status);
    return -1;
}

int singlestep(pid_t pid) {
    if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL)) {
        perror("PTRACE_SINGLESTEP");
        return -1;
    }
    return do_wait("PTRACE_SINGLESTEP");
}

/* parse '<name>=<value>'
 * retrun
 * 0 success
 * 1 '=' not exists
 * 2 empty name
 */
int
parse_env_str(char* env_str, char name[SINGLE_ENV_SIZE], char value[SINGLE_ENV_SIZE])
{
    memset(name, 0, SINGLE_ENV_SIZE);
    memset(value, 0, SINGLE_ENV_SIZE);

    char *val = strchr(env_str, '=');
    if (val == NULL)
    {
        // '=' not exist
        return 1;
    }
    if (val == env_str)
    {
        // empty name
        return 2;
    }

    strncpy(value, val + 1, strlen(val) - 1);
    strncpy(name, env_str, val - env_str);
    return 0;
}

void ulltoarray(uint64_t value, uint8_t array[8]) {
    for (int i = 0; i < 8; i++) {
        array[i] = (uint8_t)(value & 0xFF);
        value >>= 8;
    }
}

uint64_t arraytoull_little_endian(const uint8_t *array) {
    uint64_t value = 0;
    for (int i = 0; i < 8; i++) {
        value |= (uint64_t)array[i] << (i * 8);
    }
    return value;
}

/*
 * peek_environ 找到 match 名称的 env
 * return
 * 0 success
 * 1 not found
 */
int
peek_environ(const pid_t pid, char *env_name, void *__environ_addr, char ret_env_str[SINGLE_ENV_SIZE], uint64_t *ret_env_addr, uint64_t *ret_env_ptr_addr)
{
    uint8_t text[8]; // 这个是指向第一个字符串的地址
    peek_text(pid, __environ_addr, (void *)text, 8);
    int ret = 1;

    for (uint64_t star_addr = *(long *)text; ; star_addr += sizeof(long))
    {
        uint8_t text2[8]; // 这个是指向第一个字符的地址
        peek_text(pid, (void *)star_addr, (void *)text2, 8);

        if (arraytoull_little_endian(text2) == 0)
        {
            break;
        }

        void *addr3 = (void *) (*(long *)text2);

        char env_str_buf[MAXENV_SIZE];
        bool end_of_str = false;
        int round = 0;
        for (round = 0; !end_of_str; round++)
        {
            uint8_t text3[8]; // real str
            peek_text(pid, addr3, (void *)text3, sizeof(text3));
            for (size_t i = 0; i < sizeof(text3); i++)
            {
                env_str_buf[round * 8 + i] = text3[i];
                if (text3[i] == '\0')
                {
                    end_of_str = true;
                    break;
                }
                addr3++;
            }
        }

        char tmp_env_name[SINGLE_ENV_SIZE];
        char tmp_env_value[SINGLE_ENV_SIZE];
        if (parse_env_str(env_str_buf, tmp_env_name, tmp_env_value))
        {
            continue;
        }

        if (!strcmp(tmp_env_name, env_name))
        {
            memmove(ret_env_str, env_str_buf, SINGLE_ENV_SIZE);
            *ret_env_addr = (uint64_t)addr3 - strlen(env_str_buf);
            *ret_env_ptr_addr = star_addr;
            ret = 0;
            break;
        }
    }

    return ret;
}

int
ceiln(const int x, const int by)
{
    if (x % by)
        return x + (by - x % by);
    return x;
}

int
in_place_poke(pid_t pid, char *new_env_str, uint64_t target_env_addr)
{
    printf("%-32s : %s\n", "modify mode", "in-place poke");

    size_t poke_size = ceiln(strlen(new_env_str), sizeof(long));
    printf("%-32s : %zd\n", "poke size is", poke_size);

    // 在 peek 后的基础上改，确保原来的内存不改坏
    char word[poke_size];
    peek_text(pid, (void *)target_env_addr, word, poke_size);

    // mutate
    strncpy(word, new_env_str, strlen(new_env_str));

    // print word
    printf("%-32s : ", "poke word");
    for (int i = 0; i < poke_size; i++)
    {
        putchar(word[i]);
    }
    putchar('\n');

    // poke
    if ( poke_text(pid, (void *)target_env_addr, word, NULL, poke_size) )
    {
        perror("POKE_TEXT");
        return 1;
    }

    return 0;
}

void
pprint_environ(char orig_environ_char[MAXENV_SIZE])
{
    bool nul_char = false;
    for (int i = 0; i < MAXENV_SIZE; i++)
    {
        if (orig_environ_char[i] == '\0')
        {
            if (nul_char)
            {
                break;
            }
            else
            {
                nul_char = true;
                putchar('\n');
            }
            continue;
        }
        nul_char = false;

        putchar(orig_environ_char[i]);
    }
}

int
mmap_poke_only_this_one(pid_t pid, char *new_env_str, uint64_t orig_env_addr, uint64_t env_ptr_addr)
{
    printf("%-32s : %s\n", "modify mode", "mmap poke only_this_one");

    // save the register state of the remote process
    struct user_regs_struct oldregs;
    if (ptrace(PTRACE_GETREGS, pid, NULL, &oldregs))
    {
        perror("PTRACE_GETREGS");
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return -1;
    }
    void *rip = (void *)oldregs.rip;
    printf("%-32s : 0x%016lx\n", "origin RIP reg", rip);

    // mmap size
    size_t mmap_size = ceiln(strlen(new_env_str) + 1, sizeof(long));
    printf("%-32s : %d\n", "mmap size is", mmap_size);

    // prepare mmap regs
    struct user_regs_struct newregs;
    memmove(&newregs, &oldregs, sizeof(newregs));
    newregs.rax = SYS_mmap;
    newregs.rdi = 0;                                  // addr
    newregs.rsi = mmap_size;                          // length
    newregs.rdx = PROT_READ | PROT_WRITE | PROT_EXEC; // prot
    newregs.r10 = MAP_PRIVATE | MAP_ANONYMOUS;        // flags
    newregs.r8 = -1;                                  // fd
    newregs.r9 = 0;                                   // offset

    uint8_t old_word[8];
    uint8_t new_word[8];
    new_word[0] = 0x0f; // SYSCALL
    new_word[1] = 0x05; // SYSCALL
    new_word[2] = 0xff; // JMP %rax
    new_word[3] = 0xe0; // JMP %rax

    // insert the SYSCALL instruction into the process, and save the old word
    if ( poke_text(pid, rip, new_word, old_word, 8) )
    {
        return 1;
    }
    printf("%-32s : ", "origin text code is");
    for ( int i = 0; i <= 7; ++i )
        printf("0x%02x ", old_word[i]);
    putchar('\n');

    // set the new registers with our syscall arguments
    if ( ptrace(PTRACE_SETREGS, pid, NULL, &newregs) )
    {
        perror("PTRACE_SETREGS");
        return 1;
    }

    // invoke mmap(2)
    if ( singlestep(pid) )
    {
        // failed
        return 1;
    }

    // read the new register state, so we can see where the mmap went
    if ( ptrace(PTRACE_GETREGS, pid, NULL, &newregs) )
    {
        perror("PTRACE_GETREGS");
        return -1;
    }

    // this is the address of the memory we allocated
    void *mmap_memory = (void *)newregs.rax;
    if (mmap_memory == (void *)-1)
    {
        printf("failed to mmap\n");
        return 1;
    }
    printf("%-32s : 0x%016lx\n", "mmap memory addr", mmap_memory);

    // prepare new_env_array
    char new_env_array[mmap_size];
    strcpy(new_env_array, new_env_str);

    // poke text
    if ( poke_text(pid, (void *)mmap_memory, new_env_array, NULL, mmap_size) )
    {
        perror("POKE_TEXT");
        return 1;
    }

    // set *__environ addr
    ulltoarray((uint64_t)mmap_memory, new_word);
    if ( poke_text(pid, (void *)env_ptr_addr, new_word, NULL, sizeof(mmap_memory)) )
    {
        perror("POKE_TEXT *__environ");
        return 1;
    }

    // ! REASON tha munmap(2) not performed here:
    // Doc: The address addr must be a multiple of the page size (but length need not be).

    // 恢复寄存器状态
    puts("restoring origin text data");
    poke_text(pid, rip, old_word, NULL, sizeof(old_word));

    puts("restoring origin registers");
    if ( ptrace(PTRACE_SETREGS, pid, NULL, &oldregs) )
    {
        perror("PTRACE_SETREGS");
        return 1;
    }
}

int
fetch_environ(pid_t pid, void *__environ_addr, char total_environ_chars[MAXENV_SIZE], uint64_t *environ_char_start_addr, size_t *total_length, uint64_t *env_ptr_addr, size_t *last_word_index)
{
    uint8_t text[8]; // 这个是指向第一个字符串的地址
    peek_text(pid, __environ_addr, (void *)text, 8);

    void *addr2 = (void *) (*(long *)text);
    printf("%-32s : 0x%016lx\n", "*__environ addr", addr2);
    *env_ptr_addr = (uint64_t) addr2;

    uint8_t text2[8]; // 这个是指向第一个字符的地址
    peek_text(pid, addr2, (void *)text2, 8);

    void *addr3 = (void *) (*(long *)text2);
    if (environ_char_start_addr != NULL)
    {
        *environ_char_start_addr = (uint64_t)addr3;
    }
    printf("%-32s : 0x%016lx\n", "**__environ addr", addr3);

    size_t all_index = 0;
    size_t prev_char = '\0';

    int endflag = 0;
    for (;;)
    {
        uint8_t text3[8];
        peek_text(pid, addr3, (void *)text3, sizeof(text3));
        for (size_t i = 0; i < sizeof(text3); i++)
        {
            total_environ_chars[all_index] = text3[i];
            all_index++;

            if (text3[i] == '\0')
            {
                if (endflag == 1)
                {
                    *total_length = all_index;
                    return 0;
                }
                endflag = 1;
                prev_char = text3[i];
                continue;
            }
            else
            {
                if (prev_char == '\0')
                {
                    *last_word_index = all_index - 1;
                }
                endflag = 0;
                prev_char = text3[i];
            }
        }
        addr3 += sizeof(text3);
    }
}

int
do_prctl_set_mm(const pid_t pid, const void *rip, struct user_regs_struct *newregs, const uint64_t arg2, const uint64_t arg3)
{
    newregs->rax = (long)rip;
    if ( ptrace(PTRACE_SETREGS, pid, NULL, newregs) )
    {
        perror("PTRACE_SETREGS");
        return 1;
    }
    if ( singlestep(pid) ) {
        return 1;
    }

    if ( ptrace(PTRACE_GETREGS, pid, NULL, newregs) )
    {
        perror("PTRACE_GETREGS");
        return -1;
    }

    newregs->rax = SYS_prctl;
    newregs->rdi = PR_SET_MM;
    newregs->rsi = arg2;
    newregs->rdx = arg3;
    newregs->r10 = 0;
    newregs->r8 = 0;
    if ( ptrace(PTRACE_SETREGS, pid, NULL, newregs) )
    {
        perror("PTRACE_SETREGS");
        return 1;
    }

    // making call to prctl
    if ( singlestep(pid) ) {
        // failed
        return 1;
    }
    if ( ptrace(PTRACE_GETREGS, pid, NULL, newregs) ) {
        perror("PTRACE_GETREGS");
        return -1;
    }
    return 0;
}

int
mmap_poke_rebuild_environ(pid_t pid,
        char *orig_env_str,
        char *new_env_str,
        void *__environ_addr,
        uint64_t orig_env_addr)
{
    printf("%-32s : %s\n", "modify mode", "mmap poke rebuild_environ");

    bool create_new_env = orig_env_addr == 0;

    char total_environ_chars[MAXENV_SIZE];
    uint64_t environ_char_start_addr;
    size_t total_length;
    uint64_t env_ptr_addr;
    size_t last_word_index;

    if (fetch_environ(pid, __environ_addr, total_environ_chars, &environ_char_start_addr, &total_length, &env_ptr_addr, &last_word_index))
    {
        perror("fetch_environ");
        return 1;
    }

    printf("%-32s : %d\n", "offset", orig_env_addr - environ_char_start_addr);
    printf("%-32s : %zd\n", "orig __environ length", total_length);
    printf("%-32s : %zd\n", "orig last_word_index", last_word_index);

    // prepare new array
    char new_environ_char[MAXENV_SIZE];
    if (create_new_env)
    {
        strncpy(new_environ_char, new_env_str, strlen(new_env_str) + 1);
        memcpy(new_environ_char + strlen(new_env_str) + 1, total_environ_chars, total_length + 1);
    }
    else
    {
        for (size_t i = 0; i < orig_env_addr - environ_char_start_addr; i++)
        {
            new_environ_char[i] = total_environ_chars[i];
        }
        for (size_t i = 0; i < strlen(new_env_str); i++)
        {
            new_environ_char[orig_env_addr - environ_char_start_addr + i] = new_env_str[i];
        }
        for (size_t i = 0; i < total_length - (orig_env_addr - environ_char_start_addr) + strlen(new_env_str); i++)
        {
            new_environ_char[orig_env_addr - environ_char_start_addr + strlen(new_env_str) + i] = total_environ_chars[orig_env_addr - environ_char_start_addr + strlen(orig_env_str) + i];
        }
    }
    // pprint_environ(new_environ_char);

    // save the register state of the remote process
    struct user_regs_struct oldregs;
    if (ptrace(PTRACE_GETREGS, pid, NULL, &oldregs))
    {
        perror("PTRACE_GETREGS");
        return -1;
    }
    void *rip = (void *)oldregs.rip;
    printf("%-32s : 0x%016lx\n", "origin RIP reg", rip);

    // mmap size
    size_t new_environ_size = create_new_env ? total_length + strlen(new_env_str) + 1 : total_length - strlen(orig_env_str) + strlen(new_env_str);
    size_t mmap_size = ceiln(new_environ_size, sizeof(long));
    printf("%-32s : %d\n", "mmap size is", mmap_size);

    // prepare mmap regs
    struct user_regs_struct newregs;
    memmove(&newregs, &oldregs, sizeof(newregs));
    newregs.rax = SYS_mmap;
    newregs.rdi = 0;                                  // addr
    newregs.rsi = mmap_size;                          // length
    newregs.rdx = PROT_READ | PROT_WRITE | PROT_EXEC; // prot
    newregs.r10 = MAP_PRIVATE | MAP_ANONYMOUS;        // flags
    newregs.r8 = -1;                                  // fd
    newregs.r9 = 0;                                   // offset

    uint8_t old_word[8];
    uint8_t new_word[8];
    new_word[0] = 0x0f; // SYSCALL
    new_word[1] = 0x05; // SYSCALL
    new_word[2] = 0xff; // JMP %rax
    new_word[3] = 0xe0; // JMP %rax

    // insert the SYSCALL instruction into the process, and save the old word
    if ( poke_text(pid, rip, new_word, old_word, 8) )
    {
        return 1;
    }
    printf("%-32s : ", "origin text code is");
    for ( int i = 0; i <= 7; ++i )
        printf("0x%02x ", old_word[i]);
    putchar('\n');

    // set the new registers with our syscall arguments
    if ( ptrace(PTRACE_SETREGS, pid, NULL, &newregs) )
    {
        perror("PTRACE_SETREGS");
        return 1;
    }

    // invoke mmap(2)
    if ( singlestep(pid) ) {
        // failed
        return 1;
    }

    // read the new register state, so we can see where the mmap went
    if ( ptrace(PTRACE_GETREGS, pid, NULL, &newregs) )
    {
        perror("PTRACE_GETREGS");
        return -1;
    }

    // this is the address of the memory we allocated
    void *mmap_memory = (void *)newregs.rax;
    if (mmap_memory == (void *)-1)
    {
        printf("failed to mmap\n");
        return 1;
    }
    printf("%-32s : 0x%016lx\n", "mmap memory addr", mmap_memory);

    // poke text
    if ( poke_text(pid, (void *)mmap_memory, new_environ_char, NULL, mmap_size) )
    {
        perror("POKE_TEXT");
        return 1;
    }

    // 循环修改 __environ* 的所有目标地址为新的地址
    uint64_t addr = env_ptr_addr;
    uint64_t new_addr = (uint64_t)mmap_memory;

    bool nul_char = true;
    for (int i = 0; i < MAXENV_SIZE; i++)
    {
        if (new_environ_char[i] == '\0')
        {
            if (nul_char)
            {
                break;
            }
            else
            {
                nul_char = true;
            }
            continue;
        }
        if (nul_char)
        {
            // start of new env string
            uint8_t new_word[8];
            ulltoarray(new_addr + i, new_word);
            if (poke_text(pid, (void *)addr, new_word, NULL, sizeof(long)))
            {
                perror("POKE_TEXT 1");
                return 1;
            }
            addr += sizeof(long);
        }
        nul_char = false;
    }

    // prctl(PR_SET_MM_ENV_START, new_addr) to reset env start block
    if ( do_prctl_set_mm(pid, rip, &newregs, PR_SET_MM_ENV_START, new_addr) )
    {
        perror("do_prctl_set_mm PR_SET_MM_ENV_START");
        return 1;
    }
    printf("%-32s : %ld\n", "prctl start syscall retrun", newregs.rax);

    // prctl(PR_SET_MM_ENV_END, new_addr+offset) to reset env end block
    if ( do_prctl_set_mm(pid, rip, &newregs, PR_SET_MM_ENV_END, new_addr + new_environ_size - (total_length - last_word_index)) )
    {
        perror("do_prctl_set_mm PR_SET_MM_ENV_END");
        return 1;
    }
    printf("%-32s : %ld\n", "prctl end syscall retrun", newregs.rax);

    // ! REASON tha munmap(2) not performed here:
    // Doc: The address addr must be a multiple of the page size (but length need not be).

    // 恢复寄存器状态
    puts("restoring origin text data");
    poke_text(pid, rip, old_word, NULL, sizeof(old_word));

    puts("restoring origin registers");
    if ( ptrace(PTRACE_SETREGS, pid, NULL, &oldregs) )
    {
        perror("PTRACE_SETREGS");
        return 1;
    }
}

int
penv(pid_t pid, char *opt_env_str, char *mode)
{
    char new_env_name[SINGLE_ENV_SIZE];
    char new_env_value[SINGLE_ENV_SIZE];
    if (parse_env_str(opt_env_str, new_env_name, new_env_value))
    {
        fprintf(stderr, "parse env_str failed\n");
        return 1;
    }
    printf("%-32s : %s\n", "new env name", new_env_name);
    printf("%-32s : %s\n", "new env value", new_env_value);

    // attach to the process
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL))
    {
        perror("PTRACE_ATTACH");
        return 1;
    }

    // wait for the process to actually stop
    if ( waitpid(pid, NULL, WSTOPPED) == -1 )
    {
        perror("waitpid");
        return 1;
    }

    // get libc base addr and path
    uint64_t libc_addr = 0;
    char libc_path[PATH_MAX];
    if (get_libc_base_addr(&libc_addr, libc_path, pid) != 0)
    {
        perror("get_libc_base_addr");
        return 1;
    }
    printf("%-32s : 0x%016lx\n", "libc addr is", libc_addr);
    printf("%-32s : %s\n", "libc path is", libc_path);

    // get __environ symbol offset
    ElfW(Addr) __environ_offset = find_st_value_by_symname(libc_path, "__environ");
    printf("%-32s : 0x%016lx\n", "__environ symbol offset", __environ_offset);
    ElfW(Addr) __environ_addr = libc_addr + __environ_offset;
    printf("%-32s : 0x%016lx\n", "__environ addr", __environ_addr);

    // peek envirion
    char orig_env_str[SINGLE_ENV_SIZE];
    uint64_t orig_env_addr = 0;
    uint64_t orig_env_ptr_addr = 0;
    int create_new_env = peek_environ(pid, new_env_name, (void *)__environ_addr, orig_env_str, &orig_env_addr, &orig_env_ptr_addr);

    printf("%-32s : 0x%016lx\n", "env ptr addr", orig_env_ptr_addr);
    printf("%-32s : 0x%016lx\n", "env addr", orig_env_addr);
    printf("%-32s : %s\n", "orig env str", orig_env_str);
    printf("%-32s : %d\n", "create_new_env", create_new_env);

    // main process mutate environ
    if (create_new_env)
    {
        // env not found, should create new
        if (mode != NULL && strcmp(mode, OPT_MODE_REBUILD_ENVIRON))
        {
            fprintf(stderr, "create new env, mode cannot be %s\n", mode);
            goto fail;
        }
        if (mmap_poke_rebuild_environ(pid, orig_env_str, opt_env_str, (void *)__environ_addr, orig_env_addr))
        {
            goto fail;
        }
    }
    else
    {
        if (mode != NULL)
        {
            if (!strcmp(mode, OPT_MODE_ONLY_THIS_ONE))
            {
                if (mmap_poke_only_this_one(pid, opt_env_str, orig_env_addr, orig_env_ptr_addr))
                {
                    goto fail;
                }
            }
            else if (!strcmp(mode, OPT_MODE_REBUILD_ENVIRON))
            {
                if (mmap_poke_rebuild_environ(pid, orig_env_str, opt_env_str, (void *)__environ_addr, orig_env_addr))
                {
                    goto fail;
                }
            }
        }
        else
        {
            if (strlen(orig_env_str) == strlen(opt_env_str))
            {
                if (in_place_poke(pid, opt_env_str, orig_env_addr))
                {
                    goto fail;
                }
            }
            else
            {
                if (mmap_poke_only_this_one(pid, opt_env_str, orig_env_addr, orig_env_ptr_addr))
                {
                    goto fail;
                }
            }
        }
    }

    // detach pid
    if ( ptrace(PTRACE_DETACH, pid, NULL, NULL) )
    {
        perror("PTRACE_DETACH");
        goto fail;
    }

    return 0;

fail:
    // detach
    printf("Detaching from process...\n");
    ptrace(PTRACE_DETACH, pid, NULL, NULL);

    return 1;
}

void
print_help()
{
    printf(
        "%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n",
        "Usage: penv [options] - put env on another process",
        "Options:",
        "    -h              print this help",
        "    -p <pid>        pid to modify env",
        "    -e <env_str>    env str in format: <name>=<value>",
        "    -m <mode>       set mode, only_this_one|rebuild_environ",
        "                      - only_this_one: just like putenv() or setenv()",
        "                      - rebuild_environ: rebuild the whole environ and reset the",
        "                        /proc/<pid>/environ memory address",
        "                    default: in_place for equal value length, otherwise only_this_one"
    );
}

int
main(int argc, char *argv[])
{
    char c;
    pid_t pid = 0;
    char *new_env_str;
    char *opt_mode = NULL;

    while ( (c = getopt(argc, argv, "hp:e:m:")) != -1 )
    {
        switch (c)
        {
        case 'h':
            print_help();
            return 0;
        case 'p':
            pid = (pid_t) atol(optarg);
            break;
        case 'e':
            new_env_str = optarg;
            break;
        case 'm':
            opt_mode = optarg;
            break;
        default:
            print_help();
            return 1;
        }
    }

    // validation
    if (pid <= 0)
    {
        fprintf(stderr, "invalid pid: %zd\n", pid);
        return 1;
    }
    if (opt_mode != NULL && strcmp(opt_mode, OPT_MODE_ONLY_THIS_ONE) && strcmp(opt_mode, OPT_MODE_REBUILD_ENVIRON))
    {
        fprintf(stderr, "invalid mode: %s\n", opt_mode);
        return 1;
    }

    // invoke
    return penv(pid, new_env_str, opt_mode);
}
