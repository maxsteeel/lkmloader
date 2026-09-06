#include <stdio.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <elf.h>
#include <errno.h>

#ifndef PATH_MAX
# define PATH_MAX 4096
#endif
#ifndef MFD_CLOEXEC
# define MFD_CLOEXEC 0x0001U
#endif
# define HASH_SIZE 1024

struct undef_sym {
    Elf64_Sym *sym;
    const char *name;
    unsigned long hash;
    int len;
    int next;
};

static int read_file(const char *path, unsigned char **buf_out, size_t *sz_out, int *mfd_out) {
    int fd, mfd; struct stat st; unsigned char *buf; size_t total = 0; ssize_t rn;
    if ((fd = open(path, O_RDONLY)) < 0 || fstat(fd, &st) < 0) return -1;
    if ((mfd = syscall(SYS_memfd_create, "ko", MFD_CLOEXEC)) < 0) { close(fd); return -1; }
    if (ftruncate(mfd, st.st_size + 4096) < 0) { close(mfd); close(fd); return -1; }
    if ((buf = mmap(NULL, st.st_size + 4096, PROT_READ | PROT_WRITE, MAP_SHARED, mfd, 0)) == MAP_FAILED) { close(mfd); close(fd); return -1; }
    while (total < (size_t)st.st_size) {
        rn = read(fd, buf + total, st.st_size - total);
        if (rn > 0) total += rn;
        else if (rn < 0 && errno == EINTR) continue;
        else { munmap(buf, st.st_size + 4096); close(mfd); close(fd); return -1; }
    }
    close(fd);
    *buf_out = buf; *sz_out = st.st_size; *mfd_out = mfd;
    return 0;
}

static void resolve_undef_symbols(unsigned char *buf, size_t mod_sz) {
    Elf64_Ehdr *eh = (Elf64_Ehdr *)buf;
    if (eh->e_shoff + (eh->e_shnum * sizeof(Elf64_Shdr)) > mod_sz) return;
    Elf64_Shdr *sh = (Elf64_Shdr *)(buf + eh->e_shoff);
    Elf64_Sym *syms = NULL;
    char *strtab = NULL;
    int num_syms = 0;

    for (int i = 0; i < eh->e_shnum; i++) {
        if (sh[i].sh_type == SHT_SYMTAB) {
            strtab = (char *)(buf + sh[sh[i].sh_link].sh_offset);
            syms = (Elf64_Sym *)(buf + sh[i].sh_offset);
            num_syms = sh[i].sh_size / sizeof(Elf64_Sym);
            break;
        }
    }
    if (!syms || !strtab) return;

    struct undef_sym *undefs = __builtin_malloc(num_syms * sizeof(struct undef_sym));
    if (!undefs) return;

    int head[HASH_SIZE];
    for (int i = 0; i < HASH_SIZE; i++) head[i] = -1;

    int count = 0;
    for (int i = 0; i < num_syms; i++) {
        if (syms[i].st_shndx == SHN_UNDEF) {
            const char *name = strtab + syms[i].st_name;
            if (!*name) continue;
            unsigned long h = 5381;
            int len = 0;
            for (const char *s = name; *s; s++) { h = ((h << 5) + h) + (unsigned char)*s; len++; }
            undefs[count] = (struct undef_sym){ .sym = &syms[i], .name = name, .hash = h, .len = len, .next = head[h % HASH_SIZE] };
            head[h % HASH_SIZE] = count++;
        }
    }

    if (count > 0) {
        int kptr_fd = open("/proc/sys/kernel/kptr_restrict", O_RDWR);
        char orig_kptr = '0';
        if (kptr_fd >= 0) {
            if (read(kptr_fd, &orig_kptr, 1) == 1 && orig_kptr != '0') {
                lseek(kptr_fd, 0, SEEK_SET);
                write(kptr_fd, "0\n", 2);
            }
        }

        int fd = open("/proc/kallsyms", O_RDONLY);
        if (fd >= 0) {
            size_t cap = 16 * 1024 * 1024;
            char *kbuf = __builtin_malloc(cap + 8);
            if (kbuf) {
                ssize_t n; size_t total = 0;
                while (total < cap - 1) {
                    n = read(fd, kbuf + total, cap - total - 1);
                    if (n > 0) total += n;
                    else if (n < 0 && errno == EINTR) continue;
                    else break;
                }

                char *p = kbuf, *end_buf = kbuf + total;
                int resolved = 0;
                while (p < end_buf) {
                    unsigned long addr = 0;
                    char *ap = p;
                    while (*ap > ' ') {
                        unsigned int c = (unsigned char)*ap++;
                        addr = (addr << 4) | ((c & 0xF) + ((c >> 6) * 9));
                    }

                    if (*ap != ' ') { 
                        while (ap < end_buf && *ap != '\n') ap++;
                        p = ap + 1;
                        continue;
                    }
                    ap += 3;

                    char *name = ap;
                    unsigned long h = 5381;
                    int name_len = 0;
                    while (*ap > ' ') {
                        /* SWAR: ".llvm." = 0x2e6d766c6c2e */
                        if (*ap == '$' || (*(uint64_t *)ap & 0xFFFFFFFFFFFFULL) == 0x2e6d766c6c2eULL) { while (*ap > ' ') ap++; break; }
                        h = ((h << 5) + h) + (unsigned char)*ap++;
                        name_len++;
                    }

                    for (int idx = head[h % HASH_SIZE]; idx != -1; idx = undefs[idx].next) {
                        if (undefs[idx].sym->st_value == 0 && undefs[idx].len == name_len && undefs[idx].hash == h) {
                            int match = 1;
                            for (int i = 0; i < name_len; i++) {
                                if (undefs[idx].name[i] != name[i]) { match = 0; break; }
                            }
                            if (match) {
                                undefs[idx].sym->st_value = addr;
                                undefs[idx].sym->st_shndx = SHN_ABS;
                                resolved++;
                                break;
                            }
                        }
                    }
                    if (resolved == count) break;
                    while (ap < end_buf && *ap != '\n') ap++;
                    p = ap + 1;
                }
                __builtin_free(kbuf);
            }
            close(fd);
        }

        if (kptr_fd >= 0) {
            if (orig_kptr != '0') {
                char restore_buf[2] = {orig_kptr, '\n'};
                lseek(kptr_fd, 0, SEEK_SET);
                write(kptr_fd, restore_buf, 2);
            }
            close(kptr_fd);
        }
    }
    __builtin_free(undefs);
}

static int patch_vermagic(unsigned char *buf, size_t *sz_out, const char *req) {
    Elf64_Ehdr *eh = (Elf64_Ehdr *)buf;
    Elf64_Shdr *sh = (Elf64_Shdr *)(buf + eh->e_shoff), *mod = NULL;
    char *str = (char *)(buf + sh[eh->e_shstrndx].sh_offset);

    for (int i = 0; i < eh->e_shnum; i++) {
        const char *sname = str + sh[i].sh_name;
        /* SWAR: ".modinfo" = 0x6f666e69646f6d2e */
        if (*(uint64_t *)sname == 0x6f666e69646f6d2eULL && sname[8] == '\0') {
            mod = &sh[i]; break;
        }
    }
    if (!mod) return 0;

    size_t align = mod->sh_addralign ? mod->sh_addralign : 1;
    size_t noff = (*sz_out + align - 1) & ~(align - 1);
    unsigned char *new_mod = buf + noff, *old_mod = buf + mod->sh_offset;

    size_t len = 0, pos = 0;
    int rep = 0, req_len = 0;   
    while (req[req_len]) req_len++;

    while (pos < mod->sh_size) {
        unsigned char *entry = old_mod + pos;
        int elen = 0; while (entry[elen]) elen++;
        if (!elen) { pos++; continue; }

        /* SWAR: "vermagic" = 0x636967616d726576 */
        int is_verm = (elen >= 9 && *(uint64_t *)entry == 0x636967616d726576ULL && entry[8] == '=');
        if (is_verm && !rep) {
            *(uint64_t *)(new_mod + len) = 0x636967616d726576ULL;
            new_mod[len + 8] = '='; len += 9;
            for (int k = 0; k < req_len; k++) new_mod[len++] = req[k];
            new_mod[len++] = '\0';
            rep = 1;
        } else {
            for (int k = 0; k <= elen; k++) new_mod[len++] = entry[k];
        }
        pos += elen + 1;
    }

    if (!rep) {
        *(uint64_t *)(new_mod + len) = 0x636967616d726576ULL;
        new_mod[len + 8] = '='; len += 9;
        for (int k = 0; k < req_len; k++) new_mod[len++] = req[k];
        new_mod[len++] = '\0';
    }

    mod->sh_offset = noff;
    mod->sh_size = len;
    *sz_out = noff + len;
    return 1;
}

int main(int argc, char **argv) {
    if (argc < 2) return fprintf(stderr, "Usage: %s <module.ko> [args...]\n", argv[0]), 1;
    unsigned char *mod_buf; size_t mod_sz, p_len = 0; char params[4096] = {0}; int fd, mfd = -1;
    if (read_file(argv[1], &mod_buf, &mod_sz, &mfd)) return perror("Failed reading module"), 1;
    size_t map_sz = mod_sz + 4096;

    /* SWAR: "\x7fELF\x02\x01\x01\x00" (ELF, 64-bit, Little Endian, Version 1) */
    if (*(uint64_t *)mod_buf != 0x00010102464c457fULL)
        return fprintf(stderr, "[-] Invalid or unsupported ELF64 image\n"), 1;

    for (int i = 2; i < argc; i++) {
        char *arg = argv[i];
        while (*arg && p_len < sizeof(params) - 2) params[p_len++] = *arg++;
        params[p_len++] = ' ';
    } 
    params[p_len] = '\0';

    resolve_undef_symbols(mod_buf, mod_sz);
    if ((fd = open("/dev/kmsg", O_RDONLY | O_NONBLOCK)) < 0) fd = open("/kmsg", O_RDONLY | O_NONBLOCK);
    if (fd >= 0) lseek(fd, 0, SEEK_END);
    int retries = 5, last_err = 0;
    long ret;

    while (retries-- > 0) {
        ret = syscall(SYS_init_module, mod_buf, mod_sz, params);
        if (ret < 0 && (errno == ENOSYS || errno == EPERM)) ret = syscall(SYS_finit_module, mfd, params, 0);
        last_err = errno; if (fd < 0) break;
        usleep(50000);

        char kmsg[8192], req_ver[128] = {0};
        ssize_t n; int mut = 0;
        while ((n = read(fd, kmsg, sizeof(kmsg) - 1)) > 0 || (n < 0 && errno == EINTR)) {
            if (n <= 0) continue;
            kmsg[n] = '\0';
            char *p = kmsg, *end_kmsg = kmsg + n - 15;
            while (p < end_kmsg) {
                /* "version " (8), "magic '" (7) */
                if (*(uint64_t *)p == 0x206e6f6973726576ULL && (*(uint64_t *)(p + 8) & 0xFFFFFFFFFFFFFFULL) == 0x2720636967616dULL) {
                    char *sp = p + 15, *end_sp = kmsg + n - 13;
                    while (sp < end_sp) {
                        /* "' should " (8), " be " (4) */
                        if (*(uint64_t *)sp == 0x646c756f68732027ULL && *(uint32_t *)(sp + 8) == 0x20656220 && sp[12] == '\'') {
                            char *ep = sp + 13; int i = 0;
                            while (*ep && *ep != '\'' && i < 127) req_ver[i++] = *ep++;
                            req_ver[i] = '\0';
                            goto apply_patch;
                        }
                        sp++;
                    }
                }
                p++;
            }
        }

apply_patch:
        if (req_ver[0] && patch_vermagic(mod_buf, &mod_sz, req_ver))
            printf("[!] Vermagic patched to: '%s'\n", req_ver), mut = 1;

        if (!mut) break;
    }

    if (fd >= 0) close(fd);
    close(mfd);
    munmap(mod_buf, map_sz);

    if (!ret) return printf("[+] Loaded: %s\n", argv[1]), 0;
    errno = last_err; return perror("[-] init_module failed"), 1;
}
