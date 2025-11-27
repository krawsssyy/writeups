#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <link.h>
#include <elf.h>
#include <dlfcn.h>

// fnv1a hash func
uint32_t fnv1a(const char *s) {
    uint32_t h = 0x811c9dc5u;
    while (*s) {
        h ^= (uint8_t)*s++;
        h *= 0x01000193u;
    }
    return h;
}

typedef struct {
    uint32_t target_hash;
    void *result;
} resolver_ctx;

// dl_iterate_phdr callback
static int find_symbol(struct dl_phdr_info *info, size_t size, void *data) {
    resolver_ctx *ctx = (resolver_ctx*)data;

    // skip vDSO (virtual dynamic shared lib) 
    if (info->dlpi_name && strncmp(info->dlpi_name, "linux-vdso", 10) == 0)
        return 0;

    const ElfW(Phdr) *phdr = info->dlpi_phdr;
    ElfW(Addr) base = info->dlpi_addr;
    const ElfW(Dyn) *dyn = NULL;

    // find PT_DYNAMIC (.dynamic ELF section)
    for (int i = 0; i < info->dlpi_phnum; i++) {
        if (phdr[i].p_type == PT_DYNAMIC) {
            dyn = (const ElfW(Dyn)*)(base + phdr[i].p_vaddr);
            break;
        }
    }
    if (!dyn)
        return 0;

    const char *strtab = NULL;
    const ElfW(Sym) *symtab = NULL;
    size_t syment = sizeof(ElfW(Sym));
    const uint32_t *hashtab = NULL;

    // IMPORTANT: at runtime, d_un.d_ptr is an *absolute* address
    for (const ElfW(Dyn) *d = dyn; d->d_tag != DT_NULL; ++d) {
        switch (d->d_tag) {
            case DT_STRTAB:
                strtab = (const char*)d->d_un.d_ptr;
                break;
            case DT_SYMTAB:
                symtab = (const ElfW(Sym)*)d->d_un.d_ptr;
                break;
            case DT_SYMENT:
                syment = d->d_un.d_val;
                break;
            case DT_HASH:
                hashtab = (const uint32_t*)d->d_un.d_ptr;
                break;
            default:
                break;
        }
    }

    if (!strtab || !symtab || !hashtab)
        return 0;

    // DT_HASH: [0] = nbucket, [1] = nchain
    uint32_t nbucket = hashtab[0];
    uint32_t nchain = hashtab[1];
    (void)nbucket; // unused here

    // walk all symbols safely: 0 .. nchain-1
    for (uint32_t i = 0; i < nchain; ++i) {
        const ElfW(Sym) *sym =
            (const ElfW(Sym) *)((const char*)symtab + i * syment);

        if (sym->st_name == 0)
            continue;

        const char *name = strtab + sym->st_name;
        if (!name || !*name)
            continue;

        if (fnv1a(name) == ctx->target_hash) {
            // for shared libs, st_value is offset from base
            ctx->result = (void*)(base + sym->st_value);
            return 1; // stop
        }
    }

    return 0; // continue with next object
}

// use dl_iterate_phdr with the callback and get the value
void *resolve_by_hash(uint32_t hash) {
    resolver_ctx ctx;
    ctx.target_hash = hash;
    ctx.result = NULL;

    dl_iterate_phdr(find_symbol, &ctx);
    return ctx.result;
}

int main(void) {
    uint32_t h = fnv1a("printf");
    printf("Looking for printf() via hash: 0x%x\n", h);

    void *addr = resolve_by_hash(h);
    if (!addr) {
        printf("Could not resolve func!\n");
        return 1;
    }

    printf("Found printf() at %p\n", addr);

    typedef int (*printf_t)(const char *, ...);
    printf_t my_printf = (printf_t)addr;

    my_printf("Success! This line is printed via hashed printf.\n");

    return 0;
}
