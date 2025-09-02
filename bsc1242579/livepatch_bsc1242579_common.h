#ifndef _LIVEPATCH_BSC1242579_COMMON_H
#define _LIVEPATCH_BSC1242579_COMMON_H

#define PROC_ENTRY_proc_read_iter    (1U << 1)
#define PROC_ENTRY_proc_compat_ioctl (1U << 2)
#define PROC_ENTRY_bsc1242579        (1U << 7)

static inline bool pde_is_new_proc(const struct proc_dir_entry *pde)
{
    return pde->flags & PROC_ENTRY_bsc1242579;
}

#endif /* _LIVEPATCH_BSC1242579_COMMON_H */
