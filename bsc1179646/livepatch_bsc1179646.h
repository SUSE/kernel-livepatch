#ifndef _LIVEPATCH_BSC1179646_H
#define _LIVEPATCH_BSC1179646_H

int livepatch_bsc1179646_init(void);
static inline void livepatch_bsc1179646_cleanup(void) {}


struct mm_struct;
struct list_head;

int klpp___do_munmap(struct mm_struct *mm, unsigned long start, size_t len,
		struct list_head *uf, bool downgrade);

#endif /* _LIVEPATCH_BSC1179646_H */
