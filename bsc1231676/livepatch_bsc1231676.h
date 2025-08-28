#ifndef _LIVEPATCH_BSC1231676_H
#define _LIVEPATCH_BSC1231676_H

int livepatch_bsc1231676_init(void);
static inline void livepatch_bsc1231676_cleanup(void) {}

#include <linux/mm.h>
int klpp_remap_pfn_range(struct vm_area_struct *, unsigned long addr,
			unsigned long pfn, unsigned long size, pgprot_t);
#endif /* _LIVEPATCH_BSC1231676_H */
