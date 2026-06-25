#ifndef _LIVEPATCH_BSC1256615_H
#define _LIVEPATCH_BSC1256615_H

#include <linux/types.h>

static inline int livepatch_bsc1256615_init(void) { return 0; }
static inline void livepatch_bsc1256615_cleanup(void) {}

struct device;
struct iommu_sva;
struct mm_struct;

struct iommu_sva *klpp_iommu_sva_bind_device(struct device *dev, struct mm_struct *mm);

#endif /* _LIVEPATCH_BSC1256615_H */
