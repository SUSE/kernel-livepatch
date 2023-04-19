#ifndef _LIVEPATCH_BSC1203993_H
#define _LIVEPATCH_BSC1203993_H

struct nvme_ns;

int klpp_nvme_nvm_register(struct nvme_ns *ns, char *disk_name, int node);

static inline int livepatch_bsc1203993_init(void) { return 0; }
static inline void livepatch_bsc1203993_cleanup(void) {}

#endif /* _LIVEPATCH_BSC1203993_H */
