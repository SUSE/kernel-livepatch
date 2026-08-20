#ifndef _LIVEPATCH_BSC1264078_H
#define _LIVEPATCH_BSC1264078_H

#include <linux/types.h>

static inline int livepatch_bsc1264078_init(void) { return 0; }
static inline void livepatch_bsc1264078_cleanup(void) {}

struct device;
struct ulpi;
struct ulpi_ops;

struct ulpi *klpp_ulpi_register_interface(struct device *, const struct ulpi_ops *);

#endif /* _LIVEPATCH_BSC1264078_H */
