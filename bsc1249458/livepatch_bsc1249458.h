#ifndef _LIVEPATCH_BSC1249458_H
#define _LIVEPATCH_BSC1249458_H

#include <linux/types.h>

static inline int livepatch_bsc1249458_init(void) { return 0; }
static inline void livepatch_bsc1249458_cleanup(void) {}

struct mii_bus;
int klpp___mdiobus_c45_read(struct mii_bus *bus, int addr, int devad,
                            u32 regnum);
int klpp___mdiobus_c45_write(struct mii_bus *bus, int addr, int devad,
                             u32 regnum, u16 val);
#endif /* _LIVEPATCH_BSC1249458_H */
