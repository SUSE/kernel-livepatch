#ifndef _LIVEPATCH_BSC1249455_H
#define _LIVEPATCH_BSC1249455_H

struct mii_bus;

static inline int livepatch_bsc1249455_init(void) { return 0; }
static inline void livepatch_bsc1249455_cleanup(void) {}

int klpp___mdiobus_read(struct mii_bus *bus, int addr, u32 regnum);
int klpp___mdiobus_write(struct mii_bus *bus, int addr, u32 regnum, u16 val);

#endif /* _LIVEPATCH_BSC1249455_H */
