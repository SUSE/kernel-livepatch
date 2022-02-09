#ifndef _LIVEPATCH_BSC1194460_H
#define _LIVEPATCH_BSC1194460_H

static inline int livepatch_bsc1194460_init(void) { return 0; }
static inline void livepatch_bsc1194460_cleanup(void) { }


struct file;

struct file *klpp___fget(unsigned int fd, fmode_t mask);

#endif /* _LIVEPATCH_BSC1194460_H */
