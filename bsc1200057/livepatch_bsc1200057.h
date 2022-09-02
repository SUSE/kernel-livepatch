#ifndef _LIVEPATCH_BSC1200057_H
#define _LIVEPATCH_BSC1200057_H

#if IS_ENABLED(CONFIG_BLK_DEV_FD)

int livepatch_bsc1200057_init(void);
void livepatch_bsc1200057_cleanup(void);

int klpp_interpret_errors(void);
void klpp_bad_flp_intr(void);
void klpp_redo_fd_request(void);

struct block_device;
int klpp_fd_locked_ioctl(struct block_device *bdev, fmode_t mode, unsigned int cmd,
		    unsigned long param);

#else /* !IS_ENABLED(CONFIG_BLK_DEV_FD) */

static inline int livepatch_bsc1200057_init(void) { return 0; }
static inline void livepatch_bsc1200057_cleanup(void) {}

#endif /* IS_ENABLED(CONFIG_BLK_DEV_FD) */

#endif /* _LIVEPATCH_BSC1200057_H */
