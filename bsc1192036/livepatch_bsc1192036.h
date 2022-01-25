#ifndef _LIVEPATCH_BSC1192036_H
#define _LIVEPATCH_BSC1192036_H

#if IS_ENABLED(CONFIG_DVB_FIREDTV)

int livepatch_bsc1192036_init(void);
void livepatch_bsc1192036_cleanup(void);


struct file;

int klpp_fdtv_ca_ioctl(struct file *file, unsigned int cmd, void *arg);

#else /* !IS_ENABLED(CONFIG_DVB_FIREDTV) */

static inline int livepatch_bsc1192036_init(void) { return 0; }

static inline void livepatch_bsc1192036_cleanup(void) {}

#endif /* IS_ENABLED(CONFIG_DVB_FIREDTV) */
#endif /* _LIVEPATCH_BSC1192036_H */
