#ifndef _LIVEPATCH_BSC1203606_H
#define _LIVEPATCH_BSC1203606_H

#if IS_ENABLED(CONFIG_DVB_CORE)

int livepatch_bsc1203606_init(void);
void livepatch_bsc1203606_cleanup(void);


struct inode;
struct file;
struct dmxdev;

int klpp_dvb_demux_open(struct inode *inode, struct file *file);
void klpp_dvb_dmxdev_release(struct dmxdev *dmxdev);

#else /* !IS_ENABLED(CONFIG_DVB_CORE) */

static inline int livepatch_bsc1203606_init(void) { return 0; }

static inline void livepatch_bsc1203606_cleanup(void) {}

#endif /* IS_ENABLED(CONFIG_DVB_CORE) */
#endif /* _LIVEPATCH_BSC1203606_H */
