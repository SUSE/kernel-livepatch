#ifndef _BSC1207190_COMMON_H
#define _BSC1207190_COMMON_H

int livepatch_bsc1207190_fs_compat_ioctl_init(void);
static inline void livepatch_bsc1207190_fs_compat_ioctl_cleanup(void) {}

int livepatch_bsc1207190_snd_control_compat_init(void);
void livepatch_bsc1207190_snd_control_compat_cleanup(void);


struct file;

long klpp_snd_ctl_ioctl_compat(struct file *file, unsigned int cmd, unsigned long arg);
extern long (*klpe_snd_ctl_ioctl_compat)(struct file *file, unsigned int cmd, unsigned long arg);

#endif
