#ifndef _LIVEPATCH_BSC1179877_H
#define _LIVEPATCH_BSC1179877_H

int livepatch_bsc1179877_init(void);
static inline void livepatch_bsc1179877_cleanup(void) {}


struct tty_struct;
struct work_struct;
struct file;

void klpp___do_SAK(struct tty_struct *tty);
void klpp_do_SAK_work(struct work_struct *work);
void klpp___proc_set_tty(struct tty_struct *tty);
void klpp_disassociate_ctty(int priv);
void klpp_no_tty(void);
long klpp_tty_jobctrl_ioctl(struct tty_struct *tty, struct tty_struct *real_tty,
		       struct file *file, unsigned int cmd, unsigned long arg);

#endif /* _LIVEPATCH_BSC1179877_H */
