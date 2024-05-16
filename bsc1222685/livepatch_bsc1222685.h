#ifndef _LIVEPATCH_BSC1222685_H
#define _LIVEPATCH_BSC1222685_H

int livepatch_bsc1222685_init(void);
void livepatch_bsc1222685_cleanup(void);

struct tty_struct;

int klpp_gsmld_open(struct tty_struct *tty);

#endif /* _LIVEPATCH_BSC1222685_H */
