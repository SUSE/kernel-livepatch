#ifndef _LIVEPATCH_BSC1225211_H
#define _LIVEPATCH_BSC1225211_H

int livepatch_bsc1225211_init(void);
static inline void livepatch_bsc1225211_cleanup(void) {}

struct tty_struct;
struct vc_data;

int klpp_vc_do_resize(struct tty_struct *tty, struct vc_data *vc,
				unsigned int cols, unsigned int lines);

#endif /* _LIVEPATCH_BSC1225211_H */
