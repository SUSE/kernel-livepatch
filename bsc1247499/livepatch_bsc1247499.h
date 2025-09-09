#ifndef _LIVEPATCH_BSC1247499_H
#define _LIVEPATCH_BSC1247499_H

int livepatch_bsc1247499_init(void);
static inline void livepatch_bsc1247499_cleanup(void) {}


long klpp_do_mount(const char *dev_name, const char __user *dir_name,
		const char *type_page, unsigned long flags, void *data_page);
#endif /* _LIVEPATCH_BSC1247499_H */
