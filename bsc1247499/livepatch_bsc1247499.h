#ifndef _LIVEPATCH_BSC1247499_H
#define _LIVEPATCH_BSC1247499_H

static inline int livepatch_bsc1247499_init(void) { return 0; }
static inline void livepatch_bsc1247499_cleanup(void) {}

struct path;
int klpp_path_mount(const char *dev_name, struct path *path,
		const char *type_page, unsigned long flags, void *data_page);
#endif /* _LIVEPATCH_BSC1247499_H */
