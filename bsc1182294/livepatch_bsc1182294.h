#ifndef _LIVEPATCH_BSC1182294_H
#define _LIVEPATCH_BSC1182294_H

#if IS_ENABLED(CONFIG_XEN_BLKDEV_BACKEND)

int livepatch_bsc1182294_init(void);
void livepatch_bsc1182294_cleanup(void);


struct xen_blkif_ring;
struct grant_page;

int klpp_xen_blkbk_map(struct xen_blkif_ring *ring,
			 struct grant_page *pages[],
			 int num, bool ro);

#else /* !IS_ENABLED(CONFIG_XEN_BLKDEV_BACKEND) */

static inline int livepatch_bsc1182294_init(void) { return 0; }

static inline void livepatch_bsc1182294_cleanup(void) {}

#endif /* IS_ENABLED(CONFIG_XEN_BLKDEV_BACKEND) */
#endif /* _LIVEPATCH_BSC1182294_H */
