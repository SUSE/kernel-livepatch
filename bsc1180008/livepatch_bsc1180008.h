#ifndef _LIVEPATCH_BSC1180008_H
#define _LIVEPATCH_BSC1180008_H

#if IS_ENABLED(CONFIG_XEN_BLKDEV_BACKEND)

int livepatch_bsc1180008_init(void);
void livepatch_bsc1180008_cleanup(void);


struct xen_blkif;

int klpp_xen_blkif_disconnect(struct xen_blkif *blkif);

#else /* !IS_ENABLED(CONFIG_XEN_BLKDEV_BACKEND) */

static inline int livepatch_bsc1180008_init(void) { return 0; }

static inline void livepatch_bsc1180008_cleanup(void) {}

#endif /* IS_ENABLED(CONFIG_XEN_BLKDEV_BACKEND) */
#endif /* _LIVEPATCH_BSC1180008_H */
