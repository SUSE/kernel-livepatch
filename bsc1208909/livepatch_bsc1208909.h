#ifndef _LIVEPATCH_BSC1208909_H
#define _LIVEPATCH_BSC1208909_H

#if IS_ENABLED(CONFIG_MPLS_ROUTING)

int livepatch_bsc1208909_init(void);
void livepatch_bsc1208909_cleanup(void);

struct net_device;
struct mpls_dev;

int klpp_mpls_dev_sysctl_register(struct net_device *dev,
				    struct mpls_dev *mdev);
void klpp_mpls_dev_sysctl_unregister(struct net_device *dev,
				       struct mpls_dev *mdev);

#else /* !IS_ENABLED(CONFIG_MPLS_ROUTING) */

static inline int livepatch_bsc1208909_init(void) { return 0; }
static inline void livepatch_bsc1208909_cleanup(void) {}

#endif /* IS_ENABLED(CONFIG_MPLS_ROUTING) */

#endif /* _LIVEPATCH_BSC1208909_H */
