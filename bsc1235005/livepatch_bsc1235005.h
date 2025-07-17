#ifndef _LIVEPATCH_BSC1235005_H
#define _LIVEPATCH_BSC1235005_H

struct vfio_pci_device;

int livepatch_bsc1235005_init(void);
void livepatch_bsc1235005_cleanup(void);
ssize_t klpp_vfio_pci_config_rw(struct vfio_pci_device *vdev, char __user *buf,
			   size_t count, loff_t *ppos, bool iswrite);

#endif /* _LIVEPATCH_BSC1235005_H */
