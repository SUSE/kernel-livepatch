#ifndef _LIVEPATCH_BSC1256217_H
#define _LIVEPATCH_BSC1256217_H

#include <linux/types.h>

int livepatch_bsc1256217_init(void);
void livepatch_bsc1256217_cleanup(void);


struct pci_dev;
struct pci_device_id;
struct work_struct;

int klpp_nvme_probe(struct pci_dev *pdev, const struct pci_device_id *id);
void klpp_nvme_reset_work(struct work_struct *work);
#endif /* _LIVEPATCH_BSC1256217_H */
