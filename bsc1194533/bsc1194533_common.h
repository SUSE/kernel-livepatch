#ifndef BSC1194533_COMMON_H
#define BSC1194533_COMMON_H

int livepatch_bsc1194533_nfc_core_init(void);
void livepatch_bsc1194533_nfc_core_cleanup(void);

int livepatch_bsc1194533_nci_core_init(void);
void livepatch_bsc1194533_nci_core_cleanup(void);

int livepatch_bsc1194533_nci_hci_init(void);
void livepatch_bsc1194533_nci_hci_cleanup(void);


struct nci_dev;

int klpp_nci_request(struct nci_dev *ndev,
		       void (*req)(struct nci_dev *ndev,
				   unsigned long opt),
		       unsigned long opt, __u32 timeout);

#endif
