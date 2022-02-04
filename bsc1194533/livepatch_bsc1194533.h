#ifndef _LIVEPATCH_BSC1194533_H
#define _LIVEPATCH_BSC1194533_H

#if IS_ENABLED(CONFIG_NFC_NCI)

int livepatch_bsc1194533_init(void);
void livepatch_bsc1194533_cleanup(void);


struct nci_dev;
struct sk_buff;
struct nfc_dev;
struct nfc_target;

int klpp_nci_nfcc_loopback(struct nci_dev *ndev, void *data, size_t data_len,
		      struct sk_buff **resp);
int klpp_nci_close_device(struct nci_dev *ndev);
int klpp_nci_dev_up(struct nfc_dev *nfc_dev);
int klpp_nci_start_poll(struct nfc_dev *nfc_dev,
			  __u32 im_protocols, __u32 tm_protocols);
void klpp_nci_stop_poll(struct nfc_dev *nfc_dev);
int klpp_nci_activate_target(struct nfc_dev *nfc_dev,
			       struct nfc_target *target, __u32 protocol);
void klpp_nci_deactivate_target(struct nfc_dev *nfc_dev,
				  struct nfc_target *target,
				  __u8 mode);
int klpp_nci_dep_link_down(struct nfc_dev *nfc_dev);
void klpp_nci_unregister_device(struct nci_dev *ndev);

int klpp_nci_hci_send_cmd(struct nci_dev *ndev, u8 gate,
		     u8 cmd, const u8 *param, size_t param_len,
		     struct sk_buff **skb);
int klpp_nci_hci_open_pipe(struct nci_dev *ndev, u8 pipe);

int klpp_nci_hci_set_param(struct nci_dev *ndev, u8 gate, u8 idx,
		      const u8 *param, size_t param_len);
int klpp_nci_hci_get_param(struct nci_dev *ndev, u8 gate, u8 idx,
		      struct sk_buff **skb);

int klpp_nfc_dev_up(struct nfc_dev *dev);
int klpp_nfc_register_device(struct nfc_dev *dev);
void klpp_nfc_unregister_device(struct nfc_dev *dev);

#else /* !IS_ENABLED(CONFIG_NFC_NCI) */

static inline int livepatch_bsc1194533_init(void) { return 0; }

static inline void livepatch_bsc1194533_cleanup(void) {}

#endif /* IS_ENABLED(CONFIG_NFC_NCI) */
#endif /* _LIVEPATCH_BSC1194533_H */
