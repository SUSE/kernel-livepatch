#ifndef _LIVEPATCH_BSC1204167_H
#define _LIVEPATCH_BSC1204167_H

#if IS_ENABLED(CONFIG_SGI_GRU)

int klpp_gru_handle_user_call_os(unsigned long cb);
int klpp_gru_set_context_option(unsigned long arg);

struct vm_fault;
int klpp_gru_fault(struct vm_fault *vmf);

int bsc1204167_drivers_misc_sgi_gru_grumain_init(void);
void bsc1204167_drivers_misc_sgi_gru_grumain_cleanup(void);

int bsc1204167_drivers_misc_sgi_gru_grufault_init(void);
void bsc1204167_drivers_misc_sgi_gru_grufault_cleanup(void);

int livepatch_bsc1204167_init(void);
void livepatch_bsc1204167_cleanup(void);

#else /* !IS_ENABLED(CONFIG_SGI_GRU) */

static inline int livepatch_bsc1204167_init(void) { return 0; }
static inline void livepatch_bsc1204167_cleanup(void) {}

#endif /* IS_ENABLED(CONFIG_SGI_GRU) */

#endif /* _LIVEPATCH_BSC1204167_H */
