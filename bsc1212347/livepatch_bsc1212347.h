#ifndef _LIVEPATCH_BSC1212347_H
#define _LIVEPATCH_BSC1212347_H

#if IS_ENABLED(CONFIG_FIREWIRE)

int livepatch_bsc1212347_init(void);
void livepatch_bsc1212347_cleanup(void);

struct fw_packet;
struct fw_card;

void klpp_outbound_phy_packet_callback(struct fw_packet *packet,
					 struct fw_card *card, int status);

#else /* !IS_ENABLED(CONFIG_FIREWIRE) */

static inline int livepatch_bsc1212347_init(void) { return 0; }
static inline void livepatch_bsc1212347_cleanup(void) {}

#endif /* IS_ENABLED(CONFIG_FIREWIRE) */

#endif /* _LIVEPATCH_BSC1212347_H */
