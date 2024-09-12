#ifndef _LIVEPATCH_BSC1225099_H
#define _LIVEPATCH_BSC1225099_H

struct sk_buff *klpp_prp_create_tagged_frame(struct hsr_frame_info *frame,
                                             struct hsr_port *port);

static inline int livepatch_bsc1225099_init(void) { return 0; }
static inline void livepatch_bsc1225099_cleanup(void) {}

#endif /* _LIVEPATCH_BSC1225099_H */
