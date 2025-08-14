#ifndef _LIVEPATCH_BSC1247350_H
#define _LIVEPATCH_BSC1247350_H

static inline int livepatch_bsc1247350_init(void) { return 0; }
static inline void livepatch_bsc1247350_cleanup(void) {}

void klpp___hid_request(struct hid_device *hid, struct hid_report *rep, int reqtype);

#endif /* _LIVEPATCH_BSC1247350_H */
