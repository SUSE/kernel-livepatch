#ifndef _LIVEPATCH_BSC1185847_H
#define _LIVEPATCH_BSC1185847_H

int livepatch_bsc1185847_init(void);
void livepatch_bsc1185847_cleanup(void);


struct bio;

void klpp_raid1_end_write_request(struct bio *bio);

#endif /* _LIVEPATCH_BSC1185847_H */
