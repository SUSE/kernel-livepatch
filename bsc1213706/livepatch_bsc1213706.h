#ifndef _LIVEPATCH_BSC1213706_H
#define _LIVEPATCH_BSC1213706_H


struct tun_struct;
struct tun_file;
struct iov_iter;

ssize_t klpp_tun_get_user(struct tun_struct *tun, struct tun_file *tfile,
			    void *msg_control, struct iov_iter *from,
			    int noblock, bool more);


int livepatch_bsc1213706_init(void);
void livepatch_bsc1213706_cleanup(void);


#endif /* _LIVEPATCH_BSC1213706_H */
