#ifndef _LIVEPATCH_BSC1180859_H
#define _LIVEPATCH_BSC1180859_H

int livepatch_bsc1180859_init(void);
void livepatch_bsc1180859_cleanup(void);


struct tun_struct;
struct tun_file;
struct iov_iter;

ssize_t klpp_tun_get_user(struct tun_struct *tun, struct tun_file *tfile,
			    void *msg_control, struct iov_iter *from,
			    int noblock, bool more);

#endif /* _LIVEPATCH_BSC1180859_H */
