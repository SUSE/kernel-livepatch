#ifndef _LIVEPATCH_BSC1223363_H
#define _LIVEPATCH_BSC1223363_H

int livepatch_bsc1223363_init(void);
void livepatch_bsc1223363_cleanup(void);

struct network_interface_info_ioctl_rsp;
struct cifs_ses;

int
klpp_parse_server_interfaces(struct network_interface_info_ioctl_rsp *buf,
			size_t buf_len, struct cifs_ses *ses, bool in_mount);

#endif /* _LIVEPATCH_BSC1223363_H */
