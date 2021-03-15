#ifndef _LIVEPATCH_BSC1183120_H
#define _LIVEPATCH_BSC1183120_H

int livepatch_bsc1183120_init(void);
void livepatch_bsc1183120_cleanup(void);


struct device;
struct device_attribute;
struct sk_buff;
struct nlmsghdr;

ssize_t
klpp_show_transport_handle(struct device *dev, struct device_attribute *attr,
		      char *buf);

int
klpp_iscsi_if_recv_msg(struct sk_buff *skb, struct nlmsghdr *nlh, uint32_t *group);

#endif /* _LIVEPATCH_BSC1183120_H */
