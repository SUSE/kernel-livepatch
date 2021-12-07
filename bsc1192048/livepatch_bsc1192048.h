#ifndef _LIVEPATCH_BSC1192048_H
#define _LIVEPATCH_BSC1192048_H

int livepatch_bsc1192048_init(void);
static inline void livepatch_bsc1192048_cleanup(void) {}

u64 klpp_bpf_skb_adjust_room(u64 skb, u64 len_diff, u64 mode, u64 flags,
			     u64 __ur_1);

u64 klpp_bpf_skb_change_tail(u64 skb, u64 new_len, u64 flags,
			     u64 __ur_1, u64 __ur_2);

u64 klpp_sk_skb_change_tail(u64 skb, u64 new_len, u64 flags,
			    u64 __ur_1, u64 __ur_2);

u64 klpp_bpf_skb_change_head(u64 skb, u64 head_room, u64 flags,
			     u64 __ur_1, u64 __ur_2);

u64 klpp_sk_skb_change_head(u64 skb, u64 head_room, u64 flags,
			    u64 __ur_1, u64 __ur_2);

#endif /* _LIVEPATCH_BSC1192048_H */
