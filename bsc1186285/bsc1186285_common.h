#ifndef _BSC1186285_COMMON_H
#define _BSC1186285_COMMON_H

#include <linux/types.h>
#include <linux/skbuff.h>
#include <linux/list.h>
#include <net/bluetooth/bluetooth.h>
#include <net/bluetooth/hci_core.h>

static inline int livepatch_bsc1186285_hci_conn_init(void) { return 0; }
static inline void livepatch_bsc1186285_hci_conn_cleanup(void) {}

int livepatch_bsc1186285_hci_event_init(void);
void livepatch_bsc1186285_hci_event_cleanup(void);

struct klpp_hci_chan {
	struct list_head list;
	__u16 handle;
	struct hci_conn *conn;
	struct sk_buff_head data_q;
	unsigned int	sent;
	__u8		state;
	/*
	 * Fix CVE-2021-33034
	 *  +1 line
	 */
	__u8		klpp_not_amp;
};

/* New, livepatch specific. */
static inline bool klpp_hci_chan_is_amp(const struct hci_chan * const _c)
{
	const struct klpp_hci_chan * const c = (const struct klpp_hci_chan *)_c;

#define KLPP_HCI_CHAN_CHECK_MEMBER_OFFSET(member)		\
	BUILD_BUG_ON(offsetof(struct hci_chan, member) !=	\
		     offsetof(struct klpp_hci_chan, member))
	BUILD_BUG_ON(sizeof(struct hci_chan) != sizeof(struct klpp_hci_chan));
	KLPP_HCI_CHAN_CHECK_MEMBER_OFFSET(list);
	KLPP_HCI_CHAN_CHECK_MEMBER_OFFSET(handle);
	KLPP_HCI_CHAN_CHECK_MEMBER_OFFSET(conn);
	KLPP_HCI_CHAN_CHECK_MEMBER_OFFSET(data_q);
	KLPP_HCI_CHAN_CHECK_MEMBER_OFFSET(sent);
	KLPP_HCI_CHAN_CHECK_MEMBER_OFFSET(state);
#undef KLPP_HCI_CHAN_CHECK_MEMBER_OFFSET

	/*
	 * In order to deal with the constraints of livepatching, use
	 * an inverted ->amp flag. Only hci_chan instances created
	 * after livepatch application will get protected from
	 * amp_destroy_logical_link(). Instances which have been
	 * created beforehand all have this flag cleared per the
	 * kzalloc() allocation, which means that the livepatch
	 * effectively doesn't apply to those.
	 */
	return !c->klpp_not_amp;
}

/* New, livepatch specific. */
static inline void klpp_hci_chan_set_amp(struct hci_chan * const _c)
{
	struct klpp_hci_chan * const c = (struct klpp_hci_chan *)_c;

	c->klpp_not_amp = false;
}

/* New, livepatch specific. */
static inline void klpp_hci_chan_clear_amp(struct hci_chan * const _c)
{
	struct klpp_hci_chan * const c = (struct klpp_hci_chan *)_c;

	c->klpp_not_amp = true;
}


struct hci_chan *klpp_hci_chan_create(struct hci_conn *conn);

#endif
