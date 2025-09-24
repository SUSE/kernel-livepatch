/*
 * livepatch_bsc1246754
 *
 * Fix for CVE-2025-22023, bsc#1246754
 *
 *  Copyright (c) 2025 SUSE
 *  Author: Vincenzo Mezzela <vincenzo.mezzela@suse.com>
 *
 *  Based on the original Linux kernel code. Other copyrights apply.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#if IS_ENABLED(CONFIG_USB_XHCI_HCD)

#if !IS_MODULE(CONFIG_USB_XHCI_HCD)
#error "Live patch supports only CONFIG=m"
#endif

/* klp-ccp: from drivers/usb/host/xhci-ring.c */
#include <linux/jiffies.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/dma-mapping.h>

/* klp-ccp: from drivers/usb/host/xhci.h */
#include <linux/usb.h>
#include <linux/timer.h>
#include <linux/kernel.h>
#include <linux/usb/hcd.h>
#include <linux/io-64-nonatomic-lo-hi.h>

/* klp-ccp: from drivers/usb/host/xhci-ext-caps.h */
#define XHCI_CMD_RUN		(1 << 0)

#include <linux/io.h>

/* klp-ccp: from drivers/usb/host/xhci-port.h */
#define PORT_CONNECT	(1 << 0)

#define PORT_PLS_MASK	(0xf << 5)
#define XDEV_U0		(0x0 << 5)
#define XDEV_U1		(0x1 << 5)
#define XDEV_U2		(0x2 << 5)

#define XDEV_INACTIVE	(0x6 << 5)

#define XDEV_RESUME	(0xf << 5)

#define DEV_SPEED_MASK		(0xf << 10)

#define	XDEV_SS			(0x4 << 10)

#define DEV_SUPERSPEED_ANY(p)	(((p) & DEV_SPEED_MASK) >= XDEV_SS)

#define PORT_CSC	(1 << 17)

#define PORT_PLC	(1 << 22)

#define DUPLICATE_ENTRY ((u8)(-1))

/* klp-ccp: from drivers/usb/host/xhci-caps.h */
#define HCS_MAX_PORTS(p)	(((p) >> 24) & 0x7f)

/* klp-ccp: from drivers/usb/host/xhci.h */
#define MAX_HC_SLOTS		256

#define	NUM_PORT_REGS	4

struct xhci_op_regs {
	__le32	command;
	__le32	status;
	__le32	page_size;
	__le32	reserved1;
	__le32	reserved2;
	__le32	dev_notification;
	__le64	cmd_ring;
	/* rsvd: offset 0x20-2F */
	__le32	reserved3[4];
	__le64	dcbaa_ptr;
	__le32	config_reg;
	/* rsvd: offset 0x3C-3FF */
	__le32	reserved4[241];
	/* port 1 registers, which serve as a base address for other ports */
	__le32	port_status_base;
	__le32	port_power_base;
	__le32	port_link_base;
	__le32	reserved5;
	/* registers for ports 2-255 */
	__le32	reserved6[NUM_PORT_REGS*254];
};

#define CMD_RUN		XHCI_CMD_RUN

#define IMAN_IP		(1 << 0)

#define STS_FATAL	(1 << 2)

#define STS_EINT	(1 << 3)

#define STS_HCE		(1 << 12)

struct xhci_intr_reg {
	__le32	irq_pending;
	__le32	irq_control;
	__le32	erst_size;
	__le32	rsvd;
	__le64	erst_base;
	__le64	erst_dequeue;
};

#define ERST_DESI_MASK		(0x7)

#define ERST_EHB		(1 << 3)
#define ERST_PTR_MASK		(GENMASK_ULL(63, 4))

struct xhci_slot_ctx {
	__le32	dev_info;
	__le32	dev_info2;
	__le32	tt_info;
	__le32	dev_state;
	/* offset 0x10 to 0x1f reserved for HC internal use */
	__le32	reserved[4];
};

#define TT_SLOT		(0xff)

struct xhci_ep_ctx {
	__le32	ep_info;
	__le32	ep_info2;
	__le64	deq;
	__le32	tx_info;
	/* offset 0x14 - 0x1f reserved for HC internal use */
	__le32	reserved[3];
};

#define EP_STATE_MASK		(0x7)
#define EP_STATE_DISABLED	0

#define EP_STATE_HALTED		2

#define GET_EP_CTX_STATE(ctx)	(le32_to_cpu((ctx)->ep_info) & EP_STATE_MASK)

struct xhci_bw_info {
	/* ep_interval is zero-based */
	unsigned int		ep_interval;
	/* mult and num_packets are one-based */
	unsigned int		mult;
	unsigned int		num_packets;
	unsigned int		max_packet_size;
	unsigned int		max_esit_payload;
	unsigned int		type;
};

struct xhci_virt_ep {
	struct xhci_virt_device		*vdev;	/* parent */
	unsigned int			ep_index;
	struct xhci_ring		*ring;
	/* Related to endpoints that are configured to use stream IDs only */
	struct xhci_stream_info		*stream_info;
	/* Temporary storage in case the configure endpoint command fails and we
	 * have to restore the device state to the previous state
	 */
	struct xhci_ring		*new_ring;
	unsigned int			err_count;
	unsigned int			ep_state;
/* Transitioning the endpoint to using streams, don't enqueue URBs */
/* Transitioning the endpoint to not using streams, don't enqueue URBs */
/* usb_hub_clear_tt_buffer is in progress */
	/* ----  Related to URB cancellation ---- */
	struct list_head	cancelled_td_list;
	struct xhci_hcd		*xhci;
	/* Dequeue pointer and dequeue segment for a submitted Set TR Dequeue
	 * command.  We'll need to update the ring's dequeue segment and dequeue
	 * pointer after the command completes.
	 */
	struct xhci_segment	*queued_deq_seg;
	union xhci_trb		*queued_deq_ptr;
	/*
	 * Sometimes the xHC can not process isochronous endpoint ring quickly
	 * enough, and it will miss some isoc tds on the ring and generate
	 * a Missed Service Error Event.
	 * Set skip flag when receive a Missed Service Error Event and
	 * process the missed tds on the endpoint ring.
	 */
	bool			skip;
	/* Bandwidth checking storage */
	struct xhci_bw_info	bw_info;
	struct list_head	bw_endpoint_list;
	unsigned long		stop_time;
	/* Isoch Frame ID checking storage */
	int			next_frame_id;
	/* Use new Isoch TRB layout needed for extended TBC support */
	bool			use_extended_tbc;
	void *suse_kabi_padding;
};

#define EP_CTX_PER_DEV		31

struct xhci_virt_device {
	int				slot_id;
	struct usb_device		*udev;
	/*
	 * Commands to the hardware are passed an "input context" that
	 * tells the hardware what to change in its data structures.
	 * The hardware will return changes in an "output context" that
	 * software must allocate for the hardware.  We need to keep
	 * track of input and output contexts separately because
	 * these commands might fail and we don't trust the hardware.
	 */
	struct xhci_container_ctx       *out_ctx;
	/* Used for addressing devices and configuration changes */
	struct xhci_container_ctx       *in_ctx;
	struct xhci_virt_ep		eps[EP_CTX_PER_DEV];
	struct xhci_port		*rhub_port;
	struct xhci_interval_bw_table	*bw_table;
	struct xhci_tt_bw_info		*tt_info;
	/*
	 * flags for state tracking based on events and issued commands.
	 * Software can not rely on states from output contexts because of
	 * latency between events and xHC updating output context values.
	 * See xhci 1.1 section 4.8.3 for more details
	 */
	unsigned long			flags;
#define VDEV_PORT_ERROR			BIT(0) /* Port error, link inactive */
	u16				current_mel;
	/* Used for the debugfs interfaces. */
	void				*debugfs_private;
	void *suse_kabi_padding;
};

struct xhci_transfer_event {
	/* 64-bit buffer address, or immediate data */
	__le64	buffer;
	__le32	transfer_len;
	/* This field is interpreted differently based on the type of TRB */
	__le32	flags;
};

#define TRB_TO_SLOT_ID(p)	(((p) >> 24) & 0xff)

#define TRB_TO_EP_ID(p)		(((p) >> 16) & 0x1f) /* Endpoint ID 1 - 31 */

#define	EVENT_TRB_LEN(p)		((p) & 0xffffff)

#define	COMP_CODE_MASK		(0xff << 24)
#define GET_COMP_CODE(p)	(((p) & COMP_CODE_MASK) >> 24)

#define COMP_SUCCESS				1
#define COMP_DATA_BUFFER_ERROR			2
#define COMP_BABBLE_DETECTED_ERROR		3
#define COMP_USB_TRANSACTION_ERROR		4
#define COMP_TRB_ERROR				5
#define COMP_STALL_ERROR			6

#define COMP_INVALID_STREAM_TYPE_ERROR		10

#define COMP_SHORT_PACKET			13
#define COMP_RING_UNDERRUN			14
#define COMP_RING_OVERRUN			15

#define COMP_BANDWIDTH_OVERRUN_ERROR		18

#define COMP_NO_PING_RESPONSE_ERROR		20

#define COMP_INCOMPATIBLE_DEVICE_ERROR		22
#define COMP_MISSED_SERVICE_ERROR		23

#define COMP_STOPPED				26
#define COMP_STOPPED_LENGTH_INVALID		27
#define COMP_STOPPED_SHORT_PACKET		28

#define COMP_ISOCH_BUFFER_OVERRUN		31

#define COMP_INVALID_STREAM_ID_ERROR		34

#define COMP_SPLIT_TRANSACTION_ERROR		36

struct xhci_link_trb {
	/* 64-bit segment pointer*/
	__le64 segment_ptr;
	__le32 intr_target;
	__le32 control;
};

struct xhci_event_cmd {
	/* Pointer to command TRB, or the value passed by the event data trb */
	__le64 cmd_trb;
	__le32 status;
	__le32 flags;
};

enum xhci_ep_reset_type {
	EP_HARD_RESET,
	EP_SOFT_RESET,
};

#define GET_PORT_ID(p)		(((p) & (0xff << 24)) >> 24)

#define	TRB_LEN(p)		((p) & 0x1ffff)

#define TRB_CYCLE		(1<<0)

struct xhci_generic_trb {
	__le32 field[4];
};

union xhci_trb {
	struct xhci_link_trb		link;
	struct xhci_transfer_event	trans_event;
	struct xhci_event_cmd		event_cmd;
	struct xhci_generic_trb		generic;
};

#define	TRB_TYPE_BITMASK	(0xfc00)
#define TRB_TYPE(p)		((p) << 10)
#define TRB_FIELD_TO_TYPE(p)	(((p) & TRB_TYPE_BITMASK) >> 10)

#define TRB_NORMAL		1

#define TRB_SETUP		2

#define TRB_DATA		3

#define TRB_STATUS		4

#define TRB_LINK		6

#define TRB_TR_NOOP		8

#define TRB_TRANSFER		32

#define TRB_COMPLETION		33

#define TRB_PORT_STATUS		34

#define TRB_DEV_NOTE		38

#define TRB_VENDOR_DEFINED_LOW	48

#define	TRB_NEC_CMD_COMP	48

#define TRB_TYPE_LINK_LE32(x)	(((x) & cpu_to_le32(TRB_TYPE_BITMASK)) == \
				 cpu_to_le32(TRB_TYPE(TRB_LINK)))
#define TRB_TYPE_NOOP_LE32(x)	(((x) & cpu_to_le32(TRB_TYPE_BITMASK)) == \
				 cpu_to_le32(TRB_TYPE(TRB_TR_NOOP)))

#define TRBS_PER_SEGMENT	256

#define MAX_SOFT_RETRY		3

#define AVOID_BEI_INTERVAL_MIN	8

struct xhci_segment {
	union xhci_trb		*trbs;
	/* private to HCD */
	struct xhci_segment	*next;
	unsigned int		num;
	dma_addr_t		dma;
	/* Max packet sized bounce buffer for td-fragmant alignment */
	dma_addr_t		bounce_dma;
	void			*bounce_buf;
	unsigned int		bounce_offs;
	unsigned int		bounce_len;
	void *suse_kabi_padding;
};

enum xhci_cancelled_td_status {
	TD_DIRTY = 0,
	TD_HALTED,
	TD_CLEARING_CACHE,
	TD_CLEARING_CACHE_DEFERRED,
	TD_CLEARED,
};

struct xhci_td {
	struct list_head	td_list;
	struct list_head	cancelled_td_list;
	int			status;
	enum xhci_cancelled_td_status	cancel_status;
	struct urb		*urb;
	struct xhci_segment	*start_seg;
	union xhci_trb		*start_trb;
	struct xhci_segment	*end_seg;
	union xhci_trb		*end_trb;
	struct xhci_segment	*bounce_seg;
	/* actual_length of the URB has already been set */
	bool			urb_length_set;
	bool			error_mid_td;

	void *suse_kabi_padding;
};

enum xhci_ring_type {
	TYPE_CTRL = 0,
	TYPE_ISOC,
	TYPE_BULK,
	TYPE_INTR,
	TYPE_STREAM,
	TYPE_COMMAND,
	TYPE_EVENT,
};

struct xhci_ring {
	struct xhci_segment	*first_seg;
	struct xhci_segment	*last_seg;
	union  xhci_trb		*enqueue;
	struct xhci_segment	*enq_seg;
	union  xhci_trb		*dequeue;
	struct xhci_segment	*deq_seg;
	struct list_head	td_list;
	/*
	 * Write the cycle state into the TRB cycle field to give ownership of
	 * the TRB to the host controller (if we are the producer), or to check
	 * if we own the TRB (if we are the consumer).  See section 4.9.1.
	 */
	u32			cycle_state;
	unsigned int		stream_id;
	unsigned int		num_segs;
	unsigned int		num_trbs_free; /* used only by xhci DbC */
	unsigned int		bounce_buf_len;
	enum xhci_ring_type	type;
	bool			last_td_was_short;
	struct radix_tree_root	*trb_address_map;
	void *suse_kabi_padding;
};

struct xhci_erst {
	struct xhci_erst_entry	*entries;
	unsigned int		num_entries;
	/* xhci->event_ring keeps track of segment dma addresses */
	dma_addr_t		erst_dma_addr;
};

struct urb_priv {
	int	num_tds;
	int	num_tds_done;

	void *suse_kabi_padding;

	struct	xhci_td	td[] __counted_by(num_tds);
};

struct s3_save {
	u32	command;
	u32	dev_nt;
	u64	dcbaa_ptr;
	u32	config_reg;
};

struct xhci_bus_state {
	unsigned long		bus_suspended;
	unsigned long		next_statechange;

	/* Port suspend arrays are indexed by the portnum of the fake roothub */
	/* ports suspend status arrays - max 31 ports for USB2, 15 for USB3 */
	u32			port_c_suspend;
	u32			suspended_ports;
	u32			port_remote_wakeup;
	/* which ports have started to resume */
	unsigned long		resuming_ports;
	void *suse_kabi_padding;
};

struct xhci_interrupter {
	struct xhci_ring	*event_ring;
	struct xhci_erst	erst;
	struct xhci_intr_reg __iomem *ir_set;
	unsigned int		intr_num;
	bool			ip_autoclear;
	u32			isoc_bei_interval;
	/* For interrupter registers save and restore over suspend/resume */
	u32	s3_irq_pending;
	u32	s3_irq_control;
	u32	s3_erst_size;
	u64	s3_erst_base;
	u64	s3_erst_dequeue;
	void *suse_kabi_padding;
};

struct xhci_port {
	__le32 __iomem		*addr;
	int			hw_portnum;
	int			hcd_portnum;
	struct xhci_hub		*rhub;
	struct xhci_port_cap	*port_cap;
	unsigned int		lpm_incapable:1;
	unsigned long		resume_timestamp;
	bool			rexit_active;
	/* Slot ID is the index of the device directly connected to the port */
	int			slot_id;
	struct completion	rexit_done;
	struct completion	u3exit_done;
	void *suse_kabi_padding;
};

struct xhci_hub {
	struct xhci_port	**ports;
	unsigned int		num_ports;
	struct usb_hcd		*hcd;
	/* keep track of bus suspend info */
	struct xhci_bus_state   bus_state;
	/* supported prococol extended capabiliy values */
	u8			maj_rev;
	u8			min_rev;
	void *suse_kabi_padding;
};

struct xhci_hcd {
	struct usb_hcd *main_hcd;
	struct usb_hcd *shared_hcd;
	/* glue to PCI and HCD framework */
	struct xhci_cap_regs __iomem *cap_regs;
	struct xhci_op_regs __iomem *op_regs;
	struct xhci_run_regs __iomem *run_regs;
	struct xhci_doorbell_array __iomem *dba;

	/* Cached register copies of read-only HC data */
	__u32		hcs_params1;
	__u32		hcs_params2;
	__u32		hcs_params3;
	__u32		hcc_params;
	__u32		hcc_params2;

	spinlock_t	lock;

	/* packed release number */
	u16		hci_version;
	u16		max_interrupters;
	/* imod_interval in ns (I * 250ns) */
	u32		imod_interval;
	/* 4KB min, 128MB max */
	int		page_size;
	/* Valid values are 12 to 20, inclusive */
	int		page_shift;
	/* MSI-X/MSI vectors */
	int		nvecs;
	/* optional clocks */
	struct clk		*clk;
	struct clk		*reg_clk;
	/* optional reset controller */
	struct reset_control *reset;
	/* data structures */
	struct xhci_device_context_array *dcbaa;
	struct xhci_interrupter **interrupters;
	struct xhci_ring	*cmd_ring;
	unsigned int            cmd_ring_state;
	struct list_head        cmd_list;
	unsigned int		cmd_ring_reserved_trbs;
	struct delayed_work	cmd_timer;
	struct completion	cmd_ring_stop_completion;
	struct xhci_command	*current_cmd;

	/* Scratchpad */
	struct xhci_scratchpad  *scratchpad;

	/* slot enabling and address device helpers */
	/* these are not thread safe so use mutex */
	struct mutex mutex;
	/* Internal mirror of the HW's dcbaa */
	struct xhci_virt_device	*devs[MAX_HC_SLOTS];
	/* For keeping track of bandwidth domains per roothub. */
	struct xhci_root_port_bw_info	*rh_bw;

	/* DMA pools */
	struct dma_pool	*device_pool;
	struct dma_pool	*segment_pool;
	struct dma_pool	*small_streams_pool;
	struct dma_pool	*medium_streams_pool;

	/* Host controller watchdog timer structures */
	unsigned int		xhc_state;
	unsigned long		run_graceperiod;
	struct s3_save		s3;

#define XHCI_STATE_DYING	(1 << 0)
#define XHCI_STATE_HALTED	(1 << 1)
	unsigned long long	quirks;

#define XHCI_NEC_HOST		BIT_ULL(2)

#define XHCI_SPURIOUS_SUCCESS	BIT_ULL(4)

#define XHCI_RESET_PLL_ON_DISCONNECT	BIT_ULL(34)

#define XHCI_NO_SOFT_RETRY	BIT_ULL(40)
	unsigned int		num_active_eps;
	unsigned int		limit_active_eps;
	struct xhci_port	*hw_ports;
	struct xhci_hub		usb2_rhub;
	struct xhci_hub		usb3_rhub;
	/* support xHCI 1.0 spec USB2 hardware LPM */
	unsigned		hw_lpm_support:1;
	/* Broken Suspend flag for SNPS Suspend resume issue */
	unsigned		broken_suspend:1;
	/* Indicates that omitting hcd is supported if root hub has no ports */
	unsigned		allow_single_roothub:1;
	/* cached extended protocol port capabilities */
	struct xhci_port_cap	*port_caps;
	unsigned int		num_port_caps;
	/* Compliance Mode Recovery Data */
	struct timer_list	comp_mode_recovery_timer;
	u32			port_status_u0;
	u16			test_mode;
/* Compliance Mode Timer Triggered every 2 seconds */

	struct dentry		*debugfs_root;
	struct dentry		*debugfs_slots;
	struct list_head	regset_list;

	void			*dbc;
	void *suse_kabi_padding;
	/* platform-specific data -- must come last */
	unsigned long		priv[] __aligned(sizeof(s64));
};

static inline struct xhci_hcd *hcd_to_xhci(struct usb_hcd *hcd)
{
	struct usb_hcd *primary_hcd;

	if (usb_hcd_is_primary_hcd(hcd))
		primary_hcd = hcd;
	else
		primary_hcd = hcd->primary_hcd;

	return (struct xhci_hcd *) (primary_hcd->hcd_priv);
}

static inline struct usb_hcd *xhci_to_hcd(struct xhci_hcd *xhci)
{
	return xhci->main_hcd;
}

#define xhci_dbg(xhci, fmt, args...) \
	dev_dbg(xhci_to_hcd(xhci)->self.controller , fmt , ## args)
#define xhci_err(xhci, fmt, args...) \
	dev_err(xhci_to_hcd(xhci)->self.controller , fmt , ## args)
#define xhci_warn(xhci, fmt, args...) \
	dev_warn(xhci_to_hcd(xhci)->self.controller , fmt , ## args)

static inline u64 xhci_read_64(const struct xhci_hcd *xhci,
		__le64 __iomem *regs)
{
	return lo_hi_readq(regs);
}
static inline void xhci_write_64(struct xhci_hcd *xhci,
				 const u64 val, __le64 __iomem *regs)
{
	lo_hi_writeq(val, regs);
}

struct xhci_ring *xhci_dma_to_transfer_ring(
		struct xhci_virt_ep *ep,
		u64 address);

int xhci_halt(struct xhci_hcd *xhci);

irqreturn_t klpp_xhci_irq(struct usb_hcd *hcd);

dma_addr_t xhci_trb_virt_to_dma(struct xhci_segment *seg, union xhci_trb *trb);
struct xhci_segment *trb_in_td(struct xhci_hcd *xhci, struct xhci_td *td,
			       dma_addr_t suspect_dma, bool debug);
int xhci_is_vendor_info_code(struct xhci_hcd *xhci, unsigned int trb_comp_code);

void inc_deq(struct xhci_hcd *xhci, struct xhci_ring *ring);

void xhci_set_link_state(struct xhci_hcd *xhci, struct xhci_port *port,
				u32 link_state);
void xhci_test_and_clear_bit(struct xhci_hcd *xhci, struct xhci_port *port,
				u32 port_bit);

void xhci_hc_died(struct xhci_hcd *xhci);

void xhci_ring_device(struct xhci_hcd *xhci, int slot_id);

struct xhci_slot_ctx *xhci_get_slot_ctx(struct xhci_hcd *xhci, struct xhci_container_ctx *ctx);
struct xhci_ep_ctx *xhci_get_ep_ctx(struct xhci_hcd *xhci, struct xhci_container_ctx *ctx, unsigned int ep_index);

/* klp-ccp: from drivers/usb/host/xhci-trace.h */
#if !defined(__XHCI_TRACE_H) || defined(TRACE_HEADER_MULTI_READ)

#include <linux/tracepoint.h>

/* klp-ccp: from include/linux/kfifo.h */
#define _LINUX_KFIFO_H

/* klp-ccp: from drivers/usb/host/xhci-dbgcap.h */
#include <linux/kfifo.h>

/* manually copied and adapted from drivers/usb/host/xhci-trace.h */
#include "../klp_trace.h"

KLPR_TRACE_EVENT(xhci_hcd, xhci_handle_port_status,
	     TP_PROTO(struct xhci_port *port, u32 portsc),
	     TP_ARGS(port, portsc)
);

KLPR_TRACE_EVENT(xhci_hcd, xhci_handle_transfer,
	TP_PROTO(struct xhci_ring *ring, struct xhci_generic_trb *trb),
	TP_ARGS(ring, trb)
);


KLPR_TRACE_EVENT(xhci_hcd, xhci_handle_event,
	TP_PROTO(struct xhci_ring *ring, struct xhci_generic_trb *trb),
	TP_ARGS(ring, trb)
);

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif /* __XHCI_TRACE_H */

#include <trace/define_trace.h>

/* klp-ccp: from drivers/usb/host/xhci-ring.c */
dma_addr_t xhci_trb_virt_to_dma(struct xhci_segment *seg,
		union xhci_trb *trb);

static bool trb_is_noop(union xhci_trb *trb)
{
	return TRB_TYPE_NOOP_LE32(trb->generic.field[3]);
}

static bool trb_is_link(union xhci_trb *trb)
{
	return TRB_TYPE_LINK_LE32(trb->link.control);
}

static bool unhandled_event_trb(struct xhci_ring *ring)
{
	return ((le32_to_cpu(ring->dequeue->event_cmd.flags) & TRB_CYCLE) ==
		ring->cycle_state);
}

extern void next_trb(struct xhci_segment **seg,
			union xhci_trb **trb);

void inc_deq(struct xhci_hcd *xhci, struct xhci_ring *ring);

extern struct xhci_virt_ep *xhci_get_virt_ep(struct xhci_hcd *xhci,
					     unsigned int slot_id,
					     unsigned int ep_index);

extern void xhci_td_cleanup(struct xhci_hcd *xhci, struct xhci_td *td,
			    struct xhci_ring *ep_ring, int status);

static void xhci_dequeue_td(struct xhci_hcd *xhci, struct xhci_td *td, struct xhci_ring *ring,
			    u32 status)
{
	ring->dequeue = td->end_trb;
	ring->deq_seg = td->end_seg;
	inc_deq(xhci, ring);

	xhci_td_cleanup(xhci, td, ring, status);
}

extern int xhci_handle_halted_endpoint(struct xhci_hcd *xhci,
				struct xhci_virt_ep *ep,
				struct xhci_td *td,
				enum xhci_ep_reset_type reset_type);

void xhci_hc_died(struct xhci_hcd *xhci);

extern void handle_cmd_completion(struct xhci_hcd *xhci,
		struct xhci_event_cmd *event);

static void handle_vendor_event(struct xhci_hcd *xhci,
				union xhci_trb *event, u32 trb_type)
{
	xhci_dbg(xhci, "Vendor specific event TRB type = %u\n", trb_type);
	if (trb_type == TRB_NEC_CMD_COMP && (xhci->quirks & XHCI_NEC_HOST))
		handle_cmd_completion(xhci, &event->event_cmd);
}

static void handle_device_notification(struct xhci_hcd *xhci,
		union xhci_trb *event)
{
	u32 slot_id;
	struct usb_device *udev;

	slot_id = TRB_TO_SLOT_ID(le32_to_cpu(event->generic.field[3]));
	if (!xhci->devs[slot_id]) {
		xhci_warn(xhci, "Device Notification event for "
				"unused slot %u\n", slot_id);
		return;
	}

	xhci_dbg(xhci, "Device Wake Notification event for slot ID %u\n",
			slot_id);
	udev = xhci->devs[slot_id]->udev;
	if (udev && udev->parent)
		usb_wakeup_notification(udev->parent, udev->portnum);
}

static void xhci_cavium_reset_phy_quirk(struct xhci_hcd *xhci)
{
	struct usb_hcd *hcd = xhci_to_hcd(xhci);
	u32 pll_lock_check;
	u32 retry_count = 4;

	do {
		/* Assert PHY reset */
		writel(0x6F, hcd->regs + 0x1048);
		udelay(10);
		/* De-assert the PHY reset */
		writel(0x7F, hcd->regs + 0x1048);
		udelay(200);
		pll_lock_check = readl(hcd->regs + 0x1070);
	} while (!(pll_lock_check & 0x1) && --retry_count);
}

static void handle_port_status(struct xhci_hcd *xhci, union xhci_trb *event)
{
	struct usb_hcd *hcd;
	u32 port_id;
	u32 portsc, cmd_reg;
	int max_ports;
	unsigned int hcd_portnum;
	struct xhci_bus_state *bus_state;
	bool bogus_port_status = false;
	struct xhci_port *port;

	/* Port status change events always have a successful completion code */
	if (GET_COMP_CODE(le32_to_cpu(event->generic.field[2])) != COMP_SUCCESS)
		xhci_warn(xhci,
			  "WARN: xHC returned failed port status event\n");

	port_id = GET_PORT_ID(le32_to_cpu(event->generic.field[0]));
	max_ports = HCS_MAX_PORTS(xhci->hcs_params1);

	if ((port_id <= 0) || (port_id > max_ports)) {
		xhci_warn(xhci, "Port change event with invalid port ID %d\n",
			  port_id);
		return;
	}

	port = &xhci->hw_ports[port_id - 1];
	if (!port || !port->rhub || port->hcd_portnum == DUPLICATE_ENTRY) {
		xhci_warn(xhci, "Port change event, no port for port ID %u\n",
			  port_id);
		bogus_port_status = true;
		goto cleanup;
	}

	/* We might get interrupts after shared_hcd is removed */
	if (port->rhub == &xhci->usb3_rhub && xhci->shared_hcd == NULL) {
		xhci_dbg(xhci, "ignore port event for removed USB3 hcd\n");
		bogus_port_status = true;
		goto cleanup;
	}

	hcd = port->rhub->hcd;
	bus_state = &port->rhub->bus_state;
	hcd_portnum = port->hcd_portnum;
	portsc = readl(port->addr);

	xhci_dbg(xhci, "Port change event, %d-%d, id %d, portsc: 0x%x\n",
		 hcd->self.busnum, hcd_portnum + 1, port_id, portsc);

	klpr_trace_xhci_handle_port_status(port, portsc);

	if (hcd->state == HC_STATE_SUSPENDED) {
		xhci_dbg(xhci, "resume root hub\n");
		usb_hcd_resume_root_hub(hcd);
	}

	if (hcd->speed >= HCD_USB3 &&
	    (portsc & PORT_PLS_MASK) == XDEV_INACTIVE) {
		if (port->slot_id && xhci->devs[port->slot_id])
			xhci->devs[port->slot_id]->flags |= VDEV_PORT_ERROR;
	}

	if ((portsc & PORT_PLC) && (portsc & PORT_PLS_MASK) == XDEV_RESUME) {
		xhci_dbg(xhci, "port resume event for port %d\n", port_id);

		cmd_reg = readl(&xhci->op_regs->command);
		if (!(cmd_reg & CMD_RUN)) {
			xhci_warn(xhci, "xHC is not running.\n");
			goto cleanup;
		}

		if (DEV_SUPERSPEED_ANY(portsc)) {
			xhci_dbg(xhci, "remote wake SS port %d\n", port_id);
			/* Set a flag to say the port signaled remote wakeup,
			 * so we can tell the difference between the end of
			 * device and host initiated resume.
			 */
			bus_state->port_remote_wakeup |= 1 << hcd_portnum;
			xhci_test_and_clear_bit(xhci, port, PORT_PLC);
			usb_hcd_start_port_resume(&hcd->self, hcd_portnum);
			xhci_set_link_state(xhci, port, XDEV_U0);
			/* Need to wait until the next link state change
			 * indicates the device is actually in U0.
			 */
			bogus_port_status = true;
			goto cleanup;
		} else if (!test_bit(hcd_portnum, &bus_state->resuming_ports)) {
			xhci_dbg(xhci, "resume HS port %d\n", port_id);
			port->resume_timestamp = jiffies +
				msecs_to_jiffies(USB_RESUME_TIMEOUT);
			set_bit(hcd_portnum, &bus_state->resuming_ports);
			/* Do the rest in GetPortStatus after resume time delay.
			 * Avoid polling roothub status before that so that a
			 * usb device auto-resume latency around ~40ms.
			 */
			set_bit(HCD_FLAG_POLL_RH, &hcd->flags);
			mod_timer(&hcd->rh_timer,
				  port->resume_timestamp);
			usb_hcd_start_port_resume(&hcd->self, hcd_portnum);
			bogus_port_status = true;
		}
	}

	if ((portsc & PORT_PLC) &&
	    DEV_SUPERSPEED_ANY(portsc) &&
	    ((portsc & PORT_PLS_MASK) == XDEV_U0 ||
	     (portsc & PORT_PLS_MASK) == XDEV_U1 ||
	     (portsc & PORT_PLS_MASK) == XDEV_U2)) {
		xhci_dbg(xhci, "resume SS port %d finished\n", port_id);
		complete(&port->u3exit_done);
		/* We've just brought the device into U0/1/2 through either the
		 * Resume state after a device remote wakeup, or through the
		 * U3Exit state after a host-initiated resume.  If it's a device
		 * initiated remote wake, don't pass up the link state change,
		 * so the roothub behavior is consistent with external
		 * USB 3.0 hub behavior.
		 */
		if (port->slot_id && xhci->devs[port->slot_id])
			xhci_ring_device(xhci, port->slot_id);
		if (bus_state->port_remote_wakeup & (1 << hcd_portnum)) {
			xhci_test_and_clear_bit(xhci, port, PORT_PLC);
			usb_wakeup_notification(hcd->self.root_hub,
					hcd_portnum + 1);
			bogus_port_status = true;
			goto cleanup;
		}
	}

	/*
	 * Check to see if xhci-hub.c is waiting on RExit to U0 transition (or
	 * RExit to a disconnect state).  If so, let the driver know it's
	 * out of the RExit state.
	 */
	if (hcd->speed < HCD_USB3 && port->rexit_active) {
		complete(&port->rexit_done);
		port->rexit_active = false;
		bogus_port_status = true;
		goto cleanup;
	}

	if (hcd->speed < HCD_USB3) {
		xhci_test_and_clear_bit(xhci, port, PORT_PLC);
		if ((xhci->quirks & XHCI_RESET_PLL_ON_DISCONNECT) &&
		    (portsc & PORT_CSC) && !(portsc & PORT_CONNECT))
			xhci_cavium_reset_phy_quirk(xhci);
	}

cleanup:

	/* Don't make the USB core poll the roothub if we got a bad port status
	 * change event.  Besides, at that point we can't tell which roothub
	 * (USB 2.0 or USB 3.0) to kick.
	 */
	if (bogus_port_status)
		return;

	/*
	 * xHCI port-status-change events occur when the "or" of all the
	 * status-change bits in the portsc register changes from 0 to 1.
	 * New status changes won't cause an event if any other change
	 * bits are still set.  When an event occurs, switch over to
	 * polling to avoid losing status changes.
	 */
	xhci_dbg(xhci, "%s: starting usb%d port polling.\n",
		 __func__, hcd->self.busnum);
	set_bit(HCD_FLAG_POLL_RH, &hcd->flags);
	spin_unlock(&xhci->lock);
	/* Pass this up to the core */
	usb_hcd_poll_rh_status(hcd);
	spin_lock(&xhci->lock);
}

struct xhci_segment *trb_in_td(struct xhci_hcd *xhci, struct xhci_td *td, dma_addr_t suspect_dma,
			       bool debug);

static bool xhci_halted_host_endpoint(struct xhci_ep_ctx *ep_ctx, unsigned int comp_code)
{
	/* Stall halts both internal and device side endpoint */
	if (comp_code == COMP_STALL_ERROR)
		return true;

	/* TRB completion codes that may require internal halt cleanup */
	if (comp_code == COMP_USB_TRANSACTION_ERROR ||
	    comp_code == COMP_BABBLE_DETECTED_ERROR ||
	    comp_code == COMP_SPLIT_TRANSACTION_ERROR)
		/*
		 * The 0.95 spec says a babbling control endpoint is not halted.
		 * The 0.96 spec says it is. Some HW claims to be 0.95
		 * compliant, but it halts the control endpoint anyway.
		 * Check endpoint context if endpoint is halted.
		 */
		if (GET_EP_CTX_STATE(ep_ctx) == EP_STATE_HALTED)
			return true;

	return false;
}

int xhci_is_vendor_info_code(struct xhci_hcd *xhci, unsigned int trb_comp_code);

extern void finish_td(struct xhci_hcd *xhci, struct xhci_virt_ep *ep,
		      struct xhci_ring *ep_ring, struct xhci_td *td,
		      u32 trb_comp_code);

static u32 sum_trb_lengths(struct xhci_td *td, union xhci_trb *stop_trb)
{
	u32 sum;
	union xhci_trb *trb = td->start_trb;
	struct xhci_segment *seg = td->start_seg;

	for (sum = 0; trb != stop_trb; next_trb(&seg, &trb)) {
		if (!trb_is_noop(trb) && !trb_is_link(trb))
			sum += TRB_LEN(le32_to_cpu(trb->generic.field[2]));
	}
	return sum;
}

static void process_ctrl_td(struct xhci_hcd *xhci, struct xhci_virt_ep *ep,
			    struct xhci_ring *ep_ring,  struct xhci_td *td,
			    union xhci_trb *ep_trb, struct xhci_transfer_event *event)
{
	struct xhci_ep_ctx *ep_ctx;
	u32 trb_comp_code;
	u32 remaining, requested;
	u32 trb_type;

	trb_type = TRB_FIELD_TO_TYPE(le32_to_cpu(ep_trb->generic.field[3]));
	ep_ctx = xhci_get_ep_ctx(xhci, ep->vdev->out_ctx, ep->ep_index);
	trb_comp_code = GET_COMP_CODE(le32_to_cpu(event->transfer_len));
	requested = td->urb->transfer_buffer_length;
	remaining = EVENT_TRB_LEN(le32_to_cpu(event->transfer_len));

	switch (trb_comp_code) {
	case COMP_SUCCESS:
		if (trb_type != TRB_STATUS) {
			xhci_warn(xhci, "WARN: Success on ctrl %s TRB without IOC set?\n",
				  (trb_type == TRB_DATA) ? "data" : "setup");
			td->status = -ESHUTDOWN;
			break;
		}
		td->status = 0;
		break;
	case COMP_SHORT_PACKET:
		td->status = 0;
		break;
	case COMP_STOPPED_SHORT_PACKET:
		if (trb_type == TRB_DATA || trb_type == TRB_NORMAL)
			td->urb->actual_length = remaining;
		else
			xhci_warn(xhci, "WARN: Stopped Short Packet on ctrl setup or status TRB\n");
		goto finish_td;
	case COMP_STOPPED:
		switch (trb_type) {
		case TRB_SETUP:
			td->urb->actual_length = 0;
			goto finish_td;
		case TRB_DATA:
		case TRB_NORMAL:
			td->urb->actual_length = requested - remaining;
			goto finish_td;
		case TRB_STATUS:
			td->urb->actual_length = requested;
			goto finish_td;
		default:
			xhci_warn(xhci, "WARN: unexpected TRB Type %d\n",
				  trb_type);
			goto finish_td;
		}
	case COMP_STOPPED_LENGTH_INVALID:
		goto finish_td;
	default:
		if (!xhci_halted_host_endpoint(ep_ctx, trb_comp_code))
			break;
		xhci_dbg(xhci, "TRB error %u, halted endpoint index = %u\n",
			 trb_comp_code, ep->ep_index);
		fallthrough;
	case COMP_STALL_ERROR:
		/* Did we transfer part of the data (middle) phase? */
		if (trb_type == TRB_DATA || trb_type == TRB_NORMAL)
			td->urb->actual_length = requested - remaining;
		else if (!td->urb_length_set)
			td->urb->actual_length = 0;
		goto finish_td;
	}

	/* stopped at setup stage, no data transferred */
	if (trb_type == TRB_SETUP)
		goto finish_td;

	/*
	 * if on data stage then update the actual_length of the URB and flag it
	 * as set, so it won't be overwritten in the event for the last TRB.
	 */
	if (trb_type == TRB_DATA ||
		trb_type == TRB_NORMAL) {
		td->urb_length_set = true;
		td->urb->actual_length = requested - remaining;
		xhci_dbg(xhci, "Waiting for status stage event\n");
		return;
	}

	/* at status stage */
	if (!td->urb_length_set)
		td->urb->actual_length = requested;

finish_td:
	finish_td(xhci, ep, ep_ring, td, trb_comp_code);
}

static void process_isoc_td(struct xhci_hcd *xhci, struct xhci_virt_ep *ep,
			    struct xhci_ring *ep_ring, struct xhci_td *td,
			    union xhci_trb *ep_trb, struct xhci_transfer_event *event)
{
	struct urb_priv *urb_priv;
	int idx;
	struct usb_iso_packet_descriptor *frame;
	u32 trb_comp_code;
	bool sum_trbs_for_length = false;
	u32 remaining, requested, ep_trb_len;
	int short_framestatus;

	trb_comp_code = GET_COMP_CODE(le32_to_cpu(event->transfer_len));
	urb_priv = td->urb->hcpriv;
	idx = urb_priv->num_tds_done;
	frame = &td->urb->iso_frame_desc[idx];
	requested = frame->length;
	remaining = EVENT_TRB_LEN(le32_to_cpu(event->transfer_len));
	ep_trb_len = TRB_LEN(le32_to_cpu(ep_trb->generic.field[2]));
	short_framestatus = td->urb->transfer_flags & URB_SHORT_NOT_OK ?
		-EREMOTEIO : 0;

	/* handle completion code */
	switch (trb_comp_code) {
	case COMP_SUCCESS:
		/* Don't overwrite status if TD had an error, see xHCI 4.9.1 */
		if (td->error_mid_td)
			break;
		if (remaining) {
			frame->status = short_framestatus;
			sum_trbs_for_length = true;
			break;
		}
		frame->status = 0;
		break;
	case COMP_SHORT_PACKET:
		frame->status = short_framestatus;
		sum_trbs_for_length = true;
		break;
	case COMP_BANDWIDTH_OVERRUN_ERROR:
		frame->status = -ECOMM;
		break;
	case COMP_BABBLE_DETECTED_ERROR:
		sum_trbs_for_length = true;
		fallthrough;
	case COMP_ISOCH_BUFFER_OVERRUN:
		frame->status = -EOVERFLOW;
		if (ep_trb != td->end_trb)
			td->error_mid_td = true;
		break;
	case COMP_INCOMPATIBLE_DEVICE_ERROR:
	case COMP_STALL_ERROR:
		frame->status = -EPROTO;
		break;
	case COMP_USB_TRANSACTION_ERROR:
		frame->status = -EPROTO;
		sum_trbs_for_length = true;
		if (ep_trb != td->end_trb)
			td->error_mid_td = true;
		break;
	case COMP_STOPPED:
		sum_trbs_for_length = true;
		break;
	case COMP_STOPPED_SHORT_PACKET:
		/* field normally containing residue now contains transferred */
		frame->status = short_framestatus;
		requested = remaining;
		break;
	case COMP_STOPPED_LENGTH_INVALID:
		/* exclude stopped trb with invalid length from length sum */
		sum_trbs_for_length = true;
		ep_trb_len = 0;
		remaining = 0;
		break;
	default:
		sum_trbs_for_length = true;
		frame->status = -1;
		break;
	}

	if (td->urb_length_set)
		goto finish_td;

	if (sum_trbs_for_length)
		frame->actual_length = sum_trb_lengths(td, ep_trb) +
			ep_trb_len - remaining;
	else
		frame->actual_length = requested;

	td->urb->actual_length += frame->actual_length;

finish_td:
	/* Don't give back TD yet if we encountered an error mid TD */
	if (td->error_mid_td && ep_trb != td->end_trb) {
		xhci_dbg(xhci, "Error mid isoc TD, wait for final completion event\n");
		td->urb_length_set = true;
		return;
	}
	finish_td(xhci, ep, ep_ring, td, trb_comp_code);
}

static void skip_isoc_td(struct xhci_hcd *xhci, struct xhci_td *td,
			 struct xhci_virt_ep *ep, int status)
{
	struct urb_priv *urb_priv;
	struct usb_iso_packet_descriptor *frame;
	int idx;

	urb_priv = td->urb->hcpriv;
	idx = urb_priv->num_tds_done;
	frame = &td->urb->iso_frame_desc[idx];

	/* The transfer is partly done. */
	frame->status = -EXDEV;

	/* calc actual length */
	frame->actual_length = 0;

	xhci_dequeue_td(xhci, td, ep->ring, status);
}

static void process_bulk_intr_td(struct xhci_hcd *xhci, struct xhci_virt_ep *ep,
				 struct xhci_ring *ep_ring, struct xhci_td *td,
				 union xhci_trb *ep_trb, struct xhci_transfer_event *event)
{
	struct xhci_slot_ctx *slot_ctx;
	u32 trb_comp_code;
	u32 remaining, requested, ep_trb_len;

	slot_ctx = xhci_get_slot_ctx(xhci, ep->vdev->out_ctx);
	trb_comp_code = GET_COMP_CODE(le32_to_cpu(event->transfer_len));
	remaining = EVENT_TRB_LEN(le32_to_cpu(event->transfer_len));
	ep_trb_len = TRB_LEN(le32_to_cpu(ep_trb->generic.field[2]));
	requested = td->urb->transfer_buffer_length;

	switch (trb_comp_code) {
	case COMP_SUCCESS:
		ep->err_count = 0;
		/* handle success with untransferred data as short packet */
		if (ep_trb != td->end_trb || remaining) {
			xhci_warn(xhci, "WARN Successful completion on short TX\n");
			xhci_dbg(xhci, "ep %#x - asked for %d bytes, %d bytes untransferred\n",
				 td->urb->ep->desc.bEndpointAddress,
				 requested, remaining);
		}
		td->status = 0;
		break;
	case COMP_SHORT_PACKET:
		td->status = 0;
		break;
	case COMP_STOPPED_SHORT_PACKET:
		td->urb->actual_length = remaining;
		goto finish_td;
	case COMP_STOPPED_LENGTH_INVALID:
		/* stopped on ep trb with invalid length, exclude it */
		td->urb->actual_length = sum_trb_lengths(td, ep_trb);
		goto finish_td;
	case COMP_USB_TRANSACTION_ERROR:
		if (xhci->quirks & XHCI_NO_SOFT_RETRY ||
		    (ep->err_count++ > MAX_SOFT_RETRY) ||
		    le32_to_cpu(slot_ctx->tt_info) & TT_SLOT)
			break;

		td->status = 0;

		xhci_handle_halted_endpoint(xhci, ep, td, EP_SOFT_RESET);
		return;
	default:
		/* do nothing */
		break;
	}

	if (ep_trb == td->end_trb)
		td->urb->actual_length = requested - remaining;
	else
		td->urb->actual_length =
			sum_trb_lengths(td, ep_trb) +
			ep_trb_len - remaining;
finish_td:
	if (remaining > requested) {
		xhci_warn(xhci, "bad transfer trb length %d in event trb\n",
			  remaining);
		td->urb->actual_length = 0;
	}

	finish_td(xhci, ep, ep_ring, td, trb_comp_code);
}

static int handle_transferless_tx_event(struct xhci_hcd *xhci, struct xhci_virt_ep *ep,
					u32 trb_comp_code)
{
	switch (trb_comp_code) {
	case COMP_STALL_ERROR:
	case COMP_USB_TRANSACTION_ERROR:
	case COMP_INVALID_STREAM_TYPE_ERROR:
	case COMP_INVALID_STREAM_ID_ERROR:
		xhci_dbg(xhci, "Stream transaction error ep %u no id\n", ep->ep_index);
		if (ep->err_count++ > MAX_SOFT_RETRY)
			xhci_handle_halted_endpoint(xhci, ep, NULL, EP_HARD_RESET);
		else
			xhci_handle_halted_endpoint(xhci, ep, NULL, EP_SOFT_RESET);
		break;
	case COMP_RING_UNDERRUN:
	case COMP_RING_OVERRUN:
	case COMP_STOPPED_LENGTH_INVALID:
		break;
	default:
		xhci_err(xhci, "Transfer event %u for unknown stream ring slot %u ep %u\n",
			 trb_comp_code, ep->vdev->slot_id, ep->ep_index);
		return -ENODEV;
	}
	return 0;
}

static int klpp_handle_tx_event(struct xhci_hcd *xhci,
			   struct xhci_interrupter *ir,
			   struct xhci_transfer_event *event)
{
	struct xhci_virt_ep *ep;
	struct xhci_ring *ep_ring;
	unsigned int slot_id;
	int ep_index;
	struct xhci_td *td = NULL;
	dma_addr_t ep_trb_dma;
	struct xhci_segment *ep_seg;
	union xhci_trb *ep_trb;
	int status = -EINPROGRESS;
	struct xhci_ep_ctx *ep_ctx;
	u32 trb_comp_code;

	slot_id = TRB_TO_SLOT_ID(le32_to_cpu(event->flags));
	ep_index = TRB_TO_EP_ID(le32_to_cpu(event->flags)) - 1;
	trb_comp_code = GET_COMP_CODE(le32_to_cpu(event->transfer_len));
	ep_trb_dma = le64_to_cpu(event->buffer);

	ep = xhci_get_virt_ep(xhci, slot_id, ep_index);
	if (!ep) {
		xhci_err(xhci, "ERROR Invalid Transfer event\n");
		goto err_out;
	}

	ep_ring = xhci_dma_to_transfer_ring(ep, ep_trb_dma);
	ep_ctx = xhci_get_ep_ctx(xhci, ep->vdev->out_ctx, ep_index);

	if (GET_EP_CTX_STATE(ep_ctx) == EP_STATE_DISABLED) {
		xhci_err(xhci,
			 "ERROR Transfer event for disabled endpoint slot %u ep %u\n",
			  slot_id, ep_index);
		goto err_out;
	}

	if (!ep_ring)
		return handle_transferless_tx_event(xhci, ep, trb_comp_code);

	/* Look for common error cases */
	switch (trb_comp_code) {
	/* Skip codes that require special handling depending on
	 * transfer type
	 */
	case COMP_SUCCESS:
		if (EVENT_TRB_LEN(le32_to_cpu(event->transfer_len)) != 0) {
			trb_comp_code = COMP_SHORT_PACKET;
			xhci_dbg(xhci, "Successful completion on short TX for slot %u ep %u with last td short %d\n",
				 slot_id, ep_index, ep_ring->last_td_was_short);
		}
		break;
	case COMP_SHORT_PACKET:
		break;
	/* Completion codes for endpoint stopped state */
	case COMP_STOPPED:
		xhci_dbg(xhci, "Stopped on Transfer TRB for slot %u ep %u\n",
			 slot_id, ep_index);
		break;
	case COMP_STOPPED_LENGTH_INVALID:
		xhci_dbg(xhci,
			 "Stopped on No-op or Link TRB for slot %u ep %u\n",
			 slot_id, ep_index);
		break;
	case COMP_STOPPED_SHORT_PACKET:
		xhci_dbg(xhci,
			 "Stopped with short packet transfer detected for slot %u ep %u\n",
			 slot_id, ep_index);
		break;
	/* Completion codes for endpoint halted state */
	case COMP_STALL_ERROR:
		xhci_dbg(xhci, "Stalled endpoint for slot %u ep %u\n", slot_id,
			 ep_index);
		status = -EPIPE;
		break;
	case COMP_SPLIT_TRANSACTION_ERROR:
		xhci_dbg(xhci, "Split transaction error for slot %u ep %u\n",
			 slot_id, ep_index);
		status = -EPROTO;
		break;
	case COMP_USB_TRANSACTION_ERROR:
		xhci_dbg(xhci, "Transfer error for slot %u ep %u on endpoint\n",
			 slot_id, ep_index);
		status = -EPROTO;
		break;
	case COMP_BABBLE_DETECTED_ERROR:
		xhci_dbg(xhci, "Babble error for slot %u ep %u on endpoint\n",
			 slot_id, ep_index);
		status = -EOVERFLOW;
		break;
	/* Completion codes for endpoint error state */
	case COMP_TRB_ERROR:
		xhci_warn(xhci,
			  "WARN: TRB error for slot %u ep %u on endpoint\n",
			  slot_id, ep_index);
		status = -EILSEQ;
		break;
	/* completion codes not indicating endpoint state change */
	case COMP_DATA_BUFFER_ERROR:
		xhci_warn(xhci,
			  "WARN: HC couldn't access mem fast enough for slot %u ep %u\n",
			  slot_id, ep_index);
		status = -ENOSR;
		break;
	case COMP_BANDWIDTH_OVERRUN_ERROR:
		xhci_warn(xhci,
			  "WARN: bandwidth overrun event for slot %u ep %u on endpoint\n",
			  slot_id, ep_index);
		break;
	case COMP_ISOCH_BUFFER_OVERRUN:
		xhci_warn(xhci,
			  "WARN: buffer overrun event for slot %u ep %u on endpoint",
			  slot_id, ep_index);
		break;
	case COMP_RING_UNDERRUN:
		/*
		 * When the Isoch ring is empty, the xHC will generate
		 * a Ring Overrun Event for IN Isoch endpoint or Ring
		 * Underrun Event for OUT Isoch endpoint.
		 */
		xhci_dbg(xhci, "Underrun event on slot %u ep %u\n", slot_id, ep_index);
		if (ep->skip)
			break;
		return 0;
	case COMP_RING_OVERRUN:
		xhci_dbg(xhci, "Overrun event on slot %u ep %u\n", slot_id, ep_index);
		if (ep->skip)
			break;
		return 0;
	case COMP_MISSED_SERVICE_ERROR:
		/*
		 * When encounter missed service error, one or more isoc tds
		 * may be missed by xHC.
		 * Set skip flag of the ep_ring; Complete the missed tds as
		 * short transfer when process the ep_ring next time.
		 */
		ep->skip = true;
		xhci_dbg(xhci,
			 "Miss service interval error for slot %u ep %u, set skip flag\n",
			 slot_id, ep_index);
		return 0;
	case COMP_NO_PING_RESPONSE_ERROR:
		ep->skip = true;
		xhci_dbg(xhci,
			 "No Ping response error for slot %u ep %u, Skip one Isoc TD\n",
			 slot_id, ep_index);
		return 0;

	case COMP_INCOMPATIBLE_DEVICE_ERROR:
		/* needs disable slot command to recover */
		xhci_warn(xhci,
			  "WARN: detect an incompatible device for slot %u ep %u",
			  slot_id, ep_index);
		status = -EPROTO;
		break;
	default:
		if (xhci_is_vendor_info_code(xhci, trb_comp_code)) {
			status = 0;
			break;
		}
		xhci_warn(xhci,
			  "ERROR Unknown event condition %u for slot %u ep %u , HC probably busted\n",
			  trb_comp_code, slot_id, ep_index);
		if (ep->skip)
			break;
		return 0;
	}

	/*
	 * xhci 4.10.2 states isoc endpoints should continue
	 * processing the next TD if there was an error mid TD.
	 * So host like NEC don't generate an event for the last
	 * isoc TRB even if the IOC flag is set.
	 * xhci 4.9.1 states that if there are errors in mult-TRB
	 * TDs xHC should generate an error for that TRB, and if xHC
	 * proceeds to the next TD it should genete an event for
	 * any TRB with IOC flag on the way. Other host follow this.
	 *
	 * We wait for the final IOC event, but if we get an event
	 * anywhere outside this TD, just give it back already.
	 */
	td = list_first_entry_or_null(&ep_ring->td_list, struct xhci_td, td_list);

	if (td && td->error_mid_td && !trb_in_td(xhci, td, ep_trb_dma, false)) {
		xhci_dbg(xhci, "Missing TD completion event after mid TD error\n");
		xhci_dequeue_td(xhci, td, ep_ring, td->status);
	}

	if (list_empty(&ep_ring->td_list)) {
		/*
		 * Don't print wanings if ring is empty due to a stopped endpoint generating an
		 * extra completion event if the device was suspended. Or, a event for the last TRB
		 * of a short TD we already got a short event for. The short TD is already removed
		 * from the TD list.
		 */
		if (trb_comp_code != COMP_STOPPED &&
		    trb_comp_code != COMP_STOPPED_LENGTH_INVALID &&
		    !ep_ring->last_td_was_short) {
			xhci_warn(xhci, "Event TRB for slot %u ep %u with no TDs queued\n",
				  slot_id, ep_index);
		}

		ep->skip = false;
		goto check_endpoint_halted;
	}

	do {
		td = list_first_entry(&ep_ring->td_list, struct xhci_td,
				      td_list);

		/* Is this a TRB in the currently executing TD? */
		ep_seg = trb_in_td(xhci, td, ep_trb_dma, false);

		if (!ep_seg) {

			if (ep->skip && usb_endpoint_xfer_isoc(&td->urb->ep->desc)) {
				/* this event is unlikely to match any TD, don't skip them all */
				if (trb_comp_code == COMP_STOPPED_LENGTH_INVALID)
					return 0;

				skip_isoc_td(xhci, td, ep, status);
				if (!list_empty(&ep_ring->td_list))
					continue;

				xhci_dbg(xhci, "All TDs skipped for slot %u ep %u. Clear skip flag.\n",
					 slot_id, ep_index);
				ep->skip = false;
				td = NULL;
				goto check_endpoint_halted;
			}

			/*
			 * Skip the Force Stopped Event. The 'ep_trb' of FSE is not in the current
			 * TD pointed by 'ep_ring->dequeue' because that the hardware dequeue
			 * pointer still at the previous TRB of the current TD. The previous TRB
			 * maybe a Link TD or the last TRB of the previous TD. The command
			 * completion handle will take care the rest.
			 */
			if (trb_comp_code == COMP_STOPPED ||
			    trb_comp_code == COMP_STOPPED_LENGTH_INVALID) {
				return 0;
			}

			/*
			 * Some hosts give a spurious success event after a short
			 * transfer. Ignore it.
			 */
			if ((xhci->quirks & XHCI_SPURIOUS_SUCCESS) &&
			    ep_ring->last_td_was_short) {
				ep_ring->last_td_was_short = false;
				return 0;
			}

			/* HC is busted, give up! */
			xhci_err(xhci,
				 "ERROR Transfer event TRB DMA ptr not part of current TD ep_index %d comp_code %u\n",
				 ep_index, trb_comp_code);
			trb_in_td(xhci, td, ep_trb_dma, true);

			return -ESHUTDOWN;
		}

		if (ep->skip) {
			xhci_dbg(xhci,
				 "Found td. Clear skip flag for slot %u ep %u.\n",
				 slot_id, ep_index);
			ep->skip = false;
		}

	/*
	 * If ep->skip is set, it means there are missed tds on the
	 * endpoint ring need to take care of.
	 * Process them as short transfer until reach the td pointed by
	 * the event.
	 */
	} while (ep->skip);

	if (trb_comp_code == COMP_SHORT_PACKET)
		ep_ring->last_td_was_short = true;
	else
		ep_ring->last_td_was_short = false;

	ep_trb = &ep_seg->trbs[(ep_trb_dma - ep_seg->dma) / sizeof(*ep_trb)];
	klpr_trace_xhci_handle_transfer(ep_ring, (struct xhci_generic_trb *) ep_trb);

	/*
	 * No-op TRB could trigger interrupts in a case where a URB was killed
	 * and a STALL_ERROR happens right after the endpoint ring stopped.
	 * Reset the halted endpoint. Otherwise, the endpoint remains stalled
	 * indefinitely.
	 */

	if (trb_is_noop(ep_trb))
		goto check_endpoint_halted;

	td->status = status;

	/* update the urb's actual_length and give back to the core */
	if (usb_endpoint_xfer_control(&td->urb->ep->desc))
		process_ctrl_td(xhci, ep, ep_ring, td, ep_trb, event);
	else if (usb_endpoint_xfer_isoc(&td->urb->ep->desc))
		process_isoc_td(xhci, ep, ep_ring, td, ep_trb, event);
	else
		process_bulk_intr_td(xhci, ep, ep_ring, td, ep_trb, event);
	return 0;

check_endpoint_halted:
	if (xhci_halted_host_endpoint(ep_ctx, trb_comp_code))
		xhci_handle_halted_endpoint(xhci, ep, td, EP_HARD_RESET);

	return 0;

err_out:
	xhci_err(xhci, "@%016llx %08x %08x %08x %08x\n",
		 (unsigned long long) xhci_trb_virt_to_dma(
			 ir->event_ring->deq_seg,
			 ir->event_ring->dequeue),
		 lower_32_bits(le64_to_cpu(event->buffer)),
		 upper_32_bits(le64_to_cpu(event->buffer)),
		 le32_to_cpu(event->transfer_len),
		 le32_to_cpu(event->flags));
	return -ENODEV;
}

static int klpr_xhci_handle_event_trb(struct xhci_hcd *xhci, struct xhci_interrupter *ir,
				 union xhci_trb *event)
{
	u32 trb_type;

	klpr_trace_xhci_handle_event(ir->event_ring, &event->generic);

	/*
	 * Barrier between reading the TRB_CYCLE (valid) flag before, and any
	 * speculative reads of the event's flags/data below.
	 */
	rmb();
	trb_type = TRB_FIELD_TO_TYPE(le32_to_cpu(event->event_cmd.flags));
	/* FIXME: Handle more event types. */

	switch (trb_type) {
	case TRB_COMPLETION:
		handle_cmd_completion(xhci, &event->event_cmd);
		break;
	case TRB_PORT_STATUS:
		handle_port_status(xhci, event);
		break;
	case TRB_TRANSFER:
		klpp_handle_tx_event(xhci, ir, &event->trans_event);
		break;
	case TRB_DEV_NOTE:
		handle_device_notification(xhci, event);
		break;
	default:
		if (trb_type >= TRB_VENDOR_DEFINED_LOW)
			handle_vendor_event(xhci, event, trb_type);
		else
			xhci_warn(xhci, "ERROR unknown event type %d\n", trb_type);
	}
	/* Any of the above functions may drop and re-acquire the lock, so check
	 * to make sure a watchdog timer didn't mark the host as non-responsive.
	 */
	if (xhci->xhc_state & XHCI_STATE_DYING) {
		xhci_dbg(xhci, "xHCI host dying, returning from event handler.\n");
		return -ENODEV;
	}

	return 0;
}

static void xhci_update_erst_dequeue(struct xhci_hcd *xhci,
				     struct xhci_interrupter *ir,
				     bool clear_ehb)
{
	u64 temp_64;
	dma_addr_t deq;

	temp_64 = xhci_read_64(xhci, &ir->ir_set->erst_dequeue);
	deq = xhci_trb_virt_to_dma(ir->event_ring->deq_seg,
				   ir->event_ring->dequeue);
	if (deq == 0)
		xhci_warn(xhci, "WARN something wrong with SW event ring dequeue ptr\n");
	/*
	 * Per 4.9.4, Software writes to the ERDP register shall always advance
	 * the Event Ring Dequeue Pointer value.
	 */
	if ((temp_64 & ERST_PTR_MASK) == (deq & ERST_PTR_MASK) && !clear_ehb)
		return;

	/* Update HC event ring dequeue pointer */
	temp_64 = ir->event_ring->deq_seg->num & ERST_DESI_MASK;
	temp_64 |= deq & ERST_PTR_MASK;

	/* Clear the event handler busy flag (RW1C) */
	if (clear_ehb)
		temp_64 |= ERST_EHB;
	xhci_write_64(xhci, temp_64, &ir->ir_set->erst_dequeue);
}

static void xhci_clear_interrupt_pending(struct xhci_interrupter *ir)
{
	if (!ir->ip_autoclear) {
		u32 irq_pending;

		irq_pending = readl(&ir->ir_set->irq_pending);
		irq_pending |= IMAN_IP;
		writel(irq_pending, &ir->ir_set->irq_pending);
	}
}

static int klpr_xhci_handle_events(struct xhci_hcd *xhci, struct xhci_interrupter *ir)
{
	int event_loop = 0;
	int err;
	u64 temp;

	xhci_clear_interrupt_pending(ir);

	/* Event ring hasn't been allocated yet. */
	if (!ir->event_ring || !ir->event_ring->dequeue) {
		xhci_err(xhci, "ERROR interrupter event ring not ready\n");
		return -ENOMEM;
	}

	if (xhci->xhc_state & XHCI_STATE_DYING ||
	    xhci->xhc_state & XHCI_STATE_HALTED) {
		xhci_dbg(xhci, "xHCI dying, ignoring interrupt. Shouldn't IRQs be disabled?\n");

		/* Clear the event handler busy flag (RW1C) */
		temp = xhci_read_64(xhci, &ir->ir_set->erst_dequeue);
		xhci_write_64(xhci, temp | ERST_EHB, &ir->ir_set->erst_dequeue);
		return -ENODEV;
	}

	/* Process all OS owned event TRBs on this event ring */
	while (unhandled_event_trb(ir->event_ring)) {
		err = klpr_xhci_handle_event_trb(xhci, ir, ir->event_ring->dequeue);

		/*
		 * If half a segment of events have been handled in one go then
		 * update ERDP, and force isoc trbs to interrupt more often
		 */
		if (event_loop++ > TRBS_PER_SEGMENT / 2) {
			xhci_update_erst_dequeue(xhci, ir, false);

			if (ir->isoc_bei_interval > AVOID_BEI_INTERVAL_MIN)
				ir->isoc_bei_interval = ir->isoc_bei_interval / 2;

			event_loop = 0;
		}

		/* Update SW event ring dequeue pointer */
		inc_deq(xhci, ir->event_ring);

		if (err)
			break;
	}

	xhci_update_erst_dequeue(xhci, ir, true);

	return 0;
}

irqreturn_t klpp_xhci_irq(struct usb_hcd *hcd)
{
	struct xhci_hcd *xhci = hcd_to_xhci(hcd);
	irqreturn_t ret = IRQ_HANDLED;
	u32 status;

	spin_lock(&xhci->lock);
	/* Check if the xHC generated the interrupt, or the irq is shared */
	status = readl(&xhci->op_regs->status);
	if (status == ~(u32)0) {
		xhci_hc_died(xhci);
		goto out;
	}

	if (!(status & STS_EINT)) {
		ret = IRQ_NONE;
		goto out;
	}

	if (status & STS_HCE) {
		xhci_warn(xhci, "WARNING: Host Controller Error\n");
		goto out;
	}

	if (status & STS_FATAL) {
		xhci_warn(xhci, "WARNING: Host System Error\n");
		xhci_halt(xhci);
		goto out;
	}

	/*
	 * Clear the op reg interrupt status first,
	 * so we can receive interrupts from other MSI-X interrupters.
	 * Write 1 to clear the interrupt status.
	 */
	status |= STS_EINT;
	writel(status, &xhci->op_regs->status);
	ret = IRQ_HANDLED;

	/* This is the handler of the primary interrupter */
	klpr_xhci_handle_events(xhci, xhci->interrupters[0]);

out:
	spin_unlock(&xhci->lock);

	return ret;
}


#include "livepatch_bsc1246754.h"

#include <linux/livepatch.h>

extern typeof(finish_td) finish_td
	 KLP_RELOC_SYMBOL(xhci_hcd, xhci_hcd, finish_td);
extern typeof(handle_cmd_completion) handle_cmd_completion
	 KLP_RELOC_SYMBOL(xhci_hcd, xhci_hcd, handle_cmd_completion);
extern typeof(inc_deq) inc_deq KLP_RELOC_SYMBOL(xhci_hcd, xhci_hcd, inc_deq);
extern typeof(next_trb) next_trb KLP_RELOC_SYMBOL(xhci_hcd, xhci_hcd, next_trb);
extern typeof(trb_in_td) trb_in_td
	 KLP_RELOC_SYMBOL(xhci_hcd, xhci_hcd, trb_in_td);
extern typeof(xhci_dma_to_transfer_ring) xhci_dma_to_transfer_ring
	 KLP_RELOC_SYMBOL(xhci_hcd, xhci_hcd, xhci_dma_to_transfer_ring);
extern typeof(xhci_get_ep_ctx) xhci_get_ep_ctx
	 KLP_RELOC_SYMBOL(xhci_hcd, xhci_hcd, xhci_get_ep_ctx);
extern typeof(xhci_get_slot_ctx) xhci_get_slot_ctx
	 KLP_RELOC_SYMBOL(xhci_hcd, xhci_hcd, xhci_get_slot_ctx);
extern typeof(xhci_get_virt_ep) xhci_get_virt_ep
	 KLP_RELOC_SYMBOL(xhci_hcd, xhci_hcd, xhci_get_virt_ep);
extern typeof(xhci_halt) xhci_halt
	 KLP_RELOC_SYMBOL(xhci_hcd, xhci_hcd, xhci_halt);
extern typeof(xhci_handle_halted_endpoint) xhci_handle_halted_endpoint
	 KLP_RELOC_SYMBOL(xhci_hcd, xhci_hcd, xhci_handle_halted_endpoint);
extern typeof(xhci_hc_died) xhci_hc_died
	 KLP_RELOC_SYMBOL(xhci_hcd, xhci_hcd, xhci_hc_died);
extern typeof(xhci_is_vendor_info_code) xhci_is_vendor_info_code
	 KLP_RELOC_SYMBOL(xhci_hcd, xhci_hcd, xhci_is_vendor_info_code);
extern typeof(xhci_ring_device) xhci_ring_device
	 KLP_RELOC_SYMBOL(xhci_hcd, xhci_hcd, xhci_ring_device);
extern typeof(xhci_set_link_state) xhci_set_link_state
	 KLP_RELOC_SYMBOL(xhci_hcd, xhci_hcd, xhci_set_link_state);
extern typeof(xhci_td_cleanup) xhci_td_cleanup
	 KLP_RELOC_SYMBOL(xhci_hcd, xhci_hcd, xhci_td_cleanup);
extern typeof(xhci_test_and_clear_bit) xhci_test_and_clear_bit
	 KLP_RELOC_SYMBOL(xhci_hcd, xhci_hcd, xhci_test_and_clear_bit);
extern typeof(xhci_trb_virt_to_dma) xhci_trb_virt_to_dma
	 KLP_RELOC_SYMBOL(xhci_hcd, xhci_hcd, xhci_trb_virt_to_dma);
extern typeof(usb_hcd_is_primary_hcd) usb_hcd_is_primary_hcd
	 KLP_RELOC_SYMBOL(xhci_hcd, usbcore, usb_hcd_is_primary_hcd);
extern typeof(usb_hcd_poll_rh_status) usb_hcd_poll_rh_status
	 KLP_RELOC_SYMBOL(xhci_hcd, usbcore, usb_hcd_poll_rh_status);
extern typeof(usb_hcd_resume_root_hub) usb_hcd_resume_root_hub
	 KLP_RELOC_SYMBOL(xhci_hcd, usbcore, usb_hcd_resume_root_hub);
extern typeof(usb_hcd_start_port_resume) usb_hcd_start_port_resume
	 KLP_RELOC_SYMBOL(xhci_hcd, usbcore, usb_hcd_start_port_resume);
extern typeof(usb_wakeup_notification) usb_wakeup_notification
	 KLP_RELOC_SYMBOL(xhci_hcd, usbcore, usb_wakeup_notification);

#endif /* IS_ENABLED(CONFIG_USB_XHCI_HCD) */
