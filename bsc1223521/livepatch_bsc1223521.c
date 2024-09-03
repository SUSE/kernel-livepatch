/*
 * livepatch_bsc1223521
 *
 * Fix for CVE-2022-48662, bsc#1223521
 *
 *  Upstream commit:
 *  d119888b09bd ("drm/i915/gem: Really move i915_gem_context.link under ref protection")
 *
 *  SLE12-SP5 commit:
 *  Not affected
 *
 *  SLE15-SP2 and -SP3 commit:
 *  Not affected
 *
 *  SLE15-SP4 and -SP5 commit:
 *  1ea0422b210c3ea352e61c616157bb5e2d522ef7
 *
 *  SLE15-SP6 commit:
 *  Not affected
 *
 *  Copyright (c) 2024 SUSE
 *  Author: Lukas Hruska <lhruska@suse.cz>
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

#if IS_ENABLED(CONFIG_DRM_I915)

#if !IS_MODULE(CONFIG_DRM_I915)
#error "Live patch supports only CONFIG=m"
#endif

/* klp-ccp: from drivers/gpu/drm/i915/i915_perf.c */
#include <linux/sizes.h>
#include <linux/uuid.h>
/* klp-ccp: from drivers/gpu/drm/i915/gem/i915_gem_context_types.h */
#include <linux/atomic.h>
#include <linux/list.h>
#include <linux/llist.h>
#include <linux/kref.h>
#include <linux/mutex.h>
#include <linux/radix-tree.h>
#include <linux/rbtree.h>
#include <linux/rcupdate.h>
#include <linux/types.h>
/* klp-ccp: from drivers/gpu/drm/i915/gt/intel_context_types.h */
#include <linux/average.h>
#include <linux/kref.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/types.h>
/* klp-ccp: from drivers/gpu/drm/i915/i915_active_types.h */
#include <linux/atomic.h>
#include <linux/dma-fence.h>
#include <linux/llist.h>
#include <linux/mutex.h>
#include <linux/rbtree.h>
#include <linux/rcupdate.h>
#include <linux/workqueue.h>

struct i915_active_fence {
	struct dma_fence __rcu *fence;
	struct dma_fence_cb cb;
};

struct i915_active {
	atomic_t count;
	struct mutex mutex;

	spinlock_t tree_lock;
	struct active_node *cache;
	struct rb_root tree;

	/* Preallocated "exclusive" node */
	struct i915_active_fence excl;

	unsigned long flags;

	int (*active)(struct i915_active *ref);
	void (*retire)(struct i915_active *ref);

	struct work_struct work;

	struct llist_head preallocated_barriers;
};

/* klp-ccp: from drivers/gpu/drm/i915/i915_sw_fence.h */
#include <linux/dma-fence.h>
#include <linux/gfp.h>
#include <linux/kref.h>
#include <linux/notifier.h> /* for NOTIFY_DONE */
#include <linux/wait.h>

struct i915_sw_fence;

enum i915_sw_fence_notify;

typedef int (*i915_sw_fence_notify_t)(struct i915_sw_fence *,
				      enum i915_sw_fence_notify state);

struct i915_sw_fence {
	wait_queue_head_t wait;
	i915_sw_fence_notify_t fn;
#ifdef CONFIG_DRM_I915_SW_FENCE_CHECK_DAG
#error "klp-ccp: non-taken branch"
#endif
	atomic_t pending;
	int error;
};

/* klp-ccp: from drivers/gpu/drm/i915/i915_utils.h */
#include <linux/list.h>
#include <linux/overflow.h>
#include <linux/sched.h>

/* klp-ccp: from include/linux/ctype.h */
#define _LINUX_CTYPE_H

/* klp-ccp: from drivers/gpu/drm/i915/i915_utils.h */
#include <linux/types.h>
#include <linux/workqueue.h>

#ifdef CONFIG_X86
#include <asm/hypervisor.h>
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif

/* klp-ccp: from drivers/gpu/drm/i915/gt/intel_engine_types.h */
#include <linux/average.h>
#include <linux/hashtable.h>
#include <linux/irq_work.h>
#include <linux/kref.h>
#include <linux/list.h>
#include <linux/llist.h>
#include <linux/rbtree.h>
#include <linux/timer.h>
#include <linux/types.h>
#include <linux/workqueue.h>
/* klp-ccp: from drivers/gpu/drm/i915/i915_gem.h */
#include <linux/bug.h>
#include <drm/drm_drv.h>

#define GEM_BUG_ON(expr) BUILD_BUG_ON_INVALID(expr)

/* klp-ccp: from drivers/gpu/drm/i915/i915_pmu.h */
#include <linux/hrtimer.h>
#include <linux/perf_event.h>
#include <linux/spinlock_types.h>
#include <uapi/drm/i915_drm.h>

enum i915_pmu_tracked_events {
	__I915_PMU_ACTUAL_FREQUENCY_ENABLED = 0,
	__I915_PMU_REQUESTED_FREQUENCY_ENABLED,
	__I915_PMU_RC6_RESIDENCY_ENABLED,
	__I915_PMU_TRACKED_EVENT_COUNT, /* count marker */
};

enum {
	__I915_SAMPLE_FREQ_ACT = 0,
	__I915_SAMPLE_FREQ_REQ,
	__I915_SAMPLE_RC6,
	__I915_SAMPLE_RC6_LAST_REPORTED,
	__I915_NUM_PMU_SAMPLERS
};

#define I915_PMU_MASK_BITS \
	(I915_ENGINE_SAMPLE_COUNT + __I915_PMU_TRACKED_EVENT_COUNT)

#define I915_ENGINE_SAMPLE_COUNT (I915_SAMPLE_SEMA + 1)

struct i915_pmu_sample {
	u64 cur;
};

struct i915_pmu {
	/**
	 * @cpuhp: Struct used for CPU hotplug handling.
	 */
	struct {
		struct hlist_node node;
		unsigned int cpu;
	} cpuhp;
	/**
	 * @base: PMU base.
	 */
	struct pmu base;
	/**
	 * @closed: i915 is unregistering.
	 */
	bool closed;
	/**
	 * @name: Name as registered with perf core.
	 */
	const char *name;
	/**
	 * @lock: Lock protecting enable mask and ref count handling.
	 */
	spinlock_t lock;
	/**
	 * @timer: Timer for internal i915 PMU sampling.
	 */
	struct hrtimer timer;
	/**
	 * @enable: Bitmask of specific enabled events.
	 *
	 * For some events we need to track their state and do some internal
	 * house keeping.
	 *
	 * Each engine event sampler type and event listed in enum
	 * i915_pmu_tracked_events gets a bit in this field.
	 *
	 * Low bits are engine samplers and other events continue from there.
	 */
	u32 enable;

	/**
	 * @timer_last:
	 *
	 * Timestmap of the previous timer invocation.
	 */
	ktime_t timer_last;

	/**
	 * @enable_count: Reference counts for the enabled events.
	 *
	 * Array indices are mapped in the same way as bits in the @enable field
	 * and they are used to control sampling on/off when multiple clients
	 * are using the PMU API.
	 */
	unsigned int enable_count[I915_PMU_MASK_BITS];
	/**
	 * @timer_enabled: Should the internal sampling timer be running.
	 */
	bool timer_enabled;
	/**
	 * @sample: Current and previous (raw) counters for sampling events.
	 *
	 * These counters are updated from the i915 PMU sampling timer.
	 *
	 * Only global counters are held here, while the per-engine ones are in
	 * struct intel_engine_cs.
	 */
	struct i915_pmu_sample sample[__I915_NUM_PMU_SAMPLERS];
	/**
	 * @sleep_last: Last time GT parked for RC6 estimation.
	 */
	ktime_t sleep_last;
	/**
	 * @irq_count: Number of interrupts
	 *
	 * Intentionally unsigned long to avoid atomics or heuristics on 32bit.
	 * 4e9 interrupts are a lot and postprocessing can really deal with an
	 * occasional wraparound easily. It's 32bit after all.
	 */
	unsigned long irq_count;
	/**
	 * @events_attr_group: Device events attribute group.
	 */
	struct attribute_group events_attr_group;
	/**
	 * @i915_attr: Memory block holding device attributes.
	 */
	void *i915_attr;
	/**
	 * @pmu_attr: Memory block holding device attributes.
	 */
	void *pmu_attr;
};

/* klp-ccp: from drivers/gpu/drm/i915/i915_priolist_types.h */
#include <linux/list.h>
#include <linux/rbtree.h>
#include <uapi/drm/i915_drm.h>
/* klp-ccp: from drivers/gpu/drm/i915/i915_selftest.h */
#include <linux/types.h>

#define I915_SELFTEST_DECLARE(x)

/* klp-ccp: from drivers/gpu/drm/i915/gt/intel_sseu.h */
#include <linux/types.h>
#include <linux/kernel.h>

struct intel_gt;

#define GEN_MAX_HSW_SLICES		3

#define GEN_MAX_SS_PER_HSW_SLICE	8

#define I915_MAX_SS_FUSE_REGS	2
#define I915_MAX_SS_FUSE_BITS	(I915_MAX_SS_FUSE_REGS * 32)

typedef union {
	u8 hsw[GEN_MAX_HSW_SLICES];

	/* Bitmap compatible with linux/bitmap.h; may exceed size of u64 */
	unsigned long xehp[BITS_TO_LONGS(I915_MAX_SS_FUSE_BITS)];
} intel_sseu_ss_mask_t;

struct sseu_dev_info {
	u8 slice_mask;
	intel_sseu_ss_mask_t subslice_mask;
	intel_sseu_ss_mask_t geometry_subslice_mask;
	intel_sseu_ss_mask_t compute_subslice_mask;
	union {
		u16 hsw[GEN_MAX_HSW_SLICES][GEN_MAX_SS_PER_HSW_SLICE];
		u16 xehp[I915_MAX_SS_FUSE_BITS];
	} eu_mask;

	u16 eu_total;
	u8 eu_per_subslice;
	u8 min_eu_in_pool;
	/* For each slice, which subslice(s) has(have) 7 EUs (bitfield)? */
	u8 subslice_7eu[3];
	u8 has_slice_pg:1;
	u8 has_subslice_pg:1;
	u8 has_eu_pg:1;
	/*
	 * For Xe_HP and beyond, the hardware no longer has traditional slices
	 * so we just report the entire DSS pool under a fake "slice 0."
	 */
	u8 has_xehp_dss:1;

	/* Topology fields */
	u8 max_slices;
	u8 max_subslices;
	u8 max_eus_per_subslice;
};

struct intel_sseu {
	u8 slice_mask;
	u8 subslice_mask;
	u8 min_eus_per_subslice;
	u8 max_eus_per_subslice;
};

static u32 (*klpe_intel_sseu_make_rpcs)(struct intel_gt *gt,
			 const struct intel_sseu *req_sseu);

/* klp-ccp: from drivers/gpu/drm/i915/gt/intel_timeline_types.h */
#include <linux/list.h>
#include <linux/kref.h>
#include <linux/mutex.h>
#include <linux/rcupdate.h>
#include <linux/types.h>
/* klp-ccp: from drivers/gpu/drm/i915/intel_uncore.h */
#include <linux/spinlock.h>
#include <linux/notifier.h>
#include <linux/hrtimer.h>
#include <linux/io-64-nonatomic-lo-hi.h>
#include <linux/types.h>

/* klp-ccp: from include/linux/bitfield.h */
#define _LINUX_BITFIELD_H

/* klp-ccp: from drivers/gpu/drm/i915/i915_reg_defs.h */
#include <linux/bits.h>

typedef struct {
	u32 reg;
} i915_reg_t;

#define _MMIO(r) ((const i915_reg_t){ .reg = (r) })

static __always_inline u32 i915_mmio_reg_offset(i915_reg_t reg)
{
	return reg.reg;
}

/* klp-ccp: from drivers/gpu/drm/i915/intel_uncore.h */
struct intel_uncore;

struct intel_uncore_mmio_debug {
	spinlock_t lock; /** lock is also taken in irq contexts. */
	int unclaimed_mmio_check;
	int saved_mmio_check;
	u32 suspend_count;
};

enum forcewake_domain_id {
	FW_DOMAIN_ID_RENDER = 0,
	FW_DOMAIN_ID_GT,        /* also includes blitter engine */
	FW_DOMAIN_ID_MEDIA,
	FW_DOMAIN_ID_MEDIA_VDBOX0,
	FW_DOMAIN_ID_MEDIA_VDBOX1,
	FW_DOMAIN_ID_MEDIA_VDBOX2,
	FW_DOMAIN_ID_MEDIA_VDBOX3,
	FW_DOMAIN_ID_MEDIA_VDBOX4,
	FW_DOMAIN_ID_MEDIA_VDBOX5,
	FW_DOMAIN_ID_MEDIA_VDBOX6,
	FW_DOMAIN_ID_MEDIA_VDBOX7,
	FW_DOMAIN_ID_MEDIA_VEBOX0,
	FW_DOMAIN_ID_MEDIA_VEBOX1,
	FW_DOMAIN_ID_MEDIA_VEBOX2,
	FW_DOMAIN_ID_MEDIA_VEBOX3,

	FW_DOMAIN_ID_COUNT
};

enum forcewake_domains {
	FORCEWAKE_RENDER	= BIT(FW_DOMAIN_ID_RENDER),
	FORCEWAKE_GT		= BIT(FW_DOMAIN_ID_GT),
	FORCEWAKE_MEDIA		= BIT(FW_DOMAIN_ID_MEDIA),
	FORCEWAKE_MEDIA_VDBOX0	= BIT(FW_DOMAIN_ID_MEDIA_VDBOX0),
	FORCEWAKE_MEDIA_VDBOX1	= BIT(FW_DOMAIN_ID_MEDIA_VDBOX1),
	FORCEWAKE_MEDIA_VDBOX2	= BIT(FW_DOMAIN_ID_MEDIA_VDBOX2),
	FORCEWAKE_MEDIA_VDBOX3	= BIT(FW_DOMAIN_ID_MEDIA_VDBOX3),
	FORCEWAKE_MEDIA_VDBOX4	= BIT(FW_DOMAIN_ID_MEDIA_VDBOX4),
	FORCEWAKE_MEDIA_VDBOX5	= BIT(FW_DOMAIN_ID_MEDIA_VDBOX5),
	FORCEWAKE_MEDIA_VDBOX6	= BIT(FW_DOMAIN_ID_MEDIA_VDBOX6),
	FORCEWAKE_MEDIA_VDBOX7	= BIT(FW_DOMAIN_ID_MEDIA_VDBOX7),
	FORCEWAKE_MEDIA_VEBOX0	= BIT(FW_DOMAIN_ID_MEDIA_VEBOX0),
	FORCEWAKE_MEDIA_VEBOX1	= BIT(FW_DOMAIN_ID_MEDIA_VEBOX1),
	FORCEWAKE_MEDIA_VEBOX2	= BIT(FW_DOMAIN_ID_MEDIA_VEBOX2),
	FORCEWAKE_MEDIA_VEBOX3	= BIT(FW_DOMAIN_ID_MEDIA_VEBOX3),

	FORCEWAKE_ALL = BIT(FW_DOMAIN_ID_COUNT) - 1,
};

struct intel_uncore_funcs {
	enum forcewake_domains (*read_fw_domains)(struct intel_uncore *uncore,
						  i915_reg_t r);
	enum forcewake_domains (*write_fw_domains)(struct intel_uncore *uncore,
						   i915_reg_t r);

	u8 (*mmio_readb)(struct intel_uncore *uncore,
			 i915_reg_t r, bool trace);
	u16 (*mmio_readw)(struct intel_uncore *uncore,
			  i915_reg_t r, bool trace);
	u32 (*mmio_readl)(struct intel_uncore *uncore,
			  i915_reg_t r, bool trace);
	u64 (*mmio_readq)(struct intel_uncore *uncore,
			  i915_reg_t r, bool trace);

	void (*mmio_writeb)(struct intel_uncore *uncore,
			    i915_reg_t r, u8 val, bool trace);
	void (*mmio_writew)(struct intel_uncore *uncore,
			    i915_reg_t r, u16 val, bool trace);
	void (*mmio_writel)(struct intel_uncore *uncore,
			    i915_reg_t r, u32 val, bool trace);
};

struct intel_uncore {
	void __iomem *regs;

	struct drm_i915_private *i915;
	struct intel_gt *gt;
	struct intel_runtime_pm *rpm;

	spinlock_t lock; /** lock is also taken in irq contexts. */

	unsigned int flags;

	const struct intel_forcewake_range *fw_domains_table;
	unsigned int fw_domains_table_entries;

	/*
	 * Shadowed registers are special cases where we can safely write
	 * to the register *without* grabbing forcewake.
	 */
	const struct i915_range *shadowed_reg_table;
	unsigned int shadowed_reg_table_entries;

	struct notifier_block pmic_bus_access_nb;
	const struct intel_uncore_fw_get *fw_get_funcs;
	struct intel_uncore_funcs funcs;

	unsigned int fifo_count;

	enum forcewake_domains fw_domains;
	enum forcewake_domains fw_domains_active;
	enum forcewake_domains fw_domains_timer;
	enum forcewake_domains fw_domains_saved; /* user domains saved for S3 */

	struct intel_uncore_forcewake_domain {
		struct intel_uncore *uncore;
		enum forcewake_domain_id id;
		enum forcewake_domains mask;
		unsigned int wake_count;
		bool active;
		struct hrtimer timer;
		u32 __iomem *reg_set;
		u32 __iomem *reg_ack;
	} *fw_domain[FW_DOMAIN_ID_COUNT];

	unsigned int user_forcewake_count;

	struct intel_uncore_mmio_debug *debug;
};

#define __uncore_read(name__, x__, s__, trace__) \
static inline u##x__ intel_uncore_##name__(struct intel_uncore *uncore, \
					   i915_reg_t reg) \
{ \
	return uncore->funcs.mmio_read##s__(uncore, reg, (trace__)); \
}

#define __uncore_write(name__, x__, s__, trace__) \
static inline void intel_uncore_##name__(struct intel_uncore *uncore, \
					 i915_reg_t reg, u##x__ val) \
{ \
	uncore->funcs.mmio_write##s__(uncore, reg, val, (trace__)); \
}

__uncore_read(read, 32, l, true)

__uncore_write(write, 32, l, true)

static inline void intel_uncore_rmw(struct intel_uncore *uncore,
				    i915_reg_t reg, u32 clear, u32 set)
{
	u32 old, val;

	old = intel_uncore_read(uncore, reg);
	val = (old & ~clear) | set;
	if (val != old)
		intel_uncore_write(uncore, reg, val);
}

/* klp-ccp: from drivers/gpu/drm/i915/intel_wakeref.h */
#include <linux/atomic.h>
#include <linux/bitfield.h>
#include <linux/bits.h>
#include <linux/lockdep.h>
#include <linux/mutex.h>
#include <linux/refcount.h>
#include <linux/stackdepot.h>
#include <linux/timer.h>
#include <linux/workqueue.h>

typedef depot_stack_handle_t intel_wakeref_t;

struct intel_wakeref {
	atomic_t count;
	struct mutex mutex;

	intel_wakeref_t wakeref;

	struct intel_runtime_pm *rpm;
	const struct intel_wakeref_ops *ops;

	struct delayed_work work;
};

/* klp-ccp: from drivers/gpu/drm/i915/gt/intel_workarounds_types.h */
#include <linux/types.h>

struct i915_wa_list {
	const char	*name;
	const char	*engine_name;
	struct i915_wa	*list;
	unsigned int	count;
	unsigned int	wa_count;
};

/* klp-ccp: from drivers/gpu/drm/i915/gt/intel_engine_types.h */
#define RENDER_CLASS		0

#define MAX_ENGINE_CLASS	5
#define MAX_ENGINE_INSTANCE	8

#define I915_CMD_HASH_ORDER 9

typedef u32 intel_engine_mask_t;

struct intel_hw_status_page {
	struct list_head timelines;
	struct i915_vma *vma;
	u32 *addr;
};

struct i915_ctx_workarounds {
	struct i915_wa_ctx_bb {
		u32 offset;
		u32 size;
	} indirect_ctx, per_ctx;
	struct i915_vma *vma;
};

enum intel_engine_id {
	RCS0 = 0,
	BCS0,
	BCS1,
	BCS2,
	BCS3,
	BCS4,
	BCS5,
	BCS6,
	BCS7,
	BCS8,
	VCS0,
	VCS1,
	VCS2,
	VCS3,
	VCS4,
	VCS5,
	VCS6,
	VCS7,
	VECS0,
	VECS1,
	VECS2,
	VECS3,
	CCS0,
	CCS1,
	CCS2,
	CCS3,
	I915_NUM_ENGINES
};

struct ewma__engine_latency { unsigned long internal; };

struct intel_engine_execlists {
	/**
	 * @timer: kick the current context if its timeslice expires
	 */
	struct timer_list timer;

	/**
	 * @preempt: reset the current context if it fails to give way
	 */
	struct timer_list preempt;

	/**
	 * @preempt_target: active request at the time of the preemption request
	 *
	 * We force a preemption to occur if the pending contexts have not
	 * been promoted to active upon receipt of the CS ack event within
	 * the timeout. This timeout maybe chosen based on the target,
	 * using a very short timeout if the context is no longer schedulable.
	 * That short timeout may not be applicable to other contexts, so
	 * if a context switch should happen within before the preemption
	 * timeout, we may shoot early at an innocent context. To prevent this,
	 * we record which context was active at the time of the preemption
	 * request and only reset that context upon the timeout.
	 */
	const struct i915_request *preempt_target;

	/**
	 * @ccid: identifier for contexts submitted to this engine
	 */
	u32 ccid;

	/**
	 * @yield: CCID at the time of the last semaphore-wait interrupt.
	 *
	 * Instead of leaving a semaphore busy-spinning on an engine, we would
	 * like to switch to another ready context, i.e. yielding the semaphore
	 * timeslice.
	 */
	u32 yield;

	/**
	 * @error_interrupt: CS Master EIR
	 *
	 * The CS generates an interrupt when it detects an error. We capture
	 * the first error interrupt, record the EIR and schedule the tasklet.
	 * In the tasklet, we process the pending CS events to ensure we have
	 * the guilty request, and then reset the engine.
	 *
	 * Low 16b are used by HW, with the upper 16b used as the enabling mask.
	 * Reserve the upper 16b for tracking internal errors.
	 */
	u32 error_interrupt;

	/**
	 * @reset_ccid: Active CCID [EXECLISTS_STATUS_HI] at the time of reset
	 */
	u32 reset_ccid;

	/**
	 * @submit_reg: gen-specific execlist submission register
	 * set to the ExecList Submission Port (elsp) register pre-Gen11 and to
	 * the ExecList Submission Queue Contents register array for Gen11+
	 */
	u32 __iomem *submit_reg;

	/**
	 * @ctrl_reg: the enhanced execlists control register, used to load the
	 * submit queue on the HW and to request preemptions to idle
	 */
	u32 __iomem *ctrl_reg;

#define EXECLIST_MAX_PORTS 2
	struct i915_request * const *active;
	/**
	 * @inflight: the set of contexts submitted and acknowleged by HW
	 *
	 * The set of inflight contexts is managed by reading CS events
	 * from the HW. On a context-switch event (not preemption), we
	 * know the HW has transitioned from port0 to port1, and we
	 * advance our inflight/active tracking accordingly.
	 */
	struct i915_request *inflight[EXECLIST_MAX_PORTS + 1 /* sentinel */];
	/**
	 * @pending: the next set of contexts submitted to ELSP
	 *
	 * We store the array of contexts that we submit to HW (via ELSP) and
	 * promote them to the inflight array once HW has signaled the
	 * preemption or idle-to-active event.
	 */
	struct i915_request *pending[EXECLIST_MAX_PORTS + 1];

	/**
	 * @port_mask: number of execlist ports - 1
	 */
	unsigned int port_mask;

	/**
	 * @virtual: Queue of requets on a virtual engine, sorted by priority.
	 * Each RB entry is a struct i915_priolist containing a list of requests
	 * of the same priority.
	 */
	struct rb_root_cached virtual;

	/**
	 * @csb_write: control register for Context Switch buffer
	 *
	 * Note this register may be either mmio or HWSP shadow.
	 */
	u32 *csb_write;

	/**
	 * @csb_status: status array for Context Switch buffer
	 *
	 * Note these register may be either mmio or HWSP shadow.
	 */
	u64 *csb_status;

	/**
	 * @csb_size: context status buffer FIFO size
	 */
	u8 csb_size;

	/**
	 * @csb_head: context status buffer head
	 */
	u8 csb_head;

	I915_SELFTEST_DECLARE(struct st_preempt_hang preempt_hang;)
};

#define INTEL_ENGINE_CS_MAX_NAME 8

struct intel_engine_execlists_stats {
	/**
	 * @active: Number of contexts currently scheduled in.
	 */
	unsigned int active;

	/**
	 * @lock: Lock protecting the below fields.
	 */
	seqcount_t lock;

	/**
	 * @total: Total time this engine was busy.
	 *
	 * Accumulated time not counting the most recent block in cases where
	 * engine is currently busy (active > 0).
	 */
	ktime_t total;

	/**
	 * @start: Timestamp of the last idle to active transition.
	 *
	 * Idle is defined as active == 0, active is active > 0.
	 */
	ktime_t start;
};

struct intel_engine_guc_stats {
	/**
	 * @running: Active state of the engine when busyness was last sampled.
	 */
	bool running;

	/**
	 * @prev_total: Previous value of total runtime clock cycles.
	 */
	u32 prev_total;

	/**
	 * @total_gt_clks: Total gt clock cycles this engine was busy.
	 */
	u64 total_gt_clks;

	/**
	 * @start_gt_clk: GT clock time of last idle to active transition.
	 */
	u64 start_gt_clk;
};

struct intel_engine_cs {
	struct drm_i915_private *i915;
	struct intel_gt *gt;
	struct intel_uncore *uncore;
	char name[INTEL_ENGINE_CS_MAX_NAME];

	enum intel_engine_id id;
	enum intel_engine_id legacy_idx;

	unsigned int guc_id;

	intel_engine_mask_t mask;
	u32 reset_domain;
	/**
	 * @logical_mask: logical mask of engine, reported to user space via
	 * query IOCTL and used to communicate with the GuC in logical space.
	 * The logical instance of a physical engine can change based on product
	 * and fusing.
	 */
	intel_engine_mask_t logical_mask;

	u8 class;
	u8 instance;

	u16 uabi_class;
	u16 uabi_instance;

	u32 uabi_capabilities;
	u32 context_size;
	u32 mmio_base;

	/*
	 * Some w/a require forcewake to be held (which prevents RC6) while
	 * a particular engine is active. If so, we set fw_domain to which
	 * domains need to be held for the duration of request activity,
	 * and 0 if none. We try to limit the duration of the hold as much
	 * as possible.
	 */
	enum forcewake_domains fw_domain;
	unsigned int fw_active;

	unsigned long context_tag;

	struct rb_node uabi_node;

	struct intel_sseu sseu;

	struct i915_sched_engine *sched_engine;

	/* keep a request in reserve for a [pm] barrier under oom */
	struct i915_request *request_pool;

	struct intel_context *hung_ce;

	struct llist_head barrier_tasks;

	struct intel_context *kernel_context; /* pinned */

	/**
	 * pinned_contexts_list: List of pinned contexts. This list is only
	 * assumed to be manipulated during driver load- or unload time and
	 * does therefore not have any additional protection.
	 */
	struct list_head pinned_contexts_list;

	intel_engine_mask_t saturated; /* submitting semaphores too late? */

	struct {
		struct delayed_work work;
		struct i915_request *systole;
		unsigned long blocked;
	} heartbeat;

	unsigned long serial;

	unsigned long wakeref_serial;
	struct intel_wakeref wakeref;
	struct file *default_state;

	struct {
		struct intel_ring *ring;
		struct intel_timeline *timeline;
	} legacy;

	/*
	 * We track the average duration of the idle pulse on parking the
	 * engine to keep an estimate of the how the fast the engine is
	 * under ideal conditions.
	 */
	struct ewma__engine_latency latency;

	/* Keep track of all the seqno used, a trail of breadcrumbs */
	struct intel_breadcrumbs *breadcrumbs;

	struct intel_engine_pmu {
		/**
		 * @enable: Bitmask of enable sample events on this engine.
		 *
		 * Bits correspond to sample event types, for instance
		 * I915_SAMPLE_QUEUED is bit 0 etc.
		 */
		u32 enable;
		/**
		 * @enable_count: Reference count for the enabled samplers.
		 *
		 * Index number corresponds to @enum drm_i915_pmu_engine_sample.
		 */
		unsigned int enable_count[I915_ENGINE_SAMPLE_COUNT];
		/**
		 * @sample: Counter values for sampling events.
		 *
		 * Our internal timer stores the current counters in this field.
		 *
		 * Index number corresponds to @enum drm_i915_pmu_engine_sample.
		 */
		struct i915_pmu_sample sample[I915_ENGINE_SAMPLE_COUNT];
	} pmu;

	struct intel_hw_status_page status_page;
	struct i915_ctx_workarounds wa_ctx;
	struct i915_wa_list ctx_wa_list;
	struct i915_wa_list wa_list;
	struct i915_wa_list whitelist;

	u32             irq_keep_mask; /* always keep these interrupts */
	u32		irq_enable_mask; /* bitmask to enable ring interrupt */
	void		(*irq_enable)(struct intel_engine_cs *engine);
	void		(*irq_disable)(struct intel_engine_cs *engine);
	void		(*irq_handler)(struct intel_engine_cs *engine, u16 iir);

	void		(*sanitize)(struct intel_engine_cs *engine);
	int		(*resume)(struct intel_engine_cs *engine);

	struct {
		void (*prepare)(struct intel_engine_cs *engine);

		void (*rewind)(struct intel_engine_cs *engine, bool stalled);
		void (*cancel)(struct intel_engine_cs *engine);

		void (*finish)(struct intel_engine_cs *engine);
	} reset;

	void		(*park)(struct intel_engine_cs *engine);
	void		(*unpark)(struct intel_engine_cs *engine);

	void		(*bump_serial)(struct intel_engine_cs *engine);

	void		(*set_default_submission)(struct intel_engine_cs *engine);

	const struct intel_context_ops *cops;

	int		(*request_alloc)(struct i915_request *rq);

	int		(*emit_flush)(struct i915_request *request, u32 mode);
	int		(*emit_bb_start)(struct i915_request *rq,
					 u64 offset, u32 length,
					 unsigned int dispatch_flags);
	int		 (*emit_init_breadcrumb)(struct i915_request *rq);
	u32		*(*emit_fini_breadcrumb)(struct i915_request *rq,
						 u32 *cs);
	unsigned int	emit_fini_breadcrumb_dw;

	/* Pass the request to the hardware queue (e.g. directly into
	 * the legacy ringbuffer or to the end of an execlist).
	 *
	 * This is called from an atomic context with irqs disabled; must
	 * be irq safe.
	 */
	void		(*submit_request)(struct i915_request *rq);

	void		(*release)(struct intel_engine_cs *engine);

	/*
	 * Add / remove request from engine active tracking
	 */
	void		(*add_active_request)(struct i915_request *rq);
	void		(*remove_active_request)(struct i915_request *rq);

	/*
	 * Get engine busyness and the time at which the busyness was sampled.
	 */
	ktime_t		(*busyness)(struct intel_engine_cs *engine,
				    ktime_t *now);

	struct intel_engine_execlists execlists;

	/*
	 * Keep track of completed timelines on this engine for early
	 * retirement with the goal of quickly enabling powersaving as
	 * soon as the engine is idle.
	 */
	struct intel_timeline *retire;
	struct work_struct retire_work;

	/* status_notifier: list of callbacks for context-switch changes */
	struct atomic_notifier_head context_status_notifier;

	unsigned int flags;

	/*
	 * Table of commands the command parser needs to know about
	 * for this engine.
	 */
	DECLARE_HASHTABLE(cmd_hash, I915_CMD_HASH_ORDER);

	/*
	 * Table of registers allowed in commands that read/write registers.
	 */
	const struct drm_i915_reg_table *reg_tables;
	int reg_table_count;

	/*
	 * Returns the bitmask for the length field of the specified command.
	 * Return 0 for an unrecognized/invalid command.
	 *
	 * If the command parser finds an entry for a command in the engine's
	 * cmd_tables, it gets the command's length based on the table entry.
	 * If not, it calls this function to determine the per-engine length
	 * field encoding for the command (i.e. different opcode ranges use
	 * certain bits to encode the command length in the header).
	 */
	u32 (*get_cmd_length_mask)(u32 cmd_header);

	struct {
		union {
			struct intel_engine_execlists_stats execlists;
			struct intel_engine_guc_stats guc;
		};

		/**
		 * @rps: Utilisation at last RPS sampling.
		 */
		ktime_t rps;
	} stats;

	struct {
		unsigned long heartbeat_interval_ms;
		unsigned long max_busywait_duration_ns;
		unsigned long preempt_timeout_ms;
		unsigned long stop_timeout_ms;
		unsigned long timeslice_duration_ms;
	} props, defaults;

	I915_SELFTEST_DECLARE(struct fault_attr reset_timeout);
};

/* klp-ccp: from drivers/gpu/drm/i915/gt/uc/intel_guc_fwif.h */
#include <linux/bits.h>
#include <linux/compiler.h>
#include <linux/types.h>
/* klp-ccp: from drivers/gpu/drm/i915/gt/uc/abi/guc_actions_slpc_abi.h */
#include <linux/types.h>
/* klp-ccp: from drivers/gpu/drm/i915/gt/uc/abi/guc_communication_ctb_abi.h */
#include <linux/types.h>
#include <linux/build_bug.h>
/* klp-ccp: from drivers/gpu/drm/i915/gt/uc/abi/guc_klvs_abi.h */
#include <linux/types.h>

/* klp-ccp: from drivers/gpu/drm/i915/gt/uc/intel_guc_fwif.h */
#define GUC_CLIENT_PRIORITY_NUM		4

#define GUC_CTL_MAX_DWORDS		(SOFT_SCRATCH_COUNT - 2) /* [1..14] */

enum guc_log_buffer_type {
	GUC_DEBUG_LOG_BUFFER,
	GUC_CRASH_DUMP_LOG_BUFFER,
	GUC_CAPTURE_LOG_BUFFER,
	GUC_MAX_LOG_BUFFER
};

/* klp-ccp: from drivers/gpu/drm/i915/gt/intel_context_types.h */
struct ewma_runtime { unsigned long internal; };

struct i915_gem_ww_ctx;

struct intel_context_ops {
	unsigned long flags;


	int (*alloc)(struct intel_context *ce);

	void (*revoke)(struct intel_context *ce, struct i915_request *rq,
		       unsigned int preempt_timeout_ms);

	int (*pre_pin)(struct intel_context *ce, struct i915_gem_ww_ctx *ww, void **vaddr);
	int (*pin)(struct intel_context *ce, void *vaddr);
	void (*unpin)(struct intel_context *ce);
	void (*post_unpin)(struct intel_context *ce);

	void (*cancel_request)(struct intel_context *ce,
			       struct i915_request *rq);

	void (*enter)(struct intel_context *ce);
	void (*exit)(struct intel_context *ce);

	void (*sched_disable)(struct intel_context *ce);

	void (*reset)(struct intel_context *ce);
	void (*destroy)(struct kref *kref);

	/* virtual/parallel engine/context interface */
	struct intel_context *(*create_virtual)(struct intel_engine_cs **engine,
						unsigned int count,
						unsigned long flags);
	struct intel_context *(*create_parallel)(struct intel_engine_cs **engines,
						 unsigned int num_siblings,
						 unsigned int width);
	struct intel_engine_cs *(*get_sibling)(struct intel_engine_cs *engine,
					       unsigned int sibling);
};

struct intel_context {
	/*
	 * Note: Some fields may be accessed under RCU.
	 *
	 * Unless otherwise noted a field can safely be assumed to be protected
	 * by strong reference counting.
	 */
	union {
		struct kref ref; /* no kref_get_unless_zero()! */
		struct rcu_head rcu;
	};

	struct intel_engine_cs *engine;
	struct intel_engine_cs *inflight;

	struct i915_address_space *vm;
	struct i915_gem_context __rcu *gem_context;

	/*
	 * @signal_lock protects the list of requests that need signaling,
	 * @signals. While there are any requests that need signaling,
	 * we add the context to the breadcrumbs worker, and remove it
	 * upon completion/cancellation of the last request.
	 */
	struct list_head signal_link; /* Accessed under RCU */
	struct list_head signals; /* Guarded by signal_lock */
	spinlock_t signal_lock; /* protects signals, the list of requests */

	struct i915_vma *state;
	u32 ring_size;
	struct intel_ring *ring;
	struct intel_timeline *timeline;

	unsigned long flags;

	struct {
		u64 timeout_us;
	} watchdog;

	u32 *lrc_reg_state;
	union {
		struct {
			u32 lrca;
			u32 ccid;
		};
		u64 desc;
	} lrc;
	u32 tag; /* cookie passed to HW to track this context on submission */

	/** stats: Context GPU engine busyness tracking. */
	struct intel_context_stats {
		u64 active;

		/* Time on GPU as tracked by the hw. */
		struct {
			struct ewma_runtime avg;
			u64 total;
			u32 last;
			I915_SELFTEST_DECLARE(u32 num_underflow);
			I915_SELFTEST_DECLARE(u32 max_underflow);
		} runtime;
	} stats;

	unsigned int active_count; /* protected by timeline->mutex */

	atomic_t pin_count;
	struct mutex pin_mutex; /* guards pinning and associated on-gpuing */

	/**
	 * active: Active tracker for the rq activity (inc. external) on this
	 * intel_context object.
	 */
	struct i915_active active;

	const struct intel_context_ops *ops;

	/** sseu: Control eu/slice partitioning */
	struct intel_sseu sseu;

	/**
	 * pinned_contexts_link: List link for the engine's pinned contexts.
	 * This is only used if this is a perma-pinned kernel context and
	 * the list is assumed to only be manipulated during driver load
	 * or unload time so no mutex protection currently.
	 */
	struct list_head pinned_contexts_link;

	u8 wa_bb_page; /* if set, page num reserved for context workarounds */

	struct {
		/** @lock: protects everything in guc_state */
		spinlock_t lock;
		/**
		 * @sched_state: scheduling state of this context using GuC
		 * submission
		 */
		u32 sched_state;
		/*
		 * @fences: maintains a list of requests that are currently
		 * being fenced until a GuC operation completes
		 */
		struct list_head fences;
		/**
		 * @blocked: fence used to signal when the blocking of a
		 * context's submissions is complete.
		 */
		struct i915_sw_fence blocked;
		/** @number_committed_requests: number of committed requests */
		int number_committed_requests;
		/** @requests: list of active requests on this context */
		struct list_head requests;
		/** @prio: the context's current guc priority */
		u8 prio;
		/**
		 * @prio_count: a counter of the number requests in flight in
		 * each priority bucket
		 */
		u32 prio_count[GUC_CLIENT_PRIORITY_NUM];
	} guc_state;

	struct {
		/**
		 * @id: handle which is used to uniquely identify this context
		 * with the GuC, protected by guc->submission_state.lock
		 */
		u16 id;
		/**
		 * @ref: the number of references to the guc_id, when
		 * transitioning in and out of zero protected by
		 * guc->submission_state.lock
		 */
		atomic_t ref;
		/**
		 * @link: in guc->guc_id_list when the guc_id has no refs but is
		 * still valid, protected by guc->submission_state.lock
		 */
		struct list_head link;
	} guc_id;

	/**
	 * @destroyed_link: link in guc->submission_state.destroyed_contexts, in
	 * list when context is pending to be destroyed (deregistered with the
	 * GuC), protected by guc->submission_state.lock
	 */
	struct list_head destroyed_link;

	/** @parallel: sub-structure for parallel submission members */
	struct {
		union {
			/**
			 * @child_list: parent's list of children
			 * contexts, no protection as immutable after context
			 * creation
			 */
			struct list_head child_list;
			/**
			 * @child_link: child's link into parent's list of
			 * children
			 */
			struct list_head child_link;
		};
		/** @parent: pointer to parent if child */
		struct intel_context *parent;
		/**
		 * @last_rq: last request submitted on a parallel context, used
		 * to insert submit fences between requests in the parallel
		 * context
		 */
		struct i915_request *last_rq;
		/**
		 * @fence_context: fence context composite fence when doing
		 * parallel submission
		 */
		u64 fence_context;
		/**
		 * @seqno: seqno for composite fence when doing parallel
		 * submission
		 */
		u32 seqno;
		/** @number_children: number of children if parent */
		u8 number_children;
		/** @child_index: index into child_list if child */
		u8 child_index;
		/** @guc: GuC specific members for parallel submission */
		struct {
			/** @wqi_head: cached head pointer in work queue */
			u16 wqi_head;
			/** @wqi_tail: cached tail pointer in work queue */
			u16 wqi_tail;
			/** @wq_head: pointer to the actual head in work queue */
			u32 *wq_head;
			/** @wq_tail: pointer to the actual head in work queue */
			u32 *wq_tail;
			/** @wq_status: pointer to the status in work queue */
			u32 *wq_status;

			/**
			 * @parent_page: page in context state (ce->state) used
			 * by parent for work queue, process descriptor
			 */
			u8 parent_page;
		} guc;
	} parallel;

#ifdef CONFIG_DRM_I915_SELFTEST
#error "klp-ccp: non-taken branch"
#endif
};

/* klp-ccp: from drivers/gpu/drm/i915/i915_scheduler.h */
#include <linux/bitops.h>
#include <linux/list.h>
#include <linux/kernel.h>
/* klp-ccp: from drivers/gpu/drm/i915/i915_scheduler_types.h */
#include <linux/list.h>

struct i915_sched_attr {
	/**
	 * @priority: execution and service priority
	 *
	 * All clients are equal, but some are more equal than others!
	 *
	 * Requests from a context with a greater (more positive) value of
	 * @priority will be executed before those with a lower @priority
	 * value, forming a simple QoS.
	 *
	 * The &drm_i915_private.kernel_context is assigned the lowest priority.
	 */
	int priority;
};

/* klp-ccp: from drivers/gpu/drm/i915/i915_tasklet.h */
#include <linux/interrupt.h>

/* klp-ccp: from drivers/gpu/drm/i915/gem/i915_gem_context_types.h */
struct i915_gem_engines {
	union {
		/** @link: Link in i915_gem_context::stale::engines */
		struct list_head link;

		/** @rcu: RCU to use when freeing */
		struct rcu_head rcu;
	};

	/** @fence: Fence used for delayed destruction of engines */
	struct i915_sw_fence fence;

	/** @ctx: i915_gem_context backpointer */
	struct i915_gem_context *ctx;

	/** @num_engines: Number of engines in this set */
	unsigned int num_engines;

	/** @engines: Array of engines */
	struct intel_context *engines[];
};

struct i915_gem_engines_iter {
	/** @idx: Index into i915_gem_engines::engines */
	unsigned int idx;

	/** @engines: Engine set being iterated */
	const struct i915_gem_engines *engines;
};

struct i915_gem_context {
	/** @i915: i915 device backpointer */
	struct drm_i915_private *i915;

	/** @file_priv: owning file descriptor */
	struct drm_i915_file_private *file_priv;

	/**
	 * @engines: User defined engines for this context
	 *
	 * Various uAPI offer the ability to lookup up an
	 * index from this array to select an engine operate on.
	 *
	 * Multiple logically distinct instances of the same engine
	 * may be defined in the array, as well as composite virtual
	 * engines.
	 *
	 * Execbuf uses the I915_EXEC_RING_MASK as an index into this
	 * array to select which HW context + engine to execute on. For
	 * the default array, the user_ring_map[] is used to translate
	 * the legacy uABI onto the approprate index (e.g. both
	 * I915_EXEC_DEFAULT and I915_EXEC_RENDER select the same
	 * context, and I915_EXEC_BSD is weird). For a use defined
	 * array, execbuf uses I915_EXEC_RING_MASK as a plain index.
	 *
	 * User defined by I915_CONTEXT_PARAM_ENGINE (when the
	 * CONTEXT_USER_ENGINES flag is set).
	 */
	struct i915_gem_engines __rcu *engines;

	/** @engines_mutex: guards writes to engines */
	struct mutex engines_mutex;

	/**
	 * @syncobj: Shared timeline syncobj
	 *
	 * When the SHARED_TIMELINE flag is set on context creation, we
	 * emulate a single timeline across all engines using this syncobj.
	 * For every execbuffer2 call, this syncobj is used as both an in-
	 * and out-fence.  Unlike the real intel_timeline, this doesn't
	 * provide perfect atomic in-order guarantees if the client races
	 * with itself by calling execbuffer2 twice concurrently.  However,
	 * if userspace races with itself, that's not likely to yield well-
	 * defined results anyway so we choose to not care.
	 */
	struct drm_syncobj *syncobj;

	/**
	 * @vm: unique address space (GTT)
	 *
	 * In full-ppgtt mode, each context has its own address space ensuring
	 * complete seperation of one client from all others.
	 *
	 * In other modes, this is a NULL pointer with the expectation that
	 * the caller uses the shared global GTT.
	 */
	struct i915_address_space *vm;

	/**
	 * @pid: process id of creator
	 *
	 * Note that who created the context may not be the principle user,
	 * as the context may be shared across a local socket. However,
	 * that should only affect the default context, all contexts created
	 * explicitly by the client are expected to be isolated.
	 */
	struct pid *pid;

	/** @link: place with &drm_i915_private.context_list */
	struct list_head link;

	/** @client: struct i915_drm_client */
	struct i915_drm_client *client;

	/** @client_link: for linking onto &i915_drm_client.ctx_list */
	struct list_head client_link;

	/**
	 * @ref: reference count
	 *
	 * A reference to a context is held by both the client who created it
	 * and on each request submitted to the hardware using the request
	 * (to ensure the hardware has access to the state until it has
	 * finished all pending writes). See i915_gem_context_get() and
	 * i915_gem_context_put() for access.
	 */
	struct kref ref;

	/**
	 * @release_work:
	 *
	 * Work item for deferred cleanup, since i915_gem_context_put() tends to
	 * be called from hardirq context.
	 *
	 * FIXME: The only real reason for this is &i915_gem_engines.fence, all
	 * other callers are from process context and need at most some mild
	 * shuffling to pull the i915_gem_context_put() call out of a spinlock.
	 */
	struct work_struct release_work;

	/**
	 * @rcu: rcu_head for deferred freeing.
	 */
	struct rcu_head rcu;

	/**
	 * @user_flags: small set of booleans controlled by the user
	 */
	unsigned long user_flags;

	/**
	 * @flags: small set of booleans
	 */
	unsigned long flags;

	/**
	 * @uses_protected_content: context uses PXP-encrypted objects.
	 *
	 * This flag can only be set at ctx creation time and it's immutable for
	 * the lifetime of the context. See I915_CONTEXT_PARAM_PROTECTED_CONTENT
	 * in uapi/drm/i915_drm.h for more info on setting restrictions and
	 * expected behaviour of marked contexts.
	 */
	bool uses_protected_content;

	/**
	 * @pxp_wakeref: wakeref to keep the device awake when PXP is in use
	 *
	 * PXP sessions are invalidated when the device is suspended, which in
	 * turns invalidates all contexts and objects using it. To keep the
	 * flow simple, we keep the device awake when contexts using PXP objects
	 * are in use. It is expected that the userspace application only uses
	 * PXP when the display is on, so taking a wakeref here shouldn't worsen
	 * our power metrics.
	 */
	intel_wakeref_t pxp_wakeref;

	/** @mutex: guards everything that isn't engines or handles_vma */
	struct mutex mutex;

	/** @sched: scheduler parameters */
	struct i915_sched_attr sched;

	/** @guilty_count: How many times this context has caused a GPU hang. */
	atomic_t guilty_count;
	/**
	 * @active_count: How many times this context was active during a GPU
	 * hang, but did not cause it.
	 */
	atomic_t active_count;

	/**
	 * @hang_timestamp: The last time(s) this context caused a GPU hang
	 */
	unsigned long hang_timestamp[2];

	/** @remap_slice: Bitmask of cache lines that need remapping */
	u8 remap_slice;

	/**
	 * @handles_vma: rbtree to look up our context specific obj/vma for
	 * the user handle. (user handles are per fd, but the binding is
	 * per vm, which may be one per context or shared with the global GTT)
	 */
	struct radix_tree_root handles_vma;

	/** @lut_mutex: Locks handles_vma */
	struct mutex lut_mutex;

	/**
	 * @name: arbitrary name, used for user debug
	 *
	 * A name is constructed for the context from the creator's process
	 * name, pid and user handle in order to uniquely identify the
	 * context in messages.
	 */
	char name[TASK_COMM_LEN + 8];

	/** @stale: tracks stale engines to be destroyed */
	struct {
		/** @lock: guards engines */
		spinlock_t lock;
		/** @engines: list of stale engines */
		struct list_head engines;
	} stale;
};

/* klp-ccp: from drivers/gpu/drm/i915/gt/intel_context.h */
#include <linux/bitops.h>
#include <linux/lockdep.h>
#include <linux/types.h>
/* klp-ccp: from drivers/gpu/drm/i915/i915_active.h */
#include <linux/lockdep.h>
/* klp-ccp: from drivers/gpu/drm/i915/i915_request.h */
#include <linux/dma-fence.h>
#include <linux/hrtimer.h>
#include <linux/irq_work.h>
#include <linux/llist.h>
#include <linux/lockdep.h>
/* klp-ccp: from drivers/gpu/drm/i915/i915_vma_resource.h */
#include <linux/dma-fence.h>
#include <linux/refcount.h>
/* klp-ccp: from drivers/gpu/drm/i915/i915_scatterlist.h */
#include <linux/pfn.h>

/* klp-ccp: from include/linux/scatterlist.h */
#define _LINUX_SCATTERLIST_H

/* klp-ccp: from drivers/gpu/drm/i915/intel_runtime_pm.h */
#include <linux/types.h>

struct intel_runtime_pm {
	atomic_t wakeref_count;
	struct device *kdev; /* points to i915->drm.dev */
	bool available;
	bool suspended;
	bool irqs_enabled;
	bool no_wakeref_tracking;

#if IS_ENABLED(CONFIG_DRM_I915_DEBUG_RUNTIME_PM)
#error "klp-ccp: non-taken branch"
#endif
};

/* klp-ccp: from drivers/gpu/drm/i915/i915_vma_resource.h */
struct i915_page_sizes {
	/**
	 * The sg mask of the pages sg_table. i.e the mask of
	 * the lengths for each sg entry.
	 */
	unsigned int phys;

	/**
	 * The gtt page sizes we are allowed to use given the
	 * sg mask and the supported page sizes. This will
	 * express the smallest unit we can use for the whole
	 * object, as well as the larger sizes we may be able
	 * to use opportunistically.
	 */
	unsigned int sg;
};

struct i915_vma_resource {
	struct dma_fence unbind_fence;
	/* See above for description of the lock. */
	spinlock_t lock;
	refcount_t hold_count;
	struct work_struct work;
	struct i915_sw_fence chain;
	struct rb_node rb;
	u64 __subtree_last;
	struct i915_address_space *vm;
	intel_wakeref_t wakeref;

	/**
	 * struct i915_vma_bindinfo - Information needed for async bind
	 * only but that can be dropped after the bind has taken place.
	 * Consider making this a separate argument to the bind_vma
	 * op, coalescing with other arguments like vm, stash, cache_level
	 * and flags
	 * @pages: The pages sg-table.
	 * @page_sizes: Page sizes of the pages.
	 * @pages_rsgt: Refcounted sg-table when delayed object destruction
	 * is supported. May be NULL.
	 * @readonly: Whether the vma should be bound read-only.
	 * @lmem: Whether the vma points to lmem.
	 */
	struct i915_vma_bindinfo {
		struct sg_table *pages;
		struct i915_page_sizes page_sizes;
		struct i915_refct_sgt *pages_rsgt;
		bool readonly:1;
		bool lmem:1;
	} bi;

#if IS_ENABLED(CONFIG_DRM_I915_CAPTURE_ERROR)
	struct intel_memory_region *mr;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	const struct i915_vma_ops *ops;
	void *private;
	u64 start;
	u64 node_size;
	u64 vma_size;
	u32 page_sizes_gtt;

	u32 bound_flags;
	bool allocated:1;
	bool immediate_unbind:1;
	bool needs_wakeref:1;
	bool skip_pte_rewrite:1;

	u32 *tlb;
};

/* klp-ccp: from drivers/gpu/drm/i915/i915_request.h */
#include <uapi/drm/i915_drm.h>
/* klp-ccp: from drivers/gpu/drm/i915/i915_drv.h */
#include <uapi/drm/i915_drm.h>
#include <linux/pm_qos.h>
#include <drm/drm_connector.h>
#include <drm/ttm/ttm_device.h>
/* klp-ccp: from drivers/gpu/drm/i915/display/intel_cdclk.h */
#include <linux/types.h>
/* klp-ccp: from drivers/gpu/drm/i915/display/intel_display.h */
#include <drm/drm_util.h>

enum pipe {
	INVALID_PIPE = -1,

	PIPE_A = 0,
	PIPE_B,
	PIPE_C,
	PIPE_D,
	_PIPE_EDP,

	I915_MAX_PIPES = _PIPE_EDP
};

enum transcoder {
	INVALID_TRANSCODER = -1,
	/*
	 * The following transcoders have a 1:1 transcoder -> pipe mapping,
	 * keep their values fixed: the code assumes that TRANSCODER_A=0, the
	 * rest have consecutive values and match the enum values of the pipes
	 * they map to.
	 */
	TRANSCODER_A = PIPE_A,
	TRANSCODER_B = PIPE_B,
	TRANSCODER_C = PIPE_C,
	TRANSCODER_D = PIPE_D,

	/*
	 * The following transcoders can map to any pipe, their enum value
	 * doesn't need to stay fixed.
	 */
	TRANSCODER_EDP,
	TRANSCODER_DSI_0,
	TRANSCODER_DSI_1,
	TRANSCODER_DSI_A = TRANSCODER_DSI_0,	/* legacy DSI */
	TRANSCODER_DSI_C = TRANSCODER_DSI_1,	/* legacy DSI */

	I915_MAX_TRANSCODERS
};

enum plane_id {
	PLANE_PRIMARY,
	PLANE_SPRITE0,
	PLANE_SPRITE1,
	PLANE_SPRITE2,
	PLANE_SPRITE3,
	PLANE_SPRITE4,
	PLANE_SPRITE5,
	PLANE_CURSOR,

	I915_MAX_PLANES,
};

enum port {
	PORT_NONE = -1,

	PORT_A = 0,
	PORT_B,
	PORT_C,
	PORT_D,
	PORT_E,
	PORT_F,
	PORT_G,
	PORT_H,
	PORT_I,

	/* tgl+ */
	PORT_TC1 = PORT_D,
	PORT_TC2,
	PORT_TC3,
	PORT_TC4,
	PORT_TC5,
	PORT_TC6,

	/* XE_LPD repositions D/E offsets and bitfields */
	PORT_D_XELPD = PORT_TC5,
	PORT_E_XELPD,

	I915_MAX_PORTS
};

enum hpd_pin {
	HPD_NONE = 0,
	HPD_TV = HPD_NONE,     /* TV is known to be unreliable */
	HPD_CRT,
	HPD_SDVO_B,
	HPD_SDVO_C,
	HPD_PORT_A,
	HPD_PORT_B,
	HPD_PORT_C,
	HPD_PORT_D,
	HPD_PORT_E,
	HPD_PORT_TC1,
	HPD_PORT_TC2,
	HPD_PORT_TC3,
	HPD_PORT_TC4,
	HPD_PORT_TC5,
	HPD_PORT_TC6,

	HPD_NUM_PINS
};

/* klp-ccp: from drivers/gpu/drm/i915/display/intel_global_state.h */
#include <linux/kref.h>
#include <linux/list.h>

struct intel_global_obj {
	struct list_head head;
	struct intel_global_state *state;
	const struct intel_global_state_funcs *funcs;
};

/* klp-ccp: from drivers/gpu/drm/i915/display/intel_cdclk.h */
struct intel_cdclk_config {
	unsigned int cdclk, vco, ref, bypass;
	u8 voltage_level;
};

/* klp-ccp: from drivers/gpu/drm/i915/display/intel_display_power.h */
enum intel_display_power_domain {
	POWER_DOMAIN_DISPLAY_CORE,
	POWER_DOMAIN_PIPE_A,
	POWER_DOMAIN_PIPE_B,
	POWER_DOMAIN_PIPE_C,
	POWER_DOMAIN_PIPE_D,
	POWER_DOMAIN_PIPE_PANEL_FITTER_A,
	POWER_DOMAIN_PIPE_PANEL_FITTER_B,
	POWER_DOMAIN_PIPE_PANEL_FITTER_C,
	POWER_DOMAIN_PIPE_PANEL_FITTER_D,
	POWER_DOMAIN_TRANSCODER_A,
	POWER_DOMAIN_TRANSCODER_B,
	POWER_DOMAIN_TRANSCODER_C,
	POWER_DOMAIN_TRANSCODER_D,
	POWER_DOMAIN_TRANSCODER_EDP,
	POWER_DOMAIN_TRANSCODER_DSI_A,
	POWER_DOMAIN_TRANSCODER_DSI_C,

	/* VDSC/joining for eDP/DSI transcoder (ICL) or pipe A (TGL) */
	POWER_DOMAIN_TRANSCODER_VDSC_PW2,

	POWER_DOMAIN_PORT_DDI_LANES_A,
	POWER_DOMAIN_PORT_DDI_LANES_B,
	POWER_DOMAIN_PORT_DDI_LANES_C,
	POWER_DOMAIN_PORT_DDI_LANES_D,
	POWER_DOMAIN_PORT_DDI_LANES_E,
	POWER_DOMAIN_PORT_DDI_LANES_F,

	POWER_DOMAIN_PORT_DDI_LANES_TC1,
	POWER_DOMAIN_PORT_DDI_LANES_TC2,
	POWER_DOMAIN_PORT_DDI_LANES_TC3,
	POWER_DOMAIN_PORT_DDI_LANES_TC4,
	POWER_DOMAIN_PORT_DDI_LANES_TC5,
	POWER_DOMAIN_PORT_DDI_LANES_TC6,

	POWER_DOMAIN_PORT_DDI_IO_A,
	POWER_DOMAIN_PORT_DDI_IO_B,
	POWER_DOMAIN_PORT_DDI_IO_C,
	POWER_DOMAIN_PORT_DDI_IO_D,
	POWER_DOMAIN_PORT_DDI_IO_E,
	POWER_DOMAIN_PORT_DDI_IO_F,

	POWER_DOMAIN_PORT_DDI_IO_TC1,
	POWER_DOMAIN_PORT_DDI_IO_TC2,
	POWER_DOMAIN_PORT_DDI_IO_TC3,
	POWER_DOMAIN_PORT_DDI_IO_TC4,
	POWER_DOMAIN_PORT_DDI_IO_TC5,
	POWER_DOMAIN_PORT_DDI_IO_TC6,

	POWER_DOMAIN_PORT_DSI,
	POWER_DOMAIN_PORT_CRT,
	POWER_DOMAIN_PORT_OTHER,
	POWER_DOMAIN_VGA,
	POWER_DOMAIN_AUDIO_MMIO,
	POWER_DOMAIN_AUDIO_PLAYBACK,
	POWER_DOMAIN_AUX_A,
	POWER_DOMAIN_AUX_B,
	POWER_DOMAIN_AUX_C,
	POWER_DOMAIN_AUX_D,
	POWER_DOMAIN_AUX_E,
	POWER_DOMAIN_AUX_F,

	POWER_DOMAIN_AUX_USBC1,
	POWER_DOMAIN_AUX_USBC2,
	POWER_DOMAIN_AUX_USBC3,
	POWER_DOMAIN_AUX_USBC4,
	POWER_DOMAIN_AUX_USBC5,
	POWER_DOMAIN_AUX_USBC6,

	POWER_DOMAIN_AUX_IO_A,

	POWER_DOMAIN_AUX_TBT1,
	POWER_DOMAIN_AUX_TBT2,
	POWER_DOMAIN_AUX_TBT3,
	POWER_DOMAIN_AUX_TBT4,
	POWER_DOMAIN_AUX_TBT5,
	POWER_DOMAIN_AUX_TBT6,

	POWER_DOMAIN_GMBUS,
	POWER_DOMAIN_MODESET,
	POWER_DOMAIN_GT_IRQ,
	POWER_DOMAIN_DC_OFF,
	POWER_DOMAIN_TC_COLD_OFF,
	POWER_DOMAIN_INIT,

	POWER_DOMAIN_NUM,
	POWER_DOMAIN_INVALID = POWER_DOMAIN_NUM,
};

struct intel_power_domain_mask {
	DECLARE_BITMAP(bits, POWER_DOMAIN_NUM);
};

struct i915_power_domains {
	/*
	 * Power wells needed for initialization at driver init and suspend
	 * time are on. They are kept on until after the first modeset.
	 */
	bool initializing;
	bool display_core_suspended;
	int power_well_count;

	intel_wakeref_t init_wakeref;
	intel_wakeref_t disable_wakeref;

	struct mutex lock;
	int domain_use_count[POWER_DOMAIN_NUM];

	struct delayed_work async_put_work;
	intel_wakeref_t async_put_wakeref;
	struct intel_power_domain_mask async_put_domains[2];

	struct i915_power_well *power_wells;
};

/* klp-ccp: from drivers/gpu/drm/i915/display/intel_dmc.h */
#include <linux/workqueue.h>

enum {
	DMC_FW_MAIN = 0,
	DMC_FW_PIPEA,
	DMC_FW_PIPEB,
	DMC_FW_PIPEC,
	DMC_FW_PIPED,
	DMC_FW_MAX
};

struct intel_dmc {
	struct work_struct work;
	const char *fw_path;
	u32 required_version;
	u32 max_fw_size; /* bytes */
	u32 version;
	struct dmc_fw_info {
		u32 mmio_count;
		i915_reg_t mmioaddr[20];
		u32 mmiodata[20];
		u32 dmc_offset;
		u32 start_mmioaddr;
		u32 dmc_fw_size; /*dwords */
		u32 *payload;
		bool present;
	} dmc_info[DMC_FW_MAX];

	u32 dc_state;
	u32 target_dc_state;
	u32 allowed_dc_mask;
	intel_wakeref_t wakeref;
};

/* klp-ccp: from drivers/gpu/drm/i915/display/intel_dpll_mgr.h */
#include <linux/types.h>

#define I915_NUM_PLLS 9

struct intel_dpll_hw_state {
	/* i9xx, pch plls */
	u32 dpll;
	u32 dpll_md;
	u32 fp0;
	u32 fp1;

	/* hsw, bdw */
	u32 wrpll;
	u32 spll;

	/* skl */
	/*
	 * DPLL_CTRL1 has 6 bits for each each this DPLL. We store those in
	 * lower part of ctrl1 and they get shifted into position when writing
	 * the register.  This allows us to easily compare the state to share
	 * the DPLL.
	 */
	u32 ctrl1;
	/* HDMI only, 0 when used for DP */
	u32 cfgcr1, cfgcr2;

	/* icl */
	u32 cfgcr0;

	/* tgl */
	u32 div0;

	/* bxt */
	u32 ebb0, ebb4, pll0, pll1, pll2, pll3, pll6, pll8, pll9, pll10, pcsdw12;

	/*
	 * ICL uses the following, already defined:
	 * u32 cfgcr0, cfgcr1;
	 */
	u32 mg_refclkin_ctl;
	u32 mg_clktop2_coreclkctl1;
	u32 mg_clktop2_hsclkctl;
	u32 mg_pll_div0;
	u32 mg_pll_div1;
	u32 mg_pll_lf;
	u32 mg_pll_frac_lock;
	u32 mg_pll_ssc;
	u32 mg_pll_bias;
	u32 mg_pll_tdc_coldst_bias;
	u32 mg_pll_bias_mask;
	u32 mg_pll_tdc_coldst_bias_mask;
};

struct intel_shared_dpll_state {
	/**
	 * @pipe_mask: mask of pipes using this DPLL, active or not
	 */
	u8 pipe_mask;

	/**
	 * @hw_state: hardware configuration for the DPLL stored in
	 * struct &intel_dpll_hw_state.
	 */
	struct intel_dpll_hw_state hw_state;
};

struct intel_shared_dpll {
	/**
	 * @state:
	 *
	 * Store the state for the pll, including its hw state
	 * and CRTCs using it.
	 */
	struct intel_shared_dpll_state state;

	/**
	 * @active_mask: mask of active pipes (i.e. DPMS on) using this DPLL
	 */
	u8 active_mask;

	/**
	 * @on: is the PLL actually active? Disabled during modeset
	 */
	bool on;

	/**
	 * @info: platform specific info
	 */
	const struct dpll_info *info;

	/**
	 * @wakeref: In some platforms a device-level runtime pm reference may
	 * need to be grabbed to disable DC states while this DPLL is enabled
	 */
	intel_wakeref_t wakeref;
};

/* klp-ccp: from drivers/gpu/drm/i915/display/intel_dsb.h */
#include <linux/types.h>
/* klp-ccp: from drivers/gpu/drm/i915/display/intel_fbc.h */
#include <linux/types.h>

enum intel_fbc_id {
	INTEL_FBC_A,

	I915_MAX_FBCS,
};

/* klp-ccp: from drivers/gpu/drm/i915/display/intel_frontbuffer.h */
#include <linux/atomic.h>
#include <linux/kref.h>
/* klp-ccp: from drivers/gpu/drm/i915/gem/i915_gem_object_types.h */
#include <drm/drm_gem.h>
#include <uapi/drm/i915_drm.h>
/* klp-ccp: from drivers/gpu/drm/i915/display/intel_gmbus.h */
#include <linux/types.h>

#define GMBUS_NUM_PINS	15 /* including 0 */

/* klp-ccp: from drivers/gpu/drm/i915/display/intel_opregion.h */
#include <linux/workqueue.h>

struct intel_opregion {
	struct opregion_header *header;
	struct opregion_acpi *acpi;
	struct opregion_swsci *swsci;
	u32 swsci_gbda_sub_functions;
	u32 swsci_sbcb_sub_functions;
	struct opregion_asle *asle;
	struct opregion_asle_ext *asle_ext;
	void *rvda;
	void *vbt_firmware;
	const void *vbt;
	u32 vbt_size;
	u32 *lid_state;
	struct work_struct asle_work;
	struct notifier_block acpi_notifier;
};

/* klp-ccp: from drivers/gpu/drm/i915/gem/i915_gem_lmem.h */
#include <linux/types.h>
/* klp-ccp: from drivers/gpu/drm/i915/gem/i915_gem_shrinker.h */
#include <linux/bits.h>
/* klp-ccp: from drivers/gpu/drm/i915/gem/i915_gem_stolen.h */
#include <linux/types.h>
/* klp-ccp: from drivers/gpu/drm/i915/gt/intel_engine.h */
#include <drm/drm_util.h>
#include <linux/hashtable.h>
#include <linux/irq_work.h>
#include <linux/random.h>
#include <linux/seqlock.h>
/* klp-ccp: from drivers/gpu/drm/i915/gt/intel_gt_types.h */
#include <linux/ktime.h>
#include <linux/list.h>
#include <linux/llist.h>
#include <linux/mutex.h>
#include <linux/notifier.h>
#include <linux/seqlock.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/workqueue.h>
/* klp-ccp: from drivers/gpu/drm/i915/gt/uc/intel_guc.h */
#include <linux/iosys-map.h>
#include <linux/xarray.h>
/* klp-ccp: from drivers/gpu/drm/i915/gt/uc/intel_guc_ct.h */
#include <linux/interrupt.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>
#include <linux/ktime.h>
#include <linux/wait.h>

struct intel_guc_ct_buffer {
	spinlock_t lock;
	struct guc_ct_buffer_desc *desc;
	u32 *cmds;
	u32 size;
	u32 resv_space;
	u32 tail;
	u32 head;
	atomic_t space;
	bool broken;
};

struct intel_guc_ct {
	struct i915_vma *vma;
	bool enabled;

	/* buffers for sending and receiving commands */
	struct {
		struct intel_guc_ct_buffer send;
		struct intel_guc_ct_buffer recv;
	} ctbs;

	struct tasklet_struct receive_tasklet;

	/** @wq: wait queue for g2h chanenl */
	wait_queue_head_t wq;

	struct {
		u16 last_fence; /* last fence used to send request */

		spinlock_t lock; /* protects pending requests list */
		struct list_head pending; /* requests waiting for response */

		struct list_head incoming; /* incoming requests */
		struct work_struct worker; /* handler for incoming requests */
	} requests;

	/** @stall_time: time of first time a CTB submission is stalled */
	ktime_t stall_time;
};

/* klp-ccp: from drivers/gpu/drm/i915/gt/uc/intel_guc_log.h */
#include <linux/mutex.h>

/* klp-ccp: from include/linux/poll.h */
#define _LINUX_POLL_H

/* klp-ccp: from drivers/gpu/drm/i915/gt/uc/intel_guc_log.h */
#include <linux/workqueue.h>

struct intel_guc_log {
	u32 level;
	struct i915_vma *vma;
	void *buf_addr;
	struct {
		bool buf_in_use;
		bool started;
		struct work_struct flush_work;
		struct rchan *channel;
		struct mutex lock;
		u32 full_count;
	} relay;
	/* logging related stats */
	struct {
		u32 sampled_overflow;
		u32 overflow;
		u32 flush;
	} stats[GUC_MAX_LOG_BUFFER];
};

/* klp-ccp: from drivers/gpu/drm/i915/gt/uc/intel_guc_reg.h */
#include <linux/compiler.h>
#include <linux/types.h>

#define SOFT_SCRATCH_COUNT		16

/* klp-ccp: from drivers/gpu/drm/i915/gt/uc/intel_guc_slpc_types.h */
#include <linux/atomic.h>
#include <linux/workqueue.h>
#include <linux/mutex.h>
#include <linux/types.h>

struct intel_guc_slpc {
	struct i915_vma *vma;
	struct slpc_shared_data *vaddr;
	bool supported;
	bool selected;

	/* platform frequency limits */
	u32 min_freq;
	u32 rp0_freq;
	u32 rp1_freq;
	u32 boost_freq;

	/* frequency softlimits */
	u32 min_freq_softlimit;
	u32 max_freq_softlimit;

	/* cached media ratio mode */
	u32 media_ratio_mode;

	/* Protects set/reset of boost freq
	 * and value of num_waiters
	 */
	struct mutex lock;

	struct work_struct boost_work;
	atomic_t num_waiters;
	u32 num_boosts;
};

/* klp-ccp: from drivers/gpu/drm/i915/gt/uc/intel_uc_fw.h */
#include <linux/types.h>
/* klp-ccp: from drivers/gpu/drm/i915/gt/uc/intel_uc_fw_abi.h */
#include <linux/types.h>
#include <linux/build_bug.h>
/* klp-ccp: from drivers/gpu/drm/i915/intel_device_info.h */
#include <uapi/drm/i915_drm.h>
/* klp-ccp: from drivers/gpu/drm/i915/intel_step.h */
#include <linux/types.h>

struct intel_step_info {
	u8 graphics_step;	/* Represents the compute tile on Xe_HPC */
	u8 display_step;
	u8 media_step;
	u8 basedie_step;
};

/* klp-ccp: from drivers/gpu/drm/i915/intel_device_info.h */
enum intel_platform {
	INTEL_PLATFORM_UNINITIALIZED = 0,
	/* gen2 */
	INTEL_I830,
	INTEL_I845G,
	INTEL_I85X,
	INTEL_I865G,
	/* gen3 */
	INTEL_I915G,
	INTEL_I915GM,
	INTEL_I945G,
	INTEL_I945GM,
	INTEL_G33,
	INTEL_PINEVIEW,
	/* gen4 */
	INTEL_I965G,
	INTEL_I965GM,
	INTEL_G45,
	INTEL_GM45,
	/* gen5 */
	INTEL_IRONLAKE,
	/* gen6 */
	INTEL_SANDYBRIDGE,
	/* gen7 */
	INTEL_IVYBRIDGE,
	INTEL_VALLEYVIEW,
	INTEL_HASWELL,
	/* gen8 */
	INTEL_BROADWELL,
	INTEL_CHERRYVIEW,
	/* gen9 */
	INTEL_SKYLAKE,
	INTEL_BROXTON,
	INTEL_KABYLAKE,
	INTEL_GEMINILAKE,
	INTEL_COFFEELAKE,
	INTEL_COMETLAKE,
	/* gen11 */
	INTEL_ICELAKE,
	INTEL_ELKHARTLAKE,
	INTEL_JASPERLAKE,
	/* gen12 */
	INTEL_TIGERLAKE,
	INTEL_ROCKETLAKE,
	INTEL_DG1,
	INTEL_ALDERLAKE_S,
	INTEL_ALDERLAKE_P,
	INTEL_XEHPSDV,
	INTEL_DG2,
	INTEL_PONTEVECCHIO,
	INTEL_METEORLAKE,
	INTEL_MAX_PLATFORMS
};

enum intel_ppgtt_type {
	INTEL_PPGTT_NONE = I915_GEM_PPGTT_NONE,
	INTEL_PPGTT_ALIASING = I915_GEM_PPGTT_ALIASING,
	INTEL_PPGTT_FULL = I915_GEM_PPGTT_FULL,
};

#define DEV_INFO_FOR_EACH_FLAG(func) \
	func(is_mobile); \
	func(is_lp); \
	func(require_force_probe); \
	func(is_dgfx); \
	/* Keep has_* in alphabetical order */ \
	func(has_64bit_reloc); \
	func(has_64k_pages); \
	func(needs_compact_pt); \
	func(gpu_reset_clobbers_display); \
	func(has_reset_engine); \
	func(has_3d_pipeline); \
	func(has_4tile); \
	func(has_flat_ccs); \
	func(has_global_mocs); \
	func(has_gt_uc); \
	func(has_heci_pxp); \
	func(has_heci_gscfi); \
	func(has_guc_deprivilege); \
	func(has_l3_ccs_read); \
	func(has_l3_dpf); \
	func(has_llc); \
	func(has_logical_ring_contexts); \
	func(has_logical_ring_elsq); \
	func(has_media_ratio_mode); \
	func(has_mslice_steering); \
	func(has_one_eu_per_fuse_bit); \
	func(has_pooled_eu); \
	func(has_pxp); \
	func(has_rc6); \
	func(has_rc6p); \
	func(has_rps); \
	func(has_runtime_pm); \
	func(has_snoop); \
	func(has_coherent_ggtt); \
	func(unfenced_needs_alignment); \
	func(hws_needs_physical);

#define DEV_INFO_DISPLAY_FOR_EACH_FLAG(func) \
	/* Keep in alphabetical order */ \
	func(cursor_needs_physical); \
	func(has_cdclk_crawl); \
	func(has_dmc); \
	func(has_ddi); \
	func(has_dp_mst); \
	func(has_dsb); \
	func(has_dsc); \
	func(has_fpga_dbg); \
	func(has_gmch); \
	func(has_hdcp); \
	func(has_hotplug); \
	func(has_hti); \
	func(has_ipc); \
	func(has_modular_fia); \
	func(has_overlay); \
	func(has_psr); \
	func(has_psr_hw_tracking); \
	func(overlay_needs_physical); \
	func(supports_tv);

struct ip_version {
	u8 ver;
	u8 rel;
};

struct intel_device_info {
	struct ip_version graphics;
	struct ip_version media;

	intel_engine_mask_t platform_engine_mask; /* Engines supported by the HW */

	enum intel_platform platform;

	unsigned int dma_mask_size; /* available DMA address bits */

	enum intel_ppgtt_type ppgtt_type;
	unsigned int ppgtt_size; /* log2, e.g. 31/32/48 bits */

	unsigned int page_sizes; /* page sizes supported by the HW */

	u32 memory_regions; /* regions supported by the HW */

	u8 gt; /* GT number, 0 if undefined */

#define DEFINE_FLAG(name) u8 name:1
	DEV_INFO_FOR_EACH_FLAG(DEFINE_FLAG);

	struct {
		u8 ver;
		u8 rel;

		u8 pipe_mask;
		u8 cpu_transcoder_mask;
		u8 fbc_mask;
		u8 abox_mask;

		struct {
			u16 size; /* in blocks */
			u8 slice_mask;
		} dbuf;

		DEV_INFO_DISPLAY_FOR_EACH_FLAG(DEFINE_FLAG);

		/* Global register offset for the display engine */
		u32 mmio_offset;

		/* Register offsets for the various display pipes and transcoders */
		u32 pipe_offsets[I915_MAX_TRANSCODERS];
		u32 trans_offsets[I915_MAX_TRANSCODERS];
		u32 cursor_offsets[I915_MAX_PIPES];

		struct {
			u32 degamma_lut_size;
			u32 gamma_lut_size;
			u32 degamma_lut_tests;
			u32 gamma_lut_tests;
		} color;
	} display;
};

struct intel_runtime_info {
	/*
	 * Platform mask is used for optimizing or-ed IS_PLATFORM calls into
	 * into single runtime conditionals, and also to provide groundwork
	 * for future per platform, or per SKU build optimizations.
	 *
	 * Array can be extended when necessary if the corresponding
	 * BUILD_BUG_ON is hit.
	 */
	u32 platform_mask[2];

	u16 device_id;

	u8 num_sprites[I915_MAX_PIPES];
	u8 num_scalers[I915_MAX_PIPES];

	u32 rawclk_freq;

	struct intel_step_info step;
};

struct intel_driver_caps {
	unsigned int scheduler;
	bool has_logical_contexts:1;
};

/* klp-ccp: from drivers/gpu/drm/i915/i915_vma.h */
#include <linux/rbtree.h>
#include <drm/drm_mm.h>
/* klp-ccp: from drivers/gpu/drm/i915/gt/intel_ggtt_fencing.h */
#include <linux/list.h>
#include <linux/types.h>
/* klp-ccp: from drivers/gpu/drm/i915/gem/i915_gem_object.h */
#include <drm/drm_gem.h>
#include <drm/drm_device.h>
/* klp-ccp: from drivers/gpu/drm/i915/intel_memory_region.h */
#include <linux/ioport.h>
#include <linux/mutex.h>
#include <drm/drm_mm.h>
#include <uapi/drm/i915_drm.h>

enum intel_region_id {
	INTEL_REGION_SMEM = 0,
	INTEL_REGION_LMEM_0,
	INTEL_REGION_LMEM_1,
	INTEL_REGION_LMEM_2,
	INTEL_REGION_LMEM_3,
	INTEL_REGION_STOLEN_SMEM,
	INTEL_REGION_STOLEN_LMEM,
	INTEL_REGION_UNKNOWN, /* Should be last */
};

/* klp-ccp: from drivers/gpu/drm/i915/i915_gem_gtt.h */
#include <linux/types.h>
#include <drm/drm_mm.h>
/* klp-ccp: from drivers/gpu/drm/i915/gt/intel_gtt.h */
#include <linux/kref.h>
#include <linux/mm.h>
#include <linux/scatterlist.h>
#include <linux/workqueue.h>
#include <drm/drm_mm.h>
/* klp-ccp: from drivers/gpu/drm/i915/gt/intel_reset.h */
#include <linux/compiler.h>
#include <linux/types.h>
#include <linux/srcu.h>
/* klp-ccp: from drivers/gpu/drm/i915/gt/intel_reset_types.h */
#include <linux/mutex.h>
#include <linux/wait.h>
#include <linux/srcu.h>

struct intel_reset {
	/**
	 * flags: Control various stages of the GPU reset
	 *
	 * #I915_RESET_BACKOFF - When we start a global reset, we need to
	 * serialise with any other users attempting to do the same, and
	 * any global resources that may be clobber by the reset (such as
	 * FENCE registers).
	 *
	 * #I915_RESET_ENGINE[num_engines] - Since the driver doesn't need to
	 * acquire the struct_mutex to reset an engine, we need an explicit
	 * flag to prevent two concurrent reset attempts in the same engine.
	 * As the number of engines continues to grow, allocate the flags from
	 * the most significant bits.
	 *
	 * #I915_WEDGED - If reset fails and we can no longer use the GPU,
	 * we set the #I915_WEDGED bit. Prior to command submission, e.g.
	 * i915_request_alloc(), this bit is checked and the sequence
	 * aborted (with -EIO reported to userspace) if set.
	 *
	 * #I915_WEDGED_ON_INIT - If we fail to initialize the GPU we can no
	 * longer use the GPU - similar to #I915_WEDGED bit. The difference in
	 * the way we're handling "forced" unwedged (e.g. through debugfs),
	 * which is not allowed in case we failed to initialize.
	 *
	 * #I915_WEDGED_ON_FINI - Similar to #I915_WEDGED_ON_INIT, except we
	 * use it to mark that the GPU is no longer available (and prevent
	 * users from using it).
	 */
	unsigned long flags;

	struct mutex mutex; /* serialises wedging/unwedging */

	/**
	 * Waitqueue to signal when the reset has completed. Used by clients
	 * that wait for dev_priv->mm.wedged to settle.
	 */
	wait_queue_head_t queue;

	struct srcu_struct backoff_srcu;
};

/* klp-ccp: from drivers/gpu/drm/i915/i915_vma_types.h */
#include <linux/rbtree.h>
#include <drm/drm_mm.h>
/* klp-ccp: from drivers/gpu/drm/i915/i915_params.h */
#include <linux/bitops.h>
#include <linux/cache.h> /* for __read_mostly */

#define I915_PARAMS_FOR_EACH(param) \
	param(char *, vbt_firmware, NULL, 0400) \
	param(int, modeset, -1, 0400) \
	param(int, lvds_channel_mode, 0, 0400) \
	param(int, panel_use_ssc, -1, 0600) \
	param(int, vbt_sdvo_panel_type, -1, 0400) \
	param(int, enable_dc, -1, 0400) \
	param(int, enable_fbc, -1, 0600) \
	param(int, enable_psr, -1, 0600) \
	param(bool, psr_safest_params, false, 0400) \
	param(bool, enable_psr2_sel_fetch, true, 0400) \
	param(int, disable_power_well, -1, 0400) \
	param(int, enable_ips, 1, 0600) \
	param(int, invert_brightness, 0, 0600) \
	param(int, enable_guc, -1, 0400) \
	param(int, guc_log_level, -1, 0400) \
	param(char *, guc_firmware_path, NULL, 0400) \
	param(char *, huc_firmware_path, NULL, 0400) \
	param(char *, dmc_firmware_path, NULL, 0400) \
	param(bool, memtest, false, 0400) \
	param(int, mmio_debug, -IS_ENABLED(CONFIG_DRM_I915_DEBUG_MMIO), 0600) \
	param(int, edp_vswing, 0, 0400) \
	param(unsigned int, reset, 3, 0600) \
	param(unsigned int, inject_probe_failure, 0, 0) \
	param(int, fastboot, -1, 0600) \
	param(int, enable_dpcd_backlight, -1, 0600) \
	param(char *, force_probe, CONFIG_DRM_I915_FORCE_PROBE, 0400) \
	param(unsigned int, request_timeout_ms, CONFIG_DRM_I915_REQUEST_TIMEOUT, CONFIG_DRM_I915_REQUEST_TIMEOUT ? 0600 : 0) \
	param(unsigned int, lmem_size, 0, 0400) \
	param(unsigned int, lmem_bar_size, 0, 0400) \
	/* leave bools at the end to not create holes */ \
	param(bool, enable_hangcheck, true, 0600) \
	param(bool, load_detect_test, false, 0600) \
	param(bool, force_reset_modeset_test, false, 0600) \
	param(bool, error_capture, true, IS_ENABLED(CONFIG_DRM_I915_CAPTURE_ERROR) ? 0600 : 0) \
	param(bool, disable_display, false, 0400) \
	param(bool, verbose_state_checks, true, 0) \
	param(bool, nuclear_pageflip, false, 0400) \
	param(bool, enable_dp_mst, true, 0600) \
	param(bool, enable_gvt, false, IS_ENABLED(CONFIG_DRM_I915_GVT) ? 0400 : 0)

#define MEMBER(T, member, ...) T member;
struct i915_params {
	I915_PARAMS_FOR_EACH(MEMBER);
};

/* klp-ccp: from drivers/gpu/drm/i915/i915_gem_ww.h */
#include <drm/drm_drv.h>

/* klp-ccp: from drivers/gpu/drm/i915/gt/uc/intel_uc_fw.h */
enum intel_uc_fw_status {
	INTEL_UC_FIRMWARE_NOT_SUPPORTED = -1, /* no uc HW */
	INTEL_UC_FIRMWARE_UNINITIALIZED = 0, /* used to catch checks done too early */
	INTEL_UC_FIRMWARE_DISABLED, /* disabled */
	INTEL_UC_FIRMWARE_SELECTED, /* selected the blob we want to load */
	INTEL_UC_FIRMWARE_MISSING, /* blob not found on the system */
	INTEL_UC_FIRMWARE_ERROR, /* invalid format or version */
	INTEL_UC_FIRMWARE_AVAILABLE, /* blob found and copied in mem */
	INTEL_UC_FIRMWARE_INIT_FAIL, /* failed to prepare fw objects for load */
	INTEL_UC_FIRMWARE_LOADABLE, /* all fw-required objects are ready */
	INTEL_UC_FIRMWARE_LOAD_FAIL, /* failed to xfer or init/auth the fw */
	INTEL_UC_FIRMWARE_TRANSFERRED, /* dma xfer done */
	INTEL_UC_FIRMWARE_RUNNING /* init/auth done */
};

enum intel_uc_fw_type {
	INTEL_UC_FW_TYPE_GUC = 0,
	INTEL_UC_FW_TYPE_HUC
};

struct intel_uc_fw_file {
	const char *path;
	u16 major_ver;
	u16 minor_ver;
	u16 patch_ver;
};

struct intel_uc_fw {
	enum intel_uc_fw_type type;
	union {
		const enum intel_uc_fw_status status;
		enum intel_uc_fw_status __status; /* no accidental overwrites */
	};
	struct intel_uc_fw_file file_wanted;
	struct intel_uc_fw_file file_selected;
	bool user_overridden;
	size_t size;
	struct drm_i915_gem_object *obj;

	/**
	 * @dummy: A vma used in binding the uc fw to ggtt. We can't define this
	 * vma on the stack as it can lead to a stack overflow, so we define it
	 * here. Safe to have 1 copy per uc fw because the binding is single
	 * threaded as it done during driver load (inherently single threaded)
	 * or during a GT reset (mutex guarantees single threaded).
	 */
	struct i915_vma_resource dummy;
	struct i915_vma *rsa_data;

	u32 rsa_size;
	u32 ucode_size;
	u32 private_data_size;

	bool loaded_via_gsc;
};

/* klp-ccp: from drivers/gpu/drm/i915/gt/uc/intel_guc.h */
struct intel_guc {
	/** @fw: the GuC firmware */
	struct intel_uc_fw fw;
	/** @log: sub-structure containing GuC log related data and objects */
	struct intel_guc_log log;
	/** @ct: the command transport communication channel */
	struct intel_guc_ct ct;
	/** @slpc: sub-structure containing SLPC related data and objects */
	struct intel_guc_slpc slpc;
	/** @capture: the error-state-capture module's data and objects */
	struct intel_guc_state_capture *capture;

	/** @sched_engine: Global engine used to submit requests to GuC */
	struct i915_sched_engine *sched_engine;
	/**
	 * @stalled_request: if GuC can't process a request for any reason, we
	 * save it until GuC restarts processing. No other request can be
	 * submitted until the stalled request is processed.
	 */
	struct i915_request *stalled_request;
	/**
	 * @submission_stall_reason: reason why submission is stalled
	 */
	enum {
		STALL_NONE,
		STALL_REGISTER_CONTEXT,
		STALL_MOVE_LRC_TAIL,
		STALL_ADD_REQUEST,
	} submission_stall_reason;

	/* intel_guc_recv interrupt related state */
	/** @irq_lock: protects GuC irq state */
	spinlock_t irq_lock;
	/**
	 * @msg_enabled_mask: mask of events that are processed when receiving
	 * an INTEL_GUC_ACTION_DEFAULT G2H message.
	 */
	unsigned int msg_enabled_mask;

	/**
	 * @outstanding_submission_g2h: number of outstanding GuC to Host
	 * responses related to GuC submission, used to determine if the GT is
	 * idle
	 */
	atomic_t outstanding_submission_g2h;

	/** @interrupts: pointers to GuC interrupt-managing functions. */
	struct {
		void (*reset)(struct intel_guc *guc);
		void (*enable)(struct intel_guc *guc);
		void (*disable)(struct intel_guc *guc);
	} interrupts;

	/**
	 * @submission_state: sub-structure for submission state protected by
	 * single lock
	 */
	struct {
		/**
		 * @lock: protects everything in submission_state,
		 * ce->guc_id.id, and ce->guc_id.ref when transitioning in and
		 * out of zero
		 */
		spinlock_t lock;
		/**
		 * @guc_ids: used to allocate new guc_ids, single-lrc
		 */
		struct ida guc_ids;
		/**
		 * @num_guc_ids: Number of guc_ids, selftest feature to be able
		 * to reduce this number while testing.
		 */
		int num_guc_ids;
		/**
		 * @guc_ids_bitmap: used to allocate new guc_ids, multi-lrc
		 */
		unsigned long *guc_ids_bitmap;
		/**
		 * @guc_id_list: list of intel_context with valid guc_ids but no
		 * refs
		 */
		struct list_head guc_id_list;
		/**
		 * @destroyed_contexts: list of contexts waiting to be destroyed
		 * (deregistered with the GuC)
		 */
		struct list_head destroyed_contexts;
		/**
		 * @destroyed_worker: worker to deregister contexts, need as we
		 * need to take a GT PM reference and can't from destroy
		 * function as it might be in an atomic context (no sleeping)
		 */
		struct work_struct destroyed_worker;
		/**
		 * @reset_fail_worker: worker to trigger a GT reset after an
		 * engine reset fails
		 */
		struct work_struct reset_fail_worker;
		/**
		 * @reset_fail_mask: mask of engines that failed to reset
		 */
		intel_engine_mask_t reset_fail_mask;
	} submission_state;

	/**
	 * @submission_supported: tracks whether we support GuC submission on
	 * the current platform
	 */
	bool submission_supported;
	/** @submission_selected: tracks whether the user enabled GuC submission */
	bool submission_selected;
	/** @submission_initialized: tracks whether GuC submission has been initialised */
	bool submission_initialized;
	/**
	 * @rc_supported: tracks whether we support GuC rc on the current platform
	 */
	bool rc_supported;
	/** @rc_selected: tracks whether the user enabled GuC rc */
	bool rc_selected;

	/** @ads_vma: object allocated to hold the GuC ADS */
	struct i915_vma *ads_vma;
	/** @ads_map: contents of the GuC ADS */
	struct iosys_map ads_map;
	/** @ads_regset_size: size of the save/restore regsets in the ADS */
	u32 ads_regset_size;
	/**
	 * @ads_regset_count: number of save/restore registers in the ADS for
	 * each engine
	 */
	u32 ads_regset_count[I915_NUM_ENGINES];
	/** @ads_regset: save/restore regsets in the ADS */
	struct guc_mmio_reg *ads_regset;
	/** @ads_golden_ctxt_size: size of the golden contexts in the ADS */
	u32 ads_golden_ctxt_size;
	/** @ads_capture_size: size of register lists in the ADS used for error capture */
	u32 ads_capture_size;
	/** @ads_engine_usage_size: size of engine usage in the ADS */
	u32 ads_engine_usage_size;

	/** @lrc_desc_pool_v69: object allocated to hold the GuC LRC descriptor pool */
	struct i915_vma *lrc_desc_pool_v69;
	/** @lrc_desc_pool_vaddr_v69: contents of the GuC LRC descriptor pool */
	void *lrc_desc_pool_vaddr_v69;

	/**
	 * @context_lookup: used to resolve intel_context from guc_id, if a
	 * context is present in this structure it is registered with the GuC
	 */
	struct xarray context_lookup;

	/** @params: Control params for fw initialization */
	u32 params[GUC_CTL_MAX_DWORDS];

	/** @send_regs: GuC's FW specific registers used for sending MMIO H2G */
	struct {
		u32 base;
		unsigned int count;
		enum forcewake_domains fw_domains;
	} send_regs;

	/** @notify_reg: register used to send interrupts to the GuC FW */
	i915_reg_t notify_reg;

	/**
	 * @mmio_msg: notification bitmask that the GuC writes in one of its
	 * registers when the CT channel is disabled, to be processed when the
	 * channel is back up.
	 */
	u32 mmio_msg;

	/** @send_mutex: used to serialize the intel_guc_send actions */
	struct mutex send_mutex;

	/**
	 * @timestamp: GT timestamp object that stores a copy of the timestamp
	 * and adjusts it for overflow using a worker.
	 */
	struct {
		/**
		 * @lock: Lock protecting the below fields and the engine stats.
		 */
		spinlock_t lock;

		/**
		 * @gt_stamp: 64 bit extended value of the GT timestamp.
		 */
		u64 gt_stamp;

		/**
		 * @ping_delay: Period for polling the GT timestamp for
		 * overflow.
		 */
		unsigned long ping_delay;

		/**
		 * @work: Periodic work to adjust GT timestamp, engine and
		 * context usage for overflows.
		 */
		struct delayed_work work;

		/**
		 * @shift: Right shift value for the gpm timestamp
		 */
		u32 shift;

		/**
		 * @last_stat_jiffies: jiffies at last actual stats collection time
		 * We use this timestamp to ensure we don't oversample the
		 * stats because runtime power management events can trigger
		 * stats collection at much higher rates than required.
		 */
		unsigned long last_stat_jiffies;
	} timestamp;

#ifdef CONFIG_DRM_I915_SELFTEST
#error "klp-ccp: non-taken branch"
#endif
};

/* klp-ccp: from drivers/gpu/drm/i915/gt/uc/intel_guc_submission.h */
#include <linux/types.h>
/* klp-ccp: from drivers/gpu/drm/i915/gt/uc/intel_huc.h */
#include <linux/notifier.h>
#include <linux/hrtimer.h>

enum intel_huc_delayed_load_status {
	INTEL_HUC_WAITING_ON_GSC = 0,
	INTEL_HUC_WAITING_ON_PXP,
	INTEL_HUC_DELAYED_LOAD_ERROR,
};

struct intel_huc {
	/* Generic uC firmware management */
	struct intel_uc_fw fw;

	/* HuC-specific additions */
	struct {
		i915_reg_t reg;
		u32 mask;
		u32 value;
	} status;

	struct {
		struct i915_sw_fence fence;
		struct hrtimer timer;
		struct notifier_block nb;
		enum intel_huc_delayed_load_status status;
	} delayed_load;
};

/* klp-ccp: from drivers/gpu/drm/i915/gt/uc/intel_uc.h */
struct intel_uc {
	struct intel_uc_ops const *ops;
	struct intel_guc guc;
	struct intel_huc huc;

	/* Snapshot of GuC log from last failed load */
	struct drm_i915_gem_object *load_err_log;

	bool reset_in_progress;
};

/* klp-ccp: from drivers/gpu/drm/i915/gt/intel_gsc.h */
#include <linux/types.h>

#define INTEL_GSC_NUM_INTERFACES 2

struct intel_gsc {
	struct intel_gsc_intf {
		struct mei_aux_device *adev;
		struct drm_i915_gem_object *gem_obj;
		int irq;
		unsigned int id;
	} intf[INTEL_GSC_NUM_INTERFACES];
};

/* klp-ccp: from drivers/gpu/drm/i915/gt/intel_gt_buffer_pool_types.h */
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>

struct intel_gt_buffer_pool {
	spinlock_t lock;
	struct list_head cache_list[4];
	struct delayed_work work;
};

/* klp-ccp: from drivers/gpu/drm/i915/gt/intel_hwconfig.h */
#include <linux/types.h>

struct intel_hwconfig {
	u32 size;
	void *ptr;
};

/* klp-ccp: from drivers/gpu/drm/i915/gt/intel_llc_types.h */
struct intel_llc {
};

/* klp-ccp: from drivers/gpu/drm/i915/gt/intel_rc6_types.h */
#include <linux/spinlock.h>
#include <linux/types.h>

struct intel_rc6 {
	u64 prev_hw_residency[4];
	u64 cur_residency[4];

	u32 ctl_enable;

	struct drm_i915_gem_object *pctx;

	bool supported : 1;
	bool enabled : 1;
	bool manual : 1;
	bool wakeref : 1;
};

/* klp-ccp: from drivers/gpu/drm/i915/gt/intel_rps_types.h */
#include <linux/atomic.h>
#include <linux/ktime.h>
#include <linux/mutex.h>
#include <linux/types.h>
#include <linux/workqueue.h>

struct intel_ips {
	u64 last_count1;
	unsigned long last_time1;
	unsigned long chipset_power;
	u64 last_count2;
	u64 last_time2;
	unsigned long gfx_power;
	u8 corr;

	int c, m;
};

struct intel_rps_ei {
	ktime_t ktime;
	u32 render_c0;
	u32 media_c0;
};

struct intel_rps {
	struct mutex lock; /* protects enabling and the worker */

	/*
	 * work, interrupts_enabled and pm_iir are protected by
	 * dev_priv->irq_lock
	 */
	struct timer_list timer;
	struct work_struct work;
	unsigned long flags;

	ktime_t pm_timestamp;
	u32 pm_interval;
	u32 pm_iir;

	/* PM interrupt bits that should never be masked */
	u32 pm_intrmsk_mbz;
	u32 pm_events;

	/* Frequencies are stored in potentially platform dependent multiples.
	 * In other words, *_freq needs to be multiplied by X to be interesting.
	 * Soft limits are those which are used for the dynamic reclocking done
	 * by the driver (raise frequencies under heavy loads, and lower for
	 * lighter loads). Hard limits are those imposed by the hardware.
	 *
	 * A distinction is made for overclocking, which is never enabled by
	 * default, and is considered to be above the hard limit if it's
	 * possible at all.
	 */
	u8 cur_freq;		/* Current frequency (cached, may not == HW) */
	u8 last_freq;		/* Last SWREQ frequency */
	u8 min_freq_softlimit;	/* Minimum frequency permitted by the driver */
	u8 max_freq_softlimit;	/* Max frequency permitted by the driver */
	u8 max_freq;		/* Maximum frequency, RP0 if not overclocking */
	u8 min_freq;		/* AKA RPn. Minimum frequency */
	u8 boost_freq;		/* Frequency to request when wait boosting */
	u8 idle_freq;		/* Frequency to request when we are idle */
	u8 efficient_freq;	/* AKA RPe. Pre-determined balanced frequency */
	u8 rp1_freq;		/* "less than" RP0 power/freqency */
	u8 rp0_freq;		/* Non-overclocked max frequency. */
	u16 gpll_ref_freq;	/* vlv/chv GPLL reference frequency */

	int last_adj;

	struct {
		struct mutex mutex;

		enum { LOW_POWER, BETWEEN, HIGH_POWER } mode;
		unsigned int interactive;

		u8 up_threshold; /* Current %busy required to uplock */
		u8 down_threshold; /* Current %busy required to downclock */
	} power;

	atomic_t num_waiters;
	unsigned int boosts;

	/* manual wa residency calculations */
	struct intel_rps_ei ei;
	struct intel_ips ips;
};

/* klp-ccp: from drivers/gpu/drm/i915/gt/intel_migrate_types.h */
struct intel_migrate {
	struct intel_context *context;
};

/* klp-ccp: from drivers/gpu/drm/i915/pxp/intel_pxp_types.h */
#include <linux/completion.h>
#include <linux/mutex.h>
#include <linux/types.h>
#include <linux/workqueue.h>

struct intel_pxp {
	/**
	 * @pxp_component: i915_pxp_component struct of the bound mei_pxp
	 * module. Only set and cleared inside component bind/unbind functions,
	 * which are protected by &tee_mutex.
	 */
	struct i915_pxp_component *pxp_component;
	/**
	 * @pxp_component_added: track if the pxp component has been added.
	 * Set and cleared in tee init and fini functions respectively.
	 */
	bool pxp_component_added;

	/** @ce: kernel-owned context used for PXP operations */
	struct intel_context *ce;

	/** @arb_mutex: protects arb session start */
	struct mutex arb_mutex;
	/**
	 * @arb_is_valid: tracks arb session status.
	 * After a teardown, the arb session can still be in play on the HW
	 * even if the keys are gone, so we can't rely on the HW state of the
	 * session to know if it's valid and need to track the status in SW.
	 */
	bool arb_is_valid;

	/**
	 * @key_instance: tracks which key instance we're on, so we can use it
	 * to determine if an object was created using the current key or a
	 * previous one.
	 */
	u32 key_instance;

	/** @tee_mutex: protects the tee channel binding and messaging. */
	struct mutex tee_mutex;

	/** @stream_cmd: LMEM obj used to send stream PXP commands to the GSC */
	struct {
		struct drm_i915_gem_object *obj; /* contains PXP command memory */
		void *vaddr; /* virtual memory for PXP command */
	} stream_cmd;

	/**
	 * @hw_state_invalidated: if the HW perceives an attack on the integrity
	 * of the encryption it will invalidate the keys and expect SW to
	 * re-initialize the session. We keep track of this state to make sure
	 * we only re-start the arb session when required.
	 */
	bool hw_state_invalidated;

	/** @irq_enabled: tracks the status of the kcr irqs */
	bool irq_enabled;
	/**
	 * @termination: tracks the status of a pending termination. Only
	 * re-initialized under gt->irq_lock and completed in &session_work.
	 */
	struct completion termination;

	/** @session_work: worker that manages session events. */
	struct work_struct session_work;
	/** @session_events: pending session events, protected with gt->irq_lock. */
	u32 session_events;
};

/* klp-ccp: from drivers/gpu/drm/i915/gt/intel_gt_types.h */
enum intel_steering_type {
	L3BANK,
	MSLICE,
	LNCF,

	/*
	 * On some platforms there are multiple types of MCR registers that
	 * will always return a non-terminated value at instance (0, 0).  We'll
	 * lump those all into a single category to keep things simple.
	 */
	INSTANCE0,

	NUM_STEERING_TYPES
};

enum intel_submission_method {
	INTEL_SUBMISSION_RING,
	INTEL_SUBMISSION_ELSP,
	INTEL_SUBMISSION_GUC,
};

struct intel_gt {
	struct drm_i915_private *i915;
	struct intel_uncore *uncore;
	struct i915_ggtt *ggtt;

	struct intel_uc uc;
	struct intel_gsc gsc;

	struct i915_wa_list wa_list;

	struct {
		/* Serialize global tlb invalidations */
		struct mutex invalidate_lock;

		/*
		 * Batch TLB invalidations
		 *
		 * After unbinding the PTE, we need to ensure the TLB
		 * are invalidated prior to releasing the physical pages.
		 * But we only need one such invalidation for all unbinds,
		 * so we track how many TLB invalidations have been
		 * performed since unbind the PTE and only emit an extra
		 * invalidate if no full barrier has been passed.
		 */
		seqcount_mutex_t seqno;
	} tlb;

	struct intel_gt_timelines {
		spinlock_t lock; /* protects active_list */
		struct list_head active_list;
	} timelines;

	struct intel_gt_requests {
		/**
		 * We leave the user IRQ off as much as possible,
		 * but this means that requests will finish and never
		 * be retired once the system goes idle. Set a timer to
		 * fire periodically while the ring is running. When it
		 * fires, go retire requests.
		 */
		struct delayed_work retire_work;
	} requests;

	struct {
		struct llist_head list;
		struct work_struct work;
	} watchdog;

	struct intel_wakeref wakeref;
	atomic_t user_wakeref;

	struct list_head closed_vma;
	spinlock_t closed_lock; /* guards the list of closed_vma */

	ktime_t last_init_time;
	struct intel_reset reset;

	/**
	 * Is the GPU currently considered idle, or busy executing
	 * userspace requests? Whilst idle, we allow runtime power
	 * management to power down the hardware and display clocks.
	 * In order to reduce the effect on performance, there
	 * is a slight delay before we do so.
	 */
	intel_wakeref_t awake;

	u32 clock_frequency;
	u32 clock_period_ns;

	struct intel_llc llc;
	struct intel_rc6 rc6;
	struct intel_rps rps;

	spinlock_t irq_lock;
	u32 gt_imr;
	u32 pm_ier;
	u32 pm_imr;

	u32 pm_guc_events;

	struct {
		bool active;

		/**
		 * @lock: Lock protecting the below fields.
		 */
		seqcount_mutex_t lock;

		/**
		 * @total: Total time this engine was busy.
		 *
		 * Accumulated time not counting the most recent block in cases
		 * where engine is currently busy (active > 0).
		 */
		ktime_t total;

		/**
		 * @start: Timestamp of the last idle to active transition.
		 *
		 * Idle is defined as active == 0, active is active > 0.
		 */
		ktime_t start;
	} stats;

	struct intel_engine_cs *engine[I915_NUM_ENGINES];
	struct intel_engine_cs *engine_class[MAX_ENGINE_CLASS + 1]
					    [MAX_ENGINE_INSTANCE + 1];
	enum intel_submission_method submission_method;

	/*
	 * Default address space (either GGTT or ppGTT depending on arch).
	 *
	 * Reserved for exclusive use by the kernel.
	 */
	struct i915_address_space *vm;

	/*
	 * A pool of objects to use as shadow copies of client batch buffers
	 * when the command parser is enabled. Prevents the client from
	 * modifying the batch contents after software parsing.
	 *
	 * Buffers older than 1s are periodically reaped from the pool,
	 * or may be reclaimed by the shrinker before then.
	 */
	struct intel_gt_buffer_pool buffer_pool;

	struct i915_vma *scratch;

	struct intel_migrate migrate;

	const struct intel_mmio_range *steering_table[NUM_STEERING_TYPES];

	struct {
		u8 groupid;
		u8 instanceid;
	} default_steering;

	/*
	 * Base of per-tile GTTMMADR where we can derive the MMIO and the GGTT.
	 */
	phys_addr_t phys_addr;

	struct intel_gt_info {
		unsigned int id;

		intel_engine_mask_t engine_mask;

		u32 l3bank_mask;

		u8 num_engines;

		/* General presence of SFC units */
		u8 sfc_mask;

		/* Media engine access to SFC per instance */
		u8 vdbox_sfc_access;

		/* Slice/subslice/EU info */
		struct sseu_dev_info sseu;

		unsigned long mslice_mask;

		/** @hwconfig: hardware configuration data */
		struct intel_hwconfig hwconfig;
	} info;

	struct {
		u8 uc_index;
		u8 wb_index; /* Only used on HAS_L3_CCS_READ() platforms */
	} mocs;

	struct intel_pxp pxp;

	/* gt/gtN sysfs */
	struct kobject sysfs_gt;
};

/* klp-ccp: from drivers/gpu/drm/i915/gt/intel_timeline.h */
#include <linux/lockdep.h>
/* klp-ccp: from drivers/gpu/drm/i915/i915_syncmap.h */
#include <linux/types.h>
/* klp-ccp: from drivers/gpu/drm/i915/gt/intel_workarounds.h */
#include <linux/slab.h>
/* klp-ccp: from drivers/gpu/drm/i915/i915_drm_client.h */
#include <linux/kref.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/xarray.h>
#include <uapi/drm/i915_drm.h>

#define I915_LAST_UABI_ENGINE_CLASS I915_ENGINE_CLASS_COMPUTE

struct i915_drm_clients {
	struct drm_i915_private *i915;

	struct xarray xarray;
	u32 next_id;
};

/* klp-ccp: from drivers/gpu/drm/i915/i915_gpu_error.h */
#include <linux/atomic.h>
#include <linux/kref.h>
#include <linux/ktime.h>
#include <linux/sched.h>
#include <drm/drm_mm.h>

struct i915_gpu_error {
	/* For reset and error_state handling. */
	spinlock_t lock;
	/* Protected by the above dev->gpu_error.lock. */
	struct i915_gpu_coredump *first_error;

	atomic_t pending_fb_pin;

	/** Number of times the device has been reset (global) */
	atomic_t reset_count;

	/** Number of times an engine has been reset */
	atomic_t reset_engine_count[I915_NUM_ENGINES];
};

/* klp-ccp: from drivers/gpu/drm/i915/i915_perf_types.h */
#include <linux/atomic.h>
#include <linux/device.h>
#include <linux/hrtimer.h>
#include <linux/llist.h>
#include <linux/poll.h>
#include <linux/sysfs.h>
#include <linux/types.h>
#include <linux/uuid.h>
#include <linux/wait.h>
#include <uapi/drm/i915_drm.h>

struct i915_oa_reg {
	i915_reg_t addr;
	u32 value;
};

struct i915_oa_config {
	struct i915_perf *perf;

	char uuid[UUID_STRING_LEN + 1];
	int id;

	const struct i915_oa_reg *mux_regs;
	u32 mux_regs_len;
	const struct i915_oa_reg *b_counter_regs;
	u32 b_counter_regs_len;
	const struct i915_oa_reg *flex_regs;
	u32 flex_regs_len;

	struct attribute_group sysfs_metric;
	struct attribute *attrs[2];
	struct kobj_attribute sysfs_metric_id;

	struct kref ref;
	struct rcu_head rcu;
};

struct i915_perf_stream {
	/**
	 * @perf: i915_perf backpointer
	 */
	struct i915_perf *perf;

	/**
	 * @uncore: mmio access path
	 */
	struct intel_uncore *uncore;

	/**
	 * @engine: Engine associated with this performance stream.
	 */
	struct intel_engine_cs *engine;

	/**
	 * @sample_flags: Flags representing the `DRM_I915_PERF_PROP_SAMPLE_*`
	 * properties given when opening a stream, representing the contents
	 * of a single sample as read() by userspace.
	 */
	u32 sample_flags;

	/**
	 * @sample_size: Considering the configured contents of a sample
	 * combined with the required header size, this is the total size
	 * of a single sample record.
	 */
	int sample_size;

	/**
	 * @ctx: %NULL if measuring system-wide across all contexts or a
	 * specific context that is being monitored.
	 */
	struct i915_gem_context *ctx;

	/**
	 * @enabled: Whether the stream is currently enabled, considering
	 * whether the stream was opened in a disabled state and based
	 * on `I915_PERF_IOCTL_ENABLE` and `I915_PERF_IOCTL_DISABLE` calls.
	 */
	bool enabled;

	/**
	 * @hold_preemption: Whether preemption is put on hold for command
	 * submissions done on the @ctx. This is useful for some drivers that
	 * cannot easily post process the OA buffer context to subtract delta
	 * of performance counters not associated with @ctx.
	 */
	bool hold_preemption;

	/**
	 * @ops: The callbacks providing the implementation of this specific
	 * type of configured stream.
	 */
	const struct i915_perf_stream_ops *ops;

	/**
	 * @oa_config: The OA configuration used by the stream.
	 */
	struct i915_oa_config *oa_config;

	/**
	 * @oa_config_bos: A list of struct i915_oa_config_bo allocated lazily
	 * each time @oa_config changes.
	 */
	struct llist_head oa_config_bos;

	/**
	 * @pinned_ctx: The OA context specific information.
	 */
	struct intel_context *pinned_ctx;

	/**
	 * @specific_ctx_id: The id of the specific context.
	 */
	u32 specific_ctx_id;

	/**
	 * @specific_ctx_id_mask: The mask used to masking specific_ctx_id bits.
	 */
	u32 specific_ctx_id_mask;

	/**
	 * @poll_check_timer: High resolution timer that will periodically
	 * check for data in the circular OA buffer for notifying userspace
	 * (e.g. during a read() or poll()).
	 */
	struct hrtimer poll_check_timer;

	/**
	 * @poll_wq: The wait queue that hrtimer callback wakes when it
	 * sees data ready to read in the circular OA buffer.
	 */
	wait_queue_head_t poll_wq;

	/**
	 * @pollin: Whether there is data available to read.
	 */
	bool pollin;

	/**
	 * @periodic: Whether periodic sampling is currently enabled.
	 */
	bool periodic;

	/**
	 * @period_exponent: The OA unit sampling frequency is derived from this.
	 */
	int period_exponent;

	/**
	 * @oa_buffer: State of the OA buffer.
	 */
	struct {
		struct i915_vma *vma;
		u8 *vaddr;
		u32 last_ctx_id;
		int format;
		int format_size;
		int size_exponent;

		/**
		 * @ptr_lock: Locks reads and writes to all head/tail state
		 *
		 * Consider: the head and tail pointer state needs to be read
		 * consistently from a hrtimer callback (atomic context) and
		 * read() fop (user context) with tail pointer updates happening
		 * in atomic context and head updates in user context and the
		 * (unlikely) possibility of read() errors needing to reset all
		 * head/tail state.
		 *
		 * Note: Contention/performance aren't currently a significant
		 * concern here considering the relatively low frequency of
		 * hrtimer callbacks (5ms period) and that reads typically only
		 * happen in response to a hrtimer event and likely complete
		 * before the next callback.
		 *
		 * Note: This lock is not held *while* reading and copying data
		 * to userspace so the value of head observed in htrimer
		 * callbacks won't represent any partial consumption of data.
		 */
		spinlock_t ptr_lock;

		/**
		 * @aging_tail: The last HW tail reported by HW. The data
		 * might not have made it to memory yet though.
		 */
		u32 aging_tail;

		/**
		 * @aging_timestamp: A monotonic timestamp for when the current aging tail pointer
		 * was read; used to determine when it is old enough to trust.
		 */
		u64 aging_timestamp;

		/**
		 * @head: Although we can always read back the head pointer register,
		 * we prefer to avoid trusting the HW state, just to avoid any
		 * risk that some hardware condition could * somehow bump the
		 * head pointer unpredictably and cause us to forward the wrong
		 * OA buffer data to userspace.
		 */
		u32 head;

		/**
		 * @tail: The last verified tail that can be read by userspace.
		 */
		u32 tail;
	} oa_buffer;

	/**
	 * @noa_wait: A batch buffer doing a wait on the GPU for the NOA logic to be
	 * reprogrammed.
	 */
	struct i915_vma *noa_wait;

	/**
	 * @poll_oa_period: The period in nanoseconds at which the OA
	 * buffer should be checked for available data.
	 */
	u64 poll_oa_period;
};

struct i915_oa_ops {
	/**
	 * @is_valid_b_counter_reg: Validates register's address for
	 * programming boolean counters for a particular platform.
	 */
	bool (*is_valid_b_counter_reg)(struct i915_perf *perf, u32 addr);

	/**
	 * @is_valid_mux_reg: Validates register's address for programming mux
	 * for a particular platform.
	 */
	bool (*is_valid_mux_reg)(struct i915_perf *perf, u32 addr);

	/**
	 * @is_valid_flex_reg: Validates register's address for programming
	 * flex EU filtering for a particular platform.
	 */
	bool (*is_valid_flex_reg)(struct i915_perf *perf, u32 addr);

	/**
	 * @enable_metric_set: Selects and applies any MUX configuration to set
	 * up the Boolean and Custom (B/C) counters that are part of the
	 * counter reports being sampled. May apply system constraints such as
	 * disabling EU clock gating as required.
	 */
	int (*enable_metric_set)(struct i915_perf_stream *stream,
				 struct i915_active *active);

	/**
	 * @disable_metric_set: Remove system constraints associated with using
	 * the OA unit.
	 */
	void (*disable_metric_set)(struct i915_perf_stream *stream);

	/**
	 * @oa_enable: Enable periodic sampling
	 */
	void (*oa_enable)(struct i915_perf_stream *stream);

	/**
	 * @oa_disable: Disable periodic sampling
	 */
	void (*oa_disable)(struct i915_perf_stream *stream);

	/**
	 * @read: Copy data from the circular OA buffer into a given userspace
	 * buffer.
	 */
	int (*read)(struct i915_perf_stream *stream,
		    char __user *buf,
		    size_t count,
		    size_t *offset);

	/**
	 * @oa_hw_tail_read: read the OA tail pointer register
	 *
	 * In particular this enables us to share all the fiddly code for
	 * handling the OA unit tail pointer race that affects multiple
	 * generations.
	 */
	u32 (*oa_hw_tail_read)(struct i915_perf_stream *stream);
};

struct i915_perf {
	struct drm_i915_private *i915;

	struct kobject *metrics_kobj;

	/*
	 * Lock associated with adding/modifying/removing OA configs
	 * in perf->metrics_idr.
	 */
	struct mutex metrics_lock;

	/*
	 * List of dynamic configurations (struct i915_oa_config), you
	 * need to hold perf->metrics_lock to access it.
	 */
	struct idr metrics_idr;

	/*
	 * Lock associated with anything below within this structure
	 * except exclusive_stream.
	 */
	struct mutex lock;

	/*
	 * The stream currently using the OA unit. If accessed
	 * outside a syscall associated to its file
	 * descriptor.
	 */
	struct i915_perf_stream *exclusive_stream;

	/**
	 * @sseu: sseu configuration selected to run while perf is active,
	 * applies to all contexts.
	 */
	struct intel_sseu sseu;

	/**
	 * For rate limiting any notifications of spurious
	 * invalid OA reports
	 */
	struct ratelimit_state spurious_report_rs;

	/**
	 * For rate limiting any notifications of tail pointer
	 * race.
	 */
	struct ratelimit_state tail_pointer_race;

	u32 gen7_latched_oastatus1;
	u32 ctx_oactxctrl_offset;
	u32 ctx_flexeu0_offset;

	/**
	 * The RPT_ID/reason field for Gen8+ includes a bit
	 * to determine if the CTX ID in the report is valid
	 * but the specific bit differs between Gen 8 and 9
	 */
	u32 gen8_valid_ctx_bit;

	struct i915_oa_ops ops;
	const struct i915_oa_format *oa_formats;

#define FORMAT_MASK_SIZE DIV_ROUND_UP(I915_OA_FORMAT_MAX - 1, BITS_PER_LONG)
	unsigned long format_mask[FORMAT_MASK_SIZE];

	atomic64_t noa_programming_delay;
};

/* klp-ccp: from drivers/gpu/drm/i915/intel_pch.h */
enum intel_pch {
	PCH_NOP = -1,	/* PCH without south display */
	PCH_NONE = 0,	/* No PCH present */
	PCH_IBX,	/* Ibexpeak PCH */
	PCH_CPT,	/* Cougarpoint/Pantherpoint PCH */
	PCH_LPT,	/* Lynxpoint/Wildcatpoint PCH */
	PCH_SPT,        /* Sunrisepoint/Kaby Lake PCH */
	PCH_CNP,        /* Cannon/Comet Lake PCH */
	PCH_ICP,	/* Ice Lake/Jasper Lake PCH */
	PCH_TGP,	/* Tiger Lake/Mule Creek Canyon PCH */
	PCH_ADP,	/* Alder Lake PCH */

	/* Fake PCHs, functionality handled on the same PCI dev */
	PCH_DG1 = 1024,
	PCH_DG2,
};

/* klp-ccp: from drivers/gpu/drm/i915/intel_pm_types.h */
#include <linux/types.h>

enum intel_ddb_partitioning {
	INTEL_DDB_PART_1_2,
	INTEL_DDB_PART_5_6, /* IVB+ */
};

struct ilk_wm_values {
	u32 wm_pipe[3];
	u32 wm_lp[3];
	u32 wm_lp_spr[3];
	bool enable_fbc_wm;
	enum intel_ddb_partitioning partitioning;
};

struct g4x_pipe_wm {
	u16 plane[I915_MAX_PLANES];
	u16 fbc;
};

struct g4x_sr_wm {
	u16 plane;
	u16 cursor;
	u16 fbc;
};

struct vlv_wm_ddl_values {
	u8 plane[I915_MAX_PLANES];
};

struct vlv_wm_values {
	struct g4x_pipe_wm pipe[3];
	struct g4x_sr_wm sr;
	struct vlv_wm_ddl_values ddl[3];
	u8 level;
	bool cxsr;
};

struct g4x_wm_values {
	struct g4x_pipe_wm pipe[2];
	struct g4x_sr_wm sr;
	struct g4x_sr_wm hpll;
	bool cxsr;
	bool hpll_en;
	bool fbc_en;
};

/* klp-ccp: from drivers/gpu/drm/i915/intel_wopcm.h */
#include <linux/types.h>

struct intel_wopcm {
	u32 size;
	struct {
		u32 base;
		u32 size;
	} guc;
};

/* klp-ccp: from drivers/gpu/drm/i915/i915_drv.h */
struct i915_hotplug {
	struct delayed_work hotplug_work;

	const u32 *hpd, *pch_hpd;

	struct {
		unsigned long last_jiffies;
		int count;
		enum {
			HPD_ENABLED = 0,
			HPD_DISABLED = 1,
			HPD_MARK_DISABLED = 2
		} state;
	} stats[HPD_NUM_PINS];
	u32 event_bits;
	u32 retry_bits;
	struct delayed_work reenable_work;

	u32 long_port_mask;
	u32 short_port_mask;
	struct work_struct dig_port_work;

	struct work_struct poll_init_work;
	bool poll_enabled;

	unsigned int hpd_storm_threshold;
	/* Whether or not to count short HPD IRQs in HPD storms */
	u8 hpd_short_storm_enabled;

	/*
	 * if we get a HPD irq from DP and a HPD irq from non-DP
	 * the non-DP HPD could block the workqueue on a mode config
	 * mutex getting, that userspace may have taken. However
	 * userspace is waiting on the DP workqueue to run which is
	 * blocked behind the non-DP one.
	 */
	struct workqueue_struct *dp_wq;
};

struct sdvo_device_mapping {
	u8 initialized;
	u8 dvo_port;
	u8 slave_addr;
	u8 dvo_wiring;
	u8 i2c_pin;
	u8 ddc_pin;
};

struct i915_suspend_saved_registers {
	u32 saveDSPARB;
	u32 saveSWF0[16];
	u32 saveSWF1[16];
	u32 saveSWF3[3];
	u16 saveGCDGMBUS;
};

#define MAX_L3_SLICES 2
struct intel_l3_parity {
	u32 *remap_info[MAX_L3_SLICES];
	struct work_struct error_work;
	int which_slice;
};

struct i915_gem_mm {
	/*
	 * Shortcut for the stolen region. This points to either
	 * INTEL_REGION_STOLEN_SMEM for integrated platforms, or
	 * INTEL_REGION_STOLEN_LMEM for discrete, or NULL if the device doesn't
	 * support stolen.
	 */
	struct intel_memory_region *stolen_region;
	/** Memory allocator for GTT stolen memory */
	struct drm_mm stolen;
	/** Protects the usage of the GTT stolen memory allocator. This is
	 * always the inner lock when overlapping with struct_mutex. */
	struct mutex stolen_lock;

	/* Protects bound_list/unbound_list and #drm_i915_gem_object.mm.link */
	spinlock_t obj_lock;

	/**
	 * List of objects which are purgeable.
	 */
	struct list_head purge_list;

	/**
	 * List of objects which have allocated pages and are shrinkable.
	 */
	struct list_head shrink_list;

	/**
	 * List of objects which are pending destruction.
	 */
	struct llist_head free_list;
	struct work_struct free_work;
	/**
	 * Count of objects pending destructions. Used to skip needlessly
	 * waiting on an RCU barrier if no objects are waiting to be freed.
	 */
	atomic_t free_count;

	/**
	 * tmpfs instance used for shmem backed objects
	 */
	struct vfsmount *gemfs;

	struct intel_memory_region *regions[INTEL_REGION_UNKNOWN];

	struct notifier_block oom_notifier;
	struct notifier_block vmap_notifier;
	struct shrinker shrinker;

#ifdef CONFIG_MMU_NOTIFIER
	rwlock_t notifier_lock;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	u64 shrink_memory;
	u32 shrink_count;
};

#define I915_NUM_QGV_POINTS 8

#define I915_NUM_PSF_GV_POINTS 3

struct intel_vbt_data {
	/* bdb version */
	u16 version;

	/* Feature bits */
	unsigned int int_tv_support:1;
	unsigned int int_crt_support:1;
	unsigned int lvds_use_ssc:1;
	unsigned int int_lvds_support:1;
	unsigned int display_clock_mode:1;
	unsigned int fdi_rx_polarity_inverted:1;
	int lvds_ssc_freq;
	enum drm_panel_orientation orientation;

	bool override_afc_startup;
	u8 override_afc_startup_val;

	int crt_ddc_pin;

	struct list_head display_devices;
	struct list_head bdb_blocks;

	struct intel_bios_encoder_data *ports[I915_MAX_PORTS]; /* Non-NULL if port present. */
	struct sdvo_device_mapping sdvo_mappings[2];
};

struct i915_frontbuffer_tracking {
	spinlock_t lock;

	/*
	 * Tracking bits for delayed frontbuffer flushing du to gpu activity or
	 * scheduled flips.
	 */
	unsigned busy_bits;
	unsigned flip_bits;
};

struct i915_virtual_gpu {
	struct mutex lock; /* serialises sending of g2v_notify command pkts */
	bool active;
	u32 caps;
	u32 *initial_mmio;
	u8 *initial_cfg_space;
	struct list_head entry;
};

struct intel_audio_private {
	/* Display internal audio functions */
	const struct intel_audio_funcs *funcs;

	/* hda/i915 audio component */
	struct i915_audio_component *component;
	bool component_registered;
	/* mutex for audio/video sync */
	struct mutex mutex;
	int power_refcount;
	u32 freq_cntrl;

	/* Used to save the pipe-to-encoder mapping for audio */
	struct intel_encoder *encoder_map[I915_MAX_PIPES];

	/* necessary resource sharing with HDMI LPE audio driver. */
	struct {
		struct platform_device *platdev;
		int irq;
	} lpe;
};

struct drm_i915_private {
	struct drm_device drm;

	/* FIXME: Device release actions should all be moved to drmm_ */
	bool do_release;

	/* i915 device parameters */
	struct i915_params params;

	const struct intel_device_info __info; /* Use INTEL_INFO() to access. */
	struct intel_runtime_info __runtime; /* Use RUNTIME_INFO() to access. */
	struct intel_driver_caps caps;

	/**
	 * Data Stolen Memory - aka "i915 stolen memory" gives us the start and
	 * end of stolen which we can optionally use to create GEM objects
	 * backed by stolen memory. Note that stolen_usable_size tells us
	 * exactly how much of this we are actually allowed to use, given that
	 * some portion of it is in fact reserved for use by hardware functions.
	 */
	struct resource dsm;
	/**
	 * Reseved portion of Data Stolen Memory
	 */
	struct resource dsm_reserved;

	/*
	 * Stolen memory is segmented in hardware with different portions
	 * offlimits to certain functions.
	 *
	 * The drm_mm is initialised to the total accessible range, as found
	 * from the PCI config. On Broadwell+, this is further restricted to
	 * avoid the first page! The upper end of stolen memory is reserved for
	 * hardware functions and similarly removed from the accessible range.
	 */
	resource_size_t stolen_usable_size;	/* Total size minus reserved ranges */

	struct intel_uncore uncore;
	struct intel_uncore_mmio_debug mmio_debug;

	struct i915_virtual_gpu vgpu;

	struct intel_gvt *gvt;

	struct intel_wopcm wopcm;

	struct intel_dmc dmc;

	struct intel_gmbus *gmbus[GMBUS_NUM_PINS];

	/** gmbus_mutex protects against concurrent usage of the single hw gmbus
	 * controller on different i2c buses. */
	struct mutex gmbus_mutex;

	/**
	 * Base address of where the gmbus and gpio blocks are located (either
	 * on PCH or on SoC for platforms without PCH).
	 */
	u32 gpio_mmio_base;

	/* MMIO base address for MIPI regs */
	u32 mipi_mmio_base;

	u32 pps_mmio_base;

	wait_queue_head_t gmbus_wait_queue;

	struct pci_dev *bridge_dev;

	struct rb_root uabi_engines;
	unsigned int engine_uabi_class_count[I915_LAST_UABI_ENGINE_CLASS + 1];

	struct resource mch_res;

	/* protects the irq masks */
	spinlock_t irq_lock;

	bool display_irqs_enabled;

	/* Sideband mailbox protection */
	struct mutex sb_lock;
	struct pm_qos_request sb_qos;

	/** Cached value of IMR to avoid reads in updating the bitfield */
	union {
		u32 irq_mask;
		u32 de_irq_mask[I915_MAX_PIPES];
	};
	u32 pipestat_irq_mask[I915_MAX_PIPES];

	struct i915_hotplug hotplug;
	struct intel_fbc *fbc[I915_MAX_FBCS];
	struct intel_opregion opregion;
	struct intel_vbt_data vbt;

	bool preserve_bios_swizzle;

	/* overlay */
	struct intel_overlay *overlay;

	/* backlight registers and fields in struct intel_panel */
	struct mutex backlight_lock;

	/* protects panel power sequencer state */
	struct mutex pps_mutex;

	unsigned int fsb_freq, mem_freq, is_ddr3;
	unsigned int skl_preferred_vco_freq;
	unsigned int max_cdclk_freq;

	unsigned int max_dotclk_freq;
	unsigned int hpll_freq;
	unsigned int fdi_pll_freq;
	unsigned int czclk_freq;

	struct {
		/* The current hardware cdclk configuration */
		struct intel_cdclk_config hw;

		/* cdclk, divider, and ratio table from bspec */
		const struct intel_cdclk_vals *table;

		struct intel_global_obj obj;
	} cdclk;

	struct {
		/* The current hardware dbuf configuration */
		u8 enabled_slices;

		struct intel_global_obj obj;
	} dbuf;

	/**
	 * wq - Driver workqueue for GEM.
	 *
	 * NOTE: Work items scheduled here are not allowed to grab any modeset
	 * locks, for otherwise the flushing done in the pageflip code will
	 * result in deadlocks.
	 */
	struct workqueue_struct *wq;

	/* ordered wq for modesets */
	struct workqueue_struct *modeset_wq;
	/* unbound hipri wq for page flips/plane updates */
	struct workqueue_struct *flip_wq;

	/* pm private clock gating functions */
	const struct drm_i915_clock_gating_funcs *clock_gating_funcs;

	/* pm display functions */
	const struct drm_i915_wm_disp_funcs *wm_disp;

	/* irq display functions */
	const struct intel_hotplug_funcs *hotplug_funcs;

	/* fdi display functions */
	const struct intel_fdi_funcs *fdi_funcs;

	/* display pll funcs */
	const struct intel_dpll_funcs *dpll_funcs;

	/* Display functions */
	const struct drm_i915_display_funcs *display;

	/* Display internal color functions */
	const struct intel_color_funcs *color_funcs;

	/* Display CDCLK functions */
	const struct intel_cdclk_funcs *cdclk_funcs;

	/* PCH chipset type */
	enum intel_pch pch_type;
	unsigned short pch_id;

	unsigned long quirks;

	struct drm_atomic_state *modeset_restore_state;
	struct drm_modeset_acquire_ctx reset_ctx;

	struct i915_gem_mm mm;

	/* Kernel Modesetting */

	/**
	 * dpll and cdclk state is protected by connection_mutex
	 * dpll.lock serializes intel_{prepare,enable,disable}_shared_dpll.
	 * Must be global rather than per dpll, because on some platforms plls
	 * share registers.
	 */
	struct {
		struct mutex lock;

		int num_shared_dpll;
		struct intel_shared_dpll shared_dplls[I915_NUM_PLLS];
		const struct intel_dpll_mgr *mgr;

		struct {
			int nssc;
			int ssc;
		} ref_clks;
	} dpll;

	struct list_head global_obj_list;

	struct i915_frontbuffer_tracking fb_tracking;

	struct intel_atomic_helper {
		struct llist_head free_list;
		struct work_struct free_work;
	} atomic_helper;

	bool mchbar_need_disable;

	struct intel_l3_parity l3_parity;

	/*
	 * HTI (aka HDPORT) state read during initial hw readout.  Most
	 * platforms don't have HTI, so this will just stay 0.  Those that do
	 * will use this later to figure out which PLLs and PHYs are unavailable
	 * for driver usage.
	 */
	u32 hti_state;

	/*
	 * edram size in MB.
	 * Cannot be determined by PCIID. You must always read a register.
	 */
	u32 edram_size_mb;

	struct i915_power_domains power_domains;

	struct i915_gpu_error gpu_error;

	/* list of fbdev register on this device */
	struct intel_fbdev *fbdev;
	struct work_struct fbdev_suspend_work;

	struct drm_property *broadcast_rgb_property;
	struct drm_property *force_audio_property;

	u32 fdi_rx_config;

	/* Shadow for DISPLAY_PHY_CONTROL which can't be safely read */
	u32 chv_phy_control;
	/*
	 * Shadows for CHV DPLL_MD regs to keep the state
	 * checker somewhat working in the presence hardware
	 * crappiness (can't read out DPLL_MD for pipes B & C).
	 */
	u32 chv_dpll_md[I915_MAX_PIPES];
	u32 bxt_phy_grc;

	u32 suspend_count;
	struct i915_suspend_saved_registers regfile;
	struct vlv_s0ix_state *vlv_s0ix_state;

	enum {
		I915_SAGV_UNKNOWN = 0,
		I915_SAGV_DISABLED,
		I915_SAGV_ENABLED,
		I915_SAGV_NOT_CONTROLLED
	} sagv_status;

	u32 sagv_block_time_us;

	struct {
		/*
		 * Raw watermark latency values:
		 * in 0.1us units for WM0,
		 * in 0.5us units for WM1+.
		 */
		/* primary */
		u16 pri_latency[5];
		/* sprite */
		u16 spr_latency[5];
		/* cursor */
		u16 cur_latency[5];
		/*
		 * Raw watermark memory latency values
		 * for SKL for all 8 levels
		 * in 1us units.
		 */
		u16 skl_latency[8];

		/* current hardware state */
		union {
			struct ilk_wm_values hw;
			struct vlv_wm_values vlv;
			struct g4x_wm_values g4x;
		};

		u8 max_level;

		/*
		 * Should be held around atomic WM register writing; also
		 * protects * intel_crtc->wm.active and
		 * crtc_state->wm.need_postvbl_update.
		 */
		struct mutex wm_mutex;
	} wm;

	struct dram_info {
		bool wm_lv_0_adjust_needed;
		u8 num_channels;
		bool symmetric_memory;
		enum intel_dram_type {
			INTEL_DRAM_UNKNOWN,
			INTEL_DRAM_DDR3,
			INTEL_DRAM_DDR4,
			INTEL_DRAM_LPDDR3,
			INTEL_DRAM_LPDDR4,
			INTEL_DRAM_DDR5,
			INTEL_DRAM_LPDDR5,
		} type;
		u8 num_qgv_points;
		u8 num_psf_gv_points;
	} dram_info;

	struct intel_bw_info {
		/* for each QGV point */
		unsigned int deratedbw[I915_NUM_QGV_POINTS];
		/* for each PSF GV point */
		unsigned int psf_bw[I915_NUM_PSF_GV_POINTS];
		u8 num_qgv_points;
		u8 num_psf_gv_points;
		u8 num_planes;
	} max_bw[6];

	struct intel_global_obj bw_obj;

	struct intel_runtime_pm runtime_pm;

	struct i915_perf perf;

	/* Abstract the submission mechanism (legacy ringbuffer or execlists) away */
	struct intel_gt gt0;

#define I915_MAX_GT 4
	struct intel_gt *gt[I915_MAX_GT];

	struct kobject *sysfs_gt;

	struct {
		struct i915_gem_contexts {
			spinlock_t lock; /* locks list */
			struct list_head list;
		} contexts;

		/*
		 * We replace the local file with a global mappings as the
		 * backing storage for the mmap is on the device and not
		 * on the struct file, and we do not want to prolong the
		 * lifetime of the local fd. To minimise the number of
		 * anonymous inodes we create, we use a global singleton to
		 * share the global mapping.
		 */
		struct file *mmap_singleton;
	} gem;

	/* Window2 specifies time required to program DSB (Window2) in number of scan lines */
	u8 window2_delay;

	u8 pch_ssc_use;

	/* For i915gm/i945gm vblank irq workaround */
	u8 vblank_enabled;

	bool irq_enabled;

	union {
		/* perform PHY state sanity checks? */
		bool chv_phy_assert[2];

		/*
		 * DG2: Mask of PHYs that were not calibrated by the firmware
		 * and should not be used.
		 */
		u8 snps_phy_failed_calibration;
	};

	bool ipc_enabled;

	struct intel_audio_private audio;

	struct i915_pmu pmu;

	struct i915_drm_clients clients;

	struct i915_hdcp_comp_master *hdcp_master;
	bool hdcp_comp_added;

	/* Mutex to protect the above hdcp component related values. */
	struct mutex hdcp_comp_mutex;

	/* The TTM device structure. */
	struct ttm_device bdev;

	I915_SELFTEST_DECLARE(struct i915_selftest_stash selftest;)

	/*
	 * NOTE: This is the dri1/ums dungeon, don't add stuff here. Your patch
	 * will be rejected. Instead look for a better place.
	 */
};

#define rb_to_uabi_engine(rb) \
	rb_entry_safe(rb, struct intel_engine_cs, uabi_node)

#define for_each_uabi_engine(engine__, i915__) \
	for ((engine__) = rb_to_uabi_engine(rb_first(&(i915__)->uabi_engines));\
	     (engine__); \
	     (engine__) = rb_to_uabi_engine(rb_next(&(engine__)->uabi_node)))

#define INTEL_INFO(dev_priv)	(&(dev_priv)->__info)

#define GRAPHICS_VER(i915)		(INTEL_INFO(i915)->graphics.ver)

#define IS_GRAPHICS_VER(i915, from, until) \
	(GRAPHICS_VER(i915) >= (from) && GRAPHICS_VER(i915) <= (until))

/* klp-ccp: from drivers/gpu/drm/i915/gt/intel_ring_types.h */
#include <linux/atomic.h>
#include <linux/kref.h>
#include <linux/types.h>

/* klp-ccp: from drivers/gpu/drm/i915/i915_trace.h */
#if !defined(_I915_TRACE_H_) || defined(TRACE_HEADER_MULTI_READ)

#include <linux/stringify.h>
#include <linux/types.h>
#include <drm/drm_drv.h>
/* klp-ccp: from drivers/gpu/drm/i915/i915_irq.h */
#include <linux/ktime.h>
#include <linux/types.h>

/* klp-ccp: from drivers/gpu/drm/i915/i915_reg.h */
#define __MASKED_FIELD(mask, value) ((mask) << 16 | (value))
#define _MASKED_FIELD(mask, value) ({					   \
	if (__builtin_constant_p(mask))					   \
		BUILD_BUG_ON_MSG(((mask) & 0xffff0000), "Incorrect mask"); \
	if (__builtin_constant_p(value))				   \
		BUILD_BUG_ON_MSG((value) & 0xffff0000, "Incorrect value"); \
	if (__builtin_constant_p(mask) && __builtin_constant_p(value))	   \
		BUILD_BUG_ON_MSG((value) & ~(mask),			   \
				 "Incorrect value for mask");		   \
	__MASKED_FIELD(mask, value); })
#define _MASKED_BIT_ENABLE(a)	({ typeof(a) _a = (a); _MASKED_FIELD(_a, _a); })

#define RENDER_RING_BASE	0x02000

#else
#error "klp-ccp: a preceeding branch should have been taken"
/* klp-ccp: from drivers/gpu/drm/i915/i915_trace.h */
#endif /* _I915_TRACE_H_ */

#include <trace/define_trace.h>

/* klp-ccp: from drivers/gpu/drm/i915/gt/intel_context.h */
static inline bool intel_context_pin_if_active(struct intel_context *ce)
{
	return atomic_inc_not_zero(&ce->pin_count);
}

static void (*klpe___intel_context_do_unpin)(struct intel_context *ce, int sub);

static inline void klpr_intel_context_unpin(struct intel_context *ce)
{
	if (!ce->ops->sched_disable) {
		(*klpe___intel_context_do_unpin)(ce, 1);
	} else {
		/*
		 * Move ownership of this pin to the scheduling disable which is
		 * an async operation. When that operation completes the above
		 * intel_context_sched_disable_unpin is called potentially
		 * unpinning the context.
		 */
		while (!atomic_add_unless(&ce->pin_count, -1, 1)) {
			if (atomic_cmpxchg(&ce->pin_count, 1, 2) == 1) {
				ce->ops->sched_disable(ce);
				break;
			}
		}
	}
}

/* klp-ccp: from drivers/gpu/drm/i915/gem/i915_gem_context.h */
static void (*klpe_i915_gem_context_release)(struct kref *ctx_ref);

static inline void klpr_i915_gem_context_put(struct i915_gem_context *ctx)
{
	kref_put(&ctx->ref, (*klpe_i915_gem_context_release));
}

static inline struct i915_gem_engines *
i915_gem_context_engines(struct i915_gem_context *ctx)
{
	return rcu_dereference_protected(ctx->engines,
					 lockdep_is_held(&ctx->engines_mutex));
}

static inline struct i915_gem_engines *
i915_gem_context_lock_engines(struct i915_gem_context *ctx)
	__acquires(&ctx->engines_mutex)
{
	mutex_lock(&ctx->engines_mutex);
	return i915_gem_context_engines(ctx);
}

static inline void
i915_gem_context_unlock_engines(struct i915_gem_context *ctx)
	__releases(&ctx->engines_mutex)
{
	mutex_unlock(&ctx->engines_mutex);
}

static inline void
i915_gem_engines_iter_init(struct i915_gem_engines_iter *it,
			   struct i915_gem_engines *engines)
{
	it->engines = engines;
	it->idx = 0;
}

static struct intel_context *
(*klpe_i915_gem_engines_iter_next)(struct i915_gem_engines_iter *it);

/* klp-ccp: from drivers/gpu/drm/i915/gem/i915_gem_internal.h */
#include <linux/types.h>
/* klp-ccp: from drivers/gpu/drm/i915/gt/intel_gt_pm.h */
#include <linux/types.h>

/* klp-ccp: from drivers/gpu/drm/i915/gt/intel_engine_regs.h */
#define GEN8_R_PWR_CLK_STATE(base)		_MMIO((base) + 0xc8)

/* klp-ccp: from drivers/gpu/drm/i915/gt/intel_engine_user.h */
#include <linux/types.h>
/* klp-ccp: from drivers/gpu/drm/i915/gt/intel_execlists_submission.h */
#include <linux/llist.h>
#include <linux/types.h>
/* klp-ccp: from drivers/gpu/drm/i915/gt/intel_gpu_commands.h */
#include <linux/bitops.h>
/* klp-ccp: from drivers/gpu/drm/i915/gt/intel_gt_clock_utils.h */
#include <linux/types.h>

/* klp-ccp: from drivers/gpu/drm/i915/gt/intel_gt_regs.h */
#define RPM_CONFIG1				_MMIO(0xd04)
#define   GEN10_GT_NOA_ENABLE			(1 << 9)

#define EU_PERF_CNTL0				_MMIO(0xe458)
#define EU_PERF_CNTL4				_MMIO(0xe45c)

#define EU_PERF_CNTL1				_MMIO(0xe558)
#define EU_PERF_CNTL5				_MMIO(0xe55c)

#define EU_PERF_CNTL2				_MMIO(0xe658)
#define EU_PERF_CNTL6				_MMIO(0xe65c)
#define EU_PERF_CNTL3				_MMIO(0xe758)

/* klp-ccp: from drivers/gpu/drm/i915/gt/intel_lrc.h */
#include <linux/bitfield.h>
#include <linux/types.h>
/* klp-ccp: from drivers/gpu/drm/i915/gt/intel_lrc_reg.h */
#include <linux/types.h>

#define CTX_R_PWR_CLK_STATE		(0x42 + 1)

/* klp-ccp: from drivers/gpu/drm/i915/i915_file_private.h */
#include <linux/mutex.h>
#include <linux/types.h>
#include <linux/xarray.h>
/* klp-ccp: from drivers/gpu/drm/i915/i915_perf.h */
#include <linux/kref.h>
#include <linux/types.h>

/* klp-ccp: from drivers/gpu/drm/i915/i915_perf_oa_regs.h */
#define GEN8_OA_DEBUG _MMIO(0x2B04)
#define  GEN9_OA_DEBUG_DISABLE_CLK_RATIO_REPORTS    (1 << 5)
#define  GEN9_OA_DEBUG_INCLUDE_CLK_RATIO	    (1 << 6)

#define GEN8_OACTXCONTROL _MMIO(0x2360)

#define  GEN8_OA_TIMER_PERIOD_SHIFT	    2
#define  GEN8_OA_TIMER_ENABLE		    (1 << 1)
#define  GEN8_OA_COUNTER_RESUME		    (1 << 0)

#define GEN12_OAG_OAGLBCTXCTRL _MMIO(0x2b28)
#define  GEN12_OAG_OAGLBCTXCTRL_TIMER_PERIOD_SHIFT 2
#define  GEN12_OAG_OAGLBCTXCTRL_TIMER_ENABLE       (1 << 1)
#define  GEN12_OAG_OAGLBCTXCTRL_COUNTER_RESUME     (1 << 0)

#define GEN12_OAG_OA_DEBUG _MMIO(0xdaf8)
#define  GEN12_OAG_OA_DEBUG_INCLUDE_CLK_RATIO          (1 << 6)
#define  GEN12_OAG_OA_DEBUG_DISABLE_CLK_RATIO_REPORTS  (1 << 5)

#define  GEN12_OAG_OA_DEBUG_DISABLE_CTX_SWITCH_REPORTS (1 << 1)

#define GDT_CHICKEN_BITS    _MMIO(0x9840)
#define   GT_NOA_ENABLE	    0x00000080

/* klp-ccp: from drivers/gpu/drm/i915/i915_perf.c */
#define SAMPLE_OA_REPORT      (1<<0)

static int
(*klpe_emit_oa_config)(struct i915_perf_stream *stream,
	       struct i915_oa_config *oa_config,
	       struct intel_context *ce,
	       struct i915_active *active);

static struct intel_context *oa_context(struct i915_perf_stream *stream)
{
	return stream->pinned_ctx ?: stream->engine->kernel_context;
}

static u32 oa_config_flex_reg(const struct i915_oa_config *oa_config,
			      i915_reg_t reg)
{
	u32 mmio = i915_mmio_reg_offset(reg);
	int i;

	/*
	 * This arbitrary default will select the 'EU FPU0 Pipeline
	 * Active' event. In the future it's anticipated that there
	 * will be an explicit 'No Event' we can select, but not yet...
	 */
	if (!oa_config)
		return 0;

	for (i = 0; i < oa_config->flex_regs_len; i++) {
		if (i915_mmio_reg_offset(oa_config->flex_regs[i].addr) == mmio)
			return oa_config->flex_regs[i].value;
	}

	return 0;
}

struct flex {
	i915_reg_t reg;
	u32 offset;
	u32 value;
};

static int (*klpe_gen8_modify_context)(struct intel_context *ce,
			       const struct flex *flex, unsigned int count);

static int
(*klpe_gen8_modify_self)(struct intel_context *ce,
		 const struct flex *flex, unsigned int count,
		 struct i915_active *active);

static int klpr_gen8_configure_context(struct i915_gem_context *ctx,
				  struct flex *flex, unsigned int count)
{
	struct i915_gem_engines_iter it;
	struct intel_context *ce;
	int err = 0;

	for (i915_gem_engines_iter_init(&(it), (i915_gem_context_lock_engines(ctx))); ((ce) = (*klpe_i915_gem_engines_iter_next)(&(it)));) {
		GEM_BUG_ON(ce == ce->engine->kernel_context);

		if (ce->engine->class != RENDER_CLASS)
			continue;

		/* Otherwise OA settings will be set upon first use */
		if (!intel_context_pin_if_active(ce))
			continue;

		flex->value = (*klpe_intel_sseu_make_rpcs)(ce->engine->gt, &ce->sseu);
		err = (*klpe_gen8_modify_context)(ce, flex, count);

		klpr_intel_context_unpin(ce);
		if (err)
			break;
	}
	i915_gem_context_unlock_engines(ctx);

	return err;
}

static int (*klpe_gen12_configure_oar_context)(struct i915_perf_stream *stream,
				       struct i915_active *active);

static int
klpp_oa_configure_all_contexts(struct i915_perf_stream *stream,
			  struct flex *regs,
			  size_t num_regs,
			  struct i915_active *active)
{
	struct drm_i915_private *i915 = stream->perf->i915;
	struct intel_engine_cs *engine;
	struct i915_gem_context *ctx, *cn;
	int err;

	lockdep_assert_held(&stream->perf->lock);

	/*
	 * The OA register config is setup through the context image. This image
	 * might be written to by the GPU on context switch (in particular on
	 * lite-restore). This means we can't safely update a context's image,
	 * if this context is scheduled/submitted to run on the GPU.
	 *
	 * We could emit the OA register config through the batch buffer but
	 * this might leave small interval of time where the OA unit is
	 * configured at an invalid sampling period.
	 *
	 * Note that since we emit all requests from a single ring, there
	 * is still an implicit global barrier here that may cause a high
	 * priority context to wait for an otherwise independent low priority
	 * context. Contexts idle at the time of reconfiguration are not
	 * trapped behind the barrier.
	 */
	spin_lock(&i915->gem.contexts.lock);
	list_for_each_entry_safe(ctx, cn, &i915->gem.contexts.list, link) {
		if (!kref_get_unless_zero(&ctx->ref))
			continue;

		spin_unlock(&i915->gem.contexts.lock);

		err = klpr_gen8_configure_context(ctx, regs, num_regs);
		if (err) {
			klpr_i915_gem_context_put(ctx);
			return err;
		}

		spin_lock(&i915->gem.contexts.lock);
		if (ctx->link.next == LIST_POISON1) {
			spin_unlock(&i915->gem.contexts.lock);
			klpr_i915_gem_context_put(ctx);
			return -EAGAIN;
		}
		list_safe_reset_next(ctx, cn, link);
		klpr_i915_gem_context_put(ctx);
	}
	spin_unlock(&i915->gem.contexts.lock);

	/*
	 * After updating all other contexts, we need to modify ourselves.
	 * If we don't modify the kernel_context, we do not get events while
	 * idle.
	 */
	for_each_uabi_engine(engine, i915) {
		struct intel_context *ce = engine->kernel_context;

		if (engine->class != RENDER_CLASS)
			continue;

		regs[0].value = (*klpe_intel_sseu_make_rpcs)(engine->gt, &ce->sseu);

		err = (*klpe_gen8_modify_self)(ce, regs, num_regs, active);
		if (err)
			return err;
	}

	return 0;
}

static int
klpp_gen12_configure_all_contexts(struct i915_perf_stream *stream,
			     const struct i915_oa_config *oa_config,
			     struct i915_active *active)
{
	struct flex regs[] = {
		{
			GEN8_R_PWR_CLK_STATE(RENDER_RING_BASE),
			CTX_R_PWR_CLK_STATE,
		},
	};

	return klpp_oa_configure_all_contexts(stream,
					 regs, ARRAY_SIZE(regs),
					 active);
}

static int
klpp_lrc_configure_all_contexts(struct i915_perf_stream *stream,
			   const struct i915_oa_config *oa_config,
			   struct i915_active *active)
{
	/* The MMIO offsets for Flex EU registers aren't contiguous */
	const u32 ctx_flexeu0 = stream->perf->ctx_flexeu0_offset;
#define ctx_flexeuN(N) (ctx_flexeu0 + 2 * (N) + 1)
	struct flex regs[] = {
		{
			GEN8_R_PWR_CLK_STATE(RENDER_RING_BASE),
			CTX_R_PWR_CLK_STATE,
		},
		{
			GEN8_OACTXCONTROL,
			stream->perf->ctx_oactxctrl_offset + 1,
		},
		{ EU_PERF_CNTL0, ctx_flexeuN(0) },
		{ EU_PERF_CNTL1, ctx_flexeuN(1) },
		{ EU_PERF_CNTL2, ctx_flexeuN(2) },
		{ EU_PERF_CNTL3, ctx_flexeuN(3) },
		{ EU_PERF_CNTL4, ctx_flexeuN(4) },
		{ EU_PERF_CNTL5, ctx_flexeuN(5) },
		{ EU_PERF_CNTL6, ctx_flexeuN(6) },
	};
	int i;

	regs[1].value =
		(stream->period_exponent << GEN8_OA_TIMER_PERIOD_SHIFT) |
		(stream->periodic ? GEN8_OA_TIMER_ENABLE : 0) |
		GEN8_OA_COUNTER_RESUME;

	for (i = 2; i < ARRAY_SIZE(regs); i++)
		regs[i].value = oa_config_flex_reg(oa_config, regs[i].reg);

	return klpp_oa_configure_all_contexts(stream,
					 regs, ARRAY_SIZE(regs),
					 active);
}

int klpp_gen8_enable_metric_set(struct i915_perf_stream *stream,
		       struct i915_active *active)
{
	struct intel_uncore *uncore = stream->uncore;
	struct i915_oa_config *oa_config = stream->oa_config;
	int ret;

	/*
	 * We disable slice/unslice clock ratio change reports on SKL since
	 * they are too noisy. The HW generates a lot of redundant reports
	 * where the ratio hasn't really changed causing a lot of redundant
	 * work to processes and increasing the chances we'll hit buffer
	 * overruns.
	 *
	 * Although we don't currently use the 'disable overrun' OABUFFER
	 * feature it's worth noting that clock ratio reports have to be
	 * disabled before considering to use that feature since the HW doesn't
	 * correctly block these reports.
	 *
	 * Currently none of the high-level metrics we have depend on knowing
	 * this ratio to normalize.
	 *
	 * Note: This register is not power context saved and restored, but
	 * that's OK considering that we disable RC6 while the OA unit is
	 * enabled.
	 *
	 * The _INCLUDE_CLK_RATIO bit allows the slice/unslice frequency to
	 * be read back from automatically triggered reports, as part of the
	 * RPT_ID field.
	 */
	if (IS_GRAPHICS_VER(stream->perf->i915, 9, 11)) {
		intel_uncore_write(uncore, GEN8_OA_DEBUG,
				   _MASKED_BIT_ENABLE(GEN9_OA_DEBUG_DISABLE_CLK_RATIO_REPORTS |
						      GEN9_OA_DEBUG_INCLUDE_CLK_RATIO));
	}

	/*
	 * Update all contexts prior writing the mux configurations as we need
	 * to make sure all slices/subslices are ON before writing to NOA
	 * registers.
	 */
	ret = klpp_lrc_configure_all_contexts(stream, oa_config, active);
	if (ret)
		return ret;

	return (*klpe_emit_oa_config)(stream,
			      stream->oa_config, oa_context(stream),
			      active);
}

static u32 oag_report_ctx_switches(const struct i915_perf_stream *stream)
{
	return _MASKED_FIELD(GEN12_OAG_OA_DEBUG_DISABLE_CTX_SWITCH_REPORTS,
			     (stream->sample_flags & SAMPLE_OA_REPORT) ?
			     0 : GEN12_OAG_OA_DEBUG_DISABLE_CTX_SWITCH_REPORTS);
}

int klpp_gen12_enable_metric_set(struct i915_perf_stream *stream,
			struct i915_active *active)
{
	struct intel_uncore *uncore = stream->uncore;
	struct i915_oa_config *oa_config = stream->oa_config;
	bool periodic = stream->periodic;
	u32 period_exponent = stream->period_exponent;
	int ret;

	intel_uncore_write(uncore, GEN12_OAG_OA_DEBUG,
			   /* Disable clk ratio reports, like previous Gens. */
			   _MASKED_BIT_ENABLE(GEN12_OAG_OA_DEBUG_DISABLE_CLK_RATIO_REPORTS |
					      GEN12_OAG_OA_DEBUG_INCLUDE_CLK_RATIO) |
			   /*
			    * If the user didn't require OA reports, instruct
			    * the hardware not to emit ctx switch reports.
			    */
			   oag_report_ctx_switches(stream));

	intel_uncore_write(uncore, GEN12_OAG_OAGLBCTXCTRL, periodic ?
			   (GEN12_OAG_OAGLBCTXCTRL_COUNTER_RESUME |
			    GEN12_OAG_OAGLBCTXCTRL_TIMER_ENABLE |
			    (period_exponent << GEN12_OAG_OAGLBCTXCTRL_TIMER_PERIOD_SHIFT))
			    : 0);

	/*
	 * Update all contexts prior writing the mux configurations as we need
	 * to make sure all slices/subslices are ON before writing to NOA
	 * registers.
	 */
	ret = klpp_gen12_configure_all_contexts(stream, oa_config, active);
	if (ret)
		return ret;

	/*
	 * For Gen12, performance counters are context
	 * saved/restored. Only enable it for the context that
	 * requested this.
	 */
	if (stream->ctx) {
		ret = (*klpe_gen12_configure_oar_context)(stream, active);
		if (ret)
			return ret;
	}

	return (*klpe_emit_oa_config)(stream,
			      stream->oa_config, oa_context(stream),
			      active);
}

void klpp_gen8_disable_metric_set(struct i915_perf_stream *stream)
{
	struct intel_uncore *uncore = stream->uncore;

	/* Reset all contexts' slices/subslices configurations. */
	klpp_lrc_configure_all_contexts(stream, NULL, NULL);

	intel_uncore_rmw(uncore, GDT_CHICKEN_BITS, GT_NOA_ENABLE, 0);
}

void klpp_gen11_disable_metric_set(struct i915_perf_stream *stream)
{
	struct intel_uncore *uncore = stream->uncore;

	/* Reset all contexts' slices/subslices configurations. */
	klpp_lrc_configure_all_contexts(stream, NULL, NULL);

	/* Make sure we disable noa to save power. */
	intel_uncore_rmw(uncore, RPM_CONFIG1, GEN10_GT_NOA_ENABLE, 0);
}

void klpp_gen12_disable_metric_set(struct i915_perf_stream *stream)
{
	struct intel_uncore *uncore = stream->uncore;

	/* Reset all contexts' slices/subslices configurations. */
	klpp_gen12_configure_all_contexts(stream, NULL, NULL);

	/* disable the context save/restore or OAR counters */
	if (stream->ctx)
		(*klpe_gen12_configure_oar_context)(stream, NULL);

	/* Make sure we disable noa to save power. */
	intel_uncore_rmw(uncore, RPM_CONFIG1, GEN10_GT_NOA_ENABLE, 0);
}


#include "livepatch_bsc1223521.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "i915"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "__intel_context_do_unpin", (void *)&klpe___intel_context_do_unpin,
	  "i915" },
	{ "emit_oa_config", (void *)&klpe_emit_oa_config, "i915" },
	{ "gen12_configure_oar_context",
	  (void *)&klpe_gen12_configure_oar_context, "i915" },
	{ "gen8_modify_context", (void *)&klpe_gen8_modify_context, "i915" },
	{ "gen8_modify_self", (void *)&klpe_gen8_modify_self, "i915" },
	{ "i915_gem_context_release", (void *)&klpe_i915_gem_context_release,
	  "i915" },
	{ "i915_gem_engines_iter_next",
	  (void *)&klpe_i915_gem_engines_iter_next, "i915" },
	{ "intel_sseu_make_rpcs", (void *)&klpe_intel_sseu_make_rpcs, "i915" },
};

static int module_notify(struct notifier_block *nb,
			unsigned long action, void *data)
{
	struct module *mod = data;
	int ret;

	if (action != MODULE_STATE_COMING || strcmp(mod->name, LP_MODULE))
		return 0;
	ret = klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));

	WARN(ret, "%s: delayed kallsyms lookup failed. System is broken and can crash.\n",
		__func__);

	return ret;
}

static struct notifier_block module_nb = {
	.notifier_call = module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1223521_init(void)
{
	int ret;
	struct module *mod;

	ret = klp_kallsyms_relocs_init();
	if (ret)
		return ret;

	ret = register_module_notifier(&module_nb);
	if (ret)
		return ret;

	rcu_read_lock_sched();
	mod = (*klpe_find_module)(LP_MODULE);
	if (!try_module_get(mod))
		mod = NULL;
	rcu_read_unlock_sched();

	if (mod) {
		ret = klp_resolve_kallsyms_relocs(klp_funcs,
						ARRAY_SIZE(klp_funcs));
	}

	if (ret)
		unregister_module_notifier(&module_nb);
	module_put(mod);

	return ret;
}

void livepatch_bsc1223521_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}

#endif /* IS_ENABLED(CONFIG_DRM_I915) */
