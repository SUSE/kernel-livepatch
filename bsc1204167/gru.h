/* klp-ccp: from drivers/misc/sgi-gru/gru.h */
#define GRU_GSEG_PAGESIZE	(256 * 1024UL)		/* ZZZ 2MB ??? */

/* klp-ccp: from drivers/misc/sgi-gru/gruhandles.h */
#define GRU_NUM_TFM		16

#define GRU_NUM_CBE		128

#define GRU_NUM_CCH		16

#define GRU_GSEG_STRIDE		(4 * 1024 * 1024)

#define GRU_CBR_AU_SIZE		2
#define GRU_CBR_AU		(GRU_NUM_CBE / GRU_CBR_AU_SIZE)

#define gru_dbg(x...)

#define TSID(a, v)		(((a) - (v)->vm_start) / GRU_GSEG_PAGESIZE)

struct gru_gseg_statistics {
	unsigned long	fmm_tlbmiss;
	unsigned long	upm_tlbmiss;
	unsigned long	tlbdropin;
	unsigned long	context_stolen;
	unsigned long	reserved[10];
};

struct gru_stats_s {
	atomic_long_t vdata_alloc;
	atomic_long_t vdata_free;
	atomic_long_t gts_alloc;
	atomic_long_t gts_free;
	atomic_long_t gms_alloc;
	atomic_long_t gms_free;
	atomic_long_t gts_double_allocate;
	atomic_long_t assign_context;
	atomic_long_t assign_context_failed;
	atomic_long_t free_context;
	atomic_long_t load_user_context;
	atomic_long_t load_kernel_context;
	atomic_long_t lock_kernel_context;
	atomic_long_t unlock_kernel_context;
	atomic_long_t steal_user_context;
	atomic_long_t steal_kernel_context;
	atomic_long_t steal_context_failed;
	atomic_long_t nopfn;
	atomic_long_t asid_new;
	atomic_long_t asid_next;
	atomic_long_t asid_wrap;
	atomic_long_t asid_reuse;
	atomic_long_t intr;
	atomic_long_t intr_cbr;
	atomic_long_t intr_tfh;
	atomic_long_t intr_spurious;
	atomic_long_t intr_mm_lock_failed;
	atomic_long_t call_os;
	atomic_long_t call_os_wait_queue;
	atomic_long_t user_flush_tlb;
	atomic_long_t user_unload_context;
	atomic_long_t user_exception;
	atomic_long_t set_context_option;
	atomic_long_t check_context_retarget_intr;
	atomic_long_t check_context_unload;
	atomic_long_t tlb_dropin;
	atomic_long_t tlb_preload_page;
	atomic_long_t tlb_dropin_fail_no_asid;
	atomic_long_t tlb_dropin_fail_upm;
	atomic_long_t tlb_dropin_fail_invalid;
	atomic_long_t tlb_dropin_fail_range_active;
	atomic_long_t tlb_dropin_fail_idle;
	atomic_long_t tlb_dropin_fail_fmm;
	atomic_long_t tlb_dropin_fail_no_exception;
	atomic_long_t tfh_stale_on_fault;
	atomic_long_t mmu_invalidate_range;
	atomic_long_t mmu_invalidate_page;
	atomic_long_t flush_tlb;
	atomic_long_t flush_tlb_gru;
	atomic_long_t flush_tlb_gru_tgh;
	atomic_long_t flush_tlb_gru_zero_asid;

	atomic_long_t copy_gpa;
	atomic_long_t read_gpa;

	atomic_long_t mesq_receive;
	atomic_long_t mesq_receive_none;
	atomic_long_t mesq_send;
	atomic_long_t mesq_send_failed;
	atomic_long_t mesq_noop;
	atomic_long_t mesq_send_unexpected_error;
	atomic_long_t mesq_send_lb_overflow;
	atomic_long_t mesq_send_qlimit_reached;
	atomic_long_t mesq_send_amo_nacked;
	atomic_long_t mesq_send_put_nacked;
	atomic_long_t mesq_page_overflow;
	atomic_long_t mesq_qf_locked;
	atomic_long_t mesq_qf_noop_not_full;
	atomic_long_t mesq_qf_switch_head_failed;
	atomic_long_t mesq_qf_unexpected_error;
	atomic_long_t mesq_noop_unexpected_error;
	atomic_long_t mesq_noop_lb_overflow;
	atomic_long_t mesq_noop_qlimit_reached;
	atomic_long_t mesq_noop_amo_nacked;
	atomic_long_t mesq_noop_put_nacked;
	atomic_long_t mesq_noop_page_overflow;

};

struct gru_thread_state {
	struct list_head	ts_next;	/* list - head at vma-private */
	struct mutex		ts_ctxlock;	/* load/unload CTX lock */
	struct mm_struct	*ts_mm;		/* mm currently mapped to
						   context */
	struct vm_area_struct	*ts_vma;	/* vma of GRU context */
	struct gru_state	*ts_gru;	/* GRU where the context is
						   loaded */
	struct gru_mm_struct	*ts_gms;	/* asid & ioproc struct */
	unsigned char		ts_tlb_preload_count; /* TLB preload pages */
	unsigned long		ts_cbr_map;	/* map of allocated CBRs */
	unsigned long		ts_dsr_map;	/* map of allocated DATA
						   resources */
	unsigned long		ts_steal_jiffies;/* jiffies when context last
						    stolen */
	long			ts_user_options;/* misc user option flags */
	pid_t			ts_tgid_owner;	/* task that is using the
						   context - for migration */
	short			ts_user_blade_id;/* user selected blade */
	char			ts_user_chiplet_id;/* user selected chiplet */
	unsigned short		ts_sizeavail;	/* Pagesizes in use */
	int			ts_tsid;	/* thread that owns the
						   structure */
	int			ts_tlb_int_select;/* target cpu if interrupts
						     enabled */
	int			ts_ctxnum;	/* context number where the
						   context is loaded */
	atomic_t		ts_refcnt;	/* reference count GTS */
	unsigned char		ts_dsr_au_count;/* Number of DSR resources
						   required for contest */
	unsigned char		ts_cbr_au_count;/* Number of CBR resources
						   required for contest */
	char			ts_cch_req_slice;/* CCH packet slice */
	char			ts_blade;	/* If >= 0, migrate context if
						   ref from different blade */
	char			ts_force_cch_reload;
	char			ts_cbr_idx[GRU_CBR_AU];/* CBR numbers of each
							  allocated CB */
	int			ts_data_valid;	/* Indicates if ts_gdata has
						   valid data */
	struct gru_gseg_statistics ustats;	/* User statistics */
	unsigned long		ts_gdata[0];	/* save area for GRU data (CB,
						   DS, CBE) */
};

struct gru_state {
	struct gru_blade_state	*gs_blade;		/* GRU state for entire
							   blade */
	unsigned long		gs_gru_base_paddr;	/* Physical address of
							   gru segments (64) */
	void			*gs_gru_base_vaddr;	/* Virtual address of
							   gru segments (64) */
	unsigned short		gs_gid;			/* unique GRU number */
	unsigned short		gs_blade_id;		/* blade of GRU */
	unsigned char		gs_chiplet_id;		/* blade chiplet of GRU */
	unsigned char		gs_tgh_local_shift;	/* used to pick TGH for
							   local flush */
	unsigned char		gs_tgh_first_remote;	/* starting TGH# for
							   remote flush */
	spinlock_t		gs_asid_lock;		/* lock used for
							   assigning asids */
	spinlock_t		gs_lock;		/* lock used for
							   assigning contexts */

	/* -- the following are protected by the gs_asid_lock spinlock ---- */
	unsigned int		gs_asid;		/* Next availe ASID */
	unsigned int		gs_asid_limit;		/* Limit of available
							   ASIDs */
	unsigned int		gs_asid_gen;		/* asid generation.
							   Inc on wrap */

	/* --- the following fields are protected by the gs_lock spinlock --- */
	unsigned long		gs_context_map;		/* bitmap to manage
							   contexts in use */
	unsigned long		gs_cbr_map;		/* bitmap to manage CB
							   resources */
	unsigned long		gs_dsr_map;		/* bitmap used to manage
							   DATA resources */
	unsigned int		gs_reserved_cbrs;	/* Number of kernel-
							   reserved cbrs */
	unsigned int		gs_reserved_dsr_bytes;	/* Bytes of kernel-
							   reserved dsrs */
	unsigned short		gs_active_contexts;	/* number of contexts
							   in use */
	struct gru_thread_state	*gs_gts[GRU_NUM_CCH];	/* GTS currently using
							   the context */
	int			gs_irq[GRU_NUM_TFM];	/* Interrupt irqs */
};

#define KLPR_OPT_DPRINT		1
#define KLPR_OPT_STATS		2

#define KLPR_STAT(id)	do {						\
				if ((*klpe_gru_options) & KLPR_OPT_STATS) \
					atomic_long_inc(&(*klpe_gru_stats).id);	\
			} while (0)

int klpp_gru_check_context_placement(struct gru_thread_state *gts);
