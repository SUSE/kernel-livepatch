/*
 * livepatch_bsc1226184
 *
 * Fix for CVE-2024-27029, bsc#1226184
 *
 *  Upstream commit:
 *  6540ff6482c1 ("drm/amdgpu: fix mmhub client id out-of-bounds access")
 *
 *  SLE12-SP5 commit:
 *  Not affected
 *
 *  SLE15-SP2 and -SP3 commit:
 *  Not affected
 *
 *  SLE15-SP4 and -SP5 commit:
 *  Not affected
 *
 *  SLE15-SP6 commit:
 *  b55a702970015f4c69a3dd299da595fba8af0d52
 *
 *  Copyright (c) 2025 SUSE
 *  Author: Fernando Gonzalez <fernando.gonzalez@suse.com>
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

#if IS_ENABLED(CONFIG_DRM_AMDGPU)

#if !IS_MODULE(CONFIG_DRM_AMDGPU)
#error "Live patch supports only CONFIG=m"
#endif

/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu_ctx.h */
#include <linux/ktime.h>
#include <linux/types.h>

/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu_ring.h */
#include <drm/amdgpu_drm.h>
#include <drm/gpu_scheduler.h>
#include <drm/drm_print.h>
#include <drm/drm_suballoc.h>

#define AMDGPU_MAX_RINGS		124
#define AMDGPU_MAX_HWIP_RINGS		64
#define AMDGPU_MAX_GFX_RINGS		2
#define AMDGPU_MAX_SW_GFX_RINGS         2
#define AMDGPU_MAX_COMPUTE_RINGS	8
#define AMDGPU_MAX_VCE_RINGS		3
#define AMDGPU_MAX_UVD_ENC_RINGS	2

enum amdgpu_ring_priority_level {
	AMDGPU_RING_PRIO_0,
	AMDGPU_RING_PRIO_1,
	AMDGPU_RING_PRIO_DEFAULT = 1,
	AMDGPU_RING_PRIO_2,
	AMDGPU_RING_PRIO_MAX
};

enum amdgpu_ib_pool_type {
	/* Normal submissions to the top of the pipeline. */
	AMDGPU_IB_POOL_DELAYED,
	/* Immediate submissions to the bottom of the pipeline. */
	AMDGPU_IB_POOL_IMMEDIATE,
	/* Direct submission to the ring buffer during init and reset. */
	AMDGPU_IB_POOL_DIRECT,

	AMDGPU_IB_POOL_MAX
};

struct amdgpu_sched {
	u32				num_scheds;
	struct drm_gpu_scheduler	*sched[AMDGPU_MAX_HWIP_RINGS];
};

struct amdgpu_fence_driver {
	uint64_t			gpu_addr;
	volatile uint32_t		*cpu_addr;
	/* sync_seq is protected by ring emission lock */
	uint32_t			sync_seq;
	atomic_t			last_seq;
	bool				initialized;
	struct amdgpu_irq_src		*irq_src;
	unsigned			irq_type;
	struct timer_list		fallback_timer;
	unsigned			num_fences_mask;
	spinlock_t			lock;
	struct dma_fence		**fences;
};

struct amdgpu_ring {
	struct amdgpu_device		*adev;
	const struct amdgpu_ring_funcs	*funcs;
	struct amdgpu_fence_driver	fence_drv;
	struct drm_gpu_scheduler	sched;

	struct amdgpu_bo	*ring_obj;
	volatile uint32_t	*ring;
	unsigned		rptr_offs;
	u64			rptr_gpu_addr;
	volatile u32		*rptr_cpu_addr;
	u64			wptr;
	u64			wptr_old;
	unsigned		ring_size;
	unsigned		max_dw;
	int			count_dw;
	uint64_t		gpu_addr;
	uint64_t		ptr_mask;
	uint32_t		buf_mask;
	u32			idx;
	u32			xcc_id;
	u32			xcp_id;
	u32			me;
	u32			pipe;
	u32			queue;
	struct amdgpu_bo	*mqd_obj;
	uint64_t                mqd_gpu_addr;
	void                    *mqd_ptr;
	unsigned                mqd_size;
	uint64_t                eop_gpu_addr;
	u32			doorbell_index;
	bool			use_doorbell;
	bool			use_pollmem;
	unsigned		wptr_offs;
	u64			wptr_gpu_addr;
	volatile u32		*wptr_cpu_addr;
	unsigned		fence_offs;
	u64			fence_gpu_addr;
	volatile u32		*fence_cpu_addr;
	uint64_t		current_ctx;
	char			name[16];
	u32                     trail_seq;
	unsigned		trail_fence_offs;
	u64			trail_fence_gpu_addr;
	volatile u32		*trail_fence_cpu_addr;
	unsigned		cond_exe_offs;
	u64			cond_exe_gpu_addr;
	volatile u32		*cond_exe_cpu_addr;
	unsigned		vm_hub;
	unsigned		vm_inv_eng;
	struct dma_fence	*vmid_wait;
	bool			has_compute_vm_bug;
	bool			no_scheduler;
	int			hw_prio;
	unsigned 		num_hw_submission;
	atomic_t		*sched_score;

	/* used for mes */
	bool			is_mes_queue;
	uint32_t		hw_queue_id;
	struct amdgpu_mes_ctx_data *mes_ctx;

	bool            is_sw_ring;
	unsigned int    entry_index;

};

/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu.h */
#include <linux/atomic.h>
#include <linux/wait.h>
#include <linux/list.h>
#include <linux/kref.h>
#include <linux/rbtree.h>

/* klp-ccp: from include/linux/hashtable.h */
#define _LINUX_HASHTABLE_H

#define DECLARE_HASHTABLE(name, bits)                                   	\
	struct hlist_head name[1 << (bits)]

/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu.h */
#include <linux/dma-fence.h>
#include <linux/pci.h>

#include <drm/ttm/ttm_bo.h>

#include <drm/amdgpu_drm.h>
#include <drm/drm_gem.h>

/* klp-ccp: from drivers/gpu/drm/amd/include/kgd_kfd_interface.h */
#include <linux/types.h>
#include <linux/bitmap.h>
#include <linux/dma-fence.h>

/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu_irq.h */
#include <linux/irqdomain.h>

/* klp-ccp: from drivers/gpu/drm/amd/include/soc15_ih_clientid.h */
enum soc15_ih_clientid {
	SOC15_IH_CLIENTID_IH		= 0x00,
	SOC15_IH_CLIENTID_ACP		= 0x01,
	SOC15_IH_CLIENTID_ATHUB		= 0x02,
	SOC15_IH_CLIENTID_BIF		= 0x03,
	SOC15_IH_CLIENTID_DCE		= 0x04,
	SOC15_IH_CLIENTID_ISP		= 0x05,
	SOC15_IH_CLIENTID_PCIE0		= 0x06,
	SOC15_IH_CLIENTID_RLC		= 0x07,
	SOC15_IH_CLIENTID_SDMA0		= 0x08,
	SOC15_IH_CLIENTID_SDMA1		= 0x09,
	SOC15_IH_CLIENTID_SE0SH		= 0x0a,
	SOC15_IH_CLIENTID_SE1SH		= 0x0b,
	SOC15_IH_CLIENTID_SE2SH		= 0x0c,
	SOC15_IH_CLIENTID_SE3SH		= 0x0d,
	SOC15_IH_CLIENTID_UVD1		= 0x0e,
	SOC15_IH_CLIENTID_THM		= 0x0f,
	SOC15_IH_CLIENTID_UVD		= 0x10,
	SOC15_IH_CLIENTID_VCE0		= 0x11,
	SOC15_IH_CLIENTID_VMC		= 0x12,
	SOC15_IH_CLIENTID_XDMA		= 0x13,
	SOC15_IH_CLIENTID_GRBM_CP	= 0x14,
	SOC15_IH_CLIENTID_ATS		= 0x15,
	SOC15_IH_CLIENTID_ROM_SMUIO	= 0x16,
	SOC15_IH_CLIENTID_DF		= 0x17,
	SOC15_IH_CLIENTID_VCE1		= 0x18,
	SOC15_IH_CLIENTID_PWR		= 0x19,
	SOC15_IH_CLIENTID_RESERVED	= 0x1a,
	SOC15_IH_CLIENTID_UTCL2		= 0x1b,
	SOC15_IH_CLIENTID_EA		= 0x1c,
	SOC15_IH_CLIENTID_UTCL2LOG	= 0x1d,
	SOC15_IH_CLIENTID_MP0		= 0x1e,
	SOC15_IH_CLIENTID_MP1		= 0x1f,

	SOC15_IH_CLIENTID_MAX,

	SOC15_IH_CLIENTID_VCN		= SOC15_IH_CLIENTID_UVD,
	SOC15_IH_CLIENTID_VCN1		= SOC15_IH_CLIENTID_UVD1,
	SOC15_IH_CLIENTID_SDMA2		= SOC15_IH_CLIENTID_ACP,
	SOC15_IH_CLIENTID_SDMA3		= SOC15_IH_CLIENTID_DCE,
	SOC15_IH_CLIENTID_SDMA3_Sienna_Cichlid    = SOC15_IH_CLIENTID_ISP,
	SOC15_IH_CLIENTID_SDMA4		= SOC15_IH_CLIENTID_ISP,
	SOC15_IH_CLIENTID_SDMA5		= SOC15_IH_CLIENTID_VCE0,
	SOC15_IH_CLIENTID_SDMA6		= SOC15_IH_CLIENTID_XDMA,
	SOC15_IH_CLIENTID_SDMA7		= SOC15_IH_CLIENTID_VCE1,
	SOC15_IH_CLIENTID_VMC1		= SOC15_IH_CLIENTID_PCIE0,
};

/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu_ih.h */
struct amdgpu_ih_regs {
	uint32_t ih_rb_base;
	uint32_t ih_rb_base_hi;
	uint32_t ih_rb_cntl;
	uint32_t ih_rb_wptr;
	uint32_t ih_rb_rptr;
	uint32_t ih_doorbell_rptr;
	uint32_t ih_rb_wptr_addr_lo;
	uint32_t ih_rb_wptr_addr_hi;
	uint32_t psp_reg_id;
};

struct amdgpu_ih_ring {
	unsigned		ring_size;
	uint32_t		ptr_mask;
	u32			doorbell_index;
	bool			use_doorbell;
	bool			use_bus_addr;

	struct amdgpu_bo	*ring_obj;
	volatile uint32_t	*ring;
	uint64_t		gpu_addr;

	uint64_t		wptr_addr;
	volatile uint32_t	*wptr_cpu;

	uint64_t		rptr_addr;
	volatile uint32_t	*rptr_cpu;

	bool                    enabled;
	unsigned		rptr;
	struct amdgpu_ih_regs	ih_regs;

	/* For waiting on IH processing at checkpoint. */
	wait_queue_head_t wait_process;
	uint64_t		processed_timestamp;
};

/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu_irq.h */
#define AMDGPU_MAX_IRQ_SRC_ID		0x100

#define AMDGPU_IRQ_CLIENTID_MAX		SOC15_IH_CLIENTID_MAX

struct amdgpu_irq_src {
	unsigned				num_types;
	atomic_t				*enabled_types;
	const struct amdgpu_irq_src_funcs	*funcs;
};

struct amdgpu_irq_client {
	struct amdgpu_irq_src **sources;
};

struct amdgpu_irq {
	bool				installed;
	unsigned int			irq;
	spinlock_t			lock;
	/* interrupt sources */
	struct amdgpu_irq_client	client[AMDGPU_IRQ_CLIENTID_MAX];

	/* status, etc. */
	bool				msi_enabled; /* msi enabled */

	/* interrupt rings */
	struct amdgpu_ih_ring		ih, ih1, ih2, ih_soft;
	const struct amdgpu_ih_funcs    *ih_funcs;
	struct work_struct		ih1_work, ih2_work, ih_soft_work;
	struct amdgpu_irq_src		self_irq;

	/* gen irq stuff */
	struct irq_domain		*domain; /* GPU irq controller domain */
	unsigned			virq[AMDGPU_MAX_IRQ_SRC_ID];
	uint32_t                        srbm_soft_reset;
	u32                             retry_cam_doorbell_index;
	bool                            retry_cam_enabled;
};

/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu_rlc.h */
#define AMDGPU_MAX_RLC_INSTANCES	8

struct amdgpu_rlcg_reg_access_ctrl {
	uint32_t scratch_reg0;
	uint32_t scratch_reg1;
	uint32_t scratch_reg2;
	uint32_t scratch_reg3;
	uint32_t grbm_cntl;
	uint32_t grbm_idx;
	uint32_t spare_int;
};

struct amdgpu_rlc {
	/* for power gating */
	struct amdgpu_bo        *save_restore_obj;
	uint64_t                save_restore_gpu_addr;
	volatile uint32_t       *sr_ptr;
	const u32               *reg_list;
	u32                     reg_list_size;
	/* for clear state */
	struct amdgpu_bo        *clear_state_obj;
	uint64_t                clear_state_gpu_addr;
	volatile uint32_t       *cs_ptr;
	const struct cs_section_def   *cs_data;
	u32                     clear_state_size;
	/* for cp tables */
	struct amdgpu_bo        *cp_table_obj;
	uint64_t                cp_table_gpu_addr;
	volatile uint32_t       *cp_table_ptr;
	u32                     cp_table_size;

	/* safe mode for updating CG/PG state */
	bool in_safe_mode[AMDGPU_MAX_RLC_INSTANCES];
	const struct amdgpu_rlc_funcs *funcs;

	/* for firmware data */
	u32 save_and_restore_offset;
	u32 clear_state_descriptor_offset;
	u32 avail_scratch_ram_locations;
	u32 reg_restore_list_size;
	u32 reg_list_format_start;
	u32 reg_list_format_separate_start;
	u32 starting_offsets_start;
	u32 reg_list_format_size_bytes;
	u32 reg_list_size_bytes;
	u32 reg_list_format_direct_reg_list_length;
	u32 save_restore_list_cntl_size_bytes;
	u32 save_restore_list_gpm_size_bytes;
	u32 save_restore_list_srm_size_bytes;
	u32 rlc_iram_ucode_size_bytes;
	u32 rlc_dram_ucode_size_bytes;
	u32 rlcp_ucode_size_bytes;
	u32 rlcv_ucode_size_bytes;
	u32 global_tap_delays_ucode_size_bytes;
	u32 se0_tap_delays_ucode_size_bytes;
	u32 se1_tap_delays_ucode_size_bytes;
	u32 se2_tap_delays_ucode_size_bytes;
	u32 se3_tap_delays_ucode_size_bytes;

	u32 *register_list_format;
	u32 *register_restore;
	u8 *save_restore_list_cntl;
	u8 *save_restore_list_gpm;
	u8 *save_restore_list_srm;
	u8 *rlc_iram_ucode;
	u8 *rlc_dram_ucode;
	u8 *rlcp_ucode;
	u8 *rlcv_ucode;
	u8 *global_tap_delays_ucode;
	u8 *se0_tap_delays_ucode;
	u8 *se1_tap_delays_ucode;
	u8 *se2_tap_delays_ucode;
	u8 *se3_tap_delays_ucode;

	bool is_rlc_v2_1;

	/* for rlc autoload */
	struct amdgpu_bo	*rlc_autoload_bo;
	u64			rlc_autoload_gpu_addr;
	void			*rlc_autoload_ptr;

	/* rlc toc buffer */
	struct amdgpu_bo	*rlc_toc_bo;
	uint64_t		rlc_toc_gpu_addr;
	void			*rlc_toc_buf;

	bool rlcg_reg_access_supported;
	/* registers for rlcg indirect reg access */
	struct amdgpu_rlcg_reg_access_ctrl reg_access_ctrl[AMDGPU_MAX_RLC_INSTANCES];
};

/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu_imu.h */
enum imu_work_mode {
	DEBUG_MODE,
	MISSION_MODE
};

struct amdgpu_imu {
    const struct amdgpu_imu_funcs *funcs;
    enum imu_work_mode mode;
};

/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu_ras.h */
#include <linux/debugfs.h>
#include <linux/list.h>

/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu_ras_eeprom.h */
#include <linux/i2c.h>

/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu_smuio.h */
struct amdgpu_smuio {
	const struct amdgpu_smuio_funcs		*funcs;
};

/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu_ring_mux.h */
#include <linux/timer.h>
#include <linux/spinlock.h>

struct amdgpu_ring_mux {
	struct amdgpu_ring      *real_ring;

	struct amdgpu_mux_entry *ring_entry;
	unsigned int            num_ring_entries;
	unsigned int            ring_entry_size;
	/*the lock for copy data from different software rings*/
	spinlock_t              lock;
	bool                    s_resubmit;
	uint32_t                seqno_to_resubmit;
	u64                     wptr_resubmit;
	struct timer_list       resubmit_timer;

	bool                    pending_trailing_fence_signaled;
};

/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu_gfx.h */
#define AMDGPU_MAX_GC_INSTANCES		8
#define AMDGPU_MAX_QUEUES		128

#define AMDGPU_MAX_GFX_QUEUES AMDGPU_MAX_QUEUES
#define AMDGPU_MAX_COMPUTE_QUEUES AMDGPU_MAX_QUEUES

struct amdgpu_mec {
	struct amdgpu_bo	*hpd_eop_obj;
	u64			hpd_eop_gpu_addr;
	struct amdgpu_bo	*mec_fw_obj;
	u64			mec_fw_gpu_addr;
	struct amdgpu_bo	*mec_fw_data_obj;
	u64			mec_fw_data_gpu_addr;

	u32 num_mec;
	u32 num_pipe_per_mec;
	u32 num_queue_per_pipe;
	void			*mqd_backup[AMDGPU_MAX_COMPUTE_RINGS * AMDGPU_MAX_GC_INSTANCES];
};

struct amdgpu_mec_bitmap {
	/* These are the resources for which amdgpu takes ownership */
	DECLARE_BITMAP(queue_bitmap, AMDGPU_MAX_COMPUTE_QUEUES);
};

struct amdgpu_kiq {
	u64			eop_gpu_addr;
	struct amdgpu_bo	*eop_obj;
	spinlock_t              ring_lock;
	struct amdgpu_ring	ring;
	struct amdgpu_irq_src	irq;
	const struct kiq_pm4_funcs *pmf;
	void			*mqd_backup;
};

#define AMDGPU_GFX_MAX_SE 4
#define AMDGPU_GFX_MAX_SH_PER_SE 2

struct amdgpu_rb_config {
	uint32_t rb_backend_disable;
	uint32_t user_rb_backend_disable;
	uint32_t raster_config;
	uint32_t raster_config_1;
};

struct gb_addr_config {
	uint16_t pipe_interleave_size;
	uint8_t num_pipes;
	uint8_t max_compress_frags;
	uint8_t num_banks;
	uint8_t num_se;
	uint8_t num_rb_per_se;
	uint8_t num_pkrs;
};

struct amdgpu_gfx_config {
	unsigned max_shader_engines;
	unsigned max_tile_pipes;
	unsigned max_cu_per_sh;
	unsigned max_sh_per_se;
	unsigned max_backends_per_se;
	unsigned max_texture_channel_caches;
	unsigned max_gprs;
	unsigned max_gs_threads;
	unsigned max_hw_contexts;
	unsigned sc_prim_fifo_size_frontend;
	unsigned sc_prim_fifo_size_backend;
	unsigned sc_hiz_tile_fifo_size;
	unsigned sc_earlyz_tile_fifo_size;

	unsigned num_tile_pipes;
	unsigned backend_enable_mask;
	unsigned mem_max_burst_length_bytes;
	unsigned mem_row_size_in_kb;
	unsigned shader_engine_tile_size;
	unsigned num_gpus;
	unsigned multi_gpu_tile_size;
	unsigned mc_arb_ramcfg;
	unsigned num_banks;
	unsigned num_ranks;
	unsigned gb_addr_config;
	unsigned num_rbs;
	unsigned gs_vgt_table_depth;
	unsigned gs_prim_buffer_depth;

	uint32_t tile_mode_array[32];
	uint32_t macrotile_mode_array[16];

	struct gb_addr_config gb_addr_config_fields;
	struct amdgpu_rb_config rb_config[AMDGPU_GFX_MAX_SE][AMDGPU_GFX_MAX_SH_PER_SE];

	/* gfx configure feature */
	uint32_t double_offchip_lds_buf;
	/* cached value of DB_DEBUG2 */
	uint32_t db_debug2;
	/* gfx10 specific config */
	uint32_t num_sc_per_sh;
	uint32_t num_packer_per_sc;
	uint32_t pa_sc_tile_steering_override;
	/* Whether texture coordinate truncation is conformant. */
	bool ta_cntl2_truncate_coord_mode;
	uint64_t tcc_disabled_mask;
	uint32_t gc_num_tcp_per_sa;
	uint32_t gc_num_sdp_interface;
	uint32_t gc_num_tcps;
	uint32_t gc_num_tcp_per_wpg;
	uint32_t gc_tcp_l1_size;
	uint32_t gc_num_sqc_per_wgp;
	uint32_t gc_l1_instruction_cache_size_per_sqc;
	uint32_t gc_l1_data_cache_size_per_sqc;
	uint32_t gc_gl1c_per_sa;
	uint32_t gc_gl1c_size_per_instance;
	uint32_t gc_gl2c_per_gpu;
	uint32_t gc_tcp_size_per_cu;
	uint32_t gc_num_cu_per_sqc;
	uint32_t gc_tcc_size;
};

struct amdgpu_cu_info {
	uint32_t simd_per_cu;
	uint32_t max_waves_per_simd;
	uint32_t wave_front_size;
	uint32_t max_scratch_slots_per_cu;
	uint32_t lds_size;

	/* total active CU number */
	uint32_t number;
	uint32_t ao_cu_mask;
	uint32_t ao_cu_bitmap[4][4];
	uint32_t bitmap[AMDGPU_MAX_GC_INSTANCES][4][4];
};

struct sq_work {
	struct work_struct	work;
	unsigned ih_data;
};

struct amdgpu_pfp {
	struct amdgpu_bo		*pfp_fw_obj;
	uint64_t			pfp_fw_gpu_addr;
	uint32_t			*pfp_fw_ptr;

	struct amdgpu_bo		*pfp_fw_data_obj;
	uint64_t			pfp_fw_data_gpu_addr;
	uint32_t			*pfp_fw_data_ptr;
};

struct amdgpu_ce {
	struct amdgpu_bo		*ce_fw_obj;
	uint64_t			ce_fw_gpu_addr;
	uint32_t			*ce_fw_ptr;
};

struct amdgpu_me {
	struct amdgpu_bo		*me_fw_obj;
	uint64_t			me_fw_gpu_addr;
	uint32_t			*me_fw_ptr;

	struct amdgpu_bo		*me_fw_data_obj;
	uint64_t			me_fw_data_gpu_addr;
	uint32_t			*me_fw_data_ptr;

	uint32_t			num_me;
	uint32_t			num_pipe_per_me;
	uint32_t			num_queue_per_pipe;
	void				*mqd_backup[AMDGPU_MAX_GFX_RINGS];

	/* These are the resources for which amdgpu takes ownership */
	DECLARE_BITMAP(queue_bitmap, AMDGPU_MAX_GFX_QUEUES);
};

struct amdgpu_gfx {
	struct mutex			gpu_clock_mutex;
	struct amdgpu_gfx_config	config;
	struct amdgpu_rlc		rlc;
	struct amdgpu_pfp		pfp;
	struct amdgpu_ce		ce;
	struct amdgpu_me		me;
	struct amdgpu_mec		mec;
	struct amdgpu_mec_bitmap	mec_bitmap[AMDGPU_MAX_GC_INSTANCES];
	struct amdgpu_kiq		kiq[AMDGPU_MAX_GC_INSTANCES];
	struct amdgpu_imu		imu;
	bool				rs64_enable; /* firmware format */
	const struct firmware		*me_fw;	/* ME firmware */
	uint32_t			me_fw_version;
	const struct firmware		*pfp_fw; /* PFP firmware */
	uint32_t			pfp_fw_version;
	const struct firmware		*ce_fw;	/* CE firmware */
	uint32_t			ce_fw_version;
	const struct firmware		*rlc_fw; /* RLC firmware */
	uint32_t			rlc_fw_version;
	const struct firmware		*mec_fw; /* MEC firmware */
	uint32_t			mec_fw_version;
	const struct firmware		*mec2_fw; /* MEC2 firmware */
	uint32_t			mec2_fw_version;
	const struct firmware		*imu_fw; /* IMU firmware */
	uint32_t			imu_fw_version;
	uint32_t			me_feature_version;
	uint32_t			ce_feature_version;
	uint32_t			pfp_feature_version;
	uint32_t			rlc_feature_version;
	uint32_t			rlc_srlc_fw_version;
	uint32_t			rlc_srlc_feature_version;
	uint32_t			rlc_srlg_fw_version;
	uint32_t			rlc_srlg_feature_version;
	uint32_t			rlc_srls_fw_version;
	uint32_t			rlc_srls_feature_version;
	uint32_t			rlcp_ucode_version;
	uint32_t			rlcp_ucode_feature_version;
	uint32_t			rlcv_ucode_version;
	uint32_t			rlcv_ucode_feature_version;
	uint32_t			mec_feature_version;
	uint32_t			mec2_feature_version;
	bool				mec_fw_write_wait;
	bool				me_fw_write_wait;
	bool				cp_fw_write_wait;
	struct amdgpu_ring		gfx_ring[AMDGPU_MAX_GFX_RINGS];
	unsigned			num_gfx_rings;
	struct amdgpu_ring		compute_ring[AMDGPU_MAX_COMPUTE_RINGS * AMDGPU_MAX_GC_INSTANCES];
	unsigned			num_compute_rings;
	struct amdgpu_irq_src		eop_irq;
	struct amdgpu_irq_src		priv_reg_irq;
	struct amdgpu_irq_src		priv_inst_irq;
	struct amdgpu_irq_src		cp_ecc_error_irq;
	struct amdgpu_irq_src		sq_irq;
	struct amdgpu_irq_src		rlc_gc_fed_irq;
	struct sq_work			sq_work;

	/* gfx status */
	uint32_t			gfx_current_status;
	/* ce ram size*/
	unsigned			ce_ram_size;
	struct amdgpu_cu_info		cu_info;
	const struct amdgpu_gfx_funcs	*funcs;

	/* reset mask */
	uint32_t                        grbm_soft_reset;
	uint32_t                        srbm_soft_reset;

	/* gfx off */
	bool                            gfx_off_state;      /* true: enabled, false: disabled */
	struct mutex                    gfx_off_mutex;      /* mutex to change gfxoff state */
	uint32_t                        gfx_off_req_count;  /* default 1, enable gfx off: dec 1, disable gfx off: add 1 */
	struct delayed_work             gfx_off_delay_work; /* async work to set gfx block off */
	uint32_t                        gfx_off_residency;  /* last logged residency */
	uint64_t                        gfx_off_entrycount; /* count of times GPU has get into GFXOFF state */

	/* pipe reservation */
	struct mutex			pipe_reserve_mutex;
	DECLARE_BITMAP			(pipe_reserve_bitmap, AMDGPU_MAX_COMPUTE_QUEUES);

	/*ras */
	struct ras_common_if		*ras_if;
	struct amdgpu_gfx_ras		*ras;

	bool				is_poweron;

	struct amdgpu_ring		sw_gfx_ring[AMDGPU_MAX_SW_GFX_RINGS];
	struct amdgpu_ring_mux          muxer;

	bool				cp_gfx_shadow; /* for gfx11 */

	uint16_t 			xcc_mask;
	uint32_t			num_xcc_per_xcp;
	struct mutex			partition_mutex;
	bool				mcbp; /* mid command buffer preemption */
};

/* klp-ccp: from drivers/gpu/drm/amd/display/dc/os_types.h */
#include <linux/slab.h>
#include <linux/kgdb.h>
#include <linux/kref.h>
#include <linux/types.h>

/* klp-ccp: from include/linux/delay.h */
#define _LINUX_DELAY_H

/* klp-ccp: from drivers/gpu/drm/amd/display/dc/os_types.h */
#include <linux/mm.h>

#include <asm/byteorder.h>

#include <drm/display/drm_dp_helper.h>
#include <drm/drm_device.h>
#include <drm/drm_print.h>

/* klp-ccp: from drivers/gpu/drm/amd/include/amd_shared.h */
#include <drm/amd_asic_type.h>

enum amd_ip_block_type {
	AMD_IP_BLOCK_TYPE_COMMON,
	AMD_IP_BLOCK_TYPE_GMC,
	AMD_IP_BLOCK_TYPE_IH,
	AMD_IP_BLOCK_TYPE_SMC,
	AMD_IP_BLOCK_TYPE_PSP,
	AMD_IP_BLOCK_TYPE_DCE,
	AMD_IP_BLOCK_TYPE_GFX,
	AMD_IP_BLOCK_TYPE_SDMA,
	AMD_IP_BLOCK_TYPE_UVD,
	AMD_IP_BLOCK_TYPE_VCE,
	AMD_IP_BLOCK_TYPE_ACP,
	AMD_IP_BLOCK_TYPE_VCN,
	AMD_IP_BLOCK_TYPE_MES,
	AMD_IP_BLOCK_TYPE_JPEG,
	AMD_IP_BLOCK_TYPE_VPE,
	AMD_IP_BLOCK_TYPE_UMSCH_MM,
	AMD_IP_BLOCK_TYPE_NUM,
};

enum amd_powergating_state {
	AMD_PG_STATE_GATE = 0,
	AMD_PG_STATE_UNGATE,
};

/* klp-ccp: from drivers/gpu/drm/amd/display/dc/irq_types.h */
enum dc_irq_source {
	/* Use as mask to specify invalid irq source */
	DC_IRQ_SOURCE_INVALID = 0,

	DC_IRQ_SOURCE_HPD1,
	DC_IRQ_SOURCE_HPD2,
	DC_IRQ_SOURCE_HPD3,
	DC_IRQ_SOURCE_HPD4,
	DC_IRQ_SOURCE_HPD5,
	DC_IRQ_SOURCE_HPD6,

	DC_IRQ_SOURCE_HPD1RX,
	DC_IRQ_SOURCE_HPD2RX,
	DC_IRQ_SOURCE_HPD3RX,
	DC_IRQ_SOURCE_HPD4RX,
	DC_IRQ_SOURCE_HPD5RX,
	DC_IRQ_SOURCE_HPD6RX,

	DC_IRQ_SOURCE_I2C_DDC1,
	DC_IRQ_SOURCE_I2C_DDC2,
	DC_IRQ_SOURCE_I2C_DDC3,
	DC_IRQ_SOURCE_I2C_DDC4,
	DC_IRQ_SOURCE_I2C_DDC5,
	DC_IRQ_SOURCE_I2C_DDC6,

	DC_IRQ_SOURCE_DPSINK1,
	DC_IRQ_SOURCE_DPSINK2,
	DC_IRQ_SOURCE_DPSINK3,
	DC_IRQ_SOURCE_DPSINK4,
	DC_IRQ_SOURCE_DPSINK5,
	DC_IRQ_SOURCE_DPSINK6,

	DC_IRQ_SOURCE_TIMER,

	DC_IRQ_SOURCE_PFLIP_FIRST,
	DC_IRQ_SOURCE_PFLIP1 = DC_IRQ_SOURCE_PFLIP_FIRST,
	DC_IRQ_SOURCE_PFLIP2,
	DC_IRQ_SOURCE_PFLIP3,
	DC_IRQ_SOURCE_PFLIP4,
	DC_IRQ_SOURCE_PFLIP5,
	DC_IRQ_SOURCE_PFLIP6,
	DC_IRQ_SOURCE_PFLIP_UNDERLAY0,
	DC_IRQ_SOURCE_PFLIP_LAST = DC_IRQ_SOURCE_PFLIP_UNDERLAY0,

	DC_IRQ_SOURCE_GPIOPAD0,
	DC_IRQ_SOURCE_GPIOPAD1,
	DC_IRQ_SOURCE_GPIOPAD2,
	DC_IRQ_SOURCE_GPIOPAD3,
	DC_IRQ_SOURCE_GPIOPAD4,
	DC_IRQ_SOURCE_GPIOPAD5,
	DC_IRQ_SOURCE_GPIOPAD6,
	DC_IRQ_SOURCE_GPIOPAD7,
	DC_IRQ_SOURCE_GPIOPAD8,
	DC_IRQ_SOURCE_GPIOPAD9,
	DC_IRQ_SOURCE_GPIOPAD10,
	DC_IRQ_SOURCE_GPIOPAD11,
	DC_IRQ_SOURCE_GPIOPAD12,
	DC_IRQ_SOURCE_GPIOPAD13,
	DC_IRQ_SOURCE_GPIOPAD14,
	DC_IRQ_SOURCE_GPIOPAD15,
	DC_IRQ_SOURCE_GPIOPAD16,
	DC_IRQ_SOURCE_GPIOPAD17,
	DC_IRQ_SOURCE_GPIOPAD18,
	DC_IRQ_SOURCE_GPIOPAD19,
	DC_IRQ_SOURCE_GPIOPAD20,
	DC_IRQ_SOURCE_GPIOPAD21,
	DC_IRQ_SOURCE_GPIOPAD22,
	DC_IRQ_SOURCE_GPIOPAD23,
	DC_IRQ_SOURCE_GPIOPAD24,
	DC_IRQ_SOURCE_GPIOPAD25,
	DC_IRQ_SOURCE_GPIOPAD26,
	DC_IRQ_SOURCE_GPIOPAD27,
	DC_IRQ_SOURCE_GPIOPAD28,
	DC_IRQ_SOURCE_GPIOPAD29,
	DC_IRQ_SOURCE_GPIOPAD30,

	DC_IRQ_SOURCE_DC1UNDERFLOW,
	DC_IRQ_SOURCE_DC2UNDERFLOW,
	DC_IRQ_SOURCE_DC3UNDERFLOW,
	DC_IRQ_SOURCE_DC4UNDERFLOW,
	DC_IRQ_SOURCE_DC5UNDERFLOW,
	DC_IRQ_SOURCE_DC6UNDERFLOW,

	DC_IRQ_SOURCE_DMCU_SCP,
	DC_IRQ_SOURCE_VBIOS_SW,

	DC_IRQ_SOURCE_VUPDATE1,
	DC_IRQ_SOURCE_VUPDATE2,
	DC_IRQ_SOURCE_VUPDATE3,
	DC_IRQ_SOURCE_VUPDATE4,
	DC_IRQ_SOURCE_VUPDATE5,
	DC_IRQ_SOURCE_VUPDATE6,

	DC_IRQ_SOURCE_VBLANK1,
	DC_IRQ_SOURCE_VBLANK2,
	DC_IRQ_SOURCE_VBLANK3,
	DC_IRQ_SOURCE_VBLANK4,
	DC_IRQ_SOURCE_VBLANK5,
	DC_IRQ_SOURCE_VBLANK6,

	DC_IRQ_SOURCE_DC1_VLINE0,
	DC_IRQ_SOURCE_DC2_VLINE0,
	DC_IRQ_SOURCE_DC3_VLINE0,
	DC_IRQ_SOURCE_DC4_VLINE0,
	DC_IRQ_SOURCE_DC5_VLINE0,
	DC_IRQ_SOURCE_DC6_VLINE0,

	DC_IRQ_SOURCE_DC1_VLINE1,
	DC_IRQ_SOURCE_DC2_VLINE1,
	DC_IRQ_SOURCE_DC3_VLINE1,
	DC_IRQ_SOURCE_DC4_VLINE1,
	DC_IRQ_SOURCE_DC5_VLINE1,
	DC_IRQ_SOURCE_DC6_VLINE1,
	DC_IRQ_SOURCE_DMCUB_OUTBOX,
	DC_IRQ_SOURCE_DMCUB_OUTBOX0,
	DC_IRQ_SOURCE_DMCUB_GENERAL_DATAOUT,
	DAL_IRQ_SOURCES_NUMBER
};

/* klp-ccp: from drivers/gpu/drm/amd/include/dm_pp_interface.h */
enum amd_pp_display_config_type{
	AMD_PP_DisplayConfigType_None = 0,
	AMD_PP_DisplayConfigType_DP54 ,
	AMD_PP_DisplayConfigType_DP432 ,
	AMD_PP_DisplayConfigType_DP324 ,
	AMD_PP_DisplayConfigType_DP27,
	AMD_PP_DisplayConfigType_DP243,
	AMD_PP_DisplayConfigType_DP216,
	AMD_PP_DisplayConfigType_DP162,
	AMD_PP_DisplayConfigType_HDMI6G ,
	AMD_PP_DisplayConfigType_HDMI297 ,
	AMD_PP_DisplayConfigType_HDMI162,
	AMD_PP_DisplayConfigType_LVDS,
	AMD_PP_DisplayConfigType_DVI,
	AMD_PP_DisplayConfigType_WIRELESS,
	AMD_PP_DisplayConfigType_VGA
};

struct single_display_configuration
{
	uint32_t controller_index;
	uint32_t controller_id;
	uint32_t signal_type;
	uint32_t display_state;
	/* phy id for the primary internal transmitter */
	uint8_t primary_transmitter_phyi_d;
	/* bitmap with the active lanes */
	uint8_t primary_transmitter_active_lanemap;
	/* phy id for the secondary internal transmitter (for dual-link dvi) */
	uint8_t secondary_transmitter_phy_id;
	/* bitmap with the active lanes */
	uint8_t secondary_transmitter_active_lanemap;
	/* misc phy settings for SMU. */
	uint32_t config_flags;
	uint32_t display_type;
	uint32_t view_resolution_cx;
	uint32_t view_resolution_cy;
	enum amd_pp_display_config_type displayconfigtype;
	uint32_t vertical_refresh; /* for active display */
};

#define MAX_NUM_DISPLAY 32

struct amd_pp_display_configuration {
	bool nb_pstate_switch_disable;/* controls NB PState switch */
	bool cpu_cc6_disable; /* controls CPU CState switch ( on or off) */
	bool cpu_pstate_disable;
	uint32_t cpu_pstate_separation_time;

	uint32_t num_display;  /* total number of display*/
	uint32_t num_path_including_non_display;
	uint32_t crossfire_display_index;
	uint32_t min_mem_set_clock;
	uint32_t min_core_set_clock;
	/* unit 10KHz x bit*/
	uint32_t min_bus_bandwidth;
	/* minimum required stutter sclk, in 10khz uint32_t ulMinCoreSetClk;*/
	uint32_t min_core_set_clock_in_sr;

	struct single_display_configuration displays[MAX_NUM_DISPLAY];

	uint32_t vrefresh; /* for active display*/

	uint32_t min_vblank_time; /* for active display*/
	bool multi_monitor_in_sync;
	/* Controller Index of primary display - used in MCLK SMC switching hang
	 * SW Workaround*/
	uint32_t crtc_index;
	/* htotal*1000/pixelclk - used in MCLK SMC switching hang SW Workaround*/
	uint32_t line_time_in_us;
	bool invalid_vblank_time;

	uint32_t display_clk;
	/*
	 * for given display configuration if multimonitormnsync == false then
	 * Memory clock DPMS with this latency or below is allowed, DPMS with
	 * higher latency not allowed.
	 */
	uint32_t dce_tolerable_mclk_in_active_latency;
	uint32_t min_dcef_set_clk;
	uint32_t min_dcef_deep_sleep_set_clk;
};

/* klp-ccp: from drivers/gpu/drm/amd/include/kgd_pp_interface.h */
struct amd_vce_state {
	/* vce clocks */
	u32 evclk;
	u32 ecclk;
	/* gpu clocks */
	u32 sclk;
	u32 mclk;
	u8 clk_idx;
	u8 pstate;
};

enum amd_dpm_forced_level {
	AMD_DPM_FORCED_LEVEL_AUTO = 0x1,
	AMD_DPM_FORCED_LEVEL_MANUAL = 0x2,
	AMD_DPM_FORCED_LEVEL_LOW = 0x4,
	AMD_DPM_FORCED_LEVEL_HIGH = 0x8,
	AMD_DPM_FORCED_LEVEL_PROFILE_STANDARD = 0x10,
	AMD_DPM_FORCED_LEVEL_PROFILE_MIN_SCLK = 0x20,
	AMD_DPM_FORCED_LEVEL_PROFILE_MIN_MCLK = 0x40,
	AMD_DPM_FORCED_LEVEL_PROFILE_PEAK = 0x80,
	AMD_DPM_FORCED_LEVEL_PROFILE_EXIT = 0x100,
	AMD_DPM_FORCED_LEVEL_PERF_DETERMINISM = 0x200,
};

enum amd_pm_state_type {
	/* not used for dpm */
	POWER_STATE_TYPE_DEFAULT,
	POWER_STATE_TYPE_POWERSAVE,
	/* user selectable states */
	POWER_STATE_TYPE_BATTERY,
	POWER_STATE_TYPE_BALANCED,
	POWER_STATE_TYPE_PERFORMANCE,
	/* internal states */
	POWER_STATE_TYPE_INTERNAL_UVD,
	POWER_STATE_TYPE_INTERNAL_UVD_SD,
	POWER_STATE_TYPE_INTERNAL_UVD_HD,
	POWER_STATE_TYPE_INTERNAL_UVD_HD2,
	POWER_STATE_TYPE_INTERNAL_UVD_MVC,
	POWER_STATE_TYPE_INTERNAL_BOOT,
	POWER_STATE_TYPE_INTERNAL_THERMAL,
	POWER_STATE_TYPE_INTERNAL_ACPI,
	POWER_STATE_TYPE_INTERNAL_ULV,
	POWER_STATE_TYPE_INTERNAL_3DPERF,
};

#define AMD_MAX_VCE_LEVELS 6

enum amd_vce_level {
	AMD_VCE_LEVEL_AC_ALL = 0,     /* AC, All cases */
	AMD_VCE_LEVEL_DC_EE = 1,      /* DC, entropy encoding */
	AMD_VCE_LEVEL_DC_LL_LOW = 2,  /* DC, low latency queue, res <= 720 */
	AMD_VCE_LEVEL_DC_LL_HIGH = 3, /* DC, low latency queue, 1080 >= res > 720 */
	AMD_VCE_LEVEL_DC_GP_LOW = 4,  /* DC, general purpose queue, res <= 720 */
	AMD_VCE_LEVEL_DC_GP_HIGH = 5, /* DC, general purpose queue, 1080 >= res > 720 */
};

enum pp_mp1_state {
	PP_MP1_STATE_NONE,
	PP_MP1_STATE_SHUTDOWN,
	PP_MP1_STATE_UNLOAD,
	PP_MP1_STATE_RESET,
};

/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu_mode.h */
#include <drm/display/drm_dp_helper.h>
#include <drm/drm_crtc.h>

#include <drm/drm_encoder.h>

#include <linux/i2c.h>

#include <linux/hrtimer.h>

#include <drm/display/drm_dp_mst_helper.h>

#define AMDGPU_MAX_CRTCS 6
#define AMDGPU_MAX_PLANES 6
#define AMDGPU_MAX_AFMT_BLOCKS 9

enum amdgpu_rmx_type {
	RMX_OFF,
	RMX_FULL,
	RMX_CENTER,
	RMX_ASPECT
};

enum amdgpu_underscan_type {
	UNDERSCAN_OFF,
	UNDERSCAN_ON,
	UNDERSCAN_AUTO,
};

#define AMDGPU_MAX_I2C_BUS 16

struct amdgpu_pll {
	/* reference frequency */
	uint32_t reference_freq;

	/* fixed dividers */
	uint32_t reference_div;
	uint32_t post_div;

	/* pll in/out limits */
	uint32_t pll_in_min;
	uint32_t pll_in_max;
	uint32_t pll_out_min;
	uint32_t pll_out_max;
	uint32_t lcd_pll_out_min;
	uint32_t lcd_pll_out_max;
	uint32_t best_vco;

	/* divider limits */
	uint32_t min_ref_div;
	uint32_t max_ref_div;
	uint32_t min_post_div;
	uint32_t max_post_div;
	uint32_t min_feedback_div;
	uint32_t max_feedback_div;
	uint32_t min_frac_feedback_div;
	uint32_t max_frac_feedback_div;

	/* flags for the current clock */
	uint32_t flags;

	/* pll id */
	uint32_t id;
};

struct amdgpu_audio_pin {
	int			channels;
	int			rate;
	int			bits_per_sample;
	u8			status_bits;
	u8			category_code;
	u32			offset;
	bool			connected;
	u32			id;
};

struct amdgpu_audio {
	bool enabled;
	struct amdgpu_audio_pin pin[AMDGPU_MAX_AFMT_BLOCKS];
	int num_pins;
};

struct amdgpu_mode_info {
	struct atom_context *atom_context;
	struct card_info *atom_card_info;
	bool mode_config_initialized;
	struct amdgpu_crtc *crtcs[AMDGPU_MAX_CRTCS];
	struct drm_plane *planes[AMDGPU_MAX_PLANES];
	struct amdgpu_afmt *afmt[AMDGPU_MAX_AFMT_BLOCKS];
	/* DVI-I properties */
	struct drm_property *coherent_mode_property;
	/* DAC enable load detect */
	struct drm_property *load_detect_property;
	/* underscan */
	struct drm_property *underscan_property;
	struct drm_property *underscan_hborder_property;
	struct drm_property *underscan_vborder_property;
	/* audio */
	struct drm_property *audio_property;
	/* FMT dithering */
	struct drm_property *dither_property;
	/* Adaptive Backlight Modulation (power feature) */
	struct drm_property *abm_level_property;
	/* hardcoded DFP edid from BIOS */
	struct edid *bios_hardcoded_edid;
	int bios_hardcoded_edid_size;

	/* firmware flags */
	u32 firmware_flags;
	/* pointer to backlight encoder */
	struct amdgpu_encoder *bl_encoder;
	u8 bl_level; /* saved backlight level */
	struct amdgpu_audio	audio; /* audio stuff */
	int			num_crtc; /* number of crtcs */
	int			num_hpd; /* number of hpd pins */
	int			num_dig; /* number of dig blocks */
	bool			gpu_vm_support; /* supports display from GTT */
	int			disp_priority;
	const struct amdgpu_display_funcs *funcs;
	const enum drm_plane_type *plane_type;
};

struct amdgpu_encoder {
	struct drm_encoder base;
	uint32_t encoder_enum;
	uint32_t encoder_id;
	uint32_t devices;
	uint32_t active_device;
	uint32_t flags;
	uint32_t pixel_clock;
	enum amdgpu_rmx_type rmx_type;
	enum amdgpu_underscan_type underscan_type;
	uint32_t underscan_hborder;
	uint32_t underscan_vborder;
	struct drm_display_mode native_mode;
	void *enc_priv;
	int audio_polling_active;
	bool is_ext_encoder;
	u16 caps;
};

/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu_ucode.h */
enum AMDGPU_UCODE_ID {
	AMDGPU_UCODE_ID_CAP = 0,
	AMDGPU_UCODE_ID_SDMA0,
	AMDGPU_UCODE_ID_SDMA1,
	AMDGPU_UCODE_ID_SDMA2,
	AMDGPU_UCODE_ID_SDMA3,
	AMDGPU_UCODE_ID_SDMA4,
	AMDGPU_UCODE_ID_SDMA5,
	AMDGPU_UCODE_ID_SDMA6,
	AMDGPU_UCODE_ID_SDMA7,
	AMDGPU_UCODE_ID_SDMA_UCODE_TH0,
	AMDGPU_UCODE_ID_SDMA_UCODE_TH1,
	AMDGPU_UCODE_ID_CP_CE,
	AMDGPU_UCODE_ID_CP_PFP,
	AMDGPU_UCODE_ID_CP_ME,
	AMDGPU_UCODE_ID_CP_RS64_PFP,
	AMDGPU_UCODE_ID_CP_RS64_ME,
	AMDGPU_UCODE_ID_CP_RS64_MEC,
	AMDGPU_UCODE_ID_CP_RS64_PFP_P0_STACK,
	AMDGPU_UCODE_ID_CP_RS64_PFP_P1_STACK,
	AMDGPU_UCODE_ID_CP_RS64_ME_P0_STACK,
	AMDGPU_UCODE_ID_CP_RS64_ME_P1_STACK,
	AMDGPU_UCODE_ID_CP_RS64_MEC_P0_STACK,
	AMDGPU_UCODE_ID_CP_RS64_MEC_P1_STACK,
	AMDGPU_UCODE_ID_CP_RS64_MEC_P2_STACK,
	AMDGPU_UCODE_ID_CP_RS64_MEC_P3_STACK,
	AMDGPU_UCODE_ID_CP_MEC1,
	AMDGPU_UCODE_ID_CP_MEC1_JT,
	AMDGPU_UCODE_ID_CP_MEC2,
	AMDGPU_UCODE_ID_CP_MEC2_JT,
	AMDGPU_UCODE_ID_CP_MES,
	AMDGPU_UCODE_ID_CP_MES_DATA,
	AMDGPU_UCODE_ID_CP_MES1,
	AMDGPU_UCODE_ID_CP_MES1_DATA,
	AMDGPU_UCODE_ID_IMU_I,
	AMDGPU_UCODE_ID_IMU_D,
	AMDGPU_UCODE_ID_GLOBAL_TAP_DELAYS,
	AMDGPU_UCODE_ID_SE0_TAP_DELAYS,
	AMDGPU_UCODE_ID_SE1_TAP_DELAYS,
	AMDGPU_UCODE_ID_SE2_TAP_DELAYS,
	AMDGPU_UCODE_ID_SE3_TAP_DELAYS,
	AMDGPU_UCODE_ID_RLC_RESTORE_LIST_CNTL,
	AMDGPU_UCODE_ID_RLC_RESTORE_LIST_GPM_MEM,
	AMDGPU_UCODE_ID_RLC_RESTORE_LIST_SRM_MEM,
	AMDGPU_UCODE_ID_RLC_IRAM,
	AMDGPU_UCODE_ID_RLC_DRAM,
	AMDGPU_UCODE_ID_RLC_P,
	AMDGPU_UCODE_ID_RLC_V,
	AMDGPU_UCODE_ID_RLC_G,
	AMDGPU_UCODE_ID_STORAGE,
	AMDGPU_UCODE_ID_SMC,
	AMDGPU_UCODE_ID_PPTABLE,
	AMDGPU_UCODE_ID_UVD,
	AMDGPU_UCODE_ID_UVD1,
	AMDGPU_UCODE_ID_VCE,
	AMDGPU_UCODE_ID_VCN,
	AMDGPU_UCODE_ID_VCN1,
	AMDGPU_UCODE_ID_DMCU_ERAM,
	AMDGPU_UCODE_ID_DMCU_INTV,
	AMDGPU_UCODE_ID_VCN0_RAM,
	AMDGPU_UCODE_ID_VCN1_RAM,
	AMDGPU_UCODE_ID_DMCUB,
	AMDGPU_UCODE_ID_VPE_CTX,
	AMDGPU_UCODE_ID_VPE_CTL,
	AMDGPU_UCODE_ID_VPE,
	AMDGPU_UCODE_ID_UMSCH_MM_UCODE,
	AMDGPU_UCODE_ID_UMSCH_MM_DATA,
	AMDGPU_UCODE_ID_UMSCH_MM_CMD_BUFFER,
	AMDGPU_UCODE_ID_P2S_TABLE,
	AMDGPU_UCODE_ID_MAXIMUM,
};

enum amdgpu_firmware_load_type {
	AMDGPU_FW_LOAD_DIRECT = 0,
	AMDGPU_FW_LOAD_PSP,
	AMDGPU_FW_LOAD_SMU,
	AMDGPU_FW_LOAD_RLC_BACKDOOR_AUTO,
};

struct amdgpu_firmware_info {
	/* ucode ID */
	enum AMDGPU_UCODE_ID ucode_id;
	/* request_firmware */
	const struct firmware *fw;
	/* starting mc address */
	uint64_t mc_addr;
	/* kernel linear address */
	void *kaddr;
	/* ucode_size_bytes */
	uint32_t ucode_size;
	/* starting tmr mc address */
	uint32_t tmr_mc_addr_lo;
	uint32_t tmr_mc_addr_hi;
};

struct amdgpu_firmware {
	struct amdgpu_firmware_info ucode[AMDGPU_UCODE_ID_MAXIMUM];
	enum amdgpu_firmware_load_type load_type;
	struct amdgpu_bo *fw_buf;
	unsigned int fw_size;
	unsigned int max_ucodes;
	/* firmwares are loaded by psp instead of smu from vega10 */
	const struct amdgpu_psp_funcs *funcs;
	struct amdgpu_bo *rbuf;
	struct mutex mutex;

	/* gpu info firmware data pointer */
	const struct firmware *gpu_info_fw;

	void *fw_buf_ptr;
	uint64_t fw_buf_mc;
};

/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu_ttm.h */
#include <linux/dma-direction.h>
#include <drm/gpu_scheduler.h>

/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu_vram_mgr.h */
#include <drm/drm_buddy.h>

struct amdgpu_vram_mgr {
	struct ttm_resource_manager manager;
	struct drm_buddy mm;
	/* protects access to buffer objects */
	struct mutex lock;
	struct list_head reservations_pending;
	struct list_head reserved_pages;
	atomic64_t vis_usage;
	u64 default_page_size;
};

/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu_ttm.h */
struct amdgpu_gtt_mgr {
	struct ttm_resource_manager manager;
	struct drm_mm mm;
	spinlock_t lock;
};

struct amdgpu_mman {
	struct ttm_device		bdev;
	struct ttm_pool			*ttm_pools;
	bool				initialized;
	void __iomem			*aper_base_kaddr;

	/* buffer handling */
	const struct amdgpu_buffer_funcs	*buffer_funcs;
	struct amdgpu_ring			*buffer_funcs_ring;
	bool					buffer_funcs_enabled;

	struct mutex				gtt_window_lock;
	/* High priority scheduler entity for buffer moves */
	struct drm_sched_entity			high_pr;
	/* Low priority scheduler entity for VRAM clearing */
	struct drm_sched_entity			low_pr;

	struct amdgpu_vram_mgr vram_mgr;
	struct amdgpu_gtt_mgr gtt_mgr;
	struct ttm_resource_manager preempt_mgr;

	uint64_t		stolen_vga_size;
	struct amdgpu_bo	*stolen_vga_memory;
	uint64_t		stolen_extended_size;
	struct amdgpu_bo	*stolen_extended_memory;
	bool			keep_stolen_vga_memory;

	struct amdgpu_bo	*stolen_reserved_memory;
	uint64_t		stolen_reserved_offset;
	uint64_t		stolen_reserved_size;

	/* discovery */
	uint8_t				*discovery_bin;
	uint32_t			discovery_tmr_size;
	/* fw reserved memory */
	struct amdgpu_bo		*fw_reserved_memory;

	/* firmware VRAM reservation */
	u64		fw_vram_usage_start_offset;
	u64		fw_vram_usage_size;
	struct amdgpu_bo	*fw_vram_usage_reserved_bo;
	void		*fw_vram_usage_va;

	/* driver VRAM reservation */
	u64		drv_vram_usage_start_offset;
	u64		drv_vram_usage_size;
	struct amdgpu_bo	*drv_vram_usage_reserved_bo;
	void		*drv_vram_usage_va;

	/* PAGE_SIZE'd BO for process memory r/w over SDMA. */
	struct amdgpu_bo	*sdma_access_bo;
	void			*sdma_access_ptr;
};

/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/psp_gfx_if.h */
enum psp_gfx_cmd_id
{
    GFX_CMD_ID_LOAD_TA            = 0x00000001,   /* load TA */
    GFX_CMD_ID_UNLOAD_TA          = 0x00000002,   /* unload TA */
    GFX_CMD_ID_INVOKE_CMD         = 0x00000003,   /* send command to TA */
    GFX_CMD_ID_LOAD_ASD           = 0x00000004,   /* load ASD Driver */
    GFX_CMD_ID_SETUP_TMR          = 0x00000005,   /* setup TMR region */
    GFX_CMD_ID_LOAD_IP_FW         = 0x00000006,   /* load HW IP FW */
    GFX_CMD_ID_DESTROY_TMR        = 0x00000007,   /* destroy TMR region */
    GFX_CMD_ID_SAVE_RESTORE       = 0x00000008,   /* save/restore HW IP FW */
    GFX_CMD_ID_SETUP_VMR          = 0x00000009,   /* setup VMR region */
    GFX_CMD_ID_DESTROY_VMR        = 0x0000000A,   /* destroy VMR region */
    GFX_CMD_ID_PROG_REG           = 0x0000000B,   /* program regs */
    GFX_CMD_ID_GET_FW_ATTESTATION = 0x0000000F,   /* Query GPUVA of the Fw Attestation DB */
    /* IDs upto 0x1F are reserved for older programs (Raven, Vega 10/12/20) */
    GFX_CMD_ID_LOAD_TOC           = 0x00000020,   /* Load TOC and obtain TMR size */
    GFX_CMD_ID_AUTOLOAD_RLC       = 0x00000021,   /* Indicates all graphics fw loaded, start RLC autoload */
    GFX_CMD_ID_BOOT_CFG           = 0x00000022,   /* Boot Config */
    GFX_CMD_ID_SRIOV_SPATIAL_PART = 0x00000027,   /* Configure spatial partitioning mode */
};

/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/ta_xgmi_if.h */
enum { TA_XGMI__MAX_PORT_NUM = 8 };

enum ta_xgmi_assigned_sdma_engine {
	TA_XGMI_ASSIGNED_SDMA_ENGINE__NOT_ASSIGNED	= -1,
	TA_XGMI_ASSIGNED_SDMA_ENGINE__SDMA0		= 0,
	TA_XGMI_ASSIGNED_SDMA_ENGINE__SDMA1		= 1,
	TA_XGMI_ASSIGNED_SDMA_ENGINE__SDMA2		= 2,
	TA_XGMI_ASSIGNED_SDMA_ENGINE__SDMA3		= 3,
	TA_XGMI_ASSIGNED_SDMA_ENGINE__SDMA4		= 4,
	TA_XGMI_ASSIGNED_SDMA_ENGINE__SDMA5		= 5
};

struct xgmi_connected_port_num {
	uint8_t		dst_xgmi_port_num;
	uint8_t		src_xgmi_port_num;
};

/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu_psp.h */
enum psp_shared_mem_size {
	PSP_ASD_SHARED_MEM_SIZE				= 0x0,
	PSP_XGMI_SHARED_MEM_SIZE			= 0x4000,
	PSP_RAS_SHARED_MEM_SIZE				= 0x4000,
	PSP_HDCP_SHARED_MEM_SIZE			= 0x4000,
	PSP_DTM_SHARED_MEM_SIZE				= 0x4000,
	PSP_RAP_SHARED_MEM_SIZE				= 0x4000,
	PSP_SECUREDISPLAY_SHARED_MEM_SIZE	= 0x4000,
};

enum ta_type_id {
	TA_TYPE_XGMI = 1,
	TA_TYPE_RAS,
	TA_TYPE_HDCP,
	TA_TYPE_DTM,
	TA_TYPE_RAP,
	TA_TYPE_SECUREDISPLAY,

	TA_TYPE_MAX_INDEX,
};

enum psp_ring_type {
	PSP_RING_TYPE__INVALID = 0,
	/*
	 * These values map to the way the PSP kernel identifies the
	 * rings.
	 */
	PSP_RING_TYPE__UM = 1, /* User mode ring (formerly called RBI) */
	PSP_RING_TYPE__KM = 2  /* Kernel mode ring (formerly called GPCOM) */
};

struct psp_ring {
	enum psp_ring_type		ring_type;
	struct psp_gfx_rb_frame		*ring_mem;
	uint64_t			ring_mem_mc_addr;
	void				*ring_mem_handle;
	uint32_t			ring_size;
	uint32_t			ring_wptr;
};

#define AMDGPU_XGMI_MAX_CONNECTED_NODES		64
struct psp_xgmi_node_info {
	uint64_t				node_id;
	uint8_t					num_hops;
	uint8_t					is_sharing_enabled;
	enum ta_xgmi_assigned_sdma_engine	sdma_engine;
	uint8_t					num_links;
	struct xgmi_connected_port_num		port_num[TA_XGMI__MAX_PORT_NUM];
};

struct psp_xgmi_topology_info {
	uint32_t			num_nodes;
	struct psp_xgmi_node_info	nodes[AMDGPU_XGMI_MAX_CONNECTED_NODES];
};

struct psp_bin_desc {
	uint32_t fw_version;
	uint32_t feature_version;
	uint32_t size_bytes;
	uint8_t *start_addr;
};

struct ta_mem_context {
	struct amdgpu_bo		*shared_bo;
	uint64_t		shared_mc_addr;
	void			*shared_buf;
	enum psp_shared_mem_size	shared_mem_size;
};

struct ta_context {
	bool			initialized;
	uint32_t		session_id;
	uint32_t		resp_status;
	struct ta_mem_context	mem_context;
	struct psp_bin_desc		bin_desc;
	enum psp_gfx_cmd_id		ta_load_type;
	enum ta_type_id		ta_type;
};

struct ta_cp_context {
	struct ta_context		context;
	struct mutex			mutex;
};

struct psp_xgmi_context {
	struct ta_context		context;
	struct psp_xgmi_topology_info	top_info;
	bool				supports_extended_data;
	uint8_t				xgmi_ta_caps;
};

struct psp_ras_context {
	struct ta_context		context;
	struct amdgpu_ras		*ras;
};

enum psp_memory_training_init_flag {
	PSP_MEM_TRAIN_NOT_SUPPORT	= 0x0,
	PSP_MEM_TRAIN_SUPPORT		= 0x1,
	PSP_MEM_TRAIN_INIT_FAILED	= 0x2,
	PSP_MEM_TRAIN_RESERVE_SUCCESS	= 0x4,
	PSP_MEM_TRAIN_INIT_SUCCESS	= 0x8,
};

struct psp_memory_training_context {
	/*training data size*/
	u64 train_data_size;
	/*
	 * sys_cache
	 * cpu virtual address
	 * system memory buffer that used to store the training data.
	 */
	void *sys_cache;

	/*vram offset of the p2c training data*/
	u64 p2c_train_data_offset;

	/*vram offset of the c2p training data*/
	u64 c2p_train_data_offset;
	struct amdgpu_bo *c2p_bo;

	enum psp_memory_training_init_flag init;
	u32 training_cnt;
	bool enable_mem_training;
};

struct psp_context {
	struct amdgpu_device		*adev;
	struct psp_ring			km_ring;
	struct psp_gfx_cmd_resp		*cmd;

	const struct psp_funcs		*funcs;
	const struct ta_funcs		*ta_funcs;

	/* firmware buffer */
	struct amdgpu_bo		*fw_pri_bo;
	uint64_t			fw_pri_mc_addr;
	void				*fw_pri_buf;

	/* sos firmware */
	const struct firmware		*sos_fw;
	struct psp_bin_desc		sys;
	struct psp_bin_desc		sos;
	struct psp_bin_desc		toc;
	struct psp_bin_desc		kdb;
	struct psp_bin_desc		spl;
	struct psp_bin_desc		rl;
	struct psp_bin_desc		soc_drv;
	struct psp_bin_desc		intf_drv;
	struct psp_bin_desc		dbg_drv;
	struct psp_bin_desc		ras_drv;

	/* tmr buffer */
	struct amdgpu_bo		*tmr_bo;
	uint64_t			tmr_mc_addr;

	/* asd firmware */
	const struct firmware		*asd_fw;

	/* toc firmware */
	const struct firmware		*toc_fw;

	/* cap firmware */
	const struct firmware		*cap_fw;

	/* fence buffer */
	struct amdgpu_bo		*fence_buf_bo;
	uint64_t			fence_buf_mc_addr;
	void				*fence_buf;

	/* cmd buffer */
	struct amdgpu_bo		*cmd_buf_bo;
	uint64_t			cmd_buf_mc_addr;
	struct psp_gfx_cmd_resp		*cmd_buf_mem;

	/* fence value associated with cmd buffer */
	atomic_t			fence_value;
	/* flag to mark whether gfx fw autoload is supported or not */
	bool				autoload_supported;
	/* flag to mark whether df cstate management centralized to PMFW */
	bool				pmfw_centralized_cstate_management;

	/* xgmi ta firmware and buffer */
	const struct firmware		*ta_fw;
	uint32_t			ta_fw_version;

	uint32_t			cap_fw_version;
	uint32_t			cap_feature_version;
	uint32_t			cap_ucode_size;

	struct ta_context		asd_context;
	struct psp_xgmi_context		xgmi_context;
	struct psp_ras_context		ras_context;
	struct ta_cp_context		hdcp_context;
	struct ta_cp_context		dtm_context;
	struct ta_cp_context		rap_context;
	struct ta_cp_context		securedisplay_context;
	struct mutex			mutex;
	struct psp_memory_training_context mem_train_ctx;

	uint32_t			boot_cfg_bitmask;

	/* firmware upgrades supported */
	bool				sup_pd_fw_up;
	bool				sup_ifwi_up;

	char				*vbflash_tmp_buf;
	size_t				vbflash_image_size;
	bool				vbflash_done;
};

/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu_gds.h */
struct amdgpu_gds {
	uint32_t gds_size;
	uint32_t gws_size;
	uint32_t oa_size;
	uint32_t gds_compute_max_wave_id;
};

/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu_sync.h */
#include <linux/hashtable.h>

struct amdgpu_sync {
	DECLARE_HASHTABLE(fences, 4);
};

/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu_vm.h */
#include <linux/idr.h>

/* klp-ccp: from include/linux/kfifo.h */
#define _LINUX_KFIFO_H

/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu_vm.h */
#include <linux/rbtree.h>
#include <drm/gpu_scheduler.h>

/* klp-ccp: from include/drm/drm_file.h */
#define _DRM_FILE_H_

/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu_vm.h */
#include <drm/ttm/ttm_bo.h>
#include <linux/sched/mm.h>
/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu_ids.h */
#include <linux/types.h>
#include <linux/mutex.h>
#include <linux/list.h>
#include <linux/dma-fence.h>

#define AMDGPU_NUM_VMID	16

struct amdgpu_vmid {
	struct list_head	list;
	struct amdgpu_sync	active;
	struct dma_fence	*last_flush;
	uint64_t		owner;

	uint64_t		pd_gpu_addr;
	/* last flushed PD/PT update */
	uint64_t		flushed_updates;

	uint32_t                current_gpu_reset_count;

	uint32_t		gds_base;
	uint32_t		gds_size;
	uint32_t		gws_base;
	uint32_t		gws_size;
	uint32_t		oa_base;
	uint32_t		oa_size;

	unsigned		pasid;
	struct dma_fence	*pasid_mapping;
};

struct amdgpu_vmid_mgr {
	struct mutex		lock;
	unsigned		num_ids;
	struct list_head	ids_lru;
	struct amdgpu_vmid	ids[AMDGPU_NUM_VMID];
	struct amdgpu_vmid	*reserved;
	unsigned int		reserved_use_count;
};

/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu_vm.h */
#define AMDGPU_MAX_VMHUBS			13

enum amdgpu_vm_level {
	AMDGPU_VM_PDB2,
	AMDGPU_VM_PDB1,
	AMDGPU_VM_PDB0,
	AMDGPU_VM_PTB
};

struct amdgpu_vm_manager {
	/* Handling of VMIDs */
	struct amdgpu_vmid_mgr			id_mgr[AMDGPU_MAX_VMHUBS];
	unsigned int				first_kfd_vmid;
	bool					concurrent_flush;

	/* Handling of VM fences */
	u64					fence_context;
	unsigned				seqno[AMDGPU_MAX_RINGS];

	uint64_t				max_pfn;
	uint32_t				num_level;
	uint32_t				block_size;
	uint32_t				fragment_size;
	enum amdgpu_vm_level			root_level;
	/* vram base address for page table entry  */
	u64					vram_base_offset;
	/* vm pte handling */
	const struct amdgpu_vm_pte_funcs	*vm_pte_funcs;
	struct drm_gpu_scheduler		*vm_pte_scheds[AMDGPU_MAX_RINGS];
	unsigned				vm_pte_num_scheds;
	struct amdgpu_ring			*page_fault;

	/* partial resident texture handling */
	spinlock_t				prt_lock;
	atomic_t				num_prt_users;

	/* controls how VM page tables are updated for Graphics and Compute.
	 * BIT0[= 0] Graphics updated by SDMA [= 1] by CPU
	 * BIT1[= 0] Compute updated by SDMA [= 1] by CPU
	 */
	int					vm_update_mode;

	/* PASID to VM mapping, will be used in interrupt context to
	 * look up VM of a page fault
	 */
	struct xarray				pasids;
};

/* klp-ccp: from drivers/gpu/drm/amd/pm/inc/amdgpu_dpm.h */
enum amdgpu_int_thermal_type {
	THERMAL_TYPE_NONE,
	THERMAL_TYPE_EXTERNAL,
	THERMAL_TYPE_EXTERNAL_GPIO,
	THERMAL_TYPE_RV6XX,
	THERMAL_TYPE_RV770,
	THERMAL_TYPE_ADT7473_WITH_INTERNAL,
	THERMAL_TYPE_EVERGREEN,
	THERMAL_TYPE_SUMO,
	THERMAL_TYPE_NI,
	THERMAL_TYPE_SI,
	THERMAL_TYPE_EMC2103_WITH_INTERNAL,
	THERMAL_TYPE_CI,
	THERMAL_TYPE_KV,
};

enum amdgpu_runpm_mode {
	AMDGPU_RUNPM_NONE,
	AMDGPU_RUNPM_PX,
	AMDGPU_RUNPM_BOCO,
	AMDGPU_RUNPM_BACO,
};

struct amdgpu_dpm_thermal {
	/* thermal interrupt work */
	struct work_struct work;
	/* low temperature threshold */
	int                min_temp;
	/* high temperature threshold */
	int                max_temp;
	/* edge max emergency(shutdown) temp */
	int                max_edge_emergency_temp;
	/* hotspot low temperature threshold */
	int                min_hotspot_temp;
	/* hotspot high temperature critical threshold */
	int                max_hotspot_crit_temp;
	/* hotspot max emergency(shutdown) temp */
	int                max_hotspot_emergency_temp;
	/* memory low temperature threshold */
	int                min_mem_temp;
	/* memory high temperature critical threshold */
	int                max_mem_crit_temp;
	/* memory max emergency(shutdown) temp */
	int                max_mem_emergency_temp;
	/* SWCTF threshold */
	int                sw_ctf_threshold;
	/* was last interrupt low to high or high to low */
	bool               high_to_low;
	/* interrupt source */
	struct amdgpu_irq_src	irq;
};

struct amdgpu_clock_and_voltage_limits {
	u32 sclk;
	u32 mclk;
	u16 vddc;
	u16 vddci;
};

struct amdgpu_clock_array {
	u32 count;
	u32 *values;
};

struct amdgpu_clock_voltage_dependency_table {
	u32 count;
	struct amdgpu_clock_voltage_dependency_entry *entries;
};

struct amdgpu_cac_leakage_table {
	u32 count;
	union amdgpu_cac_leakage_entry *entries;
};

struct amdgpu_phase_shedding_limits_table {
	u32 count;
	struct amdgpu_phase_shedding_limits_entry *entries;
};

struct amdgpu_uvd_clock_voltage_dependency_table {
	u8 count;
	struct amdgpu_uvd_clock_voltage_dependency_entry *entries;
};

struct amdgpu_vce_clock_voltage_dependency_table {
	u8 count;
	struct amdgpu_vce_clock_voltage_dependency_entry *entries;
};

struct amdgpu_dpm_dynamic_state {
	struct amdgpu_clock_voltage_dependency_table vddc_dependency_on_sclk;
	struct amdgpu_clock_voltage_dependency_table vddci_dependency_on_mclk;
	struct amdgpu_clock_voltage_dependency_table vddc_dependency_on_mclk;
	struct amdgpu_clock_voltage_dependency_table mvdd_dependency_on_mclk;
	struct amdgpu_clock_voltage_dependency_table vddc_dependency_on_dispclk;
	struct amdgpu_uvd_clock_voltage_dependency_table uvd_clock_voltage_dependency_table;
	struct amdgpu_vce_clock_voltage_dependency_table vce_clock_voltage_dependency_table;
	struct amdgpu_clock_voltage_dependency_table samu_clock_voltage_dependency_table;
	struct amdgpu_clock_voltage_dependency_table acp_clock_voltage_dependency_table;
	struct amdgpu_clock_voltage_dependency_table vddgfx_dependency_on_sclk;
	struct amdgpu_clock_array valid_sclk_values;
	struct amdgpu_clock_array valid_mclk_values;
	struct amdgpu_clock_and_voltage_limits max_clock_voltage_on_dc;
	struct amdgpu_clock_and_voltage_limits max_clock_voltage_on_ac;
	u32 mclk_sclk_ratio;
	u32 sclk_mclk_delta;
	u16 vddc_vddci_delta;
	u16 min_vddc_for_pcie_gen2;
	struct amdgpu_cac_leakage_table cac_leakage_table;
	struct amdgpu_phase_shedding_limits_table phase_shedding_limits_table;
	struct amdgpu_ppm_table *ppm_table;
	struct amdgpu_cac_tdp_table *cac_tdp_table;
};

struct amdgpu_dpm_fan {
	u16 t_min;
	u16 t_med;
	u16 t_high;
	u16 pwm_min;
	u16 pwm_med;
	u16 pwm_high;
	u8 t_hyst;
	u32 cycle_delay;
	u16 t_max;
	u8 control_mode;
	u16 default_max_fan_pwm;
	u16 default_fan_output_sensitivity;
	u16 fan_output_sensitivity;
	bool ucode_fan_control;
};

struct amdgpu_dpm {
	struct amdgpu_ps        *ps;
	/* number of valid power states */
	int                     num_ps;
	/* current power state that is active */
	struct amdgpu_ps        *current_ps;
	/* requested power state */
	struct amdgpu_ps        *requested_ps;
	/* boot up power state */
	struct amdgpu_ps        *boot_ps;
	/* default uvd power state */
	struct amdgpu_ps        *uvd_ps;
	/* vce requirements */
	u32                  num_of_vce_states;
	struct amd_vce_state vce_states[AMD_MAX_VCE_LEVELS];
	enum amd_vce_level vce_level;
	enum amd_pm_state_type state;
	enum amd_pm_state_type user_state;
	enum amd_pm_state_type last_state;
	enum amd_pm_state_type last_user_state;
	u32                     platform_caps;
	u32                     voltage_response_time;
	u32                     backbias_response_time;
	void                    *priv;
	u32			new_active_crtcs;
	int			new_active_crtc_count;
	u32			current_active_crtcs;
	int			current_active_crtc_count;
	struct amdgpu_dpm_dynamic_state dyn_state;
	struct amdgpu_dpm_fan fan;
	u32 tdp_limit;
	u32 near_tdp_limit;
	u32 near_tdp_limit_adjusted;
	u32 sq_ramping_threshold;
	u32 cac_leakage;
	u16 tdp_od_limit;
	u32 tdp_adjustment;
	u16 load_line_slope;
	bool power_control;
	/* special states active */
	bool                    thermal_active;
	bool                    uvd_active;
	bool                    vce_active;
	/* thermal handling */
	struct amdgpu_dpm_thermal thermal;
	/* forced levels */
	enum amd_dpm_forced_level forced_level;
};

#define MAX_SMU_I2C_BUSES       2

struct amdgpu_smu_i2c_bus {
	struct i2c_adapter adapter;
	struct amdgpu_device *adev;
	int port;
	struct mutex mutex;
};

struct config_table_setting
{
	uint16_t gfxclk_average_tau;
	uint16_t socclk_average_tau;
	uint16_t uclk_average_tau;
	uint16_t gfx_activity_average_tau;
	uint16_t mem_activity_average_tau;
	uint16_t socket_power_average_tau;
	uint16_t apu_socket_power_average_tau;
	uint16_t fclk_average_tau;
};

struct amdgpu_pm {
	struct mutex		mutex;
	u32                     current_sclk;
	u32                     current_mclk;
	u32                     default_sclk;
	u32                     default_mclk;
	struct amdgpu_i2c_chan *i2c_bus;
	bool                    bus_locked;
	/* internal thermal controller on rv6xx+ */
	enum amdgpu_int_thermal_type int_thermal_type;
	struct device	        *int_hwmon_dev;
	/* fan control parameters */
	bool                    no_fan;
	u8                      fan_pulses_per_revolution;
	u8                      fan_min_rpm;
	u8                      fan_max_rpm;
	/* dpm */
	bool                    dpm_enabled;
	bool                    sysfs_initialized;
	struct amdgpu_dpm       dpm;
	const struct firmware	*fw;	/* SMC firmware */
	uint32_t                fw_version;
	uint32_t                pcie_gen_mask;
	uint32_t                pcie_mlw_mask;
	struct amd_pp_display_configuration pm_display_cfg;/* set by dc */
	uint32_t                smu_prv_buffer_size;
	struct amdgpu_bo        *smu_prv_buffer;
	bool ac_power;
	/* powerplay feature */
	uint32_t pp_feature;

	/* Used for I2C access to various EEPROMs on relevant ASICs */
	struct amdgpu_smu_i2c_bus smu_i2c[MAX_SMU_I2C_BUSES];
	struct i2c_adapter     *ras_eeprom_i2c_bus;
	struct i2c_adapter     *fru_eeprom_i2c_bus;
	struct list_head	pm_attr_list;

	atomic_t		pwr_state[AMD_IP_BLOCK_TYPE_NUM];

	/*
	 * 0 = disabled (default), otherwise enable corresponding debug mode
	 */
	uint32_t		smu_debug_mask;

	bool			pp_force_state_enabled;

	struct mutex            stable_pstate_ctx_lock;
	struct amdgpu_ctx       *stable_pstate_ctx;

	struct config_table_setting config_table;
	/* runtime mode */
	enum amdgpu_runpm_mode rpm_mode;

	struct list_head	od_kobj_list;
	uint32_t		od_feature_mask;
};

/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu_acp.h */
struct amdgpu_acp {
	struct device *parent;
	struct cgs_device *cgs_device;
	struct amd_acp_private *private;
	struct mfd_cell *acp_cell;
	struct resource *acp_res;
	struct acp_pm_domain *acp_genpd;
};

/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu_uvd.h */
#define AMDGPU_MAX_UVD_HANDLES		40

#define AMDGPU_MAX_UVD_INSTANCES			2

struct amdgpu_uvd_inst {
	struct amdgpu_bo	*vcpu_bo;
	void			*cpu_addr;
	uint64_t		gpu_addr;
	void			*saved_bo;
	struct amdgpu_ring	ring;
	struct amdgpu_ring	ring_enc[AMDGPU_MAX_UVD_ENC_RINGS];
	struct amdgpu_irq_src	irq;
	uint32_t                srbm_soft_reset;
};

struct amdgpu_uvd {
	const struct firmware	*fw;	/* UVD firmware */
	unsigned		fw_version;
	unsigned		max_handles;
	unsigned		num_enc_rings;
	uint8_t			num_uvd_inst;
	bool			address_64_bit;
	bool			use_ctx_buf;
	struct amdgpu_uvd_inst	inst[AMDGPU_MAX_UVD_INSTANCES];
	struct drm_file		*filp[AMDGPU_MAX_UVD_HANDLES];
	atomic_t		handles[AMDGPU_MAX_UVD_HANDLES];
	struct drm_sched_entity entity;
	struct delayed_work	idle_work;
	unsigned		harvest_config;
	/* store image width to adjust nb memory state */
	unsigned		decode_image_width;
	uint32_t                keyselect;
	struct amdgpu_bo	*ib_bo;
};

/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu_vce.h */
#define AMDGPU_MAX_VCE_HANDLES	16

struct amdgpu_vce {
	struct amdgpu_bo	*vcpu_bo;
	uint64_t		gpu_addr;
	void			*cpu_addr;
	void			*saved_bo;
	unsigned		fw_version;
	unsigned		fb_version;
	atomic_t		handles[AMDGPU_MAX_VCE_HANDLES];
	struct drm_file		*filp[AMDGPU_MAX_VCE_HANDLES];
	uint32_t		img_size[AMDGPU_MAX_VCE_HANDLES];
	struct delayed_work	idle_work;
	struct mutex		idle_mutex;
	const struct firmware	*fw;	/* VCE firmware */
	struct amdgpu_ring	ring[AMDGPU_MAX_VCE_RINGS];
	struct amdgpu_irq_src	irq;
	unsigned		harvest_config;
	struct drm_sched_entity	entity;
	uint32_t                srbm_soft_reset;
	unsigned		num_rings;
};

/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu_vcn.h */
#define AMDGPU_VCN_MAX_ENC_RINGS	3

#define AMDGPU_MAX_VCN_INSTANCES	4

enum internal_dpg_state {
	VCN_DPG_STATE__UNPAUSE = 0,
	VCN_DPG_STATE__PAUSE,
};

struct dpg_pause_state {
	enum internal_dpg_state fw_based;
	enum internal_dpg_state jpeg;
};

struct amdgpu_vcn_reg{
	unsigned	data0;
	unsigned	data1;
	unsigned	cmd;
	unsigned	nop;
	unsigned	context_id;
	unsigned	ib_vmid;
	unsigned	ib_bar_low;
	unsigned	ib_bar_high;
	unsigned	ib_size;
	unsigned	gp_scratch8;
	unsigned	scratch9;
};

struct amdgpu_vcn_fw_shared {
	void        *cpu_addr;
	uint64_t    gpu_addr;
	uint32_t    mem_size;
	uint32_t    log_offset;
};

struct amdgpu_vcn_inst {
	struct amdgpu_bo	*vcpu_bo;
	void			*cpu_addr;
	uint64_t		gpu_addr;
	void			*saved_bo;
	struct amdgpu_ring	ring_dec;
	struct amdgpu_ring	ring_enc[AMDGPU_VCN_MAX_ENC_RINGS];
	atomic_t		sched_score;
	struct amdgpu_irq_src	irq;
	struct amdgpu_irq_src	ras_poison_irq;
	struct amdgpu_vcn_reg	external;
	struct amdgpu_bo	*dpg_sram_bo;
	struct dpg_pause_state	pause_state;
	void			*dpg_sram_cpu_addr;
	uint64_t		dpg_sram_gpu_addr;
	uint32_t		*dpg_sram_curr_addr;
	atomic_t		dpg_enc_submission_cnt;
	struct amdgpu_vcn_fw_shared fw_shared;
	uint8_t			aid_id;
};

struct amdgpu_vcn {
	unsigned		fw_version;
	struct delayed_work	idle_work;
	const struct firmware	*fw;	/* VCN firmware */
	unsigned		num_enc_rings;
	enum amd_powergating_state cur_state;
	bool			indirect_sram;

	uint8_t	num_vcn_inst;
	struct amdgpu_vcn_inst	 inst[AMDGPU_MAX_VCN_INSTANCES];
	uint8_t			 vcn_config[AMDGPU_MAX_VCN_INSTANCES];
	uint32_t		 vcn_codec_disable_mask[AMDGPU_MAX_VCN_INSTANCES];
	struct amdgpu_vcn_reg	 internal;
	struct mutex		 vcn_pg_lock;
	struct mutex		vcn1_jpeg1_workaround;
	atomic_t		 total_submission_cnt;

	unsigned	harvest_config;
	int (*pause_dpg_mode)(struct amdgpu_device *adev,
		int inst_idx, struct dpg_pause_state *new_state);

	struct ras_common_if    *ras_if;
	struct amdgpu_vcn_ras   *ras;

	uint16_t inst_mask;
	uint8_t	num_inst_per_aid;
};

/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu_jpeg.h */
#define AMDGPU_MAX_JPEG_INSTANCES	4
#define AMDGPU_MAX_JPEG_RINGS		8

struct amdgpu_jpeg_reg{
	unsigned jpeg_pitch[AMDGPU_MAX_JPEG_RINGS];
};

struct amdgpu_jpeg_inst {
	struct amdgpu_ring ring_dec[AMDGPU_MAX_JPEG_RINGS];
	struct amdgpu_irq_src irq;
	struct amdgpu_irq_src ras_poison_irq;
	struct amdgpu_jpeg_reg external;
	uint8_t aid_id;
};

struct amdgpu_jpeg {
	uint8_t	num_jpeg_inst;
	struct amdgpu_jpeg_inst inst[AMDGPU_MAX_JPEG_INSTANCES];
	unsigned num_jpeg_rings;
	struct amdgpu_jpeg_reg internal;
	unsigned harvest_config;
	struct delayed_work idle_work;
	enum amd_powergating_state cur_state;
	struct mutex jpeg_pg_lock;
	atomic_t total_submission_cnt;
	struct ras_common_if	*ras_if;
	struct amdgpu_jpeg_ras	*ras;

	uint16_t inst_mask;
	uint8_t num_inst_per_aid;
};

/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu_vpe.h */
struct vpe_regs {
	uint32_t queue0_rb_rptr_lo;
	uint32_t queue0_rb_rptr_hi;
	uint32_t queue0_rb_wptr_lo;
	uint32_t queue0_rb_wptr_hi;
	uint32_t queue0_preempt;
};

struct amdgpu_vpe {
	struct amdgpu_ring		ring;
	struct amdgpu_irq_src		trap_irq;

	const struct vpe_funcs		*funcs;
	struct vpe_regs			regs;

	const struct firmware		*fw;
	uint32_t			fw_version;
	uint32_t			feature_version;

	struct amdgpu_bo		*cmdbuf_obj;
	uint64_t			cmdbuf_gpu_addr;
	uint32_t			*cmdbuf_cpu_addr;
};

/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu_umsch_mm.h */
enum UMSCH_CONTEXT_PRIORITY_LEVEL {
	CONTEXT_PRIORITY_LEVEL_IDLE = 0,
	CONTEXT_PRIORITY_LEVEL_NORMAL = 1,
	CONTEXT_PRIORITY_LEVEL_FOCUS = 2,
	CONTEXT_PRIORITY_LEVEL_REALTIME = 3,
	CONTEXT_PRIORITY_NUM_LEVELS
};

struct amdgpu_umsch_mm {
	struct amdgpu_ring		ring;

	uint32_t			rb_wptr;
	uint32_t			rb_rptr;

	const struct umsch_mm_funcs	*funcs;

	const struct firmware		*fw;
	uint32_t			fw_version;
	uint32_t			feature_version;

	struct amdgpu_bo		*ucode_fw_obj;
	uint64_t			ucode_fw_gpu_addr;
	uint32_t			*ucode_fw_ptr;
	uint64_t			irq_start_addr;
	uint64_t			uc_start_addr;
	uint32_t			ucode_size;

	struct amdgpu_bo		*data_fw_obj;
	uint64_t			data_fw_gpu_addr;
	uint32_t			*data_fw_ptr;
	uint64_t			data_start_addr;
	uint32_t			data_size;

	struct amdgpu_bo		*cmd_buf_obj;
	uint64_t			cmd_buf_gpu_addr;
	uint32_t			*cmd_buf_ptr;
	uint32_t			*cmd_buf_curr_ptr;

	uint32_t			wb_index;
	uint64_t			sch_ctx_gpu_addr;
	uint32_t			*sch_ctx_cpu_addr;

	uint32_t			vmid_mask_mm_vcn;
	uint32_t			vmid_mask_mm_vpe;
	uint32_t			engine_mask;
	uint32_t			vcn0_hqd_mask;
	uint32_t			vcn1_hqd_mask;
	uint32_t			vcn_hqd_mask[2];
	uint32_t			vpe_hqd_mask;
	uint32_t			agdb_index[CONTEXT_PRIORITY_NUM_LEVELS];

	struct mutex			mutex_hidden;
};

/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu_gmc.h */
#include <linux/types.h>

#define AMDGPU_GMC_FAULT_RING_ORDER	8
#define AMDGPU_GMC_FAULT_RING_SIZE	(1 << AMDGPU_GMC_FAULT_RING_ORDER)

#define AMDGPU_GMC_FAULT_HASH_ORDER	8
#define AMDGPU_GMC_FAULT_HASH_SIZE	(1 << AMDGPU_GMC_FAULT_HASH_ORDER)

struct amdgpu_gmc_fault {
	uint64_t	timestamp:48;
	uint64_t	next:AMDGPU_GMC_FAULT_RING_ORDER;
	atomic64_t	key;
	uint64_t	timestamp_expiry:48;
};

struct amdgpu_vmhub {
	uint32_t	ctx0_ptb_addr_lo32;
	uint32_t	ctx0_ptb_addr_hi32;
	uint32_t	vm_inv_eng0_sem;
	uint32_t	vm_inv_eng0_req;
	uint32_t	vm_inv_eng0_ack;
	uint32_t	vm_context0_cntl;
	uint32_t	vm_l2_pro_fault_status;
	uint32_t	vm_l2_pro_fault_cntl;

	/*
	 * store the register distances between two continuous context domain
	 * and invalidation engine.
	 */
	uint32_t	ctx_distance;
	uint32_t	ctx_addr_distance; /* include LO32/HI32 */
	uint32_t	eng_distance;
	uint32_t	eng_addr_distance; /* include LO32/HI32 */

	uint32_t        vm_cntx_cntl;
	uint32_t	vm_cntx_cntl_vm_fault;
	uint32_t	vm_l2_bank_select_reserved_cid2;

	uint32_t	vm_contexts_disable;

	bool		sdma_invalidation_workaround;

	const struct amdgpu_vmhub_funcs *vmhub_funcs;
};

struct amdgpu_xgmi {
	/* from psp */
	u64 node_id;
	u64 hive_id;
	/* fixed per family */
	u64 node_segment_size;
	/* physical node (0-3) */
	unsigned physical_node_id;
	/* number of nodes (0-4) */
	unsigned num_physical_nodes;
	/* gpu list in the same hive */
	struct list_head head;
	bool supported;
	struct ras_common_if *ras_if;
	bool connected_to_cpu;
	bool pending_reset;
	struct amdgpu_xgmi_ras *ras;
};

struct amdgpu_gmc {
	/* FB's physical address in MMIO space (for CPU to
	 * map FB). This is different compared to the agp/
	 * gart/vram_start/end field as the later is from
	 * GPU's view and aper_base is from CPU's view.
	 */
	resource_size_t		aper_size;
	resource_size_t		aper_base;
	/* for some chips with <= 32MB we need to lie
	 * about vram size near mc fb location */
	u64			mc_vram_size;
	u64			visible_vram_size;
	/* AGP aperture start and end in MC address space
	 * Driver find a hole in the MC address space
	 * to place AGP by setting MC_VM_AGP_BOT/TOP registers
	 * Under VMID0, logical address == MC address. AGP
	 * aperture maps to physical bus or IOVA addressed.
	 * AGP aperture is used to simulate FB in ZFB case.
	 * AGP aperture is also used for page table in system
	 * memory (mainly for APU).
	 *
	 */
	u64			agp_size;
	u64			agp_start;
	u64			agp_end;
	/* GART aperture start and end in MC address space
	 * Driver find a hole in the MC address space
	 * to place GART by setting VM_CONTEXT0_PAGE_TABLE_START/END_ADDR
	 * registers
	 * Under VMID0, logical address inside GART aperture will
	 * be translated through gpuvm gart page table to access
	 * paged system memory
	 */
	u64			gart_size;
	u64			gart_start;
	u64			gart_end;
	/* Frame buffer aperture of this GPU device. Different from
	 * fb_start (see below), this only covers the local GPU device.
	 * If driver uses FB aperture to access FB, driver get fb_start from
	 * MC_VM_FB_LOCATION_BASE (set by vbios) and calculate vram_start
	 * of this local device by adding an offset inside the XGMI hive.
	 * If driver uses GART table for VMID0 FB access, driver finds a hole in
	 * VMID0's virtual address space to place the SYSVM aperture inside
	 * which the first part is vram and the second part is gart (covering
	 * system ram).
	 */
	u64			vram_start;
	u64			vram_end;
	/* FB region , it's same as local vram region in single GPU, in XGMI
	 * configuration, this region covers all GPUs in the same hive ,
	 * each GPU in the hive has the same view of this FB region .
	 * GPU0's vram starts at offset (0 * segment size) ,
	 * GPU1 starts at offset (1 * segment size), etc.
	 */
	u64			fb_start;
	u64			fb_end;
	unsigned		vram_width;
	u64			real_vram_size;
	int			vram_mtrr;
	u64                     mc_mask;
	const struct firmware   *fw;	/* MC firmware */
	uint32_t                fw_version;
	struct amdgpu_irq_src	vm_fault;
	uint32_t		vram_type;
	uint8_t			vram_vendor;
	uint32_t                srbm_soft_reset;
	bool			prt_warning;
	uint32_t		sdpif_register;
	/* apertures */
	u64			shared_aperture_start;
	u64			shared_aperture_end;
	u64			private_aperture_start;
	u64			private_aperture_end;
	/* protects concurrent invalidation */
	spinlock_t		invalidate_lock;
	bool			translate_further;
	struct kfd_vm_fault_info *vm_fault_info;
	atomic_t		vm_fault_info_updated;

	struct amdgpu_gmc_fault	fault_ring[AMDGPU_GMC_FAULT_RING_SIZE];
	struct {
		uint64_t	idx:AMDGPU_GMC_FAULT_RING_ORDER;
	} fault_hash[AMDGPU_GMC_FAULT_HASH_SIZE];
	uint64_t		last_fault:AMDGPU_GMC_FAULT_RING_ORDER;

	bool tmz_enabled;
	bool is_app_apu;

	struct amdgpu_mem_partition_info *mem_partitions;
	uint8_t num_mem_partitions;
	const struct amdgpu_gmc_funcs	*gmc_funcs;

	struct amdgpu_xgmi xgmi;
	struct amdgpu_irq_src	ecc_irq;
	int noretry;

	uint32_t	vmid0_page_table_block_size;
	uint32_t	vmid0_page_table_depth;
	struct amdgpu_bo		*pdb0_bo;
	/* CPU kmapped address of pdb0*/
	void				*ptr_pdb0;

	/* MALL size */
	u64 mall_size;
	uint32_t m_half_use;

	/* number of UMC instances */
	int num_umc;
	/* mode2 save restore */
	u64 VM_L2_CNTL;
	u64 VM_L2_CNTL2;
	u64 VM_DUMMY_PAGE_FAULT_CNTL;
	u64 VM_DUMMY_PAGE_FAULT_ADDR_LO32;
	u64 VM_DUMMY_PAGE_FAULT_ADDR_HI32;
	u64 VM_L2_PROTECTION_FAULT_CNTL;
	u64 VM_L2_PROTECTION_FAULT_CNTL2;
	u64 VM_L2_PROTECTION_FAULT_MM_CNTL3;
	u64 VM_L2_PROTECTION_FAULT_MM_CNTL4;
	u64 VM_L2_PROTECTION_FAULT_ADDR_LO32;
	u64 VM_L2_PROTECTION_FAULT_ADDR_HI32;
	u64 VM_DEBUG;
	u64 VM_L2_MM_GROUP_RT_CLASSES;
	u64 VM_L2_BANK_SELECT_RESERVED_CID;
	u64 VM_L2_BANK_SELECT_RESERVED_CID2;
	u64 VM_L2_CACHE_PARITY_CNTL;
	u64 VM_L2_IH_LOG_CNTL;
	u64 VM_CONTEXT_CNTL[16];
	u64 VM_CONTEXT_PAGE_TABLE_BASE_ADDR_LO32[16];
	u64 VM_CONTEXT_PAGE_TABLE_BASE_ADDR_HI32[16];
	u64 VM_CONTEXT_PAGE_TABLE_START_ADDR_LO32[16];
	u64 VM_CONTEXT_PAGE_TABLE_START_ADDR_HI32[16];
	u64 VM_CONTEXT_PAGE_TABLE_END_ADDR_LO32[16];
	u64 VM_CONTEXT_PAGE_TABLE_END_ADDR_HI32[16];
	u64 MC_VM_MX_L1_TLB_CNTL;

	u64 noretry_flags;

	bool flush_tlb_needs_extra_type_0;
	bool flush_tlb_needs_extra_type_2;
	bool flush_pasid_uses_kiq;
};

/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu_sdma.h */
#define AMDGPU_MAX_SDMA_INSTANCES		16

struct amdgpu_sdma_instance {
	/* SDMA firmware */
	const struct firmware	*fw;
	uint32_t		fw_version;
	uint32_t		feature_version;

	struct amdgpu_ring	ring;
	struct amdgpu_ring	page;
	bool			burst_nop;
	uint32_t		aid_id;
};

struct amdgpu_sdma {
	struct amdgpu_sdma_instance instance[AMDGPU_MAX_SDMA_INSTANCES];
	struct amdgpu_irq_src	trap_irq;
	struct amdgpu_irq_src	illegal_inst_irq;
	struct amdgpu_irq_src	ecc_irq;
	struct amdgpu_irq_src	vm_hole_irq;
	struct amdgpu_irq_src	doorbell_invalid_irq;
	struct amdgpu_irq_src	pool_timeout_irq;
	struct amdgpu_irq_src	srbm_write_irq;

	int			num_instances;
	uint32_t 		sdma_mask;
	int			num_inst_per_aid;
	uint32_t                    srbm_soft_reset;
	bool			has_page_queue;
	struct ras_common_if	*ras_if;
	struct amdgpu_sdma_ras	*ras;
};

/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu_lsdma.h */
struct amdgpu_lsdma {
	const struct amdgpu_lsdma_funcs      *funcs;
};

/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu_nbio.h */
struct amdgpu_nbio {
	const struct nbio_hdp_flush_reg *hdp_flush_reg;
	struct amdgpu_irq_src ras_controller_irq;
	struct amdgpu_irq_src ras_err_event_athub_irq;
	struct ras_common_if *ras_if;
	const struct amdgpu_nbio_funcs *funcs;
	struct amdgpu_nbio_ras  *ras;
};

/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu_hdp.h */
struct amdgpu_hdp {
	struct ras_common_if			*ras_if;
	const struct amdgpu_hdp_funcs		*funcs;
	struct amdgpu_hdp_ras	*ras;
};

/* klp-ccp: from drivers/gpu/drm/amd/display/amdgpu_dm/amdgpu_dm.h */
#include <drm/display/drm_dp_mst_helper.h>
#include <drm/drm_atomic.h>
#include <drm/drm_connector.h>
#include <drm/drm_crtc.h>
#include <drm/drm_plane.h>

#define AMDGPU_DM_MAX_CRTC 6

#define AMDGPU_DM_MAX_NUM_EDP 2

#define AMDGPU_DMUB_NOTIFICATION_MAX 5

struct dmub_notification;

struct common_irq_params {
	struct amdgpu_device *adev;
	enum dc_irq_source irq_src;
	atomic64_t previous_timestamp;
};

struct dm_compressor_info {
	void *cpu_addr;
	struct amdgpu_bo *bo_ptr;
	uint64_t gpu_addr;
};

typedef void (*dmub_notify_interrupt_callback_t)(struct amdgpu_device *adev, struct dmub_notification *notify);

struct amdgpu_dm_backlight_caps {
	/**
	 * @ext_caps: Keep the data struct with all the information about the
	 * display support for HDR.
	 */
	union dpcd_sink_ext_caps *ext_caps;
	/**
	 * @aux_min_input_signal: Min brightness value supported by the display
	 */
	u32 aux_min_input_signal;
	/**
	 * @aux_max_input_signal: Max brightness value supported by the display
	 * in nits.
	 */
	u32 aux_max_input_signal;
	/**
	 * @min_input_signal: minimum possible input in range 0-255.
	 */
	int min_input_signal;
	/**
	 * @max_input_signal: maximum possible input in range 0-255.
	 */
	int max_input_signal;
	/**
	 * @caps_valid: true if these values are from the ACPI interface.
	 */
	bool caps_valid;
	/**
	 * @aux_support: Describes if the display supports AUX backlight.
	 */
	bool aux_support;
};

struct amdgpu_display_manager {

	struct dc *dc;

	/**
	 * @dmub_srv:
	 *
	 * DMUB service, used for controlling the DMUB on hardware
	 * that supports it. The pointer to the dmub_srv will be
	 * NULL on hardware that does not support it.
	 */
	struct dmub_srv *dmub_srv;

	/**
	 * @dmub_notify:
	 *
	 * Notification from DMUB.
	 */

	struct dmub_notification *dmub_notify;

	/**
	 * @dmub_callback:
	 *
	 * Callback functions to handle notification from DMUB.
	 */

	dmub_notify_interrupt_callback_t dmub_callback[AMDGPU_DMUB_NOTIFICATION_MAX];

	/**
	 * @dmub_thread_offload:
	 *
	 * Flag to indicate if callback is offload.
	 */

	bool dmub_thread_offload[AMDGPU_DMUB_NOTIFICATION_MAX];

	/**
	 * @dmub_fb_info:
	 *
	 * Framebuffer regions for the DMUB.
	 */
	struct dmub_srv_fb_info *dmub_fb_info;

	/**
	 * @dmub_fw:
	 *
	 * DMUB firmware, required on hardware that has DMUB support.
	 */
	const struct firmware *dmub_fw;

	/**
	 * @dmub_bo:
	 *
	 * Buffer object for the DMUB.
	 */
	struct amdgpu_bo *dmub_bo;

	/**
	 * @dmub_bo_gpu_addr:
	 *
	 * GPU virtual address for the DMUB buffer object.
	 */
	u64 dmub_bo_gpu_addr;

	/**
	 * @dmub_bo_cpu_addr:
	 *
	 * CPU address for the DMUB buffer object.
	 */
	void *dmub_bo_cpu_addr;

	/**
	 * @dmcub_fw_version:
	 *
	 * DMCUB firmware version.
	 */
	uint32_t dmcub_fw_version;

	/**
	 * @cgs_device:
	 *
	 * The Common Graphics Services device. It provides an interface for
	 * accessing registers.
	 */
	struct cgs_device *cgs_device;

	struct amdgpu_device *adev;
	struct drm_device *ddev;
	u16 display_indexes_num;

	/**
	 * @atomic_obj:
	 *
	 * In combination with &dm_atomic_state it helps manage
	 * global atomic state that doesn't map cleanly into existing
	 * drm resources, like &dc_context.
	 */
	struct drm_private_obj atomic_obj;

	/**
	 * @dc_lock:
	 *
	 * Guards access to DC functions that can issue register write
	 * sequences.
	 */
	struct mutex dc_lock;

	/**
	 * @audio_lock:
	 *
	 * Guards access to audio instance changes.
	 */
	struct mutex audio_lock;

	/**
	 * @audio_component:
	 *
	 * Used to notify ELD changes to sound driver.
	 */
	struct drm_audio_component *audio_component;

	/**
	 * @audio_registered:
	 *
	 * True if the audio component has been registered
	 * successfully, false otherwise.
	 */
	bool audio_registered;

	/**
	 * @irq_handler_list_low_tab:
	 *
	 * Low priority IRQ handler table.
	 *
	 * It is a n*m table consisting of n IRQ sources, and m handlers per IRQ
	 * source. Low priority IRQ handlers are deferred to a workqueue to be
	 * processed. Hence, they can sleep.
	 *
	 * Note that handlers are called in the same order as they were
	 * registered (FIFO).
	 */
	struct list_head irq_handler_list_low_tab[DAL_IRQ_SOURCES_NUMBER];

	/**
	 * @irq_handler_list_high_tab:
	 *
	 * High priority IRQ handler table.
	 *
	 * It is a n*m table, same as &irq_handler_list_low_tab. However,
	 * handlers in this table are not deferred and are called immediately.
	 */
	struct list_head irq_handler_list_high_tab[DAL_IRQ_SOURCES_NUMBER];

	/**
	 * @pflip_params:
	 *
	 * Page flip IRQ parameters, passed to registered handlers when
	 * triggered.
	 */
	struct common_irq_params
	pflip_params[DC_IRQ_SOURCE_PFLIP_LAST - DC_IRQ_SOURCE_PFLIP_FIRST + 1];

	/**
	 * @vblank_params:
	 *
	 * Vertical blanking IRQ parameters, passed to registered handlers when
	 * triggered.
	 */
	struct common_irq_params
	vblank_params[DC_IRQ_SOURCE_VBLANK6 - DC_IRQ_SOURCE_VBLANK1 + 1];

	/**
	 * @vline0_params:
	 *
	 * OTG vertical interrupt0 IRQ parameters, passed to registered
	 * handlers when triggered.
	 */
	struct common_irq_params
	vline0_params[DC_IRQ_SOURCE_DC6_VLINE0 - DC_IRQ_SOURCE_DC1_VLINE0 + 1];

	/**
	 * @vupdate_params:
	 *
	 * Vertical update IRQ parameters, passed to registered handlers when
	 * triggered.
	 */
	struct common_irq_params
	vupdate_params[DC_IRQ_SOURCE_VUPDATE6 - DC_IRQ_SOURCE_VUPDATE1 + 1];

	/**
	 * @dmub_trace_params:
	 *
	 * DMUB trace event IRQ parameters, passed to registered handlers when
	 * triggered.
	 */
	struct common_irq_params
	dmub_trace_params[1];

	struct common_irq_params
	dmub_outbox_params[1];

	spinlock_t irq_handler_list_table_lock;

	struct backlight_device *backlight_dev[AMDGPU_DM_MAX_NUM_EDP];

	const struct dc_link *backlight_link[AMDGPU_DM_MAX_NUM_EDP];

	uint8_t num_of_edps;

	struct amdgpu_dm_backlight_caps backlight_caps[AMDGPU_DM_MAX_NUM_EDP];

	struct mod_freesync *freesync_module;
	struct hdcp_workqueue *hdcp_workqueue;

	/**
	 * @vblank_control_workqueue:
	 *
	 * Deferred work for vblank control events.
	 */
	struct workqueue_struct *vblank_control_workqueue;

	struct drm_atomic_state *cached_state;
	struct dc_state *cached_dc_state;

	struct dm_compressor_info compressor;

	const struct firmware *fw_dmcu;
	uint32_t dmcu_fw_version;
	/**
	 * @soc_bounding_box:
	 *
	 * gpu_info FW provided soc bounding box struct or 0 if not
	 * available in FW
	 */
	const struct gpu_info_soc_bounding_box_v1_0 *soc_bounding_box;

	/**
	 * @active_vblank_irq_count:
	 *
	 * number of currently active vblank irqs
	 */
	uint32_t active_vblank_irq_count;

#if defined(CONFIG_DRM_AMD_SECURE_DISPLAY)
	struct secure_display_context *secure_display_ctxs;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	struct hpd_rx_irq_offload_work_queue *hpd_rx_offload_wq;
	/**
	 * @mst_encoders:
	 *
	 * fake encoders used for DP MST.
	 */
	struct amdgpu_encoder mst_encoders[AMDGPU_DM_MAX_CRTC];
	bool force_timing_sync;
	bool disable_hpd_irq;
	bool dmcub_trace_event_en;
	/**
	 * @da_list:
	 *
	 * DAL fb memory allocation list, for communication with SMU.
	 */
	struct list_head da_list;
	struct completion dmub_aux_transfer_done;
	struct workqueue_struct *delayed_hpd_wq;

	/**
	 * @brightness:
	 *
	 * cached backlight values.
	 */
	u32 brightness[AMDGPU_DM_MAX_NUM_EDP];
	/**
	 * @actual_brightness:
	 *
	 * last successfully applied backlight values.
	 */
	u32 actual_brightness[AMDGPU_DM_MAX_NUM_EDP];

	/**
	 * @aux_hpd_discon_quirk:
	 *
	 * quirk for hpd discon while aux is on-going.
	 * occurred on certain intel platform
	 */
	bool aux_hpd_discon_quirk;

	/**
	 * @dpia_aux_lock:
	 *
	 * Guards access to DPIA AUX
	 */
	struct mutex dpia_aux_lock;
};

/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu_virt.h */
struct amdgpu_mm_table {
	struct amdgpu_bo	*bo;
	uint32_t		*cpu_addr;
	uint64_t		gpu_addr;
};

#define AMDGPU_VF_ERROR_ENTRY_SIZE    16

struct amdgpu_vf_error_buffer {
	struct mutex lock;
	int read_count;
	int write_count;
	uint16_t code[AMDGPU_VF_ERROR_ENTRY_SIZE];
	uint16_t flags[AMDGPU_VF_ERROR_ENTRY_SIZE];
	uint64_t data[AMDGPU_VF_ERROR_ENTRY_SIZE];
};

struct amdgpu_virt_fw_reserve {
	struct amd_sriov_msg_pf2vf_info_header *p_pf2vf;
	struct amd_sriov_msg_vf2pf_info_header *p_vf2pf;
	unsigned int checksum_key;
};

struct amdgpu_virt {
	uint32_t			caps;
	struct amdgpu_bo		*csa_obj;
	void				*csa_cpu_addr;
	bool chained_ib_support;
	uint32_t			reg_val_offs;
	struct amdgpu_irq_src		ack_irq;
	struct amdgpu_irq_src		rcv_irq;
	struct work_struct		flr_work;
	struct amdgpu_mm_table		mm_table;
	const struct amdgpu_virt_ops	*ops;
	struct amdgpu_vf_error_buffer	vf_errors;
	struct amdgpu_virt_fw_reserve	fw_reserve;
	uint32_t gim_feature;
	uint32_t reg_access_mode;
	int req_init_data_ver;
	bool tdr_debug;
	struct amdgpu_virt_ras_err_handler_data *virt_eh_data;
	bool ras_init_done;
	uint32_t reg_access;

	/* vf2pf message */
	struct delayed_work vf2pf_work;
	uint32_t vf2pf_update_interval_ms;

	/* multimedia bandwidth config */
	bool     is_mm_bw_enabled;
	uint32_t decode_max_dimension_pixels;
	uint32_t decode_max_frame_pixels;
	uint32_t encode_max_dimension_pixels;
	uint32_t encode_max_frame_pixels;

	/* the ucode id to signal the autoload */
	uint32_t autoload_ucode_id;
};

/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu_gart.h */
#include <linux/types.h>

struct amdgpu_gart {
	struct amdgpu_bo		*bo;
	/* CPU kmapped address of gart table */
	void				*ptr;
	unsigned			num_gpu_pages;
	unsigned			num_cpu_pages;
	unsigned			table_size;

	/* Asic default pte flags */
	uint64_t			gart_pte_flags;
};

/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu_job.h */
#include <drm/gpu_scheduler.h>

/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu_bo_list.h */
#include <drm/amdgpu_drm.h>

/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu_gem.h */
#include <drm/amdgpu_drm.h>
#include <drm/drm_gem.h>

/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu_doorbell.h */
struct amdgpu_doorbell {
	/* doorbell mmio */
	resource_size_t		base;
	resource_size_t		size;

	/* Number of doorbells reserved for amdgpu kernel driver */
	u32 num_kernel_doorbells;

	/* Kernel doorbells */
	struct amdgpu_bo *kernel_doorbells;

	/* For CPU access of doorbells */
	uint32_t *cpu_addr;
};

struct amdgpu_doorbell_index {
	uint32_t kiq;
	uint32_t mec_ring0;
	uint32_t mec_ring1;
	uint32_t mec_ring2;
	uint32_t mec_ring3;
	uint32_t mec_ring4;
	uint32_t mec_ring5;
	uint32_t mec_ring6;
	uint32_t mec_ring7;
	uint32_t userqueue_start;
	uint32_t userqueue_end;
	uint32_t gfx_ring0;
	uint32_t gfx_ring1;
	uint32_t gfx_userqueue_start;
	uint32_t gfx_userqueue_end;
	uint32_t sdma_engine[16];
	uint32_t mes_ring0;
	uint32_t mes_ring1;
	uint32_t ih;
	union {
		struct {
			uint32_t vcn_ring0_1;
			uint32_t vcn_ring2_3;
			uint32_t vcn_ring4_5;
			uint32_t vcn_ring6_7;
		} vcn;
		struct {
			uint32_t uvd_ring0_1;
			uint32_t uvd_ring2_3;
			uint32_t uvd_ring4_5;
			uint32_t uvd_ring6_7;
			uint32_t vce_ring0_1;
			uint32_t vce_ring2_3;
			uint32_t vce_ring4_5;
			uint32_t vce_ring6_7;
		} uvd_vce;
	};
	uint32_t vpe_ring;
	uint32_t first_non_cp;
	uint32_t last_non_cp;
	uint32_t max_assignment;
	/* Per engine SDMA doorbell size in dword */
	uint32_t sdma_doorbell_range;
	/* Per xcc doorbell size for KIQ/KCQ */
	uint32_t xcc_doorbell_range;
};

/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu_amdkfd.h */
#include <linux/list.h>
#include <linux/types.h>
#include <linux/mm.h>
#include <linux/kthread.h>
#include <linux/workqueue.h>
#include <linux/mmu_notifier.h>
#include <linux/memremap.h>

/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu_xcp.h */
#include <linux/pci.h>
#include <linux/xarray.h>

#define MAX_XCP 8

/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu_amdkfd.h */
struct amdgpu_kfd_dev {
	struct kfd_dev *dev;
	int64_t vram_used[MAX_XCP];
	uint64_t vram_used_aligned[MAX_XCP];
	bool init_complete;
	struct work_struct reset_work;

	/* HMM page migration MEMORY_DEVICE_PRIVATE mapping */
	struct dev_pagemap pgmap;
};

/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu_mes.h */
#include <linux/sched/mm.h>

#define AMDGPU_MES_MAX_COMPUTE_PIPES        8
#define AMDGPU_MES_MAX_GFX_PIPES            2
#define AMDGPU_MES_MAX_SDMA_PIPES           2

enum amdgpu_mes_priority_level {
	AMDGPU_MES_PRIORITY_LEVEL_LOW       = 0,
	AMDGPU_MES_PRIORITY_LEVEL_NORMAL    = 1,
	AMDGPU_MES_PRIORITY_LEVEL_MEDIUM    = 2,
	AMDGPU_MES_PRIORITY_LEVEL_HIGH      = 3,
	AMDGPU_MES_PRIORITY_LEVEL_REALTIME  = 4,
	AMDGPU_MES_PRIORITY_NUM_LEVELS
};

enum admgpu_mes_pipe {
	AMDGPU_MES_SCHED_PIPE = 0,
	AMDGPU_MES_KIQ_PIPE,
	AMDGPU_MAX_MES_PIPES = 2,
};

struct amdgpu_mes {
	struct amdgpu_device            *adev;

	struct mutex                    mutex_hidden;

	struct idr                      pasid_idr;
	struct idr                      gang_id_idr;
	struct idr                      queue_id_idr;
	struct ida                      doorbell_ida;

	spinlock_t                      queue_id_lock;

	uint32_t			sched_version;
	uint32_t			kiq_version;

	uint32_t                        total_max_queue;
	uint32_t                        max_doorbell_slices;

	uint64_t                        default_process_quantum;
	uint64_t                        default_gang_quantum;

	struct amdgpu_ring              ring;
	spinlock_t                      ring_lock;

	const struct firmware           *fw[AMDGPU_MAX_MES_PIPES];

	/* mes ucode */
	struct amdgpu_bo		*ucode_fw_obj[AMDGPU_MAX_MES_PIPES];
	uint64_t			ucode_fw_gpu_addr[AMDGPU_MAX_MES_PIPES];
	uint32_t			*ucode_fw_ptr[AMDGPU_MAX_MES_PIPES];
	uint64_t                        uc_start_addr[AMDGPU_MAX_MES_PIPES];

	/* mes ucode data */
	struct amdgpu_bo		*data_fw_obj[AMDGPU_MAX_MES_PIPES];
	uint64_t			data_fw_gpu_addr[AMDGPU_MAX_MES_PIPES];
	uint32_t			*data_fw_ptr[AMDGPU_MAX_MES_PIPES];
	uint64_t                        data_start_addr[AMDGPU_MAX_MES_PIPES];

	/* eop gpu obj */
	struct amdgpu_bo		*eop_gpu_obj[AMDGPU_MAX_MES_PIPES];
	uint64_t                        eop_gpu_addr[AMDGPU_MAX_MES_PIPES];

	void                            *mqd_backup[AMDGPU_MAX_MES_PIPES];
	struct amdgpu_irq_src	        irq[AMDGPU_MAX_MES_PIPES];

	uint32_t                        vmid_mask_gfxhub;
	uint32_t                        vmid_mask_mmhub;
	uint32_t                        compute_hqd_mask[AMDGPU_MES_MAX_COMPUTE_PIPES];
	uint32_t                        gfx_hqd_mask[AMDGPU_MES_MAX_GFX_PIPES];
	uint32_t                        sdma_hqd_mask[AMDGPU_MES_MAX_SDMA_PIPES];
	uint32_t                        aggregated_doorbells[AMDGPU_MES_PRIORITY_NUM_LEVELS];
	uint32_t                        sch_ctx_offs;
	uint64_t			sch_ctx_gpu_addr;
	uint64_t			*sch_ctx_ptr;
	uint32_t			query_status_fence_offs;
	uint64_t			query_status_fence_gpu_addr;
	uint64_t			*query_status_fence_ptr;
	uint32_t                        read_val_offs;
	uint64_t			read_val_gpu_addr;
	uint32_t			*read_val_ptr;

	uint32_t			saved_flags;

	/* initialize kiq pipe */
	int                             (*kiq_hw_init)(struct amdgpu_device *adev);
	int                             (*kiq_hw_fini)(struct amdgpu_device *adev);

	/* MES doorbells */
	uint32_t			db_start_dw_offset;
	uint32_t			num_mes_dbs;
	unsigned long			*doorbell_bitmap;

	/* ip specific functions */
	const struct amdgpu_mes_funcs   *funcs;
};

/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu_umc.h */
struct amdgpu_umc {
	/* max error count in one ras query call */
	uint32_t max_ras_err_cnt_per_query;
	/* number of umc channel instance with memory map register access */
	uint32_t channel_inst_num;
	/* number of umc instance with memory map register access */
	uint32_t umc_inst_num;

	/* Total number of umc node instance including harvest one */
	uint32_t node_inst_num;

	/* UMC regiser per channel offset */
	uint32_t channel_offs;
	/* how many pages are retired in one UE */
	uint32_t retire_unit;
	/* channel index table of interleaved memory */
	const uint32_t *channel_idx_tbl;
	struct ras_common_if *ras_if;

	const struct amdgpu_umc_funcs *funcs;
	struct amdgpu_umc_ras *ras;

	/* active mask for umc node instance */
	unsigned long active_mask;
};

/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu_mmhub.h */
struct amdgpu_mmhub {
	struct ras_common_if *ras_if;
	const struct amdgpu_mmhub_funcs *funcs;
	struct amdgpu_mmhub_ras  *ras;
};

/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu_gfxhub.h */
struct amdgpu_gfxhub {
	const struct amdgpu_gfxhub_funcs *funcs;
};

/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu_df.h */
struct amdgpu_df_hash_status {
	bool hash_64k;
	bool hash_2m;
	bool hash_1g;
};

struct amdgpu_df {
	struct amdgpu_df_hash_status	hash_status;
	const struct amdgpu_df_funcs	*funcs;
};

/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu_fdinfo.h */
#include <linux/idr.h>
#include <linux/kfifo.h>
#include <linux/rbtree.h>
#include <drm/gpu_scheduler.h>
#include <drm/drm_file.h>
#include <linux/sched/mm.h>

/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu_mca.h */
struct amdgpu_mca_ras {
	struct ras_common_if *ras_if;
	struct amdgpu_mca_ras_block *ras;
};

struct amdgpu_mca {
	struct amdgpu_mca_ras mp0;
	struct amdgpu_mca_ras mp1;
	struct amdgpu_mca_ras mpio;
	const struct amdgpu_mca_smu_funcs *mca_funcs;
};

/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu.h */
#define AMDGPU_BIOS_NUM_SCRATCH			16

#define AMDGPU_MAX_IP_NUM 16

struct amdgpu_ip_block_status {
	bool valid;
	bool sw;
	bool hw;
	bool late_initialized;
	bool hang;
};

struct amdgpu_ip_block {
	struct amdgpu_ip_block_status status;
	const struct amdgpu_ip_block_version *version;
};

#define AMDGPU_MAX_PPLL 3

struct amdgpu_clock {
	struct amdgpu_pll ppll[AMDGPU_MAX_PPLL];
	struct amdgpu_pll spll;
	struct amdgpu_pll mpll;
	/* 10 Khz units */
	uint32_t default_mclk;
	uint32_t default_sclk;
	uint32_t default_dispclk;
	uint32_t current_dispclk;
	uint32_t dp_extclk;
	uint32_t max_pixel_clock;
};

struct amdgpu_sa_manager {
	struct drm_suballoc_manager	base;
	struct amdgpu_bo		*bo;
	uint64_t			gpu_addr;
	void				*cpu_ptr;
};

#define AMDGPU_MAX_WB 1024	/* Reserve at most 1024 WB slots for amdgpu-owned rings. */

struct amdgpu_wb {
	struct amdgpu_bo	*wb_obj;
	volatile uint32_t	*wb;
	uint64_t		gpu_addr;
	u32			num_wb;	/* Number of wb slots actually reserved for amdgpu. */
	unsigned long		used[DIV_ROUND_UP(AMDGPU_MAX_WB, BITS_PER_LONG)];
};

struct amdgpu_mem_scratch {
	struct amdgpu_bo		*robj;
	volatile uint32_t		*ptr;
	u64				gpu_addr;
};

typedef uint32_t (*amdgpu_rreg_t)(struct amdgpu_device*, uint32_t);
typedef void (*amdgpu_wreg_t)(struct amdgpu_device*, uint32_t, uint32_t);

typedef uint32_t (*amdgpu_rreg_ext_t)(struct amdgpu_device*, uint64_t);
typedef void (*amdgpu_wreg_ext_t)(struct amdgpu_device*, uint64_t, uint32_t);

typedef uint64_t (*amdgpu_rreg64_t)(struct amdgpu_device*, uint32_t);
typedef void (*amdgpu_wreg64_t)(struct amdgpu_device*, uint32_t, uint64_t);

typedef uint64_t (*amdgpu_rreg64_ext_t)(struct amdgpu_device*, uint64_t);
typedef void (*amdgpu_wreg64_ext_t)(struct amdgpu_device*, uint64_t, uint64_t);

typedef uint32_t (*amdgpu_block_rreg_t)(struct amdgpu_device*, uint32_t, uint32_t);
typedef void (*amdgpu_block_wreg_t)(struct amdgpu_device*, uint32_t, uint32_t, uint32_t);

struct amdgpu_mmio_remap {
	u32 reg_offset;
	resource_size_t bus_addr;
};

enum amd_hw_ip_block_type {
	GC_HWIP = 1,
	HDP_HWIP,
	SDMA0_HWIP,
	SDMA1_HWIP,
	SDMA2_HWIP,
	SDMA3_HWIP,
	SDMA4_HWIP,
	SDMA5_HWIP,
	SDMA6_HWIP,
	SDMA7_HWIP,
	LSDMA_HWIP,
	MMHUB_HWIP,
	ATHUB_HWIP,
	NBIO_HWIP,
	MP0_HWIP,
	MP1_HWIP,
	UVD_HWIP,
	VCN_HWIP = UVD_HWIP,
	JPEG_HWIP = VCN_HWIP,
	VCN1_HWIP,
	VCE_HWIP,
	VPE_HWIP,
	DF_HWIP,
	DCE_HWIP,
	OSSSYS_HWIP,
	SMUIO_HWIP,
	PWR_HWIP,
	NBIF_HWIP,
	THM_HWIP,
	CLK_HWIP,
	UMC_HWIP,
	RSMU_HWIP,
	XGMI_HWIP,
	DCI_HWIP,
	PCIE_HWIP,
	MAX_HWIP
};

#define HWIP_MAX_INSTANCE	44

#define IP_VERSION_FULL(mj, mn, rv, var, srev) \
	(((mj) << 24) | ((mn) << 16) | ((rv) << 8) | ((var) << 4) | (srev))
#define IP_VERSION(mj, mn, rv)		IP_VERSION_FULL(mj, mn, rv, 0, 0)

struct amdgpu_ip_map_info {
	/* Map of logical to actual dev instances/mask */
	uint32_t 		dev_inst[MAX_HWIP][HWIP_MAX_INSTANCE];
	int8_t (*logical_to_dev_inst)(struct amdgpu_device *adev,
				      enum amd_hw_ip_block_type block,
				      int8_t inst);
	uint32_t (*logical_to_dev_mask)(struct amdgpu_device *adev,
					enum amd_hw_ip_block_type block,
					uint32_t mask);
};

struct amd_powerplay {
	void *pp_handle;
	const struct amd_pm_funcs *pp_funcs;
};

struct amdgpu_mqd_prop;

struct amdgpu_mqd {
	unsigned mqd_size;
	int (*init_mqd)(struct amdgpu_device *adev, void *mqd,
			struct amdgpu_mqd_prop *p);
};

#define AMDGPU_RESET_MAGIC_NUM 64
#define AMDGPU_MAX_DF_PERFMONS 4

struct amdgpu_reset_info {
	/* reset dump register */
	u32 *reset_dump_reg_list;
	u32 *reset_dump_reg_value;
	int num_regs;

#ifdef CONFIG_DEV_COREDUMP
	struct amdgpu_coredump_info *coredump_info;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
};

struct amdgpu_device {
	struct device			*dev;
	struct pci_dev			*pdev;
	struct drm_device		ddev;

#ifdef CONFIG_DRM_AMD_ACP
	struct amdgpu_acp		acp;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	struct amdgpu_hive_info *hive;
	struct amdgpu_xcp_mgr *xcp_mgr;
	/* ASIC */
	enum amd_asic_type		asic_type;
	uint32_t			family;
	uint32_t			rev_id;
	uint32_t			external_rev_id;
	unsigned long			flags;
	unsigned long			apu_flags;
	int				usec_timeout;
	const struct amdgpu_asic_funcs	*asic_funcs;
	bool				shutdown;
	bool				need_swiotlb;
	bool				accel_working;
	struct notifier_block		acpi_nb;
	struct amdgpu_i2c_chan		*i2c_bus[AMDGPU_MAX_I2C_BUS];
	struct debugfs_blob_wrapper     debugfs_vbios_blob;
	struct debugfs_blob_wrapper     debugfs_discovery_blob;
	struct mutex			srbm_mutex;
	/* GRBM index mutex. Protects concurrent access to GRBM index */
	struct mutex                    grbm_idx_mutex;
	struct dev_pm_domain		vga_pm_domain;
	bool				have_disp_power_ref;
	bool                            have_atomics_support;

	/* BIOS */
	bool				is_atom_fw;
	uint8_t				*bios;
	uint32_t			bios_size;
	uint32_t			bios_scratch_reg_offset;
	uint32_t			bios_scratch[AMDGPU_BIOS_NUM_SCRATCH];

	/* Register/doorbell mmio */
	resource_size_t			rmmio_base;
	resource_size_t			rmmio_size;
	void __iomem			*rmmio;
	/* protects concurrent MM_INDEX/DATA based register access */
	spinlock_t mmio_idx_lock;
	struct amdgpu_mmio_remap        rmmio_remap;
	/* protects concurrent SMC based register access */
	spinlock_t smc_idx_lock;
	amdgpu_rreg_t			smc_rreg;
	amdgpu_wreg_t			smc_wreg;
	/* protects concurrent PCIE register access */
	spinlock_t pcie_idx_lock;
	amdgpu_rreg_t			pcie_rreg;
	amdgpu_wreg_t			pcie_wreg;
	amdgpu_rreg_t			pciep_rreg;
	amdgpu_wreg_t			pciep_wreg;
	amdgpu_rreg_ext_t		pcie_rreg_ext;
	amdgpu_wreg_ext_t		pcie_wreg_ext;
	amdgpu_rreg64_t			pcie_rreg64;
	amdgpu_wreg64_t			pcie_wreg64;
	amdgpu_rreg64_ext_t			pcie_rreg64_ext;
	amdgpu_wreg64_ext_t			pcie_wreg64_ext;
	/* protects concurrent UVD register access */
	spinlock_t uvd_ctx_idx_lock;
	amdgpu_rreg_t			uvd_ctx_rreg;
	amdgpu_wreg_t			uvd_ctx_wreg;
	/* protects concurrent DIDT register access */
	spinlock_t didt_idx_lock;
	amdgpu_rreg_t			didt_rreg;
	amdgpu_wreg_t			didt_wreg;
	/* protects concurrent gc_cac register access */
	spinlock_t gc_cac_idx_lock;
	amdgpu_rreg_t			gc_cac_rreg;
	amdgpu_wreg_t			gc_cac_wreg;
	/* protects concurrent se_cac register access */
	spinlock_t se_cac_idx_lock;
	amdgpu_rreg_t			se_cac_rreg;
	amdgpu_wreg_t			se_cac_wreg;
	/* protects concurrent ENDPOINT (audio) register access */
	spinlock_t audio_endpt_idx_lock;
	amdgpu_block_rreg_t		audio_endpt_rreg;
	amdgpu_block_wreg_t		audio_endpt_wreg;
	struct amdgpu_doorbell		doorbell;

	/* clock/pll info */
	struct amdgpu_clock            clock;

	/* MC */
	struct amdgpu_gmc		gmc;
	struct amdgpu_gart		gart;
	dma_addr_t			dummy_page_addr;
	struct amdgpu_vm_manager	vm_manager;
	struct amdgpu_vmhub             vmhub[AMDGPU_MAX_VMHUBS];
	DECLARE_BITMAP(vmhubs_mask, AMDGPU_MAX_VMHUBS);

	/* memory management */
	struct amdgpu_mman		mman;
	struct amdgpu_mem_scratch	mem_scratch;
	struct amdgpu_wb		wb;
	atomic64_t			num_bytes_moved;
	atomic64_t			num_evictions;
	atomic64_t			num_vram_cpu_page_faults;
	atomic_t			gpu_reset_counter;
	atomic_t			vram_lost_counter;

	/* data for buffer migration throttling */
	struct {
		spinlock_t		lock;
		s64			last_update_us;
		s64			accum_us; /* accumulated microseconds */
		s64			accum_us_vis; /* for visible VRAM */
		u32			log2_max_MBps;
	} mm_stats;

	/* display */
	bool				enable_virtual_display;
	struct amdgpu_vkms_output       *amdgpu_vkms_output;
	struct amdgpu_mode_info		mode_info;
	/* For pre-DCE11. DCE11 and later are in "struct amdgpu_device->dm" */
	struct delayed_work         hotplug_work;
	struct amdgpu_irq_src		crtc_irq;
	struct amdgpu_irq_src		vline0_irq;
	struct amdgpu_irq_src		vupdate_irq;
	struct amdgpu_irq_src		pageflip_irq;
	struct amdgpu_irq_src		hpd_irq;
	struct amdgpu_irq_src		dmub_trace_irq;
	struct amdgpu_irq_src		dmub_outbox_irq;

	/* rings */
	u64				fence_context;
	unsigned			num_rings;
	struct amdgpu_ring		*rings[AMDGPU_MAX_RINGS];
	struct dma_fence __rcu		*gang_submit;
	bool				ib_pool_ready;
	struct amdgpu_sa_manager	ib_pools[AMDGPU_IB_POOL_MAX];
	struct amdgpu_sched		gpu_sched[AMDGPU_HW_IP_NUM][AMDGPU_RING_PRIO_MAX];

	/* interrupts */
	struct amdgpu_irq		irq;

	/* powerplay */
	struct amd_powerplay		powerplay;
	struct amdgpu_pm		pm;
	u64				cg_flags;
	u32				pg_flags;

	/* nbio */
	struct amdgpu_nbio		nbio;

	/* hdp */
	struct amdgpu_hdp		hdp;

	/* smuio */
	struct amdgpu_smuio		smuio;

	/* mmhub */
	struct amdgpu_mmhub		mmhub;

	/* gfxhub */
	struct amdgpu_gfxhub		gfxhub;

	/* gfx */
	struct amdgpu_gfx		gfx;

	/* sdma */
	struct amdgpu_sdma		sdma;

	/* lsdma */
	struct amdgpu_lsdma		lsdma;

	/* uvd */
	struct amdgpu_uvd		uvd;

	/* vce */
	struct amdgpu_vce		vce;

	/* vcn */
	struct amdgpu_vcn		vcn;

	/* jpeg */
	struct amdgpu_jpeg		jpeg;

	/* vpe */
	struct amdgpu_vpe		vpe;

	/* umsch */
	struct amdgpu_umsch_mm		umsch_mm;
	bool				enable_umsch_mm;

	/* firmwares */
	struct amdgpu_firmware		firmware;

	/* PSP */
	struct psp_context		psp;

	/* GDS */
	struct amdgpu_gds		gds;

	/* KFD */
	struct amdgpu_kfd_dev		kfd;

	/* UMC */
	struct amdgpu_umc		umc;

	/* display related functionality */
	struct amdgpu_display_manager dm;

	/* mes */
	bool                            enable_mes;
	bool                            enable_mes_kiq;
	struct amdgpu_mes               mes;
	struct amdgpu_mqd               mqds[AMDGPU_HW_IP_NUM];

	/* df */
	struct amdgpu_df                df;

	/* MCA */
	struct amdgpu_mca               mca;

	struct amdgpu_ip_block          ip_blocks[AMDGPU_MAX_IP_NUM];
	uint32_t		        harvest_ip_mask;
	int				num_ip_blocks;
	struct mutex	mn_lock;
	DECLARE_HASHTABLE(mn_hash, 7);

	/* tracking pinned memory */
	atomic64_t vram_pin_size;
	atomic64_t visible_pin_size;
	atomic64_t gart_pin_size;

	/* soc15 register offset based on ip, instance and  segment */
	uint32_t		*reg_offset[MAX_HWIP][HWIP_MAX_INSTANCE];
	struct amdgpu_ip_map_info	ip_map;

	/* delayed work_func for deferring clockgating during resume */
	struct delayed_work     delayed_init_work;

	struct amdgpu_virt	virt;

	/* link all shadow bo */
	struct list_head                shadow_list;
	struct mutex                    shadow_list_lock;

	/* record hw reset is performed */
	bool has_hw_reset;
	u8				reset_magic[AMDGPU_RESET_MAGIC_NUM];

	/* s3/s4 mask */
	bool                            in_suspend;
	bool				in_s3;
	bool				in_s4;
	bool				in_s0ix;
	/* indicate amdgpu suspension status */
	bool				suspend_complete;

	enum pp_mp1_state               mp1_state;
	struct amdgpu_doorbell_index doorbell_index;

	struct mutex			notifier_lock;

	int asic_reset_res;
	struct work_struct		xgmi_reset_work;
	struct list_head		reset_list;

	long				gfx_timeout;
	long				sdma_timeout;
	long				video_timeout;
	long				compute_timeout;

	uint64_t			unique_id;
	uint64_t	df_perfmon_config_assign_mask[AMDGPU_MAX_DF_PERFMONS];

	/* enable runtime pm on the device */
	bool                            in_runpm;
	bool                            has_pr3;

	bool                            ucode_sysfs_en;

	struct amdgpu_fru_info		*fru_info;
	atomic_t			throttling_logging_enabled;
	struct ratelimit_state		throttling_logging_rs;
	uint32_t                        ras_hw_enabled;
	uint32_t                        ras_enabled;

	bool                            no_hw_access;
	struct pci_saved_state          *pci_state;
	pci_channel_state_t		pci_channel_state;

	/* Track auto wait count on s_barrier settings */
	bool				barrier_has_auto_waitcnt;

	struct amdgpu_reset_control     *reset_cntl;
	uint32_t                        ip_versions[MAX_HWIP][HWIP_MAX_INSTANCE];

	bool				ram_is_direct_mapped;

	struct list_head                ras_list;

	struct ip_discovery_top         *ip_top;

	struct amdgpu_reset_domain	*reset_domain;

	struct mutex			benchmark_mutex;

	struct amdgpu_reset_info	reset_info;

	bool                            scpm_enabled;
	uint32_t                        scpm_status;

	struct work_struct		reset_work;

	bool                            job_hang;
	bool                            dc_enabled;
	/* Mask of active clusters */
	uint32_t			aid_mask;

	/* Debug */
	bool                            debug_vm;
	bool                            debug_largebar;
	bool                            debug_disable_soft_recovery;
};

static inline uint32_t amdgpu_ip_version(const struct amdgpu_device *adev,
					 uint8_t ip, uint8_t inst)
{
	/* This considers only major/minor/rev and ignores
	 * subrevision/variant fields.
	 */
	return adev->ip_versions[ip][inst] & ~0xFFU;
}

#define REG_FIELD_SHIFT(reg, field) reg##__##field##__SHIFT
#define REG_FIELD_MASK(reg, field) reg##__##field##_MASK

#define REG_GET_FIELD(value, reg, field)				\
	(((value) & REG_FIELD_MASK(reg, field)) >> REG_FIELD_SHIFT(reg, field))

/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu_object.h */
#include <drm/amdgpu_drm.h>
/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu_res_cursor.h */
#include <drm/drm_mm.h>
#include <drm/ttm/ttm_resource.h>

/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu_object.h */
#ifdef CONFIG_MMU_NOTIFIER
#include <linux/mmu_notifier.h>
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif

/* klp-ccp: from drivers/gpu/drm/amd/include/asic_reg/mmhub/mmhub_3_3_0_sh_mask.h */
#define MMVM_L2_PROTECTION_FAULT_STATUS__MORE_FAULTS__SHIFT                                                   0x0
#define MMVM_L2_PROTECTION_FAULT_STATUS__WALKER_ERROR__SHIFT                                                  0x1
#define MMVM_L2_PROTECTION_FAULT_STATUS__PERMISSION_FAULTS__SHIFT                                             0x4
#define MMVM_L2_PROTECTION_FAULT_STATUS__MAPPING_ERROR__SHIFT                                                 0x8
#define MMVM_L2_PROTECTION_FAULT_STATUS__CID__SHIFT                                                           0x9
#define MMVM_L2_PROTECTION_FAULT_STATUS__RW__SHIFT                                                            0x12

#define MMVM_L2_PROTECTION_FAULT_STATUS__MORE_FAULTS_MASK                                                     0x00000001L
#define MMVM_L2_PROTECTION_FAULT_STATUS__WALKER_ERROR_MASK                                                    0x0000000EL
#define MMVM_L2_PROTECTION_FAULT_STATUS__PERMISSION_FAULTS_MASK                                               0x000000F0L
#define MMVM_L2_PROTECTION_FAULT_STATUS__MAPPING_ERROR_MASK                                                   0x00000100L
#define MMVM_L2_PROTECTION_FAULT_STATUS__CID_MASK                                                             0x0003FE00L
#define MMVM_L2_PROTECTION_FAULT_STATUS__RW_MASK                                                              0x00040000L

/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/mmhub_v3_3.c */
extern const char *mmhub_client_ids_v3_3[31][2];

void
klpp_mmhub_v3_3_print_l2_protection_fault_status(struct amdgpu_device *adev,
					      uint32_t status)
{
	uint32_t cid, rw;
	const char *mmhub_cid = NULL;

	cid = REG_GET_FIELD(status,
			    MMVM_L2_PROTECTION_FAULT_STATUS, CID);
	rw = REG_GET_FIELD(status,
			   MMVM_L2_PROTECTION_FAULT_STATUS, RW);

	dev_err(adev->dev,
		"MMVM_L2_PROTECTION_FAULT_STATUS:0x%08X\n",
		status);

	switch (amdgpu_ip_version(adev, MMHUB_HWIP, 0)) {
	case IP_VERSION(3, 3, 0):
		mmhub_cid = cid < ARRAY_SIZE(mmhub_client_ids_v3_3) ?
			    mmhub_client_ids_v3_3[cid][rw] :
			    cid == 0x140 ? "UMSCH" : NULL;
		break;
	default:
		mmhub_cid = NULL;
		break;
	}

	dev_err(adev->dev, "\t Faulty UTCL2 client ID: %s (0x%x)\n",
		mmhub_cid ? mmhub_cid : "unknown", cid);
	dev_err(adev->dev, "\t MORE_FAULTS: 0x%lx\n",
		REG_GET_FIELD(status,
		MMVM_L2_PROTECTION_FAULT_STATUS, MORE_FAULTS));
	dev_err(adev->dev, "\t WALKER_ERROR: 0x%lx\n",
		REG_GET_FIELD(status,
		MMVM_L2_PROTECTION_FAULT_STATUS, WALKER_ERROR));
	dev_err(adev->dev, "\t PERMISSION_FAULTS: 0x%lx\n",
		REG_GET_FIELD(status,
		MMVM_L2_PROTECTION_FAULT_STATUS, PERMISSION_FAULTS));
	dev_err(adev->dev, "\t MAPPING_ERROR: 0x%lx\n",
		REG_GET_FIELD(status,
		MMVM_L2_PROTECTION_FAULT_STATUS, MAPPING_ERROR));
	dev_err(adev->dev, "\t RW: 0x%x\n", rw);
}

#include <linux/livepatch.h>

#include "livepatch_bsc1226184.h"

extern typeof(mmhub_client_ids_v3_3) mmhub_client_ids_v3_3
	 KLP_RELOC_SYMBOL(amdgpu, amdgpu, mmhub_client_ids_v3_3);

#endif /* IS_ENABLED(CONFIG_DRM_AMDGPU) */
