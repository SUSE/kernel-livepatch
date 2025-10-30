/*
 * livepatch_bsc1248176
 *
 * Fix for CVE-2025-38511, bsc#1248176
 *
 *  Copyright (c) 2025 SUSE
 *  Author: Lidong Zhong <lidong.zhong@suse.com>
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

#if IS_ENABLED(CONFIG_DRM_XE)


/* klp-ccp: from drivers/gpu/drm/xe/xe_lmtt.c */
#include <linux/align.h>
#include <drm/drm_managed.h>

/* klp-ccp: from drivers/gpu/drm/xe/regs/xe_reg_defs.h */
#include <linux/build_bug.h>
/* klp-ccp: from drivers/gpu/drm/i915/i915_reg_defs.h */
#include <linux/bits.h>

/* klp-ccp: from include/linux/ctype.h */
#define _LINUX_CTYPE_H

/* klp-ccp: from drivers/gpu/drm/xe/xe_assert.h */
#include <drm/drm_print.h>
/* klp-ccp: from drivers/gpu/drm/xe/xe_device_types.h */
#include <linux/pci.h>
#include <drm/drm_device.h>

#include <drm/ttm/ttm_device.h>

/* klp-ccp: from drivers/gpu/drm/xe/xe_devcoredump_types.h */
#include <linux/ktime.h>
#include <linux/mutex.h>

/* klp-ccp: from drivers/gpu/drm/xe/xe_force_wake_types.h */
#include <linux/mutex.h>
#include <linux/types.h>

/* klp-ccp: from drivers/gpu/drm/xe/xe_lrc_types.h */
#include <linux/kref.h>
/* klp-ccp: from drivers/gpu/drm/xe/xe_hw_fence_types.h */
#include <linux/dma-fence.h>
#include <linux/iosys-map.h>

#include <linux/list.h>
#include <linux/spinlock.h>

/* klp-ccp: from drivers/gpu/drm/xe/xe_reg_sr_types.h */
#include <linux/types.h>
#include <linux/xarray.h>

/* klp-ccp: from drivers/gpu/drm/xe/xe_hw_engine_types.h */
enum xe_engine_class {
	XE_ENGINE_CLASS_RENDER = 0,
	XE_ENGINE_CLASS_VIDEO_DECODE = 1,
	XE_ENGINE_CLASS_VIDEO_ENHANCE = 2,
	XE_ENGINE_CLASS_COPY = 3,
	XE_ENGINE_CLASS_OTHER = 4,
	XE_ENGINE_CLASS_COMPUTE = 5,
	XE_ENGINE_CLASS_MAX = 6,
};

enum xe_hw_engine_id {
	XE_HW_ENGINE_RCS0,
	XE_HW_ENGINE_BCS0,
	XE_HW_ENGINE_BCS1,
	XE_HW_ENGINE_BCS2,
	XE_HW_ENGINE_BCS3,
	XE_HW_ENGINE_BCS4,
	XE_HW_ENGINE_BCS5,
	XE_HW_ENGINE_BCS6,
	XE_HW_ENGINE_BCS7,
	XE_HW_ENGINE_BCS8,
	XE_HW_ENGINE_VCS0,
	XE_HW_ENGINE_VCS1,
	XE_HW_ENGINE_VCS2,
	XE_HW_ENGINE_VCS3,
	XE_HW_ENGINE_VCS4,
	XE_HW_ENGINE_VCS5,
	XE_HW_ENGINE_VCS6,
	XE_HW_ENGINE_VCS7,
	XE_HW_ENGINE_VECS0,
	XE_HW_ENGINE_VECS1,
	XE_HW_ENGINE_VECS2,
	XE_HW_ENGINE_VECS3,
	XE_HW_ENGINE_CCS0,
	XE_HW_ENGINE_CCS1,
	XE_HW_ENGINE_CCS2,
	XE_HW_ENGINE_CCS3,
	XE_HW_ENGINE_GSCCS0,
	XE_NUM_HW_ENGINES,
};

/* klp-ccp: from drivers/gpu/drm/xe/xe_devcoredump_types.h */
struct xe_devcoredump_snapshot {
	/** @snapshot_time:  Time of this capture. */
	ktime_t snapshot_time;
	/** @boot_time:  Relative boot time so the uptime can be calculated. */
	ktime_t boot_time;
	/** @process_name: Name of process that triggered this gpu hang */
	char process_name[TASK_COMM_LEN];

	/** @gt: Affected GT, used by forcewake for delayed capture */
	struct xe_gt *gt;
	/** @work: Workqueue for deferred capture outside of signaling context */
	struct work_struct work;

	/* GuC snapshots */
	/** @ct: GuC CT snapshot */
	struct xe_guc_ct_snapshot *ct;

	/** @ge: GuC Submission Engine snapshot */
	struct xe_guc_submit_exec_queue_snapshot *ge;

	/** @hwe: HW Engine snapshot array */
	struct xe_hw_engine_snapshot *hwe[XE_NUM_HW_ENGINES];
	/** @job: Snapshot of job state */
	struct xe_sched_job_snapshot *job;
	/** @vm: Snapshot of VM state */
	struct xe_vm_snapshot *vm;

	/** @read: devcoredump in human readable format */
	struct {
		/** @read.size: size of devcoredump in human readable format */
		ssize_t size;
		/** @read.buffer: buffer of devcoredump in human readable format */
		char *buffer;
	} read;
};

struct xe_devcoredump {
	/** @captured: The snapshot of the first hang has already been taken. */
	bool captured;
	/** @snapshot: Snapshot is captured at time of the first crash */
	struct xe_devcoredump_snapshot snapshot;
};

/* klp-ccp: from drivers/gpu/drm/xe/xe_heci_gsc.h */
#include <linux/types.h>

struct xe_heci_gsc {
	struct mei_aux_device *adev;
	int irq;
};

/* klp-ccp: from drivers/gpu/drm/xe/xe_gt_idle_types.h */
#include <linux/types.h>
/* klp-ccp: from drivers/gpu/drm/xe/xe_gt_sriov_pf_types.h */
#include <linux/types.h>
/* klp-ccp: from drivers/gpu/drm/xe/xe_ggtt_types.h */
#include <drm/drm_mm.h>
/* klp-ccp: from drivers/gpu/drm/xe/xe_pt_types.h */
#include <linux/types.h>
/* klp-ccp: from drivers/gpu/drm/xe/xe_pt_walk.h */
#include <linux/types.h>

/* klp-ccp: from drivers/gpu/drm/xe/xe_pt_types.h */
enum xe_cache_level {
	XE_CACHE_NONE,
	XE_CACHE_WT,
	XE_CACHE_WB,
	XE_CACHE_NONE_COMPRESSION, /*UC + COH_NONE + COMPRESSION */
	__XE_CACHE_LEVEL_COUNT,
};

/* klp-ccp: from drivers/gpu/drm/xe/xe_args.h */
#include <linux/kernel.h>
/* klp-ccp: from drivers/gpu/drm/xe/xe_gt_sriov_pf_control_types.h */
#include <linux/completion.h>
#include <linux/spinlock.h>
#include <linux/kernel.h>

/* klp-ccp: from drivers/gpu/drm/xe/xe_gt_sriov_pf_policy_types.h */
#include <linux/types.h>
/* klp-ccp: from drivers/gpu/drm/xe/xe_gt_sriov_pf_service_types.h */
#include <linux/types.h>
/* klp-ccp: from drivers/gpu/drm/xe/xe_gt_sriov_vf_types.h */
#include <linux/types.h>
/* klp-ccp: from drivers/gpu/drm/xe/xe_oa_types.h */
#include <linux/bitops.h>
#include <linux/idr.h>
#include <linux/mutex.h>
#include <linux/types.h>

enum xe_oa_format_name {
	XE_OA_FORMAT_C4_B8,

	/* Gen8+ */
	XE_OA_FORMAT_A12,
	XE_OA_FORMAT_A12_B8_C8,
	XE_OA_FORMAT_A32u40_A4u32_B8_C8,

	/* DG2 */
	XE_OAR_FORMAT_A32u40_A4u32_B8_C8,
	XE_OA_FORMAT_A24u40_A14u32_B8_C8,

	/* DG2/MTL OAC */
	XE_OAC_FORMAT_A24u64_B8_C8,
	XE_OAC_FORMAT_A22u32_R2u32_B8_C8,

	/* MTL OAM */
	XE_OAM_FORMAT_MPEC8u64_B8_C8,
	XE_OAM_FORMAT_MPEC8u32_B8_C8,

	/* Xe2+ */
	XE_OA_FORMAT_PEC64u64,
	XE_OA_FORMAT_PEC64u64_B8_C8,
	XE_OA_FORMAT_PEC64u32,
	XE_OA_FORMAT_PEC32u64_G1,
	XE_OA_FORMAT_PEC32u32_G1,
	XE_OA_FORMAT_PEC32u64_G2,
	XE_OA_FORMAT_PEC32u32_G2,
	XE_OA_FORMAT_PEC36u64_G1_32_G2_4,
	XE_OA_FORMAT_PEC36u64_G1_4_G2_32,

	__XE_OA_FORMAT_MAX,
};

struct xe_oa {
	/** @xe: back pointer to xe device */
	struct xe_device *xe;

	/** @metrics_kobj: kobj for metrics sysfs */
	struct kobject *metrics_kobj;

	/** @metrics_lock: lock protecting add/remove configs */
	struct mutex metrics_lock;

	/** @metrics_idr: List of dynamic configurations (struct xe_oa_config) */
	struct idr metrics_idr;

	/** @ctx_oactxctrl_offset: offset of OACTXCONTROL register in context image */
	u32 ctx_oactxctrl_offset[XE_ENGINE_CLASS_MAX];

	/** @oa_formats: tracks all OA formats across platforms */
	const struct xe_oa_format *oa_formats;

	/** @format_mask: tracks valid OA formats for a platform */
	unsigned long format_mask[BITS_TO_LONGS(__XE_OA_FORMAT_MAX)];

	/** @oa_unit_ids: tracks oa unit ids assigned across gt's */
	u16 oa_unit_ids;
};

/* klp-ccp: from drivers/gpu/drm/xe/xe_gsc_types.h */
#include <linux/iosys-map.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/workqueue.h>

/* klp-ccp: from drivers/gpu/drm/xe/xe_uc_fw_types.h */
#include <linux/types.h>
/* klp-ccp: from drivers/gpu/drm/xe/xe_guc_types.h */
#include <linux/idr.h>
#include <linux/xarray.h>

/* klp-ccp: from drivers/gpu/drm/xe/xe_guc_ads_types.h */
#include <linux/types.h>
/* klp-ccp: from drivers/gpu/drm/xe/xe_guc_ct_types.h */
#include <linux/interrupt.h>
#include <linux/iosys-map.h>
#include <linux/spinlock_types.h>
#include <linux/wait.h>
#include <linux/xarray.h>

/* klp-ccp: from drivers/gpu/drm/xe/abi/guc_communication_ctb_abi.h */
#include <linux/types.h>
#include <linux/build_bug.h>

/* klp-ccp: from drivers/gpu/drm/xe/xe_guc_fwif.h */
#include <linux/bits.h>
/* klp-ccp: from drivers/gpu/drm/xe/abi/guc_klvs_abi.h */
#include <linux/types.h>
/* klp-ccp: from drivers/gpu/drm/xe/xe_guc_log_types.h */
#include <linux/types.h>
/* klp-ccp: from drivers/gpu/drm/xe/xe_guc_pc_types.h */
#include <linux/mutex.h>
#include <linux/types.h>

/* klp-ccp: from drivers/gpu/drm/xe/xe_guc_relay_types.h */
#include <linux/spinlock.h>
#include <linux/workqueue.h>

/* klp-ccp: from drivers/gpu/drm/xe/xe_wopcm_types.h */
#include <linux/types.h>
/* klp-ccp: from drivers/gpu/drm/xe/xe_lmtt_types.h */
#include <linux/types.h>

struct xe_lmtt {
	/** @pd: root LMTT Directory */
	struct xe_lmtt_pt *pd;

	/** @ops: LMTT functions */
	const struct xe_lmtt_ops *ops;
};

struct xe_lmtt_pt {
	/** @level: page table level, 0 is leaf */
	unsigned int level;

	/** @bo: buffer object with actual LMTT PTE values */
	struct xe_bo *bo;

	/** @entries: leaf page tables, exist only for root/non-leaf */
	struct xe_lmtt_pt *entries[];
};

struct xe_lmtt_ops {
	/* private: */
	unsigned int (*lmtt_root_pd_level)(void);
	unsigned int (*lmtt_pte_num)(unsigned int level);
	unsigned int (*lmtt_pte_size)(unsigned int level);
	unsigned int (*lmtt_pte_shift)(unsigned int level);
	unsigned int (*lmtt_pte_index)(u64 addr, unsigned int level);
	u64 (*lmtt_pte_encode)(unsigned long offset, unsigned int level);
};

/* klp-ccp: from drivers/gpu/drm/xe/xe_memirq_types.h */
#include <linux/iosys-map.h>

struct xe_memirq {
	struct xe_bo *bo;
	struct iosys_map source;
	struct iosys_map status;
	struct iosys_map mask;
	bool enabled;
};

/* klp-ccp: from drivers/gpu/drm/xe/xe_platform_types.h */
enum xe_platform {
	XE_PLATFORM_UNINITIALIZED = 0,
	XE_TIGERLAKE,
	XE_ROCKETLAKE,
	XE_ALDERLAKE_S,
	XE_ALDERLAKE_P,
	XE_ALDERLAKE_N,
	XE_DG1,
	XE_DG2,
	XE_PVC,
	XE_METEORLAKE,
	XE_LUNARLAKE,
	XE_BATTLEMAGE,
};

enum xe_subplatform {
	XE_SUBPLATFORM_UNINITIALIZED = 0,
	XE_SUBPLATFORM_NONE,
	XE_SUBPLATFORM_ALDERLAKE_P_RPLU,
	XE_SUBPLATFORM_ALDERLAKE_S_RPLS,
	XE_SUBPLATFORM_DG2_G10,
	XE_SUBPLATFORM_DG2_G11,
	XE_SUBPLATFORM_DG2_G12,
};

/* klp-ccp: from drivers/gpu/drm/xe/xe_sriov_types.h */
#include <linux/build_bug.h>
#include <linux/mutex.h>
#include <linux/types.h>

enum xe_sriov_mode {
	/*
	 * Note: We don't use default enum value 0 to allow catch any too early
	 * attempt of checking the SR-IOV mode prior to the actual mode probe.
	 */
	XE_SRIOV_MODE_NONE = 1,
	XE_SRIOV_MODE_PF,
	XE_SRIOV_MODE_VF,
};

struct xe_device_pf {
	/** @device_total_vfs: Maximum number of VFs supported by the device. */
	u16 device_total_vfs;

	/** @driver_max_vfs: Maximum number of VFs supported by the driver. */
	u16 driver_max_vfs;

	/** @master_lock: protects all VFs configurations across GTs */
	struct mutex master_lock;
};

/* klp-ccp: from drivers/gpu/drm/xe/xe_step_types.h */
#include <linux/types.h>

struct xe_step_info {
	u8 graphics;
	u8 media;
	u8 basedie;
};

/* klp-ccp: from drivers/gpu/drm/xe/xe_device_types.h */
#if IS_ENABLED(CONFIG_DRM_XE_DISPLAY)

/* klp-ccp: from drivers/gpu/drm/i915/soc/intel_pch.h */
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
	PCH_MTL,
	PCH_LNL,
};

/* klp-ccp: from drivers/gpu/drm/i915/display/intel_display_core.h */
#include <linux/list.h>
#include <linux/llist.h>
#include <linux/mutex.h>
#include <linux/types.h>
#include <linux/wait.h>
#include <linux/workqueue.h>

#include <drm/drm_connector.h>
#include <drm/drm_modeset_lock.h>

/* klp-ccp: from drivers/gpu/drm/i915/display/intel_cdclk.h */
#include <linux/types.h>

/* klp-ccp: from drivers/gpu/drm/i915/display/intel_display_limits.h */
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
	/* skl+ universal plane names */
	PLANE_1,
	PLANE_2,
	PLANE_3,
	PLANE_4,
	PLANE_5,
	PLANE_6,
	PLANE_7,

	PLANE_CURSOR,

	I915_MAX_PLANES,

	/* pre-skl plane names */
	PLANE_PRIMARY = PLANE_1,
	PLANE_SPRITE0,
	PLANE_SPRITE1,
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
	/* This field is only valid for Xe2LPD and above. */
	bool joined_mbus;
};

/* klp-ccp: from drivers/gpu/drm/i915/display/intel_display_device.h */
#include <linux/types.h>

enum intel_display_platform {
	INTEL_DISPLAY_PLATFORM_UNINITIALIZED = 0,
	/* Display ver 2 */
	INTEL_DISPLAY_I830,
	INTEL_DISPLAY_I845G,
	INTEL_DISPLAY_I85X,
	INTEL_DISPLAY_I865G,
	/* Display ver 3 */
	INTEL_DISPLAY_I915G,
	INTEL_DISPLAY_I915GM,
	INTEL_DISPLAY_I945G,
	INTEL_DISPLAY_I945GM,
	INTEL_DISPLAY_G33,
	INTEL_DISPLAY_PINEVIEW,
	/* Display ver 4 */
	INTEL_DISPLAY_I965G,
	INTEL_DISPLAY_I965GM,
	INTEL_DISPLAY_G45,
	INTEL_DISPLAY_GM45,
	/* Display ver 5 */
	INTEL_DISPLAY_IRONLAKE,
	/* Display ver 6 */
	INTEL_DISPLAY_SANDYBRIDGE,
	/* Display ver 7 */
	INTEL_DISPLAY_IVYBRIDGE,
	INTEL_DISPLAY_VALLEYVIEW,
	INTEL_DISPLAY_HASWELL,
	/* Display ver 8 */
	INTEL_DISPLAY_BROADWELL,
	INTEL_DISPLAY_CHERRYVIEW,
	/* Display ver 9 */
	INTEL_DISPLAY_SKYLAKE,
	INTEL_DISPLAY_BROXTON,
	INTEL_DISPLAY_KABYLAKE,
	INTEL_DISPLAY_GEMINILAKE,
	INTEL_DISPLAY_COFFEELAKE,
	INTEL_DISPLAY_COMETLAKE,
	/* Display ver 11 */
	INTEL_DISPLAY_ICELAKE,
	INTEL_DISPLAY_JASPERLAKE,
	INTEL_DISPLAY_ELKHARTLAKE,
	/* Display ver 12 */
	INTEL_DISPLAY_TIGERLAKE,
	INTEL_DISPLAY_ROCKETLAKE,
	INTEL_DISPLAY_DG1,
	INTEL_DISPLAY_ALDERLAKE_S,
	/* Display ver 13 */
	INTEL_DISPLAY_ALDERLAKE_P,
	INTEL_DISPLAY_DG2,
	/* Display ver 14 (based on GMD ID) */
	INTEL_DISPLAY_METEORLAKE,
	/* Display ver 20 (based on GMD ID) */
	INTEL_DISPLAY_LUNARLAKE,
	/* Display ver 14.1 (based on GMD ID) */
	INTEL_DISPLAY_BATTLEMAGE,
};

enum intel_display_subplatform {
	INTEL_DISPLAY_SUBPLATFORM_UNINITIALIZED = 0,
	INTEL_DISPLAY_HASWELL_ULT,
	INTEL_DISPLAY_HASWELL_ULX,
	INTEL_DISPLAY_BROADWELL_ULT,
	INTEL_DISPLAY_BROADWELL_ULX,
	INTEL_DISPLAY_SKYLAKE_ULT,
	INTEL_DISPLAY_SKYLAKE_ULX,
	INTEL_DISPLAY_KABYLAKE_ULT,
	INTEL_DISPLAY_KABYLAKE_ULX,
	INTEL_DISPLAY_COFFEELAKE_ULT,
	INTEL_DISPLAY_COFFEELAKE_ULX,
	INTEL_DISPLAY_COMETLAKE_ULT,
	INTEL_DISPLAY_COMETLAKE_ULX,
	INTEL_DISPLAY_ICELAKE_PORT_F,
	INTEL_DISPLAY_TIGERLAKE_UY,
	INTEL_DISPLAY_ALDERLAKE_S_RAPTORLAKE_S,
	INTEL_DISPLAY_ALDERLAKE_P_ALDERLAKE_N,
	INTEL_DISPLAY_ALDERLAKE_P_RAPTORLAKE_P,
	INTEL_DISPLAY_ALDERLAKE_P_RAPTORLAKE_U,
	INTEL_DISPLAY_DG2_G10,
	INTEL_DISPLAY_DG2_G11,
	INTEL_DISPLAY_DG2_G12,
};

struct intel_display_runtime_info {
	enum intel_display_platform platform;
	enum intel_display_subplatform subplatform;

	struct intel_display_ip_ver {
		u16 ver;
		u16 rel;
		u16 step; /* hardware */
	} ip;
	int step; /* symbolic */

	u32 rawclk_freq;

	u8 pipe_mask;
	u8 cpu_transcoder_mask;
	u16 port_mask;

	u8 num_sprites[I915_MAX_PIPES];
	u8 num_scalers[I915_MAX_PIPES];

	u8 fbc_mask;

	bool has_hdcp;
	bool has_dmc;
	bool has_dsc;
};

/* klp-ccp: from drivers/gpu/drm/i915/display/intel_display_params.h */
#include <linux/types.h>

#define INTEL_DISPLAY_PARAMS_FOR_EACH(param) \
	param(char *, dmc_firmware_path, NULL, 0400) \
	param(char *, vbt_firmware, NULL, 0400) \
	param(int, lvds_channel_mode, 0, 0400) \
	param(int, panel_use_ssc, -1, 0600) \
	param(int, vbt_sdvo_panel_type, -1, 0400) \
	param(int, enable_dc, -1, 0400) \
	param(bool, enable_dpt, true, 0400) \
	param(bool, enable_dsb, true, 0600) \
	param(bool, enable_sagv, true, 0600) \
	param(int, disable_power_well, -1, 0400) \
	param(bool, enable_ips, true, 0600) \
	param(int, invert_brightness, 0, 0600) \
	param(int, edp_vswing, 0, 0400) \
	param(int, enable_dpcd_backlight, -1, 0600) \
	param(bool, load_detect_test, false, 0600) \
	param(bool, force_reset_modeset_test, false, 0600) \
	param(bool, disable_display, false, 0400) \
	param(bool, verbose_state_checks, true, 0400) \
	param(bool, nuclear_pageflip, false, 0400) \
	param(bool, enable_dp_mst, true, 0600) \
	param(int, enable_fbc, -1, 0600) \
	param(int, enable_psr, -1, 0600) \
	param(bool, psr_safest_params, false, 0400) \
	param(bool, enable_psr2_sel_fetch, true, 0400) \
	param(bool, enable_dmc_wl, false, 0400) \

#define MEMBER(T, member, ...) T member;
struct intel_display_params {
	INTEL_DISPLAY_PARAMS_FOR_EACH(MEMBER);
};

/* klp-ccp: from drivers/gpu/drm/i915/display/intel_display_power.h */
#include <linux/mutex.h>
#include <linux/workqueue.h>

/* klp-ccp: from drivers/gpu/drm/xe/compat-i915-headers/intel_wakeref.h */
#include <linux/types.h>

typedef unsigned long intel_wakeref_t;

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

	POWER_DOMAIN_AUX_IO_A,
	POWER_DOMAIN_AUX_IO_B,
	POWER_DOMAIN_AUX_IO_C,
	POWER_DOMAIN_AUX_IO_D,
	POWER_DOMAIN_AUX_IO_E,
	POWER_DOMAIN_AUX_IO_F,

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

	POWER_DOMAIN_AUX_TBT1,
	POWER_DOMAIN_AUX_TBT2,
	POWER_DOMAIN_AUX_TBT3,
	POWER_DOMAIN_AUX_TBT4,
	POWER_DOMAIN_AUX_TBT5,
	POWER_DOMAIN_AUX_TBT6,

	POWER_DOMAIN_GMBUS,
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

	u32 dc_state;
	u32 target_dc_state;
	u32 allowed_dc_mask;

	intel_wakeref_t init_wakeref;
	intel_wakeref_t disable_wakeref;

	struct mutex lock;
	int domain_use_count[POWER_DOMAIN_NUM];

	struct delayed_work async_put_work;
	intel_wakeref_t async_put_wakeref;
	struct intel_power_domain_mask async_put_domains[2];
	int async_put_next_delay;

	struct i915_power_well *power_wells;
};

/* klp-ccp: from drivers/gpu/drm/i915/display/intel_dpll_mgr.h */
#include <linux/types.h>
/* klp-ccp: from drivers/gpu/drm/xe/compat-i915-headers/intel_wakeref.h */
#include <linux/types.h>

typedef unsigned long intel_wakeref_t;

/* klp-ccp: from drivers/gpu/drm/i915/display/intel_dpll_mgr.h */
#define I915_NUM_PLLS 9

struct i9xx_dpll_hw_state {
	u32 dpll;
	u32 dpll_md;
	u32 fp0;
	u32 fp1;
};

struct hsw_dpll_hw_state {
	u32 wrpll;
	u32 spll;
};

struct skl_dpll_hw_state {
	/*
	 * DPLL_CTRL1 has 6 bits for each each this DPLL. We store those in
	 * lower part of ctrl1 and they get shifted into position when writing
	 * the register.  This allows us to easily compare the state to share
	 * the DPLL.
	 */
	u32 ctrl1;
	/* HDMI only, 0 when used for DP */
	u32 cfgcr1, cfgcr2;
};

struct bxt_dpll_hw_state {
	u32 ebb0, ebb4, pll0, pll1, pll2, pll3, pll6, pll8, pll9, pll10, pcsdw12;
};

struct icl_dpll_hw_state {
	u32 cfgcr0, cfgcr1;

	/* tgl */
	u32 div0;

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

struct intel_mpllb_state {
	u32 clock; /* in KHz */
	u32 ref_control;
	u32 mpllb_cp;
	u32 mpllb_div;
	u32 mpllb_div2;
	u32 mpllb_fracn1;
	u32 mpllb_fracn2;
	u32 mpllb_sscen;
	u32 mpllb_sscstep;
};

struct intel_c10pll_state {
	u32 clock; /* in KHz */
	u8 tx;
	u8 cmn;
	u8 pll[20];
};

struct intel_c20pll_state {
	u32 clock; /* in kHz */
	u16 tx[3];
	u16 cmn[4];
	union {
		u16 mplla[10];
		u16 mpllb[11];
	};
};

struct intel_cx0pll_state {
	union {
		struct intel_c10pll_state c10;
		struct intel_c20pll_state c20;
	};
	bool ssc_enabled;
	bool use_c10;
	bool tbt_mode;
};

struct intel_dpll_hw_state {
	union {
		struct i9xx_dpll_hw_state i9xx;
		struct hsw_dpll_hw_state hsw;
		struct skl_dpll_hw_state skl;
		struct bxt_dpll_hw_state bxt;
		struct icl_dpll_hw_state icl;
		struct intel_mpllb_state mpllb;
		struct intel_cx0pll_state cx0pll;
	};
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
	 * @index: index for atomic state
	 */
	u8 index;

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

/* klp-ccp: from drivers/gpu/drm/i915/display/intel_fbc.h */
#include <linux/types.h>

enum intel_fbc_id {
	INTEL_FBC_A,
	INTEL_FBC_B,
	INTEL_FBC_C,
	INTEL_FBC_D,

	I915_MAX_FBCS,
};

/* klp-ccp: from drivers/gpu/drm/i915/display/intel_gmbus.h */
#include <linux/types.h>

#define GMBUS_NUM_PINS	15 /* including 0 */

/* klp-ccp: from drivers/gpu/drm/i915/display/intel_opregion.h */
#include <linux/pci.h>
#include <linux/types.h>

/* klp-ccp: from drivers/gpu/drm/i915/display/intel_dmc_wl.h */
#include <linux/types.h>
#include <linux/workqueue.h>
#include <linux/refcount.h>

struct intel_dmc_wl {
	spinlock_t lock; /* protects enabled, taken  and refcount */
	bool enabled;
	bool taken;
	refcount_t refcount;
	struct delayed_work work;
};

/* klp-ccp: from drivers/gpu/drm/i915/display/intel_wm_types.h */
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

/* klp-ccp: from drivers/gpu/drm/i915/display/intel_display_core.h */
#define I915_NUM_QGV_POINTS 8

#define I915_NUM_PSF_GV_POINTS 3

struct intel_audio_state {
	struct intel_encoder *encoder;
	u8 eld[MAX_ELD_BYTES];
};

struct intel_audio {
	/* hda/i915 audio component */
	struct i915_audio_component *component;
	bool component_registered;
	/* mutex for audio/video sync */
	struct mutex mutex;
	int power_refcount;
	u32 freq_cntrl;

	/* current audio state for the audio component hooks */
	struct intel_audio_state state[I915_MAX_TRANSCODERS];

	/* necessary resource sharing with HDMI LPE audio driver. */
	struct {
		struct platform_device *platdev;
		int irq;
	} lpe;
};

struct intel_dpll {
	struct mutex lock;

	int num_shared_dpll;
	struct intel_shared_dpll shared_dplls[I915_NUM_PLLS];
	const struct intel_dpll_mgr *mgr;

	struct {
		int nssc;
		int ssc;
	} ref_clks;

	/*
	 * Bitmask of PLLs using the PCH SSC, indexed using enum intel_dpll_id.
	 */
	u8 pch_ssc_use;
};

struct intel_frontbuffer_tracking {
	spinlock_t lock;

	/*
	 * Tracking bits for delayed frontbuffer flushing du to gpu activity or
	 * scheduled flips.
	 */
	unsigned busy_bits;
	unsigned flip_bits;
};

struct intel_hotplug {
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

	/*
	 * Queuing of hotplug_work, reenable_work and poll_init_work is
	 * enabled. Protected by drm_i915_private::irq_lock.
	 */
	bool detection_work_enabled;

	unsigned int hpd_storm_threshold;
	/* Whether or not to count short HPD IRQs in HPD storms */
	u8 hpd_short_storm_enabled;

	/* Last state reported by oob_hotplug_event for each encoder */
	unsigned long oob_hotplug_last_state;

	/*
	 * if we get a HPD irq from DP and a HPD irq from non-DP
	 * the non-DP HPD could block the workqueue on a mode config
	 * mutex getting, that userspace may have taken. However
	 * userspace is waiting on the DP workqueue to run which is
	 * blocked behind the non-DP one.
	 */
	struct workqueue_struct *dp_wq;

	/*
	 * Flag to track if long HPDs need not to be processed
	 *
	 * Some panels generate long HPDs while keep connected to the port.
	 * This can cause issues with CI tests results. In CI systems we
	 * don't expect to disconnect the panels and could ignore the long
	 * HPDs generated from the faulty panels. This flag can be used as
	 * cue to ignore the long HPDs and can be set / unset using debugfs.
	 */
	bool ignore_long_hpd;
};

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

	struct sdvo_device_mapping {
		u8 initialized;
		u8 dvo_port;
		u8 target_addr;
		u8 dvo_wiring;
		u8 i2c_pin;
		u8 ddc_pin;
	} sdvo_mappings[2];
};

struct intel_wm {
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

	u8 num_levels;

	/*
	 * Should be held around atomic WM register writing; also
	 * protects * intel_crtc->wm.active and
	 * crtc_state->wm.need_postvbl_update.
	 */
	struct mutex wm_mutex;

	bool ipc_enabled;
};

struct intel_display {
	/* drm device backpointer */
	struct drm_device *drm;

	/* Display functions */
	struct {
		/* Top level crtc-ish functions */
		const struct intel_display_funcs *display;

		/* Display CDCLK functions */
		const struct intel_cdclk_funcs *cdclk;

		/* Display pll funcs */
		const struct intel_dpll_funcs *dpll;

		/* irq display functions */
		const struct intel_hotplug_funcs *hotplug;

		/* pm display functions */
		const struct intel_wm_funcs *wm;

		/* fdi display functions */
		const struct intel_fdi_funcs *fdi;

		/* Display internal color functions */
		const struct intel_color_funcs *color;

		/* Display internal audio functions */
		const struct intel_audio_funcs *audio;
	} funcs;

	struct {
		bool any_task_allowed;
		struct task_struct *allowed_task;
	} access;

	struct {
		/* backlight registers and fields in struct intel_panel */
		struct mutex lock;
	} backlight;

	struct {
		struct intel_global_obj obj;

		struct intel_bw_info {
			/* for each QGV point */
			unsigned int deratedbw[I915_NUM_QGV_POINTS];
			/* for each PSF GV point */
			unsigned int psf_bw[I915_NUM_PSF_GV_POINTS];
			/* Peak BW for each QGV point */
			unsigned int peakbw[I915_NUM_QGV_POINTS];
			u8 num_qgv_points;
			u8 num_psf_gv_points;
			u8 num_planes;
		} max[6];
	} bw;

	struct {
		/* The current hardware cdclk configuration */
		struct intel_cdclk_config hw;

		/* cdclk, divider, and ratio table from bspec */
		const struct intel_cdclk_vals *table;

		struct intel_global_obj obj;

		unsigned int max_cdclk_freq;
		unsigned int max_dotclk_freq;
		unsigned int skl_preferred_vco_freq;
	} cdclk;

	struct {
		struct drm_property_blob *glk_linear_degamma_lut;
	} color;

	struct {
		/* The current hardware dbuf configuration */
		u8 enabled_slices;

		struct intel_global_obj obj;
	} dbuf;

	struct {
		/*
		 * dkl.phy_lock protects against concurrent access of the
		 * Dekel TypeC PHYs.
		 */
		spinlock_t phy_lock;
	} dkl;

	struct {
		struct intel_dmc *dmc;
		intel_wakeref_t wakeref;
	} dmc;

	struct {
		/* VLV/CHV/BXT/GLK DSI MMIO register base address */
		u32 mmio_base;
	} dsi;

	struct {
		/* list of fbdev register on this device */
		struct intel_fbdev *fbdev;
		struct work_struct suspend_work;
	} fbdev;

	struct {
		unsigned int pll_freq;
		u32 rx_config;
	} fdi;

	struct {
		struct list_head obj_list;
	} global;

	struct {
		/*
		 * Base address of where the gmbus and gpio blocks are located
		 * (either on PCH or on SoC for platforms without PCH).
		 */
		u32 mmio_base;

		/*
		 * gmbus.mutex protects against concurrent usage of the single
		 * hw gmbus controller on different i2c buses.
		 */
		struct mutex mutex;

		struct intel_gmbus *bus[GMBUS_NUM_PINS];

		wait_queue_head_t wait_queue;
	} gmbus;

	struct {
		struct i915_hdcp_arbiter *arbiter;
		bool comp_added;

		/*
		 * HDCP message struct for allocation of memory which can be
		 * reused when sending message to gsc cs.
		 * this is only populated post Meteorlake
		 */
		struct intel_hdcp_gsc_message *hdcp_message;
		/* Mutex to protect the above hdcp related values. */
		struct mutex hdcp_mutex;
	} hdcp;

	struct {
		/*
		 * HTI (aka HDPORT) state read during initial hw readout. Most
		 * platforms don't have HTI, so this will just stay 0. Those
		 * that do will use this later to figure out which PLLs and PHYs
		 * are unavailable for driver usage.
		 */
		u32 state;
	} hti;

	struct {
		/* Access with DISPLAY_INFO() */
		const struct intel_display_device_info *__device_info;

		/* Access with DISPLAY_RUNTIME_INFO() */
		struct intel_display_runtime_info __runtime_info;
	} info;

	struct {
		bool false_color;
	} ips;

	struct {
		bool display_irqs_enabled;

		/* For i915gm/i945gm vblank irq workaround */
		u8 vblank_enabled;

		u32 de_irq_mask[I915_MAX_PIPES];
		u32 pipestat_irq_mask[I915_MAX_PIPES];
	} irq;

	struct {
		wait_queue_head_t waitqueue;

		/* mutex to protect pmdemand programming sequence */
		struct mutex lock;

		struct intel_global_obj obj;
	} pmdemand;

	struct {
		struct i915_power_domains domains;

		/* Shadow for DISPLAY_PHY_CONTROL which can't be safely read */
		u32 chv_phy_control;

		/* perform PHY state sanity checks? */
		bool chv_phy_assert[2];
	} power;

	struct {
		u32 mmio_base;

		/* protects panel power sequencer state */
		struct mutex mutex;
	} pps;

	struct {
		struct drm_property *broadcast_rgb;
		struct drm_property *force_audio;
	} properties;

	struct {
		unsigned long mask;
	} quirks;

	struct {
		/* restore state for suspend/resume and display reset */
		struct drm_atomic_state *modeset_state;
		struct drm_modeset_acquire_ctx reset_ctx;
	} restore;

	struct {
		enum {
			I915_SAGV_UNKNOWN = 0,
			I915_SAGV_DISABLED,
			I915_SAGV_ENABLED,
			I915_SAGV_NOT_CONTROLLED
		} status;

		u32 block_time_us;
	} sagv;

	struct {
		/*
		 * DG2: Mask of PHYs that were not calibrated by the firmware
		 * and should not be used.
		 */
		u8 phy_failed_calibration;
	} snps;

	struct {
		/*
		 * Shadows for CHV DPLL_MD regs to keep the state
		 * checker somewhat working in the presence hardware
		 * crappiness (can't read out DPLL_MD for pipes B & C).
		 */
		u32 chv_dpll_md[I915_MAX_PIPES];
		u32 bxt_phy_grc;
	} state;

	struct {
		/* ordered wq for modesets */
		struct workqueue_struct *modeset;

		/* unbound hipri wq for page flips/plane updates */
		struct workqueue_struct *flip;
	} wq;

	/* Grouping using named structs. Keep sorted. */
	struct drm_dp_tunnel_mgr *dp_tunnel_mgr;
	struct intel_audio audio;
	struct intel_dpll dpll;
	struct intel_fbc *fbc[I915_MAX_FBCS];
	struct intel_frontbuffer_tracking fb_tracking;
	struct intel_hotplug hotplug;
	struct intel_opregion *opregion;
	struct intel_overlay *overlay;
	struct intel_display_params params;
	struct intel_vbt_data vbt;
	struct intel_dmc_wl wl;
	struct intel_wm wm;
};

#else
#error "klp-ccp: a preceeding branch should have been taken"
/* klp-ccp: from drivers/gpu/drm/xe/xe_device_types.h */
#endif

#define IS_DGFX(xe) ((xe)->info.is_dgfx)

#define XE_GT1		1
#define XE_MAX_TILES_PER_DEVICE	(XE_GT1 + 1)

#define tile_to_xe(tile__)								\
	_Generic(tile__,								\
		 const struct xe_tile * : (const struct xe_device *)((tile__)->xe),	\
		 struct xe_tile * : (tile__)->xe)

struct xe_mem_region {
	/** @io_start: IO start address of this VRAM instance */
	resource_size_t io_start;
	/**
	 * @io_size: IO size of this VRAM instance
	 *
	 * This represents how much of this VRAM we can access
	 * via the CPU through the VRAM BAR. This can be smaller
	 * than @usable_size, in which case only part of VRAM is CPU
	 * accessible (typically the first 256M). This
	 * configuration is known as small-bar.
	 */
	resource_size_t io_size;
	/** @dpa_base: This memory regions's DPA (device physical address) base */
	resource_size_t dpa_base;
	/**
	 * @usable_size: usable size of VRAM
	 *
	 * Usable size of VRAM excluding reserved portions
	 * (e.g stolen mem)
	 */
	resource_size_t usable_size;
	/**
	 * @actual_physical_size: Actual VRAM size
	 *
	 * Actual VRAM size including reserved portions
	 * (e.g stolen mem)
	 */
	resource_size_t actual_physical_size;
	/** @mapping: pointer to VRAM mappable space */
	void __iomem *mapping;
};

struct xe_tile {
	/** @xe: Backpointer to tile's PCI device */
	struct xe_device *xe;

	/** @id: ID of the tile */
	u8 id;

	/**
	 * @primary_gt: Primary GT
	 */
	struct xe_gt *primary_gt;

	/**
	 * @media_gt: Media GT
	 *
	 * Only present on devices with media version >= 13.
	 */
	struct xe_gt *media_gt;

	/**
	 * @mmio: MMIO info for a tile.
	 *
	 * Each tile has its own 16MB space in BAR0, laid out as:
	 * * 0-4MB: registers
	 * * 4MB-8MB: reserved
	 * * 8MB-16MB: global GTT
	 */
	struct {
		/** @mmio.size: size of tile's MMIO space */
		size_t size;

		/** @mmio.regs: pointer to tile's MMIO space (starting with registers) */
		void __iomem *regs;
	} mmio;

	/**
	 * @mmio_ext: MMIO-extension info for a tile.
	 *
	 * Each tile has its own additional 256MB (28-bit) MMIO-extension space.
	 */
	struct {
		/** @mmio_ext.size: size of tile's additional MMIO-extension space */
		size_t size;

		/** @mmio_ext.regs: pointer to tile's additional MMIO-extension space */
		void __iomem *regs;
	} mmio_ext;

	/** @mem: memory management info for tile */
	struct {
		/**
		 * @mem.vram: VRAM info for tile.
		 *
		 * Although VRAM is associated with a specific tile, it can
		 * still be accessed by all tiles' GTs.
		 */
		struct xe_mem_region vram;

		/** @mem.vram_mgr: VRAM TTM manager */
		struct xe_ttm_vram_mgr *vram_mgr;

		/** @mem.ggtt: Global graphics translation table */
		struct xe_ggtt *ggtt;

		/**
		 * @mem.kernel_bb_pool: Pool from which batchbuffers are allocated.
		 *
		 * Media GT shares a pool with its primary GT.
		 */
		struct xe_sa_manager *kernel_bb_pool;
	} mem;

	/** @sriov: tile level virtualization data */
	union {
		struct {
			/** @sriov.pf.lmtt: Local Memory Translation Table. */
			struct xe_lmtt lmtt;
		} pf;
		struct {
			/** @sriov.vf.memirq: Memory Based Interrupts. */
			struct xe_memirq memirq;

			/** @sriov.vf.ggtt_balloon: GGTT regions excluded from use. */
			struct xe_ggtt_node *ggtt_balloon[2];
		} vf;
	} sriov;

	/** @pcode: tile's PCODE */
	struct {
		/** @pcode.lock: protecting tile's PCODE mailbox data */
		struct mutex lock;
	} pcode;

	/** @migrate: Migration helper for vram blits and clearing */
	struct xe_migrate *migrate;

	/** @sysfs: sysfs' kobj used by xe_tile_sysfs */
	struct kobject *sysfs;
};

struct xe_device {
	/** @drm: drm device */
	struct drm_device drm;

	/** @devcoredump: device coredump */
	struct xe_devcoredump devcoredump;

	/** @info: device info */
	struct intel_device_info {
		/** @info.platform_name: platform name */
		const char *platform_name;
		/** @info.graphics_name: graphics IP name */
		const char *graphics_name;
		/** @info.media_name: media IP name */
		const char *media_name;
		/** @info.tile_mmio_ext_size: size of MMIO extension space, per-tile */
		u32 tile_mmio_ext_size;
		/** @info.graphics_verx100: graphics IP version */
		u32 graphics_verx100;
		/** @info.media_verx100: media IP version */
		u32 media_verx100;
		/** @info.mem_region_mask: mask of valid memory regions */
		u32 mem_region_mask;
		/** @info.platform: XE platform enum */
		enum xe_platform platform;
		/** @info.subplatform: XE subplatform enum */
		enum xe_subplatform subplatform;
		/** @info.devid: device ID */
		u16 devid;
		/** @info.revid: device revision */
		u8 revid;
		/** @info.step: stepping information for each IP */
		struct xe_step_info step;
		/** @info.dma_mask_size: DMA address bits */
		u8 dma_mask_size;
		/** @info.vram_flags: Vram flags */
		u8 vram_flags;
		/** @info.tile_count: Number of tiles */
		u8 tile_count;
		/** @info.gt_count: Total number of GTs for entire device */
		u8 gt_count;
		/** @info.vm_max_level: Max VM level */
		u8 vm_max_level;
		/** @info.va_bits: Maximum bits of a virtual address */
		u8 va_bits;

		/** @info.is_dgfx: is discrete device */
		u8 is_dgfx:1;
		/** @info.has_asid: Has address space ID */
		u8 has_asid:1;
		/** @info.force_execlist: Forced execlist submission */
		u8 force_execlist:1;
		/** @info.has_flat_ccs: Whether flat CCS metadata is used */
		u8 has_flat_ccs:1;
		/** @info.has_llc: Device has a shared CPU+GPU last level cache */
		u8 has_llc:1;
		/** @info.has_mmio_ext: Device has extra MMIO address range */
		u8 has_mmio_ext:1;
		/** @info.has_range_tlb_invalidation: Has range based TLB invalidations */
		u8 has_range_tlb_invalidation:1;
		/** @info.has_sriov: Supports SR-IOV */
		u8 has_sriov:1;
		/** @info.has_usm: Device has unified shared memory support */
		u8 has_usm:1;
		/**
		 * @info.probe_display: Probe display hardware.  If set to
		 * false, the driver will behave as if there is no display
		 * hardware present and will not try to read/write to it in any
		 * way.  The display hardware, if it exists, will not be
		 * exposed to userspace and will be left untouched in whatever
		 * state the firmware or bootloader left it in.
		 */
		u8 probe_display:1;
		/** @info.skip_mtcfg: skip Multi-Tile configuration from MTCFG register */
		u8 skip_mtcfg:1;
		/** @info.skip_pcode: skip access to PCODE uC */
		u8 skip_pcode:1;
		/** @info.has_heci_gscfi: device has heci gscfi */
		u8 has_heci_gscfi:1;
		/** @info.has_heci_cscfi: device has heci cscfi */
		u8 has_heci_cscfi:1;
		/** @info.skip_guc_pc: Skip GuC based PM feature init */
		u8 skip_guc_pc:1;
		/** @info.has_atomic_enable_pte_bit: Device has atomic enable PTE bit */
		u8 has_atomic_enable_pte_bit:1;
		/** @info.has_device_atomics_on_smem: Supports device atomics on SMEM */
		u8 has_device_atomics_on_smem:1;
	} info;

	/** @irq: device interrupt state */
	struct {
		/** @irq.lock: lock for processing irq's on this device */
		spinlock_t lock;

		/** @irq.enabled: interrupts enabled on this device */
		bool enabled;
	} irq;

	/** @ttm: ttm device */
	struct ttm_device ttm;

	/** @mmio: mmio info for device */
	struct {
		/** @mmio.size: size of MMIO space for device */
		size_t size;
		/** @mmio.regs: pointer to MMIO space for device */
		void __iomem *regs;
	} mmio;

	/** @mem: memory info for device */
	struct {
		/** @mem.vram: VRAM info for device */
		struct xe_mem_region vram;
		/** @mem.sys_mgr: system TTM manager */
		struct ttm_resource_manager sys_mgr;
	} mem;

	/** @sriov: device level virtualization data */
	struct {
		/** @sriov.__mode: SR-IOV mode (Don't access directly!) */
		enum xe_sriov_mode __mode;

		/** @sriov.pf: PF specific data */
		struct xe_device_pf pf;

		/** @sriov.wq: workqueue used by the virtualization workers */
		struct workqueue_struct *wq;
	} sriov;

	/** @usm: unified memory state */
	struct {
		/** @usm.asid: convert a ASID to VM */
		struct xarray asid_to_vm;
		/** @usm.next_asid: next ASID, used to cyclical alloc asids */
		u32 next_asid;
		/** @usm.lock: protects UM state */
		struct rw_semaphore lock;
	} usm;

	/** @pinned: pinned BO state */
	struct {
		/** @pinned.lock: protected pinned BO list state */
		spinlock_t lock;
		/** @pinned.kernel_bo_present: pinned kernel BO that are present */
		struct list_head kernel_bo_present;
		/** @pinned.evicted: pinned BO that have been evicted */
		struct list_head evicted;
		/** @pinned.external_vram: pinned external BO in vram*/
		struct list_head external_vram;
	} pinned;

	/** @ufence_wq: user fence wait queue */
	wait_queue_head_t ufence_wq;

	/** @preempt_fence_wq: used to serialize preempt fences */
	struct workqueue_struct *preempt_fence_wq;

	/** @ordered_wq: used to serialize compute mode resume */
	struct workqueue_struct *ordered_wq;

	/** @unordered_wq: used to serialize unordered work, mostly display */
	struct workqueue_struct *unordered_wq;

	/** @destroy_wq: used to serialize user destroy work, like queue */
	struct workqueue_struct *destroy_wq;

	/** @tiles: device tiles */
	struct xe_tile tiles[XE_MAX_TILES_PER_DEVICE];

	/**
	 * @mem_access: keep track of memory access in the device, possibly
	 * triggering additional actions when they occur.
	 */
	struct {
		/**
		 * @mem_access.vram_userfault: Encapsulate vram_userfault
		 * related stuff
		 */
		struct {
			/**
			 * @mem_access.vram_userfault.lock: Protects access to
			 * @vram_usefault.list Using mutex instead of spinlock
			 * as lock is applied to entire list operation which
			 * may sleep
			 */
			struct mutex lock;

			/**
			 * @mem_access.vram_userfault.list: Keep list of userfaulted
			 * vram bo, which require to release their mmap mappings
			 * at runtime suspend path
			 */
			struct list_head list;
		} vram_userfault;
	} mem_access;

	/**
	 * @pat: Encapsulate PAT related stuff
	 */
	struct {
		/** @pat.ops: Internal operations to abstract platforms */
		const struct xe_pat_ops *ops;
		/** @pat.table: PAT table to program in the HW */
		const struct xe_pat_table_entry *table;
		/** @pat.n_entries: Number of PAT entries */
		int n_entries;
		u32 idx[__XE_CACHE_LEVEL_COUNT];
	} pat;

	/** @d3cold: Encapsulate d3cold related stuff */
	struct {
		/** @d3cold.capable: Indicates if root port is d3cold capable */
		bool capable;

		/** @d3cold.allowed: Indicates if d3cold is a valid device state */
		bool allowed;

		/**
		 * @d3cold.vram_threshold:
		 *
		 * This represents the permissible threshold(in megabytes)
		 * for vram save/restore. d3cold will be disallowed,
		 * when vram_usages is above or equals the threshold value
		 * to avoid the vram save/restore latency.
		 * Default threshold value is 300mb.
		 */
		u32 vram_threshold;
		/** @d3cold.lock: protect vram_threshold */
		struct mutex lock;
	} d3cold;

	/**
	 * @pm_callback_task: Track the active task that is running in either
	 * the runtime_suspend or runtime_resume callbacks.
	 */
	struct task_struct *pm_callback_task;

	/** @hwmon: hwmon subsystem integration */
	struct xe_hwmon *hwmon;

	/** @heci_gsc: graphics security controller */
	struct xe_heci_gsc heci_gsc;

	/** @oa: oa observation subsystem */
	struct xe_oa oa;

	/** @needs_flr_on_fini: requests function-reset on fini */
	bool needs_flr_on_fini;

	/** @wedged: Struct to control Wedged States and mode */
	struct {
		/** @wedged.flag: Xe device faced a critical error and is now blocked. */
		atomic_t flag;
		/** @wedged.mode: Mode controlled by kernel parameter and debugfs */
		int mode;
	} wedged;

#ifdef TEST_VM_OPS_ERROR
#error "klp-ccp: non-taken branch"
#endif

#if IS_ENABLED(CONFIG_DRM_XE_DISPLAY)
	struct intel_display display;
	enum intel_pch pch_type;
	u16 pch_id;

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
			INTEL_DRAM_GDDR,
		} type;
		u8 num_qgv_points;
		u8 num_psf_gv_points;
	} dram_info;

	/*
	 * edram size in MB.
	 * Cannot be determined by PCIID. You must always read a register.
	 */
	u32 edram_size_mb;

	/* To shut up runtime pm macros.. */
	struct xe_runtime_pm {} runtime_pm;

	/* only to allow build, not used functionally */
	u32 irq_mask;

	struct intel_uncore {
		spinlock_t lock;
	} uncore;

	/* only to allow build, not used functionally */
	struct {
		unsigned int hpll_freq;
		unsigned int czclk_freq;
		unsigned int fsb_freq, mem_freq, is_ddr3;
	};

	void *pxp;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
};

/* klp-ccp: from drivers/gpu/drm/xe/xe_step.h */
#include <linux/types.h>

/* klp-ccp: from drivers/gpu/drm/xe/xe_assert.h */
#define __xe_assert_msg(xe, condition, msg, arg...) ({						\
	typecheck(const struct xe_device *, xe);						\
	BUILD_BUG_ON_INVALID(condition);							\
})

#define xe_assert_msg(xe, condition, msg, arg...) ({						\
	const struct xe_device *__xe = (xe);							\
	__xe_assert_msg(__xe, condition,							\
			"platform: %s subplatform: %d\n"					\
			"graphics: %s %u.%02u step %s\n"					\
			"media: %s %u.%02u step %s\n"						\
			msg,									\
			__xe->info.platform_name, __xe->info.subplatform,			\
			__xe->info.graphics_name,						\
			__xe->info.graphics_verx100 / 100,					\
			__xe->info.graphics_verx100 % 100,					\
			xe_step_name(__xe->info.step.graphics),					\
			__xe->info.media_name,							\
			__xe->info.media_verx100 / 100,						\
			__xe->info.media_verx100 % 100,						\
			xe_step_name(__xe->info.step.media),					\
			## arg);								\
})

#define xe_tile_assert(tile, condition) xe_tile_assert_msg((tile), condition, "")
#define xe_tile_assert_msg(tile, condition, msg, arg...) ({					\
	const struct xe_tile *__tile = (tile);							\
	char __buf[10] __maybe_unused;								\
	xe_assert_msg(tile_to_xe(__tile), condition, "tile: %u VRAM %s\n" msg,			\
		      __tile->id, ({ string_get_size(__tile->mem.vram.actual_physical_size, 1,	\
				     STRING_UNITS_2, __buf, sizeof(__buf)); __buf; }), ## arg);	\
})

/* klp-ccp: from include/drm/ttm/ttm_tt.h */
#define _TTM_TT_H_

/* klp-ccp: from drivers/gpu/drm/xe/xe_bo_types.h */
#include <linux/iosys-map.h>
#include <drm/ttm/ttm_bo.h>
#include <drm/ttm/ttm_device.h>

#include <drm/ttm/ttm_placement.h>

#define XE_BO_MAX_PLACEMENTS	3

struct xe_bo {
	/** @ttm: TTM base buffer object */
	struct ttm_buffer_object ttm;
	/** @size: Size of this buffer object */
	size_t size;
	/** @flags: flags for this buffer object */
	u32 flags;
	/** @vm: VM this BO is attached to, for extobj this will be NULL */
	struct xe_vm *vm;
	/** @tile: Tile this BO is attached to (kernel BO only) */
	struct xe_tile *tile;
	/** @placements: valid placements for this BO */
	struct ttm_place placements[XE_BO_MAX_PLACEMENTS];
	/** @placement: current placement for this BO */
	struct ttm_placement placement;
	/** @ggtt_node: GGTT node if this BO is mapped in the GGTT */
	struct xe_ggtt_node *ggtt_node;
	/** @vmap: iosys map of this buffer */
	struct iosys_map vmap;
	/** @ttm_kmap: TTM bo kmap object for internal use only. Keep off. */
	struct ttm_bo_kmap_obj kmap;
	/** @pinned_link: link to present / evicted list of pinned BO */
	struct list_head pinned_link;
#ifdef CONFIG_PROC_FS
	struct xe_drm_client *client;
	/**
	 * @client_link: Link into @xe_drm_client.objects_list
	 */
	struct list_head client_link;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	struct llist_node freed;
	/** @update_index: Update index if PT BO */
	int update_index;
	/** @created: Whether the bo has passed initial creation */
	bool created;

	/** @ccs_cleared */
	bool ccs_cleared;

	/**
	 * @cpu_caching: CPU caching mode. Currently only used for userspace
	 * objects. Exceptions are system memory on DGFX, which is always
	 * WB.
	 */
	u16 cpu_caching;

	/** @vram_userfault_link: Link into @mem_access.vram_userfault.list */
		struct list_head vram_userfault_link;
};

/* klp-ccp: from drivers/gpu/drm/xe/xe_macros.h */
#include <linux/bug.h>
/* klp-ccp: from drivers/gpu/drm/xe/xe_vm_types.h */
#include <linux/dma-resv.h>
#include <linux/kref.h>
#include <linux/mmu_notifier.h>
#include <linux/scatterlist.h>

/* klp-ccp: from drivers/gpu/drm/xe/xe_range_fence.h */
#include <linux/dma-fence.h>
#include <linux/rbtree.h>
#include <linux/types.h>

/* klp-ccp: from drivers/gpu/drm/xe/xe_map.h */
#include <linux/iosys-map.h>
/* klp-ccp: from drivers/gpu/drm/xe/xe_device.h */
#include <drm/drm_util.h>

void xe_device_assert_mem_access(struct xe_device *xe);

/* klp-ccp: from drivers/gpu/drm/xe/xe_map.h */
static inline void xe_map_memset(struct xe_device *xe,
				 struct iosys_map *dst, size_t offset,
				 int value, size_t len)
{
	xe_device_assert_mem_access(xe);
	iosys_map_memset(dst, offset, value, len);
}

#define xe_map_wr(xe__, map__, offset__, type__, val__) ({		\
	struct xe_device *__xe = xe__;					\
	xe_device_assert_mem_access(__xe);				\
	iosys_map_wr(map__, offset__, type__, val__);			\
})

/* klp-ccp: from drivers/gpu/drm/xe/xe_bo.h */
#define XE_BO_FLAG_SYSTEM		BIT(1)
#define XE_BO_FLAG_VRAM0		BIT(2)

#define XE_BO_FLAG_VRAM_IF_DGFX(tile)	(IS_DGFX(tile_to_xe(tile)) ? \
					 XE_BO_FLAG_VRAM0 << (tile)->id : \
					 XE_BO_FLAG_SYSTEM)

#define XE_BO_FLAG_PINNED		BIT(7)

#define XE_BO_FLAG_NEEDS_64K		BIT(15)

#define XE_PTE_SHIFT			12
#define XE_PAGE_SIZE			(1 << XE_PTE_SHIFT)

struct xe_bo *xe_bo_create_pin_map(struct xe_device *xe, struct xe_tile *tile,
				   struct xe_vm *vm, size_t size,
				   enum ttm_bo_type type, u32 flags);

void xe_bo_put(struct xe_bo *bo);

int xe_bo_lock(struct xe_bo *bo, bool intr);

void xe_bo_unlock(struct xe_bo *bo);

void xe_bo_unpin(struct xe_bo *bo);

static inline void xe_bo_unpin_map_no_vm(struct xe_bo *bo)
{
	if (likely(bo)) {
		xe_bo_lock(bo, false);
		xe_bo_unpin(bo);
		xe_bo_unlock(bo);

		xe_bo_put(bo);
	}
}

dma_addr_t xe_bo_addr(struct xe_bo *bo, u64 offset, size_t page_size);

static inline dma_addr_t
xe_bo_main_addr(struct xe_bo *bo, size_t page_size)
{
	return xe_bo_addr(bo, 0, page_size);
}

bool xe_bo_is_vram(struct xe_bo *bo);

/* klp-ccp: from drivers/gpu/drm/xe/xe_lmtt.h */
#include <linux/types.h>

/* klp-ccp: from drivers/gpu/drm/xe/xe_res_cursor.h */
#include <linux/scatterlist.h>
#include <drm/ttm/ttm_placement.h>

#include <drm/ttm/ttm_resource.h>
#include <drm/ttm/ttm_tt.h>

/* klp-ccp: from drivers/gpu/drm/xe/xe_ttm_vram_mgr_types.h */
#include <drm/ttm/ttm_device.h>
/* klp-ccp: from drivers/gpu/drm/xe/xe_sriov_printk.h */
#include <drm/drm_print.h>

#define xe_sriov_dbg_verbose(xe, fmt, ...) typecheck(struct xe_device *, (xe))

/* klp-ccp: from drivers/gpu/drm/xe/xe_lmtt.c */
#define lmtt_assert(lmtt, condition)	xe_tile_assert(lmtt_to_tile(lmtt), condition)
#define lmtt_debug(lmtt, msg...)	xe_sriov_dbg_verbose(lmtt_to_xe(lmtt), "LMTT: " msg)

static struct xe_tile *lmtt_to_tile(struct xe_lmtt *lmtt)
{
	return container_of(lmtt, struct xe_tile, sriov.pf.lmtt);
}

static struct xe_device *lmtt_to_xe(struct xe_lmtt *lmtt)
{
	return tile_to_xe(lmtt_to_tile(lmtt));
}

static u64 lmtt_page_size(struct xe_lmtt *lmtt)
{
        return BIT_ULL(lmtt->ops->lmtt_pte_shift(0));
}

struct xe_lmtt_pt *klpp_lmtt_pt_alloc(struct xe_lmtt *lmtt, unsigned int level)
{
	unsigned int num_entries = level ? lmtt->ops->lmtt_pte_num(level) : 0;
	struct xe_lmtt_pt *pt;
	struct xe_bo *bo;
	int err;

	pt = kzalloc(struct_size(pt, entries, num_entries), GFP_KERNEL);
	if (!pt) {
		err = -ENOMEM;
		goto out;
	}

	bo = xe_bo_create_pin_map(lmtt_to_xe(lmtt), lmtt_to_tile(lmtt), NULL,
				  PAGE_ALIGN(lmtt->ops->lmtt_pte_size(level) *
					     lmtt->ops->lmtt_pte_num(level)),
				  ttm_bo_type_kernel,
				  XE_BO_FLAG_VRAM_IF_DGFX(lmtt_to_tile(lmtt)) |
				  XE_BO_FLAG_NEEDS_64K | XE_BO_FLAG_PINNED);
	if (IS_ERR(bo)) {
		err = PTR_ERR(bo);
		goto out_free_pt;
	}

	lmtt_assert(lmtt, xe_bo_is_vram(bo));
	lmtt_debug(lmtt, "level=%u addr=%#llx\n", level, (u64)xe_bo_main_addr(bo, XE_PAGE_SIZE));

	xe_map_memset(lmtt_to_xe(lmtt), &bo->vmap, 0, 0, bo->size);

	pt->level = level;
	pt->bo = bo;
	return pt;

out_free_pt:
	kfree(pt);
out:
	return ERR_PTR(err);
}

static void klpp_lmtt_pt_free(struct xe_lmtt_pt *pt)
{
	lmtt_debug(&pt->bo->tile->sriov.pf.lmtt, "level=%u addr=%llx\n",
		   pt->level, (u64)xe_bo_main_addr(pt->bo, XE_PAGE_SIZE));

	xe_bo_unpin_map_no_vm(pt->bo);
	kfree(pt);
}

static void klpp_lmtt_fini_pd(struct xe_lmtt *lmtt)
{
	struct xe_lmtt_pt *pd = lmtt->pd;
	unsigned int num_entries = lmtt->ops->lmtt_pte_num(pd->level);
	unsigned int n = 0;

	/* make sure we don't leak */
	for (n = 0; n < num_entries; n++)
		lmtt_assert(lmtt, !pd->entries[n]);

	lmtt->pd = NULL;
	klpp_lmtt_pt_free(pd);
}

void klpp_fini_lmtt(struct drm_device *drm, void *arg)
{
	struct xe_lmtt *lmtt = arg;

	lmtt_assert(lmtt, !(!!lmtt->ops ^ !!lmtt->pd));

	if (!lmtt->pd)
		return;

	klpp_lmtt_fini_pd(lmtt);
	lmtt->ops = NULL;
}

void klpp_lmtt_write_pte(struct xe_lmtt *lmtt, struct xe_lmtt_pt *pt,
			   u64 pte, unsigned int idx)
{
	unsigned int level = pt->level;

	lmtt_assert(lmtt, idx <= lmtt->ops->lmtt_pte_num(level));
	lmtt_debug(lmtt, "WRITE level=%u index=%u pte=%#llx\n", level, idx, pte);

	switch (lmtt->ops->lmtt_pte_size(level)) {
	case sizeof(u32):
		lmtt_assert(lmtt, !overflows_type(pte, u32));
		lmtt_assert(lmtt, !pte || !iosys_map_rd(&pt->bo->vmap, idx * sizeof(u32), u32));

		xe_map_wr(lmtt_to_xe(lmtt), &pt->bo->vmap, idx * sizeof(u32), u32, pte);
		break;
	case sizeof(u64):
		lmtt_assert(lmtt, !pte || !iosys_map_rd(&pt->bo->vmap, idx * sizeof(u64), u64));

		xe_map_wr(lmtt_to_xe(lmtt), &pt->bo->vmap, idx * sizeof(u64), u64, pte);
		break;
	default:
		lmtt_assert(lmtt, !!!"invalid pte size");
	}
}

void klpp_lmtt_destroy_pt(struct xe_lmtt *lmtt, struct xe_lmtt_pt *pd)
{
	unsigned int num_entries = pd->level ? lmtt->ops->lmtt_pte_num(pd->level) : 0;
	struct xe_lmtt_pt *pt;
	unsigned int i;

	for (i = 0; i < num_entries; i++) {
		pt = pd->entries[i];
		pd->entries[i] = NULL;
		if (!pt)
			continue;

		klpp_lmtt_destroy_pt(lmtt, pt);
	}

	klpp_lmtt_pt_free(pd);
}

extern int __lmtt_alloc_range(struct xe_lmtt *lmtt, struct xe_lmtt_pt *pd,
			      u64 start, u64 end);

static int klpp_lmtt_alloc_range(struct xe_lmtt *lmtt, unsigned int vfid, u64 start, u64 end)
{
	struct xe_lmtt_pt *pd = lmtt->pd;
	struct xe_lmtt_pt *pt;
	u64 pt_addr;
	u64 pde;
	int err;

	lmtt_assert(lmtt, pd->level > 0);
	lmtt_assert(lmtt, vfid <= lmtt->ops->lmtt_pte_num(pd->level));
	lmtt_assert(lmtt, IS_ALIGNED(start, lmtt_page_size(lmtt)));
	lmtt_assert(lmtt, IS_ALIGNED(end, lmtt_page_size(lmtt)));

	if (pd->entries[vfid])
		return -ENOTEMPTY;

	pt = klpp_lmtt_pt_alloc(lmtt, pd->level - 1);
	if (IS_ERR(pt))
		return PTR_ERR(pt);

	pt_addr = xe_bo_main_addr(pt->bo, XE_PAGE_SIZE);

	pde = lmtt->ops->lmtt_pte_encode(pt_addr, pd->level);

	klpp_lmtt_write_pte(lmtt, pd, pde, vfid);

	pd->entries[vfid] = pt;

	if (pt->level != 0) {
		err = __lmtt_alloc_range(lmtt, pt, start, end);
		if (err)
			goto out_free_pt;
	}

	return 0;

out_free_pt:
	klpp_lmtt_pt_free(pt);
	return err;
}

int klpp_xe_lmtt_prepare_pages(struct xe_lmtt *lmtt, unsigned int vfid, u64 range)
{
	lmtt_assert(lmtt, lmtt->pd);
	lmtt_assert(lmtt, vfid);

	return klpp_lmtt_alloc_range(lmtt, vfid, 0, range);
}


#include "livepatch_bsc1248176.h"

#include <linux/livepatch.h>

extern typeof(__lmtt_alloc_range) __lmtt_alloc_range
	 KLP_RELOC_SYMBOL(xe, xe, __lmtt_alloc_range);
extern typeof(xe_bo_addr) xe_bo_addr KLP_RELOC_SYMBOL(xe, xe, xe_bo_addr);
extern typeof(xe_bo_create_pin_map) xe_bo_create_pin_map
	 KLP_RELOC_SYMBOL(xe, xe, xe_bo_create_pin_map);
extern typeof(xe_bo_lock) xe_bo_lock KLP_RELOC_SYMBOL(xe, xe, xe_bo_lock);
extern typeof(xe_bo_put) xe_bo_put KLP_RELOC_SYMBOL(xe, xe, xe_bo_put);
extern typeof(xe_bo_unlock) xe_bo_unlock KLP_RELOC_SYMBOL(xe, xe, xe_bo_unlock);
extern typeof(xe_bo_unpin) xe_bo_unpin KLP_RELOC_SYMBOL(xe, xe, xe_bo_unpin);
extern typeof(xe_device_assert_mem_access) xe_device_assert_mem_access
	 KLP_RELOC_SYMBOL(xe, xe, xe_device_assert_mem_access);

#endif /* IS_ENABLED(CONFIG_DRM_XE) */
