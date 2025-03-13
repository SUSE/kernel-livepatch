/*
 * livepatch_bsc1231196
 *
 * Fix for CVE-2024-46815, bsc#1231196
 *
 *  Upstream commit:
 *  b38a4815f79b ("drm/amd/display: Check num_valid_sets before accessing reader_wm_sets[]")
 *
 *  SLE12-SP5 commit:
 *  Not affected
 *
 *  SLE15-SP3 commit:
 *  Not affected
 *
 *  SLE15-SP4 and -SP5 commit:
 *  ad18f86cfc7d1fb2b1553509e651ddfd95781a03
 *
 *  SLE15-SP6 commit:
 *  22f1565e5ecf78618306e96514bcd9ad7ffc3dc3
 *
 *  SLE MICRO-6-0 commit:
 *  22f1565e5ecf78618306e96514bcd9ad7ffc3dc3
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

/* klp-ccp: from drivers/gpu/drm/amd/display/dc/os_types.h */
#include <linux/slab.h>

/* klp-ccp: from include/linux/mm.h */
#define _LINUX_MM_H

/* klp-ccp: from drivers/gpu/drm/amd/display/dc/os_types.h */
#include <linux/kref.h>
#include <linux/types.h>

/* klp-ccp: from include/linux/delay.h */
#define _LINUX_DELAY_H

/* klp-ccp: from drivers/gpu/drm/amd/display/dc/os_types.h */
#include <linux/mm.h>

#include <asm/byteorder.h>

#define dc_breakpoint()		do {} while (0)

#define ASSERT(expr) do {			\
		if (WARN_ON_ONCE(!(expr)))	\
			dc_breakpoint();	\
	} while (0)

/* klp-ccp: from drivers/gpu/drm/amd/display/dc/dc_dp_types.h */
struct dc_link_settings;

struct dpcd_vendor_signature {
	bool is_valid;

	union dpcd_ieee_vendor_signature {
		struct {
			uint8_t ieee_oui[3];/*24-bit IEEE OUI*/
			uint8_t ieee_device_id[6];/*usually 6-byte ASCII name*/
			uint8_t ieee_hw_rev;
			uint8_t ieee_fw_rev[2];
		};
		uint8_t raw[12];
	} data;
};

/* klp-ccp: from drivers/gpu/drm/amd/display/include/signal_types.h */
enum signal_type;

/* klp-ccp: from drivers/gpu/drm/amd/display/dc/dc_hw_types.h */
struct dc_cursor_attributes;

enum dc_color_space;

enum dc_color_depth;

struct dc_crtc_timing_adjust;

struct tg_color;

/* klp-ccp: from drivers/gpu/drm/amd/display/include/dal_types.h */
enum dce_version {
	DCE_VERSION_UNKNOWN = (-1),
	DCE_VERSION_6_0,
	DCE_VERSION_6_1,
	DCE_VERSION_6_4,
	DCE_VERSION_8_0,
	DCE_VERSION_8_1,
	DCE_VERSION_8_3,
	DCE_VERSION_10_0,
	DCE_VERSION_11_0,
	DCE_VERSION_11_2,
	DCE_VERSION_11_22,
	DCE_VERSION_12_0,
	DCE_VERSION_12_1,
	DCE_VERSION_MAX,
	DCN_VERSION_1_0,
	DCN_VERSION_1_01,
	DCN_VERSION_2_0,
	DCN_VERSION_2_01,
	DCN_VERSION_2_1,
	DCN_VERSION_3_0,
	DCN_VERSION_3_01,
	DCN_VERSION_3_02,
	DCN_VERSION_3_03,
	DCN_VERSION_3_1,
	DCN_VERSION_3_14,
	DCN_VERSION_3_15,
	DCN_VERSION_3_16,
	DCN_VERSION_3_2,
	DCN_VERSION_3_21,
	DCN_VERSION_3_5,
	DCN_VERSION_3_51,
	DCN_VERSION_MAX
};

/* klp-ccp: from drivers/gpu/drm/amd/display/include/grph_object_id.h */
enum clock_source_id;

/* klp-ccp: from drivers/gpu/drm/amd/display/dc/dm_cp_psp.h */
struct dc_link;

struct cp_psp_stream_config;

struct cp_psp_funcs {
	bool (*enable_assr)(void *handle, struct dc_link *link);
	void (*update_stream_config)(void *handle, struct cp_psp_stream_config *config);
};

struct cp_psp {
	void *handle;
	struct cp_psp_funcs funcs;
};

/* klp-ccp: from drivers/gpu/drm/amd/display/dc/dc_types.h */
struct dc_plane_state;
struct dc_stream_state;

struct dc_sink;

enum dce_environment {
	DCE_ENV_PRODUCTION_DRV = 0,
	/* Emulation on FPGA, in "Maximus" System.
	 * This environment enforces that *only* DC registers accessed.
	 * (access to non-DC registers will hang FPGA) */
	DCE_ENV_FPGA_MAXIMUS,
	/* Emulation on real HW or on FPGA. Used by Diagnostics, enforces
	 * requirements of Diagnostics team. */
	DCE_ENV_DIAG,
	/*
	 * Guest VM system, DC HW may exist but is not virtualized and
	 * should not be used.  SW support for VDI only.
	 */
	DCE_ENV_VIRTUAL_HW
};

enum dc_clock_type;

struct dc_clock_config;

struct hw_asic_id {
	uint32_t chip_id;
	uint32_t chip_family;
	uint32_t pci_revision_id;
	uint32_t hw_internal_rev;
	uint32_t vram_type;
	uint32_t vram_width;
	uint32_t feature_flags;
	uint32_t fake_paths_num;
	void *atombios_base_address;
};

struct dc_context {
	struct dc *dc;

	void *driver_context; /* e.g. amdgpu_device */
	struct dal_logger *logger;
	struct dc_perf_trace *perf_trace;
	void *cgs_device;

	enum dce_environment dce_environment;
	struct hw_asic_id asic_id;

	/* todo: below should probably move to dc.  to facilitate removal
	 * of AS we will store these here
	 */
	enum dce_version dce_version;
	struct dc_bios *dc_bios;
	bool created_bios;
	struct gpio_service *gpio_service;
	uint32_t dc_sink_id_count;
	uint32_t dc_stream_id_count;
	uint32_t dc_edp_id_count;
	uint64_t fbc_gpu_addr;
	struct dc_dmub_srv *dmub_srv;
	struct cp_psp cp_psp;
	uint32_t *dcn_reg_offsets;
	uint32_t *nbio_reg_offsets;
	uint32_t *clk_reg_offsets;
};

/* klp-ccp: from drivers/gpu/drm/amd/display/dc/inc/hw/hw_shared.h */
#define MAX_PIPES 6

enum controller_dp_test_pattern;

enum controller_dp_color_space;

/* klp-ccp: from drivers/gpu/drm/amd/display/include/logger_types.h */
struct dc_log_buffer_ctx;

/* klp-ccp: from drivers/gpu/drm/amd/display/include/link_service_types.h */
enum lttpr_mode {
	LTTPR_MODE_UNKNOWN,
	LTTPR_MODE_NON_LTTPR,
	LTTPR_MODE_TRANSPARENT,
	LTTPR_MODE_NON_TRANSPARENT,
};

/* klp-ccp: from drivers/gpu/drm/amd/display/dc/dm_services_types.h */
enum dm_pp_clocks_state {
	DM_PP_CLOCKS_STATE_INVALID,
	DM_PP_CLOCKS_STATE_ULTRA_LOW,
	DM_PP_CLOCKS_STATE_LOW,
	DM_PP_CLOCKS_STATE_NOMINAL,
	DM_PP_CLOCKS_STATE_PERFORMANCE,

	/* Starting from DCE11, Max 8 levels of DPM state supported. */
	DM_PP_CLOCKS_DPM_STATE_LEVEL_INVALID = DM_PP_CLOCKS_STATE_INVALID,
	DM_PP_CLOCKS_DPM_STATE_LEVEL_0,
	DM_PP_CLOCKS_DPM_STATE_LEVEL_1,
	DM_PP_CLOCKS_DPM_STATE_LEVEL_2,
	/* to be backward compatible */
	DM_PP_CLOCKS_DPM_STATE_LEVEL_3,
	DM_PP_CLOCKS_DPM_STATE_LEVEL_4,
	DM_PP_CLOCKS_DPM_STATE_LEVEL_5,
	DM_PP_CLOCKS_DPM_STATE_LEVEL_6,
	DM_PP_CLOCKS_DPM_STATE_LEVEL_7,

	DM_PP_CLOCKS_MAX_STATES
};

#define DM_PP_MAX_CLOCK_LEVELS 16

struct dm_pp_clock_levels {
	uint32_t num_levels;
	uint32_t clocks_in_khz[DM_PP_MAX_CLOCK_LEVELS];
};

/* klp-ccp: from drivers/gpu/drm/amd/display/include/logger_interface.h */
struct resource_context;
struct dc_state;

/* klp-ccp: from drivers/gpu/drm/amd/display/dc/inc/hw/timing_generator.h */
struct crtc_position;

struct timing_generator;

/* klp-ccp: from drivers/gpu/drm/amd/display/dc/inc/hw/link_encoder.h */
struct pipe_ctx;

/* klp-ccp: from drivers/gpu/drm/amd/display/dc/hwss/hw_sequencer.h */
struct dc_writeback_info;
struct dchub_init_data;
struct dc_static_screen_params;
struct resource_pool;
struct dc_phy_addr_space_config;
struct dc_virtual_addr_space_config;

struct dce_hwseq;
struct link_resource;

struct pg_block_update;

union block_sequence_params;

struct hw_sequencer_funcs {
	void (*hardware_release)(struct dc *dc);
	/* Embedded Display Related */
	void (*edp_power_control)(struct dc_link *link, bool enable);
	void (*edp_wait_for_hpd_ready)(struct dc_link *link, bool power_up);
	void (*edp_wait_for_T12)(struct dc_link *link);

	/* Pipe Programming Related */
	void (*init_hw)(struct dc *dc);
	void (*power_down_on_boot)(struct dc *dc);
	void (*enable_accelerated_mode)(struct dc *dc,
			struct dc_state *context);
	enum dc_status (*apply_ctx_to_hw)(struct dc *dc,
			struct dc_state *context);
	void (*disable_plane)(struct dc *dc, struct pipe_ctx *pipe_ctx);
	void (*disable_pixel_data)(struct dc *dc, struct pipe_ctx *pipe_ctx, bool blank);
	void (*apply_ctx_for_surface)(struct dc *dc,
			const struct dc_stream_state *stream,
			int num_planes, struct dc_state *context);
	void (*program_front_end_for_ctx)(struct dc *dc,
			struct dc_state *context);
	void (*wait_for_pending_cleared)(struct dc *dc,
			struct dc_state *context);
	void (*post_unlock_program_front_end)(struct dc *dc,
			struct dc_state *context);
	void (*update_plane_addr)(const struct dc *dc,
			struct pipe_ctx *pipe_ctx);
	void (*update_dchub)(struct dce_hwseq *hws,
			struct dchub_init_data *dh_data);
	void (*wait_for_mpcc_disconnect)(struct dc *dc,
			struct resource_pool *res_pool,
			struct pipe_ctx *pipe_ctx);
	void (*edp_backlight_control)(
			struct dc_link *link,
			bool enable);
	void (*program_triplebuffer)(const struct dc *dc,
		struct pipe_ctx *pipe_ctx, bool enableTripleBuffer);
	void (*update_pending_status)(struct pipe_ctx *pipe_ctx);
	void (*power_down)(struct dc *dc);
	void (*update_dsc_pg)(struct dc *dc, struct dc_state *context, bool safe_to_disable);

	/* Pipe Lock Related */
	void (*pipe_control_lock)(struct dc *dc,
			struct pipe_ctx *pipe, bool lock);
	void (*interdependent_update_lock)(struct dc *dc,
			struct dc_state *context, bool lock);
	void (*set_flip_control_gsl)(struct pipe_ctx *pipe_ctx,
			bool flip_immediate);
	void (*cursor_lock)(struct dc *dc, struct pipe_ctx *pipe, bool lock);

	/* Timing Related */
	void (*get_position)(struct pipe_ctx **pipe_ctx, int num_pipes,
			struct crtc_position *position);
	int (*get_vupdate_offset_from_vsync)(struct pipe_ctx *pipe_ctx);
	void (*calc_vupdate_position)(
			struct dc *dc,
			struct pipe_ctx *pipe_ctx,
			uint32_t *start_line,
			uint32_t *end_line);
	void (*enable_per_frame_crtc_position_reset)(struct dc *dc,
			int group_size, struct pipe_ctx *grouped_pipes[]);
	void (*enable_timing_synchronization)(struct dc *dc,
			int group_index, int group_size,
			struct pipe_ctx *grouped_pipes[]);
	void (*enable_vblanks_synchronization)(struct dc *dc,
			int group_index, int group_size,
			struct pipe_ctx *grouped_pipes[]);
	void (*setup_periodic_interrupt)(struct dc *dc,
			struct pipe_ctx *pipe_ctx);
	void (*set_drr)(struct pipe_ctx **pipe_ctx, int num_pipes,
			struct dc_crtc_timing_adjust adjust);
	void (*set_static_screen_control)(struct pipe_ctx **pipe_ctx,
			int num_pipes,
			const struct dc_static_screen_params *events);

	/* Stream Related */
	void (*enable_stream)(struct pipe_ctx *pipe_ctx);
	void (*disable_stream)(struct pipe_ctx *pipe_ctx);
	void (*blank_stream)(struct pipe_ctx *pipe_ctx);
	void (*unblank_stream)(struct pipe_ctx *pipe_ctx,
			struct dc_link_settings *link_settings);

	/* Bandwidth Related */
	void (*prepare_bandwidth)(struct dc *dc, struct dc_state *context);
	bool (*update_bandwidth)(struct dc *dc, struct dc_state *context);
	void (*optimize_bandwidth)(struct dc *dc, struct dc_state *context);

	/* Infopacket Related */
	void (*set_avmute)(struct pipe_ctx *pipe_ctx, bool enable);
	void (*send_immediate_sdp_message)(
			struct pipe_ctx *pipe_ctx,
			const uint8_t *custom_sdp_message,
			unsigned int sdp_message_size);
	void (*update_info_frame)(struct pipe_ctx *pipe_ctx);
	void (*set_dmdata_attributes)(struct pipe_ctx *pipe);
	void (*program_dmdata_engine)(struct pipe_ctx *pipe_ctx);
	bool (*dmdata_status_done)(struct pipe_ctx *pipe_ctx);

	/* Cursor Related */
	void (*set_cursor_position)(struct pipe_ctx *pipe);
	void (*set_cursor_attribute)(struct pipe_ctx *pipe);
	void (*set_cursor_sdr_white_level)(struct pipe_ctx *pipe);

	/* Colour Related */
	void (*program_gamut_remap)(struct pipe_ctx *pipe_ctx);
	void (*program_output_csc)(struct dc *dc, struct pipe_ctx *pipe_ctx,
			enum dc_color_space colorspace,
			uint16_t *matrix, int opp_id);

	/* VM Related */
	int (*init_sys_ctx)(struct dce_hwseq *hws,
			struct dc *dc,
			struct dc_phy_addr_space_config *pa_config);
	void (*init_vm_ctx)(struct dce_hwseq *hws,
			struct dc *dc,
			struct dc_virtual_addr_space_config *va_config,
			int vmid);

	/* Writeback Related */
	void (*update_writeback)(struct dc *dc,
			struct dc_writeback_info *wb_info,
			struct dc_state *context);
	void (*enable_writeback)(struct dc *dc,
			struct dc_writeback_info *wb_info,
			struct dc_state *context);
	void (*disable_writeback)(struct dc *dc,
			unsigned int dwb_pipe_inst);

	bool (*mmhubbub_warmup)(struct dc *dc,
			unsigned int num_dwb,
			struct dc_writeback_info *wb_info);

	/* Clock Related */
	enum dc_status (*set_clock)(struct dc *dc,
			enum dc_clock_type clock_type,
			uint32_t clk_khz, uint32_t stepping);
	void (*get_clock)(struct dc *dc, enum dc_clock_type clock_type,
			struct dc_clock_config *clock_cfg);
	void (*optimize_pwr_state)(const struct dc *dc,
			struct dc_state *context);
	void (*exit_optimized_pwr_state)(const struct dc *dc,
			struct dc_state *context);

	/* Audio Related */
	void (*enable_audio_stream)(struct pipe_ctx *pipe_ctx);
	void (*disable_audio_stream)(struct pipe_ctx *pipe_ctx);

	/* Stereo 3D Related */
	void (*setup_stereo)(struct pipe_ctx *pipe_ctx, struct dc *dc);

	/* HW State Logging Related */
	void (*log_hw_state)(struct dc *dc, struct dc_log_buffer_ctx *log_ctx);
	void (*get_hw_state)(struct dc *dc, char *pBuf,
			unsigned int bufSize, unsigned int mask);
	void (*clear_status_bits)(struct dc *dc, unsigned int mask);

	bool (*set_backlight_level)(struct pipe_ctx *pipe_ctx,
			uint32_t backlight_pwm_u16_16,
			uint32_t frame_ramp);

	void (*set_abm_immediate_disable)(struct pipe_ctx *pipe_ctx);

	void (*set_pipe)(struct pipe_ctx *pipe_ctx);

	void (*enable_dp_link_output)(struct dc_link *link,
			const struct link_resource *link_res,
			enum signal_type signal,
			enum clock_source_id clock_source,
			const struct dc_link_settings *link_settings);
	void (*enable_tmds_link_output)(struct dc_link *link,
			const struct link_resource *link_res,
			enum signal_type signal,
			enum clock_source_id clock_source,
			enum dc_color_depth color_depth,
			uint32_t pixel_clock);
	void (*enable_lvds_link_output)(struct dc_link *link,
			const struct link_resource *link_res,
			enum clock_source_id clock_source,
			uint32_t pixel_clock);
	void (*disable_link_output)(struct dc_link *link,
			const struct link_resource *link_res,
			enum signal_type signal);

	void (*get_dcc_en_bits)(struct dc *dc, int *dcc_en_bits);

	/* Idle Optimization Related */
	bool (*apply_idle_power_optimizations)(struct dc *dc, bool enable);

	bool (*does_plane_fit_in_mall)(struct dc *dc, struct dc_plane_state *plane,
			struct dc_cursor_attributes *cursor_attr);
	void (*commit_subvp_config)(struct dc *dc, struct dc_state *context);
	void (*enable_phantom_streams)(struct dc *dc, struct dc_state *context);
	void (*subvp_pipe_control_lock)(struct dc *dc,
			struct dc_state *context,
			bool lock,
			bool should_lock_all_pipes,
			struct pipe_ctx *top_pipe_to_program,
			bool subvp_prev_use);
	void (*subvp_pipe_control_lock_fast)(union block_sequence_params *params);

	void (*z10_restore)(const struct dc *dc);
	void (*z10_save_init)(struct dc *dc);
	bool (*is_abm_supported)(struct dc *dc,
			struct dc_state *context, struct dc_stream_state *stream);

	void (*set_disp_pattern_generator)(const struct dc *dc,
			struct pipe_ctx *pipe_ctx,
			enum controller_dp_test_pattern test_pattern,
			enum controller_dp_color_space color_space,
			enum dc_color_depth color_depth,
			const struct tg_color *solid_color,
			int width, int height, int offset);
	void (*blank_phantom)(struct dc *dc,
			struct timing_generator *tg,
			int width,
			int height);
	void (*update_visual_confirm_color)(struct dc *dc,
			struct pipe_ctx *pipe_ctx,
			int mpcc_id);
	void (*update_phantom_vp_position)(struct dc *dc,
			struct dc_state *context,
			struct pipe_ctx *phantom_pipe);
	void (*apply_update_flags_for_phantom)(struct pipe_ctx *phantom_pipe);

	void (*calc_blocks_to_gate)(struct dc *dc, struct dc_state *context,
		struct pg_block_update *update_state);
	void (*calc_blocks_to_ungate)(struct dc *dc, struct dc_state *context,
		struct pg_block_update *update_state);
	void (*block_power_control)(struct dc *dc,
		struct pg_block_update *update_state, bool power_on);
	void (*root_clock_control)(struct dc *dc,
		struct pg_block_update *update_state, bool power_on);
	void (*set_idle_state)(const struct dc *dc, bool allow_idle);
	uint32_t (*get_idle_state)(const struct dc *dc);
	bool (*is_pipe_topology_transition_seamless)(struct dc *dc,
			const struct dc_state *cur_ctx,
			const struct dc_state *new_ctx);
};

/* klp-ccp: from drivers/gpu/drm/amd/display/dc/inc/hw/dmcu.h */
struct dmcu_version {
	unsigned int interface_version;
	unsigned int abm_version;
	unsigned int psr_version;
	unsigned int build_version;
};

/* klp-ccp: from drivers/gpu/drm/amd/display/dc/dml/dc_features.h */
#define DC__VOLTAGE_STATES 40

#define DC__NUM_DPP__MAX 8

#define DC__NUM_CURSOR__MAX 2

/* klp-ccp: from drivers/gpu/drm/amd/display/dc/dml/display_mode_enums.h */
enum output_encoder_class {
	dm_dp = 0,
	dm_hdmi = 1,
	dm_wb = 2,
	dm_edp = 3,
	dm_dp2p0 = 5,
};
enum output_format_class {
	dm_444 = 0, dm_420 = 1, dm_n422, dm_s422
};
enum source_format_class {
	dm_444_16 = 0,
	dm_444_32 = 1,
	dm_444_64 = 2,
	dm_420_8 = 3,
	dm_420_10 = 4,
	dm_420_12 = 5,
	dm_422_8 = 6,
	dm_422_10 = 7,
	dm_444_8 = 8,
	dm_mono_8 = dm_444_8,
	dm_mono_16 = dm_444_16,
	dm_rgbe = 9,
	dm_rgbe_alpha = 10,
};

enum scan_direction_class {
	dm_horz = 0, dm_vert = 1
};
enum dm_swizzle_mode {
	dm_sw_linear = 0,
	dm_sw_256b_s = 1,
	dm_sw_256b_d = 2,
	dm_sw_SPARE_0 = 3,
	dm_sw_SPARE_1 = 4,
	dm_sw_4kb_s = 5,
	dm_sw_4kb_d = 6,
	dm_sw_SPARE_2 = 7,
	dm_sw_SPARE_3 = 8,
	dm_sw_64kb_s = 9,
	dm_sw_64kb_d = 10,
	dm_sw_SPARE_4 = 11,
	dm_sw_SPARE_5 = 12,
	dm_sw_var_s = 13,
	dm_sw_var_d = 14,
	dm_sw_SPARE_6 = 15,
	dm_sw_SPARE_7 = 16,
	dm_sw_64kb_s_t = 17,
	dm_sw_64kb_d_t = 18,
	dm_sw_SPARE_10 = 19,
	dm_sw_SPARE_11 = 20,
	dm_sw_4kb_s_x = 21,
	dm_sw_4kb_d_x = 22,
	dm_sw_SPARE_12 = 23,
	dm_sw_SPARE_13 = 24,
	dm_sw_64kb_s_x = 25,
	dm_sw_64kb_d_x = 26,
	dm_sw_64kb_r_x = 27,
	dm_sw_SPARE_15 = 28,
	dm_sw_var_s_x = 29,
	dm_sw_var_d_x = 30,
	dm_sw_var_r_x = 31,
	dm_sw_gfx7_2d_thin_l_vp,
	dm_sw_gfx7_2d_thin_gl,
};

enum clock_change_support {
	/**
	 * @dm_dram_clock_change_uninitialized: If you see this, we might have
	 * a code initialization issue
	 */
	dm_dram_clock_change_uninitialized = 0,

	/**
	 * @dm_dram_clock_change_vactive: Support DRAM switch in VActive
	 */
	dm_dram_clock_change_vactive,

	/**
	 * @dm_dram_clock_change_vblank: Support DRAM switch in VBlank
	 */
	dm_dram_clock_change_vblank,

	dm_dram_clock_change_vactive_w_mall_full_frame,
	dm_dram_clock_change_vactive_w_mall_sub_vp,
	dm_dram_clock_change_vblank_w_mall_full_frame,
	dm_dram_clock_change_vblank_w_mall_sub_vp,

	/**
	 * @dm_dram_clock_change_unsupported: Do not support DRAM switch
	 */
	dm_dram_clock_change_unsupported
};

enum mpc_combine_affinity {
	dm_mpc_always_when_possible,
	dm_mpc_reduce_voltage,
	dm_mpc_reduce_voltage_and_clocks,
	dm_mpc_never
};

enum self_refresh_affinity {
	dm_try_to_allow_self_refresh_and_mclk_switch,
	dm_allow_self_refresh_and_mclk_switch,
	dm_allow_self_refresh,
	dm_neither_self_refresh_nor_mclk_switch
};

enum dm_validation_status {
	DML_VALIDATION_OK,
	DML_FAIL_SCALE_RATIO_TAP,
	DML_FAIL_SOURCE_PIXEL_FORMAT,
	DML_FAIL_VIEWPORT_SIZE,
	DML_FAIL_TOTAL_V_ACTIVE_BW,
	DML_FAIL_DIO_SUPPORT,
	DML_FAIL_NOT_ENOUGH_DSC,
	DML_FAIL_DSC_CLK_REQUIRED,
	DML_FAIL_DSC_VALIDATION_FAILURE,
	DML_FAIL_URGENT_LATENCY,
	DML_FAIL_REORDERING_BUFFER,
	DML_FAIL_DISPCLK_DPPCLK,
	DML_FAIL_TOTAL_AVAILABLE_PIPES,
	DML_FAIL_NUM_OTG,
	DML_FAIL_WRITEBACK_MODE,
	DML_FAIL_WRITEBACK_LATENCY,
	DML_FAIL_WRITEBACK_SCALE_RATIO_TAP,
	DML_FAIL_CURSOR_SUPPORT,
	DML_FAIL_PITCH_SUPPORT,
	DML_FAIL_PTE_BUFFER_SIZE,
	DML_FAIL_HOST_VM_IMMEDIATE_FLIP,
	DML_FAIL_DSC_INPUT_BPC,
	DML_FAIL_PREFETCH_SUPPORT,
	DML_FAIL_V_RATIO_PREFETCH,
	DML_FAIL_P2I_WITH_420,
	DML_FAIL_DSC_ONLY_IF_NECESSARY_WITH_BPP,
	DML_FAIL_NOT_DSC422_NATIVE,
	DML_FAIL_ODM_COMBINE4TO1,
	DML_FAIL_ENOUGH_WRITEBACK_UNITS,
	DML_FAIL_VIEWPORT_EXCEEDS_SURFACE,
	DML_FAIL_DYNAMIC_METADATA,
	DML_FAIL_FMT_BUFFER_EXCEEDED,
};

enum writeback_config {
	dm_normal,
	dm_whole_buffer_for_single_stream_no_interleave,
	dm_whole_buffer_for_single_stream_interleave,
};

enum odm_combine_mode {
	dm_odm_combine_mode_disabled,
	dm_odm_combine_mode_2to1,
	dm_odm_combine_mode_4to1,
	dm_odm_split_mode_1to2,
	dm_odm_mode_mso_1to2,
	dm_odm_mode_mso_1to4
};

enum odm_combine_policy {
	dm_odm_combine_policy_dal,
	dm_odm_combine_policy_none,
	dm_odm_combine_policy_2to1,
	dm_odm_combine_policy_4to1,
	dm_odm_split_policy_1to2,
	dm_odm_mso_policy_1to2,
	dm_odm_mso_policy_1to4,
};

enum immediate_flip_requirement {
	dm_immediate_flip_not_required,
	dm_immediate_flip_required,
	dm_immediate_flip_opportunistic,
};

enum unbounded_requesting_policy {
	dm_unbounded_requesting,
	dm_unbounded_requesting_edp_only,
	dm_unbounded_requesting_disable
};

enum dm_rotation_angle {
	dm_rotation_0,
	dm_rotation_90,
	dm_rotation_180,
	dm_rotation_270,
	dm_rotation_0m,
	dm_rotation_90m,
	dm_rotation_180m,
	dm_rotation_270m,
};

enum dm_use_mall_for_pstate_change_mode {
	dm_use_mall_pstate_change_disable,
	dm_use_mall_pstate_change_full_frame,
	dm_use_mall_pstate_change_sub_viewport,
	dm_use_mall_pstate_change_phantom_pipe
};

enum dm_use_mall_for_static_screen_mode {
	dm_use_mall_static_screen_disable,
	dm_use_mall_static_screen_optimize,
	dm_use_mall_static_screen_enable,
};

enum dm_output_link_dp_rate {
	dm_dp_rate_na,
	dm_dp_rate_hbr,
	dm_dp_rate_hbr2,
	dm_dp_rate_hbr3,
	dm_dp_rate_uhbr10,
	dm_dp_rate_uhbr13p5,
	dm_dp_rate_uhbr20,
};

enum dm_fclock_change_support {
	dm_fclock_change_vactive,
	dm_fclock_change_vblank,
	dm_fclock_change_unsupported,
};

enum dm_prefetch_modes {
	dm_prefetch_support_uclk_fclk_and_stutter_if_possible,
	dm_prefetch_support_uclk_fclk_and_stutter,
	dm_prefetch_support_fclk_and_stutter,
	dm_prefetch_support_stutter,
	dm_prefetch_support_none,
};
enum dm_output_type {
	dm_output_type_unknown,
	dm_output_type_dp,
	dm_output_type_edp,
	dm_output_type_dp2p0,
	dm_output_type_hdmi,
	dm_output_type_hdmifrl,
};

enum dm_output_rate {
	dm_output_rate_unknown,
	dm_output_rate_dp_rate_hbr,
	dm_output_rate_dp_rate_hbr2,
	dm_output_rate_dp_rate_hbr3,
	dm_output_rate_dp_rate_uhbr10,
	dm_output_rate_dp_rate_uhbr13p5,
	dm_output_rate_dp_rate_uhbr20,
	dm_output_rate_hdmi_rate_3x3,
	dm_output_rate_hdmi_rate_6x3,
	dm_output_rate_hdmi_rate_6x4,
	dm_output_rate_hdmi_rate_8x4,
	dm_output_rate_hdmi_rate_10x4,
	dm_output_rate_hdmi_rate_12x4,
};

/* klp-ccp: from drivers/gpu/drm/amd/display/dc/dml/display_mode_structs.h */
#ifndef __DISPLAY_MODE_STRUCTS_H__

typedef struct _vcs_dpi_soc_bounding_box_st soc_bounding_box_st;
typedef struct _vcs_dpi_ip_params_st ip_params_st;
typedef struct _vcs_dpi_display_pipe_source_params_st display_pipe_source_params_st;
typedef struct _vcs_dpi_display_output_params_st display_output_params_st;
typedef struct _vcs_dpi_scaler_ratio_depth_st scaler_ratio_depth_st;
typedef struct _vcs_dpi_scaler_taps_st scaler_taps_st;
typedef struct _vcs_dpi_display_pipe_dest_params_st display_pipe_dest_params_st;
typedef struct _vcs_dpi_display_pipe_params_st display_pipe_params_st;
typedef struct _vcs_dpi_display_clocks_and_cfg_st display_clocks_and_cfg_st;
typedef struct _vcs_dpi_display_e2e_pipe_params_st display_e2e_pipe_params_st;

typedef struct _vcs_dpi_display_dlg_regs_st display_dlg_regs_st;
typedef struct _vcs_dpi_display_ttu_regs_st display_ttu_regs_st;

typedef struct _vcs_dpi_display_rq_regs_st display_rq_regs_st;

typedef struct {
	double UrgentWatermark;
	double WritebackUrgentWatermark;
	double DRAMClockChangeWatermark;
	double FCLKChangeWatermark;
	double WritebackDRAMClockChangeWatermark;
	double WritebackFCLKChangeWatermark;
	double StutterExitWatermark;
	double StutterEnterPlusExitWatermark;
	double Z8StutterExitWatermark;
	double Z8StutterEnterPlusExitWatermark;
	double USRRetrainingWatermark;
} Watermarks;

typedef struct {
	double Dppclk;
	double Dispclk;
	double PixelClock;
	double DCFClkDeepSleep;
	unsigned int DPPPerSurface;
	bool ScalerEnabled;
	enum dm_rotation_angle SourceRotation;
	unsigned int ViewportHeight;
	unsigned int ViewportHeightChroma;
	unsigned int BlockWidth256BytesY;
	unsigned int BlockHeight256BytesY;
	unsigned int BlockWidth256BytesC;
	unsigned int BlockHeight256BytesC;
	unsigned int BlockWidthY;
	unsigned int BlockHeightY;
	unsigned int BlockWidthC;
	unsigned int BlockHeightC;
	unsigned int InterlaceEnable;
	unsigned int NumberOfCursors;
	unsigned int VBlank;
	unsigned int HTotal;
	unsigned int HActive;
	bool DCCEnable;
	enum odm_combine_mode ODMMode;
	enum source_format_class SourcePixelFormat;
	enum dm_swizzle_mode SurfaceTiling;
	unsigned int BytePerPixelY;
	unsigned int BytePerPixelC;
	bool ProgressiveToInterlaceUnitInOPP;
	double VRatio;
	double VRatioChroma;
	unsigned int VTaps;
	unsigned int VTapsChroma;
	unsigned int PitchY;
	unsigned int DCCMetaPitchY;
	unsigned int PitchC;
	unsigned int DCCMetaPitchC;
	bool ViewportStationary;
	unsigned int ViewportXStart;
	unsigned int ViewportYStart;
	unsigned int ViewportXStartC;
	unsigned int ViewportYStartC;
	bool FORCE_ONE_ROW_FOR_FRAME;
	unsigned int SwathHeightY;
	unsigned int SwathHeightC;
} DmlPipe;

typedef struct {
	double UrgentLatency;
	double ExtraLatency;
	double WritebackLatency;
	double DRAMClockChangeLatency;
	double FCLKChangeLatency;
	double SRExitTime;
	double SREnterPlusExitTime;
	double SRExitZ8Time;
	double SREnterPlusExitZ8Time;
	double USRRetrainingLatency;
	double SMNLatency;
} SOCParametersList;

struct _vcs_dpi_voltage_scaling_st {
	int state;
	double dscclk_mhz;
	double dcfclk_mhz;
	double socclk_mhz;
	double phyclk_d18_mhz;
	double phyclk_d32_mhz;
	double dram_speed_mts;
	double fabricclk_mhz;
	double dispclk_mhz;
	double dram_bw_per_chan_gbps;
	double phyclk_mhz;
	double dppclk_mhz;
	double dtbclk_mhz;
	float net_bw_in_kbytes_sec;
};

struct _vcs_dpi_soc_bounding_box_st {
	struct _vcs_dpi_voltage_scaling_st clock_limits[DC__VOLTAGE_STATES];
	/**
	 * @num_states: It represents the total of Display Power Management
	 * (DPM) supported by the specific ASIC.
	 */
	unsigned int num_states;
	double sr_exit_time_us;
	double sr_enter_plus_exit_time_us;
	double sr_exit_z8_time_us;
	double sr_enter_plus_exit_z8_time_us;
	double urgent_latency_us;
	double urgent_latency_pixel_data_only_us;
	double urgent_latency_pixel_mixed_with_vm_data_us;
	double urgent_latency_vm_data_only_us;
	double usr_retraining_latency_us;
	double smn_latency_us;
	double fclk_change_latency_us;
	double mall_allocated_for_dcn_mbytes;
	double pct_ideal_fabric_bw_after_urgent;
	double pct_ideal_dram_bw_after_urgent_strobe;
	double max_avg_fabric_bw_use_normal_percent;
	double max_avg_dram_bw_use_normal_strobe_percent;
	enum dm_prefetch_modes allow_for_pstate_or_stutter_in_vblank_final;
	bool dram_clock_change_requirement_final;
	double writeback_latency_us;
	double ideal_dram_bw_after_urgent_percent;
	double pct_ideal_dram_sdp_bw_after_urgent_pixel_only; // PercentOfIdealDRAMFabricAndSDPPortBWReceivedAfterUrgLatencyPixelDataOnly
	double pct_ideal_dram_sdp_bw_after_urgent_pixel_and_vm;
	double pct_ideal_dram_sdp_bw_after_urgent_vm_only;
	double pct_ideal_sdp_bw_after_urgent;
	double max_avg_sdp_bw_use_normal_percent;
	double max_avg_dram_bw_use_normal_percent;
	unsigned int max_request_size_bytes;
	double downspread_percent;
	double dram_page_open_time_ns;
	double dram_rw_turnaround_time_ns;
	double dram_return_buffer_per_channel_bytes;
	double dram_channel_width_bytes;
	double fabric_datapath_to_dcn_data_return_bytes;
	double dcn_downspread_percent;
	double dispclk_dppclk_vco_speed_mhz;
	double dfs_vco_period_ps;
	unsigned int urgent_out_of_order_return_per_channel_pixel_only_bytes;
	unsigned int urgent_out_of_order_return_per_channel_pixel_and_vm_bytes;
	unsigned int urgent_out_of_order_return_per_channel_vm_only_bytes;
	unsigned int round_trip_ping_latency_dcfclk_cycles;
	unsigned int urgent_out_of_order_return_per_channel_bytes;
	unsigned int channel_interleave_bytes;
	unsigned int num_banks;
	unsigned int num_chans;
	unsigned int vmm_page_size_bytes;
	unsigned int hostvm_min_page_size_bytes;
	unsigned int gpuvm_min_page_size_bytes;
	double dram_clock_change_latency_us;
	double dummy_pstate_latency_us;
	double writeback_dram_clock_change_latency_us;
	unsigned int return_bus_width_bytes;
	unsigned int voltage_override;
	double xfc_bus_transport_time_us;
	double xfc_xbuf_latency_tolerance_us;
	int use_urgent_burst_bw;
	double min_dcfclk;
	bool do_urgent_latency_adjustment;
	double urgent_latency_adjustment_fabric_clock_component_us;
	double urgent_latency_adjustment_fabric_clock_reference_mhz;
	bool disable_dram_clock_change_vactive_support;
	bool allow_dram_clock_one_display_vactive;
	enum self_refresh_affinity allow_dram_self_refresh_or_dram_clock_change_in_vblank;
	double max_vratio_pre;
};

struct _vcs_dpi_ip_params_st {
	bool use_min_dcfclk;
	bool clamp_min_dcfclk;
	bool gpuvm_enable;
	bool hostvm_enable;
	bool dsc422_native_support;
	unsigned int gpuvm_max_page_table_levels;
	unsigned int hostvm_max_page_table_levels;
	unsigned int hostvm_cached_page_table_levels;
	unsigned int pte_group_size_bytes;
	unsigned int max_inter_dcn_tile_repeaters;
	unsigned int num_dsc;
	unsigned int odm_capable;
	unsigned int rob_buffer_size_kbytes;
	unsigned int det_buffer_size_kbytes;
	unsigned int min_comp_buffer_size_kbytes;
	unsigned int dpte_buffer_size_in_pte_reqs_luma;
	unsigned int dpte_buffer_size_in_pte_reqs_chroma;
	unsigned int pde_proc_buffer_size_64k_reqs;
	unsigned int dpp_output_buffer_pixels;
	unsigned int opp_output_buffer_lines;
	unsigned int pixel_chunk_size_kbytes;
	unsigned int alpha_pixel_chunk_size_kbytes;
	unsigned int min_pixel_chunk_size_bytes;
	unsigned int dcc_meta_buffer_size_bytes;
	unsigned char pte_enable;
	unsigned int pte_chunk_size_kbytes;
	unsigned int meta_chunk_size_kbytes;
	unsigned int min_meta_chunk_size_bytes;
	unsigned int writeback_chunk_size_kbytes;
	unsigned int line_buffer_size_bits;
	unsigned int max_line_buffer_lines;
	unsigned int writeback_luma_buffer_size_kbytes;
	unsigned int writeback_chroma_buffer_size_kbytes;
	unsigned int writeback_chroma_line_buffer_width_pixels;

	unsigned int writeback_interface_buffer_size_kbytes;
	unsigned int writeback_line_buffer_buffer_size;

	unsigned int writeback_10bpc420_supported;
	double writeback_max_hscl_ratio;
	double writeback_max_vscl_ratio;
	double writeback_min_hscl_ratio;
	double writeback_min_vscl_ratio;
	unsigned int maximum_dsc_bits_per_component;
	unsigned int maximum_pixels_per_line_per_dsc_unit;
	unsigned int writeback_max_hscl_taps;
	unsigned int writeback_max_vscl_taps;
	unsigned int writeback_line_buffer_luma_buffer_size;
	unsigned int writeback_line_buffer_chroma_buffer_size;

	unsigned int max_page_table_levels;
	/**
	 * @max_num_dpp: Maximum number of DPP supported in the target ASIC.
	 */
	unsigned int max_num_dpp;
	unsigned int max_num_otg;
	unsigned int cursor_chunk_size;
	unsigned int cursor_buffer_size;
	unsigned int max_num_wb;
	unsigned int max_dchub_pscl_bw_pix_per_clk;
	unsigned int max_pscl_lb_bw_pix_per_clk;
	unsigned int max_lb_vscl_bw_pix_per_clk;
	unsigned int max_vscl_hscl_bw_pix_per_clk;
	double max_hscl_ratio;
	double max_vscl_ratio;
	unsigned int hscl_mults;
	unsigned int vscl_mults;
	unsigned int max_hscl_taps;
	unsigned int max_vscl_taps;
	unsigned int xfc_supported;
	unsigned int ptoi_supported;
	unsigned int gfx7_compat_tiling_supported;

	bool odm_combine_4to1_supported;
	bool dynamic_metadata_vm_enabled;
	unsigned int max_num_hdmi_frl_outputs;

	unsigned int xfc_fill_constant_bytes;
	double dispclk_ramp_margin_percent;
	double xfc_fill_bw_overhead_percent;
	double underscan_factor;
	unsigned int min_vblank_lines;
	unsigned int dppclk_delay_subtotal;
	unsigned int dispclk_delay_subtotal;
	double dcfclk_cstate_latency;
	unsigned int dppclk_delay_scl;
	unsigned int dppclk_delay_scl_lb_only;
	unsigned int dppclk_delay_cnvc_formatter;
	unsigned int dppclk_delay_cnvc_cursor;
	unsigned int is_line_buffer_bpp_fixed;
	unsigned int line_buffer_fixed_bpp;
	unsigned int dcc_supported;
	unsigned int config_return_buffer_size_in_kbytes;
	unsigned int compressed_buffer_segment_size_in_kbytes;
	unsigned int meta_fifo_size_in_kentries;
	unsigned int zero_size_buffer_entries;
	unsigned int compbuf_reserved_space_64b;
	unsigned int compbuf_reserved_space_zs;

	unsigned int IsLineBufferBppFixed;
	unsigned int LineBufferFixedBpp;
	unsigned int can_vstartup_lines_exceed_vsync_plus_back_porch_lines_minus_one;
	unsigned int bug_forcing_LC_req_same_size_fixed;
	unsigned int number_of_cursors;
	unsigned int max_num_dp2p0_outputs;
	unsigned int max_num_dp2p0_streams;
	unsigned int VBlankNomDefaultUS;

	/* DM workarounds */
	double dsc_delay_factor_wa; // TODO: Remove after implementing root cause fix
	double min_prefetch_in_strobe_us;
};

struct _vcs_dpi_display_xfc_params_st {
	double xfc_tslv_vready_offset_us;
	double xfc_tslv_vupdate_width_us;
	double xfc_tslv_vupdate_offset_us;
	int xfc_slv_chunk_size_bytes;
};

struct _vcs_dpi_display_pipe_source_params_st {
	int source_format;
	double dcc_fraction_of_zs_req_luma;
	double dcc_fraction_of_zs_req_chroma;
	unsigned char dcc;
	unsigned int dcc_rate;
	unsigned int dcc_rate_chroma;
	unsigned char dcc_use_global;
	unsigned char vm;
	bool unbounded_req_mode;
	bool gpuvm;    // gpuvm enabled
	bool hostvm;    // hostvm enabled
	bool gpuvm_levels_force_en;
	unsigned int gpuvm_levels_force;
	bool hostvm_levels_force_en;
	unsigned int hostvm_levels_force;
	int source_scan;
	int source_rotation; // new in dml32
	unsigned int det_size_override; // use to populate DETSizeOverride in vba struct
	int sw_mode;
	int macro_tile_size;
	unsigned int surface_width_y;
	unsigned int surface_height_y;
	unsigned int surface_width_c;
	unsigned int surface_height_c;
	unsigned int viewport_width;
	unsigned int viewport_height;
	unsigned int viewport_y_y;
	unsigned int viewport_y_c;
	unsigned int viewport_width_c;
	unsigned int viewport_height_c;
	unsigned int viewport_width_max;
	unsigned int viewport_height_max;
	unsigned int viewport_x_y;
	unsigned int viewport_x_c;
	bool viewport_stationary;
	unsigned int dcc_rate_luma;
	unsigned int gpuvm_min_page_size_kbytes;
	unsigned int use_mall_for_pstate_change;
	unsigned int use_mall_for_static_screen;
	bool force_one_row_for_frame;
	bool pte_buffer_mode;
	unsigned int data_pitch;
	unsigned int data_pitch_c;
	unsigned int meta_pitch;
	unsigned int meta_pitch_c;
	unsigned int cur0_src_width;
	int cur0_bpp;
	unsigned int cur1_src_width;
	int cur1_bpp;
	int num_cursors;
	unsigned char is_hsplit;
	unsigned char dynamic_metadata_enable;
	unsigned int dynamic_metadata_lines_before_active;
	unsigned int dynamic_metadata_xmit_bytes;
	unsigned int hsplit_grp;
	unsigned char xfc_enable;
	unsigned char xfc_slave;
	unsigned char immediate_flip;
	struct _vcs_dpi_display_xfc_params_st xfc_params;
	//for vstartuplines calculation freesync
	unsigned char v_total_min;
	unsigned char v_total_max;
};
struct writeback_st {
	int wb_src_height;
	int wb_src_width;
	int wb_dst_width;
	int wb_dst_height;
	int wb_pixel_format;
	int wb_htaps_luma;
	int wb_vtaps_luma;
	int wb_htaps_chroma;
	int wb_vtaps_chroma;
	unsigned int wb_htaps;
	unsigned int wb_vtaps;
	double wb_hratio;
	double wb_vratio;
};

struct display_audio_params_st {
	unsigned int   audio_sample_rate_khz;
	int    		   audio_sample_layout;
};

struct _vcs_dpi_display_output_params_st {
	int dp_lanes;
	double output_bpp;
	unsigned int dsc_input_bpc;
	int dsc_enable;
	int wb_enable;
	int num_active_wb;
	int output_type;
	int is_virtual;
	int output_format;
	int dsc_slices;
	int max_audio_sample_rate;
	struct writeback_st wb;
	struct display_audio_params_st audio;
	unsigned int output_bpc;
	int dp_rate;
	unsigned int dp_multistream_id;
	bool dp_multistream_en;
};

struct _vcs_dpi_scaler_ratio_depth_st {
	double hscl_ratio;
	double vscl_ratio;
	double hscl_ratio_c;
	double vscl_ratio_c;
	double vinit;
	double vinit_c;
	double vinit_bot;
	double vinit_bot_c;
	int lb_depth;
	int scl_enable;
};

struct _vcs_dpi_scaler_taps_st {
	unsigned int htaps;
	unsigned int vtaps;
	unsigned int htaps_c;
	unsigned int vtaps_c;
};

struct _vcs_dpi_display_pipe_dest_params_st {
	unsigned int recout_width;
	unsigned int recout_height;
	unsigned int full_recout_width;
	unsigned int full_recout_height;
	unsigned int hblank_start;
	unsigned int hblank_end;
	unsigned int vblank_start;
	unsigned int vblank_end;
	unsigned int htotal;
	unsigned int vtotal;
	unsigned int vfront_porch;
	unsigned int vblank_nom;
	unsigned int vactive;
	unsigned int hactive;
	unsigned int vstartup_start;
	unsigned int vupdate_offset;
	unsigned int vupdate_width;
	unsigned int vready_offset;
	unsigned char interlaced;
	double pixel_rate_mhz;
	unsigned char synchronized_vblank_all_planes;
	unsigned char otg_inst;
	unsigned int odm_combine;
	unsigned char use_maximum_vstartup;
	unsigned int vtotal_max;
	unsigned int vtotal_min;
	unsigned int refresh_rate;
	bool synchronize_timings;
	unsigned int odm_combine_policy;
	bool drr_display;
};

struct _vcs_dpi_display_pipe_params_st {
	display_pipe_source_params_st src;
	display_pipe_dest_params_st dest;
	scaler_ratio_depth_st scale_ratio_depth;
	scaler_taps_st scale_taps;
};

struct _vcs_dpi_display_clocks_and_cfg_st {
	int voltage;
	double dppclk_mhz;
	double refclk_mhz;
	double dispclk_mhz;
	double dcfclk_mhz;
	double socclk_mhz;
};

struct _vcs_dpi_display_e2e_pipe_params_st {
	display_pipe_params_st pipe;
	display_output_params_st dout;
	display_clocks_and_cfg_st clks_cfg;
};

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif /*__DISPLAY_MODE_STRUCTS_H__*/

/* klp-ccp: from drivers/gpu/drm/amd/display/dc/dml/display_mode_vba.h */
struct display_mode_lib;

struct DISPCLKDPPCLKDCFCLKDeepSleepPrefetchParametersWatermarksAndPerformanceCalculation {
	unsigned int dummy_integer_array[2][DC__NUM_DPP__MAX];
	double dummy_single_array[2][DC__NUM_DPP__MAX];
	unsigned int dummy_long_array[2][DC__NUM_DPP__MAX];
	double dummy_double_array[2][DC__NUM_DPP__MAX];
	bool dummy_boolean_array[DC__NUM_DPP__MAX];
	bool dummy_boolean;
	bool dummy_boolean2;
	enum output_encoder_class dummy_output_encoder_array[DC__NUM_DPP__MAX];
	DmlPipe SurfaceParameters[DC__NUM_DPP__MAX];
	bool dummy_boolean_array2[2][DC__NUM_DPP__MAX];
	unsigned int ReorderBytes;
	unsigned int VMDataOnlyReturnBW;
	double HostVMInefficiencyFactor;
	DmlPipe myPipe;
	SOCParametersList mmSOCParameters;
	double dummy_unit_vector[DC__NUM_DPP__MAX];
	double dummy_single[2];
	enum clock_change_support dummy_dramchange_support;
	enum dm_fclock_change_support dummy_fclkchange_support;
	bool dummy_USRRetrainingSupport;
};

struct dml32_ModeSupportAndSystemConfigurationFull {
	unsigned int dummy_integer_array[22][DC__NUM_DPP__MAX];
	double dummy_double_array[2][DC__NUM_DPP__MAX];
	DmlPipe SurfParameters[DC__NUM_DPP__MAX];
	double dummy_single[5];
	double dummy_single2[5];
	SOCParametersList mSOCParameters;
	unsigned int MaximumSwathWidthSupportLuma;
	unsigned int MaximumSwathWidthSupportChroma;
	double DSTYAfterScaler[DC__NUM_DPP__MAX];
	double DSTXAfterScaler[DC__NUM_DPP__MAX];
	double MaxTotalVActiveRDBandwidth;
	bool dummy_boolean_array[2][DC__NUM_DPP__MAX];
	enum odm_combine_mode dummy_odm_mode[DC__NUM_DPP__MAX];
	DmlPipe myPipe;
	unsigned int dummy_integer[4];
	unsigned int TotalNumberOfActiveOTG;
	unsigned int TotalNumberOfActiveHDMIFRL;
	unsigned int TotalNumberOfActiveDP2p0;
	unsigned int TotalNumberOfActiveDP2p0Outputs;
	unsigned int TotalDSCUnitsRequired;
	unsigned int ReorderingBytes;
	unsigned int TotalSlots;
	unsigned int NumberOfDPPDSC;
	unsigned int NumberOfDPPNoDSC;
	unsigned int NextPrefetchModeState;
	bool MPCCombineMethodAsNeededForPStateChangeAndVoltage;
	bool MPCCombineMethodAsPossible;
	bool FullFrameMALLPStateMethod;
	bool SubViewportMALLPStateMethod;
	bool PhantomPipeMALLPStateMethod;
	bool NoChroma;
	bool TotalAvailablePipesSupportNoDSC;
	bool TotalAvailablePipesSupportDSC;
	enum odm_combine_mode ODMModeNoDSC;
	enum odm_combine_mode ODMModeDSC;
	double RequiredDISPCLKPerSurfaceNoDSC;
	double RequiredDISPCLKPerSurfaceDSC;
	double BWOfNonCombinedSurfaceOfMaximumBandwidth;
	double VMDataOnlyReturnBWPerState;
	double HostVMInefficiencyFactor;
	bool dummy_boolean[2];
};

struct dummy_vars {
	struct DISPCLKDPPCLKDCFCLKDeepSleepPrefetchParametersWatermarksAndPerformanceCalculation
	DISPCLKDPPCLKDCFCLKDeepSleepPrefetchParametersWatermarksAndPerformanceCalculation;
	struct dml32_ModeSupportAndSystemConfigurationFull dml32_ModeSupportAndSystemConfigurationFull;
};

struct vba_vars_st {
	ip_params_st ip;
	soc_bounding_box_st soc;

	int maxMpcComb;
	bool UseMaximumVStartup;

	double MaxVRatioPre;
	double WritebackDISPCLK;
	double DPPCLKUsingSingleDPPLuma;
	double DPPCLKUsingSingleDPPChroma;
	double DISPCLKWithRamping;
	double DISPCLKWithoutRamping;
	double GlobalDPPCLK;
	double DISPCLKWithRampingRoundedToDFSGranularity;
	double DISPCLKWithoutRampingRoundedToDFSGranularity;
	double MaxDispclkRoundedToDFSGranularity;
	bool DCCEnabledAnyPlane;
	double ReturnBandwidthToDCN;
	unsigned int TotalActiveDPP;
	unsigned int TotalDCCActiveDPP;
	double UrgentRoundTripAndOutOfOrderLatency;
	double StutterPeriod;
	double FrameTimeForMinFullDETBufferingTime;
	double AverageReadBandwidth;
	double TotalRowReadBandwidth;
	double PartOfBurstThatFitsInROB;
	double StutterBurstTime;
	unsigned int NextPrefetchMode;
	double NextMaxVStartup;
	double VBlankTime;
	double SmallestVBlank;
	enum dm_prefetch_modes AllowForPStateChangeOrStutterInVBlankFinal; // Mode Support only
	double DCFCLKDeepSleepPerPlane[DC__NUM_DPP__MAX];
	double EffectiveDETPlusLBLinesLuma;
	double EffectiveDETPlusLBLinesChroma;
	double UrgentLatencySupportUsLuma;
	double UrgentLatencySupportUsChroma;
	unsigned int DSCFormatFactor;

	bool DummyPStateCheck;
	bool DRAMClockChangeSupportsVActive;
	bool PrefetchModeSupported;
	bool PrefetchAndImmediateFlipSupported;
	enum self_refresh_affinity AllowDRAMSelfRefreshOrDRAMClockChangeInVblank; // Mode Support only
	double XFCRemoteSurfaceFlipDelay;
	double TInitXFill;
	double TslvChk;
	double SrcActiveDrainRate;
	bool ImmediateFlipSupported;
	enum mpc_combine_affinity WhenToDoMPCCombine; // Mode Support only

	bool PrefetchERROR;

	unsigned int VStartupLines;
	unsigned int ActiveDPPs;
	unsigned int LBLatencyHidingSourceLinesY;
	unsigned int LBLatencyHidingSourceLinesC;
	double ActiveDRAMClockChangeLatencyMarginPerState[DC__VOLTAGE_STATES][2][DC__NUM_DPP__MAX];// DML doesn't save active margin per state
	double ActiveDRAMClockChangeLatencyMargin[DC__NUM_DPP__MAX];
	double CachedActiveDRAMClockChangeLatencyMargin[DC__NUM_DPP__MAX]; // Cache in dml_get_voltage_level for debug purposes only
	double MinActiveDRAMClockChangeMargin;
	double InitFillLevel;
	double FinalFillMargin;
	double FinalFillLevel;
	double RemainingFillLevel;
	double TFinalxFill;

	//
	// SOC Bounding Box Parameters
	//
	double SRExitTime;
	double SREnterPlusExitTime;
	double UrgentLatencyPixelDataOnly;
	double UrgentLatencyPixelMixedWithVMData;
	double UrgentLatencyVMDataOnly;
	double UrgentLatency; // max of the above three
	double USRRetrainingLatency;
	double SMNLatency;
	double FCLKChangeLatency;
	unsigned int MALLAllocatedForDCNFinal;
	double MaxAveragePercentOfIdealFabricBWDisplayCanUseInNormalSystemOperation;
	double MaxAveragePercentOfIdealDRAMBWDisplayCanUseInNormalSystemOperationSTROBE;
	double PercentOfIdealDRAMBWReceivedAfterUrgLatencySTROBE;
	double WritebackLatency;
	double PercentOfIdealDRAMFabricAndSDPPortBWReceivedAfterUrgLatencyPixelDataOnly; // Mode Support
	double PercentOfIdealDRAMFabricAndSDPPortBWReceivedAfterUrgLatencyPixelMixedWithVMData; // Mode Support
	double PercentOfIdealDRAMFabricAndSDPPortBWReceivedAfterUrgLatencyVMDataOnly; // Mode Support
	double MaxAveragePercentOfIdealSDPPortBWDisplayCanUseInNormalSystemOperation; // Mode Support
	double MaxAveragePercentOfIdealDRAMBWDisplayCanUseInNormalSystemOperation; // Mode Support
	double NumberOfChannels;
	double DRAMChannelWidth;
	double FabricDatapathToDCNDataReturn;
	double ReturnBusWidth;
	double Downspreading;
	double DISPCLKDPPCLKDSCCLKDownSpreading;
	double DISPCLKDPPCLKVCOSpeed;
	double RoundTripPingLatencyCycles;
	double UrgentOutOfOrderReturnPerChannel;
	double UrgentOutOfOrderReturnPerChannelPixelDataOnly;
	double UrgentOutOfOrderReturnPerChannelPixelMixedWithVMData;
	double UrgentOutOfOrderReturnPerChannelVMDataOnly;
	unsigned int VMMPageSize;
	double DRAMClockChangeLatency;
	double XFCBusTransportTime;
	bool UseUrgentBurstBandwidth;
	double XFCXBUFLatencyTolerance;

	//
	// IP Parameters
	//
	unsigned int ROBBufferSizeInKByte;
	unsigned int DETBufferSizeInKByte[DC__NUM_DPP__MAX];
	double DETBufferSizeInTime;
	unsigned int DPPOutputBufferPixels;
	unsigned int OPPOutputBufferLines;
	unsigned int PixelChunkSizeInKByte;
	double ReturnBW;
	bool GPUVMEnable;
	bool HostVMEnable;
	unsigned int GPUVMMaxPageTableLevels;
	unsigned int HostVMMaxPageTableLevels;
	unsigned int HostVMCachedPageTableLevels;
	unsigned int OverrideGPUVMPageTableLevels;
	unsigned int OverrideHostVMPageTableLevels;
	unsigned int MetaChunkSize;
	unsigned int MinMetaChunkSizeBytes;
	unsigned int WritebackChunkSize;
	bool ODMCapability;
	unsigned int NumberOfDSC;
	unsigned int LineBufferSize;
	unsigned int MaxLineBufferLines;
	unsigned int WritebackInterfaceLumaBufferSize;
	unsigned int WritebackInterfaceChromaBufferSize;
	unsigned int WritebackChromaLineBufferWidth;
	enum writeback_config WritebackConfiguration;
	double MaxDCHUBToPSCLThroughput;
	double MaxPSCLToLBThroughput;
	unsigned int PTEBufferSizeInRequestsLuma;
	unsigned int PTEBufferSizeInRequestsChroma;
	double DISPCLKRampingMargin;
	unsigned int MaxInterDCNTileRepeaters;
	bool XFCSupported;
	double XFCSlvChunkSize;
	double XFCFillBWOverhead;
	double XFCFillConstant;
	double XFCTSlvVupdateOffset;
	double XFCTSlvVupdateWidth;
	double XFCTSlvVreadyOffset;
	double DPPCLKDelaySubtotal;
	double DPPCLKDelaySCL;
	double DPPCLKDelaySCLLBOnly;
	double DPPCLKDelayCNVCFormater;
	double DPPCLKDelayCNVCCursor;
	double DISPCLKDelaySubtotal;
	bool ProgressiveToInterlaceUnitInOPP;
	unsigned int CompressedBufferSegmentSizeInkByteFinal;
	unsigned int CompbufReservedSpace64B;
	unsigned int CompbufReservedSpaceZs;
	unsigned int LineBufferSizeFinal;
	unsigned int MaximumPixelsPerLinePerDSCUnit;
	unsigned int AlphaPixelChunkSizeInKByte;
	double MinPixelChunkSizeBytes;
	unsigned int DCCMetaBufferSizeBytes;
	// Pipe/Plane Parameters

	/** @VoltageLevel:
	 * Every ASIC has a fixed number of DPM states, and some devices might
	 * have some particular voltage configuration that does not map
	 * directly to the DPM states. This field tells how many states the
	 * target device supports; even though this field combines the DPM and
	 * special SOC voltages, it mostly matches the total number of DPM
	 * states.
	 */
	int VoltageLevel;
	double FabricClock;
	double DRAMSpeed;
	double DISPCLK;
	double SOCCLK;
	double DCFCLK;
	unsigned int MaxTotalDETInKByte;
	unsigned int MinCompressedBufferSizeInKByte;
	unsigned int NumberOfActiveSurfaces;
	bool ViewportStationary[DC__NUM_DPP__MAX];
	unsigned int RefreshRate[DC__NUM_DPP__MAX];
	double       OutputBPP[DC__NUM_DPP__MAX];
	unsigned int GPUVMMinPageSizeKBytes[DC__NUM_DPP__MAX];
	bool SynchronizeTimingsFinal;
	bool SynchronizeDRRDisplaysForUCLKPStateChangeFinal;
	bool ForceOneRowForFrame[DC__NUM_DPP__MAX];
	unsigned int ViewportXStartY[DC__NUM_DPP__MAX];
	unsigned int ViewportXStartC[DC__NUM_DPP__MAX];
	enum dm_rotation_angle SourceRotation[DC__NUM_DPP__MAX];
	bool DRRDisplay[DC__NUM_DPP__MAX];
	bool PteBufferMode[DC__NUM_DPP__MAX];
	enum dm_output_type OutputType[DC__NUM_DPP__MAX];
	enum dm_output_rate OutputRate[DC__NUM_DPP__MAX];

	unsigned int NumberOfActivePlanes;
	unsigned int NumberOfDSCSlices[DC__NUM_DPP__MAX];
	unsigned int ViewportWidth[DC__NUM_DPP__MAX];
	unsigned int ViewportHeight[DC__NUM_DPP__MAX];
	unsigned int ViewportYStartY[DC__NUM_DPP__MAX];
	unsigned int ViewportYStartC[DC__NUM_DPP__MAX];
	unsigned int PitchY[DC__NUM_DPP__MAX];
	unsigned int PitchC[DC__NUM_DPP__MAX];
	double HRatio[DC__NUM_DPP__MAX];
	double VRatio[DC__NUM_DPP__MAX];
	unsigned int htaps[DC__NUM_DPP__MAX];
	unsigned int vtaps[DC__NUM_DPP__MAX];
	unsigned int HTAPsChroma[DC__NUM_DPP__MAX];
	unsigned int VTAPsChroma[DC__NUM_DPP__MAX];
	unsigned int HTotal[DC__NUM_DPP__MAX];
	unsigned int VTotal[DC__NUM_DPP__MAX];
	unsigned int VTotal_Max[DC__NUM_DPP__MAX];
	unsigned int VTotal_Min[DC__NUM_DPP__MAX];
	int DPPPerPlane[DC__NUM_DPP__MAX];
	double PixelClock[DC__NUM_DPP__MAX];
	double PixelClockBackEnd[DC__NUM_DPP__MAX];
	bool DCCEnable[DC__NUM_DPP__MAX];
	bool FECEnable[DC__NUM_DPP__MAX];
	unsigned int DCCMetaPitchY[DC__NUM_DPP__MAX];
	unsigned int DCCMetaPitchC[DC__NUM_DPP__MAX];
	enum scan_direction_class SourceScan[DC__NUM_DPP__MAX];
	enum source_format_class SourcePixelFormat[DC__NUM_DPP__MAX];
	bool WritebackEnable[DC__NUM_DPP__MAX];
	unsigned int ActiveWritebacksPerPlane[DC__NUM_DPP__MAX];
	double WritebackDestinationWidth[DC__NUM_DPP__MAX];
	double WritebackDestinationHeight[DC__NUM_DPP__MAX];
	double WritebackSourceHeight[DC__NUM_DPP__MAX];
	enum source_format_class WritebackPixelFormat[DC__NUM_DPP__MAX];
	unsigned int WritebackLumaHTaps[DC__NUM_DPP__MAX];
	unsigned int WritebackLumaVTaps[DC__NUM_DPP__MAX];
	unsigned int WritebackChromaHTaps[DC__NUM_DPP__MAX];
	unsigned int WritebackChromaVTaps[DC__NUM_DPP__MAX];
	double WritebackHRatio[DC__NUM_DPP__MAX];
	double WritebackVRatio[DC__NUM_DPP__MAX];
	unsigned int HActive[DC__NUM_DPP__MAX];
	unsigned int VActive[DC__NUM_DPP__MAX];
	bool Interlace[DC__NUM_DPP__MAX];
	enum dm_swizzle_mode SurfaceTiling[DC__NUM_DPP__MAX];
	unsigned int ScalerRecoutWidth[DC__NUM_DPP__MAX];
	bool DynamicMetadataEnable[DC__NUM_DPP__MAX];
	int DynamicMetadataLinesBeforeActiveRequired[DC__NUM_DPP__MAX];
	unsigned int DynamicMetadataTransmittedBytes[DC__NUM_DPP__MAX];
	double DCCRate[DC__NUM_DPP__MAX];
	double AverageDCCCompressionRate;
	enum odm_combine_mode ODMCombineEnabled[DC__NUM_DPP__MAX];
	double OutputBpp[DC__NUM_DPP__MAX];
	bool DSCEnabled[DC__NUM_DPP__MAX];
	unsigned int DSCInputBitPerComponent[DC__NUM_DPP__MAX];
	enum output_format_class OutputFormat[DC__NUM_DPP__MAX];
	enum output_encoder_class Output[DC__NUM_DPP__MAX];
	bool skip_dio_check[DC__NUM_DPP__MAX];
	unsigned int BlendingAndTiming[DC__NUM_DPP__MAX];
	bool SynchronizedVBlank;
	unsigned int NumberOfCursors[DC__NUM_DPP__MAX];
	unsigned int CursorWidth[DC__NUM_DPP__MAX][DC__NUM_CURSOR__MAX];
	unsigned int CursorBPP[DC__NUM_DPP__MAX][DC__NUM_CURSOR__MAX];
	bool XFCEnabled[DC__NUM_DPP__MAX];
	bool ScalerEnabled[DC__NUM_DPP__MAX];
	unsigned int VBlankNom[DC__NUM_DPP__MAX];
	bool DisableUnboundRequestIfCompBufReservedSpaceNeedAdjustment;

	// Intermediates/Informational
	bool ImmediateFlipSupport;
	unsigned int DETBufferSizeY[DC__NUM_DPP__MAX];
	unsigned int DETBufferSizeC[DC__NUM_DPP__MAX];
	unsigned int SwathHeightY[DC__NUM_DPP__MAX];
	unsigned int SwathHeightC[DC__NUM_DPP__MAX];
	unsigned int LBBitPerPixel[DC__NUM_DPP__MAX];
	double LastPixelOfLineExtraWatermark;
	double TotalDataReadBandwidth;
	unsigned int TotalActiveWriteback;
	unsigned int EffectiveLBLatencyHidingSourceLinesLuma;
	unsigned int EffectiveLBLatencyHidingSourceLinesChroma;
	double BandwidthAvailableForImmediateFlip;
	unsigned int PrefetchMode[DC__VOLTAGE_STATES][2];
	unsigned int PrefetchModePerState[DC__VOLTAGE_STATES][2];
	unsigned int MinPrefetchMode;
	unsigned int MaxPrefetchMode;
	bool AnyLinesForVMOrRowTooLarge;
	double MaxVStartup;
	bool IgnoreViewportPositioning;
	bool ErrorResult[DC__NUM_DPP__MAX];
	//
	// Calculated dml_ml->vba.Outputs
	//
	double DCFCLKDeepSleep;
	double UrgentWatermark;
	double UrgentExtraLatency;
	double WritebackUrgentWatermark;
	double StutterExitWatermark;
	double StutterEnterPlusExitWatermark;
	double DRAMClockChangeWatermark;
	double WritebackDRAMClockChangeWatermark;
	double StutterEfficiency;
	double StutterEfficiencyNotIncludingVBlank;
	double NonUrgentLatencyTolerance;
	double MinActiveDRAMClockChangeLatencySupported;
	double Z8StutterEfficiencyBestCase;
	unsigned int Z8NumberOfStutterBurstsPerFrameBestCase;
	double Z8StutterEfficiencyNotIncludingVBlankBestCase;
	double StutterPeriodBestCase;
	Watermarks      Watermark;
	bool DCHUBBUB_ARB_CSTATE_MAX_CAP_MODE;
	unsigned int CompBufReservedSpaceKBytes;
	unsigned int CompBufReservedSpace64B;
	unsigned int CompBufReservedSpaceZs;
	bool CompBufReservedSpaceNeedAdjustment;

	// These are the clocks calcuated by the library but they are not actually
	// used explicitly. They are fetched by tests and then possibly used. The
	// ultimate values to use are the ones specified by the parameters to DML
	double DISPCLK_calculated;
	double DPPCLK_calculated[DC__NUM_DPP__MAX];

	bool ImmediateFlipSupportedSurface[DC__NUM_DPP__MAX];

	bool Use_One_Row_For_Frame[DC__NUM_DPP__MAX];
	bool Use_One_Row_For_Frame_Flip[DC__NUM_DPP__MAX];
	unsigned int VUpdateOffsetPix[DC__NUM_DPP__MAX];
	double VUpdateWidthPix[DC__NUM_DPP__MAX];
	double VReadyOffsetPix[DC__NUM_DPP__MAX];

	unsigned int TotImmediateFlipBytes;
	double TCalc;

	display_e2e_pipe_params_st cache_pipes[DC__NUM_DPP__MAX];
	unsigned int cache_num_pipes;
	unsigned int pipe_plane[DC__NUM_DPP__MAX];

	/* vba mode support */
	/*inputs*/
	bool SupportGFX7CompatibleTilingIn32bppAnd64bpp;
	double MaxHSCLRatio;
	double MaxVSCLRatio;
	unsigned int MaxNumWriteback;
	bool WritebackLumaAndChromaScalingSupported;
	bool Cursor64BppSupport;
	double DCFCLKPerState[DC__VOLTAGE_STATES];
	double DCFCLKState[DC__VOLTAGE_STATES][2];
	double FabricClockPerState[DC__VOLTAGE_STATES];
	double SOCCLKPerState[DC__VOLTAGE_STATES];
	double PHYCLKPerState[DC__VOLTAGE_STATES];
	double DTBCLKPerState[DC__VOLTAGE_STATES];
	double MaxDppclk[DC__VOLTAGE_STATES];
	double MaxDSCCLK[DC__VOLTAGE_STATES];
	double DRAMSpeedPerState[DC__VOLTAGE_STATES];
	double MaxDispclk[DC__VOLTAGE_STATES];
	int VoltageOverrideLevel;
	double PHYCLKD32PerState[DC__VOLTAGE_STATES];

	/*outputs*/
	bool ScaleRatioAndTapsSupport;
	bool SourceFormatPixelAndScanSupport;
	double TotalBandwidthConsumedGBytePerSecond;
	bool DCCEnabledInAnyPlane;
	bool WritebackLatencySupport;
	bool WritebackModeSupport;
	bool Writeback10bpc420Supported;
	bool BandwidthSupport[DC__VOLTAGE_STATES];
	unsigned int TotalNumberOfActiveWriteback;
	double CriticalPoint;
	double ReturnBWToDCNPerState;
	bool IsErrorResult[DC__VOLTAGE_STATES][2][DC__NUM_DPP__MAX];
	bool prefetch_vm_bw_valid;
	bool prefetch_row_bw_valid;
	bool NumberOfOTGSupport;
	bool NonsupportedDSCInputBPC;
	bool WritebackScaleRatioAndTapsSupport;
	bool CursorSupport;
	bool PitchSupport;
	enum dm_validation_status ValidationStatus[DC__VOLTAGE_STATES];

	/* Mode Support Reason */
	bool P2IWith420;
	bool DSCOnlyIfNecessaryWithBPP;
	bool DSC422NativeNotSupported;
	bool LinkRateDoesNotMatchDPVersion;
	bool LinkRateForMultistreamNotIndicated;
	bool BPPForMultistreamNotIndicated;
	bool MultistreamWithHDMIOreDP;
	bool MSOOrODMSplitWithNonDPLink;
	bool NotEnoughLanesForMSO;
	bool ViewportExceedsSurface;

	bool ImmediateFlipRequiredButTheRequirementForEachSurfaceIsNotSpecified;
	bool ImmediateFlipOrHostVMAndPStateWithMALLFullFrameOrPhantomPipe;
	bool InvalidCombinationOfMALLUseForPStateAndStaticScreen;
	bool InvalidCombinationOfMALLUseForPState;

	enum dm_output_link_dp_rate OutputLinkDPRate[DC__NUM_DPP__MAX];
	double PrefetchLinesYThisState[DC__NUM_DPP__MAX];
	double PrefetchLinesCThisState[DC__NUM_DPP__MAX];
	double meta_row_bandwidth_this_state[DC__NUM_DPP__MAX];
	double dpte_row_bandwidth_this_state[DC__NUM_DPP__MAX];
	double DPTEBytesPerRowThisState[DC__NUM_DPP__MAX];
	double PDEAndMetaPTEBytesPerFrameThisState[DC__NUM_DPP__MAX];
	double MetaRowBytesThisState[DC__NUM_DPP__MAX];
	bool use_one_row_for_frame[DC__VOLTAGE_STATES][2][DC__NUM_DPP__MAX];
	bool use_one_row_for_frame_flip[DC__VOLTAGE_STATES][2][DC__NUM_DPP__MAX];
	bool use_one_row_for_frame_this_state[DC__NUM_DPP__MAX];
	bool use_one_row_for_frame_flip_this_state[DC__NUM_DPP__MAX];

	unsigned int OutputTypeAndRatePerState[DC__VOLTAGE_STATES][DC__NUM_DPP__MAX];
	double RequiredDISPCLKPerSurface[DC__VOLTAGE_STATES][2][DC__NUM_DPP__MAX];
	unsigned int MacroTileHeightY[DC__NUM_DPP__MAX];
	unsigned int MacroTileHeightC[DC__NUM_DPP__MAX];
	unsigned int MacroTileWidthY[DC__NUM_DPP__MAX];
	unsigned int MacroTileWidthC[DC__NUM_DPP__MAX];
	bool ImmediateFlipRequiredFinal;
	bool DCCProgrammingAssumesScanDirectionUnknownFinal;
	bool EnoughWritebackUnits;
	bool ODMCombine2To1SupportCheckOK[DC__VOLTAGE_STATES];
	bool NumberOfDP2p0Support;
	unsigned int MaxNumDP2p0Streams;
	unsigned int MaxNumDP2p0Outputs;
	enum dm_output_type OutputTypePerState[DC__VOLTAGE_STATES][DC__NUM_DPP__MAX];
	enum dm_output_rate OutputRatePerState[DC__VOLTAGE_STATES][DC__NUM_DPP__MAX];
	double WritebackLineBufferLumaBufferSize;
	double WritebackLineBufferChromaBufferSize;
	double WritebackMinHSCLRatio;
	double WritebackMinVSCLRatio;
	double WritebackMaxHSCLRatio;
	double WritebackMaxVSCLRatio;
	double WritebackMaxHSCLTaps;
	double WritebackMaxVSCLTaps;
	unsigned int MaxNumDPP;
	unsigned int MaxNumOTG;
	double CursorBufferSize;
	double CursorChunkSize;
	unsigned int Mode;
	double OutputLinkDPLanes[DC__NUM_DPP__MAX];
	double ForcedOutputLinkBPP[DC__NUM_DPP__MAX]; // Mode Support only
	double ImmediateFlipBW[DC__NUM_DPP__MAX];
	double MaxMaxVStartup[DC__VOLTAGE_STATES][2];

	double WritebackLumaVExtra;
	double WritebackChromaVExtra;
	double WritebackRequiredDISPCLK;
	double MaximumSwathWidthSupport;
	double MaximumSwathWidthInDETBuffer;
	double MaximumSwathWidthInLineBuffer;
	double MaxDispclkRoundedDownToDFSGranularity;
	double MaxDppclkRoundedDownToDFSGranularity;
	double PlaneRequiredDISPCLKWithoutODMCombine;
	double PlaneRequiredDISPCLKWithODMCombine;
	double PlaneRequiredDISPCLK;
	double TotalNumberOfActiveOTG;
	double FECOverhead;
	double EffectiveFECOverhead;
	double Outbpp;
	unsigned int OutbppDSC;
	double TotalDSCUnitsRequired;
	double bpp;
	unsigned int slices;
	double SwathWidthGranularityY;
	double RoundedUpMaxSwathSizeBytesY;
	double SwathWidthGranularityC;
	double RoundedUpMaxSwathSizeBytesC;
	double EffectiveDETLBLinesLuma;
	double EffectiveDETLBLinesChroma;
	double ProjectedDCFCLKDeepSleep[DC__VOLTAGE_STATES][2];
	double PDEAndMetaPTEBytesPerFrameY;
	double PDEAndMetaPTEBytesPerFrameC;
	unsigned int MetaRowBytesY;
	unsigned int MetaRowBytesC;
	unsigned int DPTEBytesPerRowC;
	unsigned int DPTEBytesPerRowY;
	double ExtraLatency;
	double TimeCalc;
	double TWait;
	double MaximumReadBandwidthWithPrefetch;
	double MaximumReadBandwidthWithoutPrefetch;
	double total_dcn_read_bw_with_flip;
	double total_dcn_read_bw_with_flip_no_urgent_burst;
	double FractionOfUrgentBandwidth;
	double FractionOfUrgentBandwidthImmediateFlip; // Mode Support debugging output

	/* ms locals */
	double IdealSDPPortBandwidthPerState[DC__VOLTAGE_STATES][2];
	unsigned int NoOfDPP[DC__VOLTAGE_STATES][2][DC__NUM_DPP__MAX];
	int NoOfDPPThisState[DC__NUM_DPP__MAX];
	enum odm_combine_mode ODMCombineEnablePerState[DC__VOLTAGE_STATES][DC__NUM_DPP__MAX];
	double SwathWidthYThisState[DC__NUM_DPP__MAX];
	unsigned int SwathHeightCPerState[DC__VOLTAGE_STATES][2][DC__NUM_DPP__MAX];
	unsigned int SwathHeightYThisState[DC__NUM_DPP__MAX];
	unsigned int SwathHeightCThisState[DC__NUM_DPP__MAX];
	double VRatioPreY[DC__VOLTAGE_STATES][2][DC__NUM_DPP__MAX];
	double VRatioPreC[DC__VOLTAGE_STATES][2][DC__NUM_DPP__MAX];
	double RequiredPrefetchPixelDataBWLuma[DC__VOLTAGE_STATES][2][DC__NUM_DPP__MAX];
	double RequiredPrefetchPixelDataBWChroma[DC__VOLTAGE_STATES][2][DC__NUM_DPP__MAX];
	double RequiredDPPCLK[DC__VOLTAGE_STATES][2][DC__NUM_DPP__MAX];
	double RequiredDPPCLKThisState[DC__NUM_DPP__MAX];
	bool PTEBufferSizeNotExceededY[DC__VOLTAGE_STATES][2][DC__NUM_DPP__MAX];
	bool PTEBufferSizeNotExceededC[DC__VOLTAGE_STATES][2][DC__NUM_DPP__MAX];
	bool BandwidthWithoutPrefetchSupported[DC__VOLTAGE_STATES][2];
	bool PrefetchSupported[DC__VOLTAGE_STATES][2];
	bool VRatioInPrefetchSupported[DC__VOLTAGE_STATES][2];
	double RequiredDISPCLK[DC__VOLTAGE_STATES][2];
	bool DISPCLK_DPPCLK_Support[DC__VOLTAGE_STATES][2];
	bool TotalAvailablePipesSupport[DC__VOLTAGE_STATES][2];
	unsigned int TotalNumberOfActiveDPP[DC__VOLTAGE_STATES][2];
	unsigned int TotalNumberOfDCCActiveDPP[DC__VOLTAGE_STATES][2];
	bool ModeSupport[DC__VOLTAGE_STATES][2];
	double ReturnBWPerState[DC__VOLTAGE_STATES][2];
	bool DIOSupport[DC__VOLTAGE_STATES];
	bool NotEnoughDSCUnits[DC__VOLTAGE_STATES];
	bool DSCCLKRequiredMoreThanSupported[DC__VOLTAGE_STATES];
	bool DTBCLKRequiredMoreThanSupported[DC__VOLTAGE_STATES];
	double UrgentRoundTripAndOutOfOrderLatencyPerState[DC__VOLTAGE_STATES];
	bool ROBSupport[DC__VOLTAGE_STATES][2];
	//based on rev 99: Dim DCCMetaBufferSizeSupport(NumberOfStates, 1) As Boolean
	bool DCCMetaBufferSizeSupport[DC__VOLTAGE_STATES][2];
	bool PTEBufferSizeNotExceeded[DC__VOLTAGE_STATES][2];
	bool TotalVerticalActiveBandwidthSupport[DC__VOLTAGE_STATES][2];
	double MaxTotalVerticalActiveAvailableBandwidth[DC__VOLTAGE_STATES][2];
	double PrefetchBW[DC__NUM_DPP__MAX];
	double PDEAndMetaPTEBytesPerFrame[DC__VOLTAGE_STATES][2][DC__NUM_DPP__MAX];
	double MetaRowBytes[DC__VOLTAGE_STATES][2][DC__NUM_DPP__MAX];
	double DPTEBytesPerRow[DC__VOLTAGE_STATES][2][DC__NUM_DPP__MAX];
	double PrefetchLinesY[DC__VOLTAGE_STATES][2][DC__NUM_DPP__MAX];
	double PrefetchLinesC[DC__VOLTAGE_STATES][2][DC__NUM_DPP__MAX];
	unsigned int MaxNumSwY[DC__NUM_DPP__MAX];
	unsigned int MaxNumSwC[DC__NUM_DPP__MAX];
	double PrefillY[DC__NUM_DPP__MAX];
	double PrefillC[DC__NUM_DPP__MAX];
	double LineTimesForPrefetch[DC__NUM_DPP__MAX];
	double LinesForMetaPTE[DC__NUM_DPP__MAX];
	double LinesForMetaAndDPTERow[DC__NUM_DPP__MAX];
	double MinDPPCLKUsingSingleDPP[DC__NUM_DPP__MAX];
	double SwathWidthYSingleDPP[DC__NUM_DPP__MAX];
	double BytePerPixelInDETY[DC__NUM_DPP__MAX];
	double BytePerPixelInDETC[DC__NUM_DPP__MAX];
	bool RequiresDSC[DC__VOLTAGE_STATES][DC__NUM_DPP__MAX];
	unsigned int NumberOfDSCSlice[DC__VOLTAGE_STATES][DC__NUM_DPP__MAX];
	double RequiresFEC[DC__VOLTAGE_STATES][DC__NUM_DPP__MAX];
	double OutputBppPerState[DC__VOLTAGE_STATES][DC__NUM_DPP__MAX];
	double DSCDelayPerState[DC__VOLTAGE_STATES][DC__NUM_DPP__MAX];
	bool ViewportSizeSupport[DC__VOLTAGE_STATES][2];
	unsigned int Read256BlockHeightY[DC__NUM_DPP__MAX];
	unsigned int Read256BlockWidthY[DC__NUM_DPP__MAX];
	unsigned int Read256BlockHeightC[DC__NUM_DPP__MAX];
	unsigned int Read256BlockWidthC[DC__NUM_DPP__MAX];
	double MaxSwathHeightY[DC__NUM_DPP__MAX];
	double MaxSwathHeightC[DC__NUM_DPP__MAX];
	double MinSwathHeightY[DC__NUM_DPP__MAX];
	double MinSwathHeightC[DC__NUM_DPP__MAX];
	double ReadBandwidthLuma[DC__NUM_DPP__MAX];
	double ReadBandwidthChroma[DC__NUM_DPP__MAX];
	double ReadBandwidth[DC__NUM_DPP__MAX];
	double WriteBandwidth[DC__NUM_DPP__MAX];
	double PSCL_FACTOR[DC__NUM_DPP__MAX];
	double PSCL_FACTOR_CHROMA[DC__NUM_DPP__MAX];
	double MaximumVStartup[DC__VOLTAGE_STATES][2][DC__NUM_DPP__MAX];
	double AlignedDCCMetaPitch[DC__NUM_DPP__MAX];
	double AlignedYPitch[DC__NUM_DPP__MAX];
	double AlignedCPitch[DC__NUM_DPP__MAX];
	double MaximumSwathWidth[DC__NUM_DPP__MAX];
	double cursor_bw[DC__NUM_DPP__MAX];
	double cursor_bw_pre[DC__NUM_DPP__MAX];
	double Tno_bw[DC__NUM_DPP__MAX];
	double prefetch_vmrow_bw[DC__NUM_DPP__MAX];
	double DestinationLinesToRequestVMInImmediateFlip[DC__NUM_DPP__MAX];
	double DestinationLinesToRequestRowInImmediateFlip[DC__NUM_DPP__MAX];
	double final_flip_bw[DC__NUM_DPP__MAX];
	bool ImmediateFlipSupportedForState[DC__VOLTAGE_STATES][2];
	double WritebackDelay[DC__VOLTAGE_STATES][DC__NUM_DPP__MAX];
	unsigned int vm_group_bytes[DC__NUM_DPP__MAX];
	unsigned int dpte_group_bytes[DC__NUM_DPP__MAX];
	unsigned int dpte_row_height[DC__NUM_DPP__MAX];
	unsigned int meta_req_height[DC__NUM_DPP__MAX];
	unsigned int meta_req_width[DC__NUM_DPP__MAX];
	unsigned int meta_row_height[DC__NUM_DPP__MAX];
	unsigned int meta_row_width[DC__NUM_DPP__MAX];
	unsigned int dpte_row_height_chroma[DC__NUM_DPP__MAX];
	unsigned int meta_req_height_chroma[DC__NUM_DPP__MAX];
	unsigned int meta_req_width_chroma[DC__NUM_DPP__MAX];
	unsigned int meta_row_height_chroma[DC__NUM_DPP__MAX];
	unsigned int meta_row_width_chroma[DC__NUM_DPP__MAX];
	bool ImmediateFlipSupportedForPipe[DC__NUM_DPP__MAX];
	double meta_row_bw[DC__NUM_DPP__MAX];
	double dpte_row_bw[DC__NUM_DPP__MAX];
	double DisplayPipeLineDeliveryTimeLuma[DC__NUM_DPP__MAX];                     // WM
	double DisplayPipeLineDeliveryTimeChroma[DC__NUM_DPP__MAX];                     // WM
	double DisplayPipeRequestDeliveryTimeLuma[DC__NUM_DPP__MAX];
	double DisplayPipeRequestDeliveryTimeChroma[DC__NUM_DPP__MAX];
	enum clock_change_support DRAMClockChangeSupport[DC__VOLTAGE_STATES][2];
	double UrgentBurstFactorCursor[DC__NUM_DPP__MAX];
	double UrgentBurstFactorCursorPre[DC__NUM_DPP__MAX];
	double UrgentBurstFactorLuma[DC__NUM_DPP__MAX];
	double UrgentBurstFactorLumaPre[DC__NUM_DPP__MAX];
	double UrgentBurstFactorChroma[DC__NUM_DPP__MAX];
	double UrgentBurstFactorChromaPre[DC__NUM_DPP__MAX];


	bool           MPCCombine[DC__VOLTAGE_STATES][2][DC__NUM_DPP__MAX];
	double         SwathWidthCSingleDPP[DC__NUM_DPP__MAX];
	double         MaximumSwathWidthInLineBufferLuma;
	double         MaximumSwathWidthInLineBufferChroma;
	double         MaximumSwathWidthLuma[DC__NUM_DPP__MAX];
	double         MaximumSwathWidthChroma[DC__NUM_DPP__MAX];
	enum odm_combine_mode odm_combine_dummy[DC__NUM_DPP__MAX];
	double         dummy1[DC__NUM_DPP__MAX];
	double         dummy2[DC__NUM_DPP__MAX];
	unsigned int   dummy3[DC__NUM_DPP__MAX];
	unsigned int   dummy4[DC__NUM_DPP__MAX];
	double         dummy5;
	double         dummy6;
	double         dummy7[DC__NUM_DPP__MAX];
	double         dummy8[DC__NUM_DPP__MAX];
	double         dummy13[DC__NUM_DPP__MAX];
	double         dummy_double_array[2][DC__NUM_DPP__MAX];
	unsigned int        dummyinteger3[DC__NUM_DPP__MAX];
	unsigned int        dummyinteger4[DC__NUM_DPP__MAX];
	unsigned int        dummyinteger5;
	unsigned int        dummyinteger6;
	unsigned int        dummyinteger7;
	unsigned int        dummyinteger8;
	unsigned int        dummyinteger9;
	unsigned int        dummyinteger10;
	unsigned int        dummyinteger11;
	unsigned int        dummy_integer_array[8][DC__NUM_DPP__MAX];

	bool           dummysinglestring;
	bool           SingleDPPViewportSizeSupportPerPlane[DC__NUM_DPP__MAX];
	double         PlaneRequiredDISPCLKWithODMCombine2To1;
	double         PlaneRequiredDISPCLKWithODMCombine4To1;
	unsigned int   TotalNumberOfSingleDPPPlanes[DC__VOLTAGE_STATES][2];
	bool           LinkDSCEnable;
	bool           ODMCombine4To1SupportCheckOK[DC__VOLTAGE_STATES];
	enum odm_combine_mode ODMCombineEnableThisState[DC__NUM_DPP__MAX];
	double   SwathWidthCThisState[DC__NUM_DPP__MAX];
	bool           ViewportSizeSupportPerPlane[DC__NUM_DPP__MAX];
	double         AlignedDCCMetaPitchY[DC__NUM_DPP__MAX];
	double         AlignedDCCMetaPitchC[DC__NUM_DPP__MAX];

	unsigned int NotEnoughUrgentLatencyHiding[DC__VOLTAGE_STATES][2];
	unsigned int NotEnoughUrgentLatencyHidingPre;
	int PTEBufferSizeInRequestsForLuma;
	int PTEBufferSizeInRequestsForChroma;

	// Missing from VBA
	int dpte_group_bytes_chroma;
	unsigned int vm_group_bytes_chroma;
	double dst_x_after_scaler;
	double dst_y_after_scaler;
	unsigned int VStartupRequiredWhenNotEnoughTimeForDynamicMetadata;

	/* perf locals*/
	double PrefetchBandwidth[DC__NUM_DPP__MAX];
	double VInitPreFillY[DC__NUM_DPP__MAX];
	double VInitPreFillC[DC__NUM_DPP__MAX];
	unsigned int MaxNumSwathY[DC__NUM_DPP__MAX];
	unsigned int MaxNumSwathC[DC__NUM_DPP__MAX];
	unsigned int VStartup[DC__NUM_DPP__MAX];
	double DSTYAfterScaler[DC__NUM_DPP__MAX];
	double DSTXAfterScaler[DC__NUM_DPP__MAX];
	bool AllowDRAMClockChangeDuringVBlank[DC__NUM_DPP__MAX];
	bool AllowDRAMSelfRefreshDuringVBlank[DC__NUM_DPP__MAX];
	double VRatioPrefetchY[DC__NUM_DPP__MAX];
	double VRatioPrefetchC[DC__NUM_DPP__MAX];
	double DestinationLinesForPrefetch[DC__NUM_DPP__MAX];
	double DestinationLinesToRequestVMInVBlank[DC__NUM_DPP__MAX];
	double DestinationLinesToRequestRowInVBlank[DC__NUM_DPP__MAX];
	double MinTTUVBlank[DC__NUM_DPP__MAX];
	double BytePerPixelDETY[DC__NUM_DPP__MAX];
	double BytePerPixelDETC[DC__NUM_DPP__MAX];
	double SwathWidthY[DC__NUM_DPP__MAX];
	double SwathWidthSingleDPPY[DC__NUM_DPP__MAX];
	double CursorRequestDeliveryTime[DC__NUM_DPP__MAX];
	double CursorRequestDeliveryTimePrefetch[DC__NUM_DPP__MAX];
	double ReadBandwidthPlaneLuma[DC__NUM_DPP__MAX];
	double ReadBandwidthPlaneChroma[DC__NUM_DPP__MAX];
	double DisplayPipeLineDeliveryTimeLumaPrefetch[DC__NUM_DPP__MAX];
	double DisplayPipeLineDeliveryTimeChromaPrefetch[DC__NUM_DPP__MAX];
	double DisplayPipeRequestDeliveryTimeLumaPrefetch[DC__NUM_DPP__MAX];
	double DisplayPipeRequestDeliveryTimeChromaPrefetch[DC__NUM_DPP__MAX];
	double PixelPTEBytesPerRow[DC__NUM_DPP__MAX];
	double PDEAndMetaPTEBytesFrame[DC__NUM_DPP__MAX];
	double MetaRowByte[DC__NUM_DPP__MAX];
	double PrefetchSourceLinesY[DC__NUM_DPP__MAX];
	double RequiredPrefetchPixDataBWLuma[DC__NUM_DPP__MAX];
	double RequiredPrefetchPixDataBWChroma[DC__NUM_DPP__MAX];
	double PrefetchSourceLinesC[DC__NUM_DPP__MAX];
	double PSCL_THROUGHPUT_LUMA[DC__NUM_DPP__MAX];
	double PSCL_THROUGHPUT_CHROMA[DC__NUM_DPP__MAX];
	double DSCCLK_calculated[DC__NUM_DPP__MAX];
	unsigned int DSCDelay[DC__NUM_DPP__MAX];
	unsigned int MaxVStartupLines[DC__NUM_DPP__MAX];
	double DPPCLKUsingSingleDPP[DC__NUM_DPP__MAX];
	double DPPCLK[DC__NUM_DPP__MAX];
	unsigned int DCCYMaxUncompressedBlock[DC__NUM_DPP__MAX];
	unsigned int DCCYMaxCompressedBlock[DC__NUM_DPP__MAX];
	unsigned int DCCYIndependent64ByteBlock[DC__NUM_DPP__MAX];
	double MaximumDCCCompressionYSurface[DC__NUM_DPP__MAX];
	unsigned int BlockHeight256BytesY[DC__NUM_DPP__MAX];
	unsigned int BlockHeight256BytesC[DC__NUM_DPP__MAX];
	unsigned int BlockWidth256BytesY[DC__NUM_DPP__MAX];
	unsigned int BlockWidth256BytesC[DC__NUM_DPP__MAX];
	double XFCSlaveVUpdateOffset[DC__NUM_DPP__MAX];
	double XFCSlaveVupdateWidth[DC__NUM_DPP__MAX];
	double XFCSlaveVReadyOffset[DC__NUM_DPP__MAX];
	double XFCTransferDelay[DC__NUM_DPP__MAX];
	double XFCPrechargeDelay[DC__NUM_DPP__MAX];
	double XFCRemoteSurfaceFlipLatency[DC__NUM_DPP__MAX];
	double XFCPrefetchMargin[DC__NUM_DPP__MAX];
	unsigned int dpte_row_width_luma_ub[DC__NUM_DPP__MAX];
	unsigned int dpte_row_width_chroma_ub[DC__NUM_DPP__MAX];
	double FullDETBufferingTimeY[DC__NUM_DPP__MAX];                     // WM
	double FullDETBufferingTimeC[DC__NUM_DPP__MAX];                     // WM
	double DST_Y_PER_PTE_ROW_NOM_L[DC__NUM_DPP__MAX];
	double DST_Y_PER_PTE_ROW_NOM_C[DC__NUM_DPP__MAX];
	double DST_Y_PER_META_ROW_NOM_L[DC__NUM_DPP__MAX];
	double TimePerMetaChunkNominal[DC__NUM_DPP__MAX];
	double TimePerMetaChunkVBlank[DC__NUM_DPP__MAX];
	double TimePerMetaChunkFlip[DC__NUM_DPP__MAX];
	unsigned int swath_width_luma_ub[DC__NUM_DPP__MAX];
	unsigned int swath_width_chroma_ub[DC__NUM_DPP__MAX];
	unsigned int PixelPTEReqWidthY[DC__NUM_DPP__MAX];
	unsigned int PixelPTEReqHeightY[DC__NUM_DPP__MAX];
	unsigned int PTERequestSizeY[DC__NUM_DPP__MAX];
	unsigned int PixelPTEReqWidthC[DC__NUM_DPP__MAX];
	unsigned int PixelPTEReqHeightC[DC__NUM_DPP__MAX];
	unsigned int PTERequestSizeC[DC__NUM_DPP__MAX];
	double time_per_pte_group_nom_luma[DC__NUM_DPP__MAX];
	double time_per_pte_group_nom_chroma[DC__NUM_DPP__MAX];
	double time_per_pte_group_vblank_luma[DC__NUM_DPP__MAX];
	double time_per_pte_group_vblank_chroma[DC__NUM_DPP__MAX];
	double time_per_pte_group_flip_luma[DC__NUM_DPP__MAX];
	double time_per_pte_group_flip_chroma[DC__NUM_DPP__MAX];
	double TimePerVMGroupVBlank[DC__NUM_DPP__MAX];
	double TimePerVMGroupFlip[DC__NUM_DPP__MAX];
	double TimePerVMRequestVBlank[DC__NUM_DPP__MAX];
	double TimePerVMRequestFlip[DC__NUM_DPP__MAX];
	unsigned int dpde0_bytes_per_frame_ub_l[DC__NUM_DPP__MAX];
	unsigned int meta_pte_bytes_per_frame_ub_l[DC__NUM_DPP__MAX];
	unsigned int dpde0_bytes_per_frame_ub_c[DC__NUM_DPP__MAX];
	unsigned int meta_pte_bytes_per_frame_ub_c[DC__NUM_DPP__MAX];
	double LinesToFinishSwathTransferStutterCriticalPlane;
	unsigned int BytePerPixelYCriticalPlane;
	double SwathWidthYCriticalPlane;
	double LinesInDETY[DC__NUM_DPP__MAX];
	double LinesInDETYRoundedDownToSwath[DC__NUM_DPP__MAX];

	double SwathWidthSingleDPPC[DC__NUM_DPP__MAX];
	double SwathWidthC[DC__NUM_DPP__MAX];
	unsigned int BytePerPixelY[DC__NUM_DPP__MAX];
	unsigned int BytePerPixelC[DC__NUM_DPP__MAX];
	unsigned int dummyinteger1;
	unsigned int dummyinteger2;
	double FinalDRAMClockChangeLatency;
	double Tdmdl_vm[DC__NUM_DPP__MAX];
	double Tdmdl[DC__NUM_DPP__MAX];
	double TSetup[DC__NUM_DPP__MAX];
	unsigned int ThisVStartup;
	bool WritebackAllowDRAMClockChangeEndPosition[DC__NUM_DPP__MAX];
	double DST_Y_PER_META_ROW_NOM_C[DC__NUM_DPP__MAX];
	double TimePerChromaMetaChunkNominal[DC__NUM_DPP__MAX];
	double TimePerChromaMetaChunkVBlank[DC__NUM_DPP__MAX];
	double TimePerChromaMetaChunkFlip[DC__NUM_DPP__MAX];
	unsigned int DCCCMaxUncompressedBlock[DC__NUM_DPP__MAX];
	unsigned int DCCCMaxCompressedBlock[DC__NUM_DPP__MAX];
	double VStartupMargin;
	bool NotEnoughTimeForDynamicMetadata[DC__NUM_DPP__MAX];

	/* Missing from VBA */
	unsigned int MaximumMaxVStartupLines;
	double FabricAndDRAMBandwidth;
	double LinesInDETLuma;
	double LinesInDETChroma;
	unsigned int ImmediateFlipBytes[DC__NUM_DPP__MAX];
	unsigned int LinesInDETC[DC__NUM_DPP__MAX];
	unsigned int LinesInDETCRoundedDownToSwath[DC__NUM_DPP__MAX];
	double UrgentLatencySupportUsPerState[DC__VOLTAGE_STATES][2][DC__NUM_DPP__MAX];
	double UrgentLatencySupportUs[DC__NUM_DPP__MAX];
	double FabricAndDRAMBandwidthPerState[DC__VOLTAGE_STATES];
	bool UrgentLatencySupport[DC__VOLTAGE_STATES][2];
	unsigned int SwathWidthYPerState[DC__VOLTAGE_STATES][2][DC__NUM_DPP__MAX];
	unsigned int SwathHeightYPerState[DC__VOLTAGE_STATES][2][DC__NUM_DPP__MAX];
	double qual_row_bw[DC__NUM_DPP__MAX];
	double prefetch_row_bw[DC__NUM_DPP__MAX];
	double prefetch_vm_bw[DC__NUM_DPP__MAX];

	double PTEGroupSize;
	unsigned int PDEProcessingBufIn64KBReqs;

	double MaxTotalVActiveRDBandwidth;
	bool DoUrgentLatencyAdjustment;
	double UrgentLatencyAdjustmentFabricClockComponent;
	double UrgentLatencyAdjustmentFabricClockReference;
	double MinUrgentLatencySupportUs;
	double MinFullDETBufferingTime;
	double AverageReadBandwidthGBytePerSecond;
	bool   FirstMainPlane;
	bool NotEnoughDETSwathFillLatencyHiding;

	unsigned int ViewportWidthChroma[DC__NUM_DPP__MAX];
	unsigned int ViewportHeightChroma[DC__NUM_DPP__MAX];
	double HRatioChroma[DC__NUM_DPP__MAX];
	double VRatioChroma[DC__NUM_DPP__MAX];
	int WritebackSourceWidth[DC__NUM_DPP__MAX];

	bool ModeIsSupported;
	bool ODMCombine4To1Supported;

	unsigned int SurfaceWidthY[DC__NUM_DPP__MAX];
	unsigned int SurfaceWidthC[DC__NUM_DPP__MAX];
	unsigned int SurfaceHeightY[DC__NUM_DPP__MAX];
	unsigned int SurfaceHeightC[DC__NUM_DPP__MAX];
	unsigned int WritebackHTaps[DC__NUM_DPP__MAX];
	unsigned int WritebackVTaps[DC__NUM_DPP__MAX];
	bool DSCEnable[DC__NUM_DPP__MAX];

	double DRAMClockChangeLatencyOverride;

	double GPUVMMinPageSize;
	double HostVMMinPageSize;

	bool   MPCCombineEnable[DC__NUM_DPP__MAX];
	unsigned int HostVMMaxNonCachedPageTableLevels;
	bool   DynamicMetadataVMEnabled;
	double       WritebackInterfaceBufferSize;
	double       WritebackLineBufferSize;

	double DCCRateLuma[DC__NUM_DPP__MAX];
	double DCCRateChroma[DC__NUM_DPP__MAX];

	double PHYCLKD18PerState[DC__VOLTAGE_STATES];

	bool WritebackSupportInterleaveAndUsingWholeBufferForASingleStream;
	bool NumberOfHDMIFRLSupport;
	unsigned int MaxNumHDMIFRLOutputs;
	int    AudioSampleRate[DC__NUM_DPP__MAX];
	int    AudioSampleLayout[DC__NUM_DPP__MAX];

	int PercentMarginOverMinimumRequiredDCFCLK;
	bool DynamicMetadataSupported[DC__VOLTAGE_STATES][2];
	enum immediate_flip_requirement ImmediateFlipRequirement[DC__NUM_DPP__MAX];
	unsigned int DETBufferSizeYThisState[DC__NUM_DPP__MAX];
	unsigned int DETBufferSizeCThisState[DC__NUM_DPP__MAX];
	bool NoUrgentLatencyHiding[DC__NUM_DPP__MAX];
	bool NoUrgentLatencyHidingPre[DC__NUM_DPP__MAX];
	int swath_width_luma_ub_this_state[DC__NUM_DPP__MAX];
	int swath_width_chroma_ub_this_state[DC__NUM_DPP__MAX];
	double UrgLatency[DC__VOLTAGE_STATES];
	double VActiveCursorBandwidth[DC__VOLTAGE_STATES][2][DC__NUM_DPP__MAX];
	double VActivePixelBandwidth[DC__VOLTAGE_STATES][2][DC__NUM_DPP__MAX];
	bool NoTimeForPrefetch[DC__VOLTAGE_STATES][2][DC__NUM_DPP__MAX];
	bool NoTimeForDynamicMetadata[DC__VOLTAGE_STATES][2][DC__NUM_DPP__MAX];
	double dpte_row_bandwidth[DC__VOLTAGE_STATES][2][DC__NUM_DPP__MAX];
	double meta_row_bandwidth[DC__VOLTAGE_STATES][2][DC__NUM_DPP__MAX];
	double DETBufferSizeYAllStates[DC__VOLTAGE_STATES][2][DC__NUM_DPP__MAX];
	double DETBufferSizeCAllStates[DC__VOLTAGE_STATES][2][DC__NUM_DPP__MAX];
	unsigned int swath_width_luma_ub_all_states[DC__VOLTAGE_STATES][2][DC__NUM_DPP__MAX];
	unsigned int swath_width_chroma_ub_all_states[DC__VOLTAGE_STATES][2][DC__NUM_DPP__MAX];
	bool NotUrgentLatencyHiding[DC__VOLTAGE_STATES][2];
	unsigned int SwathHeightYAllStates[DC__VOLTAGE_STATES][2][DC__NUM_DPP__MAX];
	unsigned int SwathHeightCAllStates[DC__VOLTAGE_STATES][2][DC__NUM_DPP__MAX];
	unsigned int SwathWidthYAllStates[DC__VOLTAGE_STATES][2][DC__NUM_DPP__MAX];
	unsigned int SwathWidthCAllStates[DC__VOLTAGE_STATES][2][DC__NUM_DPP__MAX];
	double TotalDPTERowBandwidth[DC__VOLTAGE_STATES][2];
	double TotalMetaRowBandwidth[DC__VOLTAGE_STATES][2];
	double TotalVActiveCursorBandwidth[DC__VOLTAGE_STATES][2];
	double TotalVActivePixelBandwidth[DC__VOLTAGE_STATES][2];
	double WritebackDelayTime[DC__NUM_DPP__MAX];
	unsigned int DCCYIndependentBlock[DC__NUM_DPP__MAX];
	unsigned int DCCCIndependentBlock[DC__NUM_DPP__MAX];
	unsigned int dummyinteger17;
	unsigned int dummyinteger18;
	unsigned int dummyinteger19;
	unsigned int dummyinteger20;
	unsigned int dummyinteger21;
	unsigned int dummyinteger22;
	unsigned int dummyinteger23;
	unsigned int dummyinteger24;
	unsigned int dummyinteger25;
	unsigned int dummyinteger26;
	unsigned int dummyinteger27;
	unsigned int dummyinteger28;
	unsigned int dummyinteger29;
	bool dummystring[DC__NUM_DPP__MAX];
	double BPP;
	enum odm_combine_policy ODMCombinePolicy;
	bool UseMinimumRequiredDCFCLK;
	bool ClampMinDCFCLK;
	bool AllowDramClockChangeOneDisplayVactive;

	double MaxAveragePercentOfIdealFabricAndSDPPortBWDisplayCanUseInNormalSystemOperation;
	double PercentOfIdealFabricAndSDPPortBWReceivedAfterUrgLatency;
	double PercentOfIdealDRAMBWReceivedAfterUrgLatencyPixelMixedWithVMData;
	double PercentOfIdealDRAMBWReceivedAfterUrgLatencyVMDataOnly;
	double PercentOfIdealDRAMBWReceivedAfterUrgLatencyPixelDataOnly;
	double SRExitZ8Time;
	double SREnterPlusExitZ8Time;
	double Z8StutterExitWatermark;
	double Z8StutterEnterPlusExitWatermark;
	double Z8StutterEfficiencyNotIncludingVBlank;
	double Z8StutterEfficiency;
	double DCCFractionOfZeroSizeRequestsLuma[DC__NUM_DPP__MAX];
	double DCCFractionOfZeroSizeRequestsChroma[DC__NUM_DPP__MAX];
	double UrgBurstFactorCursor[DC__NUM_DPP__MAX];
	double UrgBurstFactorLuma[DC__NUM_DPP__MAX];
	double UrgBurstFactorChroma[DC__NUM_DPP__MAX];
	double UrgBurstFactorCursorPre[DC__NUM_DPP__MAX];
	double UrgBurstFactorLumaPre[DC__NUM_DPP__MAX];
	double UrgBurstFactorChromaPre[DC__NUM_DPP__MAX];
	bool NotUrgentLatencyHidingPre[DC__NUM_DPP__MAX];
	bool LinkCapacitySupport[DC__VOLTAGE_STATES];
	bool VREADY_AT_OR_AFTER_VSYNC[DC__NUM_DPP__MAX];
	unsigned int MIN_DST_Y_NEXT_START[DC__NUM_DPP__MAX];
	unsigned int VFrontPorch[DC__NUM_DPP__MAX];
	int ConfigReturnBufferSizeInKByte;
	enum unbounded_requesting_policy UseUnboundedRequesting;
	int CompressedBufferSegmentSizeInkByte;
	int CompressedBufferSizeInkByte;
	int MetaFIFOSizeInKEntries;
	int ZeroSizeBufferEntries;
	int COMPBUF_RESERVED_SPACE_64B;
	int COMPBUF_RESERVED_SPACE_ZS;
	bool UnboundedRequestEnabled;
	bool DSC422NativeSupport;
	bool NoEnoughUrgentLatencyHiding;
	bool NoEnoughUrgentLatencyHidingPre;
	int NumberOfStutterBurstsPerFrame;
	int Z8NumberOfStutterBurstsPerFrame;
	unsigned int MaximumDSCBitsPerComponent;
	unsigned int NotEnoughUrgentLatencyHidingA[DC__VOLTAGE_STATES][2];
	double ReadBandwidthSurfaceLuma[DC__NUM_DPP__MAX];
	double ReadBandwidthSurfaceChroma[DC__NUM_DPP__MAX];
	double SurfaceRequiredDISPCLKWithoutODMCombine;
	double SurfaceRequiredDISPCLK;
	double MinActiveFCLKChangeLatencySupported;
	int MinVoltageLevel;
	int MaxVoltageLevel;
	unsigned int TotalNumberOfSingleDPPSurfaces[DC__VOLTAGE_STATES][2];
	unsigned int CompressedBufferSizeInkByteAllStates[DC__VOLTAGE_STATES][2];
	unsigned int DETBufferSizeInKByteAllStates[DC__VOLTAGE_STATES][2][DC__NUM_DPP__MAX];
	unsigned int DETBufferSizeInKByteThisState[DC__NUM_DPP__MAX];
	unsigned int SurfaceSizeInMALL[DC__NUM_DPP__MAX];
	bool ExceededMALLSize;
	bool PTE_BUFFER_MODE[DC__NUM_DPP__MAX];
	unsigned int BIGK_FRAGMENT_SIZE[DC__NUM_DPP__MAX];
	unsigned int CompressedBufferSizeInkByteThisState;
	enum dm_fclock_change_support FCLKChangeSupport[DC__VOLTAGE_STATES][2];
	bool USRRetrainingSupport[DC__VOLTAGE_STATES][2];
	enum dm_use_mall_for_pstate_change_mode UsesMALLForPStateChange[DC__NUM_DPP__MAX];
	bool UnboundedRequestEnabledAllStates[DC__VOLTAGE_STATES][2];
	bool SingleDPPViewportSizeSupportPerSurface[DC__NUM_DPP__MAX];
	enum dm_use_mall_for_static_screen_mode UseMALLForStaticScreen[DC__NUM_DPP__MAX];
	bool UnboundedRequestEnabledThisState;
	bool DRAMClockChangeRequirementFinal;
	bool FCLKChangeRequirementFinal;
	bool USRRetrainingRequiredFinal;
	unsigned int DETSizeOverride[DC__NUM_DPP__MAX];
	unsigned int nomDETInKByte;
	enum mpc_combine_affinity  MPCCombineUse[DC__NUM_DPP__MAX];
	bool MPCCombineMethodIncompatible;
	unsigned int RequiredSlots[DC__VOLTAGE_STATES][DC__NUM_DPP__MAX];
	bool ExceededMultistreamSlots[DC__VOLTAGE_STATES];
	enum odm_combine_policy ODMUse[DC__NUM_DPP__MAX];
	unsigned int OutputMultistreamId[DC__NUM_DPP__MAX];
	bool OutputMultistreamEn[DC__NUM_DPP__MAX];
	bool UsesMALLForStaticScreen[DC__NUM_DPP__MAX];
	double MaxActiveDRAMClockChangeLatencySupported[DC__NUM_DPP__MAX];
	double WritebackAllowFCLKChangeEndPosition[DC__NUM_DPP__MAX];
	bool PTEBufferSizeNotExceededPerState[DC__NUM_DPP__MAX]; // new in DML32
	bool DCCMetaBufferSizeNotExceededPerState[DC__NUM_DPP__MAX]; // new in DML32
	bool NotEnoughDSCSlices[DC__VOLTAGE_STATES];
	bool PixelsPerLinePerDSCUnitSupport[DC__VOLTAGE_STATES];
	bool DCCMetaBufferSizeNotExceeded[DC__VOLTAGE_STATES][2];
	unsigned int dpte_row_height_linear[DC__NUM_DPP__MAX];
	unsigned int dpte_row_height_linear_chroma[DC__NUM_DPP__MAX];
	unsigned int BlockHeightY[DC__NUM_DPP__MAX];
	unsigned int BlockHeightC[DC__NUM_DPP__MAX];
	unsigned int BlockWidthY[DC__NUM_DPP__MAX];
	unsigned int BlockWidthC[DC__NUM_DPP__MAX];
	unsigned int SubViewportLinesNeededInMALL[DC__NUM_DPP__MAX];
	bool VActiveBandwithSupport[DC__VOLTAGE_STATES][2];
	bool NotEnoughDETSwathFillLatencyHidingPerState[DC__VOLTAGE_STATES][2];
	struct dummy_vars dummy_vars;
};

/* klp-ccp: from drivers/gpu/drm/amd/display/dc/dml/display_mode_lib.h */
enum dml_project {
	DML_PROJECT_UNDEFINED,
	DML_PROJECT_RAVEN1,
	DML_PROJECT_NAVI10,
	DML_PROJECT_NAVI10v2,
	DML_PROJECT_DCN201,
	DML_PROJECT_DCN21,
	DML_PROJECT_DCN30,
	DML_PROJECT_DCN31,
	DML_PROJECT_DCN315,
	DML_PROJECT_DCN314,
	DML_PROJECT_DCN32,
};

struct dml_funcs {
	void (*rq_dlg_get_dlg_reg)(
			struct display_mode_lib *mode_lib,
			display_dlg_regs_st *dlg_regs,
			display_ttu_regs_st *ttu_regs,
			const display_e2e_pipe_params_st *e2e_pipe_param,
			const unsigned int num_pipes,
			const unsigned int pipe_idx,
			const bool cstate_en,
			const bool pstate_en,
			const bool vm_en,
			const bool ignore_viewport_pos,
			const bool immediate_flip_support);
	void (*rq_dlg_get_rq_reg)(
		struct display_mode_lib *mode_lib,
		display_rq_regs_st *rq_regs,
		const display_pipe_params_st *pipe_param);
	// DLG interfaces have different function parameters in DCN32.
	// Create new function pointers to address the changes
	void (*rq_dlg_get_dlg_reg_v2)(
			struct display_mode_lib *mode_lib,
			display_dlg_regs_st *dlg_regs,
			display_ttu_regs_st *ttu_regs,
			display_e2e_pipe_params_st *e2e_pipe_param,
			const unsigned int num_pipes,
			const unsigned int pipe_idx);
	void (*rq_dlg_get_rq_reg_v2)(display_rq_regs_st *rq_regs,
			struct display_mode_lib *mode_lib,
			const display_e2e_pipe_params_st *e2e_pipe_param,
			const unsigned int num_pipes,
			const unsigned int pipe_idx);
	void (*recalculate)(struct display_mode_lib *mode_lib);
	void (*validate)(struct display_mode_lib *mode_lib);
};

struct display_mode_lib {
	struct _vcs_dpi_ip_params_st ip;
	struct _vcs_dpi_soc_bounding_box_st soc;
	enum dml_project project;
	struct vba_vars_st vba;
	struct dal_logger *logger;
	struct dml_funcs funcs;
	struct _vcs_dpi_display_e2e_pipe_params_st dml_pipe_state[6];
	bool validate_max_state;
};

/* klp-ccp: from drivers/gpu/drm/amd/display/dc/dml2/dml2_wrapper.h */
#define DML2_MAX_NUM_DPM_LVL 30

struct display_stream_compressor;

struct dml2_soc_mall_info {
	// Cache line size of 0 means MALL is not enabled/present
	unsigned int cache_line_size_bytes;
	unsigned int cache_num_ways;
	unsigned int max_cab_allocation_bytes;

	unsigned int mblk_width_pixels;
	unsigned int mblk_size_bytes;
	unsigned int mblk_height_4bpe_pixels;
	unsigned int mblk_height_8bpe_pixels;
};

struct dml2_dc_callbacks {
	struct dc *dc;
	bool (*build_scaling_params)(struct pipe_ctx *pipe_ctx);
	bool (*can_support_mclk_switch_using_fw_based_vblank_stretch)(struct dc *dc, struct dc_state *context);
	bool (*acquire_secondary_pipe_for_mpc_odm)(const struct dc *dc, struct dc_state *state, struct pipe_ctx *pri_pipe, struct pipe_ctx *sec_pipe, bool odm);
	bool (*update_pipes_for_stream_with_slice_count)(
			struct dc_state *new_ctx,
			const struct dc_state *cur_ctx,
			const struct resource_pool *pool,
			const struct dc_stream_state *stream,
			int new_slice_count);
	bool (*update_pipes_for_plane_with_slice_count)(
			struct dc_state *new_ctx,
			const struct dc_state *cur_ctx,
			const struct resource_pool *pool,
			const struct dc_plane_state *plane,
			int slice_count);
	int (*get_odm_slice_index)(const struct pipe_ctx *opp_head);
	int (*get_mpc_slice_index)(const struct pipe_ctx *dpp_pipe);
	struct pipe_ctx *(*get_opp_head)(const struct pipe_ctx *pipe_ctx);
};

struct dml2_dc_svp_callbacks {
	struct dc *dc;
	bool (*build_scaling_params)(struct pipe_ctx *pipe_ctx);
	struct dc_stream_state* (*create_stream_for_sink)(struct dc_sink *dc_sink_data);
	struct dc_plane_state* (*create_plane)(struct dc *dc);
	enum dc_status (*add_stream_to_ctx)(struct dc *dc, struct dc_state *new_ctx, struct dc_stream_state *dc_stream);
	bool (*add_plane_to_context)(const struct dc *dc, struct dc_stream_state *stream, struct dc_plane_state *plane_state, struct dc_state *context);
	bool (*remove_plane_from_context)(const struct dc *dc, struct dc_stream_state *stream, struct dc_plane_state *plane_state, struct dc_state *context);
	enum dc_status (*remove_stream_from_ctx)(struct dc *dc, struct dc_state *new_ctx, struct dc_stream_state *stream);
	void (*plane_state_release)(struct dc_plane_state *plane_state);
	void (*stream_release)(struct dc_stream_state *stream);
	void (*release_dsc)(struct resource_context *res_ctx, const struct resource_pool *pool, struct display_stream_compressor **dsc);
};

struct dml2_clks_table_entry {
	unsigned int dcfclk_mhz;
	unsigned int fclk_mhz;
	unsigned int memclk_mhz;
	unsigned int socclk_mhz;
	unsigned int dtbclk_mhz;
	unsigned int dispclk_mhz;
	unsigned int dppclk_mhz;
};

struct dml2_clks_num_entries {
	unsigned int num_dcfclk_levels;
	unsigned int num_fclk_levels;
	unsigned int num_memclk_levels;
	unsigned int num_socclk_levels;
	unsigned int num_dtbclk_levels;
	unsigned int num_dispclk_levels;
	unsigned int num_dppclk_levels;
};

struct dml2_clks_limit_table {
	struct dml2_clks_table_entry clk_entries[DML2_MAX_NUM_DPM_LVL];
	struct dml2_clks_num_entries num_entries_per_clk;
	unsigned int num_states;
};

struct dml2_soc_bbox_overrides {
	double xtalclk_mhz;
	double dchub_refclk_mhz;
	double dprefclk_mhz;
	double disp_pll_vco_speed_mhz;
	double urgent_latency_us;
	double sr_exit_latency_us;
	double sr_enter_plus_exit_latency_us;
	double sr_exit_z8_time_us;
	double sr_enter_plus_exit_z8_time_us;
	double dram_clock_change_latency_us;
	double fclk_change_latency_us;
	unsigned int dram_num_chan;
	unsigned int dram_chanel_width_bytes;
	struct dml2_clks_limit_table clks_table;
};

struct dml2_configuration_options {
	int dcn_pipe_count;
	bool use_native_pstate_optimization;
	bool enable_windowed_mpo_odm;
	bool use_native_soc_bb_construction;
	bool skip_hw_state_mapping;
	bool optimize_odm_4to1;
	bool minimize_dispclk_using_odm;
	bool override_det_buffer_size_kbytes;
	struct dml2_dc_callbacks callbacks;
	struct {
		bool force_disable_subvp;
		bool force_enable_subvp;
		unsigned int subvp_fw_processing_delay_us;
		unsigned int subvp_pstate_allow_width_us;
		unsigned int subvp_prefetch_end_to_mall_start_us;
		unsigned int subvp_swath_height_margin_lines;
		struct dml2_dc_svp_callbacks callbacks;
	} svp_pstate;
	struct dml2_soc_mall_info mall_cfg;
	struct dml2_soc_bbox_overrides bbox_overrides;
	unsigned int max_segments_per_hubp;
	unsigned int det_segment_size;
	bool map_dc_pipes_with_callbacks;
};

/* klp-ccp: from drivers/gpu/drm/amd/display/dc/dc.h */
#define MAX_PLANES 6

struct dc_versions {
	const char *dc_ver;
	struct dmcu_version dmcu_version;
};

enum dp_protocol_version {
	DP_VERSION_1_4 = 0,
	DP_VERSION_2_1,
	DP_VERSION_UNKNOWN,
};

enum dc_plane_type {
	DC_PLANE_TYPE_INVALID,
	DC_PLANE_TYPE_DCE_RGB,
	DC_PLANE_TYPE_DCE_UNDERLAY,
	DC_PLANE_TYPE_DCN_UNIVERSAL,
};

enum det_size {
	DET_SIZE_DEFAULT = 0,
	DET_SIZE_192KB = 3,
	DET_SIZE_256KB = 4,
	DET_SIZE_320KB = 5,
	DET_SIZE_384KB = 6
};

struct dc_plane_cap {
	enum dc_plane_type type;
	uint32_t per_pixel_alpha : 1;
	struct {
		uint32_t argb8888 : 1;
		uint32_t nv12 : 1;
		uint32_t fp16 : 1;
		uint32_t p010 : 1;
		uint32_t ayuv : 1;
	} pixel_format_support;
	// max upscaling factor x1000
	// upscaling factors are always >= 1
	// for example, 1080p -> 8K is 4.0, or 4000 raw value
	struct {
		uint32_t argb8888;
		uint32_t nv12;
		uint32_t fp16;
	} max_upscale_factor;
	// max downscale factor x1000
	// downscale factors are always <= 1
	// for example, 8K -> 1080p is 0.25, or 250 raw value
	struct {
		uint32_t argb8888;
		uint32_t nv12;
		uint32_t fp16;
	} max_downscale_factor;
	// minimal width/height
	uint32_t min_width;
	uint32_t min_height;
};

struct rom_curve_caps {
	uint16_t srgb : 1;
	uint16_t bt2020 : 1;
	uint16_t gamma2_2 : 1;
	uint16_t pq : 1;
	uint16_t hlg : 1;
};

struct dpp_color_caps {
	uint16_t dcn_arch : 1;
	uint16_t input_lut_shared : 1;
	uint16_t icsc : 1;
	uint16_t dgam_ram : 1;
	uint16_t post_csc : 1;
	uint16_t gamma_corr : 1;
	uint16_t hw_3d_lut : 1;
	uint16_t ogam_ram : 1;
	uint16_t ocsc : 1;
	uint16_t dgam_rom_for_yuv : 1;
	struct rom_curve_caps dgam_rom_caps;
	struct rom_curve_caps ogam_rom_caps;
};

struct mpc_color_caps {
	uint16_t gamut_remap : 1;
	uint16_t ogam_ram : 1;
	uint16_t ocsc : 1;
	uint16_t num_3dluts : 3;
	uint16_t shared_3d_lut:1;
	struct rom_curve_caps ogam_rom_caps;
};

struct dc_color_caps {
	struct dpp_color_caps dpp;
	struct mpc_color_caps mpc;
};

struct dc_dmub_caps {
	bool psr;
	bool mclk_sw;
	bool subvp_psr;
	bool gecc_enable;
};

struct dc_caps {
	uint32_t max_streams;
	uint32_t max_links;
	uint32_t max_audios;
	uint32_t max_slave_planes;
	uint32_t max_slave_yuv_planes;
	uint32_t max_slave_rgb_planes;
	uint32_t max_planes;
	uint32_t max_downscale_ratio;
	uint32_t i2c_speed_in_khz;
	uint32_t i2c_speed_in_khz_hdcp;
	uint32_t dmdata_alloc_size;
	unsigned int max_cursor_size;
	unsigned int max_video_width;
	/*
	 * max video plane width that can be safely assumed to be always
	 * supported by single DPP pipe.
	 */
	unsigned int max_optimizable_video_width;
	unsigned int min_horizontal_blanking_period;
	int linear_pitch_alignment;
	bool dcc_const_color;
	bool dynamic_audio;
	bool is_apu;
	bool dual_link_dvi;
	bool post_blend_color_processing;
	bool force_dp_tps4_for_cp2520;
	bool disable_dp_clk_share;
	bool psp_setup_panel_mode;
	bool extended_aux_timeout_support;
	bool dmcub_support;
	bool zstate_support;
	bool ips_support;
	uint32_t num_of_internal_disp;
	enum dp_protocol_version max_dp_protocol_version;
	unsigned int mall_size_per_mem_channel;
	unsigned int mall_size_total;
	unsigned int cursor_cache_size;
	struct dc_plane_cap planes[MAX_PLANES];
	struct dc_color_caps color;
	struct dc_dmub_caps dmub_caps;
	bool dp_hpo;
	bool dp_hdmi21_pcon_support;
	bool edp_dsc_support;
	bool vbios_lttpr_aware;
	bool vbios_lttpr_enable;
	uint32_t max_otg_num;
	uint32_t max_cab_allocation_bytes;
	uint32_t cache_line_size;
	uint32_t cache_num_ways;
	uint16_t subvp_fw_processing_delay_us;
	uint8_t subvp_drr_max_vblank_margin_us;
	uint16_t subvp_prefetch_end_to_mall_start_us;
	uint8_t subvp_swath_height_margin_lines; // subvp start line must be aligned to 2 x swath height
	uint16_t subvp_pstate_allow_width_us;
	uint16_t subvp_vertical_int_margin_us;
	bool seamless_odm;
	uint32_t max_v_total;
	uint32_t max_disp_clock_khz_at_vmin;
	uint8_t subvp_drr_vblank_start_margin_us;
};

struct dc_bug_wa {
	bool no_connect_phy_config;
	bool dedcn20_305_wa;
	bool skip_clock_update;
	bool lt_early_cr_pattern;
	struct {
		uint8_t uclk : 1;
		uint8_t fclk : 1;
		uint8_t dcfclk : 1;
		uint8_t dcfclk_ds: 1;
	} clock_update_disable_mask;
};
struct dc_dcc_surface_param;

struct dc_surface_dcc_cap;

struct dc_cap_funcs {
	bool (*get_dcc_compression_cap)(const struct dc *dc,
			const struct dc_dcc_surface_param *input,
			struct dc_surface_dcc_cap *output);
	bool (*get_subvp_en)(struct dc *dc, struct dc_state *context);
};

union allow_lttpr_non_transparent_mode {
	struct {
		bool DP1_4A : 1;
		bool DP2_0 : 1;
	} bits;
	unsigned char raw;
};

struct dc_config {
	bool gpu_vm_support;
	bool disable_disp_pll_sharing;
	bool fbc_support;
	bool disable_fractional_pwm;
	bool allow_seamless_boot_optimization;
	bool seamless_boot_edp_requested;
	bool edp_not_connected;
	bool edp_no_power_sequencing;
	bool force_enum_edp;
	bool forced_clocks;
	union allow_lttpr_non_transparent_mode allow_lttpr_non_transparent_mode;
	bool multi_mon_pp_mclk_switch;
	bool disable_dmcu;
	bool enable_4to1MPC;
	bool enable_windowed_mpo_odm;
	bool forceHBR2CP2520; // Used for switching between test patterns TPS4 and CP2520
	uint32_t allow_edp_hotplug_detection;
	bool clamp_min_dcfclk;
	uint64_t vblank_alignment_dto_params;
	uint8_t  vblank_alignment_max_frame_time_diff;
	bool is_asymmetric_memory;
	bool is_single_rank_dimm;
	bool is_vmin_only_asic;
	bool use_pipe_ctx_sync_logic;
	bool ignore_dpref_ss;
	bool enable_mipi_converter_optimization;
	bool use_default_clock_table;
	bool force_bios_enable_lttpr;
	uint8_t force_bios_fixed_vs;
	int sdpif_request_limit_words_per_umc;
	bool use_old_fixed_vs_sequence;
	bool dc_mode_clk_limit_support;
	bool EnableMinDispClkODM;
	bool enable_auto_dpm_test_logs;
	unsigned int disable_ips;
};

enum visual_confirm {
	VISUAL_CONFIRM_DISABLE = 0,
	VISUAL_CONFIRM_SURFACE = 1,
	VISUAL_CONFIRM_HDR = 2,
	VISUAL_CONFIRM_MPCTREE = 4,
	VISUAL_CONFIRM_PSR = 5,
	VISUAL_CONFIRM_SWAPCHAIN = 6,
	VISUAL_CONFIRM_FAMS = 7,
	VISUAL_CONFIRM_SWIZZLE = 9,
	VISUAL_CONFIRM_REPLAY = 12,
	VISUAL_CONFIRM_SUBVP = 14,
	VISUAL_CONFIRM_MCLK_SWITCH = 16,
};

enum dml_hostvm_override_opts {
	DML_HOSTVM_NO_OVERRIDE = 0x0,
	DML_HOSTVM_OVERRIDE_FALSE = 0x1,
	DML_HOSTVM_OVERRIDE_TRUE = 0x2,
};

enum dcc_option {
	DCC_ENABLE = 0,
	DCC_DISABLE = 1,
	DCC_HALF_REQ_DISALBE = 2,
};

enum pipe_split_policy {
	/**
	 * @MPC_SPLIT_DYNAMIC: DC will automatically decide how to split the
	 * pipe in order to bring the best trade-off between performance and
	 * power consumption. This is the recommended option.
	 */
	MPC_SPLIT_DYNAMIC = 0,

	/**
	 * @MPC_SPLIT_AVOID: Avoid pipe split, which means that DC will not
	 * try any sort of split optimization.
	 */
	MPC_SPLIT_AVOID = 1,

	/**
	 * @MPC_SPLIT_AVOID_MULT_DISP: With this option, DC will only try to
	 * optimize the pipe utilization when using a single display; if the
	 * user connects to a second display, DC will avoid pipe split.
	 */
	MPC_SPLIT_AVOID_MULT_DISP = 2,
};

enum wm_report_mode {
	WM_REPORT_DEFAULT = 0,
	WM_REPORT_OVERRIDE = 1,
};
enum dtm_pstate{
	dtm_level_p0 = 0,/*highest voltage*/
	dtm_level_p1,
	dtm_level_p2,
	dtm_level_p3,
	dtm_level_p4,/*when active_display_count = 0*/
};

enum dcn_pwr_state {
	DCN_PWR_STATE_UNKNOWN = -1,
	DCN_PWR_STATE_MISSION_MODE = 0,
	DCN_PWR_STATE_LOW_POWER = 3,
};

enum dcn_zstate_support_state {
	DCN_ZSTATE_SUPPORT_UNKNOWN,
	DCN_ZSTATE_SUPPORT_ALLOW,
	DCN_ZSTATE_SUPPORT_ALLOW_Z8_ONLY,
	DCN_ZSTATE_SUPPORT_ALLOW_Z8_Z10_ONLY,
	DCN_ZSTATE_SUPPORT_ALLOW_Z10_ONLY,
	DCN_ZSTATE_SUPPORT_DISALLOW,
};

struct dc_clocks {
	int dispclk_khz;
	int actual_dispclk_khz;
	int dppclk_khz;
	int actual_dppclk_khz;
	int disp_dpp_voltage_level_khz;
	int dcfclk_khz;
	int socclk_khz;
	int dcfclk_deep_sleep_khz;
	int fclk_khz;
	int phyclk_khz;
	int dramclk_khz;
	bool p_state_change_support;
	enum dcn_zstate_support_state zstate_support;
	bool dtbclk_en;
	int ref_dtbclk_khz;
	bool fclk_p_state_change_support;
	enum dcn_pwr_state pwr_state;
	/*
	 * Elements below are not compared for the purposes of
	 * optimization required
	 */
	bool prev_p_state_change_support;
	bool fclk_prev_p_state_change_support;
	int num_ways;

	/*
	 * @fw_based_mclk_switching
	 *
	 * DC has a mechanism that leverage the variable refresh rate to switch
	 * memory clock in cases that we have a large latency to achieve the
	 * memory clock change and a short vblank window. DC has some
	 * requirements to enable this feature, and this field describes if the
	 * system support or not such a feature.
	 */
	bool fw_based_mclk_switching;
	bool fw_based_mclk_switching_shut_down;
	int prev_num_ways;
	enum dtm_pstate dtm_level;
	int max_supported_dppclk_khz;
	int max_supported_dispclk_khz;
	int bw_dppclk_khz; /*a copy of dppclk_khz*/
	int bw_dispclk_khz;
};

struct dc_bw_validation_profile {
	bool enable;

	unsigned long long total_ticks;
	unsigned long long voltage_level_ticks;
	unsigned long long watermark_ticks;
	unsigned long long rq_dlg_ticks;

	unsigned long long total_count;
	unsigned long long skip_fast_count;
	unsigned long long skip_pass_count;
	unsigned long long skip_fail_count;
};

union mem_low_power_enable_options {
	struct {
		bool vga: 1;
		bool i2c: 1;
		bool dmcu: 1;
		bool dscl: 1;
		bool cm: 1;
		bool mpc: 1;
		bool optc: 1;
		bool vpg: 1;
		bool afmt: 1;
	} bits;
	uint32_t u32All;
};

union root_clock_optimization_options {
	struct {
		bool dpp: 1;
		bool dsc: 1;
		bool hdmistream: 1;
		bool hdmichar: 1;
		bool dpstream: 1;
		bool symclk32_se: 1;
		bool symclk32_le: 1;
		bool symclk_fe: 1;
		bool physymclk: 1;
		bool dpiasymclk: 1;
		uint32_t reserved: 22;
	} bits;
	uint32_t u32All;
};

union fine_grain_clock_gating_enable_options {
	struct {
		bool dccg_global_fgcg_rep : 1; /* Global fine grain clock gating of repeaters */
		bool dchub : 1;	   /* Display controller hub */
		bool dchubbub : 1;
		bool dpp : 1;	   /* Display pipes and planes */
		bool opp : 1;	   /* Output pixel processing */
		bool optc : 1;	   /* Output pipe timing combiner */
		bool dio : 1;	   /* Display output */
		bool dwb : 1;	   /* Display writeback */
		bool mmhubbub : 1; /* Multimedia hub */
		bool dmu : 1;	   /* Display core management unit */
		bool az : 1;	   /* Azalia */
		bool dchvm : 1;
		bool dsc : 1;	   /* Display stream compression */

		uint32_t reserved : 19;
	} bits;
	uint32_t u32All;
};

union dpia_debug_options {
	struct {
		uint32_t disable_dpia:1; /* bit 0 */
		uint32_t force_non_lttpr:1; /* bit 1 */
		uint32_t extend_aux_rd_interval:1; /* bit 2 */
		uint32_t disable_mst_dsc_work_around:1; /* bit 3 */
		uint32_t enable_force_tbt3_work_around:1; /* bit 4 */
		uint32_t reserved:27;
	} bits;
	uint32_t raw;
};

union aux_wake_wa_options {
	struct {
		uint32_t enable_wa : 1;
		uint32_t use_default_timeout : 1;
		uint32_t rsvd: 14;
		uint32_t timeout_ms : 16;
	} bits;
	uint32_t raw;
};

struct dc_debug_data {
	uint32_t ltFailCount;
	uint32_t i2cErrorCount;
	uint32_t auxErrorCount;
};

struct dc_phy_addr_space_config {
	struct {
		uint64_t start_addr;
		uint64_t end_addr;
		uint64_t fb_top;
		uint64_t fb_offset;
		uint64_t fb_base;
		uint64_t agp_top;
		uint64_t agp_bot;
		uint64_t agp_base;
	} system_aperture;

	struct {
		uint64_t page_table_start_addr;
		uint64_t page_table_end_addr;
		uint64_t page_table_base_addr;
		bool base_addr_is_mc_addr;
	} gart_config;

	bool valid;
	bool is_hvm_enabled;
	uint64_t page_table_default_page_addr;
};

struct dc_bounding_box_overrides {
	int sr_exit_time_ns;
	int sr_enter_plus_exit_time_ns;
	int sr_exit_z8_time_ns;
	int sr_enter_plus_exit_z8_time_ns;
	int urgent_latency_ns;
	int percent_of_ideal_drambw;
	int dram_clock_change_latency_ns;
	int dummy_clock_change_latency_ns;
	int fclk_clock_change_latency_ns;
	/* This forces a hard min on the DCFCLK we use
	 * for DML.  Unlike the debug option for forcing
	 * DCFCLK, this override affects watermark calculations
	 */
	int min_dcfclk_mhz;
};

struct dc_debug_options {
	bool native422_support;
	bool disable_dsc;
	enum visual_confirm visual_confirm;
	int visual_confirm_rect_height;

	bool sanity_checks;
	bool max_disp_clk;
	bool surface_trace;
	bool timing_trace;
	bool clock_trace;
	bool validation_trace;
	bool bandwidth_calcs_trace;
	int max_downscale_src_width;

	/* stutter efficiency related */
	bool disable_stutter;
	bool use_max_lb;
	enum dcc_option disable_dcc;

	/*
	 * @pipe_split_policy: Define which pipe split policy is used by the
	 * display core.
	 */
	enum pipe_split_policy pipe_split_policy;
	bool force_single_disp_pipe_split;
	bool voltage_align_fclk;
	bool disable_min_fclk;

	bool disable_dfs_bypass;
	bool disable_dpp_power_gate;
	bool disable_hubp_power_gate;
	bool disable_dsc_power_gate;
	bool disable_optc_power_gate;
	bool disable_hpo_power_gate;
	int dsc_min_slice_height_override;
	int dsc_bpp_increment_div;
	bool disable_pplib_wm_range;
	enum wm_report_mode pplib_wm_report_mode;
	unsigned int min_disp_clk_khz;
	unsigned int min_dpp_clk_khz;
	unsigned int min_dram_clk_khz;
	int sr_exit_time_dpm0_ns;
	int sr_enter_plus_exit_time_dpm0_ns;
	int sr_exit_time_ns;
	int sr_enter_plus_exit_time_ns;
	int sr_exit_z8_time_ns;
	int sr_enter_plus_exit_z8_time_ns;
	int urgent_latency_ns;
	uint32_t underflow_assert_delay_us;
	int percent_of_ideal_drambw;
	int dram_clock_change_latency_ns;
	bool optimized_watermark;
	int always_scale;
	bool disable_pplib_clock_request;
	bool disable_clock_gate;
	bool disable_mem_low_power;
	bool pstate_enabled;
	bool disable_dmcu;
	bool force_abm_enable;
	bool disable_stereo_support;
	bool vsr_support;
	bool performance_trace;
	bool az_endpoint_mute_only;
	bool always_use_regamma;
	bool recovery_enabled;
	bool avoid_vbios_exec_table;
	bool scl_reset_length10;
	bool hdmi20_disable;
	bool skip_detection_link_training;
	uint32_t edid_read_retry_times;
	unsigned int force_odm_combine; //bit vector based on otg inst
	unsigned int seamless_boot_odm_combine;
	unsigned int force_odm_combine_4to1; //bit vector based on otg inst
	int minimum_z8_residency_time;
	int minimum_z10_residency_time;
	bool disable_z9_mpc;
	unsigned int force_fclk_khz;
	bool enable_tri_buf;
	bool dmub_offload_enabled;
	bool dmcub_emulation;
	bool disable_idle_power_optimizations;
	unsigned int mall_size_override;
	unsigned int mall_additional_timer_percent;
	bool mall_error_as_fatal;
	bool dmub_command_table; /* for testing only */
	struct dc_bw_validation_profile bw_val_profile;
	bool disable_fec;
	bool disable_48mhz_pwrdwn;
	/* This forces a hard min on the DCFCLK requested to SMU/PP
	 * watermarks are not affected.
	 */
	unsigned int force_min_dcfclk_mhz;
	int dwb_fi_phase;
	bool disable_timing_sync;
	bool cm_in_bypass;
	int force_clock_mode;/*every mode change.*/

	bool disable_dram_clock_change_vactive_support;
	bool validate_dml_output;
	bool enable_dmcub_surface_flip;
	bool usbc_combo_phy_reset_wa;
	bool enable_dram_clock_change_one_display_vactive;
	/* TODO - remove once tested */
	bool legacy_dp2_lt;
	bool set_mst_en_for_sst;
	bool disable_uhbr;
	bool force_dp2_lt_fallback_method;
	bool ignore_cable_id;
	union mem_low_power_enable_options enable_mem_low_power;
	union root_clock_optimization_options root_clock_optimization;
	union fine_grain_clock_gating_enable_options enable_fine_grain_clock_gating;
	bool hpo_optimization;
	bool force_vblank_alignment;

	/* Enable dmub aux for legacy ddc */
	bool enable_dmub_aux_for_legacy_ddc;
	bool disable_fams;
	bool disable_fams_gaming;
	/* FEC/PSR1 sequence enable delay in 100us */
	uint8_t fec_enable_delay_in100us;
	bool enable_driver_sequence_debug;
	enum det_size crb_alloc_policy;
	int crb_alloc_policy_min_disp_count;
	bool disable_z10;
	bool enable_z9_disable_interface;
	bool psr_skip_crtc_disable;
	union dpia_debug_options dpia_debug;
	bool disable_fixed_vs_aux_timeout_wa;
	uint32_t fixed_vs_aux_delay_config_wa;
	bool force_disable_subvp;
	bool force_subvp_mclk_switch;
	bool allow_sw_cursor_fallback;
	unsigned int force_subvp_num_ways;
	unsigned int force_mall_ss_num_ways;
	bool alloc_extra_way_for_cursor;
	uint32_t subvp_extra_lines;
	bool force_usr_allow;
	/* uses value at boot and disables switch */
	bool disable_dtb_ref_clk_switch;
	bool extended_blank_optimization;
	union aux_wake_wa_options aux_wake_wa;
	uint32_t mst_start_top_delay;
	uint8_t psr_power_use_phy_fsm;
	enum dml_hostvm_override_opts dml_hostvm_override;
	bool dml_disallow_alternate_prefetch_modes;
	bool use_legacy_soc_bb_mechanism;
	bool exit_idle_opt_for_cursor_updates;
	bool using_dml2;
	bool enable_single_display_2to1_odm_policy;
	bool enable_double_buffered_dsc_pg_support;
	bool enable_dp_dig_pixel_rate_div_policy;
	enum lttpr_mode lttpr_mode_override;
	unsigned int dsc_delay_factor_wa_x1000;
	unsigned int min_prefetch_in_strobe_ns;
	bool disable_unbounded_requesting;
	bool dig_fifo_off_in_blank;
	bool temp_mst_deallocation_sequence;
	bool override_dispclk_programming;
	bool otg_crc_db;
	bool disallow_dispclk_dppclk_ds;
	bool disable_fpo_optimizations;
	bool support_eDP1_5;
	uint32_t fpo_vactive_margin_us;
	bool disable_fpo_vactive;
	bool disable_boot_optimizations;
	bool override_odm_optimization;
	bool minimize_dispclk_using_odm;
	bool disable_subvp_high_refresh;
	bool disable_dp_plus_plus_wa;
	uint32_t fpo_vactive_min_active_margin_us;
	uint32_t fpo_vactive_max_blank_us;
	bool enable_hpo_pg_support;
	bool enable_legacy_fast_update;
	bool disable_dc_mode_overwrite;
	bool replay_skip_crtc_disabled;
	bool ignore_pg;/*do nothing, let pmfw control it*/
	bool psp_disabled_wa;
	unsigned int ips2_eval_delay_us;
	unsigned int ips2_entry_delay_us;
	bool disable_dmub_reallow_idle;
};

struct dc {
	struct dc_debug_options debug;
	struct dc_versions versions;
	struct dc_caps caps;
	struct dc_cap_funcs cap_funcs;
	struct dc_config config;
	struct dc_bounding_box_overrides bb_overrides;
	struct dc_bug_wa work_arounds;
	struct dc_context *ctx;
	struct dc_phy_addr_space_config vm_pa_config;

	uint8_t link_count;
	struct dc_link *links[MAX_PIPES * 2];
	struct link_service *link_srv;

	struct dc_state *current_state;
	struct resource_pool *res_pool;

	struct clk_mgr *clk_mgr;

	/* Display Engine Clock levels */
	struct dm_pp_clock_levels sclk_lvls;

	/* Inputs into BW and WM calculations. */
	struct bw_calcs_dceip *bw_dceip;
	struct bw_calcs_vbios *bw_vbios;
	struct dcn_soc_bounding_box *dcn_soc;
	struct dcn_ip_params *dcn_ip;
	struct display_mode_lib dml;

	/* HW functions */
	struct hw_sequencer_funcs hwss;
	struct dce_hwseq *hwseq;

	/* Require to optimize clocks and bandwidth for added/removed planes */
	bool optimized_required;
	bool wm_optimized_required;
	bool idle_optimizations_allowed;
	bool enable_c20_dtm_b0;

	/* Require to maintain clocks and bandwidth for UEFI enabled HW */

	/* FBC compressor */
	struct compressor *fbc_compressor;

	struct dc_debug_data debug_data;
	struct dpcd_vendor_signature vendor_signature;

	const char *build_id;
	struct vm_helper *vm_helper;

	uint32_t *dcn_reg_offsets;
	uint32_t *nbio_reg_offsets;
	uint32_t *clk_reg_offsets;

	/* Scratch memory */
	struct {
		struct {
			/*
			 * For matching clock_limits table in driver with table
			 * from PMFW.
			 */
			struct _vcs_dpi_voltage_scaling_st clock_limits[DC__VOLTAGE_STATES];
		} update_bw_bounding_box;
	} scratch;

	struct dml2_configuration_options dml2_options;
};

/* klp-ccp: from drivers/gpu/drm/amd/display/dc/dm_pp_smu.h */
enum pp_smu_ver {
	/*
	 * PP_SMU_INTERFACE_X should be interpreted as the interface defined
	 * starting from X, where X is some family of ASICs.  This is as
	 * opposed to interfaces used only for X.  There will be some degree
	 * of interface sharing between families of ASIcs.
	 */
	PP_SMU_UNSUPPORTED,
	PP_SMU_VER_RV,
	PP_SMU_VER_NV,
	PP_SMU_VER_RN,

	PP_SMU_VER_MAX
};

struct pp_smu {
	enum pp_smu_ver ver;
	const void *pp;

	/*
	 * interim extra handle for backwards compatibility
	 * as some existing functionality not yet implemented
	 * by ppsmu
	 */
	const void *dm;
};

enum pp_smu_status {
	PP_SMU_RESULT_UNDEFINED = 0,
	PP_SMU_RESULT_OK = 1,
	PP_SMU_RESULT_FAIL,
	PP_SMU_RESULT_UNSUPPORTED
};

#define PP_SMU_WM_SET_RANGE_CLK_UNCONSTRAINED_MIN 0x0
#define PP_SMU_WM_SET_RANGE_CLK_UNCONSTRAINED_MAX 0xFFFF

enum wm_type {
	WM_TYPE_PSTATE_CHG = 0,
	WM_TYPE_RETRAINING = 1,
};

struct pp_smu_wm_set_range {
	uint16_t min_fill_clk_mhz;
	uint16_t max_fill_clk_mhz;
	uint16_t min_drain_clk_mhz;
	uint16_t max_drain_clk_mhz;

	uint8_t wm_inst;
	uint8_t wm_type;
};

#define MAX_WATERMARK_SETS 4

struct pp_smu_wm_range_sets {
	unsigned int num_reader_wm_sets;
	struct pp_smu_wm_set_range reader_wm_sets[MAX_WATERMARK_SETS];

	unsigned int num_writer_wm_sets;
	struct pp_smu_wm_set_range writer_wm_sets[MAX_WATERMARK_SETS];
};

struct pp_smu_funcs_rv {
	struct pp_smu pp_smu;

	/* PPSMC_MSG_SetDisplayCount
	 * 0 triggers S0i2 optimization
	 */

	void (*set_display_count)(struct pp_smu *pp, int count);

	/* reader and writer WM's are sent together as part of one table*/
	/*
	 * PPSMC_MSG_SetDriverDramAddrHigh
	 * PPSMC_MSG_SetDriverDramAddrLow
	 * PPSMC_MSG_TransferTableDram2Smu
	 *
	 * */
	void (*set_wm_ranges)(struct pp_smu *pp,
			struct pp_smu_wm_range_sets *ranges);

	/* PPSMC_MSG_SetHardMinDcfclkByFreq
	 * fixed clock at requested freq, either from FCH bypass or DFS
	 */
	void (*set_hard_min_dcfclk_by_freq)(struct pp_smu *pp, int mhz);

	/* PPSMC_MSG_SetMinDeepSleepDcfclk
	 * when DF is in cstate, dcf clock is further divided down
	 * to just above given frequency
	 */
	void (*set_min_deep_sleep_dcfclk)(struct pp_smu *pp, int mhz);

	/* PPSMC_MSG_SetHardMinFclkByFreq
	 * FCLK will vary with DPM, but never below requested hard min
	 */
	void (*set_hard_min_fclk_by_freq)(struct pp_smu *pp, int mhz);

	/* PPSMC_MSG_SetHardMinSocclkByFreq
	 * Needed for DWB support
	 */
	void (*set_hard_min_socclk_by_freq)(struct pp_smu *pp, int mhz);

	/* PME w/a */
	void (*set_pme_wa_enable)(struct pp_smu *pp);
};

enum pp_smu_nv_clock_id;

struct pp_smu_nv_clock_table;

struct pp_smu_funcs_nv {
	struct pp_smu pp_smu;

	/* PPSMC_MSG_SetDisplayCount
	 * 0 triggers S0i2 optimization
	 */
	enum pp_smu_status (*set_display_count)(struct pp_smu *pp, int count);

	/* PPSMC_MSG_SetHardMinDcfclkByFreq
	 * fixed clock at requested freq, either from FCH bypass or DFS
	 */
	enum pp_smu_status (*set_hard_min_dcfclk_by_freq)(struct pp_smu *pp, int Mhz);

	/* PPSMC_MSG_SetMinDeepSleepDcfclk
	 * when DF is in cstate, dcf clock is further divided down
	 * to just above given frequency
	 */
	enum pp_smu_status (*set_min_deep_sleep_dcfclk)(struct pp_smu *pp, int Mhz);

	/* PPSMC_MSG_SetHardMinUclkByFreq
	 * UCLK will vary with DPM, but never below requested hard min
	 */
	enum pp_smu_status (*set_hard_min_uclk_by_freq)(struct pp_smu *pp, int Mhz);

	/* PPSMC_MSG_SetHardMinSocclkByFreq
	 * Needed for DWB support
	 */
	enum pp_smu_status (*set_hard_min_socclk_by_freq)(struct pp_smu *pp, int Mhz);

	/* PME w/a */
	enum pp_smu_status (*set_pme_wa_enable)(struct pp_smu *pp);

	/* PPSMC_MSG_SetHardMinByFreq
	 * Needed to set ASIC voltages for clocks programmed by DAL
	 */
	enum pp_smu_status (*set_voltage_by_freq)(struct pp_smu *pp,
			enum pp_smu_nv_clock_id clock_id, int Mhz);

	/* reader and writer WM's are sent together as part of one table*/
	/*
	 * PPSMC_MSG_SetDriverDramAddrHigh
	 * PPSMC_MSG_SetDriverDramAddrLow
	 * PPSMC_MSG_TransferTableDram2Smu
	 *
	 * on DCN20:
	 * 	reader fill clk = uclk
	 * 	reader drain clk = dcfclk
	 * 	writer fill clk = socclk
	 * 	writer drain clk = uclk
	 * */
	enum pp_smu_status (*set_wm_ranges)(struct pp_smu *pp,
			struct pp_smu_wm_range_sets *ranges);

	/* Not a single SMU message.  This call should return maximum sustainable limit for all
	 * clocks that DC depends on.  These will be used as basis for mode enumeration.
	 */
	enum pp_smu_status (*get_maximum_sustainable_clocks)(struct pp_smu *pp,
			struct pp_smu_nv_clock_table *max_clocks);

	/* This call should return the discrete uclk DPM states available
	 */
	enum pp_smu_status (*get_uclk_dpm_states)(struct pp_smu *pp,
			unsigned int *clock_values_in_khz, unsigned int *num_states);

	/* Not a single SMU message.  This call informs PPLIB that display will not be able
	 * to perform pstate handshaking in its current state.  Typically this handshake
	 * is used to perform uCLK switching, so disabling pstate disables uCLK switching.
	 *
	 * Note that when setting handshake to unsupported, the call is pre-emptive.  That means
	 * DC will make the call BEFORE setting up the display state which would cause pstate
	 * request to go un-acked.  Only when the call completes should such a state be applied to
	 * DC hardware
	 */
	enum pp_smu_status (*set_pstate_handshake_support)(struct pp_smu *pp,
			bool pstate_handshake_supported);
};

struct dpm_clocks;

struct pp_smu_funcs_rn {
	struct pp_smu pp_smu;

	/*
	 * reader and writer WM's are sent together as part of one table
	 *
	 * PPSMC_MSG_SetDriverDramAddrHigh
	 * PPSMC_MSG_SetDriverDramAddrLow
	 * PPSMC_MSG_TransferTableDram2Smu
	 *
	 */
	enum pp_smu_status (*set_wm_ranges)(struct pp_smu *pp,
			struct pp_smu_wm_range_sets *ranges);

	enum pp_smu_status (*get_dpm_clock_table) (struct pp_smu *pp,
			struct dpm_clocks *clock_table);
};

struct pp_smu_funcs_vgh {
	struct pp_smu pp_smu;

	/*
	 * reader and writer WM's are sent together as part of one table
	 *
	 * PPSMC_MSG_SetDriverDramAddrHigh
	 * PPSMC_MSG_SetDriverDramAddrLow
	 * PPSMC_MSG_TransferTableDram2Smu
	 *
	 */
	// TODO: Check whether this is moved to DAL, and remove as needed
	enum pp_smu_status (*set_wm_ranges)(struct pp_smu *pp,
			struct pp_smu_wm_range_sets *ranges);

	// TODO: Check whether this is moved to DAL, and remove as needed
	enum pp_smu_status (*get_dpm_clock_table) (struct pp_smu *pp,
			struct dpm_clocks *clock_table);

	enum pp_smu_status (*notify_smu_timeout) (struct pp_smu *pp);
};

struct pp_smu_funcs {
	struct pp_smu ctx;
	union {
		struct pp_smu_funcs_rv rv_funcs;
		struct pp_smu_funcs_nv nv_funcs;
		struct pp_smu_funcs_rn rn_funcs;
		struct pp_smu_funcs_vgh vgh_funcs;
	};
};

/* klp-ccp: from drivers/gpu/drm/amd/display/dc/inc/hw/clk_mgr.h */
#define WM_A 0

#define WM_SET_COUNT 4

#define MAX_NUM_DPM_LVL		8

struct clk_limit_table_entry {
	unsigned int voltage; /* milivolts withh 2 fractional bits */
	unsigned int dcfclk_mhz;
	unsigned int fclk_mhz;
	unsigned int memclk_mhz;
	unsigned int socclk_mhz;
	unsigned int dtbclk_mhz;
	unsigned int dispclk_mhz;
	unsigned int dppclk_mhz;
	unsigned int phyclk_mhz;
	unsigned int phyclk_d18_mhz;
	unsigned int wck_ratio;
};

struct clk_limit_num_entries {
	unsigned int num_dcfclk_levels;
	unsigned int num_fclk_levels;
	unsigned int num_memclk_levels;
	unsigned int num_socclk_levels;
	unsigned int num_dtbclk_levels;
	unsigned int num_dispclk_levels;
	unsigned int num_dppclk_levels;
	unsigned int num_phyclk_levels;
	unsigned int num_phyclk_d18_levels;
};

struct clk_limit_table {
	struct clk_limit_table_entry entries[MAX_NUM_DPM_LVL];
	struct clk_limit_num_entries num_entries_per_clk;
	unsigned int num_entries; /* highest populated dpm level for back compatibility */
};

struct wm_range_table_entry {
	unsigned int wm_inst;
	unsigned int wm_type;
	double pstate_latency_us;
	double sr_exit_time_us;
	double sr_enter_plus_exit_time_us;
	bool valid;
};

struct nv_wm_range_entry {
	bool valid;

	struct {
		uint8_t wm_type;
		uint16_t min_dcfclk;
		uint16_t max_dcfclk;
		uint16_t min_uclk;
		uint16_t max_uclk;
	} pmfw_breakdown;

	struct {
		double pstate_latency_us;
		double sr_exit_time_us;
		double sr_enter_plus_exit_time_us;
		double fclk_change_latency_us;
	} dml_input;
};

struct clk_state_registers_and_bypass {
	uint32_t dcfclk;
	uint32_t dcf_deep_sleep_divider;
	uint32_t dcf_deep_sleep_allow;
	uint32_t dprefclk;
	uint32_t dispclk;
	uint32_t dppclk;
	uint32_t dtbclk;

	uint32_t dppclk_bypass;
	uint32_t dcfclk_bypass;
	uint32_t dprefclk_bypass;
	uint32_t dispclk_bypass;
};

struct wm_table {
	union {
		struct nv_wm_range_entry nv_entries[WM_SET_COUNT];
		struct wm_range_table_entry entries[WM_SET_COUNT];
	};
};

struct dummy_pstate_entry {
	unsigned int dram_speed_mts;
	double dummy_pstate_latency_us;
};

struct clk_bw_params {
	unsigned int vram_type;
	unsigned int num_channels;
	unsigned int dram_channel_width_bytes;
 	unsigned int dispclk_vco_khz;
	unsigned int dc_mode_softmax_memclk;
	unsigned int max_memclk_mhz;
	struct clk_limit_table clk_table;
	struct wm_table wm_table;
	struct dummy_pstate_entry dummy_pstate_table[4];
	struct clk_limit_table_entry dc_mode_limit;
};

struct clk_mgr {
	struct dc_context *ctx;
	struct clk_mgr_funcs *funcs;
	struct dc_clocks clks;
	bool psr_allow_active_cache;
	bool force_smu_not_present;
	bool dc_mode_softmax_enabled;
	int dprefclk_khz; // Used by program pixel clock in clock source funcs, need to figureout where this goes
	int dp_dto_source_clock_in_khz; // Used to program DP DTO with ss adjustment on DCN314
	int dentist_vco_freq_khz;
	struct clk_state_registers_and_bypass boot_snapshot;
	struct clk_bw_params *bw_params;
	struct pp_smu_wm_range_sets ranges;
};

/* klp-ccp: from drivers/gpu/drm/amd/display/dmub/inc/dmub_cmd.h */
#if defined(_TEST_HARNESS) || defined(FPGA_USB4)
#error "klp-ccp: non-taken branch"
#else

#include <asm/byteorder.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/delay.h>

#endif // defined(_TEST_HARNESS) || defined(FPGA_USB4)

/* klp-ccp: from drivers/gpu/drm/amd/display/dc/inc/hw/clk_mgr_internal.h */
#define TO_CLK_MGR_INTERNAL(clk_mgr)\
	container_of(clk_mgr, struct clk_mgr_internal, base)

struct state_dependent_clocks {
	int display_clk_khz;
	int pixel_clk_khz;
};

struct clk_mgr_internal {
	struct clk_mgr base;
	int smu_ver;
	struct pp_smu_funcs *pp_smu;
	struct clk_mgr_internal_funcs *funcs;

	struct dccg *dccg;

	/*
	 * For backwards compatbility with previous implementation
	 * TODO: remove these after everything transitions to new pattern
	 * Rationale is that clk registers change a lot across DCE versions
	 * and a shared data structure doesn't really make sense.
	 */
	const struct clk_mgr_registers *regs;
	const struct clk_mgr_shift *clk_mgr_shift;
	const struct clk_mgr_mask *clk_mgr_mask;

	struct state_dependent_clocks max_clks_by_state[DM_PP_CLOCKS_MAX_STATES];

	/*TODO: figure out which of the below fields should be here vs in asic specific portion */
	/* Cache the status of DFS-bypass feature*/
	bool dfs_bypass_enabled;
	/* True if the DFS-bypass feature is enabled and active. */
	bool dfs_bypass_active;

	uint32_t dfs_ref_freq_khz;
	/*
	 * Cache the display clock returned by VBIOS if DFS-bypass is enabled.
	 * This is basically "Crystal Frequency In KHz" (XTALIN) frequency
	 */
	int dfs_bypass_disp_clk;

	/**
	 * @ss_on_dprefclk:
	 *
	 * True if spread spectrum is enabled on the DP ref clock.
	 */
	bool ss_on_dprefclk;

	/**
	 * @xgmi_enabled:
	 *
	 * True if xGMI is enabled. On VG20, both audio and display clocks need
	 * to be adjusted with the WAFL link's SS info if xGMI is enabled.
	 */
	bool xgmi_enabled;

	/**
	 * @dprefclk_ss_percentage:
	 *
	 * DPREFCLK SS percentage (if down-spread enabled).
	 *
	 * Note that if XGMI is enabled, the SS info (percentage and divider)
	 * from the WAFL link is used instead. This is decided during
	 * dce_clk_mgr initialization.
	 */
	int dprefclk_ss_percentage;

	/**
	 * @dprefclk_ss_divider:
	 *
	 * DPREFCLK SS percentage Divider (100 or 1000).
	 */
	int dprefclk_ss_divider;

	enum dm_pp_clocks_state max_clks_state;
	enum dm_pp_clocks_state cur_min_clks_state;
	bool periodic_retraining_disabled;

	unsigned int cur_phyclk_req_table[MAX_PIPES * 2];

	bool smu_present;
	void *wm_range_table;
	long long wm_range_table_addr;

	bool dpm_present;
};

/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/../display/dc/clk_mgr/dcn21/rn_clk_mgr.c */
static void klpp_build_watermark_ranges(struct clk_bw_params *bw_params, struct pp_smu_wm_range_sets *ranges)
{
	int i, num_valid_sets;

	num_valid_sets = 0;

	for (i = 0; i < WM_SET_COUNT; i++) {
		/* skip empty entries, the smu array has no holes*/
		if (!bw_params->wm_table.entries[i].valid)
			continue;

		ranges->reader_wm_sets[num_valid_sets].wm_inst = bw_params->wm_table.entries[i].wm_inst;
		ranges->reader_wm_sets[num_valid_sets].wm_type = bw_params->wm_table.entries[i].wm_type;
		/* We will not select WM based on fclk, so leave it as unconstrained */
		ranges->reader_wm_sets[num_valid_sets].min_fill_clk_mhz = PP_SMU_WM_SET_RANGE_CLK_UNCONSTRAINED_MIN;
		ranges->reader_wm_sets[num_valid_sets].max_fill_clk_mhz = PP_SMU_WM_SET_RANGE_CLK_UNCONSTRAINED_MAX;
		/* dcfclk wil be used to select WM*/

		if (ranges->reader_wm_sets[num_valid_sets].wm_type == WM_TYPE_PSTATE_CHG) {
			if (i == 0)
				ranges->reader_wm_sets[num_valid_sets].min_drain_clk_mhz = 0;
			else {
				/* add 1 to make it non-overlapping with next lvl */
				ranges->reader_wm_sets[num_valid_sets].min_drain_clk_mhz = bw_params->clk_table.entries[i - 1].dcfclk_mhz + 1;
			}
			ranges->reader_wm_sets[num_valid_sets].max_drain_clk_mhz = bw_params->clk_table.entries[i].dcfclk_mhz;

		} else {
			/* unconstrained for memory retraining */
			ranges->reader_wm_sets[num_valid_sets].min_fill_clk_mhz = PP_SMU_WM_SET_RANGE_CLK_UNCONSTRAINED_MIN;
			ranges->reader_wm_sets[num_valid_sets].max_fill_clk_mhz = PP_SMU_WM_SET_RANGE_CLK_UNCONSTRAINED_MAX;

			/* Modify previous watermark range to cover up to max */
			if (num_valid_sets > 0)
				ranges->reader_wm_sets[num_valid_sets - 1].max_fill_clk_mhz = PP_SMU_WM_SET_RANGE_CLK_UNCONSTRAINED_MAX;
		}
		num_valid_sets++;
	}

	ASSERT(num_valid_sets != 0); /* Must have at least one set of valid watermarks */
	ranges->num_reader_wm_sets = num_valid_sets;

	/* modify the min and max to make sure we cover the whole range*/
	ranges->reader_wm_sets[0].min_drain_clk_mhz = PP_SMU_WM_SET_RANGE_CLK_UNCONSTRAINED_MIN;
	ranges->reader_wm_sets[0].min_fill_clk_mhz = PP_SMU_WM_SET_RANGE_CLK_UNCONSTRAINED_MIN;
	ranges->reader_wm_sets[ranges->num_reader_wm_sets - 1].max_drain_clk_mhz = PP_SMU_WM_SET_RANGE_CLK_UNCONSTRAINED_MAX;
	ranges->reader_wm_sets[ranges->num_reader_wm_sets - 1].max_fill_clk_mhz = PP_SMU_WM_SET_RANGE_CLK_UNCONSTRAINED_MAX;

	/* This is for writeback only, does not matter currently as no writeback support*/
	ranges->num_writer_wm_sets = 1;
	ranges->writer_wm_sets[0].wm_inst = WM_A;
	ranges->writer_wm_sets[0].min_fill_clk_mhz = PP_SMU_WM_SET_RANGE_CLK_UNCONSTRAINED_MIN;
	ranges->writer_wm_sets[0].max_fill_clk_mhz = PP_SMU_WM_SET_RANGE_CLK_UNCONSTRAINED_MAX;
	ranges->writer_wm_sets[0].min_drain_clk_mhz = PP_SMU_WM_SET_RANGE_CLK_UNCONSTRAINED_MIN;
	ranges->writer_wm_sets[0].max_drain_clk_mhz = PP_SMU_WM_SET_RANGE_CLK_UNCONSTRAINED_MAX;

}

void klpp_rn_notify_wm_ranges(struct clk_mgr *clk_mgr_base)
{
	struct dc_debug_options *debug = &clk_mgr_base->ctx->dc->debug;
	struct clk_mgr_internal *clk_mgr = TO_CLK_MGR_INTERNAL(clk_mgr_base);
	struct pp_smu_funcs *pp_smu = clk_mgr->pp_smu;

	if (!debug->disable_pplib_wm_range) {
		klpp_build_watermark_ranges(clk_mgr_base->bw_params, &clk_mgr_base->ranges);

		/* Notify PP Lib/SMU which Watermarks to use for which clock ranges */
		if (pp_smu && pp_smu->rn_funcs.set_wm_ranges)
			pp_smu->rn_funcs.set_wm_ranges(&pp_smu->rn_funcs.pp_smu, &clk_mgr_base->ranges);
	}

}


#include "livepatch_bsc1231196.h"


#endif /* IS_ENABLED(CONFIG_DRM_AMDGPU) */
