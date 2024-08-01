/*
 * livepatch_bsc1225310
 *
 * Fix for CVE-2024-35950, bsc#1225310
 *
 *  Upstream commit:
 *  3eadd887dbac ("drm/client: Fully protect modes[] with dev->mode_config.mutex")
 *
 *  SLE12-SP5 commit:
 *  f0cb811d920688ecad1a2f3ae2ac9f7cef924b16
 *
 *  SLE15-SP2 and -SP3 commit:
 *  f5de9d82d094a34e6568747e4af17d017ba402f0
 *
 *  SLE15-SP4 and -SP5 commit:
 *  75706b6ffaf01a1d22c6df4e5c8e8438b58b7383
 *
 *  Copyright (c) 2024 SUSE
 *  Author: Marcos Paulo de Souza <mpdesouza@suse.com>
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

/* klp-ccp: from drivers/gpu/drm/drm_fb_helper.c */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/console.h>
#include <linux/dma-buf.h>
#include <linux/kernel.h>
#include <linux/slab.h>

/* klp-ccp: from drivers/gpu/drm/drm_fb_helper.c */
#include <drm/drmP.h>

/* klp-ccp: from include/drm/drm_mode_object.h */
static void (*klpe_drm_mode_object_get)(struct drm_mode_object *obj);
static void (*klpe_drm_mode_object_put)(struct drm_mode_object *obj);

/* klp-ccp: from include/drm/drm_connector.h */
static inline void klpr_drm_connector_get(struct drm_connector *connector)
{
	(*klpe_drm_mode_object_get)(&connector->base);
}

static inline void klpr_drm_connector_put(struct drm_connector *connector)
{
	(*klpe_drm_mode_object_put)(&connector->base);
}

/* klp-ccp: from include/drm/drm_modes.h */
static void (*klpe_drm_mode_destroy)(struct drm_device *dev, struct drm_display_mode *mode);

static struct drm_display_mode *(*klpe_drm_mode_duplicate)(struct drm_device *dev,
					    const struct drm_display_mode *mode);
static bool (*klpe_drm_mode_match)(const struct drm_display_mode *mode1,
		    const struct drm_display_mode *mode2,
		    unsigned int match_flags);

/* klp-ccp: from include/drm/drm_edid.h */
static struct drm_display_mode *(*klpe_drm_mode_find_dmt)(struct drm_device *dev,
					   int hsize, int vsize, int fresh,
					   bool rb);

/* klp-ccp: from include/drm/drm_print.h */
static __printf(2, 3)
void (*klpe_drm_dbg)(unsigned int category, const char *format, ...);
static __printf(1, 2)
void (*klpe_drm_err)(const char *format, ...);

#define KLPR_DRM_ERROR(fmt, ...)						\
	(*klpe_drm_err)(fmt, ##__VA_ARGS__)
#define KLPR_DRM_DEBUG_KMS(fmt, ...)						\
	(*klpe_drm_dbg)(DRM_UT_KMS, fmt, ##__VA_ARGS__)

/* klp-ccp: from drivers/gpu/drm/drm_fb_helper.c */
#include <drm/drm_crtc.h>
#include <drm/drm_fb_helper.h>

/* klp-ccp: from include/drm/drm_fb_helper.h */
#ifdef CONFIG_DRM_FBDEV_EMULATION

static struct drm_display_mode *
(*klpe_drm_has_preferred_mode)(struct drm_fb_helper_connector *fb_connector,
			int width, int height);
static struct drm_display_mode *
(*klpe_drm_pick_cmdline_mode)(struct drm_fb_helper_connector *fb_helper_conn);

#else
#error "klp-ccp: non-taken branch"
#endif

/* klp-ccp: from include/drm/drm_encoder.h */
#define __DRM_ENCODER_H__

/* klp-ccp: from drivers/gpu/drm/drm_crtc_helper_internal.h */
#include <drm/drm_connector.h>
#include <drm/drm_crtc.h>
#include <drm/drm_encoder.h>
#include <drm/drm_modes.h>

/* klp-ccp: from drivers/gpu/drm/drm_fb_helper.c */
#define drm_fb_helper_for_each_connector(fbh, i__) \
	for (({ lockdep_assert_held(&(fbh)->lock); }), \
	     i__ = 0; i__ < (fbh)->connector_count; i__++)

static void klpr_drm_fb_helper_modeset_release(struct drm_fb_helper *helper,
					  struct drm_mode_set *modeset)
{
	int i;

	for (i = 0; i < modeset->num_connectors; i++) {
		klpr_drm_connector_put(modeset->connectors[i]);
		modeset->connectors[i] = NULL;
	}
	modeset->num_connectors = 0;

	(*klpe_drm_mode_destroy)(helper->dev, modeset->mode);
	modeset->mode = NULL;

	/* FIXME should hold a ref? */
	modeset->fb = NULL;
}

static int drm_fb_helper_probe_connector_modes(struct drm_fb_helper *fb_helper,
						uint32_t maxX,
						uint32_t maxY)
{
	struct drm_connector *connector;
	int i, count = 0;

	drm_fb_helper_for_each_connector(fb_helper, i) {
		connector = fb_helper->connector_info[i]->connector;
		count += connector->funcs->fill_modes(connector, maxX, maxY);
	}

	return count;
}

static bool drm_connector_enabled(struct drm_connector *connector, bool strict)
{
	bool enable;

	if (connector->display_info.non_desktop)
		return false;

	if (strict)
		enable = connector->status == connector_status_connected;
	else
		enable = connector->status != connector_status_disconnected;

	return enable;
}

static void klpr_drm_enable_connectors(struct drm_fb_helper *fb_helper,
				  bool *enabled)
{
	bool any_enabled = false;
	struct drm_connector *connector;
	int i = 0;

	drm_fb_helper_for_each_connector(fb_helper, i) {
		connector = fb_helper->connector_info[i]->connector;
		enabled[i] = drm_connector_enabled(connector, true);
		KLPR_DRM_DEBUG_KMS("connector %d enabled? %s\n", connector->base.id,
			      connector->display_info.non_desktop ? "non desktop" : enabled[i] ? "yes" : "no");

		any_enabled |= enabled[i];
	}

	if (any_enabled)
		return;

	drm_fb_helper_for_each_connector(fb_helper, i) {
		connector = fb_helper->connector_info[i]->connector;
		enabled[i] = drm_connector_enabled(connector, false);
	}
}

static bool klpr_drm_target_cloned(struct drm_fb_helper *fb_helper,
			      struct drm_display_mode **modes,
			      struct drm_fb_offset *offsets,
			      bool *enabled, int width, int height)
{
	int count, i, j;
	bool can_clone = false;
	struct drm_fb_helper_connector *fb_helper_conn;
	struct drm_display_mode *dmt_mode, *mode;

	/* only contemplate cloning in the single crtc case */
	if (fb_helper->crtc_count > 1)
		return false;

	count = 0;
	drm_fb_helper_for_each_connector(fb_helper, i) {
		if (enabled[i])
			count++;
	}

	/* only contemplate cloning if more than one connector is enabled */
	if (count <= 1)
		return false;

	/* check the command line or if nothing common pick 1024x768 */
	can_clone = true;
	drm_fb_helper_for_each_connector(fb_helper, i) {
		if (!enabled[i])
			continue;
		fb_helper_conn = fb_helper->connector_info[i];
		modes[i] = (*klpe_drm_pick_cmdline_mode)(fb_helper_conn);
		if (!modes[i]) {
			can_clone = false;
			break;
		}
		for (j = 0; j < i; j++) {
			if (!enabled[j])
				continue;
			if (!(*klpe_drm_mode_match)(modes[j], modes[i],
					    DRM_MODE_MATCH_TIMINGS |
					    DRM_MODE_MATCH_CLOCK |
					    DRM_MODE_MATCH_FLAGS |
					    DRM_MODE_MATCH_3D_FLAGS))
				can_clone = false;
		}
	}

	if (can_clone) {
		KLPR_DRM_DEBUG_KMS("can clone using command line\n");
		return true;
	}

	/* try and find a 1024x768 mode on each connector */
	can_clone = true;
	dmt_mode = (*klpe_drm_mode_find_dmt)(fb_helper->dev, 1024, 768, 60, false);

	if (!dmt_mode)
		goto fail;

	drm_fb_helper_for_each_connector(fb_helper, i) {
		if (!enabled[i])
			continue;

		fb_helper_conn = fb_helper->connector_info[i];
		list_for_each_entry(mode, &fb_helper_conn->connector->modes, head) {
			if ((*klpe_drm_mode_match)(mode, dmt_mode,
					   DRM_MODE_MATCH_TIMINGS |
					   DRM_MODE_MATCH_CLOCK |
					   DRM_MODE_MATCH_FLAGS |
					   DRM_MODE_MATCH_3D_FLAGS))
				modes[i] = mode;
		}
		if (!modes[i])
			can_clone = false;
	}
	kfree(dmt_mode);

	if (can_clone) {
		KLPR_DRM_DEBUG_KMS("can clone using 1024x768\n");
		return true;
	}
fail:
	DRM_INFO("kms: can't enable cloning when we probably wanted to.\n");
	return false;
}

static int klpr_drm_get_tile_offsets(struct drm_fb_helper *fb_helper,
				struct drm_display_mode **modes,
				struct drm_fb_offset *offsets,
				int idx,
				int h_idx, int v_idx)
{
	struct drm_fb_helper_connector *fb_helper_conn;
	int i;
	int hoffset = 0, voffset = 0;

	drm_fb_helper_for_each_connector(fb_helper, i) {
		fb_helper_conn = fb_helper->connector_info[i];
		if (!fb_helper_conn->connector->has_tile)
			continue;

		if (!modes[i] && (h_idx || v_idx)) {
			KLPR_DRM_DEBUG_KMS("no modes for connector tiled %d %d\n", i,
				      fb_helper_conn->connector->base.id);
			continue;
		}
		if (fb_helper_conn->connector->tile_h_loc < h_idx)
			hoffset += modes[i]->hdisplay;

		if (fb_helper_conn->connector->tile_v_loc < v_idx)
			voffset += modes[i]->vdisplay;
	}
	offsets[idx].x = hoffset;
	offsets[idx].y = voffset;
	KLPR_DRM_DEBUG_KMS("returned %d %d for %d %d\n", hoffset, voffset, h_idx, v_idx);
	return 0;
}

static bool klpr_drm_target_preferred(struct drm_fb_helper *fb_helper,
				 struct drm_display_mode **modes,
				 struct drm_fb_offset *offsets,
				 bool *enabled, int width, int height)
{
	struct drm_fb_helper_connector *fb_helper_conn;
	const u64 mask = BIT_ULL(fb_helper->connector_count) - 1;
	u64 conn_configured = 0;
	int tile_pass = 0;
	int i;

retry:
	drm_fb_helper_for_each_connector(fb_helper, i) {
		fb_helper_conn = fb_helper->connector_info[i];

		if (conn_configured & BIT_ULL(i))
			continue;

		if (enabled[i] == false) {
			conn_configured |= BIT_ULL(i);
			continue;
		}

		/* first pass over all the untiled connectors */
		if (tile_pass == 0 && fb_helper_conn->connector->has_tile)
			continue;

		if (tile_pass == 1) {
			if (fb_helper_conn->connector->tile_h_loc != 0 ||
			    fb_helper_conn->connector->tile_v_loc != 0)
				continue;

		} else {
			if (fb_helper_conn->connector->tile_h_loc != tile_pass - 1 &&
			    fb_helper_conn->connector->tile_v_loc != tile_pass - 1)
			/* if this tile_pass doesn't cover any of the tiles - keep going */
				continue;

			/*
			 * find the tile offsets for this pass - need to find
			 * all tiles left and above
			 */
			klpr_drm_get_tile_offsets(fb_helper, modes, offsets,
					     i, fb_helper_conn->connector->tile_h_loc, fb_helper_conn->connector->tile_v_loc);
		}
		KLPR_DRM_DEBUG_KMS("looking for cmdline mode on connector %d\n",
			      fb_helper_conn->connector->base.id);

		/* got for command line mode first */
		modes[i] = (*klpe_drm_pick_cmdline_mode)(fb_helper_conn);
		if (!modes[i]) {
			KLPR_DRM_DEBUG_KMS("looking for preferred mode on connector %d %d\n",
				      fb_helper_conn->connector->base.id, fb_helper_conn->connector->tile_group ? fb_helper_conn->connector->tile_group->id : 0);
			modes[i] = (*klpe_drm_has_preferred_mode)(fb_helper_conn, width, height);
		}
		/* No preferred modes, pick one off the list */
		if (!modes[i] && !list_empty(&fb_helper_conn->connector->modes)) {
			list_for_each_entry(modes[i], &fb_helper_conn->connector->modes, head)
				break;
		}
		KLPR_DRM_DEBUG_KMS("found mode %s\n", modes[i] ? modes[i]->name :
			  "none");
		conn_configured |= BIT_ULL(i);
	}

	if ((conn_configured & mask) != mask) {
		tile_pass++;
		goto retry;
	}
	return true;
}

static int (*klpe_drm_pick_crtcs)(struct drm_fb_helper *fb_helper,
			  struct drm_fb_helper_crtc **best_crtcs,
			  struct drm_display_mode **modes,
			  int n, int width, int height);

static void drm_setup_crtc_rotation(struct drm_fb_helper *fb_helper,
				    struct drm_fb_helper_crtc *fb_crtc,
				    struct drm_connector *connector)
{
	struct drm_plane *plane = fb_crtc->mode_set.crtc->primary;
	uint64_t valid_mask = 0;
	int i, rotation;

	fb_crtc->rotation = DRM_MODE_ROTATE_0;

	switch (connector->display_info.panel_orientation) {
	case DRM_MODE_PANEL_ORIENTATION_BOTTOM_UP:
		rotation = DRM_MODE_ROTATE_180;
		break;
	case DRM_MODE_PANEL_ORIENTATION_LEFT_UP:
		rotation = DRM_MODE_ROTATE_90;
		break;
	case DRM_MODE_PANEL_ORIENTATION_RIGHT_UP:
		rotation = DRM_MODE_ROTATE_270;
		break;
	default:
		rotation = DRM_MODE_ROTATE_0;
	}

	/*
	 * TODO: support 90 / 270 degree hardware rotation,
	 * depending on the hardware this may require the framebuffer
	 * to be in a specific tiling format.
	 */
	if (rotation != DRM_MODE_ROTATE_180 || !plane->rotation_property) {
		fb_helper->sw_rotations |= rotation;
		return;
	}

	for (i = 0; i < plane->rotation_property->num_values; i++)
		valid_mask |= (1ULL << plane->rotation_property->values[i]);

	if (!(rotation & valid_mask)) {
		fb_helper->sw_rotations |= rotation;
		return;
	}

	fb_crtc->rotation = rotation;
	/* Rotating in hardware, fbcon should not rotate */
	fb_helper->sw_rotations |= DRM_MODE_ROTATE_0;
}

void klpp_drm_setup_crtcs(struct drm_fb_helper *fb_helper,
			    u32 width, u32 height)
{
	struct drm_device *dev = fb_helper->dev;
	struct drm_fb_helper_crtc **crtcs;
	/* points to modes protected by mode_config.mutex */
	struct drm_display_mode **modes;
	struct drm_fb_offset *offsets;
	bool *enabled;
	int i;

	KLPR_DRM_DEBUG_KMS("\n");
	/* prevent concurrent modification of connector_count by hotplug */
	lockdep_assert_held(&fb_helper->lock);

	crtcs = kcalloc(fb_helper->connector_count,
			sizeof(struct drm_fb_helper_crtc *), GFP_KERNEL);
	modes = kcalloc(fb_helper->connector_count,
			sizeof(struct drm_display_mode *), GFP_KERNEL);
	offsets = kcalloc(fb_helper->connector_count,
			  sizeof(struct drm_fb_offset), GFP_KERNEL);
	enabled = kcalloc(fb_helper->connector_count,
			  sizeof(bool), GFP_KERNEL);
	if (!crtcs || !modes || !enabled || !offsets) {
		KLPR_DRM_ERROR("Memory allocation failed\n");
		goto out;
	}

	mutex_lock(&fb_helper->dev->mode_config.mutex);
	if (drm_fb_helper_probe_connector_modes(fb_helper, width, height) == 0)
		KLPR_DRM_DEBUG_KMS("No connectors reported connected with modes\n");
	klpr_drm_enable_connectors(fb_helper, enabled);

	if (!(fb_helper->funcs->initial_config &&
	      fb_helper->funcs->initial_config(fb_helper, crtcs, modes,
					       offsets,
					       enabled, width, height))) {
		memset(modes, 0, fb_helper->connector_count*sizeof(modes[0]));
		memset(crtcs, 0, fb_helper->connector_count*sizeof(crtcs[0]));
		memset(offsets, 0, fb_helper->connector_count*sizeof(offsets[0]));

		if (!klpr_drm_target_cloned(fb_helper, modes, offsets,
				       enabled, width, height) &&
		    !klpr_drm_target_preferred(fb_helper, modes, offsets,
					  enabled, width, height))
			KLPR_DRM_ERROR("Unable to find initial modes\n");

		KLPR_DRM_DEBUG_KMS("picking CRTCs for %dx%d config\n",
			      width, height);

		(*klpe_drm_pick_crtcs)(fb_helper, crtcs, modes, 0, width, height);
	}

	/* need to set the modesets up here for use later */
	/* fill out the connector<->crtc mappings into the modesets */
	for (i = 0; i < fb_helper->crtc_count; i++)
		klpr_drm_fb_helper_modeset_release(fb_helper,
					      &fb_helper->crtc_info[i].mode_set);

	fb_helper->sw_rotations = 0;
	drm_fb_helper_for_each_connector(fb_helper, i) {
		struct drm_display_mode *mode = modes[i];
		struct drm_fb_helper_crtc *fb_crtc = crtcs[i];
		struct drm_fb_offset *offset = &offsets[i];

		if (mode && fb_crtc) {
			struct drm_mode_set *modeset = &fb_crtc->mode_set;
			struct drm_connector *connector =
				fb_helper->connector_info[i]->connector;

			KLPR_DRM_DEBUG_KMS("desired mode %s set on crtc %d (%d,%d)\n",
				      mode->name, fb_crtc->mode_set.crtc->base.id, offset->x, offset->y);

			fb_crtc->desired_mode = mode;
			fb_crtc->x = offset->x;
			fb_crtc->y = offset->y;
			modeset->mode = (*klpe_drm_mode_duplicate)(dev,
							   fb_crtc->desired_mode);
			klpr_drm_connector_get(connector);
			drm_setup_crtc_rotation(fb_helper, fb_crtc, connector);
			modeset->connectors[modeset->num_connectors++] = connector;
			modeset->x = offset->x;
			modeset->y = offset->y;
		}
	}
	mutex_unlock(&fb_helper->dev->mode_config.mutex);

out:
	kfree(crtcs);
	kfree(modes);
	kfree(offsets);
	kfree(enabled);
}


#include "livepatch_bsc1225310.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "drm_kms_helper"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "drm_dbg", (void *)&klpe_drm_dbg, "drm" },
	{ "drm_err", (void *)&klpe_drm_err, "drm" },
	{ "drm_mode_destroy", (void *)&klpe_drm_mode_destroy, "drm" },
	{ "drm_mode_duplicate", (void *)&klpe_drm_mode_duplicate, "drm" },
	{ "drm_mode_find_dmt", (void *)&klpe_drm_mode_find_dmt, "drm" },
	{ "drm_mode_match", (void *)&klpe_drm_mode_match, "drm" },
	{ "drm_mode_object_get", (void *)&klpe_drm_mode_object_get, "drm" },
	{ "drm_mode_object_put", (void *)&klpe_drm_mode_object_put, "drm" },
	{ "drm_has_preferred_mode", (void *)&klpe_drm_has_preferred_mode,
	  "drm_kms_helper" },
	{ "drm_pick_cmdline_mode", (void *)&klpe_drm_pick_cmdline_mode,
	  "drm_kms_helper" },
	{ "drm_pick_crtcs", (void *)&klpe_drm_pick_crtcs, "drm_kms_helper" },
};

static int module_notify(struct notifier_block *nb,
			unsigned long action, void *data)
{
	struct module *mod = data;
	int ret;

	if (action != MODULE_STATE_COMING || strcmp(mod->name, LP_MODULE))
		return 0;
	mutex_lock(&module_mutex);
	ret = __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
	mutex_unlock(&module_mutex);

	WARN(ret, "%s: delayed kallsyms lookup failed. System is broken and can crash.\n",
		__func__);

	return ret;
}

static struct notifier_block module_nb = {
	.notifier_call = module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1225310_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	if (find_module(LP_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void livepatch_bsc1225310_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}
