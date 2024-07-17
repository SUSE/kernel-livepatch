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

#include <drm/drm_crtc.h>

static void (*klpe_drm_modeset_acquire_init)(struct drm_modeset_acquire_ctx *ctx,
		uint32_t flags);
static void (*klpe_drm_modeset_acquire_fini)(struct drm_modeset_acquire_ctx *ctx);
static void (*klpe_drm_modeset_drop_locks)(struct drm_modeset_acquire_ctx *ctx);
static int (*klpe_drm_modeset_backoff)(struct drm_modeset_acquire_ctx *ctx);

struct drm_device;

static int (*klpe_drm_modeset_lock_all_ctx)(struct drm_device *dev,
			     struct drm_modeset_acquire_ctx *ctx);

/* klp-ccp: from drivers/gpu/drm/drm_client_modeset.c */
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/string_helpers.h>
#include <drm/drm_atomic.h>

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

static void (*klpe_drm_connector_list_iter_begin)(struct drm_device *dev,
				   struct drm_connector_list_iter *iter);
static struct drm_connector *
(*klpe_drm_connector_list_iter_next)(struct drm_connector_list_iter *iter);
static void (*klpe_drm_connector_list_iter_end)(struct drm_connector_list_iter *iter);

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

/* klp-ccp: from drivers/gpu/drm/drm_client_modeset.c */
#include <drm/drm_client.h>

/* klp-ccp: from drivers/gpu/drm/drm_client_modeset.c */
#include <drm/drm_connector.h>
#include <drm/drm_crtc.h>
#include <drm/drm_device.h>
#include <drm/drm_drv.h>
#include <drm/drm_print.h>

/* klp-ccp: from include/drm/drm_print.h */
static __printf(2, 3)
void (*klpe___drm_dbg)(enum drm_debug_category category, const char *format, ...);
static __printf(1, 2)
void (*klpe___drm_err)(const char *format, ...);

#define KLPR_DRM_ERROR(fmt, ...)						\
	(*klpe___drm_err)(fmt, ##__VA_ARGS__)
#define KLPR_DRM_DEBUG_KMS(fmt, ...)						\
	(*klpe___drm_dbg)(DRM_UT_KMS, fmt, ##__VA_ARGS__)

#define klpr_drm_for_each_connector_iter(connector, iter) \
	while ((connector = (*klpe_drm_connector_list_iter_next)(iter)))

#define klpr_drm_client_for_each_connector_iter(connector, iter) \
	klpr_drm_for_each_connector_iter(connector, iter) \
		if (connector->connector_type != DRM_MODE_CONNECTOR_WRITEBACK)

/* klp-ccp: from drivers/gpu/drm/drm_crtc_internal.h */
#include <linux/types.h>

/* klp-ccp: from drivers/gpu/drm/drm_client_modeset.c */
#define DRM_CLIENT_MAX_CLONED_CONNECTORS	8

struct drm_client_offset {
	int x, y;
};

static void klpr_drm_client_modeset_release(struct drm_client_dev *client)
{
	struct drm_mode_set *modeset;
	unsigned int i;

	drm_client_for_each_modeset(modeset, client) {
		(*klpe_drm_mode_destroy)(client->dev, modeset->mode);
		modeset->mode = NULL;
		modeset->fb = NULL;

		for (i = 0; i < modeset->num_connectors; i++) {
			klpr_drm_connector_put(modeset->connectors[i]);
			modeset->connectors[i] = NULL;
		}
		modeset->num_connectors = 0;
	}
}

static struct drm_mode_set *
drm_client_find_modeset(struct drm_client_dev *client, struct drm_crtc *crtc)
{
	struct drm_mode_set *modeset;

	drm_client_for_each_modeset(modeset, client)
		if (modeset->crtc == crtc)
			return modeset;

	return NULL;
}

static struct drm_display_mode *
drm_connector_get_tiled_mode(struct drm_connector *connector)
{
	struct drm_display_mode *mode;

	list_for_each_entry(mode, &connector->modes, head) {
		if (mode->hdisplay == connector->tile_h_size &&
		    mode->vdisplay == connector->tile_v_size)
			return mode;
	}
	return NULL;
}

static struct drm_display_mode *
drm_connector_fallback_non_tiled_mode(struct drm_connector *connector)
{
	struct drm_display_mode *mode;

	list_for_each_entry(mode, &connector->modes, head) {
		if (mode->hdisplay == connector->tile_h_size &&
		    mode->vdisplay == connector->tile_v_size)
			continue;
		return mode;
	}
	return NULL;
}

static struct drm_display_mode *
drm_connector_has_preferred_mode(struct drm_connector *connector, int width, int height)
{
	struct drm_display_mode *mode;

	list_for_each_entry(mode, &connector->modes, head) {
		if (mode->hdisplay > width ||
		    mode->vdisplay > height)
			continue;
		if (mode->type & DRM_MODE_TYPE_PREFERRED)
			return mode;
	}
	return NULL;
}

static struct drm_display_mode *(*klpe_drm_connector_pick_cmdline_mode)(struct drm_connector *connector);

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

static void klpr_drm_client_connectors_enabled(struct drm_connector **connectors,
					  unsigned int connector_count,
					  bool *enabled)
{
	bool any_enabled = false;
	struct drm_connector *connector;
	int i = 0;

	for (i = 0; i < connector_count; i++) {
		connector = connectors[i];
		enabled[i] = drm_connector_enabled(connector, true);
		KLPR_DRM_DEBUG_KMS("connector %d enabled? %s\n", connector->base.id,
			      connector->display_info.non_desktop ? "non desktop" : str_yes_no(enabled[i]));

		any_enabled |= enabled[i];
	}

	if (any_enabled)
		return;

	for (i = 0; i < connector_count; i++)
		enabled[i] = drm_connector_enabled(connectors[i], false);
}

static bool klpr_drm_client_target_cloned(struct drm_device *dev,
				     struct drm_connector **connectors,
				     unsigned int connector_count,
				     struct drm_display_mode **modes,
				     struct drm_client_offset *offsets,
				     bool *enabled, int width, int height)
{
	int count, i, j;
	bool can_clone = false;
	struct drm_display_mode *dmt_mode, *mode;

	/* only contemplate cloning in the single crtc case */
	if (dev->mode_config.num_crtc > 1)
		return false;

	count = 0;
	for (i = 0; i < connector_count; i++) {
		if (enabled[i])
			count++;
	}

	/* only contemplate cloning if more than one connector is enabled */
	if (count <= 1)
		return false;

	/* check the command line or if nothing common pick 1024x768 */
	can_clone = true;
	for (i = 0; i < connector_count; i++) {
		if (!enabled[i])
			continue;
		modes[i] = (*klpe_drm_connector_pick_cmdline_mode)(connectors[i]);
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
	dmt_mode = (*klpe_drm_mode_find_dmt)(dev, 1024, 768, 60, false);

	for (i = 0; i < connector_count; i++) {
		if (!enabled[i])
			continue;

		list_for_each_entry(mode, &connectors[i]->modes, head) {
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

	if (can_clone) {
		KLPR_DRM_DEBUG_KMS("can clone using 1024x768\n");
		return true;
	}
	DRM_INFO("kms: can't enable cloning when we probably wanted to.\n");
	return false;
}

static int klpr_drm_client_get_tile_offsets(struct drm_connector **connectors,
				       unsigned int connector_count,
				       struct drm_display_mode **modes,
				       struct drm_client_offset *offsets,
				       int idx,
				       int h_idx, int v_idx)
{
	struct drm_connector *connector;
	int i;
	int hoffset = 0, voffset = 0;

	for (i = 0; i < connector_count; i++) {
		connector = connectors[i];
		if (!connector->has_tile)
			continue;

		if (!modes[i] && (h_idx || v_idx)) {
			KLPR_DRM_DEBUG_KMS("no modes for connector tiled %d %d\n", i,
				      connector->base.id);
			continue;
		}
		if (connector->tile_h_loc < h_idx)
			hoffset += modes[i]->hdisplay;

		if (connector->tile_v_loc < v_idx)
			voffset += modes[i]->vdisplay;
	}
	offsets[idx].x = hoffset;
	offsets[idx].y = voffset;
	KLPR_DRM_DEBUG_KMS("returned %d %d for %d %d\n", hoffset, voffset, h_idx, v_idx);
	return 0;
}

static bool klpr_drm_client_target_preferred(struct drm_connector **connectors,
					unsigned int connector_count,
					struct drm_display_mode **modes,
					struct drm_client_offset *offsets,
					bool *enabled, int width, int height)
{
	const u64 mask = BIT_ULL(connector_count) - 1;
	struct drm_connector *connector;
	u64 conn_configured = 0;
	int tile_pass = 0;
	int num_tiled_conns = 0;
	int i;

	for (i = 0; i < connector_count; i++) {
		if (connectors[i]->has_tile &&
		    connectors[i]->status == connector_status_connected)
			num_tiled_conns++;
	}

retry:
	for (i = 0; i < connector_count; i++) {
		connector = connectors[i];

		if (conn_configured & BIT_ULL(i))
			continue;

		if (enabled[i] == false) {
			conn_configured |= BIT_ULL(i);
			continue;
		}

		/* first pass over all the untiled connectors */
		if (tile_pass == 0 && connector->has_tile)
			continue;

		if (tile_pass == 1) {
			if (connector->tile_h_loc != 0 ||
			    connector->tile_v_loc != 0)
				continue;

		} else {
			if (connector->tile_h_loc != tile_pass - 1 &&
			    connector->tile_v_loc != tile_pass - 1)
			/* if this tile_pass doesn't cover any of the tiles - keep going */
				continue;

			/*
			 * find the tile offsets for this pass - need to find
			 * all tiles left and above
			 */
			klpr_drm_client_get_tile_offsets(connectors, connector_count, modes, offsets, i,
						    connector->tile_h_loc, connector->tile_v_loc);
		}
		KLPR_DRM_DEBUG_KMS("looking for cmdline mode on connector %d\n",
			      connector->base.id);

		/* got for command line mode first */
		modes[i] = (*klpe_drm_connector_pick_cmdline_mode)(connector);
		if (!modes[i]) {
			KLPR_DRM_DEBUG_KMS("looking for preferred mode on connector %d %d\n",
				      connector->base.id, connector->tile_group ? connector->tile_group->id : 0);
			modes[i] = drm_connector_has_preferred_mode(connector, width, height);
		}
		/* No preferred modes, pick one off the list */
		if (!modes[i] && !list_empty(&connector->modes)) {
			list_for_each_entry(modes[i], &connector->modes, head)
				break;
		}
		/*
		 * In case of tiled mode if all tiles not present fallback to
		 * first available non tiled mode.
		 * After all tiles are present, try to find the tiled mode
		 * for all and if tiled mode not present due to fbcon size
		 * limitations, use first non tiled mode only for
		 * tile 0,0 and set to no mode for all other tiles.
		 */
		if (connector->has_tile) {
			if (num_tiled_conns <
			    connector->num_h_tile * connector->num_v_tile ||
			    (connector->tile_h_loc == 0 &&
			     connector->tile_v_loc == 0 &&
			     !drm_connector_get_tiled_mode(connector))) {
				KLPR_DRM_DEBUG_KMS("Falling back to non tiled mode on Connector %d\n",
					      connector->base.id);
				modes[i] = drm_connector_fallback_non_tiled_mode(connector);
			} else {
				modes[i] = drm_connector_get_tiled_mode(connector);
			}
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

static int (*klpe_drm_client_pick_crtcs)(struct drm_client_dev *client,
				 struct drm_connector **connectors,
				 unsigned int connector_count,
				 struct drm_crtc **best_crtcs,
				 struct drm_display_mode **modes,
				 int n, int width, int height);

static bool klpr_drm_client_firmware_config(struct drm_client_dev *client,
				       struct drm_connector **connectors,
				       unsigned int connector_count,
				       struct drm_crtc **crtcs,
				       struct drm_display_mode **modes,
				       struct drm_client_offset *offsets,
				       bool *enabled, int width, int height)
{
	const int count = min_t(unsigned int, connector_count, BITS_PER_LONG);
	unsigned long conn_configured, conn_seq, mask;
	struct drm_device *dev = client->dev;
	int i, j;
	bool *save_enabled;
	bool fallback = true, ret = true;
	int num_connectors_enabled = 0;
	int num_connectors_detected = 0;
	int num_tiled_conns = 0;
	struct drm_modeset_acquire_ctx ctx;

	if (!drm_drv_uses_atomic_modeset(dev))
		return false;

	if (WARN_ON(count <= 0))
		return false;

	save_enabled = kcalloc(count, sizeof(bool), GFP_KERNEL);
	if (!save_enabled)
		return false;

	(*klpe_drm_modeset_acquire_init)(&ctx, 0);

	while ((*klpe_drm_modeset_lock_all_ctx)(dev, &ctx) != 0)
		(*klpe_drm_modeset_backoff)(&ctx);

	memcpy(save_enabled, enabled, count);
	mask = GENMASK(count - 1, 0);
	conn_configured = 0;
	for (i = 0; i < count; i++) {
		if (connectors[i]->has_tile &&
		    connectors[i]->status == connector_status_connected)
			num_tiled_conns++;
	}
retry:
	conn_seq = conn_configured;
	for (i = 0; i < count; i++) {
		struct drm_connector *connector;
		struct drm_encoder *encoder;
		struct drm_crtc *new_crtc;

		connector = connectors[i];

		if (conn_configured & BIT(i))
			continue;

		if (conn_seq == 0 && !connector->has_tile)
			continue;

		if (connector->status == connector_status_connected)
			num_connectors_detected++;

		if (!enabled[i]) {
			KLPR_DRM_DEBUG_KMS("connector %s not enabled, skipping\n",
				      connector->name);
			conn_configured |= BIT(i);
			continue;
		}

		if (connector->force == DRM_FORCE_OFF) {
			KLPR_DRM_DEBUG_KMS("connector %s is disabled by user, skipping\n",
				      connector->name);
			enabled[i] = false;
			continue;
		}

		encoder = connector->state->best_encoder;
		if (!encoder || WARN_ON(!connector->state->crtc)) {
			if (connector->force > DRM_FORCE_OFF)
				goto bail;

			KLPR_DRM_DEBUG_KMS("connector %s has no encoder or crtc, skipping\n",
				      connector->name);
			enabled[i] = false;
			conn_configured |= BIT(i);
			continue;
		}

		num_connectors_enabled++;

		new_crtc = connector->state->crtc;

		/*
		 * Make sure we're not trying to drive multiple connectors
		 * with a single CRTC, since our cloning support may not
		 * match the BIOS.
		 */
		for (j = 0; j < count; j++) {
			if (crtcs[j] == new_crtc) {
				KLPR_DRM_DEBUG_KMS("fallback: cloned configuration\n");
				goto bail;
			}
		}

		KLPR_DRM_DEBUG_KMS("looking for cmdline mode on connector %s\n",
			      connector->name);

		/* go for command line mode first */
		modes[i] = (*klpe_drm_connector_pick_cmdline_mode)(connector);

		/* try for preferred next */
		if (!modes[i]) {
			KLPR_DRM_DEBUG_KMS("looking for preferred mode on connector %s %d\n",
				      connector->name, connector->has_tile);
			modes[i] = drm_connector_has_preferred_mode(connector, width, height);
		}

		/* No preferred mode marked by the EDID? Are there any modes? */
		if (!modes[i] && !list_empty(&connector->modes)) {
			KLPR_DRM_DEBUG_KMS("using first mode listed on connector %s\n",
				      connector->name);
			modes[i] = list_first_entry(&connector->modes,
						    struct drm_display_mode,
						    head);
		}

		/* last resort: use current mode */
		if (!modes[i]) {
			/*
			 * IMPORTANT: We want to use the adjusted mode (i.e.
			 * after the panel fitter upscaling) as the initial
			 * config, not the input mode, which is what crtc->mode
			 * usually contains. But since our current
			 * code puts a mode derived from the post-pfit timings
			 * into crtc->mode this works out correctly.
			 *
			 * This is crtc->mode and not crtc->state->mode for the
			 * fastboot check to work correctly.
			 */
			KLPR_DRM_DEBUG_KMS("looking for current mode on connector %s\n",
				      connector->name);
			modes[i] = &connector->state->crtc->mode;
		}
		/*
		 * In case of tiled modes, if all tiles are not present
		 * then fallback to a non tiled mode.
		 */
		if (connector->has_tile &&
		    num_tiled_conns < connector->num_h_tile * connector->num_v_tile) {
			KLPR_DRM_DEBUG_KMS("Falling back to non tiled mode on Connector %d\n",
				      connector->base.id);
			modes[i] = drm_connector_fallback_non_tiled_mode(connector);
		}
		crtcs[i] = new_crtc;

		KLPR_DRM_DEBUG_KMS("connector %s on [CRTC:%d:%s]: %dx%d%s\n",
			      connector->name,
			      connector->state->crtc->base.id,
			      connector->state->crtc->name,
			      modes[i]->hdisplay, modes[i]->vdisplay,
			      modes[i]->flags & DRM_MODE_FLAG_INTERLACE ? "i" : "");

		fallback = false;
		conn_configured |= BIT(i);
	}

	if ((conn_configured & mask) != mask && conn_configured != conn_seq)
		goto retry;

	/*
	 * If the BIOS didn't enable everything it could, fall back to have the
	 * same user experiencing of lighting up as much as possible like the
	 * fbdev helper library.
	 */
	if (num_connectors_enabled != num_connectors_detected &&
	    num_connectors_enabled < dev->mode_config.num_crtc) {
		KLPR_DRM_DEBUG_KMS("fallback: Not all outputs enabled\n");
		KLPR_DRM_DEBUG_KMS("Enabled: %i, detected: %i\n", num_connectors_enabled,
			      num_connectors_detected);
		fallback = true;
	}

	if (fallback) {
bail:
		KLPR_DRM_DEBUG_KMS("Not using firmware configuration\n");
		memcpy(enabled, save_enabled, count);
		ret = false;
	}

	(*klpe_drm_modeset_drop_locks)(&ctx);
	(*klpe_drm_modeset_acquire_fini)(&ctx);

	kfree(save_enabled);
	return ret;
}

int klpp_drm_client_modeset_probe(struct drm_client_dev *client, unsigned int width, unsigned int height)
{
	struct drm_connector *connector, **connectors = NULL;
	struct drm_connector_list_iter conn_iter;
	struct drm_device *dev = client->dev;
	unsigned int total_modes_count = 0;
	struct drm_client_offset *offsets;
	unsigned int connector_count = 0;
	/* points to modes protected by mode_config.mutex */
	struct drm_display_mode **modes;
	struct drm_crtc **crtcs;
	int i, ret = 0;
	bool *enabled;

	KLPR_DRM_DEBUG_KMS("\n");

	if (!width)
		width = dev->mode_config.max_width;
	if (!height)
		height = dev->mode_config.max_height;

	(*klpe_drm_connector_list_iter_begin)(dev, &conn_iter);
	klpr_drm_client_for_each_connector_iter(connector, &conn_iter) {
		struct drm_connector **tmp;

		tmp = krealloc(connectors, (connector_count + 1) * sizeof(*connectors), GFP_KERNEL);
		if (!tmp) {
			ret = -ENOMEM;
			goto free_connectors;
		}

		connectors = tmp;
		klpr_drm_connector_get(connector);
		connectors[connector_count++] = connector;
	}
	(*klpe_drm_connector_list_iter_end)(&conn_iter);

	if (!connector_count)
		return 0;

	crtcs = kcalloc(connector_count, sizeof(*crtcs), GFP_KERNEL);
	modes = kcalloc(connector_count, sizeof(*modes), GFP_KERNEL);
	offsets = kcalloc(connector_count, sizeof(*offsets), GFP_KERNEL);
	enabled = kcalloc(connector_count, sizeof(bool), GFP_KERNEL);
	if (!crtcs || !modes || !enabled || !offsets) {
		KLPR_DRM_ERROR("Memory allocation failed\n");
		ret = -ENOMEM;
		goto out;
	}

	mutex_lock(&client->modeset_mutex);

	mutex_lock(&dev->mode_config.mutex);
	for (i = 0; i < connector_count; i++)
		total_modes_count += connectors[i]->funcs->fill_modes(connectors[i], width, height);
	if (!total_modes_count)
		KLPR_DRM_DEBUG_KMS("No connectors reported connected with modes\n");
	klpr_drm_client_connectors_enabled(connectors, connector_count, enabled);

	if (!klpr_drm_client_firmware_config(client, connectors, connector_count, crtcs,
					modes, offsets, enabled, width, height)) {
		memset(modes, 0, connector_count * sizeof(*modes));
		memset(crtcs, 0, connector_count * sizeof(*crtcs));
		memset(offsets, 0, connector_count * sizeof(*offsets));

		if (!klpr_drm_client_target_cloned(dev, connectors, connector_count, modes,
					      offsets, enabled, width, height) &&
		    !klpr_drm_client_target_preferred(connectors, connector_count, modes,
						 offsets, enabled, width, height))
			KLPR_DRM_ERROR("Unable to find initial modes\n");

		KLPR_DRM_DEBUG_KMS("picking CRTCs for %dx%d config\n",
			      width, height);

		(*klpe_drm_client_pick_crtcs)(client, connectors, connector_count,
				      crtcs, modes, 0, width, height);
	}

	klpr_drm_client_modeset_release(client);

	for (i = 0; i < connector_count; i++) {
		struct drm_display_mode *mode = modes[i];
		struct drm_crtc *crtc = crtcs[i];
		struct drm_client_offset *offset = &offsets[i];

		if (mode && crtc) {
			struct drm_mode_set *modeset = drm_client_find_modeset(client, crtc);
			struct drm_connector *connector = connectors[i];

			KLPR_DRM_DEBUG_KMS("desired mode %s set on crtc %d (%d,%d)\n",
				      mode->name, crtc->base.id, offset->x, offset->y);

			if (WARN_ON_ONCE(modeset->num_connectors == DRM_CLIENT_MAX_CLONED_CONNECTORS ||
					 (dev->mode_config.num_crtc > 1 && modeset->num_connectors == 1))) {
				ret = -EINVAL;
				break;
			}

			modeset->mode = (*klpe_drm_mode_duplicate)(dev, mode);
			klpr_drm_connector_get(connector);
			modeset->connectors[modeset->num_connectors++] = connector;
			modeset->x = offset->x;
			modeset->y = offset->y;
		}
	}
	mutex_unlock(&dev->mode_config.mutex);

	mutex_unlock(&client->modeset_mutex);
out:
	kfree(crtcs);
	kfree(modes);
	kfree(offsets);
	kfree(enabled);
free_connectors:
	for (i = 0; i < connector_count; i++)
		klpr_drm_connector_put(connectors[i]);
	kfree(connectors);

	return ret;
}


#include "livepatch_bsc1225310.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "drm"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "__drm_dbg", (void *)&klpe___drm_dbg, "drm" },
	{ "__drm_err", (void *)&klpe___drm_err, "drm" },
	{ "drm_client_pick_crtcs", (void *)&klpe_drm_client_pick_crtcs,
	  "drm" },
	{ "drm_connector_list_iter_begin",
	  (void *)&klpe_drm_connector_list_iter_begin, "drm" },
	{ "drm_connector_list_iter_end",
	  (void *)&klpe_drm_connector_list_iter_end, "drm" },
	{ "drm_connector_list_iter_next",
	  (void *)&klpe_drm_connector_list_iter_next, "drm" },
	{ "drm_connector_pick_cmdline_mode",
	  (void *)&klpe_drm_connector_pick_cmdline_mode, "drm" },
	{ "drm_mode_destroy", (void *)&klpe_drm_mode_destroy, "drm" },
	{ "drm_mode_duplicate", (void *)&klpe_drm_mode_duplicate, "drm" },
	{ "drm_mode_find_dmt", (void *)&klpe_drm_mode_find_dmt, "drm" },
	{ "drm_mode_match", (void *)&klpe_drm_mode_match, "drm" },
	{ "drm_mode_object_get", (void *)&klpe_drm_mode_object_get, "drm" },
	{ "drm_mode_object_put", (void *)&klpe_drm_mode_object_put, "drm" },
	{ "drm_modeset_acquire_fini", (void *)&klpe_drm_modeset_acquire_fini,
	  "drm" },
	{ "drm_modeset_acquire_init", (void *)&klpe_drm_modeset_acquire_init,
	  "drm" },
	{ "drm_modeset_backoff", (void *)&klpe_drm_modeset_backoff, "drm" },
	{ "drm_modeset_drop_locks", (void *)&klpe_drm_modeset_drop_locks,
	  "drm" },
	{ "drm_modeset_lock_all_ctx", (void *)&klpe_drm_modeset_lock_all_ctx,
	  "drm" },
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

int livepatch_bsc1225310_init(void)
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

void livepatch_bsc1225310_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}
