/*
 * bsc1212348_drivers_gpu_drm_vmwgfx_vmwgfx_execbuf
 *
 * Fix for CVE-2023-33952, bsc#1212348
 *
 *  Copyright (c) 2023 SUSE
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

#if IS_ENABLED(CONFIG_DRM_VMWGFX)

#if !IS_MODULE(CONFIG_DRM_VMWGFX)
#error "Live patch supports only CONFIG=m"
#endif

#include "livepatch_bsc1212348.h"

/* klp-ccp: from include/linux/sync_file.h */
#include <linux/ktime.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/dma-fence.h>
#include <linux/dma-fence-array.h>

struct sync_file *sync_file_create(struct dma_fence *fence);

/* klp-ccp: from drivers/gpu/drm/vmwgfx/vmwgfx_drv.h */
#include <linux/suspend.h>
#include <linux/sync_file.h>

struct drm_lock_data;

/* klp-ccp: from drivers/gpu/drm/vmwgfx/vmwgfx_drv.h */
#include <drm/drm_device.h>
#include <drm/drm_file.h>
#include <drm/ttm/ttm_bo_driver.h>

/* klp-ccp: from include/drm/drm_print.h */
static __printf(2, 3)
void (*klpe___drm_dbg)(enum drm_debug_category category, const char *format, ...);
static __printf(1, 2)
void (*klpe___drm_err)(const char *format, ...);

/* klp-ccp: from include/drm/ttm/ttm_bo_api.h */
static void (*klpe_ttm_bo_put)(struct ttm_buffer_object *bo);

static int (*klpe_ttm_eu_reserve_buffers)(struct ww_acquire_ctx *ticket,
			   struct list_head *list, bool intr,
			   struct list_head *dups);

static void (*klpe_ttm_eu_fence_buffer_objects)(struct ww_acquire_ctx *ticket,
				 struct list_head *list,
				 struct dma_fence *fence);

/* klp-ccp: from drivers/gpu/drm/vmwgfx/ttm_object.h */
#include <linux/dma-buf.h>
#include <linux/kref.h>
#include <linux/list.h>
#include <linux/rcupdate.h>
/* klp-ccp: from drivers/gpu/drm/vmwgfx/vmwgfx_hashtab.h */
#include <linux/list.h>

struct vmwgfx_open_hash {
	struct hlist_head *table;
	u8 order;
};

static int (*klpe_vmwgfx_ht_create)(struct vmwgfx_open_hash *ht, unsigned int order);

/* klp-ccp: from drivers/gpu/drm/vmwgfx/vmwgfx_fence.h */
#ifndef _VMWGFX_FENCE_H_

#include <linux/dma-fence.h>
#include <linux/dma-fence-array.h>

#define VMW_FENCE_WAIT_TIMEOUT (5*HZ)

struct vmw_fence_obj {
	struct dma_fence base;

	struct list_head head;
	struct list_head seq_passed_actions;
	void (*destroy)(struct vmw_fence_obj *fence);
};

static inline void
vmw_fence_obj_unreference(struct vmw_fence_obj **fence_p)
{
	struct vmw_fence_obj *fence = *fence_p;

	*fence_p = NULL;
	if (fence)
		dma_fence_put(&fence->base);
}

static int (*klpe_vmw_fence_obj_wait)(struct vmw_fence_obj *fence,
			      bool lazy,
			      bool interruptible, unsigned long timeout);

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif /* _VMWGFX_FENCE_H_ */

/* klp-ccp: from drivers/gpu/drm/vmwgfx/vmwgfx_reg.h */
#include <linux/types.h>
/* klp-ccp: from drivers/gpu/drm/vmwgfx/device_include/vm_basic_types.h */
#include <linux/kernel.h>
#include <linux/mm.h>
#include <asm/page.h>

typedef s32 int32;
typedef u64 uint64;

typedef u8  uint8;

#define MBYTES_SHIFT 20

#define MBYTES_2_BYTES(_nbytes) ((uint64)(_nbytes) << MBYTES_SHIFT)

/* klp-ccp: from drivers/gpu/drm/vmwgfx/device_include/svga_reg.h */
typedef uint32 SVGAMobId;

typedef struct SVGAGuestPtr {
	uint32 gmrId;
	uint32 offset;
} SVGAGuestPtr;

#define SVGA_CB_MAX_SIZE_4MB (MBYTES_2_BYTES(4))
#define SVGA_CB_MAX_SIZE SVGA_CB_MAX_SIZE_4MB

typedef struct SVGAGMRImageFormat {
	union {
		struct {
			uint32 bitsPerPixel : 8;
			uint32 colorDepth : 8;
			uint32 reserved : 16;
		};

		uint32 value;
	};
} SVGAGMRImageFormat;

typedef struct SVGAGuestImage {
	SVGAGuestPtr ptr;

	uint32 pitch;
} SVGAGuestImage;

typedef struct {
	int32 left;
	int32 top;
	int32 right;
	int32 bottom;
} SVGASignedRect;

typedef struct {
	int32 x;
	int32 y;
} SVGASignedPoint;

#define SVGA_CAP_GBOBJECTS 0x08000000

enum {
	SVGA_CMD_INVALID_CMD = 0,
	SVGA_CMD_UPDATE = 1,
	SVGA_CMD_RECT_COPY = 3,
	SVGA_CMD_RECT_ROP_COPY = 14,
	SVGA_CMD_DEFINE_CURSOR = 19,
	SVGA_CMD_DEFINE_ALPHA_CURSOR = 22,
	SVGA_CMD_UPDATE_VERBOSE = 25,
	SVGA_CMD_FRONT_ROP_FILL = 29,
	SVGA_CMD_FENCE = 30,
	SVGA_CMD_ESCAPE = 33,
	SVGA_CMD_DEFINE_SCREEN = 34,
	SVGA_CMD_DESTROY_SCREEN = 35,
	SVGA_CMD_DEFINE_GMRFB = 36,
	SVGA_CMD_BLIT_GMRFB_TO_SCREEN = 37,
	SVGA_CMD_BLIT_SCREEN_TO_GMRFB = 38,
	SVGA_CMD_ANNOTATION_FILL = 39,
	SVGA_CMD_ANNOTATION_COPY = 40,
	SVGA_CMD_DEFINE_GMR2 = 41,
	SVGA_CMD_REMAP_GMR2 = 42,
	SVGA_CMD_DEAD = 43,
	SVGA_CMD_DEAD_2 = 44,
	SVGA_CMD_NOP = 45,
	SVGA_CMD_NOP_ERROR = 46,
	SVGA_CMD_MAX
};

typedef struct {
	uint32 x;
	uint32 y;
	uint32 width;
	uint32 height;
} SVGAFifoCmdUpdate;

typedef struct {
	SVGAGuestPtr ptr;
	uint32 bytesPerLine;
	SVGAGMRImageFormat format;
} SVGAFifoCmdDefineGMRFB;

typedef struct {
	SVGASignedPoint srcOrigin;
	SVGASignedRect destRect;
	uint32 destScreenId;
} SVGAFifoCmdBlitGMRFBToScreen;

/* klp-ccp: from drivers/gpu/drm/vmwgfx/device_include/svga3d_types.h */
#define SVGA3D_INVALID_ID ((uint32)-1)

typedef enum {
	SVGA3D_SHADERTYPE_INVALID = 0,
	SVGA3D_SHADERTYPE_MIN = 1,
	SVGA3D_SHADERTYPE_VS = 1,
	SVGA3D_SHADERTYPE_PS = 2,
	SVGA3D_SHADERTYPE_PREDX_MAX = 3,
	SVGA3D_SHADERTYPE_GS = 3,
	SVGA3D_SHADERTYPE_DX10_MAX = 4,
	SVGA3D_SHADERTYPE_HS = 4,
	SVGA3D_SHADERTYPE_DS = 5,
	SVGA3D_SHADERTYPE_CS = 6,
	SVGA3D_SHADERTYPE_MAX = 7
} SVGA3dShaderType;

typedef enum {
	SVGA3D_QUERYTYPE_INVALID = ((uint8)-1),
	SVGA3D_QUERYTYPE_MIN = 0,
	SVGA3D_QUERYTYPE_OCCLUSION = 0,
	SVGA3D_QUERYTYPE_TIMESTAMP = 1,
	SVGA3D_QUERYTYPE_TIMESTAMPDISJOINT = 2,
	SVGA3D_QUERYTYPE_PIPELINESTATS = 3,
	SVGA3D_QUERYTYPE_OCCLUSIONPREDICATE = 4,
	SVGA3D_QUERYTYPE_STREAMOUTPUTSTATS = 5,
	SVGA3D_QUERYTYPE_STREAMOVERFLOWPREDICATE = 6,
	SVGA3D_QUERYTYPE_OCCLUSION64 = 7,
	SVGA3D_QUERYTYPE_DX10_MAX = 8,
	SVGA3D_QUERYTYPE_SOSTATS_STREAM0 = 8,
	SVGA3D_QUERYTYPE_SOSTATS_STREAM1 = 9,
	SVGA3D_QUERYTYPE_SOSTATS_STREAM2 = 10,
	SVGA3D_QUERYTYPE_SOSTATS_STREAM3 = 11,
	SVGA3D_QUERYTYPE_SOP_STREAM0 = 12,
	SVGA3D_QUERYTYPE_SOP_STREAM1 = 13,
	SVGA3D_QUERYTYPE_SOP_STREAM2 = 14,
	SVGA3D_QUERYTYPE_SOP_STREAM3 = 15,
	SVGA3D_QUERYTYPE_MAX
} SVGA3dQueryType;

typedef enum {
	SVGA3D_WRITE_HOST_VRAM = 1,
	SVGA3D_READ_HOST_VRAM = 2,
} SVGA3dTransferType;

typedef struct SVGA3dSurfaceImageId {
	uint32 sid;
	uint32 face;
	uint32 mipmap;
} SVGA3dSurfaceImageId;

/* klp-ccp: from drivers/gpu/drm/vmwgfx/device_include/svga3d_cmd.h */
enum SVGAFifo3dCmdId {
	SVGA_3D_CMD_LEGACY_BASE = 1000,
	SVGA_3D_CMD_BASE = 1040,

	SVGA_3D_CMD_SURFACE_DEFINE = 1040,
	SVGA_3D_CMD_SURFACE_DESTROY = 1041,
	SVGA_3D_CMD_SURFACE_COPY = 1042,
	SVGA_3D_CMD_SURFACE_STRETCHBLT = 1043,
	SVGA_3D_CMD_SURFACE_DMA = 1044,
	SVGA_3D_CMD_CONTEXT_DEFINE = 1045,
	SVGA_3D_CMD_CONTEXT_DESTROY = 1046,
	SVGA_3D_CMD_SETTRANSFORM = 1047,
	SVGA_3D_CMD_SETZRANGE = 1048,
	SVGA_3D_CMD_SETRENDERSTATE = 1049,
	SVGA_3D_CMD_SETRENDERTARGET = 1050,
	SVGA_3D_CMD_SETTEXTURESTATE = 1051,
	SVGA_3D_CMD_SETMATERIAL = 1052,
	SVGA_3D_CMD_SETLIGHTDATA = 1053,
	SVGA_3D_CMD_SETLIGHTENABLED = 1054,
	SVGA_3D_CMD_SETVIEWPORT = 1055,
	SVGA_3D_CMD_SETCLIPPLANE = 1056,
	SVGA_3D_CMD_CLEAR = 1057,
	SVGA_3D_CMD_PRESENT = 1058,
	SVGA_3D_CMD_SHADER_DEFINE = 1059,
	SVGA_3D_CMD_SHADER_DESTROY = 1060,
	SVGA_3D_CMD_SET_SHADER = 1061,
	SVGA_3D_CMD_SET_SHADER_CONST = 1062,
	SVGA_3D_CMD_DRAW_PRIMITIVES = 1063,
	SVGA_3D_CMD_SETSCISSORRECT = 1064,
	SVGA_3D_CMD_BEGIN_QUERY = 1065,
	SVGA_3D_CMD_END_QUERY = 1066,
	SVGA_3D_CMD_WAIT_FOR_QUERY = 1067,
	SVGA_3D_CMD_PRESENT_READBACK = 1068,
	SVGA_3D_CMD_BLIT_SURFACE_TO_SCREEN = 1069,
	SVGA_3D_CMD_SURFACE_DEFINE_V2 = 1070,
	SVGA_3D_CMD_GENERATE_MIPMAPS = 1071,
	SVGA_3D_CMD_DEAD4 = 1072,
	SVGA_3D_CMD_DEAD5 = 1073,
	SVGA_3D_CMD_DEAD6 = 1074,
	SVGA_3D_CMD_DEAD7 = 1075,
	SVGA_3D_CMD_DEAD8 = 1076,
	SVGA_3D_CMD_DEAD9 = 1077,
	SVGA_3D_CMD_DEAD10 = 1078,
	SVGA_3D_CMD_DEAD11 = 1079,
	SVGA_3D_CMD_ACTIVATE_SURFACE = 1080,
	SVGA_3D_CMD_DEACTIVATE_SURFACE = 1081,
	SVGA_3D_CMD_SCREEN_DMA = 1082,
	SVGA_3D_CMD_DEAD1 = 1083,
	SVGA_3D_CMD_DEAD2 = 1084,

	SVGA_3D_CMD_DEAD12 = 1085,
	SVGA_3D_CMD_DEAD13 = 1086,
	SVGA_3D_CMD_DEAD14 = 1087,
	SVGA_3D_CMD_DEAD15 = 1088,
	SVGA_3D_CMD_DEAD16 = 1089,
	SVGA_3D_CMD_DEAD17 = 1090,

	SVGA_3D_CMD_SET_OTABLE_BASE = 1091,
	SVGA_3D_CMD_READBACK_OTABLE = 1092,

	SVGA_3D_CMD_DEFINE_GB_MOB = 1093,
	SVGA_3D_CMD_DESTROY_GB_MOB = 1094,
	SVGA_3D_CMD_DEAD3 = 1095,
	SVGA_3D_CMD_UPDATE_GB_MOB_MAPPING = 1096,

	SVGA_3D_CMD_DEFINE_GB_SURFACE = 1097,
	SVGA_3D_CMD_DESTROY_GB_SURFACE = 1098,
	SVGA_3D_CMD_BIND_GB_SURFACE = 1099,
	SVGA_3D_CMD_COND_BIND_GB_SURFACE = 1100,
	SVGA_3D_CMD_UPDATE_GB_IMAGE = 1101,
	SVGA_3D_CMD_UPDATE_GB_SURFACE = 1102,
	SVGA_3D_CMD_READBACK_GB_IMAGE = 1103,
	SVGA_3D_CMD_READBACK_GB_SURFACE = 1104,
	SVGA_3D_CMD_INVALIDATE_GB_IMAGE = 1105,
	SVGA_3D_CMD_INVALIDATE_GB_SURFACE = 1106,

	SVGA_3D_CMD_DEFINE_GB_CONTEXT = 1107,
	SVGA_3D_CMD_DESTROY_GB_CONTEXT = 1108,
	SVGA_3D_CMD_BIND_GB_CONTEXT = 1109,
	SVGA_3D_CMD_READBACK_GB_CONTEXT = 1110,
	SVGA_3D_CMD_INVALIDATE_GB_CONTEXT = 1111,

	SVGA_3D_CMD_DEFINE_GB_SHADER = 1112,
	SVGA_3D_CMD_DESTROY_GB_SHADER = 1113,
	SVGA_3D_CMD_BIND_GB_SHADER = 1114,

	SVGA_3D_CMD_SET_OTABLE_BASE64 = 1115,

	SVGA_3D_CMD_BEGIN_GB_QUERY = 1116,
	SVGA_3D_CMD_END_GB_QUERY = 1117,
	SVGA_3D_CMD_WAIT_FOR_GB_QUERY = 1118,

	SVGA_3D_CMD_NOP = 1119,

	SVGA_3D_CMD_ENABLE_GART = 1120,
	SVGA_3D_CMD_DISABLE_GART = 1121,
	SVGA_3D_CMD_MAP_MOB_INTO_GART = 1122,
	SVGA_3D_CMD_UNMAP_GART_RANGE = 1123,

	SVGA_3D_CMD_DEFINE_GB_SCREENTARGET = 1124,
	SVGA_3D_CMD_DESTROY_GB_SCREENTARGET = 1125,
	SVGA_3D_CMD_BIND_GB_SCREENTARGET = 1126,
	SVGA_3D_CMD_UPDATE_GB_SCREENTARGET = 1127,

	SVGA_3D_CMD_READBACK_GB_IMAGE_PARTIAL = 1128,
	SVGA_3D_CMD_INVALIDATE_GB_IMAGE_PARTIAL = 1129,

	SVGA_3D_CMD_SET_GB_SHADERCONSTS_INLINE = 1130,

	SVGA_3D_CMD_GB_SCREEN_DMA = 1131,
	SVGA_3D_CMD_BIND_GB_SURFACE_WITH_PITCH = 1132,
	SVGA_3D_CMD_GB_MOB_FENCE = 1133,
	SVGA_3D_CMD_DEFINE_GB_SURFACE_V2 = 1134,
	SVGA_3D_CMD_DEFINE_GB_MOB64 = 1135,
	SVGA_3D_CMD_REDEFINE_GB_MOB64 = 1136,
	SVGA_3D_CMD_NOP_ERROR = 1137,

	SVGA_3D_CMD_SET_VERTEX_STREAMS = 1138,
	SVGA_3D_CMD_SET_VERTEX_DECLS = 1139,
	SVGA_3D_CMD_SET_VERTEX_DIVISORS = 1140,
	SVGA_3D_CMD_DRAW = 1141,
	SVGA_3D_CMD_DRAW_INDEXED = 1142,

	SVGA_3D_CMD_DX_MIN = 1143,
	SVGA_3D_CMD_DX_DEFINE_CONTEXT = 1143,
	SVGA_3D_CMD_DX_DESTROY_CONTEXT = 1144,
	SVGA_3D_CMD_DX_BIND_CONTEXT = 1145,
	SVGA_3D_CMD_DX_READBACK_CONTEXT = 1146,
	SVGA_3D_CMD_DX_INVALIDATE_CONTEXT = 1147,
	SVGA_3D_CMD_DX_SET_SINGLE_CONSTANT_BUFFER = 1148,
	SVGA_3D_CMD_DX_SET_SHADER_RESOURCES = 1149,
	SVGA_3D_CMD_DX_SET_SHADER = 1150,
	SVGA_3D_CMD_DX_SET_SAMPLERS = 1151,
	SVGA_3D_CMD_DX_DRAW = 1152,
	SVGA_3D_CMD_DX_DRAW_INDEXED = 1153,
	SVGA_3D_CMD_DX_DRAW_INSTANCED = 1154,
	SVGA_3D_CMD_DX_DRAW_INDEXED_INSTANCED = 1155,
	SVGA_3D_CMD_DX_DRAW_AUTO = 1156,
	SVGA_3D_CMD_DX_SET_INPUT_LAYOUT = 1157,
	SVGA_3D_CMD_DX_SET_VERTEX_BUFFERS = 1158,
	SVGA_3D_CMD_DX_SET_INDEX_BUFFER = 1159,
	SVGA_3D_CMD_DX_SET_TOPOLOGY = 1160,
	SVGA_3D_CMD_DX_SET_RENDERTARGETS = 1161,
	SVGA_3D_CMD_DX_SET_BLEND_STATE = 1162,
	SVGA_3D_CMD_DX_SET_DEPTHSTENCIL_STATE = 1163,
	SVGA_3D_CMD_DX_SET_RASTERIZER_STATE = 1164,
	SVGA_3D_CMD_DX_DEFINE_QUERY = 1165,
	SVGA_3D_CMD_DX_DESTROY_QUERY = 1166,
	SVGA_3D_CMD_DX_BIND_QUERY = 1167,
	SVGA_3D_CMD_DX_SET_QUERY_OFFSET = 1168,
	SVGA_3D_CMD_DX_BEGIN_QUERY = 1169,
	SVGA_3D_CMD_DX_END_QUERY = 1170,
	SVGA_3D_CMD_DX_READBACK_QUERY = 1171,
	SVGA_3D_CMD_DX_SET_PREDICATION = 1172,
	SVGA_3D_CMD_DX_SET_SOTARGETS = 1173,
	SVGA_3D_CMD_DX_SET_VIEWPORTS = 1174,
	SVGA_3D_CMD_DX_SET_SCISSORRECTS = 1175,
	SVGA_3D_CMD_DX_CLEAR_RENDERTARGET_VIEW = 1176,
	SVGA_3D_CMD_DX_CLEAR_DEPTHSTENCIL_VIEW = 1177,
	SVGA_3D_CMD_DX_PRED_COPY_REGION = 1178,
	SVGA_3D_CMD_DX_PRED_COPY = 1179,
	SVGA_3D_CMD_DX_PRESENTBLT = 1180,
	SVGA_3D_CMD_DX_GENMIPS = 1181,
	SVGA_3D_CMD_DX_UPDATE_SUBRESOURCE = 1182,
	SVGA_3D_CMD_DX_READBACK_SUBRESOURCE = 1183,
	SVGA_3D_CMD_DX_INVALIDATE_SUBRESOURCE = 1184,
	SVGA_3D_CMD_DX_DEFINE_SHADERRESOURCE_VIEW = 1185,
	SVGA_3D_CMD_DX_DESTROY_SHADERRESOURCE_VIEW = 1186,
	SVGA_3D_CMD_DX_DEFINE_RENDERTARGET_VIEW = 1187,
	SVGA_3D_CMD_DX_DESTROY_RENDERTARGET_VIEW = 1188,
	SVGA_3D_CMD_DX_DEFINE_DEPTHSTENCIL_VIEW = 1189,
	SVGA_3D_CMD_DX_DESTROY_DEPTHSTENCIL_VIEW = 1190,
	SVGA_3D_CMD_DX_DEFINE_ELEMENTLAYOUT = 1191,
	SVGA_3D_CMD_DX_DESTROY_ELEMENTLAYOUT = 1192,
	SVGA_3D_CMD_DX_DEFINE_BLEND_STATE = 1193,
	SVGA_3D_CMD_DX_DESTROY_BLEND_STATE = 1194,
	SVGA_3D_CMD_DX_DEFINE_DEPTHSTENCIL_STATE = 1195,
	SVGA_3D_CMD_DX_DESTROY_DEPTHSTENCIL_STATE = 1196,
	SVGA_3D_CMD_DX_DEFINE_RASTERIZER_STATE = 1197,
	SVGA_3D_CMD_DX_DESTROY_RASTERIZER_STATE = 1198,
	SVGA_3D_CMD_DX_DEFINE_SAMPLER_STATE = 1199,
	SVGA_3D_CMD_DX_DESTROY_SAMPLER_STATE = 1200,
	SVGA_3D_CMD_DX_DEFINE_SHADER = 1201,
	SVGA_3D_CMD_DX_DESTROY_SHADER = 1202,
	SVGA_3D_CMD_DX_BIND_SHADER = 1203,
	SVGA_3D_CMD_DX_DEFINE_STREAMOUTPUT = 1204,
	SVGA_3D_CMD_DX_DESTROY_STREAMOUTPUT = 1205,
	SVGA_3D_CMD_DX_SET_STREAMOUTPUT = 1206,
	SVGA_3D_CMD_DX_SET_COTABLE = 1207,
	SVGA_3D_CMD_DX_READBACK_COTABLE = 1208,
	SVGA_3D_CMD_DX_BUFFER_COPY = 1209,
	SVGA_3D_CMD_DX_TRANSFER_FROM_BUFFER = 1210,
	SVGA_3D_CMD_DX_SURFACE_COPY_AND_READBACK = 1211,
	SVGA_3D_CMD_DX_MOVE_QUERY = 1212,
	SVGA_3D_CMD_DX_BIND_ALL_QUERY = 1213,
	SVGA_3D_CMD_DX_READBACK_ALL_QUERY = 1214,
	SVGA_3D_CMD_DX_PRED_TRANSFER_FROM_BUFFER = 1215,
	SVGA_3D_CMD_DX_MOB_FENCE_64 = 1216,
	SVGA_3D_CMD_DX_BIND_ALL_SHADER = 1217,
	SVGA_3D_CMD_DX_HINT = 1218,
	SVGA_3D_CMD_DX_BUFFER_UPDATE = 1219,
	SVGA_3D_CMD_DX_SET_VS_CONSTANT_BUFFER_OFFSET = 1220,
	SVGA_3D_CMD_DX_SET_PS_CONSTANT_BUFFER_OFFSET = 1221,
	SVGA_3D_CMD_DX_SET_GS_CONSTANT_BUFFER_OFFSET = 1222,
	SVGA_3D_CMD_DX_SET_HS_CONSTANT_BUFFER_OFFSET = 1223,
	SVGA_3D_CMD_DX_SET_DS_CONSTANT_BUFFER_OFFSET = 1224,
	SVGA_3D_CMD_DX_SET_CS_CONSTANT_BUFFER_OFFSET = 1225,

	SVGA_3D_CMD_DX_COND_BIND_ALL_SHADER = 1226,
	SVGA_3D_CMD_DX_MAX = 1227,

	SVGA_3D_CMD_SCREEN_COPY = 1227,

	SVGA_3D_CMD_RESERVED1 = 1228,
	SVGA_3D_CMD_RESERVED2 = 1229,
	SVGA_3D_CMD_RESERVED3 = 1230,
	SVGA_3D_CMD_RESERVED4 = 1231,
	SVGA_3D_CMD_RESERVED5 = 1232,
	SVGA_3D_CMD_RESERVED6 = 1233,
	SVGA_3D_CMD_RESERVED7 = 1234,
	SVGA_3D_CMD_RESERVED8 = 1235,

	SVGA_3D_CMD_GROW_OTABLE = 1236,
	SVGA_3D_CMD_DX_GROW_COTABLE = 1237,
	SVGA_3D_CMD_INTRA_SURFACE_COPY = 1238,

	SVGA_3D_CMD_DEFINE_GB_SURFACE_V3 = 1239,

	SVGA_3D_CMD_DX_RESOLVE_COPY = 1240,
	SVGA_3D_CMD_DX_PRED_RESOLVE_COPY = 1241,
	SVGA_3D_CMD_DX_PRED_CONVERT_REGION = 1242,
	SVGA_3D_CMD_DX_PRED_CONVERT = 1243,
	SVGA_3D_CMD_WHOLE_SURFACE_COPY = 1244,

	SVGA_3D_CMD_DX_DEFINE_UA_VIEW = 1245,
	SVGA_3D_CMD_DX_DESTROY_UA_VIEW = 1246,
	SVGA_3D_CMD_DX_CLEAR_UA_VIEW_UINT = 1247,
	SVGA_3D_CMD_DX_CLEAR_UA_VIEW_FLOAT = 1248,
	SVGA_3D_CMD_DX_COPY_STRUCTURE_COUNT = 1249,
	SVGA_3D_CMD_DX_SET_UA_VIEWS = 1250,

	SVGA_3D_CMD_DX_DRAW_INDEXED_INSTANCED_INDIRECT = 1251,
	SVGA_3D_CMD_DX_DRAW_INSTANCED_INDIRECT = 1252,
	SVGA_3D_CMD_DX_DISPATCH = 1253,
	SVGA_3D_CMD_DX_DISPATCH_INDIRECT = 1254,

	SVGA_3D_CMD_WRITE_ZERO_SURFACE = 1255,
	SVGA_3D_CMD_UPDATE_ZERO_SURFACE = 1256,
	SVGA_3D_CMD_DX_TRANSFER_TO_BUFFER = 1257,
	SVGA_3D_CMD_DX_SET_STRUCTURE_COUNT = 1258,

	SVGA_3D_CMD_LOGICOPS_BITBLT = 1259,
	SVGA_3D_CMD_LOGICOPS_TRANSBLT = 1260,
	SVGA_3D_CMD_LOGICOPS_STRETCHBLT = 1261,
	SVGA_3D_CMD_LOGICOPS_COLORFILL = 1262,
	SVGA_3D_CMD_LOGICOPS_ALPHABLEND = 1263,
	SVGA_3D_CMD_LOGICOPS_CLEARTYPEBLEND = 1264,

	SVGA_3D_CMD_DX_COPY_COTABLE_INTO_MOB = 1265,

	SVGA_3D_CMD_UPDATE_GB_SCREENTARGET_V2 = 1266,

	SVGA_3D_CMD_DEFINE_GB_SURFACE_V4 = 1267,
	SVGA_3D_CMD_DX_SET_CS_UA_VIEWS = 1268,
	SVGA_3D_CMD_DX_SET_MIN_LOD = 1269,

	SVGA_3D_CMD_DX_DEFINE_DEPTHSTENCIL_VIEW_V2 = 1272,
	SVGA_3D_CMD_DX_DEFINE_STREAMOUTPUT_WITH_MOB = 1273,
	SVGA_3D_CMD_DX_SET_SHADER_IFACE = 1274,
	SVGA_3D_CMD_DX_BIND_STREAMOUTPUT = 1275,
	SVGA_3D_CMD_SURFACE_STRETCHBLT_NON_MS_TO_MS = 1276,
	SVGA_3D_CMD_DX_BIND_SHADER_IFACE = 1277,

	SVGA_3D_CMD_UPDATE_GB_SCREENTARGET_MOVE = 1278,

	SVGA_3D_CMD_DX_PRED_STAGING_COPY = 1281,
	SVGA_3D_CMD_DX_STAGING_COPY = 1282,
	SVGA_3D_CMD_DX_PRED_STAGING_COPY_REGION = 1283,
	SVGA_3D_CMD_DX_SET_VERTEX_BUFFERS_V2 = 1284,
	SVGA_3D_CMD_DX_SET_INDEX_BUFFER_V2 = 1285,
	SVGA_3D_CMD_DX_SET_VERTEX_BUFFERS_OFFSET_AND_SIZE = 1286,
	SVGA_3D_CMD_DX_SET_INDEX_BUFFER_OFFSET_AND_SIZE = 1287,
	SVGA_3D_CMD_DX_DEFINE_RASTERIZER_STATE_V2 = 1288,
	SVGA_3D_CMD_DX_PRED_STAGING_CONVERT_REGION = 1289,
	SVGA_3D_CMD_DX_PRED_STAGING_CONVERT = 1290,
	SVGA_3D_CMD_DX_STAGING_BUFFER_COPY = 1291,

	SVGA_3D_CMD_MAX = 1303,
	SVGA_3D_CMD_FUTURE_MAX = 3000
};

typedef struct {
	uint32 discard : 1;

	uint32 unsynchronized : 1;

	uint32 reserved : 30;
} SVGA3dSurfaceDMAFlags;

typedef struct {
	SVGAGuestImage guest;
	SVGA3dSurfaceImageId host;
	SVGA3dTransferType transfer;

} SVGA3dCmdSurfaceDMA;

typedef struct {
	uint32 suffixSize;

	uint32 maximumOffset;

	SVGA3dSurfaceDMAFlags flags;
} SVGA3dCmdSurfaceDMASuffix;

typedef struct {
	uint32 cid;
	SVGA3dQueryType type;
	SVGAGuestPtr guestResult;
} SVGA3dCmdEndQuery;

typedef struct {
	uint32 cid;
	SVGA3dQueryType type;
	SVGAGuestPtr guestResult;
} SVGA3dCmdWaitForQuery;

typedef struct SVGA3dCmdBindGBSurface {
	uint32 sid;
	SVGAMobId mobid;
} SVGA3dCmdBindGBSurface;

typedef struct SVGA3dCmdBindGBShader {
	uint32 shid;
	SVGAMobId mobid;
	uint32 offsetInBytes;
} SVGA3dCmdBindGBShader;

typedef struct {
	uint32 cid;
	SVGA3dQueryType type;
	SVGAMobId mobid;
	uint32 offset;
} SVGA3dCmdEndGBQuery;

typedef struct {
	uint32 cid;
	SVGA3dQueryType type;
	SVGAMobId mobid;
	uint32 offset;
} SVGA3dCmdWaitForGBQuery;

/* klp-ccp: from drivers/gpu/drm/vmwgfx/device_include/svga3d_dx.h */
typedef uint32 SVGA3dQueryId;
typedef uint32 SVGA3dStreamOutputId;

typedef struct SVGA3dCmdDXBindQuery {
	SVGA3dQueryId queryId;
	SVGAMobId mobid;
} SVGA3dCmdDXBindQuery;

typedef struct SVGA3dCmdDXBindAllQuery {
	uint32 cid;
	SVGAMobId mobid;
} SVGA3dCmdDXBindAllQuery;

typedef struct SVGA3dCmdDXBindShader {
	uint32 cid;
	uint32 shid;
	SVGAMobId mobid;
	uint32 offsetInBytes;
} SVGA3dCmdDXBindShader;

typedef struct SVGA3dCmdDXBindStreamOutput {
	SVGA3dStreamOutputId soid;
	uint32 mobid;
	uint32 offsetInBytes;
	uint32 sizeInBytes;
} SVGA3dCmdDXBindStreamOutput;

/* klp-ccp: from drivers/gpu/drm/vmwgfx/vmwgfx_validation.h */
#include <linux/list.h>
#include <linux/ww_mutex.h>
#include <drm/ttm/ttm_execbuf_util.h>

#define VMW_RES_DIRTY_NONE 0
#define VMW_RES_DIRTY_SET BIT(0)

struct vmw_validation_context {
	struct vmwgfx_open_hash *ht;
	struct list_head resource_list;
	struct list_head resource_ctx_list;
	struct list_head bo_list;
	struct list_head page_list;
	struct ww_acquire_ctx ticket;
	struct mutex *res_mutex;
	unsigned int merge_dups;
	unsigned int mem_size_left;
	u8 *page_address;
	struct vmw_validation_mem *vm;
	size_t vm_size_left;
	size_t total_mem;
};

struct vmw_buffer_object;

#define DECLARE_VAL_CONTEXT(_name, _ht, _merge_dups)			\
	struct vmw_validation_context _name =				\
	{ .ht = _ht,							\
	  .resource_list = LIST_HEAD_INIT((_name).resource_list),	\
	  .resource_ctx_list = LIST_HEAD_INIT((_name).resource_ctx_list), \
	  .bo_list = LIST_HEAD_INIT((_name).bo_list),			\
	  .page_list = LIST_HEAD_INIT((_name).page_list),		\
	  .res_mutex = NULL,						\
	  .merge_dups = _merge_dups,					\
	  .mem_size_left = 0,						\
	}

/* NOTE: this is deprecated in favor of pr_err(). */
#define KLPR_DRM_ERROR(fmt, ...)						\
	(*klpe___drm_err)(fmt, ##__VA_ARGS__)

#define KLPR_DRM_DEBUG_DRIVER(fmt, ...)					     \
	(*klpe___drm_dbg)(DRM_UT_DRIVER, fmt, ##__VA_ARGS__)

#define KLPR_VMW_DEBUG_USER(fmt, ...)						   \
	KLPR_DRM_DEBUG_DRIVER(fmt, ##__VA_ARGS__)

#define KLPR_VMW_GET_CTX_NODE(__sw_context)					   \
({									      \
	__sw_context->dx_ctx_node ? __sw_context->dx_ctx_node : ({	      \
		KLPR_VMW_DEBUG_USER("SM context is not set at %s\n", __func__);	   \
		__sw_context->dx_ctx_node;				      \
	});								      \
})

#define KLPR_VMW_CMD_CTX_RESERVE(__priv, __bytes, __ctx_id)			\
({										\
	(*klpe_vmw_cmd_ctx_reserve)(__priv, __bytes, __ctx_id) ? : ({		\
		KLPR_DRM_ERROR("FIFO reserve failed at %s for %u bytes\n",	\
			  __func__, (unsigned int) __bytes);			\
		NULL;								\
	});									\
})

#define KLPR_VMW_CMD_RESERVE(__priv, __bytes)					\
	KLPR_VMW_CMD_CTX_RESERVE(__priv, __bytes, SVGA3D_INVALID_ID)

static inline int
klpr_vmw_validation_bo_reserve(struct vmw_validation_context *ctx,
			  bool intr)
{
	return (*klpe_ttm_eu_reserve_buffers)(&ctx->ticket, &ctx->bo_list, intr,
				      NULL);
}

static inline void
klpr_vmw_validation_bo_fence(struct vmw_validation_context *ctx,
			struct vmw_fence_obj *fence)
{
	(*klpe_ttm_eu_fence_buffer_objects)(&ctx->ticket, &ctx->bo_list,
				    (void *) fence);
}

static int (*klpe_vmw_validation_add_bo)(struct vmw_validation_context *ctx,
			  struct vmw_buffer_object *vbo,
			  bool as_mob, bool cpu_blit);

static int (*klpe_vmw_validation_bo_validate)(struct vmw_validation_context *ctx, bool intr);
static void (*klpe_vmw_validation_unref_lists)(struct vmw_validation_context *ctx);

static void (*klpe_vmw_validation_drop_ht)(struct vmw_validation_context *ctx);
static int (*klpe_vmw_validation_res_reserve)(struct vmw_validation_context *ctx,
			       bool intr);
static void (*klpe_vmw_validation_res_unreserve)(struct vmw_validation_context *ctx,
				  bool backoff);
static void (*klpe_vmw_validation_res_switch_backup)(struct vmw_validation_context *ctx,
				      void *val_private,
				      struct vmw_buffer_object *vbo,
				      unsigned long backup_offset);
static int (*klpe_vmw_validation_res_validate)(struct vmw_validation_context *ctx, bool intr);

static void *(*klpe_vmw_validation_mem_alloc)(struct vmw_validation_context *ctx,
			       unsigned int size);
static int (*klpe_vmw_validation_preload_bo)(struct vmw_validation_context *ctx);
static int (*klpe_vmw_validation_preload_res)(struct vmw_validation_context *ctx,
			       unsigned int size);

static void (*klpe_vmw_validation_bo_backoff)(struct vmw_validation_context *ctx);

/* klp-ccp: from drivers/gpu/drm/vmwgfx/vmwgfx_drv.h */
#include <drm/vmwgfx_drm.h>

#define VMWGFX_CMD_BOUNCE_INIT_SIZE 32768

#define VMWGFX_MAX_NUM_IRQS 6

#define MKSSTAT_CAPACITY_LOG2 5U
#define MKSSTAT_CAPACITY (1U << MKSSTAT_CAPACITY_LOG2)

struct vmw_fpriv {
	struct ttm_object_file *tfile;
	bool gb_aware; /* user-space is guest-backed aware */
};

struct vmw_buffer_object {
	struct ttm_buffer_object base;
	struct rb_root res_tree;
	/* For KMS atomic helpers: ttm bo mapping count */
	atomic_t base_mapped_count;

	atomic_t cpu_writers;
	/* Not ref-counted.  Protected by binding_mutex */
	struct vmw_resource *dx_query_ctx;
	/* Protected by reservation */
	struct ttm_bo_kmap_obj map;
	u32 res_prios[TTM_MAX_BO_PRIORITY];
	struct vmw_bo_dirty *dirty;
};

struct vmw_resource {
	struct kref kref;
	struct vmw_private *dev_priv;
	int id;
	u32 used_prio;
	unsigned long backup_size;
	u32 res_dirty : 1;
	u32 backup_dirty : 1;
	u32 coherent : 1;
	struct vmw_buffer_object *backup;
	unsigned long backup_offset;
	unsigned long pin_count;
	const struct vmw_res_func *func;
	struct rb_node mob_node;
	struct list_head lru_head;
	struct list_head binding_head;
	struct vmw_resource_dirty *dirty;
	void (*res_free) (struct vmw_resource *res);
	void (*hw_destroy) (struct vmw_resource *res);
};

enum vmw_res_type {
	vmw_res_context,
	vmw_res_surface,
	vmw_res_stream,
	vmw_res_shader,
	vmw_res_dx_context,
	vmw_res_cotable,
	vmw_res_view,
	vmw_res_streamoutput,
	vmw_res_max
};

struct vmw_cursor_snooper {
	size_t age;
	uint32_t *image;
};

struct vmw_surface_metadata {
	u64 flags;
	u32 format;
	u32 mip_levels[DRM_VMW_MAX_SURFACE_FACES];
	u32 multisample_count;
	u32 multisample_pattern;
	u32 quality_level;
	u32 autogen_filter;
	u32 array_size;
	u32 num_sizes;
	u32 buffer_byte_stride;
	struct drm_vmw_size base_size;
	struct drm_vmw_size *sizes;
	bool scanout;
};

struct vmw_surface {
	struct vmw_resource res;
	struct vmw_surface_metadata metadata;
	struct vmw_cursor_snooper snooper;
	struct vmw_surface_offset *offsets;
	struct list_head view_list;
};

struct vmw_res_cache_entry {
	uint32_t handle;
	struct vmw_resource *res;
	void *private;
	unsigned short valid_handle;
	unsigned short valid;
};

enum vmw_dma_map_mode {
	vmw_dma_alloc_coherent, /* Use TTM coherent pages */
	vmw_dma_map_populate,   /* Unmap from DMA just after unpopulate */
	vmw_dma_map_bind,       /* Unmap from DMA just before unbind */
	vmw_dma_map_max
};

enum vmw_display_unit_type {
	vmw_du_invalid = 0,
	vmw_du_legacy,
	vmw_du_screen_object,
	vmw_du_screen_target,
	vmw_du_max
};

struct vmw_sw_context{
	struct vmwgfx_open_hash res_ht;
	bool res_ht_initialized;
	bool kernel;
	struct vmw_fpriv *fp;
	struct drm_file *filp;
	uint32_t *cmd_bounce;
	uint32_t cmd_bounce_size;
	struct vmw_buffer_object *cur_query_bo;
	struct list_head bo_relocations;
	struct list_head res_relocations;
	uint32_t *buf_start;
	struct vmw_res_cache_entry res_cache[vmw_res_max];
	struct vmw_resource *last_query_ctx;
	bool needs_post_query_barrier;
	struct vmw_ctx_binding_state *staged_bindings;
	bool staged_bindings_inuse;
	struct list_head staged_cmd_res;
	struct list_head ctx_list;
	struct vmw_ctx_validation_info *dx_ctx_node;
	struct vmw_buffer_object *dx_query_mob;
	struct vmw_resource *dx_query_ctx;
	struct vmw_cmdbuf_res_manager *man;
	struct vmw_validation_context *ctx;
};

struct vmw_otable_batch {
	unsigned num_otables;
	struct vmw_otable *otables;
	struct vmw_resource *context;
	struct ttm_buffer_object *otable_bo;
};

enum {
	VMW_IRQTHREAD_FENCE,
	VMW_IRQTHREAD_CMDBUF,
	VMW_IRQTHREAD_MAX
};

enum vmw_sm_type {
	VMW_SM_LEGACY = 0,
	VMW_SM_4,
	VMW_SM_4_1,
	VMW_SM_5,
	VMW_SM_5_1X,
	VMW_SM_MAX
};

struct vmw_private {
	struct drm_device drm;
	struct ttm_device bdev;

	struct drm_vma_offset_manager vma_manager;
	u32 pci_id;
	resource_size_t io_start;
	resource_size_t vram_start;
	resource_size_t vram_size;
	resource_size_t max_primary_mem;
	u32 __iomem *rmmio;
	u32 *fifo_mem;
	resource_size_t fifo_mem_size;
	uint32_t fb_max_width;
	uint32_t fb_max_height;
	uint32_t texture_max_width;
	uint32_t texture_max_height;
	uint32_t stdu_max_width;
	uint32_t stdu_max_height;
	uint32_t initial_width;
	uint32_t initial_height;
	uint32_t capabilities;
	uint32_t capabilities2;
	uint32_t max_gmr_ids;
	uint32_t max_gmr_pages;
	uint32_t max_mob_pages;
	uint32_t max_mob_size;
	uint32_t memory_size;
	bool has_gmr;
	bool has_mob;
	spinlock_t hw_lock;
	bool assume_16bpp;
	u32 irqs[VMWGFX_MAX_NUM_IRQS];
	u32 num_irq_vectors;

	enum vmw_sm_type sm_type;

	/*
	 * Framebuffer info.
	 */

	void *fb_info;
	enum vmw_display_unit_type active_display_unit;
	struct vmw_legacy_display *ldu_priv;
	struct vmw_overlay *overlay_priv;
	struct drm_property *hotplug_mode_update_property;
	struct drm_property *implicit_placement_property;
	spinlock_t cursor_lock;
	struct drm_atomic_state *suspend_state;

	/*
	 * Context and surface management.
	 */

	spinlock_t resource_lock;
	struct idr res_idr[vmw_res_max];

	/*
	 * A resource manager for kernel-only surfaces and
	 * contexts.
	 */

	struct ttm_object_device *tdev;

	/*
	 * Fencing and IRQs.
	 */

	atomic_t marker_seq;
	wait_queue_head_t fence_queue;
	wait_queue_head_t fifo_queue;
	spinlock_t waiter_lock;
	int fence_queue_waiters; /* Protected by waiter_lock */
	int goal_queue_waiters; /* Protected by waiter_lock */
	int cmdbuf_waiters; /* Protected by waiter_lock */
	int error_waiters; /* Protected by waiter_lock */
	int fifo_queue_waiters; /* Protected by waiter_lock */
	uint32_t last_read_seqno;
	struct vmw_fence_manager *fman;
	uint32_t irq_mask; /* Updates protected by waiter_lock */

	/*
	 * Device state
	 */

	uint32_t traces_state;
	uint32_t enable_state;
	uint32_t config_done_state;

	/**
	 * Execbuf
	 */
	/**
	 * Protected by the cmdbuf mutex.
	 */

	struct vmw_sw_context ctx;
	struct mutex cmdbuf_mutex;
	struct mutex binding_mutex;

	bool enable_fb;

	/**
	 * PM management.
	 */
	struct notifier_block pm_nb;
	bool refuse_hibernation;
	bool suspend_locked;

	atomic_t num_fifo_resources;

	/*
	 * Query processing. These members
	 * are protected by the cmdbuf mutex.
	 */

	struct vmw_buffer_object *dummy_query_bo;
	struct vmw_buffer_object *pinned_bo;
	uint32_t query_cid;
	uint32_t query_cid_valid;
	bool dummy_query_bo_pinned;

	/*
	 * Surface swapping. The "surface_lru" list is protected by the
	 * resource lock in order to be able to destroy a surface and take
	 * it off the lru atomically. "used_memory_size" is currently
	 * protected by the cmdbuf mutex for simplicity.
	 */

	struct list_head res_lru[vmw_res_max];
	uint32_t used_memory_size;

	/*
	 * DMA mapping stuff.
	 */
	enum vmw_dma_map_mode map_mode;

	/*
	 * Guest Backed stuff
	 */
	struct vmw_otable_batch otable_batch;

	struct vmw_fifo_state *fifo;
	struct vmw_cmdbuf_man *cman;
	DECLARE_BITMAP(irqthread_pending, VMW_IRQTHREAD_MAX);

	uint32 *devcaps;

	/*
	 * mksGuestStat instance-descriptor and pid arrays
	 */
	struct page *mksstat_user_pages[MKSSTAT_CAPACITY];
	atomic_t mksstat_user_pids[MKSSTAT_CAPACITY];

#if IS_ENABLED(CONFIG_DRM_VMWGFX_MKSSTATS)
#error "klp-ccp: non-taken branch"
#endif
};

static inline struct vmw_surface *vmw_res_to_srf(struct vmw_resource *res)
{
	return container_of(res, struct vmw_surface, res);
}

static inline struct vmw_fpriv *vmw_fpriv(struct drm_file *file_priv)
{
	return (struct vmw_fpriv *)file_priv->driver_priv;
}

static inline bool has_sm5_context(const struct vmw_private *dev_priv)
{
	return (dev_priv->sm_type >= VMW_SM_5);
}

struct vmw_user_resource_conv;

static struct vmw_resource *
(*klpe_vmw_user_resource_noref_lookup_handle)(struct vmw_private *dev_priv,
				      struct ttm_object_file *tfile,
				      uint32_t handle,
				      const struct vmw_user_resource_conv *
				      converter);

static void (*klpe_vmw_bo_pin_reserved)(struct vmw_buffer_object *bo, bool pin);

static struct vmw_buffer_object *
(*klpe_vmw_user_bo_noref_lookup)(struct drm_file *filp, u32 handle);

static void *
(*klpe_vmw_cmd_ctx_reserve)(struct vmw_private *dev_priv, uint32_t bytes, int ctx_id);
static void (*klpe_vmw_cmd_commit)(struct vmw_private *dev_priv, uint32_t bytes);

static int (*klpe_vmw_cmd_emit_dummy_query)(struct vmw_private *dev_priv,
				    uint32_t cid);

static void (*klpe___vmw_execbuf_release_pinned_bo)(struct vmw_private *dev_priv,
					    struct vmw_fence_obj *fence);

static int (*klpe_vmw_execbuf_fence_commands)(struct drm_file *file_priv,
				      struct vmw_private *dev_priv,
				      struct vmw_fence_obj **p_fence,
				      uint32_t *p_handle);
static int (*klpe_vmw_execbuf_copy_fence_user)(struct vmw_private *dev_priv,
					struct vmw_fpriv *vmw_fp,
					int ret,
					struct drm_vmw_fence_rep __user
					*user_fence_rep,
					struct vmw_fence_obj *fence,
					uint32_t fence_handle,
					int32_t out_fence_fd);

static void (*klpe_vmw_kms_cursor_snoop)(struct vmw_surface *srf,
			  struct ttm_object_file *tfile,
			  struct ttm_buffer_object *bo,
			  SVGA3dCmdHeader *header);

static const struct vmw_user_resource_conv *(*klpe_user_context_converter);

static struct vmw_cmdbuf_res_manager *
(*klpe_vmw_context_res_man)(struct vmw_resource *ctx);

static int (*klpe_vmw_context_bind_dx_query)(struct vmw_resource *ctx_res,
				     struct vmw_buffer_object *mob);
static struct vmw_buffer_object *
(*klpe_vmw_context_get_dx_query_mob)(struct vmw_resource *ctx_res);

static const struct vmw_user_resource_conv *(*klpe_user_surface_converter);

static const struct vmw_user_resource_conv *(*klpe_user_shader_converter);

static struct vmw_resource *
(*klpe_vmw_shader_lookup)(struct vmw_cmdbuf_res_manager *man,
		  u32 user_key, SVGA3dShaderType shader_type);

static struct vmw_resource *
(*klpe_vmw_dx_streamoutput_lookup)(struct vmw_cmdbuf_res_manager *man,
			   u32 user_key);

static void (*klpe_vmw_dx_streamoutput_set_size)(struct vmw_resource *res, u32 size);

static void (*klpe_vmw_cmdbuf_res_revert)(struct list_head *list);
static void (*klpe_vmw_cmdbuf_res_commit)(struct list_head *list);

struct vmw_cmdbuf_header;

static void *(*klpe_vmw_cmdbuf_reserve)(struct vmw_cmdbuf_man *man, size_t size,
				int ctx_id, bool interruptible,
				struct vmw_cmdbuf_header *header);
static void (*klpe_vmw_cmdbuf_commit)(struct vmw_cmdbuf_man *man, size_t size,
			      struct vmw_cmdbuf_header *header,
			      bool flush);
static void *(*klpe_vmw_cmdbuf_alloc)(struct vmw_cmdbuf_man *man,
			      size_t size, bool interruptible,
			      struct vmw_cmdbuf_header **p_header);
static void (*klpe_vmw_cmdbuf_header_free)(struct vmw_cmdbuf_header *header);

static inline void klpr_vmw_bo_unreference(struct vmw_buffer_object **buf)
{
	struct vmw_buffer_object *tmp_buf = *buf;

	*buf = NULL;
	if (tmp_buf != NULL)
		(*klpe_ttm_bo_put)(&tmp_buf->base);
}

static inline struct vmw_buffer_object *
vmw_bo_reference(struct vmw_buffer_object *buf)
{
	ttm_bo_get(&buf->base);
	return buf;
}

/* klp-ccp: from drivers/gpu/drm/vmwgfx/vmwgfx_execbuf.c */
#include <drm/ttm/ttm_bo_api.h>
#include <drm/ttm/ttm_placement.h>
/* klp-ccp: from drivers/gpu/drm/vmwgfx/vmwgfx_binding.h */
#include <linux/list.h>

static int (*klpe_vmw_binding_rebind_all)(struct vmw_ctx_binding_state *cbs);

static void (*klpe_vmw_binding_state_reset)(struct vmw_ctx_binding_state *cbs);

/* klp-ccp: from drivers/gpu/drm/vmwgfx/vmwgfx_mksstat.h */
#include <asm/page.h>

/* klp-ccp: from drivers/gpu/drm/vmwgfx/vmwgfx_execbuf.c */
#define VMW_RES_HT_ORDER 12

#define VMW_DECLARE_CMD_VAR(__var, __type)                                    \
	struct {                                                              \
		SVGA3dCmdHeader header;                                       \
		__type body;                                                  \
	} __var

struct vmw_relocation {
	struct list_head head;
	struct vmw_buffer_object *vbo;
	union {
		SVGAMobId *mob_loc;
		SVGAGuestPtr *location;
	};
};

struct vmw_ctx_validation_info {
	struct list_head head;
	struct vmw_resource *ctx;
	struct vmw_ctx_binding_state *cur;
	struct vmw_ctx_binding_state *staged;
};

struct vmw_cmd_entry {
	int (*func) (struct vmw_private *, struct vmw_sw_context *,
		     SVGA3dCmdHeader *);
	bool user_allow;
	bool gb_disable;
	bool gb_enable;
	const char *cmd_name;
};

static void (*klpe_vmw_execbuf_bindings_commit)(struct vmw_sw_context *sw_context,
					bool backoff);

static void klpr_vmw_bind_dx_query_mob(struct vmw_sw_context *sw_context)
{
	if (sw_context->dx_query_mob)
		(*klpe_vmw_context_bind_dx_query)(sw_context->dx_query_ctx,
					  sw_context->dx_query_mob);
}

static unsigned int vmw_execbuf_res_size(struct vmw_private *dev_priv,
					 enum vmw_res_type res_type)
{
	return (res_type == vmw_res_dx_context ||
		(res_type == vmw_res_context && dev_priv->has_mob)) ?
		sizeof(struct vmw_ctx_validation_info) : 0;
}

static int (*klpe_vmw_execbuf_res_noref_val_add)(struct vmw_sw_context *sw_context,
					 struct vmw_resource *res,
					 u32 dirty);

static int (*klpe_vmw_execbuf_res_noctx_val_add)(struct vmw_sw_context *sw_context,
					 struct vmw_resource *res,
					 u32 dirty);

static void vmw_resource_relocations_free(struct list_head *list)
{
	/* Memory is validation context memory, so no need to free it */
	INIT_LIST_HEAD(list);
}

static void (*klpe_vmw_resource_relocations_apply)(uint32_t *cb,
					   struct list_head *list);

static int klpr_vmw_resources_reserve(struct vmw_sw_context *sw_context)
{
	int ret;

	ret = (*klpe_vmw_validation_res_reserve)(sw_context->ctx, true);
	if (ret)
		return ret;

	if (sw_context->dx_query_mob) {
		struct vmw_buffer_object *expected_dx_query_mob;

		expected_dx_query_mob =
			(*klpe_vmw_context_get_dx_query_mob)(sw_context->dx_query_ctx);
		if (expected_dx_query_mob &&
		    expected_dx_query_mob != sw_context->dx_query_mob) {
			ret = -EINVAL;
		}
	}

	return ret;
}

static int
(*klpe_vmw_cmd_res_check)(struct vmw_private *dev_priv,
		  struct vmw_sw_context *sw_context,
		  enum vmw_res_type res_type,
		  u32 dirty,
		  const struct vmw_user_resource_conv *converter,
		  uint32_t *id_loc,
		  struct vmw_resource **p_res);

static int klpr_vmw_rebind_all_dx_query(struct vmw_resource *ctx_res)
{
	struct vmw_private *dev_priv = ctx_res->dev_priv;
	struct vmw_buffer_object *dx_query_mob;
	VMW_DECLARE_CMD_VAR(*cmd, SVGA3dCmdDXBindAllQuery);

	dx_query_mob = (*klpe_vmw_context_get_dx_query_mob)(ctx_res);

	if (!dx_query_mob || dx_query_mob->dx_query_ctx)
		return 0;

	cmd = KLPR_VMW_CMD_CTX_RESERVE(dev_priv, sizeof(*cmd), ctx_res->id);
	if (cmd == NULL)
		return -ENOMEM;

	cmd->header.id = SVGA_3D_CMD_DX_BIND_ALL_QUERY;
	cmd->header.size = sizeof(cmd->body);
	cmd->body.cid = ctx_res->id;
	cmd->body.mobid = dx_query_mob->base.resource->start;
	(*klpe_vmw_cmd_commit)(dev_priv, sizeof(*cmd));

	(*klpe_vmw_context_bind_dx_query)(ctx_res, dx_query_mob);

	return 0;
}

static int klpr_vmw_rebind_contexts(struct vmw_sw_context *sw_context)
{
	struct vmw_ctx_validation_info *val;
	int ret;

	list_for_each_entry(val, &sw_context->ctx_list, head) {
		ret = (*klpe_vmw_binding_rebind_all)(val->cur);
		if (unlikely(ret != 0)) {
			if (ret != -ERESTARTSYS)
				(*klpe___drm_dbg)(DRM_UT_DRIVER, "Failed to rebind context.\n");
			return ret;
		}

		ret = klpr_vmw_rebind_all_dx_query(val->ctx);
		if (ret != 0) {
			(*klpe___drm_dbg)(DRM_UT_DRIVER, "Failed to rebind queries.\n");
			return ret;
		}
	}

	return 0;
}

static int (*klpe_vmw_cmd_cid_check)(struct vmw_private *dev_priv,
			     struct vmw_sw_context *sw_context,
			     SVGA3dCmdHeader *header);

static struct vmw_ctx_validation_info *
(*klpe_vmw_execbuf_info_from_res)(struct vmw_sw_context *sw_context,
			  struct vmw_resource *res);

static int klpr_vmw_query_bo_switch_prepare(struct vmw_private *dev_priv,
				       struct vmw_buffer_object *new_query_bo,
				       struct vmw_sw_context *sw_context)
{
	struct vmw_res_cache_entry *ctx_entry =
		&sw_context->res_cache[vmw_res_context];
	int ret;

	BUG_ON(!ctx_entry->valid);
	sw_context->last_query_ctx = ctx_entry->res;

	if (unlikely(new_query_bo != sw_context->cur_query_bo)) {

		if (unlikely(new_query_bo->base.resource->num_pages > 4)) {
			(*klpe___drm_dbg)(DRM_UT_DRIVER, "Query buffer too large.\n");
			return -EINVAL;
		}

		if (unlikely(sw_context->cur_query_bo != NULL)) {
			sw_context->needs_post_query_barrier = true;
			ret = (*klpe_vmw_validation_add_bo)(sw_context->ctx,
						    sw_context->cur_query_bo,
						    dev_priv->has_mob, false);
			if (unlikely(ret != 0))
				return ret;
		}
		sw_context->cur_query_bo = new_query_bo;

		ret = (*klpe_vmw_validation_add_bo)(sw_context->ctx,
					    dev_priv->dummy_query_bo,
					    dev_priv->has_mob, false);
		if (unlikely(ret != 0))
			return ret;
	}

	return 0;
}

static void klpr_vmw_query_bo_switch_commit(struct vmw_private *dev_priv,
				     struct vmw_sw_context *sw_context)
{
	/*
	 * The validate list should still hold references to all
	 * contexts here.
	 */
	if (sw_context->needs_post_query_barrier) {
		struct vmw_res_cache_entry *ctx_entry =
			&sw_context->res_cache[vmw_res_context];
		struct vmw_resource *ctx;
		int ret;

		BUG_ON(!ctx_entry->valid);
		ctx = ctx_entry->res;

		ret = (*klpe_vmw_cmd_emit_dummy_query)(dev_priv, ctx->id);

		if (unlikely(ret != 0))
			(*klpe___drm_dbg)(DRM_UT_DRIVER, "Out of fifo space for dummy query.\n");
	}

	if (dev_priv->pinned_bo != sw_context->cur_query_bo) {
		if (dev_priv->pinned_bo) {
			(*klpe_vmw_bo_pin_reserved)(dev_priv->pinned_bo, false);
			klpr_vmw_bo_unreference(&dev_priv->pinned_bo);
		}

		if (!sw_context->needs_post_query_barrier) {
			(*klpe_vmw_bo_pin_reserved)(sw_context->cur_query_bo, true);

			/*
			 * We pin also the dummy_query_bo buffer so that we
			 * don't need to validate it when emitting dummy queries
			 * in context destroy paths.
			 */
			if (!dev_priv->dummy_query_bo_pinned) {
				(*klpe_vmw_bo_pin_reserved)(dev_priv->dummy_query_bo,
						    true);
				dev_priv->dummy_query_bo_pinned = true;
			}

			BUG_ON(sw_context->last_query_ctx == NULL);
			dev_priv->query_cid = sw_context->last_query_ctx->id;
			dev_priv->query_cid_valid = true;
			dev_priv->pinned_bo =
				vmw_bo_reference(sw_context->cur_query_bo);
		}
	}
}

static int klpp_vmw_translate_mob_ptr(struct vmw_private *dev_priv,
				 struct vmw_sw_context *sw_context,
				 SVGAMobId *id,
				 struct vmw_buffer_object **vmw_bo_p)
{
	struct vmw_buffer_object *vmw_bo;
	uint32_t handle = *id;
	struct vmw_relocation *reloc;
	int ret;

	(*klpe_vmw_validation_preload_bo)(sw_context->ctx);
	vmw_bo = (*klpe_vmw_user_bo_noref_lookup)(sw_context->filp, handle);
	if (IS_ERR_OR_NULL(vmw_bo)) {
		(*klpe___drm_dbg)(DRM_UT_DRIVER, "Could not find or use MOB buffer.\n");
		return PTR_ERR(vmw_bo);
	}
	ret = (*klpe_vmw_validation_add_bo)(sw_context->ctx, vmw_bo, true, false);
	(*klpe_ttm_bo_put)(&vmw_bo->base);
	klpr_drm_gem_object_put(&vmw_bo->base.base);
	if (unlikely(ret != 0))
		return ret;

	reloc = (*klpe_vmw_validation_mem_alloc)(sw_context->ctx, sizeof(*reloc));
	if (!reloc)
		return -ENOMEM;

	reloc->mob_loc = id;
	reloc->vbo = vmw_bo;

	*vmw_bo_p = vmw_bo;
	list_add_tail(&reloc->head, &sw_context->bo_relocations);

	return 0;
}

static int klpp_vmw_translate_guest_ptr(struct vmw_private *dev_priv,
				   struct vmw_sw_context *sw_context,
				   SVGAGuestPtr *ptr,
				   struct vmw_buffer_object **vmw_bo_p)
{
	struct vmw_buffer_object *vmw_bo;
	uint32_t handle = ptr->gmrId;
	struct vmw_relocation *reloc;
	int ret;

	(*klpe_vmw_validation_preload_bo)(sw_context->ctx);
	vmw_bo = (*klpe_vmw_user_bo_noref_lookup)(sw_context->filp, handle);
	if (IS_ERR_OR_NULL(vmw_bo)) {
		(*klpe___drm_dbg)(DRM_UT_DRIVER, "Could not find or use GMR region.\n");
		return PTR_ERR(vmw_bo);
	}
	ret = (*klpe_vmw_validation_add_bo)(sw_context->ctx, vmw_bo, false, false);
	(*klpe_ttm_bo_put)(&vmw_bo->base);
	klpr_drm_gem_object_put(&vmw_bo->base.base);
	if (unlikely(ret != 0))
		return ret;

	reloc = (*klpe_vmw_validation_mem_alloc)(sw_context->ctx, sizeof(*reloc));
	if (!reloc)
		return -ENOMEM;

	reloc->location = ptr;
	reloc->vbo = vmw_bo;
	*vmw_bo_p = vmw_bo;
	list_add_tail(&reloc->head, &sw_context->bo_relocations);

	return 0;
}

int klpp_vmw_cmd_dx_bind_query(struct vmw_private *dev_priv,
				 struct vmw_sw_context *sw_context,
				 SVGA3dCmdHeader *header)
{
	VMW_DECLARE_CMD_VAR(*cmd, SVGA3dCmdDXBindQuery);
	struct vmw_buffer_object *vmw_bo;
	int ret;

	cmd = container_of(header, typeof(*cmd), header);

	/*
	 * Look up the buffer pointed to by q.mobid, put it on the relocation
	 * list so its kernel mode MOB ID can be filled in later
	 */
	ret = klpp_vmw_translate_mob_ptr(dev_priv, sw_context, &cmd->body.mobid,
				    &vmw_bo);

	if (ret != 0)
		return ret;

	sw_context->dx_query_mob = vmw_bo;
	sw_context->dx_query_ctx = sw_context->dx_ctx_node->ctx;
	return 0;
}

int klpp_vmw_cmd_end_gb_query(struct vmw_private *dev_priv,
				struct vmw_sw_context *sw_context,
				SVGA3dCmdHeader *header)
{
	struct vmw_buffer_object *vmw_bo;
	VMW_DECLARE_CMD_VAR(*cmd, SVGA3dCmdEndGBQuery);
	int ret;

	cmd = container_of(header, typeof(*cmd), header);
	ret = (*klpe_vmw_cmd_cid_check)(dev_priv, sw_context, header);
	if (unlikely(ret != 0))
		return ret;

	ret = klpp_vmw_translate_mob_ptr(dev_priv, sw_context, &cmd->body.mobid,
				    &vmw_bo);
	if (unlikely(ret != 0))
		return ret;

	ret = klpr_vmw_query_bo_switch_prepare(dev_priv, vmw_bo, sw_context);

	return ret;
}

int klpp_vmw_cmd_end_query(struct vmw_private *dev_priv,
			     struct vmw_sw_context *sw_context,
			     SVGA3dCmdHeader *header)
{
	struct vmw_buffer_object *vmw_bo;
	VMW_DECLARE_CMD_VAR(*cmd, SVGA3dCmdEndQuery);
	int ret;

	cmd = container_of(header, typeof(*cmd), header);
	if (dev_priv->has_mob) {
		VMW_DECLARE_CMD_VAR(gb_cmd, SVGA3dCmdEndGBQuery);

		BUG_ON(sizeof(gb_cmd) != sizeof(*cmd));

		gb_cmd.header.id = SVGA_3D_CMD_END_GB_QUERY;
		gb_cmd.header.size = cmd->header.size;
		gb_cmd.body.cid = cmd->body.cid;
		gb_cmd.body.type = cmd->body.type;
		gb_cmd.body.mobid = cmd->body.guestResult.gmrId;
		gb_cmd.body.offset = cmd->body.guestResult.offset;

		memcpy(cmd, &gb_cmd, sizeof(*cmd));
		return klpp_vmw_cmd_end_gb_query(dev_priv, sw_context, header);
	}

	ret = (*klpe_vmw_cmd_cid_check)(dev_priv, sw_context, header);
	if (unlikely(ret != 0))
		return ret;

	ret = klpp_vmw_translate_guest_ptr(dev_priv, sw_context,
				      &cmd->body.guestResult, &vmw_bo);
	if (unlikely(ret != 0))
		return ret;

	ret = klpr_vmw_query_bo_switch_prepare(dev_priv, vmw_bo, sw_context);

	return ret;
}

int klpp_vmw_cmd_wait_gb_query(struct vmw_private *dev_priv,
				 struct vmw_sw_context *sw_context,
				 SVGA3dCmdHeader *header)
{
	struct vmw_buffer_object *vmw_bo;
	VMW_DECLARE_CMD_VAR(*cmd, SVGA3dCmdWaitForGBQuery);
	int ret;

	cmd = container_of(header, typeof(*cmd), header);
	ret = (*klpe_vmw_cmd_cid_check)(dev_priv, sw_context, header);
	if (unlikely(ret != 0))
		return ret;

	ret = klpp_vmw_translate_mob_ptr(dev_priv, sw_context, &cmd->body.mobid,
				    &vmw_bo);
	if (unlikely(ret != 0))
		return ret;

	return 0;
}

int klpp_vmw_cmd_wait_query(struct vmw_private *dev_priv,
			      struct vmw_sw_context *sw_context,
			      SVGA3dCmdHeader *header)
{
	struct vmw_buffer_object *vmw_bo;
	VMW_DECLARE_CMD_VAR(*cmd, SVGA3dCmdWaitForQuery);
	int ret;

	cmd = container_of(header, typeof(*cmd), header);
	if (dev_priv->has_mob) {
		VMW_DECLARE_CMD_VAR(gb_cmd, SVGA3dCmdWaitForGBQuery);

		BUG_ON(sizeof(gb_cmd) != sizeof(*cmd));

		gb_cmd.header.id = SVGA_3D_CMD_WAIT_FOR_GB_QUERY;
		gb_cmd.header.size = cmd->header.size;
		gb_cmd.body.cid = cmd->body.cid;
		gb_cmd.body.type = cmd->body.type;
		gb_cmd.body.mobid = cmd->body.guestResult.gmrId;
		gb_cmd.body.offset = cmd->body.guestResult.offset;

		memcpy(cmd, &gb_cmd, sizeof(*cmd));
		return klpp_vmw_cmd_wait_gb_query(dev_priv, sw_context, header);
	}

	ret = (*klpe_vmw_cmd_cid_check)(dev_priv, sw_context, header);
	if (unlikely(ret != 0))
		return ret;

	ret = klpp_vmw_translate_guest_ptr(dev_priv, sw_context,
				      &cmd->body.guestResult, &vmw_bo);
	if (unlikely(ret != 0))
		return ret;

	return 0;
}

int klpp_vmw_cmd_dma(struct vmw_private *dev_priv,
		       struct vmw_sw_context *sw_context,
		       SVGA3dCmdHeader *header)
{
	struct vmw_buffer_object *vmw_bo = NULL;
	struct vmw_surface *srf = NULL;
	VMW_DECLARE_CMD_VAR(*cmd, SVGA3dCmdSurfaceDMA);
	int ret;
	SVGA3dCmdSurfaceDMASuffix *suffix;
	uint32_t bo_size;
	bool dirty;

	cmd = container_of(header, typeof(*cmd), header);
	suffix = (SVGA3dCmdSurfaceDMASuffix *)((unsigned long) &cmd->body +
					       header->size - sizeof(*suffix));

	/* Make sure device and verifier stays in sync. */
	if (unlikely(suffix->suffixSize != sizeof(*suffix))) {
		(*klpe___drm_dbg)(DRM_UT_DRIVER, "Invalid DMA suffix size.\n");
		return -EINVAL;
	}

	ret = klpp_vmw_translate_guest_ptr(dev_priv, sw_context,
				      &cmd->body.guest.ptr, &vmw_bo);
	if (unlikely(ret != 0))
		return ret;

	/* Make sure DMA doesn't cross BO boundaries. */
	bo_size = vmw_bo->base.base.size;
	if (unlikely(cmd->body.guest.ptr.offset > bo_size)) {
		(*klpe___drm_dbg)(DRM_UT_DRIVER, "Invalid DMA offset.\n");
		return -EINVAL;
	}

	bo_size -= cmd->body.guest.ptr.offset;
	if (unlikely(suffix->maximumOffset > bo_size))
		suffix->maximumOffset = bo_size;

	dirty = (cmd->body.transfer == SVGA3D_WRITE_HOST_VRAM) ?
		VMW_RES_DIRTY_SET : 0;
	ret = (*klpe_vmw_cmd_res_check)(dev_priv, sw_context, vmw_res_surface,
				dirty, (*klpe_user_surface_converter),
				&cmd->body.host.sid, NULL);
	if (unlikely(ret != 0)) {
		if (unlikely(ret != -ERESTARTSYS))
			(*klpe___drm_dbg)(DRM_UT_DRIVER, "could not find surface for DMA.\n");
		return ret;
	}

	srf = vmw_res_to_srf(sw_context->res_cache[vmw_res_surface].res);

	(*klpe_vmw_kms_cursor_snoop)(srf, sw_context->fp->tfile, &vmw_bo->base, header);

	return 0;
}

static int klpp_vmw_cmd_check_define_gmrfb(struct vmw_private *dev_priv,
				      struct vmw_sw_context *sw_context,
				      void *buf)
{
	struct vmw_buffer_object *vmw_bo;

	struct {
		uint32_t header;
		SVGAFifoCmdDefineGMRFB body;
	} *cmd = buf;

	return klpp_vmw_translate_guest_ptr(dev_priv, sw_context, &cmd->body.ptr,
				       &vmw_bo);
}

static int klpp_vmw_cmd_res_switch_backup(struct vmw_private *dev_priv,
				     struct vmw_sw_context *sw_context,
				     struct vmw_resource *res, uint32_t *buf_id,
				     unsigned long backup_offset)
{
	struct vmw_buffer_object *vbo;
	void *info;
	int ret;

	info = (*klpe_vmw_execbuf_info_from_res)(sw_context, res);
	if (!info)
		return -EINVAL;

	ret = klpp_vmw_translate_mob_ptr(dev_priv, sw_context, buf_id, &vbo);
	if (ret)
		return ret;

	(*klpe_vmw_validation_res_switch_backup)(sw_context->ctx, info, vbo,
					 backup_offset);
	return 0;
}

static int klpp_vmw_cmd_switch_backup(struct vmw_private *dev_priv,
				 struct vmw_sw_context *sw_context,
				 enum vmw_res_type res_type,
				 const struct vmw_user_resource_conv
				 *converter, uint32_t *res_id, uint32_t *buf_id,
				 unsigned long backup_offset)
{
	struct vmw_resource *res;
	int ret;

	ret = (*klpe_vmw_cmd_res_check)(dev_priv, sw_context, res_type,
				VMW_RES_DIRTY_NONE, converter, res_id, &res);
	if (ret)
		return ret;

	return klpp_vmw_cmd_res_switch_backup(dev_priv, sw_context, res, buf_id,
					 backup_offset);
}

int klpp_vmw_cmd_bind_gb_surface(struct vmw_private *dev_priv,
				   struct vmw_sw_context *sw_context,
				   SVGA3dCmdHeader *header)
{
	VMW_DECLARE_CMD_VAR(*cmd, SVGA3dCmdBindGBSurface) =
		container_of(header, typeof(*cmd), header);

	return klpp_vmw_cmd_switch_backup(dev_priv, sw_context, vmw_res_surface,
				     (*klpe_user_surface_converter), &cmd->body.sid,
				     &cmd->body.mobid, 0);
}

int klpp_vmw_cmd_bind_gb_shader(struct vmw_private *dev_priv,
				  struct vmw_sw_context *sw_context,
				  SVGA3dCmdHeader *header)
{
	VMW_DECLARE_CMD_VAR(*cmd, SVGA3dCmdBindGBShader) =
		container_of(header, typeof(*cmd), header);

	return klpp_vmw_cmd_switch_backup(dev_priv, sw_context, vmw_res_shader,
				     (*klpe_user_shader_converter), &cmd->body.shid,
				     &cmd->body.mobid, cmd->body.offsetInBytes);
}

int klpp_vmw_cmd_dx_bind_shader(struct vmw_private *dev_priv,
				  struct vmw_sw_context *sw_context,
				  SVGA3dCmdHeader *header)
{
	struct vmw_resource *ctx;
	struct vmw_resource *res;
	VMW_DECLARE_CMD_VAR(*cmd, SVGA3dCmdDXBindShader) =
		container_of(header, typeof(*cmd), header);
	int ret;

	if (cmd->body.cid != SVGA3D_INVALID_ID) {
		ret = (*klpe_vmw_cmd_res_check)(dev_priv, sw_context, vmw_res_context,
					VMW_RES_DIRTY_SET,
					(*klpe_user_context_converter), &cmd->body.cid,
					&ctx);
		if (ret)
			return ret;
	} else {
		struct vmw_ctx_validation_info *ctx_node =
			KLPR_VMW_GET_CTX_NODE(sw_context);

		if (!ctx_node)
			return -EINVAL;

		ctx = ctx_node->ctx;
	}

	res = (*klpe_vmw_shader_lookup)((*klpe_vmw_context_res_man)(ctx), cmd->body.shid, 0);
	if (IS_ERR(res)) {
		(*klpe___drm_dbg)(DRM_UT_DRIVER, "Could not find shader to bind.\n");
		return PTR_ERR(res);
	}

	ret = (*klpe_vmw_execbuf_res_noctx_val_add)(sw_context, res,
					    VMW_RES_DIRTY_NONE);
	if (ret) {
		(*klpe___drm_dbg)(DRM_UT_DRIVER, "Error creating resource validation node.\n");
		return ret;
	}

	return klpp_vmw_cmd_res_switch_backup(dev_priv, sw_context, res,
					 &cmd->body.mobid,
					 cmd->body.offsetInBytes);
}

int klpp_vmw_cmd_dx_bind_streamoutput(struct vmw_private *dev_priv,
					struct vmw_sw_context *sw_context,
					SVGA3dCmdHeader *header)
{
	struct vmw_ctx_validation_info *ctx_node = sw_context->dx_ctx_node;
	struct vmw_resource *res;
	struct {
		SVGA3dCmdHeader header;
		SVGA3dCmdDXBindStreamOutput body;
	} *cmd = container_of(header, typeof(*cmd), header);
	int ret;

	if (!has_sm5_context(dev_priv))
		return -EINVAL;

	if (!ctx_node) {
		(*klpe___drm_err)("DX Context not set.\n");
		return -EINVAL;
	}

	res = (*klpe_vmw_dx_streamoutput_lookup)((*klpe_vmw_context_res_man)(ctx_node->ctx),
					 cmd->body.soid);
	if (IS_ERR(res)) {
		(*klpe___drm_err)("Could not find streamoutput to bind.\n");
		return PTR_ERR(res);
	}

	(*klpe_vmw_dx_streamoutput_set_size)(res, cmd->body.sizeInBytes);

	ret = (*klpe_vmw_execbuf_res_noctx_val_add)(sw_context, res,
					    VMW_RES_DIRTY_NONE);
	if (ret) {
		(*klpe___drm_err)("Error creating resource validation node.\n");
		return ret;
	}

	return klpp_vmw_cmd_res_switch_backup(dev_priv, sw_context, res,
					 &cmd->body.mobid,
					 cmd->body.offsetInBytes);
}

static int klpp_vmw_cmd_check_not_3d(struct vmw_private *dev_priv,
				struct vmw_sw_context *sw_context,
				void *buf, uint32_t *size)
{
	uint32_t size_remaining = *size;
	uint32_t cmd_id;

	cmd_id = ((uint32_t *)buf)[0];
	switch (cmd_id) {
	case SVGA_CMD_UPDATE:
		*size = sizeof(uint32_t) + sizeof(SVGAFifoCmdUpdate);
		break;
	case SVGA_CMD_DEFINE_GMRFB:
		*size = sizeof(uint32_t) + sizeof(SVGAFifoCmdDefineGMRFB);
		break;
	case SVGA_CMD_BLIT_GMRFB_TO_SCREEN:
		*size = sizeof(uint32_t) + sizeof(SVGAFifoCmdBlitGMRFBToScreen);
		break;
	case SVGA_CMD_BLIT_SCREEN_TO_GMRFB:
		*size = sizeof(uint32_t) + sizeof(SVGAFifoCmdBlitGMRFBToScreen);
		break;
	default:
		(*klpe___drm_dbg)(DRM_UT_DRIVER, "Unsupported SVGA command: %u.\n",cmd_id);
		return -EINVAL;
	}

	if (*size > size_remaining) {
		(*klpe___drm_dbg)(DRM_UT_DRIVER, "Invalid SVGA command (size mismatch): %u.\n",cmd_id);
		return -EINVAL;
	}

	if (unlikely(!sw_context->kernel)) {
		(*klpe___drm_dbg)(DRM_UT_DRIVER, "Kernel only SVGA command: %u.\n",cmd_id);
		return -EPERM;
	}

	if (cmd_id == SVGA_CMD_DEFINE_GMRFB)
		return klpp_vmw_cmd_check_define_gmrfb(dev_priv, sw_context, buf);

	return 0;
}

static const struct vmw_cmd_entry (*klpe_vmw_cmd_entries)[SVGA_3D_CMD_MAX];

static int klpp_vmw_cmd_check(struct vmw_private *dev_priv,
			 struct vmw_sw_context *sw_context, void *buf,
			 uint32_t *size)
{
	uint32_t cmd_id;
	uint32_t size_remaining = *size;
	SVGA3dCmdHeader *header = (SVGA3dCmdHeader *) buf;
	int ret;
	const struct vmw_cmd_entry *entry;
	bool gb = dev_priv->capabilities & SVGA_CAP_GBOBJECTS;

	cmd_id = ((uint32_t *)buf)[0];
	/* Handle any none 3D commands */
	if (unlikely(cmd_id < SVGA_CMD_MAX))
		return klpp_vmw_cmd_check_not_3d(dev_priv, sw_context, buf, size);


	cmd_id = header->id;
	*size = header->size + sizeof(SVGA3dCmdHeader);

	cmd_id -= SVGA_3D_CMD_BASE;
	if (unlikely(*size > size_remaining))
		goto out_invalid;

	if (unlikely(cmd_id >= SVGA_3D_CMD_MAX - SVGA_3D_CMD_BASE))
		goto out_invalid;

	entry = &(*klpe_vmw_cmd_entries)[cmd_id];
	if (unlikely(!entry->func))
		goto out_invalid;

	if (unlikely(!entry->user_allow && !sw_context->kernel))
		goto out_privileged;

	if (unlikely(entry->gb_disable && gb))
		goto out_old;

	if (unlikely(entry->gb_enable && !gb))
		goto out_new;

	ret = entry->func(dev_priv, sw_context, header);
	if (unlikely(ret != 0)) {
		(*klpe___drm_dbg)(DRM_UT_DRIVER, "SVGA3D command: %d failed with error %d\n",cmd_id + SVGA_3D_CMD_BASE, ret);
		return ret;
	}

	return 0;
out_invalid:
	(*klpe___drm_dbg)(DRM_UT_DRIVER, "Invalid SVGA3D command: %d\n",cmd_id + SVGA_3D_CMD_BASE);
	return -EINVAL;
out_privileged:
	(*klpe___drm_dbg)(DRM_UT_DRIVER, "Privileged SVGA3D command: %d\n",cmd_id + SVGA_3D_CMD_BASE);
	return -EPERM;
out_old:
	(*klpe___drm_dbg)(DRM_UT_DRIVER, "Deprecated (disallowed) SVGA3D command: %d\n",cmd_id + SVGA_3D_CMD_BASE);
	return -EINVAL;
out_new:
	(*klpe___drm_dbg)(DRM_UT_DRIVER, "SVGA3D command: %d not supported by virtual device.\n",cmd_id + SVGA_3D_CMD_BASE);
	return -EINVAL;
}

static int klpp_vmw_cmd_check_all(struct vmw_private *dev_priv,
			     struct vmw_sw_context *sw_context, void *buf,
			     uint32_t size)
{
	int32_t cur_size = size;
	int ret;

	sw_context->buf_start = buf;

	while (cur_size > 0) {
		size = cur_size;
		ret = klpp_vmw_cmd_check(dev_priv, sw_context, buf, &size);
		if (unlikely(ret != 0))
			return ret;
		buf = (void *)((unsigned long) buf + size);
		cur_size -= size;
	}

	if (unlikely(cur_size != 0)) {
		(*klpe___drm_dbg)(DRM_UT_DRIVER, "Command verifier out of sync.\n");
		return -EINVAL;
	}

	return 0;
}

static void vmw_free_relocations(struct vmw_sw_context *sw_context)
{
	/* Memory is validation context memory, so no need to free it */
	INIT_LIST_HEAD(&sw_context->bo_relocations);
}

static void (*klpe_vmw_apply_relocations)(struct vmw_sw_context *sw_context);

static int klpr_vmw_resize_cmd_bounce(struct vmw_sw_context *sw_context,
				 uint32_t size)
{
	if (likely(sw_context->cmd_bounce_size >= size))
		return 0;

	if (sw_context->cmd_bounce_size == 0)
		sw_context->cmd_bounce_size = VMWGFX_CMD_BOUNCE_INIT_SIZE;

	while (sw_context->cmd_bounce_size < size) {
		sw_context->cmd_bounce_size =
			PAGE_ALIGN(sw_context->cmd_bounce_size +
				   (sw_context->cmd_bounce_size >> 1));
	}

	vfree(sw_context->cmd_bounce);
	sw_context->cmd_bounce = vmalloc(sw_context->cmd_bounce_size);

	if (sw_context->cmd_bounce == NULL) {
		(*klpe___drm_dbg)(DRM_UT_DRIVER, "Failed to allocate command bounce buffer.\n");
		sw_context->cmd_bounce_size = 0;
		return -ENOMEM;
	}

	return 0;
}

static int klpr_vmw_execbuf_submit_fifo(struct vmw_private *dev_priv,
				   void *kernel_commands, u32 command_size,
				   struct vmw_sw_context *sw_context)
{
	void *cmd;

	if (sw_context->dx_ctx_node)
		cmd = KLPR_VMW_CMD_CTX_RESERVE(dev_priv, command_size,
					       sw_context->dx_ctx_node->ctx->id);
	else
		cmd = KLPR_VMW_CMD_RESERVE(dev_priv, command_size);

	if (!cmd)
		return -ENOMEM;

	(*klpe_vmw_apply_relocations)(sw_context);
	memcpy(cmd, kernel_commands, command_size);
	(*klpe_vmw_resource_relocations_apply)(cmd, &sw_context->res_relocations);
	vmw_resource_relocations_free(&sw_context->res_relocations);
	(*klpe_vmw_cmd_commit)(dev_priv, command_size);

	return 0;
}

static int klpr_vmw_execbuf_submit_cmdbuf(struct vmw_private *dev_priv,
				     struct vmw_cmdbuf_header *header,
				     u32 command_size,
				     struct vmw_sw_context *sw_context)
{
	u32 id = ((sw_context->dx_ctx_node) ? sw_context->dx_ctx_node->ctx->id :
		  SVGA3D_INVALID_ID);
	void *cmd = (*klpe_vmw_cmdbuf_reserve)(dev_priv->cman, command_size, id, false,
				       header);

	(*klpe_vmw_apply_relocations)(sw_context);
	(*klpe_vmw_resource_relocations_apply)(cmd, &sw_context->res_relocations);
	vmw_resource_relocations_free(&sw_context->res_relocations);
	(*klpe_vmw_cmdbuf_commit)(dev_priv->cman, command_size, header, false);

	return 0;
}

static void *klpr_vmw_execbuf_cmdbuf(struct vmw_private *dev_priv,
				void __user *user_commands,
				void *kernel_commands, u32 command_size,
				struct vmw_cmdbuf_header **header)
{
	size_t cmdbuf_size;
	int ret;

	*header = NULL;
	if (command_size > SVGA_CB_MAX_SIZE) {
		(*klpe___drm_dbg)(DRM_UT_DRIVER, "Command buffer is too large.\n");
		return ERR_PTR(-EINVAL);
	}

	if (!dev_priv->cman || kernel_commands)
		return kernel_commands;

	/* If possible, add a little space for fencing. */
	cmdbuf_size = command_size + 512;
	cmdbuf_size = min_t(size_t, cmdbuf_size, SVGA_CB_MAX_SIZE);
	kernel_commands = (*klpe_vmw_cmdbuf_alloc)(dev_priv->cman, cmdbuf_size, true,
					   header);
	if (IS_ERR(kernel_commands))
		return kernel_commands;

	ret = copy_from_user(kernel_commands, user_commands, command_size);
	if (ret) {
		(*klpe___drm_dbg)(DRM_UT_DRIVER, "Failed copying commands.\n");
		(*klpe_vmw_cmdbuf_header_free)(*header);
		*header = NULL;
		return ERR_PTR(-EFAULT);
	}

	return kernel_commands;
}

static int klpr_vmw_execbuf_tie_context(struct vmw_private *dev_priv,
				   struct vmw_sw_context *sw_context,
				   uint32_t handle)
{
	struct vmw_resource *res;
	int ret;
	unsigned int size;

	if (handle == SVGA3D_INVALID_ID)
		return 0;

	size = vmw_execbuf_res_size(dev_priv, vmw_res_dx_context);
	ret = (*klpe_vmw_validation_preload_res)(sw_context->ctx, size);
	if (ret)
		return ret;

	res = (*klpe_vmw_user_resource_noref_lookup_handle)
		(dev_priv, sw_context->fp->tfile, handle,
		 (*klpe_user_context_converter));
	if (IS_ERR(res)) {
		(*klpe___drm_dbg)(DRM_UT_DRIVER, "Could not find or user DX context 0x%08x.\n",(unsigned int) handle);
		return PTR_ERR(res);
	}

	ret = (*klpe_vmw_execbuf_res_noref_val_add)(sw_context, res, VMW_RES_DIRTY_SET);
	if (unlikely(ret != 0))
		return ret;

	sw_context->dx_ctx_node = (*klpe_vmw_execbuf_info_from_res)(sw_context, res);
	sw_context->man = (*klpe_vmw_context_res_man)(res);

	return 0;
}

int klpp_vmw_execbuf_process(struct drm_file *file_priv,
			struct vmw_private *dev_priv,
			void __user *user_commands, void *kernel_commands,
			uint32_t command_size, uint64_t throttle_us,
			uint32_t dx_context_handle,
			struct drm_vmw_fence_rep __user *user_fence_rep,
			struct vmw_fence_obj **out_fence, uint32_t flags)
{
	struct vmw_sw_context *sw_context = &dev_priv->ctx;
	struct vmw_fence_obj *fence = NULL;
	struct vmw_cmdbuf_header *header;
	uint32_t handle = 0;
	int ret;
	int32_t out_fence_fd = -1;
	struct sync_file *sync_file = NULL;
	DECLARE_VAL_CONTEXT(val_ctx, &sw_context->res_ht, 1);

	if (flags & DRM_VMW_EXECBUF_FLAG_EXPORT_FENCE_FD) {
		out_fence_fd = get_unused_fd_flags(O_CLOEXEC);
		if (out_fence_fd < 0) {
			(*klpe___drm_dbg)(DRM_UT_DRIVER, "Failed to get a fence fd.\n");
			return out_fence_fd;
		}
	}

	if (throttle_us) {
		(*klpe___drm_dbg)(DRM_UT_DRIVER, "Throttling is no longer supported.\n");
	}

	kernel_commands = klpr_vmw_execbuf_cmdbuf(dev_priv, user_commands,
					     kernel_commands, command_size,
					     &header);
	if (IS_ERR(kernel_commands)) {
		ret = PTR_ERR(kernel_commands);
		goto out_free_fence_fd;
	}

	ret = mutex_lock_interruptible(&dev_priv->cmdbuf_mutex);
	if (ret) {
		ret = -ERESTARTSYS;
		goto out_free_header;
	}

	sw_context->kernel = false;
	if (kernel_commands == NULL) {
		ret = klpr_vmw_resize_cmd_bounce(sw_context, command_size);
		if (unlikely(ret != 0))
			goto out_unlock;

		ret = copy_from_user(sw_context->cmd_bounce, user_commands,
				     command_size);
		if (unlikely(ret != 0)) {
			ret = -EFAULT;
			(*klpe___drm_dbg)(DRM_UT_DRIVER, "Failed copying commands.\n");
			goto out_unlock;
		}

		kernel_commands = sw_context->cmd_bounce;
	} else if (!header) {
		sw_context->kernel = true;
	}

	sw_context->filp = file_priv;
	sw_context->fp = vmw_fpriv(file_priv);
	INIT_LIST_HEAD(&sw_context->ctx_list);
	sw_context->cur_query_bo = dev_priv->pinned_bo;
	sw_context->last_query_ctx = NULL;
	sw_context->needs_post_query_barrier = false;
	sw_context->dx_ctx_node = NULL;
	sw_context->dx_query_mob = NULL;
	sw_context->dx_query_ctx = NULL;
	memset(sw_context->res_cache, 0, sizeof(sw_context->res_cache));
	INIT_LIST_HEAD(&sw_context->res_relocations);
	INIT_LIST_HEAD(&sw_context->bo_relocations);

	if (sw_context->staged_bindings)
		(*klpe_vmw_binding_state_reset)(sw_context->staged_bindings);

	if (!sw_context->res_ht_initialized) {
		ret = (*klpe_vmwgfx_ht_create)(&sw_context->res_ht, VMW_RES_HT_ORDER);
		if (unlikely(ret != 0))
			goto out_unlock;

		sw_context->res_ht_initialized = true;
	}

	INIT_LIST_HEAD(&sw_context->staged_cmd_res);
	sw_context->ctx = &val_ctx;
	ret = klpr_vmw_execbuf_tie_context(dev_priv, sw_context, dx_context_handle);
	if (unlikely(ret != 0))
		goto out_err_nores;

	ret = klpp_vmw_cmd_check_all(dev_priv, sw_context, kernel_commands,
				command_size);
	if (unlikely(ret != 0))
		goto out_err_nores;

	ret = klpr_vmw_resources_reserve(sw_context);
	if (unlikely(ret != 0))
		goto out_err_nores;

	ret = klpr_vmw_validation_bo_reserve(&val_ctx, true);
	if (unlikely(ret != 0))
		goto out_err_nores;

	ret = (*klpe_vmw_validation_bo_validate)(&val_ctx, true);
	if (unlikely(ret != 0))
		goto out_err;

	ret = (*klpe_vmw_validation_res_validate)(&val_ctx, true);
	if (unlikely(ret != 0))
		goto out_err;

	(*klpe_vmw_validation_drop_ht)(&val_ctx);

	ret = mutex_lock_interruptible(&dev_priv->binding_mutex);
	if (unlikely(ret != 0)) {
		ret = -ERESTARTSYS;
		goto out_err;
	}

	if (dev_priv->has_mob) {
		ret = klpr_vmw_rebind_contexts(sw_context);
		if (unlikely(ret != 0))
			goto out_unlock_binding;
	}

	if (!header) {
		ret = klpr_vmw_execbuf_submit_fifo(dev_priv, kernel_commands,
					      command_size, sw_context);
	} else {
		ret = klpr_vmw_execbuf_submit_cmdbuf(dev_priv, header, command_size,
						sw_context);
		header = NULL;
	}
	mutex_unlock(&dev_priv->binding_mutex);
	if (ret)
		goto out_err;

	klpr_vmw_query_bo_switch_commit(dev_priv, sw_context);
	ret = (*klpe_vmw_execbuf_fence_commands)(file_priv, dev_priv, &fence,
					 (user_fence_rep) ? &handle : NULL);
	/*
	 * This error is harmless, because if fence submission fails,
	 * vmw_fifo_send_fence will sync. The error will be propagated to
	 * user-space in @fence_rep
	 */
	if (ret != 0)
		(*klpe___drm_dbg)(DRM_UT_DRIVER, "Fence submission error. Syncing.\n");

	(*klpe_vmw_execbuf_bindings_commit)(sw_context, false);
	klpr_vmw_bind_dx_query_mob(sw_context);
	(*klpe_vmw_validation_res_unreserve)(&val_ctx, false);

	klpr_vmw_validation_bo_fence(sw_context->ctx, fence);

	if (unlikely(dev_priv->pinned_bo != NULL && !dev_priv->query_cid_valid))
		(*klpe___vmw_execbuf_release_pinned_bo)(dev_priv, fence);

	/*
	 * If anything fails here, give up trying to export the fence and do a
	 * sync since the user mode will not be able to sync the fence itself.
	 * This ensures we are still functionally correct.
	 */
	if (flags & DRM_VMW_EXECBUF_FLAG_EXPORT_FENCE_FD) {

		sync_file = sync_file_create(&fence->base);
		if (!sync_file) {
			(*klpe___drm_dbg)(DRM_UT_DRIVER, "Sync file create failed for fence\n");
			put_unused_fd(out_fence_fd);
			out_fence_fd = -1;

			(void) (*klpe_vmw_fence_obj_wait)(fence, false, false,
						  VMW_FENCE_WAIT_TIMEOUT);
		}
	}

	ret = (*klpe_vmw_execbuf_copy_fence_user)(dev_priv, vmw_fpriv(file_priv), ret,
				    user_fence_rep, fence, handle, out_fence_fd);

	if (sync_file) {
		if (ret) {
			/* usercopy of fence failed, put the file object */
			fput(sync_file->file);
			put_unused_fd(out_fence_fd);
		} else {
			/* Link the fence with the FD created earlier */
			fd_install(out_fence_fd, sync_file->file);
		}
	}

	/* Don't unreference when handing fence out */
	if (unlikely(out_fence != NULL)) {
		*out_fence = fence;
		fence = NULL;
	} else if (likely(fence != NULL)) {
		vmw_fence_obj_unreference(&fence);
	}

	(*klpe_vmw_cmdbuf_res_commit)(&sw_context->staged_cmd_res);
	mutex_unlock(&dev_priv->cmdbuf_mutex);

	/*
	 * Unreference resources outside of the cmdbuf_mutex to avoid deadlocks
	 * in resource destruction paths.
	 */
	(*klpe_vmw_validation_unref_lists)(&val_ctx);

	return ret;

out_unlock_binding:
	mutex_unlock(&dev_priv->binding_mutex);
out_err:
	(*klpe_vmw_validation_bo_backoff)(&val_ctx);
out_err_nores:
	(*klpe_vmw_execbuf_bindings_commit)(sw_context, true);
	(*klpe_vmw_validation_res_unreserve)(&val_ctx, true);
	vmw_resource_relocations_free(&sw_context->res_relocations);
	vmw_free_relocations(sw_context);
	if (unlikely(dev_priv->pinned_bo != NULL && !dev_priv->query_cid_valid))
		(*klpe___vmw_execbuf_release_pinned_bo)(dev_priv, NULL);
out_unlock:
	(*klpe_vmw_cmdbuf_res_revert)(&sw_context->staged_cmd_res);
	(*klpe_vmw_validation_drop_ht)(&val_ctx);
	WARN_ON(!list_empty(&sw_context->ctx_list));
	mutex_unlock(&dev_priv->cmdbuf_mutex);

	/*
	 * Unreference resources outside of the cmdbuf_mutex to avoid deadlocks
	 * in resource destruction paths.
	 */
	(*klpe_vmw_validation_unref_lists)(&val_ctx);
out_free_header:
	if (header)
		(*klpe_vmw_cmdbuf_header_free)(header);
out_free_fence_fd:
	if (out_fence_fd >= 0)
		put_unused_fd(out_fence_fd);

	return ret;
}



#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "vmwgfx"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "__drm_dbg", (void *)&klpe___drm_dbg, "drm" },
	{ "__drm_err", (void *)&klpe___drm_err, "drm" },
	{ "ttm_bo_put", (void *)&klpe_ttm_bo_put, "ttm" },
	{ "ttm_eu_fence_buffer_objects",
	  (void *)&klpe_ttm_eu_fence_buffer_objects, "ttm" },
	{ "ttm_eu_reserve_buffers", (void *)&klpe_ttm_eu_reserve_buffers,
	  "ttm" },
	{ "__vmw_execbuf_release_pinned_bo",
	  (void *)&klpe___vmw_execbuf_release_pinned_bo, "vmwgfx" },
	{ "user_context_converter", (void *)&klpe_user_context_converter,
	  "vmwgfx" },
	{ "user_shader_converter", (void *)&klpe_user_shader_converter,
	  "vmwgfx" },
	{ "user_surface_converter", (void *)&klpe_user_surface_converter,
	  "vmwgfx" },
	{ "vmw_apply_relocations", (void *)&klpe_vmw_apply_relocations,
	  "vmwgfx" },
	{ "vmw_binding_rebind_all", (void *)&klpe_vmw_binding_rebind_all,
	  "vmwgfx" },
	{ "vmw_binding_state_reset", (void *)&klpe_vmw_binding_state_reset,
	  "vmwgfx" },
	{ "vmw_bo_pin_reserved", (void *)&klpe_vmw_bo_pin_reserved, "vmwgfx" },
	{ "vmw_cmd_cid_check", (void *)&klpe_vmw_cmd_cid_check, "vmwgfx" },
	{ "vmw_cmd_commit", (void *)&klpe_vmw_cmd_commit, "vmwgfx" },
	{ "vmw_cmd_ctx_reserve", (void *)&klpe_vmw_cmd_ctx_reserve, "vmwgfx" },
	{ "vmw_cmd_emit_dummy_query", (void *)&klpe_vmw_cmd_emit_dummy_query,
	  "vmwgfx" },
	{ "vmw_cmd_entries", (void *)&klpe_vmw_cmd_entries, "vmwgfx" },
	{ "vmw_cmd_res_check", (void *)&klpe_vmw_cmd_res_check, "vmwgfx" },
	{ "vmw_cmdbuf_alloc", (void *)&klpe_vmw_cmdbuf_alloc, "vmwgfx" },
	{ "vmw_cmdbuf_commit", (void *)&klpe_vmw_cmdbuf_commit, "vmwgfx" },
	{ "vmw_cmdbuf_header_free", (void *)&klpe_vmw_cmdbuf_header_free,
	  "vmwgfx" },
	{ "vmw_cmdbuf_res_commit", (void *)&klpe_vmw_cmdbuf_res_commit,
	  "vmwgfx" },
	{ "vmw_cmdbuf_res_revert", (void *)&klpe_vmw_cmdbuf_res_revert,
	  "vmwgfx" },
	{ "vmw_cmdbuf_reserve", (void *)&klpe_vmw_cmdbuf_reserve, "vmwgfx" },
	{ "vmw_context_bind_dx_query", (void *)&klpe_vmw_context_bind_dx_query,
	  "vmwgfx" },
	{ "vmw_context_get_dx_query_mob",
	  (void *)&klpe_vmw_context_get_dx_query_mob, "vmwgfx" },
	{ "vmw_context_res_man", (void *)&klpe_vmw_context_res_man, "vmwgfx" },
	{ "vmw_dx_streamoutput_lookup",
	  (void *)&klpe_vmw_dx_streamoutput_lookup, "vmwgfx" },
	{ "vmw_dx_streamoutput_set_size",
	  (void *)&klpe_vmw_dx_streamoutput_set_size, "vmwgfx" },
	{ "vmw_execbuf_bindings_commit",
	  (void *)&klpe_vmw_execbuf_bindings_commit, "vmwgfx" },
	{ "vmw_execbuf_copy_fence_user",
	  (void *)&klpe_vmw_execbuf_copy_fence_user, "vmwgfx" },
	{ "vmw_execbuf_fence_commands",
	  (void *)&klpe_vmw_execbuf_fence_commands, "vmwgfx" },
	{ "vmw_execbuf_info_from_res", (void *)&klpe_vmw_execbuf_info_from_res,
	  "vmwgfx" },
	{ "vmw_execbuf_res_noctx_val_add",
	  (void *)&klpe_vmw_execbuf_res_noctx_val_add, "vmwgfx" },
	{ "vmw_execbuf_res_noref_val_add",
	  (void *)&klpe_vmw_execbuf_res_noref_val_add, "vmwgfx" },
	{ "vmw_fence_obj_wait", (void *)&klpe_vmw_fence_obj_wait, "vmwgfx" },
	{ "vmw_kms_cursor_snoop", (void *)&klpe_vmw_kms_cursor_snoop,
	  "vmwgfx" },
	{ "vmw_resource_relocations_apply",
	  (void *)&klpe_vmw_resource_relocations_apply, "vmwgfx" },
	{ "vmw_shader_lookup", (void *)&klpe_vmw_shader_lookup, "vmwgfx" },
	{ "vmw_user_bo_noref_lookup", (void *)&klpe_vmw_user_bo_noref_lookup,
	  "vmwgfx" },
	{ "vmw_user_resource_noref_lookup_handle",
	  (void *)&klpe_vmw_user_resource_noref_lookup_handle, "vmwgfx" },
	{ "vmw_validation_add_bo", (void *)&klpe_vmw_validation_add_bo,
	  "vmwgfx" },
	{ "vmw_validation_bo_backoff", (void *)&klpe_vmw_validation_bo_backoff,
	  "vmwgfx" },
	{ "vmw_validation_bo_validate",
	  (void *)&klpe_vmw_validation_bo_validate, "vmwgfx" },
	{ "vmw_validation_drop_ht", (void *)&klpe_vmw_validation_drop_ht,
	  "vmwgfx" },
	{ "vmw_validation_mem_alloc", (void *)&klpe_vmw_validation_mem_alloc,
	  "vmwgfx" },
	{ "vmw_validation_preload_bo", (void *)&klpe_vmw_validation_preload_bo,
	  "vmwgfx" },
	{ "vmw_validation_preload_res",
	  (void *)&klpe_vmw_validation_preload_res, "vmwgfx" },
	{ "vmw_validation_res_reserve",
	  (void *)&klpe_vmw_validation_res_reserve, "vmwgfx" },
	{ "vmw_validation_res_switch_backup",
	  (void *)&klpe_vmw_validation_res_switch_backup, "vmwgfx" },
	{ "vmw_validation_res_unreserve",
	  (void *)&klpe_vmw_validation_res_unreserve, "vmwgfx" },
	{ "vmw_validation_res_validate",
	  (void *)&klpe_vmw_validation_res_validate, "vmwgfx" },
	{ "vmw_validation_unref_lists",
	  (void *)&klpe_vmw_validation_unref_lists, "vmwgfx" },
	{ "vmwgfx_ht_create", (void *)&klpe_vmwgfx_ht_create, "vmwgfx" },
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

int bsc1212348_drivers_gpu_drm_vmwgfx_vmwgfx_execbuf_init(void)
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

void bsc1212348_drivers_gpu_drm_vmwgfx_vmwgfx_execbuf_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}

#endif /* IS_ENABLED(CONFIG_DRM_VMWGFX) */
