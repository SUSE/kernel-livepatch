/*
 * livepatch_bsc1195951
 *
 * Fix for CVE-2022-22942, bsc#1195951
 *
 *  Upstream commit:
 *  a0f90c881570 ("drm/vmwgfx: Fix stale file descriptors on failed usercopy")
 *
 *  SLE12-SP3 commit:
 *  Not affected
 *
 *  SLE12-SP4, SLE12-SP5, SLE15 and SLE15-SP1 commit:
 *  136a4b2f8a824ff881fdfb347a5b45fca4d1656e
 *
 *  SLE15-SP2 and -SP3 commit:
 *  b93c2a444edcff93bacc0ec6d088b8aa619c132b
 *
 *  Copyright (c) 2022 SUSE
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

#include "livepatch_bsc1195951.h"




/* klp-ccp: from drivers/gpu/drm/vmwgfx/vmwgfx_execbuf.c */
#include <linux/sync_file.h>
/* klp-ccp: from drivers/gpu/drm/vmwgfx/vmwgfx_reg.h */
#include <linux/types.h>
/* klp-ccp: from drivers/gpu/drm/vmwgfx/device_include/svga_reg.h */
#include <linux/pci_ids.h>
/* klp-ccp: from drivers/gpu/drm/vmwgfx/device_include/svga_types.h */
#include <linux/kernel.h>

typedef u32 uint32;
typedef s32 int32;

/* klp-ccp: from drivers/gpu/drm/vmwgfx/device_include/svga_reg.h */
typedef uint32 SVGAMobId;

typedef

/* klp-ccp: from drivers/gpu/drm/vmwgfx/device_include/vmware_pack_begin.h */
#include <linux/compiler.h>
/* klp-ccp: from drivers/gpu/drm/vmwgfx/device_include/svga_reg.h */
struct SVGAGuestPtr {
   uint32 gmrId;
   uint32 offset;
}
/* klp-ccp: from drivers/gpu/drm/vmwgfx/device_include/vmware_pack_end.h */
/* SPDX-License-Identifier: GPL-2.0 */
__packed
/* klp-ccp: from drivers/gpu/drm/vmwgfx/device_include/svga_reg.h */
SVGAGuestPtr;

#define SVGA_CB_MAX_SIZE (512 * 1024)  /* 512 KB */

typedef struct SVGAGMRImageFormat {
   union {
      struct {
         uint32 bitsPerPixel : 8;
         uint32 colorDepth   : 8;
         uint32 reserved     : 16;  /* Must be zero */
      };

      uint32 value;
   };
} SVGAGMRImageFormat;

typedef

/* klp-ccp: from drivers/gpu/drm/vmwgfx/device_include/vmware_pack_begin.h */
#include <linux/compiler.h>
/* klp-ccp: from drivers/gpu/drm/vmwgfx/device_include/svga_reg.h */
struct {
   int32  left;
   int32  top;
   int32  right;
   int32  bottom;
}
/* klp-ccp: from drivers/gpu/drm/vmwgfx/device_include/vmware_pack_end.h */
/* SPDX-License-Identifier: GPL-2.0 */
__packed
/* klp-ccp: from drivers/gpu/drm/vmwgfx/device_include/svga_reg.h */
SVGASignedRect;

typedef

/* klp-ccp: from drivers/gpu/drm/vmwgfx/device_include/vmware_pack_begin.h */
#include <linux/compiler.h>
/* klp-ccp: from drivers/gpu/drm/vmwgfx/device_include/svga_reg.h */
struct {
   int32  x;
   int32  y;
}
/* klp-ccp: from drivers/gpu/drm/vmwgfx/device_include/vmware_pack_end.h */
/* SPDX-License-Identifier: GPL-2.0 */
__packed
/* klp-ccp: from drivers/gpu/drm/vmwgfx/device_include/svga_reg.h */
SVGASignedPoint;

#define SVGA_CAP_GBOBJECTS          0x08000000

enum {
   SVGA_CMD_INVALID_CMD           = 0,
   SVGA_CMD_UPDATE                = 1,
   SVGA_CMD_RECT_COPY             = 3,
   SVGA_CMD_RECT_ROP_COPY         = 14,
   SVGA_CMD_DEFINE_CURSOR         = 19,
   SVGA_CMD_DEFINE_ALPHA_CURSOR   = 22,
   SVGA_CMD_UPDATE_VERBOSE        = 25,
   SVGA_CMD_FRONT_ROP_FILL        = 29,
   SVGA_CMD_FENCE                 = 30,
   SVGA_CMD_ESCAPE                = 33,
   SVGA_CMD_DEFINE_SCREEN         = 34,
   SVGA_CMD_DESTROY_SCREEN        = 35,
   SVGA_CMD_DEFINE_GMRFB          = 36,
   SVGA_CMD_BLIT_GMRFB_TO_SCREEN  = 37,
   SVGA_CMD_BLIT_SCREEN_TO_GMRFB  = 38,
   SVGA_CMD_ANNOTATION_FILL       = 39,
   SVGA_CMD_ANNOTATION_COPY       = 40,
   SVGA_CMD_DEFINE_GMR2           = 41,
   SVGA_CMD_REMAP_GMR2            = 42,
   SVGA_CMD_DEAD                  = 43,
   SVGA_CMD_DEAD_2                = 44,
   SVGA_CMD_NOP                   = 45,
   SVGA_CMD_NOP_ERROR             = 46,
   SVGA_CMD_MAX
};

typedef

/* klp-ccp: from drivers/gpu/drm/vmwgfx/device_include/vmware_pack_begin.h */
#include <linux/compiler.h>
/* klp-ccp: from drivers/gpu/drm/vmwgfx/device_include/svga_reg.h */
struct {
   uint32 x;
   uint32 y;
   uint32 width;
   uint32 height;
}
/* klp-ccp: from drivers/gpu/drm/vmwgfx/device_include/vmware_pack_end.h */
/* SPDX-License-Identifier: GPL-2.0 */
__packed
/* klp-ccp: from drivers/gpu/drm/vmwgfx/device_include/svga_reg.h */
SVGAFifoCmdUpdate;

typedef

/* klp-ccp: from drivers/gpu/drm/vmwgfx/device_include/vmware_pack_begin.h */
#include <linux/compiler.h>
/* klp-ccp: from drivers/gpu/drm/vmwgfx/device_include/svga_reg.h */
struct {
   SVGAGuestPtr        ptr;
   uint32              bytesPerLine;
   SVGAGMRImageFormat  format;
}
/* klp-ccp: from drivers/gpu/drm/vmwgfx/device_include/vmware_pack_end.h */
/* SPDX-License-Identifier: GPL-2.0 */
__packed
/* klp-ccp: from drivers/gpu/drm/vmwgfx/device_include/svga_reg.h */
SVGAFifoCmdDefineGMRFB;

typedef

/* klp-ccp: from drivers/gpu/drm/vmwgfx/device_include/vmware_pack_begin.h */
#include <linux/compiler.h>
/* klp-ccp: from drivers/gpu/drm/vmwgfx/device_include/svga_reg.h */
struct {
   SVGASignedPoint  srcOrigin;
   SVGASignedRect   destRect;
   uint32           destScreenId;
}
/* klp-ccp: from drivers/gpu/drm/vmwgfx/device_include/vmware_pack_end.h */
/* SPDX-License-Identifier: GPL-2.0 */
__packed
/* klp-ccp: from drivers/gpu/drm/vmwgfx/device_include/svga_reg.h */
SVGAFifoCmdBlitGMRFBToScreen;

/* klp-ccp: from drivers/gpu/drm/vmwgfx/device_include/svga3d_types.h */
#define SVGA3D_INVALID_ID         ((uint32)-1)

typedef enum SVGA3dMSPattern {
   SVGA3D_MS_PATTERN_NONE     = 0,
   SVGA3D_MS_PATTERN_MIN      = 0,
   SVGA3D_MS_PATTERN_STANDARD = 1,
   SVGA3D_MS_PATTERN_CENTER   = 2,
   SVGA3D_MS_PATTERN_MAX      = 3,
} SVGA3dMSPattern;

typedef enum SVGA3dMSQualityLevel {
   SVGA3D_MS_QUALITY_NONE = 0,
   SVGA3D_MS_QUALITY_MIN  = 0,
   SVGA3D_MS_QUALITY_FULL = 1,
   SVGA3D_MS_QUALITY_MAX  = 2,
} SVGA3dMSQualityLevel;

/* klp-ccp: from drivers/gpu/drm/vmwgfx/device_include/svga3d_cmd.h */
enum {
   SVGA_3D_CMD_LEGACY_BASE                                = 1000,
   SVGA_3D_CMD_BASE                                       = 1040,

   SVGA_3D_CMD_SURFACE_DEFINE                             = 1040,
   SVGA_3D_CMD_SURFACE_DESTROY                            = 1041,
   SVGA_3D_CMD_SURFACE_COPY                               = 1042,
   SVGA_3D_CMD_SURFACE_STRETCHBLT                         = 1043,
   SVGA_3D_CMD_SURFACE_DMA                                = 1044,
   SVGA_3D_CMD_CONTEXT_DEFINE                             = 1045,
   SVGA_3D_CMD_CONTEXT_DESTROY                            = 1046,
   SVGA_3D_CMD_SETTRANSFORM                               = 1047,
   SVGA_3D_CMD_SETZRANGE                                  = 1048,
   SVGA_3D_CMD_SETRENDERSTATE                             = 1049,
   SVGA_3D_CMD_SETRENDERTARGET                            = 1050,
   SVGA_3D_CMD_SETTEXTURESTATE                            = 1051,
   SVGA_3D_CMD_SETMATERIAL                                = 1052,
   SVGA_3D_CMD_SETLIGHTDATA                               = 1053,
   SVGA_3D_CMD_SETLIGHTENABLED                            = 1054,
   SVGA_3D_CMD_SETVIEWPORT                                = 1055,
   SVGA_3D_CMD_SETCLIPPLANE                               = 1056,
   SVGA_3D_CMD_CLEAR                                      = 1057,
   SVGA_3D_CMD_PRESENT                                    = 1058,
   SVGA_3D_CMD_SHADER_DEFINE                              = 1059,
   SVGA_3D_CMD_SHADER_DESTROY                             = 1060,
   SVGA_3D_CMD_SET_SHADER                                 = 1061,
   SVGA_3D_CMD_SET_SHADER_CONST                           = 1062,
   SVGA_3D_CMD_DRAW_PRIMITIVES                            = 1063,
   SVGA_3D_CMD_SETSCISSORRECT                             = 1064,
   SVGA_3D_CMD_BEGIN_QUERY                                = 1065,
   SVGA_3D_CMD_END_QUERY                                  = 1066,
   SVGA_3D_CMD_WAIT_FOR_QUERY                             = 1067,
   SVGA_3D_CMD_PRESENT_READBACK                           = 1068,
   SVGA_3D_CMD_BLIT_SURFACE_TO_SCREEN                     = 1069,
   SVGA_3D_CMD_SURFACE_DEFINE_V2                          = 1070,
   SVGA_3D_CMD_GENERATE_MIPMAPS                           = 1071,
   SVGA_3D_CMD_DEAD4                                      = 1072,
   SVGA_3D_CMD_DEAD5                                      = 1073,
   SVGA_3D_CMD_DEAD6                                      = 1074,
   SVGA_3D_CMD_DEAD7                                      = 1075,
   SVGA_3D_CMD_DEAD8                                      = 1076,
   SVGA_3D_CMD_DEAD9                                      = 1077,
   SVGA_3D_CMD_DEAD10                                     = 1078,
   SVGA_3D_CMD_DEAD11                                     = 1079,
   SVGA_3D_CMD_ACTIVATE_SURFACE                           = 1080,
   SVGA_3D_CMD_DEACTIVATE_SURFACE                         = 1081,
   SVGA_3D_CMD_SCREEN_DMA                                 = 1082,
   SVGA_3D_CMD_DEAD1                                      = 1083,
   SVGA_3D_CMD_DEAD2                                      = 1084,

   SVGA_3D_CMD_LOGICOPS_BITBLT                            = 1085,
   SVGA_3D_CMD_LOGICOPS_TRANSBLT                          = 1086,
   SVGA_3D_CMD_LOGICOPS_STRETCHBLT                        = 1087,
   SVGA_3D_CMD_LOGICOPS_COLORFILL                         = 1088,
   SVGA_3D_CMD_LOGICOPS_ALPHABLEND                        = 1089,
   SVGA_3D_CMD_LOGICOPS_CLEARTYPEBLEND                    = 1090,

   SVGA_3D_CMD_SET_OTABLE_BASE                            = 1091,
   SVGA_3D_CMD_READBACK_OTABLE                            = 1092,

   SVGA_3D_CMD_DEFINE_GB_MOB                              = 1093,
   SVGA_3D_CMD_DESTROY_GB_MOB                             = 1094,
   SVGA_3D_CMD_DEAD3                                      = 1095,
   SVGA_3D_CMD_UPDATE_GB_MOB_MAPPING                      = 1096,

   SVGA_3D_CMD_DEFINE_GB_SURFACE                          = 1097,
   SVGA_3D_CMD_DESTROY_GB_SURFACE                         = 1098,
   SVGA_3D_CMD_BIND_GB_SURFACE                            = 1099,
   SVGA_3D_CMD_COND_BIND_GB_SURFACE                       = 1100,
   SVGA_3D_CMD_UPDATE_GB_IMAGE                            = 1101,
   SVGA_3D_CMD_UPDATE_GB_SURFACE                          = 1102,
   SVGA_3D_CMD_READBACK_GB_IMAGE                          = 1103,
   SVGA_3D_CMD_READBACK_GB_SURFACE                        = 1104,
   SVGA_3D_CMD_INVALIDATE_GB_IMAGE                        = 1105,
   SVGA_3D_CMD_INVALIDATE_GB_SURFACE                      = 1106,

   SVGA_3D_CMD_DEFINE_GB_CONTEXT                          = 1107,
   SVGA_3D_CMD_DESTROY_GB_CONTEXT                         = 1108,
   SVGA_3D_CMD_BIND_GB_CONTEXT                            = 1109,
   SVGA_3D_CMD_READBACK_GB_CONTEXT                        = 1110,
   SVGA_3D_CMD_INVALIDATE_GB_CONTEXT                      = 1111,

   SVGA_3D_CMD_DEFINE_GB_SHADER                           = 1112,
   SVGA_3D_CMD_DESTROY_GB_SHADER                          = 1113,
   SVGA_3D_CMD_BIND_GB_SHADER                             = 1114,

   SVGA_3D_CMD_SET_OTABLE_BASE64                          = 1115,

   SVGA_3D_CMD_BEGIN_GB_QUERY                             = 1116,
   SVGA_3D_CMD_END_GB_QUERY                               = 1117,
   SVGA_3D_CMD_WAIT_FOR_GB_QUERY                          = 1118,

   SVGA_3D_CMD_NOP                                        = 1119,

   SVGA_3D_CMD_ENABLE_GART                                = 1120,
   SVGA_3D_CMD_DISABLE_GART                               = 1121,
   SVGA_3D_CMD_MAP_MOB_INTO_GART                          = 1122,
   SVGA_3D_CMD_UNMAP_GART_RANGE                           = 1123,

   SVGA_3D_CMD_DEFINE_GB_SCREENTARGET                     = 1124,
   SVGA_3D_CMD_DESTROY_GB_SCREENTARGET                    = 1125,
   SVGA_3D_CMD_BIND_GB_SCREENTARGET                       = 1126,
   SVGA_3D_CMD_UPDATE_GB_SCREENTARGET                     = 1127,

   SVGA_3D_CMD_READBACK_GB_IMAGE_PARTIAL                  = 1128,
   SVGA_3D_CMD_INVALIDATE_GB_IMAGE_PARTIAL                = 1129,

   SVGA_3D_CMD_SET_GB_SHADERCONSTS_INLINE                 = 1130,

   SVGA_3D_CMD_GB_SCREEN_DMA                              = 1131,
   SVGA_3D_CMD_BIND_GB_SURFACE_WITH_PITCH                 = 1132,
   SVGA_3D_CMD_GB_MOB_FENCE                               = 1133,
   SVGA_3D_CMD_DEFINE_GB_SURFACE_V2                       = 1134,
   SVGA_3D_CMD_DEFINE_GB_MOB64                            = 1135,
   SVGA_3D_CMD_REDEFINE_GB_MOB64                          = 1136,
   SVGA_3D_CMD_NOP_ERROR                                  = 1137,

   SVGA_3D_CMD_SET_VERTEX_STREAMS                         = 1138,
   SVGA_3D_CMD_SET_VERTEX_DECLS                           = 1139,
   SVGA_3D_CMD_SET_VERTEX_DIVISORS                        = 1140,
   SVGA_3D_CMD_DRAW                                       = 1141,
   SVGA_3D_CMD_DRAW_INDEXED                               = 1142,

   /*
    * DX10 Commands
    */
   SVGA_3D_CMD_DX_MIN                                     = 1143,
   SVGA_3D_CMD_DX_DEFINE_CONTEXT                          = 1143,
   SVGA_3D_CMD_DX_DESTROY_CONTEXT                         = 1144,
   SVGA_3D_CMD_DX_BIND_CONTEXT                            = 1145,
   SVGA_3D_CMD_DX_READBACK_CONTEXT                        = 1146,
   SVGA_3D_CMD_DX_INVALIDATE_CONTEXT                      = 1147,
   SVGA_3D_CMD_DX_SET_SINGLE_CONSTANT_BUFFER              = 1148,
   SVGA_3D_CMD_DX_SET_SHADER_RESOURCES                    = 1149,
   SVGA_3D_CMD_DX_SET_SHADER                              = 1150,
   SVGA_3D_CMD_DX_SET_SAMPLERS                            = 1151,
   SVGA_3D_CMD_DX_DRAW                                    = 1152,
   SVGA_3D_CMD_DX_DRAW_INDEXED                            = 1153,
   SVGA_3D_CMD_DX_DRAW_INSTANCED                          = 1154,
   SVGA_3D_CMD_DX_DRAW_INDEXED_INSTANCED                  = 1155,
   SVGA_3D_CMD_DX_DRAW_AUTO                               = 1156,
   SVGA_3D_CMD_DX_SET_INPUT_LAYOUT                        = 1157,
   SVGA_3D_CMD_DX_SET_VERTEX_BUFFERS                      = 1158,
   SVGA_3D_CMD_DX_SET_INDEX_BUFFER                        = 1159,
   SVGA_3D_CMD_DX_SET_TOPOLOGY                            = 1160,
   SVGA_3D_CMD_DX_SET_RENDERTARGETS                       = 1161,
   SVGA_3D_CMD_DX_SET_BLEND_STATE                         = 1162,
   SVGA_3D_CMD_DX_SET_DEPTHSTENCIL_STATE                  = 1163,
   SVGA_3D_CMD_DX_SET_RASTERIZER_STATE                    = 1164,
   SVGA_3D_CMD_DX_DEFINE_QUERY                            = 1165,
   SVGA_3D_CMD_DX_DESTROY_QUERY                           = 1166,
   SVGA_3D_CMD_DX_BIND_QUERY                              = 1167,
   SVGA_3D_CMD_DX_SET_QUERY_OFFSET                        = 1168,
   SVGA_3D_CMD_DX_BEGIN_QUERY                             = 1169,
   SVGA_3D_CMD_DX_END_QUERY                               = 1170,
   SVGA_3D_CMD_DX_READBACK_QUERY                          = 1171,
   SVGA_3D_CMD_DX_SET_PREDICATION                         = 1172,
   SVGA_3D_CMD_DX_SET_SOTARGETS                           = 1173,
   SVGA_3D_CMD_DX_SET_VIEWPORTS                           = 1174,
   SVGA_3D_CMD_DX_SET_SCISSORRECTS                        = 1175,
   SVGA_3D_CMD_DX_CLEAR_RENDERTARGET_VIEW                 = 1176,
   SVGA_3D_CMD_DX_CLEAR_DEPTHSTENCIL_VIEW                 = 1177,
   SVGA_3D_CMD_DX_PRED_COPY_REGION                        = 1178,
   SVGA_3D_CMD_DX_PRED_COPY                               = 1179,
   SVGA_3D_CMD_DX_PRESENTBLT                              = 1180,
   SVGA_3D_CMD_DX_GENMIPS                                 = 1181,
   SVGA_3D_CMD_DX_UPDATE_SUBRESOURCE                      = 1182,
   SVGA_3D_CMD_DX_READBACK_SUBRESOURCE                    = 1183,
   SVGA_3D_CMD_DX_INVALIDATE_SUBRESOURCE                  = 1184,
   SVGA_3D_CMD_DX_DEFINE_SHADERRESOURCE_VIEW              = 1185,
   SVGA_3D_CMD_DX_DESTROY_SHADERRESOURCE_VIEW             = 1186,
   SVGA_3D_CMD_DX_DEFINE_RENDERTARGET_VIEW                = 1187,
   SVGA_3D_CMD_DX_DESTROY_RENDERTARGET_VIEW               = 1188,
   SVGA_3D_CMD_DX_DEFINE_DEPTHSTENCIL_VIEW                = 1189,
   SVGA_3D_CMD_DX_DESTROY_DEPTHSTENCIL_VIEW               = 1190,
   SVGA_3D_CMD_DX_DEFINE_ELEMENTLAYOUT                    = 1191,
   SVGA_3D_CMD_DX_DESTROY_ELEMENTLAYOUT                   = 1192,
   SVGA_3D_CMD_DX_DEFINE_BLEND_STATE                      = 1193,
   SVGA_3D_CMD_DX_DESTROY_BLEND_STATE                     = 1194,
   SVGA_3D_CMD_DX_DEFINE_DEPTHSTENCIL_STATE               = 1195,
   SVGA_3D_CMD_DX_DESTROY_DEPTHSTENCIL_STATE              = 1196,
   SVGA_3D_CMD_DX_DEFINE_RASTERIZER_STATE                 = 1197,
   SVGA_3D_CMD_DX_DESTROY_RASTERIZER_STATE                = 1198,
   SVGA_3D_CMD_DX_DEFINE_SAMPLER_STATE                    = 1199,
   SVGA_3D_CMD_DX_DESTROY_SAMPLER_STATE                   = 1200,
   SVGA_3D_CMD_DX_DEFINE_SHADER                           = 1201,
   SVGA_3D_CMD_DX_DESTROY_SHADER                          = 1202,
   SVGA_3D_CMD_DX_BIND_SHADER                             = 1203,
   SVGA_3D_CMD_DX_DEFINE_STREAMOUTPUT                     = 1204,
   SVGA_3D_CMD_DX_DESTROY_STREAMOUTPUT                    = 1205,
   SVGA_3D_CMD_DX_SET_STREAMOUTPUT                        = 1206,
   SVGA_3D_CMD_DX_SET_COTABLE                             = 1207,
   SVGA_3D_CMD_DX_READBACK_COTABLE                        = 1208,
   SVGA_3D_CMD_DX_BUFFER_COPY                             = 1209,
   SVGA_3D_CMD_DX_TRANSFER_FROM_BUFFER                    = 1210,
   SVGA_3D_CMD_DX_SURFACE_COPY_AND_READBACK               = 1211,
   SVGA_3D_CMD_DX_MOVE_QUERY                              = 1212,
   SVGA_3D_CMD_DX_BIND_ALL_QUERY                          = 1213,
   SVGA_3D_CMD_DX_READBACK_ALL_QUERY                      = 1214,
   SVGA_3D_CMD_DX_PRED_TRANSFER_FROM_BUFFER               = 1215,
   SVGA_3D_CMD_DX_MOB_FENCE_64                            = 1216,
   SVGA_3D_CMD_DX_BIND_ALL_SHADER                         = 1217,
   SVGA_3D_CMD_DX_HINT                                    = 1218,
   SVGA_3D_CMD_DX_BUFFER_UPDATE                           = 1219,
   SVGA_3D_CMD_DX_SET_VS_CONSTANT_BUFFER_OFFSET           = 1220,
   SVGA_3D_CMD_DX_SET_PS_CONSTANT_BUFFER_OFFSET           = 1221,
   SVGA_3D_CMD_DX_SET_GS_CONSTANT_BUFFER_OFFSET           = 1222,

   /*
    * Reserve some IDs to be used for the SM5 shader types.
    */
   SVGA_3D_CMD_DX_RESERVED1                               = 1223,
   SVGA_3D_CMD_DX_RESERVED2                               = 1224,
   SVGA_3D_CMD_DX_RESERVED3                               = 1225,

   SVGA_3D_CMD_DX_COND_BIND_ALL_SHADER                    = 1226,
   SVGA_3D_CMD_DX_MAX                                     = 1227,

   SVGA_3D_CMD_SCREEN_COPY                                = 1227,

   /*
    * Reserve some IDs to be used for video.
    */
   SVGA_3D_CMD_VIDEO_RESERVED1                            = 1228,
   SVGA_3D_CMD_VIDEO_RESERVED2                            = 1229,
   SVGA_3D_CMD_VIDEO_RESERVED3                            = 1230,
   SVGA_3D_CMD_VIDEO_RESERVED4                            = 1231,
   SVGA_3D_CMD_VIDEO_RESERVED5                            = 1232,
   SVGA_3D_CMD_VIDEO_RESERVED6                            = 1233,
   SVGA_3D_CMD_VIDEO_RESERVED7                            = 1234,
   SVGA_3D_CMD_VIDEO_RESERVED8                            = 1235,

   SVGA_3D_CMD_GROW_OTABLE                                = 1236,
   SVGA_3D_CMD_DX_GROW_COTABLE                            = 1237,
   SVGA_3D_CMD_INTRA_SURFACE_COPY                         = 1238,

   SVGA_3D_CMD_DEFINE_GB_SURFACE_V3                       = 1239,

   SVGA_3D_CMD_DX_RESOLVE_COPY                            = 1240,
   SVGA_3D_CMD_DX_PRED_RESOLVE_COPY                       = 1241,
   SVGA_3D_CMD_DX_PRED_CONVERT_REGION                     = 1242,
   SVGA_3D_CMD_DX_PRED_CONVERT                            = 1243,
   SVGA_3D_CMD_WHOLE_SURFACE_COPY                         = 1244,

   SVGA_3D_CMD_MAX                                        = 1245,
   SVGA_3D_CMD_FUTURE_MAX                                 = 3000
};

typedef

/* klp-ccp: from drivers/gpu/drm/vmwgfx/device_include/vmware_pack_begin.h */
#include <linux/compiler.h>
/* klp-ccp: from drivers/gpu/drm/vmwgfx/device_include/svga3d_cmd.h */
struct {
   uint32               id;
   uint32               size;
}
/* klp-ccp: from drivers/gpu/drm/vmwgfx/device_include/vmware_pack_end.h */
/* SPDX-License-Identifier: GPL-2.0 */
__packed
/* klp-ccp: from drivers/gpu/drm/vmwgfx/device_include/svga3d_cmd.h */
SVGA3dCmdHeader;

/* klp-ccp: from drivers/gpu/drm/vmwgfx/device_include/svga3d_dx.h */
typedef

/* klp-ccp: from drivers/gpu/drm/vmwgfx/device_include/vmware_pack_begin.h */
#include <linux/compiler.h>
/* klp-ccp: from drivers/gpu/drm/vmwgfx/device_include/svga3d_dx.h */
struct SVGA3dCmdDXBindAllQuery {
   uint32 cid;
   SVGAMobId mobid;
}
/* klp-ccp: from drivers/gpu/drm/vmwgfx/device_include/vmware_pack_end.h */
/* SPDX-License-Identifier: GPL-2.0 */
__packed
/* klp-ccp: from drivers/gpu/drm/vmwgfx/device_include/svga3d_dx.h */
SVGA3dCmdDXBindAllQuery;

/* klp-ccp: from drivers/gpu/drm/vmwgfx/vmwgfx_drv.h */
#include <drm/drmP.h>

/* klp-ccp: from include/drm/drm_hashtab.h */
static int (*klpe_drm_ht_create)(struct drm_open_hash *ht, unsigned int order);

/* klp-ccp: from include/drm/drm_print.h */
static __printf(1, 2)
void (*klpe_drm_err)(const char *format, ...);

/* klp-ccp: from drivers/gpu/drm/vmwgfx/vmwgfx_drv.h */
#include <drm/vmwgfx_drm.h>
#include <drm/drm_hashtab.h>
#include <drm/ttm/ttm_bo_driver.h>

/* klp-ccp: from include/drm/ttm/ttm_bo_api.h */
static void (*klpe_ttm_bo_unref)(struct ttm_buffer_object **bo);

static void (*klpe_ttm_bo_add_to_lru)(struct ttm_buffer_object *bo);

static inline void klpr_ttm_bo_unreserve(struct ttm_buffer_object *bo)
{
	if (!(bo->mem.placement & TTM_PL_FLAG_NO_EVICT)) {
		spin_lock(&bo->bdev->glob->lru_lock);
		(*klpe_ttm_bo_add_to_lru)(bo);
		spin_unlock(&bo->bdev->glob->lru_lock);
	}
	reservation_object_unlock(bo->resv);
}

/* klp-ccp: from drivers/gpu/drm/vmwgfx/vmwgfx_drv.h */
#include <drm/ttm/ttm_object.h>

/* klp-ccp: from include/drm/ttm/ttm_object.h */
static int (*klpe_ttm_ref_object_base_unref)(struct ttm_object_file *tfile,
				     unsigned long key,
				     enum ttm_ref_type ref_type);

/* klp-ccp: from drivers/gpu/drm/vmwgfx/vmwgfx_drv.h */
#include <drm/ttm/ttm_lock.h>
#include <drm/ttm/ttm_execbuf_util.h>

/* klp-ccp: from include/drm/ttm/ttm_execbuf_util.h */
static void (*klpe_ttm_eu_backoff_reservation)(struct ww_acquire_ctx *ticket,
				       struct list_head *list);

static int (*klpe_ttm_eu_reserve_buffers)(struct ww_acquire_ctx *ticket,
				  struct list_head *list, bool intr,
				  struct list_head *dups);

static void (*klpe_ttm_eu_fence_buffer_objects)(struct ww_acquire_ctx *ticket,
					struct list_head *list,
					struct dma_fence *fence);

/* klp-ccp: from drivers/gpu/drm/vmwgfx/vmwgfx_drv.h */
#include <drm/ttm/ttm_module.h>

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
/* klp-ccp: from drivers/gpu/drm/vmwgfx/vmwgfx_drv.h */
#include <linux/sync_file.h>

#define VMWGFX_MAX_RELOCATIONS 2048
#define VMWGFX_MAX_VALIDATIONS 2048
#define VMWGFX_MAX_DISPLAYS 16
#define VMWGFX_CMD_BOUNCE_INIT_SIZE 32768

struct vmw_fpriv {
	struct drm_master *locked_master;
	struct ttm_object_file *tfile;
	bool gb_aware; /* user-space is guest-backed aware */
};

struct vmw_buffer_object {
	struct ttm_buffer_object base;
	struct list_head res_list;
	s32 pin_count;
	/* Not ref-counted.  Protected by binding_mutex */
	struct vmw_resource *dx_query_ctx;
	/* Protected by reservation */
	struct ttm_bo_kmap_obj map;
};

struct vmw_validate_buffer {
	struct ttm_validate_buffer base;
	struct drm_hash_item hash;
	bool validate_as_mob;
};

struct vmw_resource {
	struct kref kref;
	struct vmw_private *dev_priv;
	int id;
	bool avail;
	unsigned long backup_size;
	bool res_dirty; /* Protected by backup buffer reserved */
	bool backup_dirty; /* Protected by backup buffer reserved */
	struct vmw_buffer_object *backup;
	unsigned long backup_offset;
	unsigned long pin_count; /* Protected by resource reserved */
	const struct vmw_res_func *func;
	struct list_head lru_head; /* Protected by the resource lock */
	struct list_head mob_head; /* Protected by @backup reserved */
	struct list_head binding_head; /* Protected by binding_mutex */
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
	vmw_res_max
};

struct vmw_marker_queue {
	struct list_head head;
	u64 lag;
	u64 lag_time;
	spinlock_t lock;
};

struct vmw_fifo_state {
	unsigned long reserved_size;
	u32 *dynamic_buffer;
	u32 *static_buffer;
	unsigned long static_buffer_size;
	bool using_bounce_buffer;
	uint32_t capabilities;
	struct mutex fifo_mutex;
	struct rw_semaphore rwsem;
	struct vmw_marker_queue marker_queue;
	bool dx;
};

struct vmw_relocation {
	SVGAMobId *mob_loc;
	SVGAGuestPtr *location;
	uint32_t index;
};

struct vmw_res_cache_entry {
	bool valid;
	uint32_t handle;
	struct vmw_resource *res;
	struct vmw_resource_val_node *node;
};

enum vmw_dma_map_mode {
	vmw_dma_phys,           /* Use physical page addresses */
	vmw_dma_alloc_coherent, /* Use TTM coherent pages */
	vmw_dma_map_populate,   /* Unmap from DMA just after unpopulate */
	vmw_dma_map_bind,       /* Unmap from DMA just before unbind */
	vmw_dma_map_max
};

enum vmw_display_unit_type {
	vmw_du_invalid = 0,
	vmw_du_legacy,
	vmw_du_screen_object,
	vmw_du_screen_target
};

struct vmw_sw_context{
	struct drm_open_hash res_ht;
	bool res_ht_initialized;
	bool kernel; /**< is the called made from the kernel */
	struct vmw_fpriv *fp;
	struct list_head validate_nodes;
	struct vmw_relocation relocs[VMWGFX_MAX_RELOCATIONS];
	uint32_t cur_reloc;
	struct vmw_validate_buffer val_bufs[VMWGFX_MAX_VALIDATIONS];
	uint32_t cur_val_buf;
	uint32_t *cmd_bounce;
	uint32_t cmd_bounce_size;
	struct list_head resource_list;
	struct list_head ctx_resource_list; /* For contexts and cotables */
	struct vmw_buffer_object *cur_query_bo;
	struct list_head res_relocations;
	uint32_t *buf_start;
	struct vmw_res_cache_entry res_cache[vmw_res_max];
	struct vmw_resource *last_query_ctx;
	bool needs_post_query_barrier;
	struct vmw_resource *error_resource;
	struct vmw_ctx_binding_state *staged_bindings;
	bool staged_bindings_inuse;
	struct list_head staged_cmd_res;
	struct vmw_resource_val_node *dx_ctx_node;
	struct vmw_buffer_object *dx_query_mob;
	struct vmw_resource *dx_query_ctx;
	struct vmw_cmdbuf_res_manager *man;
};

struct vmw_master {
	struct ttm_lock lock;
};

struct vmw_vga_topology_state {
	uint32_t width;
	uint32_t height;
	uint32_t primary;
	uint32_t pos_x;
	uint32_t pos_y;
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

struct vmw_private {
	struct ttm_bo_device bdev;
	struct ttm_bo_global_ref bo_global_ref;
	struct drm_global_reference mem_global_ref;

	struct vmw_fifo_state fifo;

	struct drm_device *dev;
	unsigned long vmw_chipset;
	unsigned int io_start;
	uint32_t vram_start;
	uint32_t vram_size;
	uint32_t prim_bb_mem;
	uint32_t mmio_start;
	uint32_t mmio_size;
	uint32_t fb_max_width;
	uint32_t fb_max_height;
	uint32_t texture_max_width;
	uint32_t texture_max_height;
	uint32_t stdu_max_width;
	uint32_t stdu_max_height;
	uint32_t initial_width;
	uint32_t initial_height;
	u32 *mmio_virt;
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
	spinlock_t cap_lock;
	bool has_dx;
	bool assume_16bpp;
	bool has_sm4_1;

	/*
	 * VGA registers.
	 */

	struct vmw_vga_topology_state vga_save[VMWGFX_MAX_DISPLAYS];
	uint32_t vga_width;
	uint32_t vga_height;
	uint32_t vga_bpp;
	uint32_t vga_bpl;
	uint32_t vga_pitchlock;

	uint32_t num_displays;

	/*
	 * Currently requested_layout_mutex is used to protect the gui
	 * positionig state in display unit. With that use case currently this
	 * mutex is only taken during layout ioctl and atomic check_modeset.
	 * Other display unit state can be protected with this mutex but that
	 * needs careful consideration.
	 */
	struct mutex requested_layout_mutex;

	/*
	 * Framebuffer info.
	 */

	void *fb_info;
	enum vmw_display_unit_type active_display_unit;
	struct vmw_legacy_display *ldu_priv;
	struct vmw_overlay *overlay_priv;
	struct drm_property *hotplug_mode_update_property;
	struct drm_property *implicit_placement_property;
	unsigned num_implicit;
	struct vmw_framebuffer *implicit_fb;
	struct mutex global_kms_state_mutex;
	spinlock_t cursor_lock;
	struct drm_atomic_state *suspend_state;

	/*
	 * Context and surface management.
	 */

	rwlock_t resource_lock;
	struct idr res_idr[vmw_res_max];
	/*
	 * Block lastclose from racing with firstopen.
	 */

	struct mutex init_mutex;

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

	/**
	 * Operating mode.
	 */

	bool stealth;
	bool enable_fb;
	spinlock_t svga_lock;

	/**
	 * Master management.
	 */

	struct vmw_master *active_master;
	struct vmw_master fbdev_master;
	struct notifier_block pm_nb;
	bool refuse_hibernation;
	bool suspend_locked;

	struct mutex release_mutex;
	atomic_t num_fifo_resources;

	/*
	 * Replace this with an rwsem as soon as we have down_xx_interruptible()
	 */
	struct ttm_lock reservation_sem;

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

	struct vmw_cmdbuf_man *cman;
	DECLARE_BITMAP(irqthread_pending, VMW_IRQTHREAD_MAX);
};

static inline struct vmw_fpriv *vmw_fpriv(struct drm_file *file_priv)
{
	return (struct vmw_fpriv *)file_priv->driver_priv;
}

struct vmw_user_resource_conv;

static void (*klpe_vmw_resource_unreference)(struct vmw_resource **p_res);

static int (*klpe_vmw_resource_validate)(struct vmw_resource *res);
static int (*klpe_vmw_resource_reserve)(struct vmw_resource *res, bool interruptible,
				bool no_backup);
static bool (*klpe_vmw_resource_needs_backup)(const struct vmw_resource *res);

static int (*klpe_vmw_user_resource_lookup_handle)(
	struct vmw_private *dev_priv,
	struct ttm_object_file *tfile,
	uint32_t handle,
	const struct vmw_user_resource_conv *converter,
	struct vmw_resource **p_res);

static void (*klpe_vmw_bo_pin_reserved)(struct vmw_buffer_object *bo, bool pin);

static int (*klpe_vmw_user_bo_lookup)(struct ttm_object_file *tfile,
			      uint32_t id, struct vmw_buffer_object **out,
			      struct ttm_base_object **base);

static void *(*klpe_vmw_fifo_reserve)(struct vmw_private *dev_priv, uint32_t bytes);
static void *
(*klpe_vmw_fifo_reserve_dx)(struct vmw_private *dev_priv, uint32_t bytes, int ctx_id);
static void (*klpe_vmw_fifo_commit)(struct vmw_private *dev_priv, uint32_t bytes);

static int (*klpe_vmw_fifo_emit_dummy_query)(struct vmw_private *dev_priv,
				     uint32_t cid);

static void (*klpe___vmw_execbuf_release_pinned_bo)(struct vmw_private *dev_priv,
					    struct vmw_fence_obj *fence);

static int (*klpe_vmw_execbuf_fence_commands)(struct drm_file *file_priv,
				      struct vmw_private *dev_priv,
				      struct vmw_fence_obj **p_fence,
				      uint32_t *p_handle);
static int (*klpe_vmw_validate_single_buffer)(struct vmw_private *dev_priv,
				      struct ttm_buffer_object *bo,
				      bool interruptible,
				      bool validate_as_mob);

static void (*klpe_vmw_update_seqno)(struct vmw_private *dev_priv,
				struct vmw_fifo_state *fifo_state);

static int (*klpe_vmw_wait_lag)(struct vmw_private *dev_priv,
			struct vmw_marker_queue *queue, uint32_t us);

static const struct vmw_user_resource_conv *(*klpe_user_context_converter);

static struct vmw_cmdbuf_res_manager *
(*klpe_vmw_context_res_man)(struct vmw_resource *ctx);

static struct vmw_ctx_binding_state *
(*klpe_vmw_context_binding_state)(struct vmw_resource *ctx);

static int (*klpe_vmw_context_bind_dx_query)(struct vmw_resource *ctx_res,
				     struct vmw_buffer_object *mob);
static struct vmw_buffer_object *
(*klpe_vmw_context_get_dx_query_mob)(struct vmw_resource *ctx_res);

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
	if (tmp_buf != NULL) {
		struct ttm_buffer_object *bo = &tmp_buf->base;

		(*klpe_ttm_bo_unref)(&bo);
	}
}

static inline struct vmw_buffer_object *
vmw_bo_reference(struct vmw_buffer_object *buf)
{
	if (ttm_bo_reference(&buf->base))
		return buf;
	return NULL;
}

/* klp-ccp: from drivers/gpu/drm/vmwgfx/vmwgfx_execbuf.c */
#include <drm/ttm/ttm_bo_api.h>
#include <drm/ttm/ttm_placement.h>
/* klp-ccp: from drivers/gpu/drm/vmwgfx/vmwgfx_binding.h */
#include <linux/list.h>

static int (*klpe_vmw_binding_rebind_all)(struct vmw_ctx_binding_state *cbs);

static void (*klpe_vmw_binding_state_free)(struct vmw_ctx_binding_state *cbs);

static void (*klpe_vmw_binding_state_reset)(struct vmw_ctx_binding_state *cbs);

/* klp-ccp: from drivers/gpu/drm/vmwgfx/vmwgfx_execbuf.c */
#define VMW_RES_HT_ORDER 12

struct vmw_resource_val_node {
	struct list_head head;
	struct drm_hash_item hash;
	struct vmw_resource *res;
	struct vmw_buffer_object *new_backup;
	struct vmw_ctx_binding_state *staged_bindings;
	unsigned long new_backup_offset;
	u32 first_usage : 1;
	u32 switching_backup : 1;
	u32 no_buffer_needed : 1;
};

struct vmw_cmd_entry {
	int (*func) (struct vmw_private *, struct vmw_sw_context *,
		     SVGA3dCmdHeader *);
	bool user_allow;
	bool gb_disable;
	bool gb_enable;
	const char *cmd_name;
};

static int (*klpe_vmw_bo_to_validate_list)(struct vmw_sw_context *sw_context,
				   struct vmw_buffer_object *vbo,
				   bool validate_as_mob,
				   uint32_t *p_val_node);

static void (*klpe_vmw_resources_unreserve)(struct vmw_sw_context *sw_context,
				    bool backoff);

static int (*klpe_vmw_resource_val_add)(struct vmw_sw_context *sw_context,
				struct vmw_resource *res,
				struct vmw_resource_val_node **p_node);

static void (*klpe_vmw_resource_relocations_free)(struct list_head *list);

static void (*klpe_vmw_resource_relocations_apply)(uint32_t *cb,
					   struct list_head *list);

static int (*klpe_vmw_bo_to_validate_list)(struct vmw_sw_context *sw_context,
				   struct vmw_buffer_object *vbo,
				   bool validate_as_mob,
				   uint32_t *p_val_node);

static int klpr_vmw_resources_reserve(struct vmw_sw_context *sw_context)
{
	struct vmw_resource_val_node *val;
	int ret = 0;

	list_for_each_entry(val, &sw_context->resource_list, head) {
		struct vmw_resource *res = val->res;

		ret = (*klpe_vmw_resource_reserve)(res, true, val->no_buffer_needed);
		if (unlikely(ret != 0))
			return ret;

		if (res->backup) {
			struct vmw_buffer_object *vbo = res->backup;

			ret = (*klpe_vmw_bo_to_validate_list)
				(sw_context, vbo,
				 (*klpe_vmw_resource_needs_backup)(res), NULL);

			if (unlikely(ret != 0))
				return ret;
		}
	}

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

static int klpr_vmw_resources_validate(struct vmw_sw_context *sw_context)
{
	struct vmw_resource_val_node *val;
	int ret;

	list_for_each_entry(val, &sw_context->resource_list, head) {
		struct vmw_resource *res = val->res;
		struct vmw_buffer_object *backup = res->backup;

		ret = (*klpe_vmw_resource_validate)(res);
		if (unlikely(ret != 0)) {
			if (ret != -ERESTARTSYS)
				(*klpe_drm_err)("Failed to validate resource.\n");
			return ret;
		}

		/* Check if the resource switched backup buffer */
		if (backup && res->backup && (backup != res->backup)) {
			struct vmw_buffer_object *vbo = res->backup;

			ret = (*klpe_vmw_bo_to_validate_list)
				(sw_context, vbo,
				 (*klpe_vmw_resource_needs_backup)(res), NULL);
			if (ret) {
				klpr_ttm_bo_unreserve(&vbo->base);
				return ret;
			}
		}
	}
	return 0;
}

static int klpr_vmw_rebind_all_dx_query(struct vmw_resource *ctx_res)
{
	struct vmw_private *dev_priv = ctx_res->dev_priv;
	struct vmw_buffer_object *dx_query_mob;
	struct {
		SVGA3dCmdHeader header;
		SVGA3dCmdDXBindAllQuery body;
	} *cmd;


	dx_query_mob = (*klpe_vmw_context_get_dx_query_mob)(ctx_res);

	if (!dx_query_mob || dx_query_mob->dx_query_ctx)
		return 0;

	cmd = (*klpe_vmw_fifo_reserve_dx)(dev_priv, sizeof(*cmd), ctx_res->id);

	if (cmd == NULL) {
		(*klpe_drm_err)("Failed to rebind queries.\n");
		return -ENOMEM;
	}

	cmd->header.id = SVGA_3D_CMD_DX_BIND_ALL_QUERY;
	cmd->header.size = sizeof(cmd->body);
	cmd->body.cid = ctx_res->id;
	cmd->body.mobid = dx_query_mob->base.mem.start;
	(*klpe_vmw_fifo_commit)(dev_priv, sizeof(*cmd));

	(*klpe_vmw_context_bind_dx_query)(ctx_res, dx_query_mob);

	return 0;
}

static int klpr_vmw_rebind_contexts(struct vmw_sw_context *sw_context)
{
	struct vmw_resource_val_node *val;
	int ret;

	list_for_each_entry(val, &sw_context->resource_list, head) {
		if (unlikely(!val->staged_bindings))
			break;

		ret = (*klpe_vmw_binding_rebind_all)
			((*klpe_vmw_context_binding_state)(val->res));
		if (unlikely(ret != 0)) {
			if (ret != -ERESTARTSYS)
				(*klpe_drm_err)("Failed to rebind context.\n");
			return ret;
		}

		ret = klpr_vmw_rebind_all_dx_query(val->res);
		if (ret != 0)
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

		ret = (*klpe_vmw_fifo_emit_dummy_query)(dev_priv, ctx->id);

		if (unlikely(ret != 0))
			(*klpe_drm_err)("Out of fifo space for dummy query.\n");
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
			 * don't need to validate it when emitting
			 * dummy queries in context destroy paths.
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

static int klpr_vmw_translate_guest_ptr(struct vmw_private *dev_priv,
				   struct vmw_sw_context *sw_context,
				   SVGAGuestPtr *ptr,
				   struct vmw_buffer_object **vmw_bo_p)
{
	struct vmw_buffer_object *vmw_bo = NULL;
	uint32_t handle = ptr->gmrId;
	struct vmw_relocation *reloc;
	int ret;

	ret = (*klpe_vmw_user_bo_lookup)(sw_context->fp->tfile, handle, &vmw_bo, NULL);
	if (unlikely(ret != 0)) {
		(*klpe_drm_err)("Could not find or use GMR region.\n");
		ret = -EINVAL;
		goto out_no_reloc;
	}

	if (unlikely(sw_context->cur_reloc >= VMWGFX_MAX_RELOCATIONS)) {
		(*klpe_drm_err)("Max number relocations per submission" " exceeded\n");
		ret = -EINVAL;
		goto out_no_reloc;
	}

	reloc = &sw_context->relocs[sw_context->cur_reloc++];
	reloc->location = ptr;

	ret = (*klpe_vmw_bo_to_validate_list)(sw_context, vmw_bo, false, &reloc->index);
	if (unlikely(ret != 0))
		goto out_no_reloc;

	*vmw_bo_p = vmw_bo;
	return 0;

out_no_reloc:
	klpr_vmw_bo_unreference(&vmw_bo);
	*vmw_bo_p = NULL;
	return ret;
}

static int klpr_vmw_cmd_check_define_gmrfb(struct vmw_private *dev_priv,
				      struct vmw_sw_context *sw_context,
				      void *buf)
{
	struct vmw_buffer_object *vmw_bo;
	int ret;

	struct {
		uint32_t header;
		SVGAFifoCmdDefineGMRFB body;
	} *cmd = buf;

	ret = klpr_vmw_translate_guest_ptr(dev_priv, sw_context,
				      &cmd->body.ptr,
				      &vmw_bo);
	if (unlikely(ret != 0))
		return ret;

	klpr_vmw_bo_unreference(&vmw_bo);

	return ret;
}

static int klpr_vmw_cmd_check_not_3d(struct vmw_private *dev_priv,
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
		(*klpe_drm_err)("Unsupported SVGA command: %u.\n",cmd_id);
		return -EINVAL;
	}

	if (*size > size_remaining) {
		(*klpe_drm_err)("Invalid SVGA command (size mismatch):" " %u.\n",cmd_id);
		return -EINVAL;
	}

	if (unlikely(!sw_context->kernel)) {
		(*klpe_drm_err)("Kernel only SVGA command: %u.\n",cmd_id);
		return -EPERM;
	}

	if (cmd_id == SVGA_CMD_DEFINE_GMRFB)
		return klpr_vmw_cmd_check_define_gmrfb(dev_priv, sw_context, buf);

	return 0;
}

static const struct vmw_cmd_entry (*klpe_vmw_cmd_entries)[SVGA_3D_CMD_MAX];

static int klpr_vmw_cmd_check(struct vmw_private *dev_priv,
			 struct vmw_sw_context *sw_context,
			 void *buf, uint32_t *size)
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
		return klpr_vmw_cmd_check_not_3d(dev_priv, sw_context, buf, size);


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
	if (unlikely(ret != 0))
		goto out_invalid;

	return 0;
out_invalid:
	(*klpe_drm_err)("Invalid SVGA3D command: %d\n",cmd_id + SVGA_3D_CMD_BASE);
	return -EINVAL;
out_privileged:
	(*klpe_drm_err)("Privileged SVGA3D command: %d\n",cmd_id + SVGA_3D_CMD_BASE);
	return -EPERM;
out_old:
	(*klpe_drm_err)("Deprecated (disallowed) SVGA3D command: %d\n",cmd_id + SVGA_3D_CMD_BASE);
	return -EINVAL;
out_new:
	(*klpe_drm_err)("SVGA3D command: %d not supported by virtual hardware.\n",cmd_id + SVGA_3D_CMD_BASE);
	return -EINVAL;
}

static int klpr_vmw_cmd_check_all(struct vmw_private *dev_priv,
			     struct vmw_sw_context *sw_context,
			     void *buf,
			     uint32_t size)
{
	int32_t cur_size = size;
	int ret;

	sw_context->buf_start = buf;

	while (cur_size > 0) {
		size = cur_size;
		ret = klpr_vmw_cmd_check(dev_priv, sw_context, buf, &size);
		if (unlikely(ret != 0))
			return ret;
		buf = (void *)((unsigned long) buf + size);
		cur_size -= size;
	}

	if (unlikely(cur_size != 0)) {
		(*klpe_drm_err)("Command verifier out of sync.\n");
		return -EINVAL;
	}

	return 0;
}

static void vmw_free_relocations(struct vmw_sw_context *sw_context)
{
	sw_context->cur_reloc = 0;
}

static void (*klpe_vmw_apply_relocations)(struct vmw_sw_context *sw_context);

static void klpr_vmw_resource_list_unreference(struct vmw_sw_context *sw_context,
					  struct list_head *list)
{
	struct vmw_resource_val_node *val, *val_next;

	/*
	 * Drop references to resources held during command submission.
	 */

	list_for_each_entry_safe(val, val_next, list, head) {
		list_del_init(&val->head);
		(*klpe_vmw_resource_unreference)(&val->res);

		if (val->staged_bindings) {
			if (val->staged_bindings != sw_context->staged_bindings)
				(*klpe_vmw_binding_state_free)(val->staged_bindings);
			else
				sw_context->staged_bindings_inuse = false;
			val->staged_bindings = NULL;
		}

		kfree(val);
	}
}

static void (*klpe_vmw_clear_validations)(struct vmw_sw_context *sw_context);

static int klpr_vmw_validate_buffers(struct vmw_private *dev_priv,
				struct vmw_sw_context *sw_context)
{
	struct vmw_validate_buffer *entry;
	int ret;

	list_for_each_entry(entry, &sw_context->validate_nodes, base.head) {
		ret = (*klpe_vmw_validate_single_buffer)(dev_priv, entry->base.bo,
						 true,
						 entry->validate_as_mob);
		if (unlikely(ret != 0))
			return ret;
	}
	return 0;
}

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
		(*klpe_drm_err)("Failed to allocate command bounce buffer.\n");
		sw_context->cmd_bounce_size = 0;
		return -ENOMEM;
	}

	return 0;
}

static int
klpp_vmw_execbuf_copy_fence_user(struct vmw_private *dev_priv,
			    struct vmw_fpriv *vmw_fp,
			    int ret,
			    struct drm_vmw_fence_rep __user *user_fence_rep,
			    struct vmw_fence_obj *fence,
			    uint32_t fence_handle,
			    int32_t out_fence_fd)
{
	struct drm_vmw_fence_rep fence_rep;

	if (user_fence_rep == NULL)
		return 0;

	memset(&fence_rep, 0, sizeof(fence_rep));

	fence_rep.error = ret;
	fence_rep.fd = out_fence_fd;
	if (ret == 0) {
		BUG_ON(fence == NULL);

		fence_rep.handle = fence_handle;
		fence_rep.seqno = fence->base.seqno;
		(*klpe_vmw_update_seqno)(dev_priv, &dev_priv->fifo);
		fence_rep.passed_seqno = dev_priv->last_read_seqno;
	}

	/*
	 * copy_to_user errors will be detected by user space not
	 * seeing fence_rep::error filled in. Typically
	 * user-space would have pre-set that member to -EFAULT.
	 */
	ret = copy_to_user(user_fence_rep, &fence_rep,
			   sizeof(fence_rep));

	/*
	 * User-space lost the fence object. We need to sync
	 * and unreference the handle.
	 */
	if (unlikely(ret != 0) && (fence_rep.error == 0)) {
		(*klpe_ttm_ref_object_base_unref)(vmw_fp->tfile,
					  fence_handle, TTM_REF_USAGE);
		(*klpe_drm_err)("Fence copy error. Syncing.\n");
		(void) (*klpe_vmw_fence_obj_wait)(fence, false, false,
					  VMW_FENCE_WAIT_TIMEOUT);
	}

	return ret ? -EFAULT : 0;
}

static int klpr_vmw_execbuf_submit_fifo(struct vmw_private *dev_priv,
				   void *kernel_commands,
				   u32 command_size,
				   struct vmw_sw_context *sw_context)
{
	void *cmd;

	if (sw_context->dx_ctx_node)
		cmd = (*klpe_vmw_fifo_reserve_dx)(dev_priv, command_size,
					  sw_context->dx_ctx_node->res->id);
	else
		cmd = (*klpe_vmw_fifo_reserve)(dev_priv, command_size);
	if (!cmd) {
		(*klpe_drm_err)("Failed reserving fifo space for commands.\n");
		return -ENOMEM;
	}

	(*klpe_vmw_apply_relocations)(sw_context);
	memcpy(cmd, kernel_commands, command_size);
	(*klpe_vmw_resource_relocations_apply)(cmd, &sw_context->res_relocations);
	(*klpe_vmw_resource_relocations_free)(&sw_context->res_relocations);
	(*klpe_vmw_fifo_commit)(dev_priv, command_size);

	return 0;
}

static int klpr_vmw_execbuf_submit_cmdbuf(struct vmw_private *dev_priv,
				     struct vmw_cmdbuf_header *header,
				     u32 command_size,
				     struct vmw_sw_context *sw_context)
{
	u32 id = ((sw_context->dx_ctx_node) ? sw_context->dx_ctx_node->res->id :
		  SVGA3D_INVALID_ID);
	void *cmd = (*klpe_vmw_cmdbuf_reserve)(dev_priv->cman, command_size,
				       id, false, header);

	(*klpe_vmw_apply_relocations)(sw_context);
	(*klpe_vmw_resource_relocations_apply)(cmd, &sw_context->res_relocations);
	(*klpe_vmw_resource_relocations_free)(&sw_context->res_relocations);
	(*klpe_vmw_cmdbuf_commit)(dev_priv->cman, command_size, header, false);

	return 0;
}

static void *klpr_vmw_execbuf_cmdbuf(struct vmw_private *dev_priv,
				void __user *user_commands,
				void *kernel_commands,
				u32 command_size,
				struct vmw_cmdbuf_header **header)
{
	size_t cmdbuf_size;
	int ret;

	*header = NULL;
	if (command_size > SVGA_CB_MAX_SIZE) {
		(*klpe_drm_err)("Command buffer is too large.\n");
		return ERR_PTR(-EINVAL);
	}

	if (!dev_priv->cman || kernel_commands)
		return kernel_commands;

	/* If possible, add a little space for fencing. */
	cmdbuf_size = command_size + 512;
	cmdbuf_size = min_t(size_t, cmdbuf_size, SVGA_CB_MAX_SIZE);
	kernel_commands = (*klpe_vmw_cmdbuf_alloc)(dev_priv->cman, cmdbuf_size,
					   true, header);
	if (IS_ERR(kernel_commands))
		return kernel_commands;

	ret = copy_from_user(kernel_commands, user_commands,
			     command_size);
	if (ret) {
		(*klpe_drm_err)("Failed copying commands.\n");
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
	struct vmw_resource_val_node *ctx_node;
	struct vmw_resource *res;
	int ret;

	if (handle == SVGA3D_INVALID_ID)
		return 0;

	ret = (*klpe_vmw_user_resource_lookup_handle)(dev_priv, sw_context->fp->tfile,
					      handle, (*klpe_user_context_converter),
					      &res);
	if (unlikely(ret != 0)) {
		(*klpe_drm_err)("Could not find or user DX context 0x%08x.\n",(unsigned) handle);
		return ret;
	}

	ret = (*klpe_vmw_resource_val_add)(sw_context, res, &ctx_node);
	if (unlikely(ret != 0))
		goto out_err;

	sw_context->dx_ctx_node = ctx_node;
	sw_context->man = (*klpe_vmw_context_res_man)(res);
out_err:
	(*klpe_vmw_resource_unreference)(&res);
	return ret;
}

int klpp_vmw_execbuf_process(struct drm_file *file_priv,
			struct vmw_private *dev_priv,
			void __user *user_commands,
			void *kernel_commands,
			uint32_t command_size,
			uint64_t throttle_us,
			uint32_t dx_context_handle,
			struct drm_vmw_fence_rep __user *user_fence_rep,
			struct vmw_fence_obj **out_fence,
			uint32_t flags)
{
	struct vmw_sw_context *sw_context = &dev_priv->ctx;
	struct vmw_fence_obj *fence = NULL;
	struct vmw_resource *error_resource;
	struct list_head resource_list;
	struct vmw_cmdbuf_header *header;
	struct ww_acquire_ctx ticket;
	uint32_t handle;
	int ret;
	int32_t out_fence_fd = -1;
	struct sync_file *sync_file = NULL;


	if (flags & DRM_VMW_EXECBUF_FLAG_EXPORT_FENCE_FD) {
		out_fence_fd = get_unused_fd_flags(O_CLOEXEC);
		if (out_fence_fd < 0) {
			(*klpe_drm_err)("Failed to get a fence file descriptor.\n");
			return out_fence_fd;
		}
	}

	if (throttle_us) {
		ret = (*klpe_vmw_wait_lag)(dev_priv, &dev_priv->fifo.marker_queue,
				   throttle_us);

		if (ret)
			goto out_free_fence_fd;
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


		ret = copy_from_user(sw_context->cmd_bounce,
				     user_commands, command_size);

		if (unlikely(ret != 0)) {
			ret = -EFAULT;
			(*klpe_drm_err)("Failed copying commands.\n");
			goto out_unlock;
		}
		kernel_commands = sw_context->cmd_bounce;
	} else if (!header)
		sw_context->kernel = true;

	sw_context->fp = vmw_fpriv(file_priv);
	sw_context->cur_reloc = 0;
	sw_context->cur_val_buf = 0;
	INIT_LIST_HEAD(&sw_context->resource_list);
	INIT_LIST_HEAD(&sw_context->ctx_resource_list);
	sw_context->cur_query_bo = dev_priv->pinned_bo;
	sw_context->last_query_ctx = NULL;
	sw_context->needs_post_query_barrier = false;
	sw_context->dx_ctx_node = NULL;
	sw_context->dx_query_mob = NULL;
	sw_context->dx_query_ctx = NULL;
	memset(sw_context->res_cache, 0, sizeof(sw_context->res_cache));
	INIT_LIST_HEAD(&sw_context->validate_nodes);
	INIT_LIST_HEAD(&sw_context->res_relocations);
	if (sw_context->staged_bindings)
		(*klpe_vmw_binding_state_reset)(sw_context->staged_bindings);

	if (!sw_context->res_ht_initialized) {
		ret = (*klpe_drm_ht_create)(&sw_context->res_ht, VMW_RES_HT_ORDER);
		if (unlikely(ret != 0))
			goto out_unlock;
		sw_context->res_ht_initialized = true;
	}
	INIT_LIST_HEAD(&sw_context->staged_cmd_res);
	INIT_LIST_HEAD(&resource_list);
	ret = klpr_vmw_execbuf_tie_context(dev_priv, sw_context, dx_context_handle);
	if (unlikely(ret != 0)) {
		list_splice_init(&sw_context->ctx_resource_list,
				 &sw_context->resource_list);
		goto out_err_nores;
	}

	ret = klpr_vmw_cmd_check_all(dev_priv, sw_context, kernel_commands,
				command_size);
	/*
	 * Merge the resource lists before checking the return status
	 * from vmd_cmd_check_all so that all the open hashtabs will
	 * be handled properly even if vmw_cmd_check_all fails.
	 */
	list_splice_init(&sw_context->ctx_resource_list,
			 &sw_context->resource_list);

	if (unlikely(ret != 0))
		goto out_err_nores;

	ret = klpr_vmw_resources_reserve(sw_context);
	if (unlikely(ret != 0))
		goto out_err_nores;

	ret = (*klpe_ttm_eu_reserve_buffers)(&ticket, &sw_context->validate_nodes,
				     true, NULL);
	if (unlikely(ret != 0))
		goto out_err_nores;

	ret = klpr_vmw_validate_buffers(dev_priv, sw_context);
	if (unlikely(ret != 0))
		goto out_err;

	ret = klpr_vmw_resources_validate(sw_context);
	if (unlikely(ret != 0))
		goto out_err;

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
	ret = (*klpe_vmw_execbuf_fence_commands)(file_priv, dev_priv,
					 &fence,
					 (user_fence_rep) ? &handle : NULL);
	/*
	 * This error is harmless, because if fence submission fails,
	 * vmw_fifo_send_fence will sync. The error will be propagated to
	 * user-space in @fence_rep
	 */

	if (ret != 0)
		(*klpe_drm_err)("Fence submission error. Syncing.\n");

	(*klpe_vmw_resources_unreserve)(sw_context, false);

	(*klpe_ttm_eu_fence_buffer_objects)(&ticket, &sw_context->validate_nodes,
				    (void *) fence);

	if (unlikely(dev_priv->pinned_bo != NULL &&
		     !dev_priv->query_cid_valid))
		(*klpe___vmw_execbuf_release_pinned_bo)(dev_priv, fence);

	(*klpe_vmw_clear_validations)(sw_context);

	/*
	 * If anything fails here, give up trying to export the fence
	 * and do a sync since the user mode will not be able to sync
	 * the fence itself.  This ensures we are still functionally
	 * correct.
	 */
	if (flags & DRM_VMW_EXECBUF_FLAG_EXPORT_FENCE_FD) {

		sync_file = sync_file_create(&fence->base);
		if (!sync_file) {
			(*klpe_drm_err)("Unable to create sync file for fence\n");
			put_unused_fd(out_fence_fd);
			out_fence_fd = -1;

			(void) (*klpe_vmw_fence_obj_wait)(fence, false, false,
						  VMW_FENCE_WAIT_TIMEOUT);
		}
	}

	ret = 	klpp_vmw_execbuf_copy_fence_user(dev_priv, vmw_fpriv(file_priv), ret,
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

	list_splice_init(&sw_context->resource_list, &resource_list);
	(*klpe_vmw_cmdbuf_res_commit)(&sw_context->staged_cmd_res);
	mutex_unlock(&dev_priv->cmdbuf_mutex);

	/*
	 * Unreference resources outside of the cmdbuf_mutex to
	 * avoid deadlocks in resource destruction paths.
	 */
	klpr_vmw_resource_list_unreference(sw_context, &resource_list);

	return ret;

out_unlock_binding:
	mutex_unlock(&dev_priv->binding_mutex);
out_err:
	(*klpe_ttm_eu_backoff_reservation)(&ticket, &sw_context->validate_nodes);
out_err_nores:
	(*klpe_vmw_resources_unreserve)(sw_context, true);
	(*klpe_vmw_resource_relocations_free)(&sw_context->res_relocations);
	vmw_free_relocations(sw_context);
	(*klpe_vmw_clear_validations)(sw_context);
	if (unlikely(dev_priv->pinned_bo != NULL &&
		     !dev_priv->query_cid_valid))
		(*klpe___vmw_execbuf_release_pinned_bo)(dev_priv, NULL);
out_unlock:
	list_splice_init(&sw_context->resource_list, &resource_list);
	error_resource = sw_context->error_resource;
	sw_context->error_resource = NULL;
	(*klpe_vmw_cmdbuf_res_revert)(&sw_context->staged_cmd_res);
	mutex_unlock(&dev_priv->cmdbuf_mutex);

	/*
	 * Unreference resources outside of the cmdbuf_mutex to
	 * avoid deadlocks in resource destruction paths.
	 */
	klpr_vmw_resource_list_unreference(sw_context, &resource_list);
	if (unlikely(error_resource != NULL))
		(*klpe_vmw_resource_unreference)(&error_resource);
out_free_header:
	if (header)
		(*klpe_vmw_cmdbuf_header_free)(header);
out_free_fence_fd:
	if (out_fence_fd >= 0)
		put_unused_fd(out_fence_fd);

	return ret;
}




#define LP_MODULE "vmwgfx"
#include <linux/module.h>
#include "../kallsyms_relocs.h"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "drm_err", (void *)&klpe_drm_err, "drm" },
	{ "drm_ht_create", (void *)&klpe_drm_ht_create, "drm" },
	{ "ttm_bo_add_to_lru", (void *)&klpe_ttm_bo_add_to_lru, "ttm" },
	{ "ttm_bo_unref", (void *)&klpe_ttm_bo_unref, "ttm" },
	{ "ttm_eu_backoff_reservation",
	  (void *)&klpe_ttm_eu_backoff_reservation, "ttm" },
	{ "ttm_eu_fence_buffer_objects",
	  (void *)&klpe_ttm_eu_fence_buffer_objects, "ttm" },
	{ "ttm_eu_reserve_buffers", (void *)&klpe_ttm_eu_reserve_buffers,
	  "ttm" },
	{ "ttm_ref_object_base_unref", (void *)&klpe_ttm_ref_object_base_unref,
	  "ttm" },
	{ "__vmw_execbuf_release_pinned_bo",
	  (void *)&klpe___vmw_execbuf_release_pinned_bo, "vmwgfx" },
	{ "user_context_converter", (void *)&klpe_user_context_converter,
	  "vmwgfx" },
	{ "vmw_apply_relocations", (void *)&klpe_vmw_apply_relocations,
	  "vmwgfx" },
	{ "vmw_binding_rebind_all", (void *)&klpe_vmw_binding_rebind_all,
	  "vmwgfx" },
	{ "vmw_binding_state_free", (void *)&klpe_vmw_binding_state_free,
	  "vmwgfx" },
	{ "vmw_binding_state_reset", (void *)&klpe_vmw_binding_state_reset,
	  "vmwgfx" },
	{ "vmw_bo_pin_reserved", (void *)&klpe_vmw_bo_pin_reserved, "vmwgfx" },
	{ "vmw_bo_to_validate_list", (void *)&klpe_vmw_bo_to_validate_list,
	  "vmwgfx" },
	{ "vmw_clear_validations", (void *)&klpe_vmw_clear_validations,
	  "vmwgfx" },
	{ "vmw_cmd_entries", (void *)&klpe_vmw_cmd_entries, "vmwgfx" },
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
	{ "vmw_context_binding_state", (void *)&klpe_vmw_context_binding_state,
	  "vmwgfx" },
	{ "vmw_context_get_dx_query_mob",
	  (void *)&klpe_vmw_context_get_dx_query_mob, "vmwgfx" },
	{ "vmw_context_res_man", (void *)&klpe_vmw_context_res_man, "vmwgfx" },
	{ "vmw_execbuf_fence_commands",
	  (void *)&klpe_vmw_execbuf_fence_commands, "vmwgfx" },
	{ "vmw_fence_obj_wait", (void *)&klpe_vmw_fence_obj_wait, "vmwgfx" },
	{ "vmw_fifo_commit", (void *)&klpe_vmw_fifo_commit, "vmwgfx" },
	{ "vmw_fifo_emit_dummy_query", (void *)&klpe_vmw_fifo_emit_dummy_query,
	  "vmwgfx" },
	{ "vmw_fifo_reserve", (void *)&klpe_vmw_fifo_reserve, "vmwgfx" },
	{ "vmw_fifo_reserve_dx", (void *)&klpe_vmw_fifo_reserve_dx, "vmwgfx" },
	{ "vmw_resource_needs_backup", (void *)&klpe_vmw_resource_needs_backup,
	  "vmwgfx" },
	{ "vmw_resource_relocations_apply",
	  (void *)&klpe_vmw_resource_relocations_apply, "vmwgfx" },
	{ "vmw_resource_relocations_free",
	  (void *)&klpe_vmw_resource_relocations_free, "vmwgfx" },
	{ "vmw_resource_reserve", (void *)&klpe_vmw_resource_reserve,
	  "vmwgfx" },
	{ "vmw_resource_unreference", (void *)&klpe_vmw_resource_unreference,
	  "vmwgfx" },
	{ "vmw_resource_val_add", (void *)&klpe_vmw_resource_val_add,
	  "vmwgfx" },
	{ "vmw_resource_validate", (void *)&klpe_vmw_resource_validate,
	  "vmwgfx" },
	{ "vmw_resources_unreserve", (void *)&klpe_vmw_resources_unreserve,
	  "vmwgfx" },
	{ "vmw_update_seqno", (void *)&klpe_vmw_update_seqno, "vmwgfx" },
	{ "vmw_user_bo_lookup", (void *)&klpe_vmw_user_bo_lookup, "vmwgfx" },
	{ "vmw_user_resource_lookup_handle",
	  (void *)&klpe_vmw_user_resource_lookup_handle, "vmwgfx" },
	{ "vmw_validate_single_buffer",
	  (void *)&klpe_vmw_validate_single_buffer, "vmwgfx" },
	{ "vmw_wait_lag", (void *)&klpe_vmw_wait_lag, "vmwgfx" },
};

static int livepatch_bsc1195951_modify_notify(struct notifier_block *nb,
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

static struct notifier_block livepatch_bsc1195951_module_nb = {
	.notifier_call = livepatch_bsc1195951_modify_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1195951_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	if (find_module(LP_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&livepatch_bsc1195951_module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void livepatch_bsc1195951_cleanup(void)
{
	unregister_module_notifier(&livepatch_bsc1195951_module_nb);
}

#endif /* IS_ENABLED(CONFIG_DRM_VMWGFX) */
