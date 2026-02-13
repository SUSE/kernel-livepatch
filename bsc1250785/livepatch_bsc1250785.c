/*
 * livepatch_bsc1250785
 *
 * Fix for CVE-2022-50423, bsc#1250785
 *
 *  Copyright (c) 2026 SUSE
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

#if IS_ENABLED(CONFIG_ACPI)

/* klp-ccp: from drivers/acpi/acpica/utcopy.c */
#include <linux/acpi.h>
/* klp-ccp: from drivers/acpi/acpica/accommon.h */
#include <acpi/acconfig.h>	/* Global configuration constants */

/* klp-ccp: from drivers/acpi/acpica/aclocal.h */
struct acpi_walk_state;

struct acpi_namespace_node {
	union acpi_operand_object *object;	/* Interpreter object */
	u8 descriptor_type;	/* Differentiate object descriptor types */
	u8 type;		/* ACPI Type associated with this name */
	u16 flags;		/* Miscellaneous flags */
	union acpi_name_union name;	/* ACPI Name, always 4 chars per ACPI spec */
	struct acpi_namespace_node *parent;	/* Parent node */
	struct acpi_namespace_node *child;	/* First child */
	struct acpi_namespace_node *peer;	/* First peer */
	acpi_owner_id owner_id;	/* Node creator */

#ifdef ACPI_LARGE_NAMESPACE_NODE
#error "klp-ccp: non-taken branch"
#endif
};

typedef u32 acpi_status;

typedef
acpi_status (*acpi_internal_method) (struct acpi_walk_state * walk_state);

union acpi_generic_state;

/* klp-ccp: from drivers/acpi/acpica/acobject.h */
#define ACPI_OBJECT_COMMON_HEADER \
	union acpi_operand_object       *next_object;       /* Objects linked to parent NS node */\
	u8                              descriptor_type;    /* To differentiate various internal objs */\
	u8                              type;               /* acpi_object_type */\
	u16                             reference_count;    /* For object deletion management */\
	u8                              flags;

struct acpi_object_common {
ACPI_OBJECT_COMMON_HEADER};

struct acpi_object_integer {
	ACPI_OBJECT_COMMON_HEADER u8 fill[3];	/* Prevent warning on some compilers */
	u64 value;
};

#define ACPI_COMMON_BUFFER_INFO(_type) \
	_type                           *pointer; \
	u32                             length;

struct acpi_object_string {
	ACPI_OBJECT_COMMON_HEADER ACPI_COMMON_BUFFER_INFO(char)	/* String in AML stream or allocated string */
};

struct acpi_object_buffer {
	ACPI_OBJECT_COMMON_HEADER ACPI_COMMON_BUFFER_INFO(u8)	/* Buffer in AML stream or allocated buffer */
	u32 aml_length;
	u8 *aml_start;
	struct acpi_namespace_node *node;	/* Link back to parent node */
};

struct acpi_object_package {
	ACPI_OBJECT_COMMON_HEADER struct acpi_namespace_node *node;	/* Link back to parent node */
	union acpi_operand_object **elements;	/* Array of pointers to acpi_objects */
	u8 *aml_start;
	u32 aml_length;
	u32 count;		/* # of elements in package */
};

struct acpi_object_event {
	ACPI_OBJECT_COMMON_HEADER acpi_semaphore os_semaphore;	/* Actual OS synchronization object */
};

struct acpi_object_mutex {
	ACPI_OBJECT_COMMON_HEADER u8 sync_level;	/* 0-15, specified in Mutex() call */
	u16 acquisition_depth;	/* Allow multiple Acquires, same thread */
	acpi_mutex os_mutex;	/* Actual OS synchronization object */
	acpi_thread_id thread_id;	/* Current owner of the mutex */
	struct acpi_thread_state *owner_thread;	/* Current owner of the mutex */
	union acpi_operand_object *prev;	/* Link for list of acquired mutexes */
	union acpi_operand_object *next;	/* Link for list of acquired mutexes */
	struct acpi_namespace_node *node;	/* Containing namespace node */
	u8 original_sync_level;	/* Owner's original sync level (0-15) */
};

struct acpi_object_region {
	ACPI_OBJECT_COMMON_HEADER u8 space_id;
	struct acpi_namespace_node *node;	/* Containing namespace node */
	union acpi_operand_object *handler;	/* Handler for region access */
	union acpi_operand_object *next;
	acpi_physical_address address;
	u32 length;
};

struct acpi_object_method {
	ACPI_OBJECT_COMMON_HEADER u8 info_flags;
	u8 param_count;
	u8 sync_level;
	union acpi_operand_object *mutex;
	union acpi_operand_object *node;
	u8 *aml_start;
	union {
		acpi_internal_method implementation;
		union acpi_operand_object *handler;
	} dispatch;

	u32 aml_length;
	acpi_owner_id owner_id;
	u8 thread_count;
};

#define ACPI_COMMON_NOTIFY_INFO \
	union acpi_operand_object       *notify_list[2];    /* Handlers for system/device notifies */\
	union acpi_operand_object       *handler;	/* Handler for Address space */

struct acpi_object_notify_common {
ACPI_OBJECT_COMMON_HEADER ACPI_COMMON_NOTIFY_INFO};

struct acpi_object_device {
	ACPI_OBJECT_COMMON_HEADER
	    ACPI_COMMON_NOTIFY_INFO struct acpi_gpe_block_info *gpe_block;
};

struct acpi_object_power_resource {
	ACPI_OBJECT_COMMON_HEADER ACPI_COMMON_NOTIFY_INFO u32 system_level;
	u32 resource_order;
};

struct acpi_object_processor {
	ACPI_OBJECT_COMMON_HEADER
	    /* The next two fields take advantage of the 3-byte space before NOTIFY_INFO */
	u8 proc_id;
	u8 length;
	ACPI_COMMON_NOTIFY_INFO acpi_io_address address;
};

struct acpi_object_thermal_zone {
ACPI_OBJECT_COMMON_HEADER ACPI_COMMON_NOTIFY_INFO};

#define ACPI_COMMON_FIELD_INFO \
	u8                              field_flags;        /* Access, update, and lock bits */\
	u8                              attribute;          /* From access_as keyword */\
	u8                              access_byte_width;  /* Read/Write size in bytes */\
	struct acpi_namespace_node      *node;              /* Link back to parent node */\
	u32                             bit_length;         /* Length of field in bits */\
	u32                             base_byte_offset;   /* Byte offset within containing object */\
	u32                             value;              /* Value to store into the Bank or Index register */\
	u8                              start_field_bit_offset;/* Bit offset within first field datum (0-63) */\
	u8                              access_length;	/* For serial regions/fields */

struct acpi_object_field_common {
	ACPI_OBJECT_COMMON_HEADER ACPI_COMMON_FIELD_INFO union acpi_operand_object *region_obj;	/* Parent Operation Region object (REGION/BANK fields only) */
};

struct acpi_object_region_field {
	ACPI_OBJECT_COMMON_HEADER ACPI_COMMON_FIELD_INFO u16 resource_length;
	union acpi_operand_object *region_obj;	/* Containing op_region object */
	u8 *resource_buffer;	/* resource_template for serial regions/fields */
	u16 pin_number_index;	/* Index relative to previous Connection/Template */
};

struct acpi_object_bank_field {
	ACPI_OBJECT_COMMON_HEADER ACPI_COMMON_FIELD_INFO union acpi_operand_object *region_obj;	/* Containing op_region object */
	union acpi_operand_object *bank_obj;	/* bank_select Register object */
};

struct acpi_object_index_field {
	ACPI_OBJECT_COMMON_HEADER ACPI_COMMON_FIELD_INFO
	    /*
	     * No "RegionObj" pointer needed since the Index and Data registers
	     * are each field definitions unto themselves.
	     */
	union acpi_operand_object *index_obj;	/* Index register */
	union acpi_operand_object *data_obj;	/* Data register */
};

struct acpi_object_buffer_field {
	ACPI_OBJECT_COMMON_HEADER ACPI_COMMON_FIELD_INFO union acpi_operand_object *buffer_obj;	/* Containing Buffer object */
};

struct acpi_object_notify_handler {
	ACPI_OBJECT_COMMON_HEADER struct acpi_namespace_node *node;	/* Parent device */
	u32 handler_type;	/* Type: Device/System/Both */
	acpi_notify_handler handler;	/* Handler address */
	void *context;
	union acpi_operand_object *next[2];	/* Device and System handler lists */
};

struct acpi_object_addr_handler {
	ACPI_OBJECT_COMMON_HEADER u8 space_id;
	u8 handler_flags;
	acpi_adr_space_handler handler;
	struct acpi_namespace_node *node;	/* Parent device */
	void *context;
	acpi_adr_space_setup setup;
	union acpi_operand_object *region_list;	/* Regions using this handler */
	union acpi_operand_object *next;
};

struct acpi_object_reference {
	ACPI_OBJECT_COMMON_HEADER u8 class;	/* Reference Class */
	u8 target_type;		/* Used for Index Op */
	u8 resolved;		/* Reference has been resolved to a value */
	void *object;		/* name_op=>HANDLE to obj, index_op=>union acpi_operand_object */
	struct acpi_namespace_node *node;	/* ref_of or Namepath */
	union acpi_operand_object **where;	/* Target of Index */
	u8 *index_pointer;	/* Used for Buffers and Strings */
	u8 *aml;		/* Used for deferred resolution of the ref */
	u32 value;		/* Used for Local/Arg/Index/ddb_handle */
};

struct acpi_object_extra {
	ACPI_OBJECT_COMMON_HEADER struct acpi_namespace_node *method_REG;	/* _REG method for this region (if any) */
	struct acpi_namespace_node *scope_node;
	void *region_context;	/* Region-specific data */
	u8 *aml_start;
	u32 aml_length;
};

struct acpi_object_data {
	ACPI_OBJECT_COMMON_HEADER acpi_object_handler handler;
	void *pointer;
};

struct acpi_object_cache_list {
	ACPI_OBJECT_COMMON_HEADER union acpi_operand_object *next;	/* Link for object cache and internal lists */
};

union acpi_operand_object {
	struct acpi_object_common common;
	struct acpi_object_integer integer;
	struct acpi_object_string string;
	struct acpi_object_buffer buffer;
	struct acpi_object_package package;
	struct acpi_object_event event;
	struct acpi_object_method method;
	struct acpi_object_mutex mutex;
	struct acpi_object_region region;
	struct acpi_object_notify_common common_notify;
	struct acpi_object_device device;
	struct acpi_object_power_resource power_resource;
	struct acpi_object_processor processor;
	struct acpi_object_thermal_zone thermal_zone;
	struct acpi_object_field_common common_field;
	struct acpi_object_region_field field;
	struct acpi_object_buffer_field buffer_field;
	struct acpi_object_bank_field bank_field;
	struct acpi_object_index_field index_field;
	struct acpi_object_notify_handler notify;
	struct acpi_object_addr_handler address_space;
	struct acpi_object_reference reference;
	struct acpi_object_extra extra;
	struct acpi_object_data data;
	struct acpi_object_cache_list cache;

	/*
	 * Add namespace node to union in order to simplify code that accepts both
	 * ACPI_OPERAND_OBJECTs and ACPI_NAMESPACE_NODEs. The structures share
	 * a common descriptor_type field in order to differentiate them.
	 */
	struct acpi_namespace_node node;
};

/* klp-ccp: from drivers/acpi/acpica/acutils.h */
typedef
acpi_status (*acpi_pkg_callback) (u8 object_type,
				  union acpi_operand_object * source_object,
				  union acpi_generic_state * state,
				  void *context);

acpi_status
klpp_acpi_ut_copy_iobject_to_iobject(union acpi_operand_object *source_desc,
				union acpi_operand_object **dest_desc,
				struct acpi_walk_state *walk_state);

void
acpi_ut_trace(u32 line_number,
	      const char *function_name,
	      const char *module_name, u32 component_id);

void
acpi_ut_status_exit(u32 line_number,
		    const char *function_name,
		    const char *module_name,
		    u32 component_id, acpi_status status);

static void (*klpe_acpi_ut_remove_reference)(union acpi_operand_object *object);

static union acpi_operand_object *(*klpe_acpi_ut_create_internal_object_dbg)(const char
							      *module_name,
							      u32 line_number,
							      u32 component_id,
							      acpi_object_type
							      type);

static acpi_status
(*klpe_acpi_ut_walk_package_tree)(union acpi_operand_object *source_object,
			  void *target_object,
			  acpi_pkg_callback walk_callback, void *context);

/* klp-ccp: from drivers/acpi/acpica/utcopy.c */
static const char __attribute__ ((unused)) (*klpe__acpi_module_name)[];

static acpi_status
(*klpe_acpi_ut_copy_ielement_to_ielement)(u8 object_type,
				  union acpi_operand_object *source_object,
				  union acpi_generic_state *state,
				  void *context);

static acpi_status
(*klpe_acpi_ut_copy_simple_object)(union acpi_operand_object *source_desc,
			   union acpi_operand_object *dest_desc);

static acpi_status
klpp_acpi_ut_copy_ipackage_to_ipackage(union acpi_operand_object *source_obj,
				  union acpi_operand_object *dest_obj,
				  struct acpi_walk_state *walk_state);

static acpi_status
(*klpe_acpi_ut_copy_simple_object)(union acpi_operand_object *source_desc,
			   union acpi_operand_object *dest_desc);

static acpi_status
(*klpe_acpi_ut_copy_ielement_to_ielement)(u8 object_type,
				  union acpi_operand_object *source_object,
				  union acpi_generic_state *state,
				  void *context);

#define KLPR_AE_INFO ((const char *)klpe__acpi_module_name), __LINE__

#define KLPR_ACPI_ERROR(plist) \
	acpi_error plist

#define KLPR_AE_CODE_ENVIRONMENTAL           0x0000	/* General ACPICA environment */
#define KLPR_EXCEP_ENV(code)                 ((acpi_status) (code | KLPR_AE_CODE_ENVIRONMENTAL))
#define KLPR_AE_NO_MEMORY                    KLPR_EXCEP_ENV (0x0004)

#define KLPR_ACPI_UTILITIES              0x00000001
#define KLPR__COMPONENT          KLPR_ACPI_UTILITIES

#define KLPR_ACPI_DEBUG_PARAMETERS \
	__LINE__, __func__, (*klpe__acpi_module_name), KLPR__COMPONENT

#define ACPI_DO_WHILE0(a)               do a while(0)

#define KLPR_ACPI_TRACE_EXIT(function, type, param) \
	ACPI_DO_WHILE0 ({ \
		register type _param = (type) (param); \
		function (KLPR_ACPI_DEBUG_PARAMETERS, _param); \
		return (_param); \
	})

#define KLPR_return_ACPI_STATUS(status) \
	KLPR_ACPI_TRACE_EXIT (acpi_ut_status_exit, acpi_status, status)

#define KLPR_ACPI_FUNCTION_TRACE(name) \
	ACPI_FUNCTION_NAME(name) \
	acpi_ut_trace (KLPR_ACPI_DEBUG_PARAMETERS)

static acpi_status
klpp_acpi_ut_copy_ipackage_to_ipackage(union acpi_operand_object *source_obj,
				  union acpi_operand_object *dest_obj,
				  struct acpi_walk_state *walk_state)
{
	acpi_status status = AE_OK;

	KLPR_ACPI_FUNCTION_TRACE(ut_copy_ipackage_to_ipackage);

	dest_obj->common.type = source_obj->common.type;
	dest_obj->common.flags = source_obj->common.flags;
	dest_obj->package.count = source_obj->package.count;

	/*
	 * Create the object array and walk the source package tree
	 */
	dest_obj->package.elements = ACPI_ALLOCATE_ZEROED(((acpi_size)
							   source_obj->package.
							   count +
							   1) * sizeof(void *));
	if (!dest_obj->package.elements) {
		KLPR_ACPI_ERROR((KLPR_AE_INFO, "Package allocation failure"));
		KLPR_return_ACPI_STATUS(KLPR_AE_NO_MEMORY);
	}

	/*
	 * Copy the package element-by-element by walking the package "tree".
	 * This handles nested packages of arbitrary depth.
	 */
	status = (*klpe_acpi_ut_walk_package_tree)(source_obj, dest_obj,
					   (*klpe_acpi_ut_copy_ielement_to_ielement),
					   walk_state);
	KLPR_return_ACPI_STATUS(status);
}

#define klpr_acpi_ut_create_internal_object(t) \
	(*klpe_acpi_ut_create_internal_object_dbg)((*klpe__acpi_module_name),__LINE__,KLPR__COMPONENT,t)

acpi_status
klpp_acpi_ut_copy_iobject_to_iobject(union acpi_operand_object *source_desc,
				union acpi_operand_object **dest_desc,
				struct acpi_walk_state *walk_state)
{
	acpi_status status = AE_OK;

	KLPR_ACPI_FUNCTION_TRACE(ut_copy_iobject_to_iobject);


	/* Create the top level object */

	*dest_desc = klpr_acpi_ut_create_internal_object(source_desc->common.type);
	if (!*dest_desc) {
		KLPR_return_ACPI_STATUS(KLPR_AE_NO_MEMORY);
	}

	/* Copy the object and possible subobjects */

	if (source_desc->common.type == ACPI_TYPE_PACKAGE) {
		status =
		    klpp_acpi_ut_copy_ipackage_to_ipackage(source_desc, *dest_desc,
						      walk_state);
	} else {
		status = (*klpe_acpi_ut_copy_simple_object)(source_desc, *dest_desc);
	}

	/* Delete the allocated object if copy failed */

	if (ACPI_FAILURE(status)) {
		(*klpe_acpi_ut_remove_reference)(*dest_desc);
	}

	KLPR_return_ACPI_STATUS(status);
}


#include "livepatch_bsc1250785.h"

#include <linux/kernel.h>
#include "../kallsyms_relocs.h"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "_acpi_module_name", (void *)&klpe__acpi_module_name, NULL, 124 },
	{ "acpi_ut_copy_ielement_to_ielement",
	  (void *)&klpe_acpi_ut_copy_ielement_to_ielement },
	{ "acpi_ut_copy_simple_object",
	  (void *)&klpe_acpi_ut_copy_simple_object },
	{ "acpi_ut_create_internal_object_dbg",
	  (void *)&klpe_acpi_ut_create_internal_object_dbg },
	{ "acpi_ut_remove_reference", (void *)&klpe_acpi_ut_remove_reference },
	{ "acpi_ut_walk_package_tree",
	  (void *)&klpe_acpi_ut_walk_package_tree },
};

int livepatch_bsc1250785_init(void)
{
	return __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
}

#endif /* IS_ENABLED(CONFIG_ACPI) */
