/*
 * livepatch_bsc1254451
 *
 * Fix for CVE-2022-50327, bsc#1254451
 *
 *  Copyright (c) 2025 SUSE
 *  Author: Avinesh Kumar <avinesh.kumar@suse.com>
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

#if IS_ENABLED(CONFIG_ACPI_PROCESSOR)

#include <linux/module.h>
#include <linux/acpi.h>
#include <acpi/processor.h>

struct acpi_lpi_states_array {
	unsigned int size;
	unsigned int composite_states_size;
	struct acpi_lpi_state *entries;
	struct acpi_lpi_state *composite_states[ACPI_PROCESSOR_MAX_POWER];
};

static int obj_get_integer(union acpi_object *obj, u32 *value)
{
	if (obj->type != ACPI_TYPE_INTEGER)
		return -EINVAL;

	*value = obj->integer.value;
	return 0;
}

static int klpr_acpi_processor_evaluate_lpi(acpi_handle handle,
				       struct acpi_lpi_states_array *info)
{
	acpi_status status;
	int ret = 0;
	int pkg_count, state_idx = 1, loop;
	struct acpi_buffer buffer = { ACPI_ALLOCATE_BUFFER, NULL };
	union acpi_object *lpi_data;
	struct acpi_lpi_state *lpi_state;

	status = acpi_evaluate_object(handle, "_LPI", NULL, &buffer);
	if (ACPI_FAILURE(status)) {
		ACPI_DEBUG_PRINT((ACPI_DB_INFO, "No _LPI, giving up\n"));
		return -ENODEV;
	}

	lpi_data = buffer.pointer;

	/* There must be at least 4 elements = 3 elements + 1 package */
	if (!lpi_data || lpi_data->type != ACPI_TYPE_PACKAGE ||
	    lpi_data->package.count < 4) {
		pr_debug("not enough elements in _LPI\n");
		ret = -ENODATA;
		goto end;
	}

	pkg_count = lpi_data->package.elements[2].integer.value;

	/* Validate number of power states. */
	if (pkg_count < 1 || pkg_count != lpi_data->package.count - 3) {
		pr_debug("count given by _LPI is not valid\n");
		ret = -ENODATA;
		goto end;
	}

	lpi_state = kcalloc(pkg_count, sizeof(*lpi_state), GFP_KERNEL);
	if (!lpi_state) {
		ret = -ENOMEM;
		goto end;
	}

	info->size = pkg_count;
	info->entries = lpi_state;

	/* LPI States start at index 3 */
	for (loop = 3; state_idx <= pkg_count; loop++, state_idx++, lpi_state++) {
		union acpi_object *element, *pkg_elem, *obj;

		element = &lpi_data->package.elements[loop];
		if (element->type != ACPI_TYPE_PACKAGE || element->package.count < 7)
			continue;

		pkg_elem = element->package.elements;

		obj = pkg_elem + 6;
		if (obj->type == ACPI_TYPE_BUFFER) {
			struct acpi_power_register *reg;

			reg = (struct acpi_power_register *)obj->buffer.pointer;
			if (reg->space_id != ACPI_ADR_SPACE_SYSTEM_IO &&
			    reg->space_id != ACPI_ADR_SPACE_FIXED_HARDWARE)
				continue;

			lpi_state->address = reg->address;
			lpi_state->entry_method =
				reg->space_id == ACPI_ADR_SPACE_FIXED_HARDWARE ?
				ACPI_CSTATE_FFH : ACPI_CSTATE_SYSTEMIO;
		} else if (obj->type == ACPI_TYPE_INTEGER) {
			lpi_state->entry_method = ACPI_CSTATE_INTEGER;
			lpi_state->address = obj->integer.value;
		} else {
			continue;
		}

		/* elements[7,8] skipped for now i.e. Residency/Usage counter*/

		obj = pkg_elem + 9;
		if (obj->type == ACPI_TYPE_STRING)
			strlcpy(lpi_state->desc, obj->string.pointer,
				ACPI_CX_DESC_LEN);

		lpi_state->index = state_idx;
		if (obj_get_integer(pkg_elem + 0, &lpi_state->min_residency)) {
			pr_debug("No min. residency found, assuming 10 us\n");
			lpi_state->min_residency = 10;
		}

		if (obj_get_integer(pkg_elem + 1, &lpi_state->wake_latency)) {
			pr_debug("No wakeup residency found, assuming 10 us\n");
			lpi_state->wake_latency = 10;
		}

		if (obj_get_integer(pkg_elem + 2, &lpi_state->flags))
			lpi_state->flags = 0;

		if (obj_get_integer(pkg_elem + 3, &lpi_state->arch_flags))
			lpi_state->arch_flags = 0;

		if (obj_get_integer(pkg_elem + 4, &lpi_state->res_cnt_freq))
			lpi_state->res_cnt_freq = 1;

		if (obj_get_integer(pkg_elem + 5, &lpi_state->enable_parent_state))
			lpi_state->enable_parent_state = 0;
	}

	acpi_handle_debug(handle, "Found %d power states\n", state_idx);
end:
	kfree(buffer.pointer);
	return ret;
}

static int (*klpe_flat_state_cnt);

static int (*klpe_flatten_lpi_states)(struct acpi_processor *pr,
			      struct acpi_lpi_states_array *curr_level,
			      struct acpi_lpi_states_array *prev_level);

int klpp_acpi_processor_get_lpi_info(struct acpi_processor *pr)
{
	int ret, i;
	acpi_status status;
	acpi_handle handle = pr->handle, pr_ahandle;
	struct acpi_device *d = NULL;
	struct acpi_lpi_states_array info[2], *tmp, *prev, *curr;

	if (!osc_pc_lpi_support_confirmed)
		return -EOPNOTSUPP;

	if (!acpi_has_method(handle, "_LPI"))
		return -EINVAL;

	(*klpe_flat_state_cnt) = 0;
	prev = &info[0];
	curr = &info[1];
	handle = pr->handle;
	ret = klpr_acpi_processor_evaluate_lpi(handle, prev);
	if (ret)
		return ret;
	(*klpe_flatten_lpi_states)(pr, prev, NULL);

	status = acpi_get_parent(handle, &pr_ahandle);
	while (ACPI_SUCCESS(status)) {
		acpi_bus_get_device(pr_ahandle, &d);
		if (!d)
			break;

		handle = pr_ahandle;

		if (strcmp(acpi_device_hid(d), ACPI_PROCESSOR_CONTAINER_HID))
			break;

		/* can be optional ? */
		if (!acpi_has_method(handle, "_LPI"))
			break;

		ret = klpr_acpi_processor_evaluate_lpi(handle, curr);
		if (ret)
			break;

		/* flatten all the LPI states in this level of hierarchy */
		(*klpe_flatten_lpi_states)(pr, curr, prev);

		tmp = prev, prev = curr, curr = tmp;

		status = acpi_get_parent(handle, &pr_ahandle);
	}

	pr->power.count = (*klpe_flat_state_cnt);
	/* reset the index after flattening */
	for (i = 0; i < pr->power.count; i++)
		pr->power.lpi_states[i].index = i;

	/* Tell driver that _LPI is supported. */
	pr->flags.has_lpi = 1;
	pr->flags.power = 1;

	return 0;
}


#include "livepatch_bsc1254451.h"

#include <linux/kernel.h>
#include "../kallsyms_relocs.h"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "flat_state_cnt", (void *)&klpe_flat_state_cnt },
	{ "flatten_lpi_states", (void *)&klpe_flatten_lpi_states },
};

int livepatch_bsc1254451_init(void)
{
	return __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
}


#endif /* IS_ENABLED(CONFIG_ACPI_PROCESSOR) */
