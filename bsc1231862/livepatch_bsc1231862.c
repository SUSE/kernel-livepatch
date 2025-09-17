/*
 * livepatch_bsc1231862
 *
 * Fix for CVE-2024-49860, bsc#1231862
 *
 *  Copyright (c) 2025 SUSE
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

/* klp-ccp: from drivers/acpi/device_sysfs.c */
#include <linux/acpi.h>
#include <linux/device.h>
#include <linux/export.h>

/* klp-ccp: from drivers/acpi/device_sysfs.c */
static void (*klpe_acpi_expose_nondev_subnodes)(struct kobject *kobj,
					struct acpi_device_data *data);

static struct device_attribute (*klpe_dev_attr_modalias);

static struct device_attribute (*klpe_dev_attr_real_power_state);

static struct device_attribute (*klpe_dev_attr_power_state);

static struct device_attribute (*klpe_dev_attr_eject);

static struct device_attribute (*klpe_dev_attr_hid);

static struct device_attribute (*klpe_dev_attr_uid);

static struct device_attribute (*klpe_dev_attr_adr);

static struct device_attribute (*klpe_dev_attr_path);

static struct device_attribute (*klpe_dev_attr_description);

static struct device_attribute (*klpe_dev_attr_sun);

static struct device_attribute (*klpe_dev_attr_hrv);

static struct device_attribute (*klpe_dev_attr_status);

int klpp_acpi_device_setup_files(struct acpi_device *dev)
{
	struct acpi_buffer buffer = {ACPI_ALLOCATE_BUFFER, NULL};
	acpi_status status;
	int result = 0;

	/*
	 * Devices gotten from FADT don't have a "path" attribute
	 */
	if (dev->handle) {
		result = device_create_file(&dev->dev, &(*klpe_dev_attr_path));
		if (result)
			goto end;
	}

	if (!list_empty(&dev->pnp.ids)) {
		result = device_create_file(&dev->dev, &(*klpe_dev_attr_hid));
		if (result)
			goto end;

		result = device_create_file(&dev->dev, &(*klpe_dev_attr_modalias));
		if (result)
			goto end;
	}

	/*
	 * If device has _STR, 'description' file is created
	 */
	if (acpi_has_method(dev->handle, "_STR")) {
		status = acpi_evaluate_object_typed(dev->handle, "_STR",
						    NULL, &buffer,
						    ACPI_TYPE_BUFFER);
		if (ACPI_FAILURE(status))
			buffer.pointer = NULL;
		dev->pnp.str_obj = buffer.pointer;
		result = device_create_file(&dev->dev, &(*klpe_dev_attr_description));
		if (result)
			goto end;
	}

	if (dev->pnp.type.bus_address)
		result = device_create_file(&dev->dev, &(*klpe_dev_attr_adr));
	if (dev->pnp.unique_id)
		result = device_create_file(&dev->dev, &(*klpe_dev_attr_uid));

	if (acpi_has_method(dev->handle, "_SUN")) {
		result = device_create_file(&dev->dev, &(*klpe_dev_attr_sun));
		if (result)
			goto end;
	}

	if (acpi_has_method(dev->handle, "_HRV")) {
		result = device_create_file(&dev->dev, &(*klpe_dev_attr_hrv));
		if (result)
			goto end;
	}

	if (acpi_has_method(dev->handle, "_STA")) {
		result = device_create_file(&dev->dev, &(*klpe_dev_attr_status));
		if (result)
			goto end;
	}

	/*
	 * If device has _EJ0, 'eject' file is created that is used to trigger
	 * hot-removal function from userland.
	 */
	if (acpi_has_method(dev->handle, "_EJ0")) {
		result = device_create_file(&dev->dev, &(*klpe_dev_attr_eject));
		if (result)
			return result;
	}

	if (dev->flags.power_manageable) {
		result = device_create_file(&dev->dev, &(*klpe_dev_attr_power_state));
		if (result)
			return result;

		if (dev->power.flags.power_resources)
			result = device_create_file(&dev->dev,
						    &(*klpe_dev_attr_real_power_state));
	}

	(*klpe_acpi_expose_nondev_subnodes)(&dev->dev.kobj, &dev->data);

end:
	return result;
}


#include "livepatch_bsc1231862.h"

#include <linux/kernel.h>
#include "../kallsyms_relocs.h"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "acpi_expose_nondev_subnodes",
	  (void *)&klpe_acpi_expose_nondev_subnodes },
	{ "dev_attr_adr", (void *)&klpe_dev_attr_adr },
	{ "dev_attr_description", (void *)&klpe_dev_attr_description, NULL, 1 },
	{ "dev_attr_eject", (void *)&klpe_dev_attr_eject },
	{ "dev_attr_hid", (void *)&klpe_dev_attr_hid },
	{ "dev_attr_hrv", (void *)&klpe_dev_attr_hrv },
	{ "dev_attr_modalias", (void *)&klpe_dev_attr_modalias, NULL, 2 },
	{ "dev_attr_path", (void *)&klpe_dev_attr_path },
	{ "dev_attr_power_state", (void *)&klpe_dev_attr_power_state },
	{ "dev_attr_real_power_state",
	  (void *)&klpe_dev_attr_real_power_state },
	{ "dev_attr_status", (void *)&klpe_dev_attr_status, NULL, 1 },
	{ "dev_attr_sun", (void *)&klpe_dev_attr_sun },
	{ "dev_attr_uid", (void *)&klpe_dev_attr_uid, NULL, 1 },
};

int livepatch_bsc1231862_init(void)
{
	return __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
}


#endif /* IS_ENABLED(CONFIG_ACPI) */
