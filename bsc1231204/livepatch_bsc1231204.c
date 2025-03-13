/*
 * livepatch_bsc1231204
 *
 * Fix for CVE-2024-46818, bsc#1231204
 *
 *  Upstream commit:
 *  2a5626eeb3b5 ("drm/amd/display: Check gpio_id before used as array index")
 *
 *  SLE12-SP5 commit:
 *  38ee0ddc7a7aacabb9d6a627c154fed4ae7abb7e
 *
 *  SLE15-SP3 commit:
 *  ed4c870bc43fa1ebadf629e974b62d13476d5012
 *
 *  SLE15-SP4 and -SP5 commit:
 *  53caf4b03bec76e77e415ca62472db32392ed261
 *
 *  SLE15-SP6 commit:
 *  ef2ff807933581d594a1c16a421d1d74280b1897
 *
 *  SLE MICRO-6-0 commit:
 *  ef2ff807933581d594a1c16a421d1d74280b1897
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

#include <linux/mm.h>

#include <asm/byteorder.h>

#include "livepatch_bsc1231204.h"

#define dc_breakpoint()		do {} while (0)

#define ASSERT_CRITICAL(expr) do {		\
		if (WARN_ON(!(expr)))		\
			dc_breakpoint();	\
	} while (0)

/* klp-ccp: from drivers/gpu/drm/amd/display/dc/irq_types.h */
struct dc_context;

enum gpio_pin_output_state {
	GPIO_PIN_OUTPUT_STATE_ACTIVE_LOW,
	GPIO_PIN_OUTPUT_STATE_ACTIVE_HIGH,
	GPIO_PIN_OUTPUT_STATE_DEFAULT = GPIO_PIN_OUTPUT_STATE_ACTIVE_LOW
};

enum gpio_mode {
	GPIO_MODE_UNKNOWN = (-1),
	GPIO_MODE_INPUT,
	GPIO_MODE_OUTPUT,
	GPIO_MODE_FAST_OUTPUT,
	GPIO_MODE_HARDWARE,
	GPIO_MODE_INTERRUPT
};

struct gpio_config_data;

/* klp-ccp: from drivers/gpu/drm/amd/display/dc/inc/hw/gpio.h */
union gpio_hw_container {
	struct hw_ddc *ddc;
	struct hw_generic *generic;
	struct hw_hpd *hpd;
};

struct gpio {
	struct gpio_service *service;
	struct hw_gpio_pin *pin;
	enum gpio_id id;
	uint32_t en;

	union gpio_hw_container hw_container;
	enum gpio_mode mode;

	/* when GPIO comes from VBIOS, it has defined output state */
	enum gpio_pin_output_state output_state;
};

/* klp-ccp: from drivers/gpu/drm/amd/display/dc/gpio/hw_translate.h */
struct hw_translate {
	const struct hw_translate_funcs *funcs;
};

/* klp-ccp: from drivers/gpu/drm/amd/display/dc/gpio/hw_factory.h */
struct hw_factory {
	uint32_t number_of_pins[GPIO_ID_COUNT];

	const struct hw_factory_funcs {
		void (*init_ddc_data)(
				struct hw_ddc **hw_ddc,
				struct dc_context *ctx,
				enum gpio_id id,
				uint32_t en);
		void (*init_generic)(
				struct hw_generic **hw_generic,
				struct dc_context *ctx,
				enum gpio_id id,
				uint32_t en);
		void (*init_hpd)(
				struct hw_hpd **hw_hpd,
				struct dc_context *ctx,
				enum gpio_id id,
				uint32_t en);
		struct hw_gpio_pin *(*get_hpd_pin)(
				struct gpio *gpio);
		struct hw_gpio_pin *(*get_ddc_pin)(
				struct gpio *gpio);
		struct hw_gpio_pin *(*get_generic_pin)(
				struct gpio *gpio);
		void (*define_hpd_registers)(
				struct hw_gpio_pin *pin,
				uint32_t en);
		void (*define_ddc_registers)(
				struct hw_gpio_pin *pin,
				uint32_t en);
		void (*define_generic_registers)(
				struct hw_gpio_pin *pin,
				uint32_t en);
	} *funcs;
};

/* klp-ccp: from drivers/gpu/drm/amd/display/dc/gpio/gpio_service.h */
struct gpio_service {
	struct dc_context *ctx;
	struct hw_translate translate;
	struct hw_factory factory;
	/*
	 * @brief
	 * Business storage.
	 * one byte For each member of 'enum gpio_id'
	 */
	char *busyness[GPIO_ID_COUNT];
};

/* klp-ccp: from drivers/gpu/drm/amd/display/dc/gpio/hw_gpio.h */
struct hw_gpio_pin {
	const struct hw_gpio_pin_funcs *funcs;
	enum gpio_id id;
	uint32_t en;
	enum gpio_mode mode;
	bool opened;
	struct dc_context *ctx;
};

struct hw_gpio_pin_funcs {
	void (*destroy)(
		struct hw_gpio_pin **ptr);
	bool (*open)(
		struct hw_gpio_pin *pin,
		enum gpio_mode mode);
	enum gpio_result (*get_value)(
		const struct hw_gpio_pin *pin,
		uint32_t *value);
	enum gpio_result (*set_value)(
		const struct hw_gpio_pin *pin,
		uint32_t value);
	enum gpio_result (*set_config)(
		struct hw_gpio_pin *pin,
		const struct gpio_config_data *config_data);
	enum gpio_result (*change_mode)(
		struct hw_gpio_pin *pin,
		enum gpio_mode mode);
	void (*close)(
		struct hw_gpio_pin *pin);
};

/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/../display/dc/gpio/gpio_service.c */
static bool klpp_is_pin_busy(
	const struct gpio_service *service,
	enum gpio_id id,
	uint32_t en)
{
	if (id == GPIO_ID_UNKNOWN)
		return false;

	return service->busyness[id][en];
}

static void klpp_set_pin_busy(
	struct gpio_service *service,
	enum gpio_id id,
	uint32_t en)
{
	if (id == GPIO_ID_UNKNOWN)
		return;

	service->busyness[id][en] = true;
}

static void klpp_set_pin_free(
	struct gpio_service *service,
	enum gpio_id id,
	uint32_t en)
{
	if (id == GPIO_ID_UNKNOWN)
		return;

	service->busyness[id][en] = false;
}

enum gpio_result klpp_dal_gpio_service_lock(
	struct gpio_service *service,
	enum gpio_id id,
	uint32_t en)
{
	if (id != GPIO_ID_UNKNOWN && !service->busyness[id]) {
		ASSERT_CRITICAL(false);
		return GPIO_RESULT_OPEN_FAILED;
	}

	klpp_set_pin_busy(service, id, en);
	return GPIO_RESULT_OK;
}

enum gpio_result klpp_dal_gpio_service_unlock(
	struct gpio_service *service,
	enum gpio_id id,
	uint32_t en)
{
	if (id != GPIO_ID_UNKNOWN && !service->busyness[id]) {
		ASSERT_CRITICAL(false);
		return GPIO_RESULT_OPEN_FAILED;
	}

	klpp_set_pin_free(service, id, en);
	return GPIO_RESULT_OK;
}

enum gpio_result klpp_dal_gpio_service_open(
	struct gpio *gpio)
{
	struct gpio_service *service = gpio->service;
	enum gpio_id id = gpio->id;
	uint32_t en = gpio->en;
	enum gpio_mode mode = gpio->mode;

	struct hw_gpio_pin **pin = &gpio->pin;


	if (!service->busyness[id]) {
		ASSERT_CRITICAL(false);
		return GPIO_RESULT_OPEN_FAILED;
	}

	if (klpp_is_pin_busy(service, id, en)) {
		ASSERT_CRITICAL(false);
		return GPIO_RESULT_DEVICE_BUSY;
	}

	switch (id) {
	case GPIO_ID_DDC_DATA:
		*pin = service->factory.funcs->get_ddc_pin(gpio);
		service->factory.funcs->define_ddc_registers(*pin, en);
	break;
	case GPIO_ID_DDC_CLOCK:
		*pin = service->factory.funcs->get_ddc_pin(gpio);
		service->factory.funcs->define_ddc_registers(*pin, en);
	break;
	case GPIO_ID_GENERIC:
		*pin = service->factory.funcs->get_generic_pin(gpio);
		service->factory.funcs->define_generic_registers(*pin, en);
	break;
	case GPIO_ID_HPD:
		*pin = service->factory.funcs->get_hpd_pin(gpio);
		service->factory.funcs->define_hpd_registers(*pin, en);
	break;

	//TODO: gsl and sync support? create_sync and create_gsl are NULL
	case GPIO_ID_SYNC:
	case GPIO_ID_GSL:
	break;
	default:
		ASSERT_CRITICAL(false);
		return GPIO_RESULT_NON_SPECIFIC_ERROR;
	}

	if (!*pin) {
		ASSERT_CRITICAL(false);
		return GPIO_RESULT_NON_SPECIFIC_ERROR;
	}

	if (!(*pin)->funcs->open(*pin, mode)) {
		ASSERT_CRITICAL(false);
		klpp_dal_gpio_service_close(service, pin);
		return GPIO_RESULT_OPEN_FAILED;
	}

	klpp_set_pin_busy(service, id, en);
	return GPIO_RESULT_OK;
}

void klpp_dal_gpio_service_close(
	struct gpio_service *service,
	struct hw_gpio_pin **ptr)
{
	struct hw_gpio_pin *pin;

	if (!ptr) {
		ASSERT_CRITICAL(false);
		return;
	}

	pin = *ptr;

	if (pin) {
		klpp_set_pin_free(service, pin->id, pin->en);

		pin->funcs->close(pin);

		*ptr = NULL;
	}
}

#endif /* IS_ENABLED(CONFIG_DRM_AMDGPU) */
