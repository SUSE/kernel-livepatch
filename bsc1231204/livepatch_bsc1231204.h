#ifndef _LIVEPATCH_BSC1231204_H
#define _LIVEPATCH_BSC1231204_H

static inline int livepatch_bsc1231204_init(void) { return 0; }
static inline void livepatch_bsc1231204_cleanup(void) {}

/* klp-ccp: from drivers/gpu/drm/amd/display/include/gpio_types.h */
enum gpio_result {
	GPIO_RESULT_OK,
	GPIO_RESULT_NULL_HANDLE,
	GPIO_RESULT_INVALID_DATA,
	GPIO_RESULT_DEVICE_BUSY,
	GPIO_RESULT_OPEN_FAILED,
	GPIO_RESULT_ALREADY_OPENED,
	GPIO_RESULT_NON_SPECIFIC_ERROR
};

enum gpio_id {
	GPIO_ID_UNKNOWN = (-1),
	GPIO_ID_DDC_DATA,
	GPIO_ID_DDC_CLOCK,
	GPIO_ID_GENERIC,
	GPIO_ID_HPD,
	GPIO_ID_GPIO_PAD,
	GPIO_ID_VIP_PAD,
	GPIO_ID_SYNC,
	GPIO_ID_GSL, /* global swap lock */
	GPIO_ID_COUNT,
	GPIO_ID_MIN = GPIO_ID_DDC_DATA,
	GPIO_ID_MAX = GPIO_ID_GSL
};


struct gpio;
struct gpio_service;
struct hw_gpio_pin;

enum gpio_result klpp_dal_gpio_service_open(struct gpio *gpio);

void klpp_dal_gpio_service_close(struct gpio_service *service,
		                 struct hw_gpio_pin **ptr);

enum gpio_result klpp_dal_gpio_service_lock(struct gpio_service *service,
		                            enum gpio_id id,
		                            uint32_t en);

enum gpio_result klpp_dal_gpio_service_unlock(
		struct gpio_service *service,
		enum gpio_id id,
		uint32_t en);

#endif /* _LIVEPATCH_BSC1231204_H */
