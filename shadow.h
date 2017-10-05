#ifndef _KGR_SHADOW_H
#define _KGR_SHADOW_H

void *klp_shadow_get(void *obj, unsigned long id);
void *klp_shadow_alloc(void *obj, unsigned long id, void *data,
		       size_t size, gfp_t gfp_flags);
void *klp_shadow_get_or_alloc(void *obj, unsigned long id, void *data,
			      size_t size, gfp_t gfp_flags);
void klp_shadow_free(void *obj, unsigned long id);
void klp_shadow_free_all(unsigned long id);

#endif
