#ifndef _LIVEPATCH_BSC1223521_H
#define _LIVEPATCH_BSC1223521_H

#if IS_ENABLED(CONFIG_DRM_I915)

struct i915_perf_stream;
struct i915_active;

void klpp_gen12_disable_metric_set(struct i915_perf_stream *stream);
int klpp_gen12_enable_metric_set(struct i915_perf_stream *stream,
			struct i915_active *active);
int klpp_gen8_enable_metric_set(struct i915_perf_stream *stream,
		       struct i915_active *active);
void klpp_gen8_disable_metric_set(struct i915_perf_stream *stream);
void klpp_gen11_disable_metric_set(struct i915_perf_stream *stream);

int livepatch_bsc1223521_init(void);
void livepatch_bsc1223521_cleanup(void);


#else /* !IS_ENABLED(CONFIG_DRM_I915) */

static inline int livepatch_bsc1223521_init(void) { return 0; }
static inline void livepatch_bsc1223521_cleanup(void) {}

#endif /* IS_ENABLED(CONFIG_DRM_I915) */

#endif /* _LIVEPATCH_BSC1223521_H */
