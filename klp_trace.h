#ifndef _KLP_TRACE_H
#define _KLP_TRACE_H

#include <linux/tracepoint.h>
#include <linux/version.h>

/*
 * Since kernel 5.12, the data_args was removed from __DECLARE_TRACE.
 * Since kernel 5.10, the __tracepoint_iter_ symbols were renamed to
 * __traceiter_ in order to have shorter symbol names.
 * As we currently support kernels from 5.3 and then 5.14, we don't need special
 * ifdefery for kernel 5.10.
*/

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 12, 0)
#define KLPR___DECLARE_TRACE(name, proto, args, cond, data_proto, data_args)		\
	static struct tracepoint (*klpe___tracepoint_##name);				\
	static inline void klpr_trace_##name(proto)					\
	{										\
		if (unlikely(static_key_enabled(&(*klpe___tracepoint_##name).key)))	\
			__DO_TRACE(&(*klpe___tracepoint_##name),			\
				TP_PROTO(data_proto),					\
				TP_ARGS(data_args),					\
				TP_CONDITION(cond), 0);					\
		if (IS_ENABLED(CONFIG_LOCKDEP) && (cond)) {				\
			rcu_read_lock_sched_notrace();					\
			rcu_dereference_sched((*klpe___tracepoint_##name).funcs);	\
			rcu_read_unlock_sched_notrace();				\
		}									\
	}										\

#define KLPR_DECLARE_TRACE(name, proto, args)				\
	KLPR___DECLARE_TRACE(name, PARAMS(proto), PARAMS(args),		\
		cpu_online(raw_smp_processor_id()),			\
		PARAMS(void *__data, proto),				\
		PARAMS(__data, args))

#define KLPR_TRACE_EVENT(name, proto, args) \
	KLPR_DECLARE_TRACE(name, PARAMS(proto), PARAMS(args))

#elif LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0)

#define KLPR___DO_TRACE_CALL(name, args)   (*klpe___traceiter_##name)(NULL, args)

#define KLPR___DO_TRACE(name, args, cond, rcuidle)			\
	do {								\
		int __maybe_unused __idx = 0;				\
									\
		if (!(cond))						\
			return;						\
									\
		/* srcu can't be used from NMI */			\
		WARN_ON_ONCE(rcuidle && in_nmi());			\
									\
		/* keep srcu and sched-rcu usage consistent */		\
		preempt_disable_notrace();				\
									\
		/*							\
		 * For rcuidle callers, use srcu since sched-rcu	\
		 * doesn't work from the idle path.			\
		 */							\
		if (rcuidle) {						\
			__idx = srcu_read_lock_notrace(&tracepoint_srcu);\
			rcu_irq_enter_irqson();				\
		}							\
									\
		KLPR___DO_TRACE_CALL(name, TP_ARGS(args));		\
									\
		if (rcuidle) {						\
			rcu_irq_exit_irqson();				\
			srcu_read_unlock_notrace(&tracepoint_srcu, __idx);\
		}							\
									\
		preempt_enable_notrace();				\
	} while (0)

#define KLPR___DECLARE_TRACE(name, proto, args, cond, data_proto)		\
	static int (*klpe___traceiter_##name)(data_proto);			\
	static struct tracepoint (*klpe___tracepoint_##name);			\
	static inline void klpr_trace_##name(proto)				\
	{									\
		if (static_key_enabled(&(*klpe___tracepoint_##name).key))	\
		KLPR___DO_TRACE(name,						\
				TP_ARGS(args),					\
				TP_CONDITION(cond), 0);				\
		if (IS_ENABLED(CONFIG_LOCKDEP) && (cond)) {			\
			rcu_read_lock_sched_notrace();				\
			rcu_dereference_sched((*klpe___tracepoint_##name).funcs);\
			rcu_read_unlock_sched_notrace();			\
		}								\
	}									\


#define KLPR_DECLARE_TRACE(name, proto, args)			\
	KLPR___DECLARE_TRACE(name, PARAMS(proto), PARAMS(args),	\
		cpu_online(raw_smp_processor_id()),		\
		PARAMS(void *__data, proto))

#define KLPR_TRACE_EVENT(name, proto, args) \
	KLPR_DECLARE_TRACE(name, PARAMS(proto), PARAMS(args))

#else /* LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0) */

#define KLPR___DO_TRACE_CALL(name, args)   __traceiter_##name(NULL, args)

#define KLPR___DO_TRACE(name, args, cond, rcuidle)			\
	do {								\
		int __maybe_unused __idx = 0;				\
									\
		if (!(cond))						\
			return;						\
									\
		if (WARN_ON_ONCE(RCUIDLE_COND(rcuidle)))		\
			return;						\
									\
		/* keep srcu and sched-rcu usage consistent */		\
		preempt_disable_notrace();				\
									\
		/*							\
		 * For rcuidle callers, use srcu since sched-rcu	\
		 * doesn't work from the idle path.			\
		 */							\
		if (rcuidle) {						\
			__idx = srcu_read_lock_notrace(&tracepoint_srcu);\
			ct_irq_enter_irqson();				\
		}							\
									\
		KLPR___DO_TRACE_CALL(name, TP_ARGS(args));		\
									\
		if (rcuidle) {						\
			ct_irq_exit_irqson();				\
			srcu_read_unlock_notrace(&tracepoint_srcu, __idx);\
		}							\
									\
		preempt_enable_notrace();				\
	} while (0)


/* module - name of module the tracepoint is from for KLP_RELOC_SYMBOL macro */
#include <linux/livepatch.h>

#define KLPR___DECLARE_TRACE(module, name, proto, args, cond, data_proto)	\
	extern int __traceiter_##name(data_proto) \
			KLP_RELOC_SYMBOL(module, module, __traceiter_##name);			\
	extern struct tracepoint __tracepoint_##name \
			KLP_RELOC_SYMBOL(module, module, __tracepoint_##name);			\
	static inline void klpr_trace_##name(proto)				\
	{									\
		if (static_key_enabled(&__tracepoint_##name.key))	\
			KLPR___DO_TRACE(name,					\
				TP_ARGS(args),					\
				TP_CONDITION(cond), 0);				\
		if (IS_ENABLED(CONFIG_LOCKDEP) && (cond)) {			\
			WARN_ON_ONCE(!rcu_is_watching());		\
		}								\
	}									\


#define KLPR_DECLARE_TRACE(module, name, proto, args)			\
	KLPR___DECLARE_TRACE(module, name, PARAMS(proto), PARAMS(args),	\
		cpu_online(raw_smp_processor_id()),		\
		PARAMS(void *__data, proto))

#define KLPR_TRACE_EVENT(module, name, proto, args) \
	KLPR_DECLARE_TRACE(module, name, PARAMS(proto), PARAMS(args))

#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(5, 12, 0) */


#endif /* _KLP_TRACE_H */
