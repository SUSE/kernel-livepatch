#ifndef _KGR_PATCH_COMPAT
#define _KGR_PATCH_COMPAT

#ifndef KGR_PATCH_OBJ
  #define __KGR_PATCH(_name, _new_function, abort) {	\
		.name = #_name,				\
		.new_fun = _new_function,		\
		.abort_if_missing = abort,		\
	  }

  #undef KGR_PATCH

  #define KGR_PATCH(_name, _new_function) \
	__KGR_PATCH(_name, _new_function, true)
  #define KGR_PATCH_OBJ(_name, _new_function, _objname) \
	__KGR_PATCH(_name, _new_function, !_objname)
  #define KGR_PATCH_OBJPOS(_name, _new_function, _objname, _sympos) \
	__KGR_PATCH(_name, _new_function, !_objname)
#endif

#endif
