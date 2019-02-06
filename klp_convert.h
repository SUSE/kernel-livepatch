#ifndef _KLP_KLPCONVERT_H
#define _KLP_KLPCONVERT_H

#ifdef USE_KLP_CONVERT

#define KLP_SYM_LINKAGE extern
#define KLP_SYM(sym) sym

#else

#define KLP_SYM_LINKAGE static
#define KLP_SYM(sym) (*klp_##sym)

#endif

#endif
