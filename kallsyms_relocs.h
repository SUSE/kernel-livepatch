#ifndef _KLP_KALLSYMS_RELOCS
#define _KLP_KALLSYMS_RELOCS

struct klp_kallsyms_reloc
{
	const char *symname;
	void **addr;
	const char *objname;
	unsigned long sympos;
};

int __klp_resolve_kallsyms_relocs(struct klp_kallsyms_reloc *relocs,
				  unsigned long count);

#endif /* _KLP_KALLSYMS_RELOCS */
