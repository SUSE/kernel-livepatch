#ifndef _KGR_KALLSYMS_RELOCS
#define _KGR_KALLSYMS_RELOCS

struct kgr_kallsyms_reloc
{
	const char *symname;
	void **addr;
	const char *objname;
	unsigned long sympos;
};

int __kgr_resolve_kallsyms_relocs(struct kgr_kallsyms_reloc *relocs,
				  unsigned long count);

#endif /* _KGR_KALLSYMS_RELOCS */
