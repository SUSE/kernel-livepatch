/*
 * kallsyms_relocs.c - resolve non-exported symbols
 *
 * Copyright (C) 2018 SUSE
 * Author: Nicolai Stange <nstange@suse.de>
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

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kallsyms.h>
#include "kallsyms_relocs.h"

struct find_args
{
	struct klp_kallsyms_reloc reloc;
	unsigned long match_count;
};

static int __find_callback(void *data, const char *name,
			   struct module *mod, unsigned long addr)
{
	struct find_args *args = data;

	if ((mod && !args->reloc.objname) || (!mod && args->reloc.objname))
		return 0;

	if (strcmp(args->reloc.symname, name))
		return 0;

	if (args->reloc.objname && strcmp(args->reloc.objname, mod->name))
		return 0;

	args->match_count++;

	/*
	 * Finish the search when the symbol is found for the desired
	 * position or the position is not defined.
	 */
	if (!args->reloc.sympos || args->match_count == args->reloc.sympos) {
		*args->reloc.addr = (void *)addr;
		return 1;
	}

	return 0;
}

static int (*klp_module_kallsyms_on_each_symbol)(int (*fn)(void *, const char *,
							   struct module *,
							   unsigned long),
						 void *data);

/* Bootstrap: resolve non-exported module_kallsyms_on_each_symbol() */
static int __kallsyms_relocs_init(void)
{
	const char symname[] = "module_kallsyms_on_each_symbol";

	if (klp_module_kallsyms_on_each_symbol)
		return 0;

	klp_module_kallsyms_on_each_symbol =
		(void *)kallsyms_lookup_name(symname);

	if (!klp_module_kallsyms_on_each_symbol) {
		pr_err("livepatch: symbol %s not resolved\n", symname);
		return -ENOENT;
	}

	return 0;
}

/*
 * Must be called with module_mutex held if any of the relocs'
 * ->objname can be non-NULL.
 */
int __klp_resolve_kallsyms_relocs(struct klp_kallsyms_reloc *relocs,
				  unsigned long count)
{
	int ret;
	unsigned long i;
	struct find_args args;

	ret = __kallsyms_relocs_init();
	if (ret)
		return ret;

	for (i = 0; i < count; ++i) {
		*relocs[i].addr = NULL;
		args.reloc = relocs[i];
		args.match_count = 0;

		if (args.reloc.objname) {
			klp_module_kallsyms_on_each_symbol(__find_callback,
							   &args);
		} else {
			kallsyms_on_each_symbol(__find_callback, &args);
		}

		if (!*relocs[i].addr) {
			if (relocs[i].objname) {
				pr_err("livepatch: symbol %s:%s not resolved\n",
				       relocs[i].objname, relocs[i].symname);
			} else {
				pr_err("livepatch: symbol %s not resolved\n",
				       relocs[i].symname);
			}

			return -ENOENT;
		}
	}

	return 0;
}
