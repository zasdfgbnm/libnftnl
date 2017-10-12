#include <string.h>
#include <linux_list.h>

#ifdef PLUGIN
#include <dlfcn.h>
#endif

#include "expr_ops.h"

/* Unfortunately, __attribute__((constructor)) breaks library static linking */
extern struct expr_ops expr_ops_bitwise;
extern struct expr_ops expr_ops_byteorder;
extern struct expr_ops expr_ops_cmp;
extern struct expr_ops expr_ops_counter;
extern struct expr_ops expr_ops_ct;
extern struct expr_ops expr_ops_dup;
extern struct expr_ops expr_ops_exthdr;
extern struct expr_ops expr_ops_fwd;
extern struct expr_ops expr_ops_immediate;
extern struct expr_ops expr_ops_limit;
extern struct expr_ops expr_ops_log;
extern struct expr_ops expr_ops_lookup;
extern struct expr_ops expr_ops_masq;
extern struct expr_ops expr_ops_match;
extern struct expr_ops expr_ops_meta;
extern struct expr_ops expr_ops_ng;
extern struct expr_ops expr_ops_nat;
extern struct expr_ops expr_ops_objref;
extern struct expr_ops expr_ops_payload;
extern struct expr_ops expr_ops_range;
extern struct expr_ops expr_ops_redir;
extern struct expr_ops expr_ops_reject;
extern struct expr_ops expr_ops_rt;
extern struct expr_ops expr_ops_queue;
extern struct expr_ops expr_ops_quota;
extern struct expr_ops expr_ops_target;
extern struct expr_ops expr_ops_dynset;
extern struct expr_ops expr_ops_hash;
extern struct expr_ops expr_ops_fib;

static struct expr_ops expr_ops_notrack = {
	.name	= "notrack",
};

static struct expr_ops *expr_ops[] = {
	&expr_ops_bitwise,
	&expr_ops_byteorder,
	&expr_ops_cmp,
	&expr_ops_counter,
	&expr_ops_ct,
	&expr_ops_dup,
	&expr_ops_exthdr,
	&expr_ops_fwd,
	&expr_ops_immediate,
	&expr_ops_limit,
	&expr_ops_log,
	&expr_ops_lookup,
	&expr_ops_masq,
	&expr_ops_match,
	&expr_ops_meta,
	&expr_ops_ng,
	&expr_ops_nat,
	&expr_ops_notrack,
	&expr_ops_payload,
	&expr_ops_range,
	&expr_ops_redir,
	&expr_ops_reject,
	&expr_ops_rt,
	&expr_ops_queue,
	&expr_ops_quota,
	&expr_ops_target,
	&expr_ops_dynset,
	&expr_ops_hash,
	&expr_ops_fib,
	&expr_ops_objref,
	NULL,
};

#ifdef PLUGIN
static int loaded_plugins = 0;
static struct plugin *plugins = NULL;

static int nftnl_find_plugin_handle(void *handle)
{
	int i;
	for (i = 0; i < loaded_plugins && plugins[i].handle != handle; i++);
	return i;
}
#endif

void *nftnl_load_plugin(const char *name)
{
#ifdef PLUGIN
	void *handle;
	struct expr_ops **expr_ops;
	char *error;

	handle = dlopen (name, RTLD_LAZY);
	if (!handle)
		return NULL;

	expr_ops = dlsym(handle, "expr_ops");
	if ((error = dlerror()) != NULL)
		goto fail;

	loaded_plugins++;

	static struct plugin *new_plugins = NULL;
	new_plugins = realloc(plugins, loaded_plugins * sizeof(*plugins));
	if (!new_plugins)
		goto fail;
	plugins = new_plugins;

	plugins[loaded_plugins - 1] = {
		.handle = handle;
		.expr_ops = expr_ops;
	};

	return handle;
fail:
	dlclose(handle);
#endif

	return NULL;
}

int nftnl_unload_plugin(void *handle)
{
#ifdef PLUGIN
	int index = nftnl_find_plugin_handle(handle);
	for (;index < loaded_plugins - 1; index++)
		plugins[index] = plugins[index+1];
	loaded_plugins--;
	plugins = realloc(plugins, loaded_plugins * sizeof(*plugins));
	return dlclose(handle);
#else
	return -1;
#endif
}

static struct expr_ops *
__nftnl_expr_ops_lookup(struct expr_ops ** table, const char *name)
{
	int i = 0;

	while (table[i] != NULL) {
		if (strcmp(table[i]->name, name) == 0)
			return table[i];
		i++;
	}
	return NULL;
}

struct expr_ops *nftnl_expr_ops_lookup(const char *name)
{
	struct expr_ops *result = __nftnl_expr_ops_lookup(expr_ops);
	if (result != NULL)
		return result;

#ifdef PLUGIN
	for (i = 0; i < loaded_plugins; i++) {
		__nftnl_expr_ops_lookup(plugins[i].expr_ops);
		if (result != NULL)
			return result;
	}
#endif

	return NULL;
}
