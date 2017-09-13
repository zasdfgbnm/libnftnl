#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include <errno.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/netfilter/abcde.h>

#include "internal.h"
#include <libmnl/libmnl.h>
#include <libnftnl/expr.h>
#include <libnftnl/rule.h>

struct nftnl_expr_abcde {
	const char		*text;
};

static int nftnl_expr_abcde_set(struct nftnl_expr *e, uint16_t type,
				 const void *data, uint32_t data_len)
{
	struct nftnl_expr_abcde *abcde = nftnl_expr_data(e);
	switch(type){
	case NFTNL_EXPR_ABCDE_TEXT:
		abcde->text = strdup(data);
		if (!abcde->text)
			return -1;
		break;
	}
	return 0;
}

static const void *
nftnl_expr_abcde_get(const struct nftnl_expr *e, uint16_t type,
		      uint32_t *data_len)
{
	struct nftnl_expr_abcde *abcde = nftnl_expr_data(e);

	switch(type) {
	case NFTNL_EXPR_ABCDE_TEXT:
		*data_len = strlen(abcde->text)+1;
		return abcde->text;
	}
	return NULL;
}

static int nftnl_expr_abcde_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, NFTA_ABCDE_MAX) < 0)
		return MNL_CB_OK;

	switch(type) {
	case NFTNL_EXPR_ABCDE_TEXT:
		if (mnl_attr_validate(attr, MNL_TYPE_STRING) < 0)
			abi_breakage();
		break;
	}

	tb[type] = attr;
	return MNL_CB_OK;
}

static void
nftnl_expr_abcde_build(struct nlmsghdr *nlh, const struct nftnl_expr *e)
{
	struct nftnl_expr_abcde *abcde = nftnl_expr_data(e);

	if (e->flags & (1 << NFTNL_EXPR_ABCDE_TEXT))
		mnl_attr_put_strz(nlh, NFTNL_EXPR_ABCDE_TEXT, abcde->text);
}

static int
nftnl_expr_abcde_parse(struct nftnl_expr *e, struct nlattr *attr)
{
	struct nftnl_expr_abcde *abcde = nftnl_expr_data(e);
	struct nlattr *tb[NFTA_ABCDE_MAX+1] = {};

	if (mnl_attr_parse_nested(attr, nftnl_expr_abcde_cb, tb) < 0)
		return -1;

	if (tb[NFTNL_EXPR_ABCDE_TEXT]) {
		if (abcde->text)
			xfree(abcde->text);

		abcde->text = strdup(mnl_attr_get_str(tb[NFTNL_EXPR_ABCDE_TEXT]));
		if (!abcde->text)
			return -1;
		e->flags |= (1 << NFTNL_EXPR_ABCDE_TEXT);
	}

	return 0;
}

static int nftnl_expr_abcde_json_parse(struct nftnl_expr *e, json_t *root,
					struct nftnl_parse_err *err)
{
#ifdef JSON_PARSING
	const char *text;
	uint16_t group, qthreshold;

	text = nftnl_jansson_parse_str(root, "text", err);
	if (text != NULL)
		nftnl_expr_set_str(e, NFTNL_EXPR_ABCDE_TEXT, text);

	return 0;
#else
	errno = EOPNOTSUPP;
	return -1;
#endif
}

static int nftnl_expr_abcde_snprintf_default(char *buf, size_t size,
					   const struct nftnl_expr *e)
{
	struct nftnl_expr_abcde *abcde = nftnl_expr_data(e);
	int ret, offset = 0, len = size;

	if (e->flags & (1 << NFTNL_EXPR_ABCDE_TEXT)) {
		ret = snprintf(buf, len, "text %s ", abcde->text);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	return offset;
}

static int nftnl_expr_abcde_export(char *buf, size_t size,
				 const struct nftnl_expr *e, int type)
{
	struct nftnl_expr_abcde *abcde = nftnl_expr_data(e);
	NFTNL_BUF_INIT(b, buf, size);

	if (e->flags & (1 << NFTNL_EXPR_ABCDE_TEXT))
		nftnl_buf_str(&b, type, abcde->text, TEXT);

	return nftnl_buf_done(&b);
}

static int
nftnl_expr_abcde_snprintf(char *buf, size_t len, uint32_t type,
			uint32_t flags, const struct nftnl_expr *e)
{
	switch(type) {
	case NFTNL_OUTPUT_DEFAULT:
		return nftnl_expr_abcde_snprintf_default(buf, len, e);
	case NFTNL_OUTPUT_XML:
	case NFTNL_OUTPUT_JSON:
		return nftnl_expr_abcde_export(buf, len, e, type);
	default:
		break;
	}
	return -1;
}

static void nftnl_expr_abcde_free(const struct nftnl_expr *e)
{
	struct nftnl_expr_abcde *abcde = nftnl_expr_data(e);

	xfree(abcde->text);
}

static bool nftnl_expr_abcde_cmp(const struct nftnl_expr *e1,
				     const struct nftnl_expr *e2)
{
	struct nftnl_expr_abcde *l1 = nftnl_expr_data(e1);
	struct nftnl_expr_abcde *l2 = nftnl_expr_data(e2);
	return !strcmp(l1->text, l2->text);
}

struct expr_ops expr_ops_abcde = {
	.name		= "abcde",
	.alloc_len	= sizeof(struct nftnl_expr_abcde),
	.max_attr	= NFTA_ABCDE_MAX,
	.free		= nftnl_expr_abcde_free,
	.cmp		= nftnl_expr_abcde_cmp,
	.set		= nftnl_expr_abcde_set,
	.get		= nftnl_expr_abcde_get,
	.parse		= nftnl_expr_abcde_parse,
	.build		= nftnl_expr_abcde_build,
	.snprintf	= nftnl_expr_abcde_snprintf,
	.json_parse	= nftnl_expr_abcde_json_parse,
};
