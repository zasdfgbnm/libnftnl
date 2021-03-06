/*
 * (C) 2016 Red Hat GmbH
 * Author: Florian Westphal <fw@strlen.de>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <arpa/inet.h>
#include <errno.h>
#include <linux/netfilter/nf_tables.h>

#include "internal.h"
#include <libmnl/libmnl.h>
#include <libnftnl/expr.h>
#include <libnftnl/rule.h>

struct nftnl_expr_fib {
	uint32_t		flags;
	uint32_t		result;
	enum nft_registers	dreg;
};

static int
nftnl_expr_fib_set(struct nftnl_expr *e, uint16_t result,
		    const void *data, uint32_t data_len)
{
	struct nftnl_expr_fib *fib = nftnl_expr_data(e);

	switch (result) {
	case NFTNL_EXPR_FIB_RESULT:
		fib->result = *((uint32_t *)data);
		break;
	case NFTNL_EXPR_FIB_DREG:
		fib->dreg = *((uint32_t *)data);
		break;
	case NFTNL_EXPR_FIB_FLAGS:
		fib->flags = *((uint32_t *)data);
		break;
	default:
		return -1;
	}
	return 0;
}

static const void *
nftnl_expr_fib_get(const struct nftnl_expr *e, uint16_t result,
		    uint32_t *data_len)
{
	struct nftnl_expr_fib *fib = nftnl_expr_data(e);

	switch (result) {
	case NFTNL_EXPR_FIB_RESULT:
		*data_len = sizeof(fib->result);
		return &fib->result;
	case NFTNL_EXPR_FIB_DREG:
		*data_len = sizeof(fib->dreg);
		return &fib->dreg;
	case NFTNL_EXPR_FIB_FLAGS:
		*data_len = sizeof(fib->flags);
		return &fib->flags;
	}
	return NULL;
}

static int nftnl_expr_fib_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, NFTA_FIB_MAX) < 0)
		return MNL_CB_OK;

	switch (type) {
	case NFTA_FIB_RESULT:
	case NFTA_FIB_DREG:
	case NFTA_FIB_FLAGS:
		if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0)
			abi_breakage();
		break;
	}

	tb[type] = attr;
	return MNL_CB_OK;
}

static void
nftnl_expr_fib_build(struct nlmsghdr *nlh, const struct nftnl_expr *e)
{
	struct nftnl_expr_fib *fib = nftnl_expr_data(e);

	if (e->flags & (1 << NFTNL_EXPR_FIB_FLAGS))
		mnl_attr_put_u32(nlh, NFTA_FIB_FLAGS, htonl(fib->flags));
	if (e->flags & (1 << NFTNL_EXPR_FIB_RESULT))
		mnl_attr_put_u32(nlh, NFTA_FIB_RESULT, htonl(fib->result));
	if (e->flags & (1 << NFTNL_EXPR_FIB_DREG))
		mnl_attr_put_u32(nlh, NFTA_FIB_DREG, htonl(fib->dreg));
}

static int
nftnl_expr_fib_parse(struct nftnl_expr *e, struct nlattr *attr)
{
	struct nftnl_expr_fib *fib = nftnl_expr_data(e);
	struct nlattr *tb[NFTA_FIB_MAX+1] = {};
	int ret = 0;

	if (mnl_attr_parse_nested(attr, nftnl_expr_fib_cb, tb) < 0)
		return -1;

	if (tb[NFTA_FIB_RESULT]) {
		fib->result = ntohl(mnl_attr_get_u32(tb[NFTA_FIB_RESULT]));
		e->flags |= (1 << NFTNL_EXPR_FIB_RESULT);
	}
	if (tb[NFTA_FIB_DREG]) {
		fib->dreg = ntohl(mnl_attr_get_u32(tb[NFTA_FIB_DREG]));
		e->flags |= (1 << NFTNL_EXPR_FIB_DREG);
	}
	if (tb[NFTA_FIB_FLAGS]) {
		fib->flags = ntohl(mnl_attr_get_u32(tb[NFTA_FIB_FLAGS]));
		e->flags |= (1 << NFTNL_EXPR_FIB_FLAGS);
	}
	return ret;
}

static int nftnl_expr_fib_json_parse(struct nftnl_expr *e, json_t *root,
				      struct nftnl_parse_err *err)
{
#ifdef JSON_PARSING
	uint32_t result, flags, dreg;

	if (nftnl_jansson_parse_reg(root, "result", NFTNL_TYPE_U32,
				    &result, err) == 0)
		nftnl_expr_set_u32(e, NFTNL_EXPR_FIB_RESULT, result);

	if (nftnl_jansson_parse_reg(root, "dreg", NFTNL_TYPE_U32,
				    &dreg, err) == 0)
		nftnl_expr_set_u32(e, NFTNL_EXPR_FIB_DREG, dreg);

	if (nftnl_jansson_parse_val(root, "flags", NFTNL_TYPE_U32,
				    &flags, err) == 0)
		nftnl_expr_set_u32(e, NFTNL_EXPR_FIB_FLAGS, flags);

	return 0;
#else
	errno = EOPNOTSUPP;
	return -1;
#endif
}

static const char *fib_type[NFT_FIB_RESULT_MAX + 1] = {
	[NFT_FIB_RESULT_OIF] = "oif",
	[NFT_FIB_RESULT_OIFNAME] = "oifname",
	[NFT_FIB_RESULT_ADDRTYPE] = "type",
};

static const char *fib_type_str(enum nft_fib_result r)
{
	if (r <= NFT_FIB_RESULT_MAX)
		return fib_type[r];

	return "unknown";
}

static int
nftnl_expr_fib_snprintf_default(char *buf, size_t size,
				const struct nftnl_expr *e)
{
	struct nftnl_expr_fib *fib = nftnl_expr_data(e);
	int remain = size, offset = 0, ret, i;
	uint32_t flags = fib->flags & ~NFTA_FIB_F_PRESENT;
	uint32_t present_flag = fib->flags & NFTA_FIB_F_PRESENT;
	static const struct {
		int bit;
		const char *name;
	} tab[] = {
		{ NFTA_FIB_F_SADDR, "saddr" },
		{ NFTA_FIB_F_DADDR, "daddr" },
		{ NFTA_FIB_F_MARK, "mark" },
		{ NFTA_FIB_F_IIF, "iif" },
		{ NFTA_FIB_F_OIF, "oif" },
	};

	for (i = 0; i < (sizeof(tab) / sizeof(tab[0])); i++) {
		if (flags & tab[i].bit) {
			ret = snprintf(buf + offset, remain, "%s ",
				       tab[i].name);
			SNPRINTF_BUFFER_SIZE(ret, remain, offset);

			flags &= ~tab[i].bit;
			if (flags) {
				ret = snprintf(buf + offset, remain, ". ");
				SNPRINTF_BUFFER_SIZE(ret, remain, offset);
			}
		}
	}

	if (flags) {
		ret = snprintf(buf + offset, remain, "unknown 0x%" PRIx32,
			       flags);
		SNPRINTF_BUFFER_SIZE(ret, remain, offset);
	}

	ret = snprintf(buf + offset, remain, "%s%s => reg %d ",
		       fib_type_str(fib->result),
		       present_flag ? " present" : "",
		       fib->dreg);
	SNPRINTF_BUFFER_SIZE(ret, remain, offset);

	return offset;
}

static int nftnl_expr_fib_export(char *buf, size_t size,
				  const struct nftnl_expr *e, int type)
{
	struct nftnl_expr_fib *fib = nftnl_expr_data(e);

	NFTNL_BUF_INIT(b, buf, size);

	if (e->flags & (1 << NFTNL_EXPR_FIB_RESULT))
		nftnl_buf_u32(&b, type, fib->result, OP);
	if (e->flags & (1 << NFTNL_EXPR_FIB_DREG))
		nftnl_buf_u32(&b, type, fib->dreg, DREG);
	if (e->flags & (1 << NFTNL_EXPR_FIB_FLAGS))
		nftnl_buf_u32(&b, type, fib->flags, FLAGS);

	return nftnl_buf_done(&b);
}

static int
nftnl_expr_fib_snprintf(char *buf, size_t len, uint32_t type,
			 uint32_t flags, const struct nftnl_expr *e)
{
	if (len)
		buf[0] = '\0';

	switch (type) {
	case NFTNL_OUTPUT_DEFAULT:
		return nftnl_expr_fib_snprintf_default(buf, len, e);
	case NFTNL_OUTPUT_XML:
	case NFTNL_OUTPUT_JSON:
		return nftnl_expr_fib_export(buf, len, e, type);
	default:
		break;
	}
	return -1;
}

static bool nftnl_expr_fib_cmp(const struct nftnl_expr *e1,
				const struct nftnl_expr *e2)
{
       struct nftnl_expr_fib *h1 = nftnl_expr_data(e1);
       struct nftnl_expr_fib *h2 = nftnl_expr_data(e2);
       bool eq = true;

       if (e1->flags & (1 << NFTNL_EXPR_FIB_RESULT))
               eq &= (h1->result == h2->result);
       if (e1->flags & (1 << NFTNL_EXPR_FIB_DREG))
               eq &= (h1->dreg == h2->dreg);
       if (e1->flags & (1 << NFTNL_EXPR_FIB_FLAGS))
               eq &= (h1->flags == h2->flags);

       return eq;
}

struct expr_ops expr_ops_fib = {
	.name		= "fib",
	.alloc_len	= sizeof(struct nftnl_expr_fib),
	.max_attr	= NFTA_FIB_MAX,
	.cmp		= nftnl_expr_fib_cmp,
	.set		= nftnl_expr_fib_set,
	.get		= nftnl_expr_fib_get,
	.parse		= nftnl_expr_fib_parse,
	.build		= nftnl_expr_fib_build,
	.snprintf	= nftnl_expr_fib_snprintf,
	.json_parse	= nftnl_expr_fib_json_parse,
};
