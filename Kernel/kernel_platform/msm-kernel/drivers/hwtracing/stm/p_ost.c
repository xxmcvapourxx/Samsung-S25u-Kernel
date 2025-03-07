// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copied from drivers/hwtracing/stm.p-sys-t.c as of commit d69d5e83110f
 * ("stm class: Add MIPI SyS-T protocol support").
 *
 * Copyright (c) 2022 2024 Qualcomm Innovation Center, Inc. All rights reserved.
 * Copyright (c) 2020-2021 The Linux Foundation. All rights reserved.
 * Copyright (c) 2018, Intel Corporation.
 *
 * MIPI OST framing protocol for STM devices.
 */

#include <linux/configfs.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/slab.h>
#include <linux/stm.h>
#include <linux/sched/clock.h>
#include "stm.h"

#define OST_TOKEN_STARTSIMPLE		(0x10)
#define OST_VERSION_MIPI1		(0x10 << 8)
#define OST_ENTITY_FTRACE		(0x01 << 16)
#define OST_ENTITY_DIAG			(0xEE << 16)
#define OST_CONTROL_PROTOCOL		(0x0 << 24)

#define DATA_HEADER (OST_TOKEN_STARTSIMPLE | OST_VERSION_MIPI1 | \
			OST_ENTITY_FTRACE | OST_CONTROL_PROTOCOL)

#define STM_MAKE_VERSION(ma, mi)	((ma << 8) | mi)
#define STM_HEADER_MAGIC		(0x5953)

enum ost_entity_type {
	OST_ENTITY_TYPE_NONE,
	OST_ENTITY_TYPE_FTRACE,
	OST_ENTITY_TYPE_DIAG,
};

static const char * const str_ost_entity_type[] = {
	[OST_ENTITY_TYPE_NONE]		= "none",
	[OST_ENTITY_TYPE_FTRACE]	= "ftrace",
	[OST_ENTITY_TYPE_DIAG]		= "diag",
};

struct ost_t_policy_node {
	enum ost_entity_type	entity_type;
};

struct ost_t_output {
	struct ost_t_policy_node	node;
};

static int ost_t_output_open(void *priv, struct stm_output *output)
{
	struct ost_t_policy_node *pn = priv;
	struct ost_t_output *opriv;

	opriv = kzalloc(sizeof(*opriv), GFP_ATOMIC);
	if (!opriv)
		return -ENOMEM;

	memcpy(&opriv->node, pn, sizeof(opriv->node));
	output->pdrv_private = opriv;
	return 0;
}

static void ost_t_output_close(struct stm_output *output)
{
	kfree(output->pdrv_private);
}

static ssize_t ost_t_policy_entity_show(struct config_item *item,
				char *page)
{
	struct ost_t_policy_node *pn = to_pdrv_policy_node(item);

		return scnprintf(page, PAGE_SIZE, "%s\n",
			str_ost_entity_type[pn->entity_type]);
}

static ssize_t
ost_t_policy_entity_store(struct config_item *item, const char *page,
			size_t count)
{
	struct mutex *mutexp = &item->ci_group->cg_subsys->su_mutex;
	struct ost_t_policy_node *pn = to_pdrv_policy_node(item);
	char str[10] = "";

	mutex_lock(mutexp);
	if (sscanf(page, "%9s", str) != 1) {
		mutex_unlock(mutexp);
		return -EINVAL;
	}
	mutex_unlock(mutexp);

	if (!strcmp(str, str_ost_entity_type[OST_ENTITY_TYPE_FTRACE]))
		pn->entity_type = OST_ENTITY_TYPE_FTRACE;
	else if (!strcmp(str, str_ost_entity_type[OST_ENTITY_TYPE_DIAG]))
		pn->entity_type = OST_ENTITY_TYPE_DIAG;
	else
		return -EINVAL;
	return count;
}

CONFIGFS_ATTR(ost_t_policy_, entity);

static struct configfs_attribute *ost_t_policy_attrs[] = {
	&ost_t_policy_attr_entity,
	NULL,
};

static ssize_t notrace __nocfi ost_write(struct stm_data *data,
		struct stm_output *output, unsigned int chan,
		const char *buf, size_t count)
{
	unsigned int c = output->channel + chan;
	unsigned int m = output->master;
	const unsigned char nil = 0;
	u32 header = DATA_HEADER;
	u8 trc_hdr[24];
	ssize_t sz;
	struct ost_t_output *op = output->pdrv_private;

	if (op->node.entity_type == OST_ENTITY_TYPE_FTRACE)
		header |= OST_ENTITY_FTRACE;
	else
		header |= OST_ENTITY_DIAG;
	/*
	 * STP framing rules for OST frames:
	 *   * the first packet of the OST frame is marked;
	 *   * the last packet is a FLAG.
	 * Message layout: HEADER / DATA / TAIL
	 */

	/* HEADER */

	sz = data->packet(data, m, c, STP_PACKET_DATA, STP_PACKET_MARKED,
			  4, (u8 *)&header);
	if (sz <= 0)
		return sz;
	*(uint16_t *)(trc_hdr) = STM_MAKE_VERSION(0, 3);
	*(uint16_t *)(trc_hdr + 2) = STM_HEADER_MAGIC;
	*(uint32_t *)(trc_hdr + 4) = raw_smp_processor_id();
	*(uint64_t *)(trc_hdr + 8) = sched_clock();
	*(uint64_t *)(trc_hdr + 16) = task_tgid_nr(get_current());

	if (op->node.entity_type != OST_ENTITY_TYPE_DIAG) {
		sz = stm_data_write(data, m, c, false, trc_hdr, sizeof(trc_hdr));
		if (sz <= 0)
			return sz;
	}
	/* DATA */
	sz = stm_data_write(data, m, c, false, buf, count);

	/* TAIL */
	if (sz > 0)
		data->packet(data, m, c, STP_PACKET_FLAG,
			STP_PACKET_TIMESTAMPED, 0, &nil);

	return sz;
}

static const struct stm_protocol_driver ost_pdrv = {
	.owner	= THIS_MODULE,
	.name	= "p_ost",
	.priv_sz		= sizeof(struct ost_t_policy_node),
	.write	= ost_write,
	.policy_attr		= ost_t_policy_attrs,
	.output_open		= ost_t_output_open,
	.output_close		= ost_t_output_close,
};

static int ost_stm_init(void)
{
	return stm_register_protocol(&ost_pdrv);
}

static void ost_stm_exit(void)
{
	stm_unregister_protocol(&ost_pdrv);
}

module_init(ost_stm_init);
module_exit(ost_stm_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("MIPI Open System Trace STM framing protocol driver");
