/*
 * Copyright (c) 2024 Qualcomm Innovation Center, Inc. All rights reserved.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "wlan_dp_ucfg_api.h"
#include "wlan_dp_svc.h"

QDF_STATUS ucfg_dp_svc_add(struct dp_svc_data *data)
{
	return dp_svc_add(data);
}

QDF_STATUS ucfg_dp_svc_remove(uint8_t svc_id)
{
	return dp_svc_remove(svc_id);
}

uint8_t ucfg_dp_svc_get(uint8_t svc_id,	struct dp_svc_data *svc_table,
			uint16_t table_size)
{
	return dp_svc_get(svc_id, svc_table, table_size);
}
