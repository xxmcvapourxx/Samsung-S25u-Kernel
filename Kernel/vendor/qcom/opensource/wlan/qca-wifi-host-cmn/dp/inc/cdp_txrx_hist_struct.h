/*
 * Copyright (c) 2020 The Linux Foundation. All rights reserved.
 * Copyright (c) 2022-2024 Qualcomm Innovation Center, Inc. All rights reserved.
 *
 * Permission to use, copy, modify, and/or distribute this software for
 * any purpose with or without fee is hereby granted, provided that the
 * above copyright notice and this permission notice appear in all
 * copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
 * WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
 * TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

/**
 * DOC: cdp_txrx_hist_struct.h
 *      Define the host data path histogram data types
 */
#ifndef _CDP_TXRX_HIST_STRUCT_H_
#define _CDP_TXRX_HIST_STRUCT_H_

#define CDP_RSSI_CHAIN_LEN 8
/**
 * enum cdp_hist_bucket_index - Histogram Bucket
 * @CDP_HIST_BUCKET_0: Bucket Index 0
 * @CDP_HIST_BUCKET_1: Bucket Index 1
 * @CDP_HIST_BUCKET_2: Bucket Index 2
 * @CDP_HIST_BUCKET_3: Bucket Index 3
 * @CDP_HIST_BUCKET_4: Bucket Index 4
 * @CDP_HIST_BUCKET_5: Bucket Index 5
 * @CDP_HIST_BUCKET_6: Bucket Index 6
 * @CDP_HIST_BUCKET_7: Bucket Index 7
 * @CDP_HIST_BUCKET_8: Bucket Index 8
 * @CDP_HIST_BUCKET_9: Bucket Index 9
 * @CDP_HIST_BUCKET_10: Bucket Index 10
 * @CDP_HIST_BUCKET_11: Bucket Index 11
 * @CDP_HIST_BUCKET_12: Bucket Index 12
 * @CDP_HIST_BUCKET_MAX: Max enumeration
 */
enum cdp_hist_bucket_index {
	CDP_HIST_BUCKET_0,
	CDP_HIST_BUCKET_1,
	CDP_HIST_BUCKET_2,
	CDP_HIST_BUCKET_3,
	CDP_HIST_BUCKET_4,
	CDP_HIST_BUCKET_5,
	CDP_HIST_BUCKET_6,
	CDP_HIST_BUCKET_7,
	CDP_HIST_BUCKET_8,
	CDP_HIST_BUCKET_9,
	CDP_HIST_BUCKET_10,
	CDP_HIST_BUCKET_11,
	CDP_HIST_BUCKET_12,
	CDP_HIST_BUCKET_MAX,
};

/**
 * enum cdp_hist_types - Histogram Types
 * @CDP_HIST_TYPE_SW_ENQEUE_DELAY: From stack to HW enqueue delay
 * @CDP_HIST_TYPE_HW_COMP_DELAY: From HW enqueue to completion delay
 * @CDP_HIST_TYPE_REAP_STACK: Rx HW reap to stack deliver delay
 * @CDP_HIST_TYPE_HW_TX_COMP_DELAY: Tx completion delay based on the timestamp
 *                                  provided by HW
 * @CDP_HIST_TYPE_DELAY_PERCENTILE: Tx completion delay based on the perctile
 * @CDP_HIST_TYPE_HW_COMP_DELAY_TSF: HW TX Compl delay for TSF report enabled
 * @CDP_HIST_TYPE_HW_COMP_DELAY_JITTER_TSF: HW TX Compl delay jitter for TSF report enabled
 * @CDP_HIST_TYPE_MAX: Max enumeration
 */
enum cdp_hist_types {
	CDP_HIST_TYPE_SW_ENQEUE_DELAY,
	CDP_HIST_TYPE_HW_COMP_DELAY,
	CDP_HIST_TYPE_REAP_STACK,
	CDP_HIST_TYPE_HW_TX_COMP_DELAY,
	CDP_HIST_TYPE_DELAY_PERCENTILE,
	CDP_HIST_TYPE_HW_COMP_DELAY_TSF,
	CDP_HIST_TYPE_HW_COMP_DELAY_JITTER_TSF,
	CDP_HIST_TYPE_MAX,
};

/**
 * struct cdp_hist_bucket - Histogram Bucket
 * @hist_type: Histogram type
 * @freq: Frequency
 */
struct cdp_hist_bucket {
	enum cdp_hist_types hist_type;
	uint64_t freq[CDP_HIST_BUCKET_MAX];
};

/**
 * struct cdp_hist_stats - Histogram of a stats type
 * @hist: Frequency distribution
 * @max: Max frequency
 * @min: Minimum frequency
 * @avg: Average frequency
 */
struct cdp_hist_stats {
	struct cdp_hist_bucket hist;
	int max;
	int min;
	int avg;
};
#endif /* _CDP_TXRX_HIST_STRUCT_H_ */
