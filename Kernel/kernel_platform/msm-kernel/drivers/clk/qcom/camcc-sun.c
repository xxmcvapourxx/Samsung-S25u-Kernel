// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2023-2024, Qualcomm Innovation Center, Inc. All rights reserved.
 */

#include <linux/clk.h>
#include <linux/clk-provider.h>
#include <linux/err.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/of_device.h>
#include <linux/of.h>
#include <linux/regmap.h>
#include <linux/pm_runtime.h>

#include <dt-bindings/clock/qcom,camcc-sun.h>

#include "clk-alpha-pll.h"
#include "clk-branch.h"
#include "clk-pll.h"
#include "clk-rcg.h"
#include "clk-regmap.h"
#include "clk-regmap-divider.h"
#include "clk-regmap-mux.h"
#include "common.h"
#include "reset.h"
#include "vdd-level.h"

static DEFINE_VDD_REGULATORS(vdd_mm, VDD_NOMINAL + 1, 1, vdd_corner);
static DEFINE_VDD_REGULATORS(vdd_mx, VDD_LOW + 1, 1, vdd_corner);
static DEFINE_VDD_REGULATORS(vdd_mxc, VDD_NOMINAL + 1, 1, vdd_corner);

static struct clk_vdd_class *cam_cc_sun_regulators[] = {
	&vdd_mm,
	&vdd_mx,
	&vdd_mxc,
};

static struct clk_vdd_class *cam_cc_sun_regulators_1[] = {
	&vdd_mm,
	&vdd_mxc,
};

static struct clk_crm cam_crm = {
	.name = "cam_crm",
	.regs = {
		.cfg_rcgr = 0x150,
		.l_val = 0x154,
		.curr_perf = 0x6c,
	},
	.offsets = {
		.vcd = 0x210,
		.level = 0x18,
	},
};

enum {
	P_BI_TCXO,
	P_CAM_CC_PLL0_OUT_EVEN,
	P_CAM_CC_PLL0_OUT_MAIN,
	P_CAM_CC_PLL0_OUT_ODD,
	P_CAM_CC_PLL1_OUT_EVEN,
	P_CAM_CC_PLL2_OUT_EVEN,
	P_CAM_CC_PLL3_OUT_EVEN,
	P_CAM_CC_PLL4_OUT_EVEN,
	P_CAM_CC_PLL5_OUT_EVEN,
	P_CAM_CC_PLL6_OUT_EVEN,
	P_CAM_CC_PLL6_OUT_ODD,
	P_SLEEP_CLK,
};

static const struct pll_vco taycan_elu_vco[] = {
	{ 249600000, 2500000000, 0 },
};

static const struct alpha_pll_config cam_cc_pll0_config = {
	.l = 0x3e,
	.cal_l = 0x44,
	.alpha = 0x8000,
	.config_ctl_val = 0x19660387,
	.config_ctl_hi_val = 0x098060a0,
	.config_ctl_hi1_val = 0xb416cb20,
	.user_ctl_val = 0x00008400,
	.user_ctl_hi_val = 0x00000002,
};

static struct clk_alpha_pll cam_cc_pll0 = {
	.offset = 0x0,
	.vco_table = taycan_elu_vco,
	.num_vco = ARRAY_SIZE(taycan_elu_vco),
	.regs = clk_alpha_pll_regs[CLK_ALPHA_PLL_TYPE_TAYCAN_ELU],
	.flags = ENABLE_IN_PREPARE | DISABLE_TO_OFF,
	.clkr = {
		.hw.init = &(const struct clk_init_data) {
			.name = "cam_cc_pll0",
			.parent_data = &(const struct clk_parent_data) {
				.fw_name = "bi_tcxo",
			},
			.num_parents = 1,
			.ops = &clk_alpha_pll_taycan_elu_ops,
		},
		.vdd_data = {
			.vdd_class = &vdd_mxc,
			.num_rate_max = VDD_NUM,
			.rate_max = (unsigned long[VDD_NUM]) {
				[VDD_LOWER_D1] = 1600000000,
				[VDD_LOW] = 1600000000,
				[VDD_LOW_L1] = 1600000000,
				[VDD_NOMINAL] = 2000000000,
				[VDD_HIGH] = 2500000000},
		},
	},
};

static const struct clk_div_table post_div_table_cam_cc_pll0_out_even[] = {
	{ 0x1, 2 },
	{ }
};

static struct clk_alpha_pll_postdiv cam_cc_pll0_out_even = {
	.offset = 0x0,
	.post_div_shift = 10,
	.post_div_table = post_div_table_cam_cc_pll0_out_even,
	.num_post_div = ARRAY_SIZE(post_div_table_cam_cc_pll0_out_even),
	.width = 4,
	.regs = clk_alpha_pll_regs[CLK_ALPHA_PLL_TYPE_TAYCAN_ELU],
	.clkr.hw.init = &(const struct clk_init_data) {
		.name = "cam_cc_pll0_out_even",
		.parent_hws = (const struct clk_hw*[]) {
			&cam_cc_pll0.clkr.hw,
		},
		.num_parents = 1,
		.flags = CLK_SET_RATE_PARENT,
		.ops = &clk_alpha_pll_postdiv_taycan_elu_ops,
	},
};

static const struct clk_div_table post_div_table_cam_cc_pll0_out_odd[] = {
	{ 0x2, 3 },
	{ }
};

static struct clk_alpha_pll_postdiv cam_cc_pll0_out_odd = {
	.offset = 0x0,
	.post_div_shift = 14,
	.post_div_table = post_div_table_cam_cc_pll0_out_odd,
	.num_post_div = ARRAY_SIZE(post_div_table_cam_cc_pll0_out_odd),
	.width = 4,
	.regs = clk_alpha_pll_regs[CLK_ALPHA_PLL_TYPE_TAYCAN_ELU],
	.clkr.hw.init = &(const struct clk_init_data) {
		.name = "cam_cc_pll0_out_odd",
		.parent_hws = (const struct clk_hw*[]) {
			&cam_cc_pll0.clkr.hw,
		},
		.num_parents = 1,
		.flags = CLK_SET_RATE_PARENT,
		.ops = &clk_alpha_pll_postdiv_taycan_elu_ops,
	},
};

static const struct alpha_pll_config cam_cc_pll1_config = {
	.l = 0x22,
	.cal_l = 0x44,
	.alpha = 0xa2aa,
	.config_ctl_val = 0x19660387,
	.config_ctl_hi_val = 0x098060a0,
	.config_ctl_hi1_val = 0xb416cb20,
	.user_ctl_val = 0x00000400,
	.user_ctl_hi_val = 0x00000002,
};

static struct clk_alpha_pll cam_cc_pll1 = {
	.offset = 0x1000,
	.vco_table = taycan_elu_vco,
	.num_vco = ARRAY_SIZE(taycan_elu_vco),
	.regs = clk_alpha_pll_regs[CLK_ALPHA_PLL_TYPE_TAYCAN_ELU],
	.flags = DISABLE_TO_OFF,
	.clkr = {
		.hw.init = &(const struct clk_init_data) {
			.name = "cam_cc_pll1",
			.parent_data = &(const struct clk_parent_data) {
				.fw_name = "bi_tcxo",
			},
			.num_parents = 1,
			.ops = &clk_alpha_pll_taycan_elu_ops,
		},
		.vdd_data = {
			.vdd_class = &vdd_mxc,
			.num_rate_max = VDD_NUM,
			.rate_max = (unsigned long[VDD_NUM]) {
				[VDD_LOWER_D1] = 1600000000,
				[VDD_LOW] = 1600000000,
				[VDD_LOW_L1] = 1600000000,
				[VDD_NOMINAL] = 2000000000,
				[VDD_HIGH] = 2500000000},
		},
	},
};

static const struct clk_div_table post_div_table_cam_cc_pll1_out_even[] = {
	{ 0x1, 2 },
	{ }
};

static struct clk_alpha_pll_postdiv cam_cc_pll1_out_even = {
	.offset = 0x1000,
	.post_div_shift = 10,
	.post_div_table = post_div_table_cam_cc_pll1_out_even,
	.num_post_div = ARRAY_SIZE(post_div_table_cam_cc_pll1_out_even),
	.width = 4,
	.regs = clk_alpha_pll_regs[CLK_ALPHA_PLL_TYPE_TAYCAN_ELU],
	.clkr.hw.init = &(const struct clk_init_data) {
		.name = "cam_cc_pll1_out_even",
		.parent_hws = (const struct clk_hw*[]) {
			&cam_cc_pll1.clkr.hw,
		},
		.num_parents = 1,
		.flags = CLK_SET_RATE_PARENT,
		.ops = &clk_alpha_pll_postdiv_taycan_elu_ops,
	},
};

static const struct alpha_pll_config cam_cc_pll2_config = {
	.l = 0x23,
	.cal_l = 0x44,
	.alpha = 0x4aaa,
	.config_ctl_val = 0x19660387,
	.config_ctl_hi_val = 0x098060a0,
	.config_ctl_hi1_val = 0xb416cb20,
	.user_ctl_val = 0x00000400,
	.user_ctl_hi_val = 0x00000002,
};

static struct clk_alpha_pll cam_cc_pll2 = {
	.offset = 0x2000,
	.vco_table = taycan_elu_vco,
	.num_vco = ARRAY_SIZE(taycan_elu_vco),
	.regs = clk_alpha_pll_regs[CLK_ALPHA_PLL_TYPE_TAYCAN_ELU],
	.flags = DISABLE_TO_OFF,
	.clkr = {
		.hw.init = &(const struct clk_init_data) {
			.name = "cam_cc_pll2",
			.parent_data = &(const struct clk_parent_data) {
				.fw_name = "bi_tcxo",
			},
			.num_parents = 1,
			.ops = &clk_alpha_pll_taycan_elu_ops,
		},
		.vdd_data = {
			.vdd_class = &vdd_mxc,
			.num_rate_max = VDD_NUM,
			.rate_max = (unsigned long[VDD_NUM]) {
				[VDD_LOWER_D1] = 1600000000,
				[VDD_LOW] = 1600000000,
				[VDD_LOW_L1] = 1600000000,
				[VDD_NOMINAL] = 2000000000,
				[VDD_HIGH] = 2500000000},
		},
	},
};

static const struct clk_div_table post_div_table_cam_cc_pll2_out_even[] = {
	{ 0x1, 2 },
	{ }
};

static struct clk_alpha_pll_postdiv cam_cc_pll2_out_even = {
	.offset = 0x2000,
	.post_div_shift = 10,
	.post_div_table = post_div_table_cam_cc_pll2_out_even,
	.num_post_div = ARRAY_SIZE(post_div_table_cam_cc_pll2_out_even),
	.width = 4,
	.regs = clk_alpha_pll_regs[CLK_ALPHA_PLL_TYPE_TAYCAN_ELU],
	.clkr.hw.init = &(const struct clk_init_data) {
		.name = "cam_cc_pll2_out_even",
		.parent_hws = (const struct clk_hw*[]) {
			&cam_cc_pll2.clkr.hw,
		},
		.num_parents = 1,
		.flags = CLK_SET_RATE_PARENT,
		.ops = &clk_alpha_pll_postdiv_taycan_elu_ops,
	},
};

static const struct alpha_pll_config cam_cc_pll3_config = {
	.l = 0x25,
	.cal_l = 0x44,
	.alpha = 0x8777,
	.config_ctl_val = 0x19660387,
	.config_ctl_hi_val = 0x098060a0,
	.config_ctl_hi1_val = 0xb416cb20,
	.user_ctl_val = 0x00000400,
	.user_ctl_hi_val = 0x00000002,
};

static struct clk_alpha_pll cam_cc_pll3 = {
	.offset = 0x3000,
	.vco_table = taycan_elu_vco,
	.num_vco = ARRAY_SIZE(taycan_elu_vco),
	.regs = clk_alpha_pll_regs[CLK_ALPHA_PLL_TYPE_TAYCAN_ELU],
	.flags = DISABLE_TO_OFF,
	.clkr = {
		.hw.init = &(const struct clk_init_data) {
			.name = "cam_cc_pll3",
			.parent_data = &(const struct clk_parent_data) {
				.fw_name = "bi_tcxo",
			},
			.num_parents = 1,
			.ops = &clk_alpha_pll_crm_taycan_elu_ops,
		},
		.vdd_data = {
			.vdd_class = &vdd_mxc,
			.num_rate_max = VDD_NUM,
			.rate_max = (unsigned long[VDD_NUM]) {
				[VDD_LOWER_D1] = 1600000000,
				[VDD_LOW] = 1600000000,
				[VDD_LOW_L1] = 1600000000,
				[VDD_NOMINAL] = 2000000000,
				[VDD_HIGH] = 2500000000},
		},
	},
};

static const struct clk_div_table post_div_table_cam_cc_pll3_out_even[] = {
	{ 0x1, 2 },
	{ }
};

static struct clk_alpha_pll_postdiv cam_cc_pll3_out_even = {
	.offset = 0x3000,
	.post_div_shift = 10,
	.post_div_table = post_div_table_cam_cc_pll3_out_even,
	.num_post_div = ARRAY_SIZE(post_div_table_cam_cc_pll3_out_even),
	.width = 4,
	.regs = clk_alpha_pll_regs[CLK_ALPHA_PLL_TYPE_TAYCAN_ELU],
	.clkr.hw.init = &(const struct clk_init_data) {
		.name = "cam_cc_pll3_out_even",
		.parent_hws = (const struct clk_hw*[]) {
			&cam_cc_pll3.clkr.hw,
		},
		.num_parents = 1,
		.flags = CLK_SET_RATE_PARENT,
		.ops = &clk_alpha_pll_crm_postdiv_taycan_elu_ops,
	},
};

static const struct alpha_pll_config cam_cc_pll4_config = {
	.l = 0x25,
	.cal_l = 0x44,
	.alpha = 0x8777,
	.config_ctl_val = 0x19660387,
	.config_ctl_hi_val = 0x098060a0,
	.config_ctl_hi1_val = 0xb416cb20,
	.user_ctl_val = 0x00000400,
	.user_ctl_hi_val = 0x00000002,
};

static struct clk_alpha_pll cam_cc_pll4 = {
	.offset = 0x4000,
	.vco_table = taycan_elu_vco,
	.num_vco = ARRAY_SIZE(taycan_elu_vco),
	.regs = clk_alpha_pll_regs[CLK_ALPHA_PLL_TYPE_TAYCAN_ELU],
	.flags = DISABLE_TO_OFF,
	.clkr = {
		.hw.init = &(const struct clk_init_data) {
			.name = "cam_cc_pll4",
			.parent_data = &(const struct clk_parent_data) {
				.fw_name = "bi_tcxo",
			},
			.num_parents = 1,
			.ops = &clk_alpha_pll_crm_taycan_elu_ops,
		},
		.vdd_data = {
			.vdd_class = &vdd_mxc,
			.num_rate_max = VDD_NUM,
			.rate_max = (unsigned long[VDD_NUM]) {
				[VDD_LOWER_D1] = 1600000000,
				[VDD_LOW] = 1600000000,
				[VDD_LOW_L1] = 1600000000,
				[VDD_NOMINAL] = 2000000000,
				[VDD_HIGH] = 2500000000},
		},
	},
};

static const struct clk_div_table post_div_table_cam_cc_pll4_out_even[] = {
	{ 0x1, 2 },
	{ }
};

static struct clk_alpha_pll_postdiv cam_cc_pll4_out_even = {
	.offset = 0x4000,
	.post_div_shift = 10,
	.post_div_table = post_div_table_cam_cc_pll4_out_even,
	.num_post_div = ARRAY_SIZE(post_div_table_cam_cc_pll4_out_even),
	.width = 4,
	.regs = clk_alpha_pll_regs[CLK_ALPHA_PLL_TYPE_TAYCAN_ELU],
	.clkr.hw.init = &(const struct clk_init_data) {
		.name = "cam_cc_pll4_out_even",
		.parent_hws = (const struct clk_hw*[]) {
			&cam_cc_pll4.clkr.hw,
		},
		.num_parents = 1,
		.flags = CLK_SET_RATE_PARENT,
		.ops = &clk_alpha_pll_crm_postdiv_taycan_elu_ops,
	},
};

static const struct alpha_pll_config cam_cc_pll5_config = {
	.l = 0x25,
	.cal_l = 0x44,
	.alpha = 0x8777,
	.config_ctl_val = 0x19660387,
	.config_ctl_hi_val = 0x098060a0,
	.config_ctl_hi1_val = 0xb416cb20,
	.user_ctl_val = 0x00000400,
	.user_ctl_hi_val = 0x00000002,
};

static struct clk_alpha_pll cam_cc_pll5 = {
	.offset = 0x5000,
	.vco_table = taycan_elu_vco,
	.num_vco = ARRAY_SIZE(taycan_elu_vco),
	.regs = clk_alpha_pll_regs[CLK_ALPHA_PLL_TYPE_TAYCAN_ELU],
	.flags = DISABLE_TO_OFF,
	.clkr = {
		.hw.init = &(const struct clk_init_data) {
			.name = "cam_cc_pll5",
			.parent_data = &(const struct clk_parent_data) {
				.fw_name = "bi_tcxo",
			},
			.num_parents = 1,
			.ops = &clk_alpha_pll_crm_taycan_elu_ops,
		},
		.vdd_data = {
			.vdd_class = &vdd_mxc,
			.num_rate_max = VDD_NUM,
			.rate_max = (unsigned long[VDD_NUM]) {
				[VDD_LOWER_D1] = 1600000000,
				[VDD_LOW] = 1600000000,
				[VDD_LOW_L1] = 1600000000,
				[VDD_NOMINAL] = 2000000000,
				[VDD_HIGH] = 2500000000},
		},
	},
};

static const struct clk_div_table post_div_table_cam_cc_pll5_out_even[] = {
	{ 0x1, 2 },
	{ }
};

static struct clk_alpha_pll_postdiv cam_cc_pll5_out_even = {
	.offset = 0x5000,
	.post_div_shift = 10,
	.post_div_table = post_div_table_cam_cc_pll5_out_even,
	.num_post_div = ARRAY_SIZE(post_div_table_cam_cc_pll5_out_even),
	.width = 4,
	.regs = clk_alpha_pll_regs[CLK_ALPHA_PLL_TYPE_TAYCAN_ELU],
	.clkr.hw.init = &(const struct clk_init_data) {
		.name = "cam_cc_pll5_out_even",
		.parent_hws = (const struct clk_hw*[]) {
			&cam_cc_pll5.clkr.hw,
		},
		.num_parents = 1,
		.flags = CLK_SET_RATE_PARENT,
		.ops = &clk_alpha_pll_crm_postdiv_taycan_elu_ops,
	},
};

static const struct alpha_pll_config cam_cc_pll6_config = {
	.l = 0x32,
	.cal_l = 0x44,
	.alpha = 0x0,
	.config_ctl_val = 0x19660387,
	.config_ctl_hi_val = 0x098060a0,
	.config_ctl_hi1_val = 0xb416cb20,
	.user_ctl_val = 0x00008400,
	.user_ctl_hi_val = 0x00000002,
};

static struct clk_alpha_pll cam_cc_pll6 = {
	.offset = 0x6000,
	.vco_table = taycan_elu_vco,
	.num_vco = ARRAY_SIZE(taycan_elu_vco),
	.regs = clk_alpha_pll_regs[CLK_ALPHA_PLL_TYPE_TAYCAN_ELU],
	.flags = DISABLE_TO_OFF,
	.clkr = {
		.hw.init = &(const struct clk_init_data) {
			.name = "cam_cc_pll6",
			.parent_data = &(const struct clk_parent_data) {
				.fw_name = "bi_tcxo",
			},
			.num_parents = 1,
			.ops = &clk_alpha_pll_taycan_elu_ops,
		},
		.vdd_data = {
			.vdd_class = &vdd_mxc,
			.num_rate_max = VDD_NUM,
			.rate_max = (unsigned long[VDD_NUM]) {
				[VDD_LOWER_D1] = 1600000000,
				[VDD_LOW] = 1600000000,
				[VDD_LOW_L1] = 1600000000,
				[VDD_NOMINAL] = 2000000000,
				[VDD_HIGH] = 2500000000},
		},
	},
};

static const struct clk_div_table post_div_table_cam_cc_pll6_out_even[] = {
	{ 0x1, 2 },
	{ }
};

static struct clk_alpha_pll_postdiv cam_cc_pll6_out_even = {
	.offset = 0x6000,
	.post_div_shift = 10,
	.post_div_table = post_div_table_cam_cc_pll6_out_even,
	.num_post_div = ARRAY_SIZE(post_div_table_cam_cc_pll6_out_even),
	.width = 4,
	.regs = clk_alpha_pll_regs[CLK_ALPHA_PLL_TYPE_TAYCAN_ELU],
	.clkr.hw.init = &(const struct clk_init_data) {
		.name = "cam_cc_pll6_out_even",
		.parent_hws = (const struct clk_hw*[]) {
			&cam_cc_pll6.clkr.hw,
		},
		.num_parents = 1,
		.flags = CLK_SET_RATE_PARENT,
		.ops = &clk_alpha_pll_postdiv_taycan_elu_ops,
	},
};

static const struct clk_div_table post_div_table_cam_cc_pll6_out_odd[] = {
	{ 0x2, 3 },
	{ }
};

static struct clk_alpha_pll_postdiv cam_cc_pll6_out_odd = {
	.offset = 0x6000,
	.post_div_shift = 14,
	.post_div_table = post_div_table_cam_cc_pll6_out_odd,
	.num_post_div = ARRAY_SIZE(post_div_table_cam_cc_pll6_out_odd),
	.width = 4,
	.regs = clk_alpha_pll_regs[CLK_ALPHA_PLL_TYPE_TAYCAN_ELU],
	.clkr.hw.init = &(const struct clk_init_data) {
		.name = "cam_cc_pll6_out_odd",
		.parent_hws = (const struct clk_hw*[]) {
			&cam_cc_pll6.clkr.hw,
		},
		.num_parents = 1,
		.flags = CLK_SET_RATE_PARENT,
		.ops = &clk_alpha_pll_postdiv_taycan_elu_ops,
	},
};

static const struct parent_map cam_cc_parent_map_0[] = {
	{ P_BI_TCXO, 0 },
	{ P_CAM_CC_PLL0_OUT_MAIN, 1 },
	{ P_CAM_CC_PLL0_OUT_EVEN, 2 },
	{ P_CAM_CC_PLL0_OUT_ODD, 3 },
	{ P_CAM_CC_PLL6_OUT_ODD, 4 },
	{ P_CAM_CC_PLL6_OUT_EVEN, 5 },
};

static const struct clk_parent_data cam_cc_parent_data_0[] = {
	{ .fw_name = "bi_tcxo" },
	{ .hw = &cam_cc_pll0.clkr.hw },
	{ .hw = &cam_cc_pll0_out_even.clkr.hw },
	{ .hw = &cam_cc_pll0_out_odd.clkr.hw },
	{ .hw = &cam_cc_pll6_out_odd.clkr.hw },
	{ .hw = &cam_cc_pll6_out_even.clkr.hw },
};

static const struct parent_map cam_cc_parent_map_1[] = {
	{ P_BI_TCXO, 0 },
	{ P_CAM_CC_PLL0_OUT_MAIN, 1 },
	{ P_CAM_CC_PLL0_OUT_EVEN, 2 },
	{ P_CAM_CC_PLL0_OUT_ODD, 3 },
	{ P_CAM_CC_PLL6_OUT_ODD, 4 },
	{ P_CAM_CC_PLL6_OUT_EVEN, 5 },
};

static const struct clk_parent_data cam_cc_parent_data_1[] = {
	{ .fw_name = "bi_tcxo" },
	{ .hw = &cam_cc_pll0.clkr.hw },
	{ .hw = &cam_cc_pll0_out_even.clkr.hw },
	{ .hw = &cam_cc_pll0_out_odd.clkr.hw },
	{ .hw = &cam_cc_pll6_out_odd.clkr.hw },
	{ .hw = &cam_cc_pll6_out_even.clkr.hw },
};

static const struct parent_map cam_cc_parent_map_2[] = {
	{ P_BI_TCXO, 0 },
	{ P_CAM_CC_PLL1_OUT_EVEN, 4 },
};

static const struct clk_parent_data cam_cc_parent_data_2[] = {
	{ .fw_name = "bi_tcxo" },
	{ .hw = &cam_cc_pll1_out_even.clkr.hw },
};

static const struct parent_map cam_cc_parent_map_3[] = {
	{ P_BI_TCXO, 0 },
	{ P_CAM_CC_PLL2_OUT_EVEN, 5 },
};

static const struct clk_parent_data cam_cc_parent_data_3[] = {
	{ .fw_name = "bi_tcxo" },
	{ .hw = &cam_cc_pll2_out_even.clkr.hw },
};

static const struct parent_map cam_cc_parent_map_4[] = {
	{ P_SLEEP_CLK, 0 },
};

static const struct clk_parent_data cam_cc_parent_data_4_ao[] = {
	{ .fw_name = "sleep_clk" },
};

static const struct parent_map cam_cc_parent_map_5[] = {
	{ P_BI_TCXO, 0 },
	{ P_CAM_CC_PLL3_OUT_EVEN, 6 },
};

static const struct clk_parent_data cam_cc_parent_data_5[] = {
	{ .fw_name = "bi_tcxo" },
	{ .hw = &cam_cc_pll3_out_even.clkr.hw },
};

static const struct parent_map cam_cc_parent_map_6[] = {
	{ P_BI_TCXO, 0 },
	{ P_CAM_CC_PLL4_OUT_EVEN, 6 },
};

static const struct clk_parent_data cam_cc_parent_data_6[] = {
	{ .fw_name = "bi_tcxo" },
	{ .hw = &cam_cc_pll4_out_even.clkr.hw },
};

static const struct parent_map cam_cc_parent_map_7[] = {
	{ P_BI_TCXO, 0 },
	{ P_CAM_CC_PLL5_OUT_EVEN, 6 },
};

static const struct clk_parent_data cam_cc_parent_data_7[] = {
	{ .fw_name = "bi_tcxo" },
	{ .hw = &cam_cc_pll5_out_even.clkr.hw },
};

static const struct parent_map cam_cc_parent_map_8[] = {
	{ P_BI_TCXO, 0 },
};

static const struct clk_parent_data cam_cc_parent_data_8_ao[] = {
	{ .fw_name = "bi_tcxo_ao" },
};

static const struct freq_tbl ftbl_cam_cc_camnoc_rt_axi_clk_src[] = {
	F(200000000, P_CAM_CC_PLL0_OUT_EVEN, 3, 0, 0),
	F(300000000, P_CAM_CC_PLL0_OUT_EVEN, 2, 0, 0),
	F(400000000, P_CAM_CC_PLL0_OUT_EVEN, 1.5, 0, 0),
	{ }
};

static struct clk_rcg2 cam_cc_camnoc_rt_axi_clk_src = {
	.cmd_rcgr = 0x112e8,
	.mnd_width = 0,
	.hid_width = 5,
	.parent_map = cam_cc_parent_map_0,
	.freq_tbl = ftbl_cam_cc_camnoc_rt_axi_clk_src,
	.enable_safe_config = true,
	.flags = HW_CLK_CTRL_MODE,
	.clkr = {
		.crm = &cam_crm,
		.crm_vcd = 8,
		.crm_num_node = 2,
	},
	.clkr.hw.init = &(const struct clk_init_data) {
		.name = "cam_cc_camnoc_rt_axi_clk_src",
		.parent_data = cam_cc_parent_data_0,
		.num_parents = ARRAY_SIZE(cam_cc_parent_data_0),
		.flags = CLK_GET_RATE_NOCACHE | CLK_SET_RATE_PARENT,
		.ops = &clk_rcg2_crmb_ops,
	},
	.clkr.vdd_data = {
		.vdd_classes = cam_cc_sun_regulators_1,
		.num_vdd_classes = ARRAY_SIZE(cam_cc_sun_regulators_1),
		.num_rate_max = VDD_NUM,
		.rate_max = (unsigned long[VDD_NUM]) {
			[VDD_LOWER_D1] = 200000000,
			[VDD_LOWER] = 300000000,
			[VDD_LOW] = 400000000},
	},
};

static const struct freq_tbl ftbl_cam_cc_cci_0_clk_src[] = {
	F(37500000, P_CAM_CC_PLL0_OUT_EVEN, 16, 0, 0),
	{ }
};

static struct clk_rcg2 cam_cc_cci_0_clk_src = {
	.cmd_rcgr = 0x1126c,
	.mnd_width = 8,
	.hid_width = 5,
	.parent_map = cam_cc_parent_map_0,
	.freq_tbl = ftbl_cam_cc_cci_0_clk_src,
	.enable_safe_config = true,
	.flags = HW_CLK_CTRL_MODE,
	.clkr.hw.init = &(const struct clk_init_data) {
		.name = "cam_cc_cci_0_clk_src",
		.parent_data = cam_cc_parent_data_0,
		.num_parents = ARRAY_SIZE(cam_cc_parent_data_0),
		.flags = CLK_SET_RATE_PARENT,
		.ops = &clk_rcg2_ops,
	},
	.clkr.vdd_data = {
		.vdd_class = &vdd_mm,
		.num_rate_max = VDD_NUM,
		.rate_max = (unsigned long[VDD_NUM]) {
			[VDD_LOWER_D1] = 37500000},
	},
};

static struct clk_rcg2 cam_cc_cci_1_clk_src = {
	.cmd_rcgr = 0x11288,
	.mnd_width = 8,
	.hid_width = 5,
	.parent_map = cam_cc_parent_map_0,
	.freq_tbl = ftbl_cam_cc_cci_0_clk_src,
	.enable_safe_config = true,
	.flags = HW_CLK_CTRL_MODE,
	.clkr.hw.init = &(const struct clk_init_data) {
		.name = "cam_cc_cci_1_clk_src",
		.parent_data = cam_cc_parent_data_0,
		.num_parents = ARRAY_SIZE(cam_cc_parent_data_0),
		.flags = CLK_SET_RATE_PARENT,
		.ops = &clk_rcg2_ops,
	},
	.clkr.vdd_data = {
		.vdd_class = &vdd_mm,
		.num_rate_max = VDD_NUM,
		.rate_max = (unsigned long[VDD_NUM]) {
			[VDD_LOWER_D1] = 37500000},
	},
};

static struct clk_rcg2 cam_cc_cci_2_clk_src = {
	.cmd_rcgr = 0x112a4,
	.mnd_width = 8,
	.hid_width = 5,
	.parent_map = cam_cc_parent_map_0,
	.freq_tbl = ftbl_cam_cc_cci_0_clk_src,
	.enable_safe_config = true,
	.flags = HW_CLK_CTRL_MODE,
	.clkr.hw.init = &(const struct clk_init_data) {
		.name = "cam_cc_cci_2_clk_src",
		.parent_data = cam_cc_parent_data_0,
		.num_parents = ARRAY_SIZE(cam_cc_parent_data_0),
		.flags = CLK_SET_RATE_PARENT,
		.ops = &clk_rcg2_ops,
	},
	.clkr.vdd_data = {
		.vdd_class = &vdd_mm,
		.num_rate_max = VDD_NUM,
		.rate_max = (unsigned long[VDD_NUM]) {
			[VDD_LOWER_D1] = 37500000},
	},
};

static const struct freq_tbl ftbl_cam_cc_cphy_rx_clk_src[] = {
	F(266666667, P_CAM_CC_PLL0_OUT_MAIN, 4.5, 0, 0),
	F(400000000, P_CAM_CC_PLL0_OUT_MAIN, 3, 0, 0),
	F(480000000, P_CAM_CC_PLL0_OUT_MAIN, 2.5, 0, 0),
	{ }
};

static struct clk_rcg2 cam_cc_cphy_rx_clk_src = {
	.cmd_rcgr = 0x11068,
	.mnd_width = 0,
	.hid_width = 5,
	.parent_map = cam_cc_parent_map_1,
	.freq_tbl = ftbl_cam_cc_cphy_rx_clk_src,
	.enable_safe_config = true,
	.flags = HW_CLK_CTRL_MODE,
	.clkr = {
		.crm = &cam_crm,
		.crm_vcd = 7,
	},
	.clkr.hw.init = &(const struct clk_init_data) {
		.name = "cam_cc_cphy_rx_clk_src",
		.parent_data = cam_cc_parent_data_1,
		.num_parents = ARRAY_SIZE(cam_cc_parent_data_1),
		.flags = CLK_GET_RATE_NOCACHE | CLK_SET_RATE_PARENT,
		.ops = &clk_rcg2_crmc_ops,
	},
	.clkr.vdd_data = {
		.vdd_classes = cam_cc_sun_regulators,
		.num_vdd_classes = ARRAY_SIZE(cam_cc_sun_regulators),
		.num_rate_max = VDD_NUM,
		.rate_max = (unsigned long[VDD_NUM]) {
			[VDD_LOWER_D1] = 266666667,
			[VDD_LOWER] = 400000000,
			[VDD_LOW] = 480000000},
	},
};

static const struct freq_tbl ftbl_cam_cc_cre_clk_src[] = {
	F(137142857, P_CAM_CC_PLL6_OUT_EVEN, 3.5, 0, 0),
	F(200000000, P_CAM_CC_PLL0_OUT_ODD, 2, 0, 0),
	F(400000000, P_CAM_CC_PLL0_OUT_ODD, 1, 0, 0),
	F(480000000, P_CAM_CC_PLL6_OUT_EVEN, 1, 0, 0),
	F(600000000, P_CAM_CC_PLL0_OUT_EVEN, 1, 0, 0),
	{ }
};

static struct clk_rcg2 cam_cc_cre_clk_src = {
	.cmd_rcgr = 0x111ac,
	.mnd_width = 0,
	.hid_width = 5,
	.parent_map = cam_cc_parent_map_0,
	.freq_tbl = ftbl_cam_cc_cre_clk_src,
	.enable_safe_config = true,
	.flags = HW_CLK_CTRL_MODE,
	.clkr.hw.init = &(const struct clk_init_data) {
		.name = "cam_cc_cre_clk_src",
		.parent_data = cam_cc_parent_data_0,
		.num_parents = ARRAY_SIZE(cam_cc_parent_data_0),
		.flags = CLK_SET_RATE_PARENT,
		.ops = &clk_rcg2_ops,
	},
	.clkr.vdd_data = {
		.vdd_class = &vdd_mm,
		.num_rate_max = VDD_NUM,
		.rate_max = (unsigned long[VDD_NUM]) {
			[VDD_LOWER_D1] = 137142857,
			[VDD_LOWER] = 200000000,
			[VDD_LOW] = 400000000,
			[VDD_LOW_L1] = 480000000,
			[VDD_NOMINAL] = 600000000},
	},
};

static const struct freq_tbl ftbl_cam_cc_csi0phytimer_clk_src[] = {
	F(400000000, P_CAM_CC_PLL0_OUT_MAIN, 3, 0, 0),
	{ }
};

static struct clk_rcg2 cam_cc_csi0phytimer_clk_src = {
	.cmd_rcgr = 0x10000,
	.mnd_width = 0,
	.hid_width = 5,
	.parent_map = cam_cc_parent_map_1,
	.freq_tbl = ftbl_cam_cc_csi0phytimer_clk_src,
	.enable_safe_config = true,
	.flags = HW_CLK_CTRL_MODE,
	.clkr.hw.init = &(const struct clk_init_data) {
		.name = "cam_cc_csi0phytimer_clk_src",
		.parent_data = cam_cc_parent_data_1,
		.num_parents = ARRAY_SIZE(cam_cc_parent_data_1),
		.flags = CLK_SET_RATE_PARENT,
		.ops = &clk_rcg2_ops,
	},
	.clkr.vdd_data = {
		.vdd_class = &vdd_mxc,
		.num_rate_max = VDD_NUM,
		.rate_max = (unsigned long[VDD_NUM]) {
			[VDD_LOWER_D1] = 400000000},
	},
};

static struct clk_rcg2 cam_cc_csi1phytimer_clk_src = {
	.cmd_rcgr = 0x10024,
	.mnd_width = 0,
	.hid_width = 5,
	.parent_map = cam_cc_parent_map_1,
	.freq_tbl = ftbl_cam_cc_csi0phytimer_clk_src,
	.enable_safe_config = true,
	.flags = HW_CLK_CTRL_MODE,
	.clkr.hw.init = &(const struct clk_init_data) {
		.name = "cam_cc_csi1phytimer_clk_src",
		.parent_data = cam_cc_parent_data_1,
		.num_parents = ARRAY_SIZE(cam_cc_parent_data_1),
		.flags = CLK_SET_RATE_PARENT,
		.ops = &clk_rcg2_ops,
	},
	.clkr.vdd_data = {
		.vdd_class = &vdd_mxc,
		.num_rate_max = VDD_NUM,
		.rate_max = (unsigned long[VDD_NUM]) {
			[VDD_LOWER_D1] = 400000000},
	},
};

static struct clk_rcg2 cam_cc_csi2phytimer_clk_src = {
	.cmd_rcgr = 0x10044,
	.mnd_width = 0,
	.hid_width = 5,
	.parent_map = cam_cc_parent_map_1,
	.freq_tbl = ftbl_cam_cc_csi0phytimer_clk_src,
	.enable_safe_config = true,
	.flags = HW_CLK_CTRL_MODE,
	.clkr.hw.init = &(const struct clk_init_data) {
		.name = "cam_cc_csi2phytimer_clk_src",
		.parent_data = cam_cc_parent_data_1,
		.num_parents = ARRAY_SIZE(cam_cc_parent_data_1),
		.flags = CLK_SET_RATE_PARENT,
		.ops = &clk_rcg2_ops,
	},
	.clkr.vdd_data = {
		.vdd_class = &vdd_mx,
		.num_rate_max = VDD_NUM,
		.rate_max = (unsigned long[VDD_NUM]) {
			[VDD_LOWER_D1] = 400000000},
	},
};

static struct clk_rcg2 cam_cc_csi3phytimer_clk_src = {
	.cmd_rcgr = 0x10064,
	.mnd_width = 0,
	.hid_width = 5,
	.parent_map = cam_cc_parent_map_1,
	.freq_tbl = ftbl_cam_cc_csi0phytimer_clk_src,
	.enable_safe_config = true,
	.flags = HW_CLK_CTRL_MODE,
	.clkr.hw.init = &(const struct clk_init_data) {
		.name = "cam_cc_csi3phytimer_clk_src",
		.parent_data = cam_cc_parent_data_1,
		.num_parents = ARRAY_SIZE(cam_cc_parent_data_1),
		.flags = CLK_SET_RATE_PARENT,
		.ops = &clk_rcg2_ops,
	},
	.clkr.vdd_data = {
		.vdd_class = &vdd_mxc,
		.num_rate_max = VDD_NUM,
		.rate_max = (unsigned long[VDD_NUM]) {
			[VDD_LOWER_D1] = 400000000},
	},
};

static struct clk_rcg2 cam_cc_csi4phytimer_clk_src = {
	.cmd_rcgr = 0x10084,
	.mnd_width = 0,
	.hid_width = 5,
	.parent_map = cam_cc_parent_map_1,
	.freq_tbl = ftbl_cam_cc_csi0phytimer_clk_src,
	.enable_safe_config = true,
	.flags = HW_CLK_CTRL_MODE,
	.clkr.hw.init = &(const struct clk_init_data) {
		.name = "cam_cc_csi4phytimer_clk_src",
		.parent_data = cam_cc_parent_data_1,
		.num_parents = ARRAY_SIZE(cam_cc_parent_data_1),
		.flags = CLK_SET_RATE_PARENT,
		.ops = &clk_rcg2_ops,
	},
	.clkr.vdd_data = {
		.vdd_class = &vdd_mx,
		.num_rate_max = VDD_NUM,
		.rate_max = (unsigned long[VDD_NUM]) {
			[VDD_LOWER_D1] = 400000000},
	},
};

static struct clk_rcg2 cam_cc_csi5phytimer_clk_src = {
	.cmd_rcgr = 0x100a4,
	.mnd_width = 0,
	.hid_width = 5,
	.parent_map = cam_cc_parent_map_1,
	.freq_tbl = ftbl_cam_cc_csi0phytimer_clk_src,
	.enable_safe_config = true,
	.flags = HW_CLK_CTRL_MODE,
	.clkr.hw.init = &(const struct clk_init_data) {
		.name = "cam_cc_csi5phytimer_clk_src",
		.parent_data = cam_cc_parent_data_1,
		.num_parents = ARRAY_SIZE(cam_cc_parent_data_1),
		.flags = CLK_SET_RATE_PARENT,
		.ops = &clk_rcg2_ops,
	},
	.clkr.vdd_data = {
		.vdd_class = &vdd_mxc,
		.num_rate_max = VDD_NUM,
		.rate_max = (unsigned long[VDD_NUM]) {
			[VDD_LOWER_D1] = 400000000},
	},
};

static struct clk_rcg2 cam_cc_csid_clk_src = {
	.cmd_rcgr = 0x112c0,
	.mnd_width = 0,
	.hid_width = 5,
	.parent_map = cam_cc_parent_map_1,
	.freq_tbl = ftbl_cam_cc_cphy_rx_clk_src,
	.enable_safe_config = true,
	.flags = HW_CLK_CTRL_MODE,
	.clkr = {
		.crm = &cam_crm,
		.crm_vcd = 6,
	},
	.clkr.hw.init = &(const struct clk_init_data) {
		.name = "cam_cc_csid_clk_src",
		.parent_data = cam_cc_parent_data_1,
		.num_parents = ARRAY_SIZE(cam_cc_parent_data_1),
		.flags = CLK_GET_RATE_NOCACHE | CLK_SET_RATE_PARENT,
		.ops = &clk_rcg2_crmc_ops,
	},
	.clkr.vdd_data = {
		.vdd_classes = cam_cc_sun_regulators_1,
		.num_vdd_classes = ARRAY_SIZE(cam_cc_sun_regulators_1),
		.num_rate_max = VDD_NUM,
		.rate_max = (unsigned long[VDD_NUM]) {
			[VDD_LOWER_D1] = 266666667,
			[VDD_LOWER] = 400000000,
			[VDD_LOW] = 480000000},
	},
};

static const struct freq_tbl ftbl_cam_cc_fast_ahb_clk_src[] = {
	F(213333333, P_CAM_CC_PLL6_OUT_ODD, 1.5, 0, 0),
	F(300000000, P_CAM_CC_PLL0_OUT_EVEN, 2, 0, 0),
	F(400000000, P_CAM_CC_PLL0_OUT_MAIN, 3, 0, 0),
	{ }
};

static struct clk_rcg2 cam_cc_fast_ahb_clk_src = {
	.cmd_rcgr = 0x100dc,
	.mnd_width = 0,
	.hid_width = 5,
	.parent_map = cam_cc_parent_map_0,
	.freq_tbl = ftbl_cam_cc_fast_ahb_clk_src,
	.enable_safe_config = true,
	.flags = HW_CLK_CTRL_MODE,
	.clkr.hw.init = &(const struct clk_init_data) {
		.name = "cam_cc_fast_ahb_clk_src",
		.parent_data = cam_cc_parent_data_0,
		.num_parents = ARRAY_SIZE(cam_cc_parent_data_0),
		.flags = CLK_SET_RATE_PARENT,
		.ops = &clk_rcg2_ops,
	},
	.clkr.vdd_data = {
		.vdd_classes = cam_cc_sun_regulators_1,
		.num_vdd_classes = ARRAY_SIZE(cam_cc_sun_regulators_1),
		.num_rate_max = VDD_NUM,
		.rate_max = (unsigned long[VDD_NUM]) {
			[VDD_LOWER_D1] = 213333333,
			[VDD_LOWER] = 300000000,
			[VDD_NOMINAL] = 400000000},
	},
};

static const struct freq_tbl ftbl_cam_cc_icp_0_clk_src[] = {
	F(300000000, P_CAM_CC_PLL0_OUT_EVEN, 2, 0, 0),
	F(400000000, P_CAM_CC_PLL0_OUT_ODD, 1, 0, 0),
	F(480000000, P_CAM_CC_PLL6_OUT_EVEN, 1, 0, 0),
	F(600000000, P_CAM_CC_PLL0_OUT_MAIN, 2, 0, 0),
	{ }
};

static struct clk_rcg2 cam_cc_icp_0_clk_src = {
	.cmd_rcgr = 0x11214,
	.mnd_width = 0,
	.hid_width = 5,
	.parent_map = cam_cc_parent_map_0,
	.freq_tbl = ftbl_cam_cc_icp_0_clk_src,
	.enable_safe_config = true,
	.flags = HW_CLK_CTRL_MODE,
	.clkr.hw.init = &(const struct clk_init_data) {
		.name = "cam_cc_icp_0_clk_src",
		.parent_data = cam_cc_parent_data_0,
		.num_parents = ARRAY_SIZE(cam_cc_parent_data_0),
		.flags = CLK_SET_RATE_PARENT,
		.ops = &clk_rcg2_ops,
	},
	.clkr.vdd_data = {
		.vdd_classes = cam_cc_sun_regulators_1,
		.num_vdd_classes = ARRAY_SIZE(cam_cc_sun_regulators_1),
		.num_rate_max = VDD_NUM,
		.rate_max = (unsigned long[VDD_NUM]) {
			[VDD_LOWER_D1] = 300000000,
			[VDD_LOWER] = 400000000,
			[VDD_LOW] = 480000000,
			[VDD_LOW_L1] = 600000000},
	},
};

static struct clk_rcg2 cam_cc_icp_1_clk_src = {
	.cmd_rcgr = 0x1123c,
	.mnd_width = 0,
	.hid_width = 5,
	.parent_map = cam_cc_parent_map_0,
	.freq_tbl = ftbl_cam_cc_icp_0_clk_src,
	.enable_safe_config = true,
	.flags = HW_CLK_CTRL_MODE,
	.clkr.hw.init = &(const struct clk_init_data) {
		.name = "cam_cc_icp_1_clk_src",
		.parent_data = cam_cc_parent_data_0,
		.num_parents = ARRAY_SIZE(cam_cc_parent_data_0),
		.flags = CLK_SET_RATE_PARENT,
		.ops = &clk_rcg2_ops,
	},
	.clkr.vdd_data = {
		.vdd_classes = cam_cc_sun_regulators_1,
		.num_vdd_classes = ARRAY_SIZE(cam_cc_sun_regulators_1),
		.num_rate_max = VDD_NUM,
		.rate_max = (unsigned long[VDD_NUM]) {
			[VDD_LOWER_D1] = 300000000,
			[VDD_LOWER] = 400000000,
			[VDD_LOW] = 480000000,
			[VDD_LOW_L1] = 600000000},
	},
};

static struct clk_rcg2 cam_cc_ife_lite_clk_src = {
	.cmd_rcgr = 0x11150,
	.mnd_width = 0,
	.hid_width = 5,
	.parent_map = cam_cc_parent_map_1,
	.freq_tbl = ftbl_cam_cc_cphy_rx_clk_src,
	.enable_safe_config = true,
	.flags = HW_CLK_CTRL_MODE,
	.clkr.hw.init = &(const struct clk_init_data) {
		.name = "cam_cc_ife_lite_clk_src",
		.parent_data = cam_cc_parent_data_1,
		.num_parents = ARRAY_SIZE(cam_cc_parent_data_1),
		.flags = CLK_SET_RATE_PARENT,
		.ops = &clk_rcg2_ops,
	},
	.clkr.vdd_data = {
		.vdd_classes = cam_cc_sun_regulators_1,
		.num_vdd_classes = ARRAY_SIZE(cam_cc_sun_regulators_1),
		.num_rate_max = VDD_NUM,
		.rate_max = (unsigned long[VDD_NUM]) {
			[VDD_LOWER_D1] = 266666667,
			[VDD_LOWER] = 400000000,
			[VDD_LOW] = 480000000},
	},
};

static struct clk_rcg2 cam_cc_ife_lite_csid_clk_src = {
	.cmd_rcgr = 0x1117c,
	.mnd_width = 0,
	.hid_width = 5,
	.parent_map = cam_cc_parent_map_1,
	.freq_tbl = ftbl_cam_cc_cphy_rx_clk_src,
	.enable_safe_config = true,
	.flags = HW_CLK_CTRL_MODE,
	.clkr.hw.init = &(const struct clk_init_data) {
		.name = "cam_cc_ife_lite_csid_clk_src",
		.parent_data = cam_cc_parent_data_1,
		.num_parents = ARRAY_SIZE(cam_cc_parent_data_1),
		.flags = CLK_SET_RATE_PARENT,
		.ops = &clk_rcg2_ops,
	},
	.clkr.vdd_data = {
		.vdd_classes = cam_cc_sun_regulators_1,
		.num_vdd_classes = ARRAY_SIZE(cam_cc_sun_regulators_1),
		.num_rate_max = VDD_NUM,
		.rate_max = (unsigned long[VDD_NUM]) {
			[VDD_LOWER_D1] = 266666667,
			[VDD_LOWER] = 400000000,
			[VDD_LOW] = 480000000},
	},
};

static const struct freq_tbl ftbl_cam_cc_ipe_nps_clk_src[] = {
	F(332500000, P_CAM_CC_PLL1_OUT_EVEN, 1, 0, 0),
	F(475000000, P_CAM_CC_PLL1_OUT_EVEN, 1, 0, 0),
	F(575000000, P_CAM_CC_PLL1_OUT_EVEN, 1, 0, 0),
	F(675000000, P_CAM_CC_PLL1_OUT_EVEN, 1, 0, 0),
	F(825000000, P_CAM_CC_PLL1_OUT_EVEN, 1, 0, 0),
	{ }
};

static struct clk_rcg2 cam_cc_ipe_nps_clk_src = {
	.cmd_rcgr = 0x10190,
	.mnd_width = 0,
	.hid_width = 5,
	.parent_map = cam_cc_parent_map_2,
	.freq_tbl = ftbl_cam_cc_ipe_nps_clk_src,
	.enable_safe_config = true,
	.flags = HW_CLK_CTRL_MODE,
	.clkr.hw.init = &(const struct clk_init_data) {
		.name = "cam_cc_ipe_nps_clk_src",
		.parent_data = cam_cc_parent_data_2,
		.num_parents = ARRAY_SIZE(cam_cc_parent_data_2),
		.flags = CLK_SET_RATE_PARENT,
		.ops = &clk_rcg2_ops,
	},
	.clkr.vdd_data = {
		.vdd_classes = cam_cc_sun_regulators_1,
		.num_vdd_classes = ARRAY_SIZE(cam_cc_sun_regulators_1),
		.num_rate_max = VDD_NUM,
		.rate_max = (unsigned long[VDD_NUM]) {
			[VDD_LOWER_D1] = 332500000,
			[VDD_LOWER] = 475000000,
			[VDD_LOW] = 575000000,
			[VDD_LOW_L1] = 675000000,
			[VDD_NOMINAL] = 825000000},
	},
};

static struct clk_rcg2 cam_cc_jpeg_clk_src = {
	.cmd_rcgr = 0x111d0,
	.mnd_width = 0,
	.hid_width = 5,
	.parent_map = cam_cc_parent_map_0,
	.freq_tbl = ftbl_cam_cc_cre_clk_src,
	.enable_safe_config = true,
	.flags = HW_CLK_CTRL_MODE,
	.clkr.hw.init = &(const struct clk_init_data) {
		.name = "cam_cc_jpeg_clk_src",
		.parent_data = cam_cc_parent_data_0,
		.num_parents = ARRAY_SIZE(cam_cc_parent_data_0),
		.flags = CLK_SET_RATE_PARENT,
		.ops = &clk_rcg2_ops,
	},
	.clkr.vdd_data = {
		.vdd_classes = cam_cc_sun_regulators_1,
		.num_vdd_classes = ARRAY_SIZE(cam_cc_sun_regulators_1),
		.num_rate_max = VDD_NUM,
		.rate_max = (unsigned long[VDD_NUM]) {
			[VDD_LOWER_D1] = 137142857,
			[VDD_LOWER] = 200000000,
			[VDD_LOW] = 400000000,
			[VDD_LOW_L1] = 480000000,
			[VDD_NOMINAL] = 600000000},
	},
};

static const struct freq_tbl ftbl_cam_cc_ofe_clk_src[] = {
	F(338800000, P_CAM_CC_PLL2_OUT_EVEN, 1, 0, 0),
	F(484000000, P_CAM_CC_PLL2_OUT_EVEN, 1, 0, 0),
	F(586000000, P_CAM_CC_PLL2_OUT_EVEN, 1, 0, 0),
	F(688000000, P_CAM_CC_PLL2_OUT_EVEN, 1, 0, 0),
	F(841000000, P_CAM_CC_PLL2_OUT_EVEN, 1, 0, 0),
	{ }
};

static struct clk_rcg2 cam_cc_ofe_clk_src = {
	.cmd_rcgr = 0x1011c,
	.mnd_width = 0,
	.hid_width = 5,
	.parent_map = cam_cc_parent_map_3,
	.freq_tbl = ftbl_cam_cc_ofe_clk_src,
	.enable_safe_config = true,
	.flags = HW_CLK_CTRL_MODE,
	.clkr.hw.init = &(const struct clk_init_data) {
		.name = "cam_cc_ofe_clk_src",
		.parent_data = cam_cc_parent_data_3,
		.num_parents = ARRAY_SIZE(cam_cc_parent_data_3),
		.flags = CLK_SET_RATE_PARENT,
		.ops = &clk_rcg2_ops,
	},
	.clkr.vdd_data = {
		.vdd_classes = cam_cc_sun_regulators_1,
		.num_vdd_classes = ARRAY_SIZE(cam_cc_sun_regulators_1),
		.num_rate_max = VDD_NUM,
		.rate_max = (unsigned long[VDD_NUM]) {
			[VDD_LOWER_D1] = 338800000,
			[VDD_LOWER] = 484000000,
			[VDD_LOW] = 586000000,
			[VDD_LOW_L1] = 688000000,
			[VDD_NOMINAL] = 841000000},
	},
};

static const struct freq_tbl ftbl_cam_cc_qdss_debug_clk_src[] = {
	F(40000000, P_CAM_CC_PLL6_OUT_ODD, 8, 0, 0),
	F(60000000, P_CAM_CC_PLL6_OUT_EVEN, 8, 0, 0),
	F(120000000, P_CAM_CC_PLL0_OUT_EVEN, 5, 0, 0),
	F(240000000, P_CAM_CC_PLL0_OUT_MAIN, 5, 0, 0),
	{ }
};

static struct clk_rcg2 cam_cc_qdss_debug_clk_src = {
	.cmd_rcgr = 0x1132c,
	.mnd_width = 0,
	.hid_width = 5,
	.parent_map = cam_cc_parent_map_0,
	.freq_tbl = ftbl_cam_cc_qdss_debug_clk_src,
	.enable_safe_config = true,
	.flags = HW_CLK_CTRL_MODE,
	.clkr.hw.init = &(const struct clk_init_data) {
		.name = "cam_cc_qdss_debug_clk_src",
		.parent_data = cam_cc_parent_data_0,
		.num_parents = ARRAY_SIZE(cam_cc_parent_data_0),
		.flags = CLK_SET_RATE_PARENT,
		.ops = &clk_rcg2_ops,
	},
	.clkr.vdd_data = {
		.vdd_class = &vdd_mm,
		.num_rate_max = VDD_NUM,
		.rate_max = (unsigned long[VDD_NUM]) {
			[VDD_LOWER_D1] = 40000000,
			[VDD_LOWER] = 60000000,
			[VDD_LOW] = 120000000,
			[VDD_LOW_L1] = 240000000},
	},
};

static const struct freq_tbl ftbl_cam_cc_sleep_clk_src[] = {
	F(32000, P_SLEEP_CLK, 1, 0, 0),
	{ }
};

static struct clk_rcg2 cam_cc_sleep_clk_src = {
	.cmd_rcgr = 0x11380,
	.mnd_width = 0,
	.hid_width = 5,
	.parent_map = cam_cc_parent_map_4,
	.freq_tbl = ftbl_cam_cc_sleep_clk_src,
	.clkr.hw.init = &(const struct clk_init_data) {
		.name = "cam_cc_sleep_clk_src",
		.parent_data = cam_cc_parent_data_4_ao,
		.num_parents = ARRAY_SIZE(cam_cc_parent_data_4_ao),
		.flags = CLK_SET_RATE_PARENT,
		.ops = &clk_rcg2_ops,
	},
};

static const struct freq_tbl ftbl_cam_cc_slow_ahb_clk_src[] = {
	F(56470588, P_CAM_CC_PLL6_OUT_EVEN, 8.5, 0, 0),
	F(80000000, P_CAM_CC_PLL0_OUT_EVEN, 7.5, 0, 0),
	{ }
};

static struct clk_rcg2 cam_cc_slow_ahb_clk_src = {
	.cmd_rcgr = 0x10100,
	.mnd_width = 0,
	.hid_width = 5,
	.parent_map = cam_cc_parent_map_0,
	.freq_tbl = ftbl_cam_cc_slow_ahb_clk_src,
	.enable_safe_config = true,
	.flags = HW_CLK_CTRL_MODE,
	.clkr.hw.init = &(const struct clk_init_data) {
		.name = "cam_cc_slow_ahb_clk_src",
		.parent_data = cam_cc_parent_data_0,
		.num_parents = ARRAY_SIZE(cam_cc_parent_data_0),
		.flags = CLK_SET_RATE_PARENT,
		.ops = &clk_rcg2_ops,
	},
	.clkr.vdd_data = {
		.vdd_classes = cam_cc_sun_regulators_1,
		.num_vdd_classes = ARRAY_SIZE(cam_cc_sun_regulators_1),
		.num_rate_max = VDD_NUM,
		.rate_max = (unsigned long[VDD_NUM]) {
			[VDD_LOWER_D1] = 56470588,
			[VDD_LOWER] = 80000000},
	},
};

static const struct freq_tbl ftbl_cam_cc_tfe_0_clk_src[] = {
	F(360280000, P_CAM_CC_PLL3_OUT_EVEN, 1, 0, 0),
	F(480000000, P_CAM_CC_PLL3_OUT_EVEN, 1, 0, 0),
	F(630000000, P_CAM_CC_PLL3_OUT_EVEN, 1, 0, 0),
	F(716000000, P_CAM_CC_PLL3_OUT_EVEN, 1, 0, 0),
	F(833000000, P_CAM_CC_PLL3_OUT_EVEN, 1, 0, 0),
	{ }
};

static struct clk_rcg2 cam_cc_tfe_0_clk_src = {
	.cmd_rcgr = 0x11018,
	.mnd_width = 0,
	.hid_width = 5,
	.parent_map = cam_cc_parent_map_5,
	.freq_tbl = ftbl_cam_cc_tfe_0_clk_src,
	.enable_safe_config = true,
	.flags = HW_CLK_CTRL_MODE,
	.clkr = {
		.crm = &cam_crm,
		.crm_vcd = 0,
	},
	.clkr.hw.init = &(const struct clk_init_data) {
		.name = "cam_cc_tfe_0_clk_src",
		.parent_data = cam_cc_parent_data_5,
		.num_parents = ARRAY_SIZE(cam_cc_parent_data_5),
		.flags = CLK_GET_RATE_NOCACHE | CLK_SET_RATE_PARENT,
		.ops = &clk_rcg2_crmc_ops,
	},
	.clkr.vdd_data = {
		.vdd_classes = cam_cc_sun_regulators_1,
		.num_vdd_classes = ARRAY_SIZE(cam_cc_sun_regulators_1),
		.num_rate_max = VDD_NUM,
		.rate_max = (unsigned long[VDD_NUM]) {
			[VDD_LOWER_D1] = 360280000,
			[VDD_LOWER] = 480000000,
			[VDD_LOW] = 630000000,
			[VDD_LOW_L1] = 716000000,
			[VDD_NOMINAL] = 833000000},
	},
};

static const struct freq_tbl ftbl_cam_cc_tfe_1_clk_src[] = {
	F(360280000, P_CAM_CC_PLL4_OUT_EVEN, 1, 0, 0),
	F(480000000, P_CAM_CC_PLL4_OUT_EVEN, 1, 0, 0),
	F(630000000, P_CAM_CC_PLL4_OUT_EVEN, 1, 0, 0),
	F(716000000, P_CAM_CC_PLL4_OUT_EVEN, 1, 0, 0),
	F(833000000, P_CAM_CC_PLL4_OUT_EVEN, 1, 0, 0),
	{ }
};

static struct clk_rcg2 cam_cc_tfe_1_clk_src = {
	.cmd_rcgr = 0x11098,
	.mnd_width = 0,
	.hid_width = 5,
	.parent_map = cam_cc_parent_map_6,
	.freq_tbl = ftbl_cam_cc_tfe_1_clk_src,
	.enable_safe_config = true,
	.flags = HW_CLK_CTRL_MODE,
	.clkr = {
		.crm = &cam_crm,
		.crm_vcd = 1,
	},
	.clkr.hw.init = &(const struct clk_init_data) {
		.name = "cam_cc_tfe_1_clk_src",
		.parent_data = cam_cc_parent_data_6,
		.num_parents = ARRAY_SIZE(cam_cc_parent_data_6),
		.flags = CLK_GET_RATE_NOCACHE | CLK_SET_RATE_PARENT,
		.ops = &clk_rcg2_crmc_ops,
	},
	.clkr.vdd_data = {
		.vdd_classes = cam_cc_sun_regulators_1,
		.num_vdd_classes = ARRAY_SIZE(cam_cc_sun_regulators_1),
		.num_rate_max = VDD_NUM,
		.rate_max = (unsigned long[VDD_NUM]) {
			[VDD_LOWER_D1] = 360280000,
			[VDD_LOWER] = 480000000,
			[VDD_LOW] = 630000000,
			[VDD_LOW_L1] = 716000000,
			[VDD_NOMINAL] = 833000000},
	},
};

static const struct freq_tbl ftbl_cam_cc_tfe_2_clk_src[] = {
	F(360280000, P_CAM_CC_PLL5_OUT_EVEN, 1, 0, 0),
	F(480000000, P_CAM_CC_PLL5_OUT_EVEN, 1, 0, 0),
	F(630000000, P_CAM_CC_PLL5_OUT_EVEN, 1, 0, 0),
	F(716000000, P_CAM_CC_PLL5_OUT_EVEN, 1, 0, 0),
	F(833000000, P_CAM_CC_PLL5_OUT_EVEN, 1, 0, 0),
	{ }
};

static struct clk_rcg2 cam_cc_tfe_2_clk_src = {
	.cmd_rcgr = 0x11100,
	.mnd_width = 0,
	.hid_width = 5,
	.parent_map = cam_cc_parent_map_7,
	.freq_tbl = ftbl_cam_cc_tfe_2_clk_src,
	.enable_safe_config = true,
	.flags = HW_CLK_CTRL_MODE,
	.clkr = {
		.crm = &cam_crm,
		.crm_vcd = 2,
	},
	.clkr.hw.init = &(const struct clk_init_data) {
		.name = "cam_cc_tfe_2_clk_src",
		.parent_data = cam_cc_parent_data_7,
		.num_parents = ARRAY_SIZE(cam_cc_parent_data_7),
		.flags = CLK_GET_RATE_NOCACHE | CLK_SET_RATE_PARENT,
		.ops = &clk_rcg2_crmc_ops,
	},
	.clkr.vdd_data = {
		.vdd_classes = cam_cc_sun_regulators_1,
		.num_vdd_classes = ARRAY_SIZE(cam_cc_sun_regulators_1),
		.num_rate_max = VDD_NUM,
		.rate_max = (unsigned long[VDD_NUM]) {
			[VDD_LOWER_D1] = 360280000,
			[VDD_LOWER] = 480000000,
			[VDD_LOW] = 630000000,
			[VDD_LOW_L1] = 716000000,
			[VDD_NOMINAL] = 833000000},
	},
};

static const struct freq_tbl ftbl_cam_cc_xo_clk_src[] = {
	F(19200000, P_BI_TCXO, 1, 0, 0),
	{ }
};

static struct clk_rcg2 cam_cc_xo_clk_src = {
	.cmd_rcgr = 0x11364,
	.mnd_width = 0,
	.hid_width = 5,
	.parent_map = cam_cc_parent_map_8,
	.freq_tbl = ftbl_cam_cc_xo_clk_src,
	.enable_safe_config = true,
	.flags = HW_CLK_CTRL_MODE,
	.clkr.hw.init = &(const struct clk_init_data) {
		.name = "cam_cc_xo_clk_src",
		.parent_data = cam_cc_parent_data_8_ao,
		.num_parents = ARRAY_SIZE(cam_cc_parent_data_8_ao),
		.flags = CLK_SET_RATE_PARENT,
		.ops = &clk_rcg2_ops,
	},
};

static struct clk_branch cam_cc_cam_top_ahb_clk = {
	.halt_reg = 0x113ac,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x113ac,
		.enable_mask = BIT(0),
		.hw.init = &(const struct clk_init_data) {
			.name = "cam_cc_cam_top_ahb_clk",
			.parent_hws = (const struct clk_hw*[]) {
				&cam_cc_slow_ahb_clk_src.clkr.hw,
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch cam_cc_cam_top_fast_ahb_clk = {
	.halt_reg = 0x1139c,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x1139c,
		.enable_mask = BIT(0),
		.hw.init = &(const struct clk_init_data) {
			.name = "cam_cc_cam_top_fast_ahb_clk",
			.parent_hws = (const struct clk_hw*[]) {
				&cam_cc_fast_ahb_clk_src.clkr.hw,
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch cam_cc_camnoc_dcd_xo_clk = {
	.halt_reg = 0x11320,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x11320,
		.enable_mask = BIT(0),
		.hw.init = &(const struct clk_init_data) {
			.name = "cam_cc_camnoc_dcd_xo_clk",
			.parent_hws = (const struct clk_hw*[]) {
				&cam_cc_xo_clk_src.clkr.hw,
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch cam_cc_camnoc_nrt_axi_clk = {
	.halt_reg = 0x11310,
	.halt_check = BRANCH_HALT_VOTED,
	.hwcg_reg = 0x11310,
	.hwcg_bit = 1,
	.clkr = {
		.enable_reg = 0x11310,
		.enable_mask = BIT(0),
		.hw.init = &(const struct clk_init_data) {
			.name = "cam_cc_camnoc_nrt_axi_clk",
			.parent_hws = (const struct clk_hw*[]) {
				&cam_cc_camnoc_rt_axi_clk_src.clkr.hw,
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_crm_ops,
		},
	},
};

static struct clk_branch cam_cc_camnoc_nrt_cre_clk = {
	.halt_reg = 0x111c8,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x111c8,
		.enable_mask = BIT(0),
		.hw.init = &(const struct clk_init_data) {
			.name = "cam_cc_camnoc_nrt_cre_clk",
			.parent_hws = (const struct clk_hw*[]) {
				&cam_cc_cre_clk_src.clkr.hw,
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch cam_cc_camnoc_nrt_ipe_nps_clk = {
	.halt_reg = 0x101b8,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x101b8,
		.enable_mask = BIT(0),
		.hw.init = &(const struct clk_init_data) {
			.name = "cam_cc_camnoc_nrt_ipe_nps_clk",
			.parent_hws = (const struct clk_hw*[]) {
				&cam_cc_ipe_nps_clk_src.clkr.hw,
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch cam_cc_camnoc_nrt_ofe_anchor_clk = {
	.halt_reg = 0x10158,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x10158,
		.enable_mask = BIT(0),
		.hw.init = &(const struct clk_init_data) {
			.name = "cam_cc_camnoc_nrt_ofe_anchor_clk",
			.parent_hws = (const struct clk_hw*[]) {
				&cam_cc_ofe_clk_src.clkr.hw,
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch cam_cc_camnoc_nrt_ofe_hdr_clk = {
	.halt_reg = 0x1016c,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x1016c,
		.enable_mask = BIT(0),
		.hw.init = &(const struct clk_init_data) {
			.name = "cam_cc_camnoc_nrt_ofe_hdr_clk",
			.parent_hws = (const struct clk_hw*[]) {
				&cam_cc_ofe_clk_src.clkr.hw,
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch cam_cc_camnoc_nrt_ofe_main_clk = {
	.halt_reg = 0x10144,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x10144,
		.enable_mask = BIT(0),
		.hw.init = &(const struct clk_init_data) {
			.name = "cam_cc_camnoc_nrt_ofe_main_clk",
			.parent_hws = (const struct clk_hw*[]) {
				&cam_cc_ofe_clk_src.clkr.hw,
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch cam_cc_camnoc_rt_axi_clk = {
	.halt_reg = 0x11300,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x11300,
		.enable_mask = BIT(0),
		.hw.init = &(const struct clk_init_data) {
			.name = "cam_cc_camnoc_rt_axi_clk",
			.parent_hws = (const struct clk_hw*[]) {
				&cam_cc_camnoc_rt_axi_clk_src.clkr.hw,
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_crm_ops,
		},
	},
};

static struct clk_branch cam_cc_camnoc_rt_ife_lite_clk = {
	.halt_reg = 0x11178,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x11178,
		.enable_mask = BIT(0),
		.hw.init = &(const struct clk_init_data) {
			.name = "cam_cc_camnoc_rt_ife_lite_clk",
			.parent_hws = (const struct clk_hw*[]) {
				&cam_cc_ife_lite_clk_src.clkr.hw,
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch cam_cc_camnoc_rt_tfe_0_bayer_clk = {
	.halt_reg = 0x11054,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x11054,
		.enable_mask = BIT(0),
		.hw.init = &(const struct clk_init_data) {
			.name = "cam_cc_camnoc_rt_tfe_0_bayer_clk",
			.parent_hws = (const struct clk_hw*[]) {
				&cam_cc_tfe_0_clk_src.clkr.hw,
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_crm_ops,
		},
	},
};

static struct clk_branch cam_cc_camnoc_rt_tfe_0_main_clk = {
	.halt_reg = 0x11040,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x11040,
		.enable_mask = BIT(0),
		.hw.init = &(const struct clk_init_data) {
			.name = "cam_cc_camnoc_rt_tfe_0_main_clk",
			.parent_hws = (const struct clk_hw*[]) {
				&cam_cc_tfe_0_clk_src.clkr.hw,
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_crm_ops,
		},
	},
};

static struct clk_branch cam_cc_camnoc_rt_tfe_1_bayer_clk = {
	.halt_reg = 0x110d4,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x110d4,
		.enable_mask = BIT(0),
		.hw.init = &(const struct clk_init_data) {
			.name = "cam_cc_camnoc_rt_tfe_1_bayer_clk",
			.parent_hws = (const struct clk_hw*[]) {
				&cam_cc_tfe_1_clk_src.clkr.hw,
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_crm_ops,
		},
	},
};

static struct clk_branch cam_cc_camnoc_rt_tfe_1_main_clk = {
	.halt_reg = 0x110c0,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x110c0,
		.enable_mask = BIT(0),
		.hw.init = &(const struct clk_init_data) {
			.name = "cam_cc_camnoc_rt_tfe_1_main_clk",
			.parent_hws = (const struct clk_hw*[]) {
				&cam_cc_tfe_1_clk_src.clkr.hw,
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_crm_ops,
		},
	},
};

static struct clk_branch cam_cc_camnoc_rt_tfe_2_bayer_clk = {
	.halt_reg = 0x1113c,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x1113c,
		.enable_mask = BIT(0),
		.hw.init = &(const struct clk_init_data) {
			.name = "cam_cc_camnoc_rt_tfe_2_bayer_clk",
			.parent_hws = (const struct clk_hw*[]) {
				&cam_cc_tfe_2_clk_src.clkr.hw,
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_crm_ops,
		},
	},
};

static struct clk_branch cam_cc_camnoc_rt_tfe_2_main_clk = {
	.halt_reg = 0x11128,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x11128,
		.enable_mask = BIT(0),
		.hw.init = &(const struct clk_init_data) {
			.name = "cam_cc_camnoc_rt_tfe_2_main_clk",
			.parent_hws = (const struct clk_hw*[]) {
				&cam_cc_tfe_2_clk_src.clkr.hw,
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_crm_ops,
		},
	},
};

static struct clk_branch cam_cc_camnoc_xo_clk = {
	.halt_reg = 0x11324,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x11324,
		.enable_mask = BIT(0),
		.hw.init = &(const struct clk_init_data) {
			.name = "cam_cc_camnoc_xo_clk",
			.parent_hws = (const struct clk_hw*[]) {
				&cam_cc_xo_clk_src.clkr.hw,
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch cam_cc_cci_0_clk = {
	.halt_reg = 0x11284,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x11284,
		.enable_mask = BIT(0),
		.hw.init = &(const struct clk_init_data) {
			.name = "cam_cc_cci_0_clk",
			.parent_hws = (const struct clk_hw*[]) {
				&cam_cc_cci_0_clk_src.clkr.hw,
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch cam_cc_cci_1_clk = {
	.halt_reg = 0x112a0,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x112a0,
		.enable_mask = BIT(0),
		.hw.init = &(const struct clk_init_data) {
			.name = "cam_cc_cci_1_clk",
			.parent_hws = (const struct clk_hw*[]) {
				&cam_cc_cci_1_clk_src.clkr.hw,
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch cam_cc_cci_2_clk = {
	.halt_reg = 0x112bc,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x112bc,
		.enable_mask = BIT(0),
		.hw.init = &(const struct clk_init_data) {
			.name = "cam_cc_cci_2_clk",
			.parent_hws = (const struct clk_hw*[]) {
				&cam_cc_cci_2_clk_src.clkr.hw,
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch cam_cc_core_ahb_clk = {
	.halt_reg = 0x11360,
	.halt_check = BRANCH_HALT_DELAY,
	.clkr = {
		.enable_reg = 0x11360,
		.enable_mask = BIT(0),
		.hw.init = &(const struct clk_init_data) {
			.name = "cam_cc_core_ahb_clk",
			.parent_hws = (const struct clk_hw*[]) {
				&cam_cc_slow_ahb_clk_src.clkr.hw,
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch cam_cc_cre_ahb_clk = {
	.halt_reg = 0x111cc,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x111cc,
		.enable_mask = BIT(0),
		.hw.init = &(const struct clk_init_data) {
			.name = "cam_cc_cre_ahb_clk",
			.parent_hws = (const struct clk_hw*[]) {
				&cam_cc_slow_ahb_clk_src.clkr.hw,
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch cam_cc_cre_clk = {
	.halt_reg = 0x111c4,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x111c4,
		.enable_mask = BIT(0),
		.hw.init = &(const struct clk_init_data) {
			.name = "cam_cc_cre_clk",
			.parent_hws = (const struct clk_hw*[]) {
				&cam_cc_cre_clk_src.clkr.hw,
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch cam_cc_csi0phytimer_clk = {
	.halt_reg = 0x10018,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x10018,
		.enable_mask = BIT(0),
		.hw.init = &(const struct clk_init_data) {
			.name = "cam_cc_csi0phytimer_clk",
			.parent_hws = (const struct clk_hw*[]) {
				&cam_cc_csi0phytimer_clk_src.clkr.hw,
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch cam_cc_csi1phytimer_clk = {
	.halt_reg = 0x1003c,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x1003c,
		.enable_mask = BIT(0),
		.hw.init = &(const struct clk_init_data) {
			.name = "cam_cc_csi1phytimer_clk",
			.parent_hws = (const struct clk_hw*[]) {
				&cam_cc_csi1phytimer_clk_src.clkr.hw,
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch cam_cc_csi2phytimer_clk = {
	.halt_reg = 0x1005c,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x1005c,
		.enable_mask = BIT(0),
		.hw.init = &(const struct clk_init_data) {
			.name = "cam_cc_csi2phytimer_clk",
			.parent_hws = (const struct clk_hw*[]) {
				&cam_cc_csi2phytimer_clk_src.clkr.hw,
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch cam_cc_csi3phytimer_clk = {
	.halt_reg = 0x1007c,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x1007c,
		.enable_mask = BIT(0),
		.hw.init = &(const struct clk_init_data) {
			.name = "cam_cc_csi3phytimer_clk",
			.parent_hws = (const struct clk_hw*[]) {
				&cam_cc_csi3phytimer_clk_src.clkr.hw,
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch cam_cc_csi4phytimer_clk = {
	.halt_reg = 0x1009c,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x1009c,
		.enable_mask = BIT(0),
		.hw.init = &(const struct clk_init_data) {
			.name = "cam_cc_csi4phytimer_clk",
			.parent_hws = (const struct clk_hw*[]) {
				&cam_cc_csi4phytimer_clk_src.clkr.hw,
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch cam_cc_csi5phytimer_clk = {
	.halt_reg = 0x100bc,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x100bc,
		.enable_mask = BIT(0),
		.hw.init = &(const struct clk_init_data) {
			.name = "cam_cc_csi5phytimer_clk",
			.parent_hws = (const struct clk_hw*[]) {
				&cam_cc_csi5phytimer_clk_src.clkr.hw,
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch cam_cc_csid_clk = {
	.halt_reg = 0x112d8,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x112d8,
		.enable_mask = BIT(0),
		.hw.init = &(const struct clk_init_data) {
			.name = "cam_cc_csid_clk",
			.parent_hws = (const struct clk_hw*[]) {
				&cam_cc_csid_clk_src.clkr.hw,
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_crm_ops,
		},
	},
};

static struct clk_branch cam_cc_csid_csiphy_rx_clk = {
	.halt_reg = 0x10020,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x10020,
		.enable_mask = BIT(0),
		.hw.init = &(const struct clk_init_data) {
			.name = "cam_cc_csid_csiphy_rx_clk",
			.parent_hws = (const struct clk_hw*[]) {
				&cam_cc_cphy_rx_clk_src.clkr.hw,
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch cam_cc_csiphy0_clk = {
	.halt_reg = 0x1001c,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x1001c,
		.enable_mask = BIT(0),
		.hw.init = &(const struct clk_init_data) {
			.name = "cam_cc_csiphy0_clk",
			.parent_hws = (const struct clk_hw*[]) {
				&cam_cc_cphy_rx_clk_src.clkr.hw,
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch cam_cc_csiphy1_clk = {
	.halt_reg = 0x10040,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x10040,
		.enable_mask = BIT(0),
		.hw.init = &(const struct clk_init_data) {
			.name = "cam_cc_csiphy1_clk",
			.parent_hws = (const struct clk_hw*[]) {
				&cam_cc_cphy_rx_clk_src.clkr.hw,
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch cam_cc_csiphy2_clk = {
	.halt_reg = 0x10060,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x10060,
		.enable_mask = BIT(0),
		.hw.init = &(const struct clk_init_data) {
			.name = "cam_cc_csiphy2_clk",
			.parent_hws = (const struct clk_hw*[]) {
				&cam_cc_cphy_rx_clk_src.clkr.hw,
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch cam_cc_csiphy3_clk = {
	.halt_reg = 0x10080,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x10080,
		.enable_mask = BIT(0),
		.hw.init = &(const struct clk_init_data) {
			.name = "cam_cc_csiphy3_clk",
			.parent_hws = (const struct clk_hw*[]) {
				&cam_cc_cphy_rx_clk_src.clkr.hw,
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch cam_cc_csiphy4_clk = {
	.halt_reg = 0x100a0,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x100a0,
		.enable_mask = BIT(0),
		.hw.init = &(const struct clk_init_data) {
			.name = "cam_cc_csiphy4_clk",
			.parent_hws = (const struct clk_hw*[]) {
				&cam_cc_cphy_rx_clk_src.clkr.hw,
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch cam_cc_csiphy5_clk = {
	.halt_reg = 0x100c0,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x100c0,
		.enable_mask = BIT(0),
		.hw.init = &(const struct clk_init_data) {
			.name = "cam_cc_csiphy5_clk",
			.parent_hws = (const struct clk_hw*[]) {
				&cam_cc_cphy_rx_clk_src.clkr.hw,
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch cam_cc_icp_0_ahb_clk = {
	.halt_reg = 0x11264,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x11264,
		.enable_mask = BIT(0),
		.hw.init = &(const struct clk_init_data) {
			.name = "cam_cc_icp_0_ahb_clk",
			.parent_hws = (const struct clk_hw*[]) {
				&cam_cc_slow_ahb_clk_src.clkr.hw,
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch cam_cc_icp_0_clk = {
	.halt_reg = 0x1122c,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x1122c,
		.enable_mask = BIT(0),
		.hw.init = &(const struct clk_init_data) {
			.name = "cam_cc_icp_0_clk",
			.parent_hws = (const struct clk_hw*[]) {
				&cam_cc_icp_0_clk_src.clkr.hw,
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch cam_cc_icp_1_ahb_clk = {
	.halt_reg = 0x11268,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x11268,
		.enable_mask = BIT(0),
		.hw.init = &(const struct clk_init_data) {
			.name = "cam_cc_icp_1_ahb_clk",
			.parent_hws = (const struct clk_hw*[]) {
				&cam_cc_slow_ahb_clk_src.clkr.hw,
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch cam_cc_icp_1_clk = {
	.halt_reg = 0x11254,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x11254,
		.enable_mask = BIT(0),
		.hw.init = &(const struct clk_init_data) {
			.name = "cam_cc_icp_1_clk",
			.parent_hws = (const struct clk_hw*[]) {
				&cam_cc_icp_1_clk_src.clkr.hw,
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch cam_cc_ife_lite_ahb_clk = {
	.halt_reg = 0x111a8,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x111a8,
		.enable_mask = BIT(0),
		.hw.init = &(const struct clk_init_data) {
			.name = "cam_cc_ife_lite_ahb_clk",
			.parent_hws = (const struct clk_hw*[]) {
				&cam_cc_slow_ahb_clk_src.clkr.hw,
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch cam_cc_ife_lite_clk = {
	.halt_reg = 0x11168,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x11168,
		.enable_mask = BIT(0),
		.hw.init = &(const struct clk_init_data) {
			.name = "cam_cc_ife_lite_clk",
			.parent_hws = (const struct clk_hw*[]) {
				&cam_cc_ife_lite_clk_src.clkr.hw,
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch cam_cc_ife_lite_cphy_rx_clk = {
	.halt_reg = 0x111a4,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x111a4,
		.enable_mask = BIT(0),
		.hw.init = &(const struct clk_init_data) {
			.name = "cam_cc_ife_lite_cphy_rx_clk",
			.parent_hws = (const struct clk_hw*[]) {
				&cam_cc_cphy_rx_clk_src.clkr.hw,
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch cam_cc_ife_lite_csid_clk = {
	.halt_reg = 0x11194,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x11194,
		.enable_mask = BIT(0),
		.hw.init = &(const struct clk_init_data) {
			.name = "cam_cc_ife_lite_csid_clk",
			.parent_hws = (const struct clk_hw*[]) {
				&cam_cc_ife_lite_csid_clk_src.clkr.hw,
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch cam_cc_ipe_nps_ahb_clk = {
	.halt_reg = 0x101d4,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x101d4,
		.enable_mask = BIT(0),
		.hw.init = &(const struct clk_init_data) {
			.name = "cam_cc_ipe_nps_ahb_clk",
			.parent_hws = (const struct clk_hw*[]) {
				&cam_cc_slow_ahb_clk_src.clkr.hw,
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch cam_cc_ipe_nps_clk = {
	.halt_reg = 0x101a8,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x101a8,
		.enable_mask = BIT(0),
		.hw.init = &(const struct clk_init_data) {
			.name = "cam_cc_ipe_nps_clk",
			.parent_hws = (const struct clk_hw*[]) {
				&cam_cc_ipe_nps_clk_src.clkr.hw,
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch cam_cc_ipe_nps_fast_ahb_clk = {
	.halt_reg = 0x101d8,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x101d8,
		.enable_mask = BIT(0),
		.hw.init = &(const struct clk_init_data) {
			.name = "cam_cc_ipe_nps_fast_ahb_clk",
			.parent_hws = (const struct clk_hw*[]) {
				&cam_cc_fast_ahb_clk_src.clkr.hw,
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch cam_cc_ipe_pps_clk = {
	.halt_reg = 0x101bc,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x101bc,
		.enable_mask = BIT(0),
		.hw.init = &(const struct clk_init_data) {
			.name = "cam_cc_ipe_pps_clk",
			.parent_hws = (const struct clk_hw*[]) {
				&cam_cc_ipe_nps_clk_src.clkr.hw,
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch cam_cc_ipe_pps_fast_ahb_clk = {
	.halt_reg = 0x101dc,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x101dc,
		.enable_mask = BIT(0),
		.hw.init = &(const struct clk_init_data) {
			.name = "cam_cc_ipe_pps_fast_ahb_clk",
			.parent_hws = (const struct clk_hw*[]) {
				&cam_cc_fast_ahb_clk_src.clkr.hw,
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch cam_cc_jpeg_0_clk = {
	.halt_reg = 0x111e8,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x111e8,
		.enable_mask = BIT(0),
		.hw.init = &(const struct clk_init_data) {
			.name = "cam_cc_jpeg_0_clk",
			.parent_hws = (const struct clk_hw*[]) {
				&cam_cc_jpeg_clk_src.clkr.hw,
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch cam_cc_jpeg_1_clk = {
	.halt_reg = 0x111f8,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x111f8,
		.enable_mask = BIT(0),
		.hw.init = &(const struct clk_init_data) {
			.name = "cam_cc_jpeg_1_clk",
			.parent_hws = (const struct clk_hw*[]) {
				&cam_cc_jpeg_clk_src.clkr.hw,
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch cam_cc_ofe_ahb_clk = {
	.halt_reg = 0x10118,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x10118,
		.enable_mask = BIT(0),
		.hw.init = &(const struct clk_init_data) {
			.name = "cam_cc_ofe_ahb_clk",
			.parent_hws = (const struct clk_hw*[]) {
				&cam_cc_slow_ahb_clk_src.clkr.hw,
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch cam_cc_ofe_anchor_clk = {
	.halt_reg = 0x10148,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x10148,
		.enable_mask = BIT(0),
		.hw.init = &(const struct clk_init_data) {
			.name = "cam_cc_ofe_anchor_clk",
			.parent_hws = (const struct clk_hw*[]) {
				&cam_cc_ofe_clk_src.clkr.hw,
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch cam_cc_ofe_anchor_fast_ahb_clk = {
	.halt_reg = 0x100f8,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x100f8,
		.enable_mask = BIT(0),
		.hw.init = &(const struct clk_init_data) {
			.name = "cam_cc_ofe_anchor_fast_ahb_clk",
			.parent_hws = (const struct clk_hw*[]) {
				&cam_cc_fast_ahb_clk_src.clkr.hw,
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch cam_cc_ofe_hdr_clk = {
	.halt_reg = 0x1015c,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x1015c,
		.enable_mask = BIT(0),
		.hw.init = &(const struct clk_init_data) {
			.name = "cam_cc_ofe_hdr_clk",
			.parent_hws = (const struct clk_hw*[]) {
				&cam_cc_ofe_clk_src.clkr.hw,
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch cam_cc_ofe_hdr_fast_ahb_clk = {
	.halt_reg = 0x100fc,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x100fc,
		.enable_mask = BIT(0),
		.hw.init = &(const struct clk_init_data) {
			.name = "cam_cc_ofe_hdr_fast_ahb_clk",
			.parent_hws = (const struct clk_hw*[]) {
				&cam_cc_fast_ahb_clk_src.clkr.hw,
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch cam_cc_ofe_main_clk = {
	.halt_reg = 0x10134,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x10134,
		.enable_mask = BIT(0),
		.hw.init = &(const struct clk_init_data) {
			.name = "cam_cc_ofe_main_clk",
			.parent_hws = (const struct clk_hw*[]) {
				&cam_cc_ofe_clk_src.clkr.hw,
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch cam_cc_ofe_main_fast_ahb_clk = {
	.halt_reg = 0x100f4,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x100f4,
		.enable_mask = BIT(0),
		.hw.init = &(const struct clk_init_data) {
			.name = "cam_cc_ofe_main_fast_ahb_clk",
			.parent_hws = (const struct clk_hw*[]) {
				&cam_cc_fast_ahb_clk_src.clkr.hw,
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch cam_cc_qdss_debug_clk = {
	.halt_reg = 0x11344,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x11344,
		.enable_mask = BIT(0),
		.hw.init = &(const struct clk_init_data) {
			.name = "cam_cc_qdss_debug_clk",
			.parent_hws = (const struct clk_hw*[]) {
				&cam_cc_qdss_debug_clk_src.clkr.hw,
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch cam_cc_qdss_debug_xo_clk = {
	.halt_reg = 0x11348,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x11348,
		.enable_mask = BIT(0),
		.hw.init = &(const struct clk_init_data) {
			.name = "cam_cc_qdss_debug_xo_clk",
			.parent_hws = (const struct clk_hw*[]) {
				&cam_cc_xo_clk_src.clkr.hw,
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch cam_cc_tfe_0_bayer_clk = {
	.halt_reg = 0x11044,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x11044,
		.enable_mask = BIT(0),
		.hw.init = &(const struct clk_init_data) {
			.name = "cam_cc_tfe_0_bayer_clk",
			.parent_hws = (const struct clk_hw*[]) {
				&cam_cc_tfe_0_clk_src.clkr.hw,
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_crm_ops,
		},
	},
};

static struct clk_branch cam_cc_tfe_0_bayer_fast_ahb_clk = {
	.halt_reg = 0x11064,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x11064,
		.enable_mask = BIT(0),
		.hw.init = &(const struct clk_init_data) {
			.name = "cam_cc_tfe_0_bayer_fast_ahb_clk",
			.parent_hws = (const struct clk_hw*[]) {
				&cam_cc_fast_ahb_clk_src.clkr.hw,
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch cam_cc_tfe_0_main_clk = {
	.halt_reg = 0x11030,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x11030,
		.enable_mask = BIT(0),
		.hw.init = &(const struct clk_init_data) {
			.name = "cam_cc_tfe_0_main_clk",
			.parent_hws = (const struct clk_hw*[]) {
				&cam_cc_tfe_0_clk_src.clkr.hw,
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_crm_ops,
		},
	},
};

static struct clk_branch cam_cc_tfe_0_main_fast_ahb_clk = {
	.halt_reg = 0x11060,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x11060,
		.enable_mask = BIT(0),
		.hw.init = &(const struct clk_init_data) {
			.name = "cam_cc_tfe_0_main_fast_ahb_clk",
			.parent_hws = (const struct clk_hw*[]) {
				&cam_cc_fast_ahb_clk_src.clkr.hw,
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch cam_cc_tfe_1_bayer_clk = {
	.halt_reg = 0x110c4,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x110c4,
		.enable_mask = BIT(0),
		.hw.init = &(const struct clk_init_data) {
			.name = "cam_cc_tfe_1_bayer_clk",
			.parent_hws = (const struct clk_hw*[]) {
				&cam_cc_tfe_1_clk_src.clkr.hw,
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_crm_ops,
		},
	},
};

static struct clk_branch cam_cc_tfe_1_bayer_fast_ahb_clk = {
	.halt_reg = 0x110e4,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x110e4,
		.enable_mask = BIT(0),
		.hw.init = &(const struct clk_init_data) {
			.name = "cam_cc_tfe_1_bayer_fast_ahb_clk",
			.parent_hws = (const struct clk_hw*[]) {
				&cam_cc_fast_ahb_clk_src.clkr.hw,
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch cam_cc_tfe_1_main_clk = {
	.halt_reg = 0x110b0,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x110b0,
		.enable_mask = BIT(0),
		.hw.init = &(const struct clk_init_data) {
			.name = "cam_cc_tfe_1_main_clk",
			.parent_hws = (const struct clk_hw*[]) {
				&cam_cc_tfe_1_clk_src.clkr.hw,
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_crm_ops,
		},
	},
};

static struct clk_branch cam_cc_tfe_1_main_fast_ahb_clk = {
	.halt_reg = 0x110e0,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x110e0,
		.enable_mask = BIT(0),
		.hw.init = &(const struct clk_init_data) {
			.name = "cam_cc_tfe_1_main_fast_ahb_clk",
			.parent_hws = (const struct clk_hw*[]) {
				&cam_cc_fast_ahb_clk_src.clkr.hw,
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch cam_cc_tfe_2_bayer_clk = {
	.halt_reg = 0x1112c,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x1112c,
		.enable_mask = BIT(0),
		.hw.init = &(const struct clk_init_data) {
			.name = "cam_cc_tfe_2_bayer_clk",
			.parent_hws = (const struct clk_hw*[]) {
				&cam_cc_tfe_2_clk_src.clkr.hw,
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_crm_ops,
		},
	},
};

static struct clk_branch cam_cc_tfe_2_bayer_fast_ahb_clk = {
	.halt_reg = 0x1114c,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x1114c,
		.enable_mask = BIT(0),
		.hw.init = &(const struct clk_init_data) {
			.name = "cam_cc_tfe_2_bayer_fast_ahb_clk",
			.parent_hws = (const struct clk_hw*[]) {
				&cam_cc_fast_ahb_clk_src.clkr.hw,
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch cam_cc_tfe_2_main_clk = {
	.halt_reg = 0x11118,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x11118,
		.enable_mask = BIT(0),
		.hw.init = &(const struct clk_init_data) {
			.name = "cam_cc_tfe_2_main_clk",
			.parent_hws = (const struct clk_hw*[]) {
				&cam_cc_tfe_2_clk_src.clkr.hw,
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_crm_ops,
		},
	},
};

static struct clk_branch cam_cc_tfe_2_main_fast_ahb_clk = {
	.halt_reg = 0x11148,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x11148,
		.enable_mask = BIT(0),
		.hw.init = &(const struct clk_init_data) {
			.name = "cam_cc_tfe_2_main_fast_ahb_clk",
			.parent_hws = (const struct clk_hw*[]) {
				&cam_cc_fast_ahb_clk_src.clkr.hw,
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_regmap *cam_cc_sun_clocks[] = {
	[CAM_CC_CAM_TOP_AHB_CLK] = &cam_cc_cam_top_ahb_clk.clkr,
	[CAM_CC_CAM_TOP_FAST_AHB_CLK] = &cam_cc_cam_top_fast_ahb_clk.clkr,
	[CAM_CC_CAMNOC_DCD_XO_CLK] = &cam_cc_camnoc_dcd_xo_clk.clkr,
	[CAM_CC_CAMNOC_NRT_AXI_CLK] = &cam_cc_camnoc_nrt_axi_clk.clkr,
	[CAM_CC_CAMNOC_NRT_CRE_CLK] = &cam_cc_camnoc_nrt_cre_clk.clkr,
	[CAM_CC_CAMNOC_NRT_IPE_NPS_CLK] = &cam_cc_camnoc_nrt_ipe_nps_clk.clkr,
	[CAM_CC_CAMNOC_NRT_OFE_ANCHOR_CLK] = &cam_cc_camnoc_nrt_ofe_anchor_clk.clkr,
	[CAM_CC_CAMNOC_NRT_OFE_HDR_CLK] = &cam_cc_camnoc_nrt_ofe_hdr_clk.clkr,
	[CAM_CC_CAMNOC_NRT_OFE_MAIN_CLK] = &cam_cc_camnoc_nrt_ofe_main_clk.clkr,
	[CAM_CC_CAMNOC_RT_AXI_CLK] = &cam_cc_camnoc_rt_axi_clk.clkr,
	[CAM_CC_CAMNOC_RT_AXI_CLK_SRC] = &cam_cc_camnoc_rt_axi_clk_src.clkr,
	[CAM_CC_CAMNOC_RT_IFE_LITE_CLK] = &cam_cc_camnoc_rt_ife_lite_clk.clkr,
	[CAM_CC_CAMNOC_RT_TFE_0_BAYER_CLK] = &cam_cc_camnoc_rt_tfe_0_bayer_clk.clkr,
	[CAM_CC_CAMNOC_RT_TFE_0_MAIN_CLK] = &cam_cc_camnoc_rt_tfe_0_main_clk.clkr,
	[CAM_CC_CAMNOC_RT_TFE_1_BAYER_CLK] = &cam_cc_camnoc_rt_tfe_1_bayer_clk.clkr,
	[CAM_CC_CAMNOC_RT_TFE_1_MAIN_CLK] = &cam_cc_camnoc_rt_tfe_1_main_clk.clkr,
	[CAM_CC_CAMNOC_RT_TFE_2_BAYER_CLK] = &cam_cc_camnoc_rt_tfe_2_bayer_clk.clkr,
	[CAM_CC_CAMNOC_RT_TFE_2_MAIN_CLK] = &cam_cc_camnoc_rt_tfe_2_main_clk.clkr,
	[CAM_CC_CAMNOC_XO_CLK] = &cam_cc_camnoc_xo_clk.clkr,
	[CAM_CC_CCI_0_CLK] = &cam_cc_cci_0_clk.clkr,
	[CAM_CC_CCI_0_CLK_SRC] = &cam_cc_cci_0_clk_src.clkr,
	[CAM_CC_CCI_1_CLK] = &cam_cc_cci_1_clk.clkr,
	[CAM_CC_CCI_1_CLK_SRC] = &cam_cc_cci_1_clk_src.clkr,
	[CAM_CC_CCI_2_CLK] = &cam_cc_cci_2_clk.clkr,
	[CAM_CC_CCI_2_CLK_SRC] = &cam_cc_cci_2_clk_src.clkr,
	[CAM_CC_CORE_AHB_CLK] = &cam_cc_core_ahb_clk.clkr,
	[CAM_CC_CPHY_RX_CLK_SRC] = &cam_cc_cphy_rx_clk_src.clkr,
	[CAM_CC_CRE_AHB_CLK] = &cam_cc_cre_ahb_clk.clkr,
	[CAM_CC_CRE_CLK] = &cam_cc_cre_clk.clkr,
	[CAM_CC_CRE_CLK_SRC] = &cam_cc_cre_clk_src.clkr,
	[CAM_CC_CSI0PHYTIMER_CLK] = &cam_cc_csi0phytimer_clk.clkr,
	[CAM_CC_CSI0PHYTIMER_CLK_SRC] = &cam_cc_csi0phytimer_clk_src.clkr,
	[CAM_CC_CSI1PHYTIMER_CLK] = &cam_cc_csi1phytimer_clk.clkr,
	[CAM_CC_CSI1PHYTIMER_CLK_SRC] = &cam_cc_csi1phytimer_clk_src.clkr,
	[CAM_CC_CSI2PHYTIMER_CLK] = &cam_cc_csi2phytimer_clk.clkr,
	[CAM_CC_CSI2PHYTIMER_CLK_SRC] = &cam_cc_csi2phytimer_clk_src.clkr,
	[CAM_CC_CSI3PHYTIMER_CLK] = &cam_cc_csi3phytimer_clk.clkr,
	[CAM_CC_CSI3PHYTIMER_CLK_SRC] = &cam_cc_csi3phytimer_clk_src.clkr,
	[CAM_CC_CSI4PHYTIMER_CLK] = &cam_cc_csi4phytimer_clk.clkr,
	[CAM_CC_CSI4PHYTIMER_CLK_SRC] = &cam_cc_csi4phytimer_clk_src.clkr,
	[CAM_CC_CSI5PHYTIMER_CLK] = &cam_cc_csi5phytimer_clk.clkr,
	[CAM_CC_CSI5PHYTIMER_CLK_SRC] = &cam_cc_csi5phytimer_clk_src.clkr,
	[CAM_CC_CSID_CLK] = &cam_cc_csid_clk.clkr,
	[CAM_CC_CSID_CLK_SRC] = &cam_cc_csid_clk_src.clkr,
	[CAM_CC_CSID_CSIPHY_RX_CLK] = &cam_cc_csid_csiphy_rx_clk.clkr,
	[CAM_CC_CSIPHY0_CLK] = &cam_cc_csiphy0_clk.clkr,
	[CAM_CC_CSIPHY1_CLK] = &cam_cc_csiphy1_clk.clkr,
	[CAM_CC_CSIPHY2_CLK] = &cam_cc_csiphy2_clk.clkr,
	[CAM_CC_CSIPHY3_CLK] = &cam_cc_csiphy3_clk.clkr,
	[CAM_CC_CSIPHY4_CLK] = &cam_cc_csiphy4_clk.clkr,
	[CAM_CC_CSIPHY5_CLK] = &cam_cc_csiphy5_clk.clkr,
	[CAM_CC_FAST_AHB_CLK_SRC] = &cam_cc_fast_ahb_clk_src.clkr,
	[CAM_CC_ICP_0_AHB_CLK] = &cam_cc_icp_0_ahb_clk.clkr,
	[CAM_CC_ICP_0_CLK] = &cam_cc_icp_0_clk.clkr,
	[CAM_CC_ICP_0_CLK_SRC] = &cam_cc_icp_0_clk_src.clkr,
	[CAM_CC_ICP_1_AHB_CLK] = &cam_cc_icp_1_ahb_clk.clkr,
	[CAM_CC_ICP_1_CLK] = &cam_cc_icp_1_clk.clkr,
	[CAM_CC_ICP_1_CLK_SRC] = &cam_cc_icp_1_clk_src.clkr,
	[CAM_CC_IFE_LITE_AHB_CLK] = &cam_cc_ife_lite_ahb_clk.clkr,
	[CAM_CC_IFE_LITE_CLK] = &cam_cc_ife_lite_clk.clkr,
	[CAM_CC_IFE_LITE_CLK_SRC] = &cam_cc_ife_lite_clk_src.clkr,
	[CAM_CC_IFE_LITE_CPHY_RX_CLK] = &cam_cc_ife_lite_cphy_rx_clk.clkr,
	[CAM_CC_IFE_LITE_CSID_CLK] = &cam_cc_ife_lite_csid_clk.clkr,
	[CAM_CC_IFE_LITE_CSID_CLK_SRC] = &cam_cc_ife_lite_csid_clk_src.clkr,
	[CAM_CC_IPE_NPS_AHB_CLK] = &cam_cc_ipe_nps_ahb_clk.clkr,
	[CAM_CC_IPE_NPS_CLK] = &cam_cc_ipe_nps_clk.clkr,
	[CAM_CC_IPE_NPS_CLK_SRC] = &cam_cc_ipe_nps_clk_src.clkr,
	[CAM_CC_IPE_NPS_FAST_AHB_CLK] = &cam_cc_ipe_nps_fast_ahb_clk.clkr,
	[CAM_CC_IPE_PPS_CLK] = &cam_cc_ipe_pps_clk.clkr,
	[CAM_CC_IPE_PPS_FAST_AHB_CLK] = &cam_cc_ipe_pps_fast_ahb_clk.clkr,
	[CAM_CC_JPEG_0_CLK] = &cam_cc_jpeg_0_clk.clkr,
	[CAM_CC_JPEG_1_CLK] = &cam_cc_jpeg_1_clk.clkr,
	[CAM_CC_JPEG_CLK_SRC] = &cam_cc_jpeg_clk_src.clkr,
	[CAM_CC_OFE_AHB_CLK] = &cam_cc_ofe_ahb_clk.clkr,
	[CAM_CC_OFE_ANCHOR_CLK] = &cam_cc_ofe_anchor_clk.clkr,
	[CAM_CC_OFE_ANCHOR_FAST_AHB_CLK] = &cam_cc_ofe_anchor_fast_ahb_clk.clkr,
	[CAM_CC_OFE_CLK_SRC] = &cam_cc_ofe_clk_src.clkr,
	[CAM_CC_OFE_HDR_CLK] = &cam_cc_ofe_hdr_clk.clkr,
	[CAM_CC_OFE_HDR_FAST_AHB_CLK] = &cam_cc_ofe_hdr_fast_ahb_clk.clkr,
	[CAM_CC_OFE_MAIN_CLK] = &cam_cc_ofe_main_clk.clkr,
	[CAM_CC_OFE_MAIN_FAST_AHB_CLK] = &cam_cc_ofe_main_fast_ahb_clk.clkr,
	[CAM_CC_PLL0] = &cam_cc_pll0.clkr,
	[CAM_CC_PLL0_OUT_EVEN] = &cam_cc_pll0_out_even.clkr,
	[CAM_CC_PLL0_OUT_ODD] = &cam_cc_pll0_out_odd.clkr,
	[CAM_CC_PLL1] = &cam_cc_pll1.clkr,
	[CAM_CC_PLL1_OUT_EVEN] = &cam_cc_pll1_out_even.clkr,
	[CAM_CC_PLL2] = &cam_cc_pll2.clkr,
	[CAM_CC_PLL2_OUT_EVEN] = &cam_cc_pll2_out_even.clkr,
	[CAM_CC_PLL3] = &cam_cc_pll3.clkr,
	[CAM_CC_PLL3_OUT_EVEN] = &cam_cc_pll3_out_even.clkr,
	[CAM_CC_PLL4] = &cam_cc_pll4.clkr,
	[CAM_CC_PLL4_OUT_EVEN] = &cam_cc_pll4_out_even.clkr,
	[CAM_CC_PLL5] = &cam_cc_pll5.clkr,
	[CAM_CC_PLL5_OUT_EVEN] = &cam_cc_pll5_out_even.clkr,
	[CAM_CC_PLL6] = &cam_cc_pll6.clkr,
	[CAM_CC_PLL6_OUT_EVEN] = &cam_cc_pll6_out_even.clkr,
	[CAM_CC_PLL6_OUT_ODD] = &cam_cc_pll6_out_odd.clkr,
	[CAM_CC_QDSS_DEBUG_CLK] = &cam_cc_qdss_debug_clk.clkr,
	[CAM_CC_QDSS_DEBUG_CLK_SRC] = &cam_cc_qdss_debug_clk_src.clkr,
	[CAM_CC_QDSS_DEBUG_XO_CLK] = &cam_cc_qdss_debug_xo_clk.clkr,
	[CAM_CC_SLEEP_CLK_SRC] = &cam_cc_sleep_clk_src.clkr,
	[CAM_CC_SLOW_AHB_CLK_SRC] = &cam_cc_slow_ahb_clk_src.clkr,
	[CAM_CC_TFE_0_BAYER_CLK] = &cam_cc_tfe_0_bayer_clk.clkr,
	[CAM_CC_TFE_0_BAYER_FAST_AHB_CLK] = &cam_cc_tfe_0_bayer_fast_ahb_clk.clkr,
	[CAM_CC_TFE_0_CLK_SRC] = &cam_cc_tfe_0_clk_src.clkr,
	[CAM_CC_TFE_0_MAIN_CLK] = &cam_cc_tfe_0_main_clk.clkr,
	[CAM_CC_TFE_0_MAIN_FAST_AHB_CLK] = &cam_cc_tfe_0_main_fast_ahb_clk.clkr,
	[CAM_CC_TFE_1_BAYER_CLK] = &cam_cc_tfe_1_bayer_clk.clkr,
	[CAM_CC_TFE_1_BAYER_FAST_AHB_CLK] = &cam_cc_tfe_1_bayer_fast_ahb_clk.clkr,
	[CAM_CC_TFE_1_CLK_SRC] = &cam_cc_tfe_1_clk_src.clkr,
	[CAM_CC_TFE_1_MAIN_CLK] = &cam_cc_tfe_1_main_clk.clkr,
	[CAM_CC_TFE_1_MAIN_FAST_AHB_CLK] = &cam_cc_tfe_1_main_fast_ahb_clk.clkr,
	[CAM_CC_TFE_2_BAYER_CLK] = &cam_cc_tfe_2_bayer_clk.clkr,
	[CAM_CC_TFE_2_BAYER_FAST_AHB_CLK] = &cam_cc_tfe_2_bayer_fast_ahb_clk.clkr,
	[CAM_CC_TFE_2_CLK_SRC] = &cam_cc_tfe_2_clk_src.clkr,
	[CAM_CC_TFE_2_MAIN_CLK] = &cam_cc_tfe_2_main_clk.clkr,
	[CAM_CC_TFE_2_MAIN_FAST_AHB_CLK] = &cam_cc_tfe_2_main_fast_ahb_clk.clkr,
	[CAM_CC_XO_CLK_SRC] = &cam_cc_xo_clk_src.clkr,
};

static const struct qcom_reset_map cam_cc_sun_resets[] = {
	[CAM_CC_DRV_BCR] = { 0x113bc },
	[CAM_CC_ICP_BCR] = { 0x11210 },
	[CAM_CC_IPE_0_BCR] = { 0x10178 },
	[CAM_CC_OFE_BCR] = { 0x100c4 },
	[CAM_CC_QDSS_DEBUG_BCR] = { 0x11328 },
	[CAM_CC_TFE_0_BCR] = { 0x11000 },
	[CAM_CC_TFE_1_BCR] = { 0x11080 },
	[CAM_CC_TFE_2_BCR] = { 0x110e8 },
};

static const struct regmap_config cam_cc_sun_regmap_config = {
	.reg_bits = 32,
	.reg_stride = 4,
	.val_bits = 32,
	.max_register = 0x1601c,
	.fast_io = true,
};

static struct qcom_cc_desc cam_cc_sun_desc = {
	.config = &cam_cc_sun_regmap_config,
	.clks = cam_cc_sun_clocks,
	.num_clks = ARRAY_SIZE(cam_cc_sun_clocks),
	.resets = cam_cc_sun_resets,
	.num_resets = ARRAY_SIZE(cam_cc_sun_resets),
	.clk_regulators = cam_cc_sun_regulators,
	.num_clk_regulators = ARRAY_SIZE(cam_cc_sun_regulators),
};

static const struct of_device_id cam_cc_sun_match_table[] = {
	{ .compatible = "qcom,sun-camcc" },
	{ }
};
MODULE_DEVICE_TABLE(of, cam_cc_sun_match_table);

static int cam_cc_sun_probe(struct platform_device *pdev)
{
	struct regmap *regmap;
	int ret;

	regmap = qcom_cc_map(pdev, &cam_cc_sun_desc);
	if (IS_ERR(regmap))
		return PTR_ERR(regmap);

	ret = qcom_cc_runtime_init(pdev, &cam_cc_sun_desc);
	if (ret)
		return ret;

	ret = pm_runtime_get_sync(&pdev->dev);
	if (ret)
		return ret;

	clk_taycan_elu_pll_configure(&cam_cc_pll0, regmap, &cam_cc_pll0_config);
	clk_taycan_elu_pll_configure(&cam_cc_pll1, regmap, &cam_cc_pll1_config);
	clk_taycan_elu_pll_configure(&cam_cc_pll2, regmap, &cam_cc_pll2_config);
	clk_taycan_elu_pll_configure(&cam_cc_pll3, regmap, &cam_cc_pll3_config);
	clk_taycan_elu_pll_configure(&cam_cc_pll4, regmap, &cam_cc_pll4_config);
	clk_taycan_elu_pll_configure(&cam_cc_pll5, regmap, &cam_cc_pll5_config);
	clk_taycan_elu_pll_configure(&cam_cc_pll6, regmap, &cam_cc_pll6_config);

	/*
	 * Keep clocks always enabled:
	 *	cam_cc_drv_ahb_clk
	 *	cam_cc_drv_xo_clk
	 *	cam_cc_gdsc_clk
	 *	cam_cc_sleep_clk
	 */
	regmap_update_bits(regmap, 0x113c4, BIT(0), BIT(0));
	regmap_update_bits(regmap, 0x113c0, BIT(0), BIT(0));
	regmap_update_bits(regmap, 0x1137c, BIT(0), BIT(0));
	regmap_update_bits(regmap, 0x11398, BIT(0), BIT(0));

	ret = qcom_cc_really_probe(pdev, &cam_cc_sun_desc, regmap);
	if (ret) {
		dev_err(&pdev->dev, "Failed to register CAM CC clocks\n");
		return ret;
	}

	pm_runtime_put_sync(&pdev->dev);
	dev_info(&pdev->dev, "Registered CAM CC clocks\n");

	return ret;
}

static void cam_cc_sun_sync_state(struct device *dev)
{
	qcom_cc_sync_state(dev, &cam_cc_sun_desc);
}

static const struct dev_pm_ops cam_cc_sun_pm_ops = {
	SET_RUNTIME_PM_OPS(qcom_cc_runtime_suspend, qcom_cc_runtime_resume, NULL)
	SET_SYSTEM_SLEEP_PM_OPS(pm_runtime_force_suspend,
				pm_runtime_force_resume)
};

static struct platform_driver cam_cc_sun_driver = {
	.probe = cam_cc_sun_probe,
	.driver = {
		.name = "cam_cc-sun",
		.of_match_table = cam_cc_sun_match_table,
		.sync_state = cam_cc_sun_sync_state,
		.pm = &cam_cc_sun_pm_ops,
	},
};

static int __init cam_cc_sun_init(void)
{
	return platform_driver_register(&cam_cc_sun_driver);
}
subsys_initcall(cam_cc_sun_init);

static void __exit cam_cc_sun_exit(void)
{
	platform_driver_unregister(&cam_cc_sun_driver);
}
module_exit(cam_cc_sun_exit);

MODULE_DESCRIPTION("QTI CAM_CC SUN Driver");
MODULE_LICENSE("GPL");
