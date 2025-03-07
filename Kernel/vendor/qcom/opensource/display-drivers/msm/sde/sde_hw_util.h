/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2021-2024 Qualcomm Innovation Center, Inc. All rights reserved.
 * Copyright (c) 2015-2021, The Linux Foundation. All rights reserved.
 */

#ifndef _SDE_HW_UTIL_H
#define _SDE_HW_UTIL_H

#include <linux/io.h>
#include <linux/slab.h>
#include <drm/drm_drv.h>
#include "sde_hw_mdss.h"
#include "sde_hw_catalog.h"

#define REG_MASK(n)                     ((BIT(n)) - 1)
#define REG_MASK_SHIFT(n, shift)        ((REG_MASK(n)) << (shift))
#define REG_MASK_ULL(n)                 ((BIT_ULL(n)) - 1)
#define REG_MASK_SHIFT_ULL(n, shift)    ((REG_MASK_ULL(n)) << (shift))
#define LP_DDR4_TYPE			0x7

struct sde_format_extended;

/*
 * This is the common struct maintained by each sub block
 * for mapping the register offsets in this block to the
 * absoulute IO address
 * @base_off:     mdp register mapped offset
 * @blk_off:      pipe offset relative to mdss offset
 * @length        length of register block offset
 * @xin_id        xin id
 * @hw_rev     mdss hw revision
 */
struct sde_hw_blk_reg_map {
	void __iomem *base_off;
	u32 blk_off;
	u32 length;
	u32 xin_id;
	u32 hw_rev;
	u32 log_mask;
};

/**
 * struct sde_hw_scaler3_de_cfg : QSEEDv3 detail enhancer configuration
 * @enable:         detail enhancer enable/disable
 * @sharpen_level1: sharpening strength for noise
 * @sharpen_level2: sharpening strength for signal
 * @ clip:          clip shift
 * @ limit:         limit value
 * @ thr_quiet:     quiet threshold
 * @ thr_dieout:    dieout threshold
 * @ thr_high:      low threshold
 * @ thr_high:      high threshold
 * @ prec_shift:    precision shift
 * @ adjust_a:      A-coefficients for mapping curve
 * @ adjust_b:      B-coefficients for mapping curve
 * @ adjust_c:      C-coefficients for mapping curve
 * @ blend:      Unsharp Blend Filter Ratio
 */
struct sde_hw_scaler3_de_cfg {
	u32 enable;
	int16_t sharpen_level1;
	int16_t sharpen_level2;
	uint16_t clip;
	uint16_t limit;
	uint16_t thr_quiet;
	uint16_t thr_dieout;
	uint16_t thr_low;
	uint16_t thr_high;
	uint16_t prec_shift;
	int16_t adjust_a[SDE_MAX_DE_CURVES];
	int16_t adjust_b[SDE_MAX_DE_CURVES];
	int16_t adjust_c[SDE_MAX_DE_CURVES];
	uint32_t blend;
};

/**
 * struct sde_hw_cac_cfg : QSEEDv3 CAC configuration
 * @cac_mode:              cac mode for current configuration
 * @uv_filter_cfg:         uv plane filter configuration in CAC mode
 * @cac_le_phase_init2_x:  LE horizontal initial phase2
 * @cac_le_phase_init2_y:  LE vertical initial phase2
 * @cac_re_phase_init2_y:  RE vertical initial phase2
 * @cac_re_phase_init_y:   RE vertical initial phase
 * @cac_le_thr_x:          LE horizontal threshold
 * @cac_le_thr_y:          LE vertical threshold
 * @cac_re_thr_y:          RE vertical threshold
 * @cac_re_preload_y:      RE preload value
 * @cac_dst_uv_w:          uv destination width
 * @cac_dst_uv_h:          uv destination height
 * @cac_le_dst_h_offset:   LE destination horizontal offset
 * @cac_le_dst_v_offset:   LE destination vertical offset
 * @cac_re_dst_v_offset:   RE destination vertical offset
 * @cac_phase_inc_first_x: horizontal inc_first control
 * @cac_phase_inc_first_y: vertical inc_first control
 * @cac_le_inc_skip_x:     LE horizontal inc_skip control
 * @cac_le_inc_skip_y:     LE vertical inc_skip control
 * @cac_re_inc_skip_x:     RE horizontal inc_skip control
 * @cac_re_inc_skip_y:     RE vertical inc_skip control
 */
struct sde_hw_cac_cfg {
	u32 cac_mode;
	u32 uv_filter_cfg;

	u32 cac_le_phase_init2_x[SDE_MAX_PLANES];
	u32 cac_le_phase_init2_y[SDE_MAX_PLANES];
	u32 cac_re_phase_init2_y[SDE_MAX_PLANES];
	u32 cac_re_phase_init_y[SDE_MAX_PLANES];

	u32 cac_le_thr_x[SDE_MAX_PLANES];
	u32 cac_le_thr_y[SDE_MAX_PLANES];

	u32 cac_re_thr_y[SDE_MAX_PLANES];
	u32 cac_re_preload_y[SDE_MAX_PLANES];

	u32 cac_dst_uv_w;
	u32 cac_dst_uv_h;
	u32 cac_le_dst_h_offset;
	u32 cac_le_dst_v_offset;
	u32 cac_re_dst_v_offset;

	u16 cac_phase_inc_first_x[SDE_MAX_PLANES];
	u16 cac_phase_inc_first_y[SDE_MAX_PLANES];
	u16 cac_le_inc_skip_x[SDE_MAX_PLANES];
	u16 cac_le_inc_skip_y[SDE_MAX_PLANES];
	u16 cac_re_inc_skip_x[SDE_MAX_PLANES];
	u16 cac_re_inc_skip_y[SDE_MAX_PLANES];
};

/**
 * struct sde_hw_scaler3_cfg : QSEEDv3 configuration
 * @enable:        scaler enable
 * @dir_en:        direction detection block enable
 * @dir45_en:      45/-45 degree direction filtering block enable
 * @cor_en:        corner detection block enable
 * @ init_phase_x: horizontal initial phase
 * @ phase_step_x: horizontal phase step
 * @ init_phase_y: vertical initial phase
 * @ phase_step_y: vertical phase step
 * @ preload_x:    horizontal preload value
 * @ preload_y:    vertical preload value
 * @ src_width:    source width
 * @ src_height:   source height
 * @ dst_width:    destination width
 * @ dst_height:   destination height
 * @ y_rgb_filter_cfg: y/rgb plane filter configuration
 * @ uv_filter_cfg: uv plane filter configuration
 * @ alpha_filter_cfg: alpha filter configuration
 * @ blend_cfg:    blend coefficients configuration
 * @ lut_flag:     scaler LUT update flags
 *                 0x1 swap LUT bank
 *                 0x2 update 2D filter LUT
 *                 0x4 update y circular filter LUT
 *                 0x8 update uv circular filter LUT
 *                 0x10 update y separable filter LUT
 *                 0x20 update uv separable filter LUT
 * @ dir_lut_idx:  2D filter LUT index
 * @ y_rgb_cir_lut_idx: y circular filter LUT index
 * @ uv_cir_lut_idx: uv circular filter LUT index
 * @ y_rgb_sep_lut_idx: y circular filter LUT index
 * @ uv_sep_lut_idx: uv separable filter LUT index
 * @ dir_lut:      pointer to 2D LUT
 * @ cir_lut:      pointer to circular filter LUT
 * @ sep_lut:      pointer to separable filter LUT
 * @ de: detail enhancer configuration
 * @ dir_weight:   Directional Weight
 * @dyn_exp_disabled:     Dynamic expansion disabled
 * @de_lpf_flags:      Detail enhancer lpf blned configuration flags
 * @de_lpf_h:          Detail enhancer lpf blend high
 * @de_lpf_l:          Detail enhancer lpf blend low
 * @de_lpf_m:          Detail enhancer lpf blend medium
 * @cac_cfg:              CAC qseed config
 */
struct sde_hw_scaler3_cfg {
	u32 enable;
	u32 dir_en;
	u32 dir45_en;
	u32 cor_en;
	int32_t init_phase_x[SDE_MAX_PLANES];
	int32_t phase_step_x[SDE_MAX_PLANES];
	int32_t init_phase_y[SDE_MAX_PLANES];
	int32_t phase_step_y[SDE_MAX_PLANES];

	u32 preload_x[SDE_MAX_PLANES];
	u32 preload_y[SDE_MAX_PLANES];
	u32 src_width[SDE_MAX_PLANES];
	u32 src_height[SDE_MAX_PLANES];

	u32 dst_width;
	u32 dst_height;

	u32 y_rgb_filter_cfg;
	u32 uv_filter_cfg;
	u32 alpha_filter_cfg;
	u32 blend_cfg;

	u32 lut_flag;
	u32 dir_lut_idx;

	u32 y_rgb_cir_lut_idx;
	u32 uv_cir_lut_idx;
	u32 y_rgb_sep_lut_idx;
	u32 uv_sep_lut_idx;
	u32 *dir_lut;
	size_t dir_len;
	u32 *cir_lut;
	size_t cir_len;
	u32 *sep_lut;
	size_t sep_len;

	/*
	 * Detail enhancer settings
	 */
	struct sde_hw_scaler3_de_cfg de;
	uint32_t dir_weight;
	uint32_t dyn_exp_disabled;

	__u32 de_lpf_flags;
	__u32 de_lpf_h;
	__u32 de_lpf_l;
	__u32 de_lpf_m;
	struct sde_hw_cac_cfg cac_cfg;
};

struct sde_hw_scaler3_lut_cfg {
	bool is_configured;
	u32 *dir_lut;
	size_t dir_len;
	u32 *cir_lut;
	size_t cir_len;
	u32 *sep_lut;
	size_t sep_len;
};

struct sde_hw_inline_pre_downscale_cfg {
	u32 pre_downscale_x_0;
	u32 pre_downscale_x_1;
	u32 pre_downscale_y_0;
	u32 pre_downscale_y_1;
};

u32 *sde_hw_util_get_log_mask_ptr(void);

void sde_reg_write(struct sde_hw_blk_reg_map *c,
		u32 reg_off,
		u32 val,
		const char *name);
int sde_reg_read(struct sde_hw_blk_reg_map *c, u32 reg_off);

#define SDE_REG_WRITE(c, off, val) sde_reg_write(c, off, val, #off)
#define SDE_REG_READ(c, off) sde_reg_read(c, off)

#define MISR_FRAME_COUNT_MASK		0xFF
#define MISR_CTRL_ENABLE		BIT(8)
#define MISR_CTRL_STATUS		BIT(9)
#define MISR_CTRL_STATUS_CLEAR		BIT(10)
#define INTF_MISR_CTRL_FREE_RUN_MASK	BIT(31)
#define INTF_MISR_CTRL_INPUT_SEL_DATA   BIT(24)

void *sde_hw_util_get_dir(void);

void sde_init_scaler_blk(struct sde_scaler_blk *blk, u32 version);

void sde_set_scaler_v2(struct sde_hw_scaler3_cfg *cfg,
		const struct sde_drm_scaler_v2 *scale_v2);

void sde_hw_setup_scaler3(struct sde_hw_blk_reg_map *c,
		struct sde_hw_scaler3_cfg *scaler3_cfg, u32 scaler_version,
		u32 scaler_offset, const struct sde_format *format, bool de_lpf);

void sde_hw_setup_scaler_cac(struct sde_hw_blk_reg_map *c,
	u32 sspp_blk_off, struct sde_hw_cac_cfg *cac_cfg);

void sde_hw_csc_matrix_coeff_setup(struct sde_hw_blk_reg_map *c,
		u32 csc_reg_off, struct sde_csc_cfg *data,
		u32 shift_bit);

void sde_hw_csc_setup(struct sde_hw_blk_reg_map  *c,
		u32 csc_reg_off,
		struct sde_csc_cfg *data, bool csc10);

uint32_t sde_copy_formats(
		struct sde_format_extended *dst_list,
		uint32_t dst_list_size,
		uint32_t dst_list_pos,
		const struct sde_format_extended *src_list,
		uint32_t src_list_size);

/**
 * struct sde_qtimer - qtimer
 * @qtimer_cb: qtimer function pointer
 * @qtimer_mmio: qtimer memory-mapped I/O
 * @time_in_ns: time inverval for qtimer function callback
 */
struct sde_qtimer {
	irqreturn_t (*qtimer_cb)(int irq, void *arg);
	void __iomem *qtimer_mmio;
	unsigned long time_in_ns;
};

/**
 * sde_qtimer_start - (re)start a qtimer
 * sde_qtimer -  basic qtimer structure, which stores
 *               qtimer handle, expiry time and qtimer mmio
 */
void sde_qtimer_start(struct sde_qtimer *sde_qtimer);

/**
 * sde_qtimer_stop - stop a qtimer
 * sde_qtimer -  basic qtimer structure, which stores
 *               qtimer handle, expiry time and qtimer mmio
 */
void sde_qtimer_stop(struct sde_qtimer *sde_qtimer);

/**
 * sde_gpio_toggle - Toggle GPIO
 * gpio_mmio - ioremap of tlmm gpio
 */
void sde_gpio_toggle(void __iomem *gpio_mmio);

static inline bool is_qseed3_rev_qseed3lite(struct sde_mdss_cfg *sde_cfg)
{
	return ((sde_cfg->qseed_sw_lib_rev == SDE_SSPP_SCALER_QSEED3LITE) ?
			true : false);
}
#endif /* _SDE_HW_UTIL_H */
