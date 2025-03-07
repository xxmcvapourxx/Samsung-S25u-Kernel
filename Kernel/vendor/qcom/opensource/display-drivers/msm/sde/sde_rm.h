/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022-2023 Qualcomm Innovation Center, Inc. All rights reserved.
 * Copyright (c) 2016-2021, The Linux Foundation. All rights reserved.
 */

#ifndef __SDE_RM_H__
#define __SDE_RM_H__

#include <linux/list.h>

#include "msm_kms.h"
#include "sde_hw_top.h"

#define SINGLE_CTL	1
#define DUAL_CTL	2

#define TOPOLOGY_SINGLEPIPE_MODE(x) \
	(x == SDE_RM_TOPOLOGY_SINGLEPIPE ||\
		x == SDE_RM_TOPOLOGY_SINGLEPIPE_DSC ||\
		x == SDE_RM_TOPOLOGY_SINGLEPIPE_VDC)

#define TOPOLOGY_DUALPIPE_MODE(x) \
	(x == SDE_RM_TOPOLOGY_DUALPIPE ||\
		x == SDE_RM_TOPOLOGY_DUALPIPE_DSC ||\
		x == SDE_RM_TOPOLOGY_DUALPIPE_DSCMERGE ||\
		x == SDE_RM_TOPOLOGY_DUALPIPE_3DMERGE ||\
		x == SDE_RM_TOPOLOGY_DUALPIPE_3DMERGE_VDC ||\
		x == SDE_RM_TOPOLOGY_DUALPIPE_3DMERGE_DSC)

#define TOPOLOGY_QUADPIPE_MODE(x) \
	(x == SDE_RM_TOPOLOGY_QUADPIPE_3DMERGE ||\
		x == SDE_RM_TOPOLOGY_QUADPIPE_3DMERGE_DSC ||\
		x == SDE_RM_TOPOLOGY_QUADPIPE_DSCMERGE ||\
		x == SDE_RM_TOPOLOGY_QUADPIPE_DSC4HSMERGE)

#define TOPOLOGY_DSC_MODE(x) \
	(x == SDE_RM_TOPOLOGY_SINGLEPIPE_DSC ||\
		x == SDE_RM_TOPOLOGY_DUALPIPE_DSC ||\
		x == SDE_RM_TOPOLOGY_DUALPIPE_3DMERGE_DSC ||\
		x == SDE_RM_TOPOLOGY_DUALPIPE_DSCMERGE ||\
		x == SDE_RM_TOPOLOGY_QUADPIPE_3DMERGE_DSC ||\
		x == SDE_RM_TOPOLOGY_QUADPIPE_DSCMERGE ||\
		x == SDE_RM_TOPOLOGY_QUADPIPE_DSC4HSMERGE)
/**
 * enum sde_rm_topology_name - HW resource use case in use by connector
 * @SDE_RM_TOPOLOGY_NONE:                 No topology in use currently
 * @SDE_RM_TOPOLOGY_SINGLEPIPE:           1 LM, 1 PP, 1 INTF/WB
 * @SDE_RM_TOPOLOGY_SINGLEPIPE_DSC:       1 LM, 1 DSC, 1 PP, 1 INTF/WB
 * @SDE_RM_TOPOLOGY_SINGLEPIPE_VDC:       1 LM, 1 VDC, 1 PP, 1 INTF/WB
 * @SDE_RM_TOPOLOGY_DUALPIPE:             2 LM, 2 PP, 2 INTF/WB
 * @SDE_RM_TOPOLOGY_DUALPIPE_DSC:         2 LM, 2 DSC, 2 PP, 2 INTF/WB
 * @SDE_RM_TOPOLOGY_DUALPIPE_3DMERGE:     2 LM, 2 PP, 3DMux, 1 INTF/WB
 * @SDE_RM_TOPOLOGY_DUALPIPE_3DMERGE_DSC: 2 LM, 2 PP, 3DMux, 1 DSC, 1 INTF/WB
 * @SDE_RM_TOPOLOGY_DUALPIPE_3DMERGE_VDC: 2 LM, 2 PP, 3DMux, 1 VDC, 1 INTF/WB
 * @SDE_RM_TOPOLOGY_DUALPIPE_DSCMERGE:    2 LM, 2 PP, 2 DSC Merge, 1 INTF/WB
 * @SDE_RM_TOPOLOGY_PPSPLIT:              1 LM, 2 PPs, 2 INTF/WB
 * @SDE_RM_TOPOLOGY_QUADPIPE_3DMERGE      4 LM, 4 PP, 3DMux, 2 INTF
 * @SDE_RM_TOPOLOGY_QUADPIPE_3DMERGE_DSC  4 LM, 4 PP, 3DMux, 3 DSC, 2 INTF
 * @SDE_RM_TOPOLOGY_QUADPIPE_DSCMERE      4 LM, 4 PP, 4 DSC Merge, 2 INTF
 * @SDE_RM_TOPOLOGY_QUADPIPE_DSC4HSMERGE  4 LM, 4 PP, 4 DSC Merge, 1 INTF
 */
enum sde_rm_topology_name {
	SDE_RM_TOPOLOGY_NONE = 0,
	SDE_RM_TOPOLOGY_SINGLEPIPE,
	SDE_RM_TOPOLOGY_SINGLEPIPE_DSC,
	SDE_RM_TOPOLOGY_SINGLEPIPE_VDC,
	SDE_RM_TOPOLOGY_DUALPIPE,
	SDE_RM_TOPOLOGY_DUALPIPE_DSC,
	SDE_RM_TOPOLOGY_DUALPIPE_3DMERGE,
	SDE_RM_TOPOLOGY_DUALPIPE_3DMERGE_DSC,
	SDE_RM_TOPOLOGY_DUALPIPE_3DMERGE_VDC,
	SDE_RM_TOPOLOGY_DUALPIPE_DSCMERGE,
	SDE_RM_TOPOLOGY_PPSPLIT,
	SDE_RM_TOPOLOGY_QUADPIPE_3DMERGE,
	SDE_RM_TOPOLOGY_QUADPIPE_3DMERGE_DSC,
	SDE_RM_TOPOLOGY_QUADPIPE_DSCMERGE,
	SDE_RM_TOPOLOGY_QUADPIPE_DSC4HSMERGE,
	SDE_RM_TOPOLOGY_MAX,
};

/**
 * enum sde_rm_topology_group - Topology group selection
 * @SDE_RM_TOPOLOGY_GROUP_NONE:        No topology group in use currently
 * @SDE_RM_TOPOLOGY_GROUP_SINGLEPIPE:  Any topology that uses 1 LM
 * @SDE_RM_TOPOLOGY_GROUP_DUALPIPE:    Any topology that uses 2 LM
 * @SDE_RM_TOPOLOGY_GROUP_QUADPIPE:    Any topology that uses 4 LM
 * @SDE_RM_TOPOLOGY_GROUP_3DMERGE:     Any topology that uses 3D merge only
 * @SDE_RM_TOPOLOGY_GROUP_3DMERGE_DSC: Any topology that uses 3D merge + DSC
 * @SDE_RM_TOPOLOGY_GROUP_DSCMERGE:    Any topology that uses DSC merge
 */
enum sde_rm_topology_group {
	SDE_RM_TOPOLOGY_GROUP_NONE = 0,
	SDE_RM_TOPOLOGY_GROUP_SINGLEPIPE,
	SDE_RM_TOPOLOGY_GROUP_DUALPIPE,
	SDE_RM_TOPOLOGY_GROUP_QUADPIPE,
	SDE_RM_TOPOLOGY_GROUP_3DMERGE,
	SDE_RM_TOPOLOGY_GROUP_3DMERGE_DSC,
	SDE_RM_TOPOLOGY_GROUP_DSCMERGE,
	SDE_RM_TOPOLOGY_GROUP_MAX,
};

/**
 * enum sde_rm_topology_control - HW resource use case in use by connector
 * @SDE_RM_TOPCTL_RESERVE_LOCK: If set, in AtomicTest phase, after a successful
 *                              test, reserve the resources for this display.
 *                              Normal behavior would not impact the reservation
 *                              list during the AtomicTest phase.
 * @SDE_RM_TOPCTL_RESERVE_CLEAR: If set, in AtomicTest phase, before testing,
 *                               release any reservation held by this display.
 *                               Normal behavior would not impact the
 *                               reservation list during the AtomicTest phase.
 * @SDE_RM_TOPCTL_DSPP: Require layer mixers with DSPP capabilities
 * @SDE_RM_TOPCTL_DS  : Require layer mixers with DS capabilities
 * @SDE_RM_TOPCTL_CWB  : Require layer mixers with CWB capabilities
 * @SDE_RM_TOPCTL_DCWB : Require layer mixers with DCWB capabilities
 * @SDE_RM_TOPCTL_DNSC_BLUR : Require writeback with downscale blur capabilities
 * @SDE_RM_TOPCTL_CDM : Require writeback with CDM capabilities
 */
enum sde_rm_topology_control {
	SDE_RM_TOPCTL_RESERVE_LOCK,
	SDE_RM_TOPCTL_RESERVE_CLEAR,
	SDE_RM_TOPCTL_DSPP,
	SDE_RM_TOPCTL_DS,
	SDE_RM_TOPCTL_CWB,
	SDE_RM_TOPCTL_DCWB,
	SDE_RM_TOPCTL_DNSC_BLUR,
	SDE_RM_TOPCTL_CDM,
};

/**
 * enum sde_rm_topology_control - HW resource use case in use by connector
 * @SDE_RM_QSYNC_DISABLED: If set, Qsync feature is supported and in
 *                              disable state.
 * @SDE_RM_QSYNC_CONTINUOUS_MODE: If set, Qsync is enabled in continuous
 *                              mode.
 * @SDE_RM_QSYNC_ONE_SHOT_MODE: If set, Qsync is enabled in one shot mode.
 *
 */
enum sde_rm_qsync_modes {
	SDE_RM_QSYNC_DISABLED,
	SDE_RM_QSYNC_CONTINUOUS_MODE,
	SDE_RM_QSYNC_ONE_SHOT_MODE
};

/**
 * struct sde_rm_topology_def - Topology table definition
 * @top_name: name identifying this topology
 * @num_lm:   number of layer mixers used
 * @num_comp_enc: number of encoders used
 * @num_intf: number of interface used
 * @num_ctl: number of control path used
 * @needs_split_display: If set split display is enabled
 * @comp_type: type of compression supported
 */
struct sde_rm_topology_def {
	enum sde_rm_topology_name top_name;
	int num_lm;
	int num_comp_enc;
	int num_intf;
	int num_ctl;
	bool needs_split_display;
	enum msm_display_compression_type comp_type;
};

/**
 * struct sde_rm - SDE dynamic hardware resource manager
 * @dev: device handle for event logging purposes
 * @rsvps: list of hardware reservations by each crtc->encoder->connector
 * @hw_blks: array of lists of hardware resources present in the system, one
 *	list per type of hardware block
 * @hw_mdp: hardware object for mdp_top
 * @lm_max_width: cached layer mixer maximum width
 * @rsvp_next_seq: sequence number for next reservation for debugging purposes
 * @rm_lock: resource manager mutex
 * @avail_res: Pointer with curr available resources
 */
struct sde_rm {
	struct drm_device *dev;
	struct list_head rsvps;
	struct list_head hw_blks[SDE_HW_BLK_MAX];
	struct sde_hw_mdp *hw_mdp;
	uint32_t lm_max_width;
	uint32_t rsvp_next_seq;
	struct mutex rm_lock;
	const struct sde_rm_topology_def *topology_tbl;
	struct msm_resource_caps_info avail_res;
};

/**
 *  struct sde_rm_hw_blk - resource manager internal structure
 *	forward declaration for single iterator definition without void pointer
 */
struct sde_rm_hw_blk;

/**
 * struct sde_rm_hw_iter - iterator for use with sde_rm
 * @hw: sde_hw object requested, or NULL on failure
 * @blk: sde_rm internal block representation. Clients ignore. Used as iterator.
 * @enc_id: DRM ID of Encoder client wishes to search for, or 0 for Any Encoder
 * @type: Hardware Block Type client wishes to search for.
 */
struct sde_rm_hw_iter {
	struct sde_hw_blk_reg_map *hw;
	struct sde_rm_hw_blk *blk;
	uint32_t enc_id;
	enum sde_hw_blk_type type;
};

/**
 * struct sde_rm_hw_request - data for requesting hw blk
 * @hw: sde_hw object requested, or NULL on failure
 * @type: Hardware Block Type client wishes to search for
 * @id: Hardware block id
 */
struct sde_rm_hw_request {
	struct sde_hw_blk_reg_map *hw;
	enum sde_hw_blk_type type;
	int id;
};

/**
 * sde_rm_get_topology_name - get the name of the given topology config
 * @rm: SDE resource manager handle
 * @topology: msm_display_topology topology config
 * @Return: name of the given topology
 */
enum sde_rm_topology_name sde_rm_get_topology_name(struct sde_rm *rm,
		struct msm_display_topology topology);

/**
 * sde_rm_debugfs_init - setup debugfs node for rm module
 * @rm: SDE resource manager handle
 * @parent: debugfs parent directory node
 */
void sde_rm_debugfs_init(struct sde_rm *rm, struct dentry *parent);

/**
 * sde_rm_init - Read hardware catalog and create reservation tracking objects
 *	for all HW blocks.
 * @rm: SDE Resource Manager handle
 * @Return: 0 on Success otherwise -ERROR
 */
int sde_rm_init(struct sde_rm *rm);

/**
 * sde_rm_destroy - Free all memory allocated by sde_rm_init
 * @rm: SDE Resource Manager handle
 * @Return: 0 on Success otherwise -ERROR
 */
int sde_rm_destroy(struct sde_rm *rm);

/**
 * sde_rm_reserve - Given a CRTC->Encoder->Connector display chain, analyze
 *	the use connections and user requirements, specified through related
 *	topology control properties, and reserve hardware blocks to that
 *	display chain.
 *	HW blocks can then be accessed through sde_rm_get_* functions.
 *	HW Reservations should be released via sde_rm_release_hw.
 * @rm: SDE Resource Manager handle
 * @drm_enc: DRM Encoder handle
 * @crtc_state: Proposed Atomic DRM CRTC State handle
 * @conn_state: Proposed Atomic DRM Connector State handle
 * @test_only: Atomic-Test phase, discard results (unless property overrides)
 * @Return: 0 on Success otherwise -ERROR
 */
int sde_rm_reserve(struct sde_rm *rm,
		struct drm_encoder *drm_enc,
		struct drm_crtc_state *crtc_state,
		struct drm_connector_state *conn_state,
		bool test_only);

/**
 * sde_rm_release - Given the encoder for the display chain, release any
 *	HW blocks previously reserved for that use case.
 * @rm: SDE Resource Manager handle
 * @enc: DRM Encoder handle
 * @nxt: Choose option to release rsvp_nxt
 * @Return: 0 on Success otherwise -ERROR
 */
void sde_rm_release(struct sde_rm *rm, struct drm_encoder *enc, bool nxt);

/**
 * sde_rm_get_mdp - Retrieve HW block for MDP TOP.
 *	This is never reserved, and is usable by any display.
 * @rm: SDE Resource Manager handle
 * @Return: Pointer to hw block or NULL
 */
struct sde_hw_mdp *sde_rm_get_mdp(struct sde_rm *rm);

/**
 * sde_rm_init_hw_iter - setup given iterator for new iteration over hw list
 *	using sde_rm_get_hw
 * @iter: iter object to initialize
 * @enc_id: DRM ID of Encoder client wishes to search for, or 0 for Any Encoder
 * @type: Hardware Block Type client wishes to search for.
 */
void sde_rm_init_hw_iter(
		struct sde_rm_hw_iter *iter,
		uint32_t enc_id,
		enum sde_hw_blk_type type);
/**
 * sde_rm_get_hw - retrieve reserved hw object given encoder and hw type
 *	Meant to do a single pass through the hardware list to iteratively
 *	retrieve hardware blocks of a given type for a given encoder.
 *	Initialize an iterator object.
 *	Set hw block type of interest. Set encoder id of interest, 0 for any.
 *	Function returns first hw of type for that encoder.
 *	Subsequent calls will return the next reserved hw of that type in-order.
 *	Iterator HW pointer will be null on failure to find hw.
 * @rm: SDE Resource Manager handle
 * @iter: iterator object
 * @Return: true on match found, false on no match found
 */
bool sde_rm_get_hw(struct sde_rm *rm, struct sde_rm_hw_iter *iter);

/**
 * sde_rm_request_hw_blk - retrieve the requested hardware block
 * @rm: SDE Resource Manager handle
 * @hw: holds the input and output information of the requested hw block
 * @Return: true on match found, false on no match found
 */
bool sde_rm_request_hw_blk(struct sde_rm *rm, struct sde_rm_hw_request *hw);

/**
 * sde_rm_cont_splash_res_init - Read the current MDSS configuration
 *	to update the splash data structure with the topology
 *	configured by the bootloader.
 * @priv: DRM private structure handle
 * @rm: SDE Resource Manager handle
 * @splash_data: Pointer to the splash_data structure to be updated.
 * @cat: Pointer to the SDE catalog
 * @Return: 0 on success or error
 */
int sde_rm_cont_splash_res_init(struct msm_drm_private *priv,
				struct sde_rm *rm,
				struct sde_splash_data *splash_data,
				struct sde_mdss_cfg *cat);

/**
 * sde_rm_update_topology - sets topology property of the connector
 * @rm: SDE resource manager handle
 * @conn_state: drm state of the connector
 * @topology: topology selected for the display
 * @return: 0 on success or error
 */
int sde_rm_update_topology(struct sde_rm *rm,
	struct drm_connector_state *conn_state,
	struct msm_display_topology *topology);

/**
 * sde_rm_topology_get_topology_def - returns the information about num
 *	of hw blocks used in this topology
 * @rm: SDE Resource Manager handle
 * @topology: topology selected for the display
 * @return: pointer to struct containing topology definition
 */
static inline const struct sde_rm_topology_def*
	sde_rm_topology_get_topology_def(
		struct sde_rm *rm,
		enum sde_rm_topology_name topology)
{
	if ((!rm) || (topology <= SDE_RM_TOPOLOGY_NONE) ||
			(topology >= SDE_RM_TOPOLOGY_MAX)) {
		pr_err("invalid arguments: rm:%d topology:%d\n",
				rm == NULL, topology);

		return ERR_PTR(-EINVAL);
	}

	return &rm->topology_tbl[topology];
}

/**
 * sde_rm_topology_get_num_lm - returns number of mixers
 * used for this topology
 * @rm: SDE Resource Manager handle
 * @topology: topology selected for the display
 * @return: number of lms
 */
static inline int sde_rm_topology_get_num_lm(struct sde_rm *rm,
		enum sde_rm_topology_name topology)
{
	if ((!rm) || (topology <= SDE_RM_TOPOLOGY_NONE) ||
			(topology >= SDE_RM_TOPOLOGY_MAX)) {
		pr_err("invalid arguments: rm:%d topology:%d\n",
				rm == NULL, topology);

		return -EINVAL;
	}

	return rm->topology_tbl[topology].num_lm;
}

/**
 * sde_rm_topology_is_group - check if the topology in use
 *	is part of the requested group
 * @rm: SDE Resource Manager handle
 * @state: drm state of the crtc
 * @group: topology group to check
 * @return: true if attached connector is in the topology group
 */
bool sde_rm_topology_is_group(struct sde_rm *rm,
		struct drm_crtc_state *state,
		enum sde_rm_topology_group group);

/**
 * sde_rm_get_resource_info - returns avail hw resource info
 * @mr: sde rm object
 * @drm_enc: drm encoder object
 * @avail_res: out parameter, available resource object
 */
void sde_rm_get_resource_info(struct sde_rm *rm,
		struct drm_encoder *drm_enc,
		struct msm_resource_caps_info *avail_res);

/**
 * sde_rm_ext_blk_create_reserve - Create external HW blocks
 *	in resource manager and reserve for specific encoder.
 * @rm: SDE Resource Manager handle
 * @hw_rm: external HW block
 * @enc: DRM Encoder handle
 * @pp_shd_hw: Pointer to hardware block register map object
 * @Return: 0 on Success otherwise -ERROR
 */
int sde_rm_ext_blk_create_reserve(struct sde_rm *rm,
				  struct sde_rm_hw_blk *hw_rm, struct drm_encoder *enc,
				  struct sde_hw_blk_reg_map *pp_shd_hw);

/**
 * sde_rm_ext_blk_create_reserve - Create external HW blocks
 *	in resource manager and reserve for specific encoder.
 * @rm: SDE Resource Manager handle
 * @hw: external HW block
 * @enc: DRM Encoder handle
 * @sde_hw_ctl: ctl SHD ops updated HW block
 * @Return: 0 on Success otherwise -ERROR
 */
int sde_rm_ext_blk_create_reserve_ctl(struct sde_rm *rm,
				      struct sde_rm_hw_blk *hw, struct drm_encoder *enc,
				      struct sde_hw_ctl *sde_hw_ctl);

/**
 * sde_rm_ext_blk_create_reserve - Create external HW blocks
 *	in resource manager and reserve for specific encoder.
 * @rm: SDE Resource Manager handle
 * @hw: external HW block
 * @enc: DRM Encoder handle
 * @sde_hw_lm: lm SHD ops updated HW block
 * @Return: 0 on Success otherwise -ERROR
 */
int sde_rm_ext_blk_create_reserve_lm(struct sde_rm *rm,
				     struct sde_rm_hw_blk *hw, struct drm_encoder *enc,
				     struct sde_hw_mixer *sde_hw_lm);
#endif /* __SDE_RM_H__ */
