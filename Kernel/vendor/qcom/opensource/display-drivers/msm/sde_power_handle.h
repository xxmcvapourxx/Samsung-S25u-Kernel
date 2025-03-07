/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023-2024 Qualcomm Innovation Center, Inc. All rights reserved.
 * Copyright (c) 2016-2021, The Linux Foundation. All rights reserved.
 */

#ifndef _SDE_POWER_HANDLE_H_
#define _SDE_POWER_HANDLE_H_

#define MAX_CLIENT_NAME_LEN 128

#define SDE_POWER_HANDLE_ENABLE_BUS_AB_QUOTA	0
#define SDE_POWER_HANDLE_DISABLE_BUS_AB_QUOTA	0
#define SDE_POWER_HANDLE_ENABLE_BUS_IB_QUOTA		400000000
#define SDE_POWER_HANDLE_ENABLE_NRT_BUS_IB_QUOTA	0
#define SDE_POWER_HANDLE_DISABLE_BUS_IB_QUOTA	0

#define SDE_POWER_HANDLE_CONT_SPLASH_BUS_IB_QUOTA	3000000000ULL
#define SDE_POWER_HANDLE_CONT_SPLASH_BUS_AB_QUOTA	3000000000ULL

#include <linux/sde_io_util.h>
#include <linux/interconnect.h>
#include <dt-bindings/interconnect/qcom,icc.h>

/* event will be triggered before power handler disable */
#define SDE_POWER_EVENT_PRE_DISABLE	0x1

/* event will be triggered after power handler disable */
#define SDE_POWER_EVENT_POST_DISABLE	0x2

/* event will be triggered before power handler enable */
#define SDE_POWER_EVENT_PRE_ENABLE	0x4

/* event will be triggered after power handler enable */
#define SDE_POWER_EVENT_POST_ENABLE	0x8

/* event will be triggered during MMRM callback */
#define SDE_POWER_EVENT_MMRM_CALLBACK	0x10

#define DATA_BUS_PATH_MAX	0x2

/**
 * mdss_bus_vote_type: register bus vote type
 * VOTE_INDEX_DISABLE: removes the client vote
 * VOTE_INDEX_LOW: keeps the lowest vote for register bus
 * VOTE_INDEX_MEDIUM: keeps medium vote for register bus
 * VOTE_INDEX_HIGH: keeps the highest vote for register bus
 * VOTE_INDEX_MAX: invalid
 */
enum mdss_bus_vote_type {
	VOTE_INDEX_DISABLE,
	VOTE_INDEX_LOW,
	VOTE_INDEX_MEDIUM,
	VOTE_INDEX_HIGH,
	VOTE_INDEX_MAX,
};

/**
 * enum sde_power_handle_data_bus_client - type of axi bus clients
 * @SDE_POWER_HANDLE_DATA_BUS_CLIENT_RT: core real-time bus client
 * @SDE_POWER_HANDLE_DATA_BUS_CLIENT_NRT: core non-real-time bus client
 * @SDE_POWER_HANDLE_DATA_BUS_CLIENT_MAX: maximum number of bus client type
 */
enum sde_power_handle_data_bus_client {
	SDE_POWER_HANDLE_DATA_BUS_CLIENT_RT,
	SDE_POWER_HANDLE_DATA_BUS_CLIENT_NRT,
	SDE_POWER_HANDLE_DATA_BUS_CLIENT_MAX
};

/**
 * enum SDE_POWER_HANDLE_DBUS_ID - data bus identifier
 * @SDE_POWER_HANDLE_DBUS_ID_MNOC: DPU/MNOC data bus
 * @SDE_POWER_HANDLE_DBUS_ID_LLCC: MNOC/LLCC data bus
 * @SDE_POWER_HANDLE_DBUS_ID_EBI: LLCC/EBI data bus
 * @SDE_POWER_HANDLE_DBUS_ID_DDR_RT: DDR RT data bus
 */
enum SDE_POWER_HANDLE_DBUS_ID {
	SDE_POWER_HANDLE_DBUS_ID_MNOC,
	SDE_POWER_HANDLE_DBUS_ID_LLCC,
	SDE_POWER_HANDLE_DBUS_ID_EBI,
	SDE_POWER_HANDLE_DBUS_ID_DDR_RT,
	SDE_POWER_HANDLE_DBUS_ID_MAX,
};

/**
 * struct sde_power_bus_scaling_data: struct for bus setting
 * @ab: average bandwidth in bytes per second
 * @ib: peak bandwidth in bytes per second
 */
struct sde_power_bus_scaling_data {
	uint64_t ab; /* Arbitrated bandwidth */
	uint64_t ib; /* Instantaneous bandwidth */
};

/**
 * struct sde_power_data_handle: power handle struct for data bus
 * @data_bus_hdl: current data bus handle
 * @curr_val : save the current bus value
 * @data_paths_cnt: number of rt data path ports
 */
struct sde_power_data_bus_handle {
	struct icc_path *data_bus_hdl[DATA_BUS_PATH_MAX];
	struct sde_power_bus_scaling_data curr_val;
	u32 data_paths_cnt;
	bool bus_active_only;
#if IS_ENABLED(CONFIG_DISPLAY_SAMSUNG)
	u64 in_ab_quota;
	u64 in_ib_quota;
#endif
};

/**
 * struct sde_power_reg_bus_handle: power handle struct for reg bus
 * @reg_bus_hdl: reg bus interconnect path handle
 * @curr_idx : use-case index in to scale_table for the current vote
 * @scale_table: bus scaling bandwidth vote table
 */
struct sde_power_reg_bus_handle {
	struct icc_path *reg_bus_hdl;
	enum mdss_bus_vote_type curr_idx;
	struct sde_power_bus_scaling_data scale_table[VOTE_INDEX_MAX];
};

/*
 * struct sde_power_event - local event registration structure
 * @client_name: name of the client registering
 * @cb_fnc: pointer to desired callback function
 * @usr: user pointer to pass to callback event trigger
 * @event: refer to SDE_POWER_HANDLE_EVENT_*
 * @list: list to attach event master list
 * @active: indicates the state of sde power handle
 */
struct sde_power_event {
	char client_name[MAX_CLIENT_NAME_LEN];
	void (*cb_fnc)(u32 event_type, void *usr);
	void *usr;
	u32 event_type;
	struct list_head list;
	bool active;
};

/*
 * struct sde_power_mmrm_reserve - mmrm resource reservation for clk and bw
 * @clk_name: name of resource reservation clock
 * @clk_rate: resource reservation clock rate
 */
struct sde_power_mmrm_reserve {
	char clk_name[32];
	u64 clk_rate;
};

/**
 * struct sde_power_handle: power handle main struct
 * @mp:		module power for clock and regulator
 * @phandle_lock: lock to synchronize the enable/disable
 * @dev: pointer to device structure
 * @reg_bus_handle: context structure for reg bus control
 * @data_bus_handle: context structure for data bus control
 * @event_list: current power handle event list
 * @rsc_client: sde rsc client pointer
 * @rsc_client_init: boolean to control rsc client create
 * @mmrm_enable: boolean to indicate if mmrm is enabled
 * @ib_quota: ib quota of the given bus
 * @hw_fence_enable: boolean to indicate if hw-fence is enabled
 * @mmrm_reserve: mmrm resource reservation
 * @wakelock_count: wakelock coint to avoid pm suspend
 */
struct sde_power_handle {
	struct dss_module_power mp;
	struct mutex phandle_lock;
	struct device *dev;
	struct sde_power_reg_bus_handle reg_bus_handle;
	struct sde_power_data_bus_handle data_bus_handle
		[SDE_POWER_HANDLE_DBUS_ID_MAX];
	struct list_head event_list;
	u32 last_event_handled;
	struct sde_rsc_client *rsc_client;
	bool rsc_client_init;
	bool mmrm_enable;
	u64 ib_quota[SDE_POWER_HANDLE_DBUS_ID_MAX];
	bool hw_fence_enable;

	struct sde_power_mmrm_reserve mmrm_reserve;
	atomic_t wakelock_count;
};

/**
 * sde_power_resource_init() - initializes the sde power handle
 * @pdev:   platform device to search the power resources
 * @pdata:  power handle to store the power resources
 *
 * Return: error code.
 */
int sde_power_resource_init(struct platform_device *pdev,
	struct sde_power_handle *pdata);

/**
 * sde_power_resource_deinit() - release the sde power handle
 * @pdev:   platform device for power resources
 * @pdata:  power handle containing the resources
 *
 * Return: error code.
 */
void sde_power_resource_deinit(struct platform_device *pdev,
	struct sde_power_handle *pdata);

/**
 * sde_power_resource_enable() - enable/disable the power resources
 * @pdata:  power handle containing the resources
 * @enable: boolean request for enable/disable
 * @dev_idx: device index for the drm device
 *
 * Return: error code.
 */
int sde_power_resource_enable(struct sde_power_handle *pdata, bool enable, int dev_idx);

/**
 * sde_power_scale_reg_bus() - Scale the registers bus for the specified client
 * @phandle:  power handle containing the resources
 * @usecase_ndx: new use case to scale the reg bus
 * @skip_lock: will skip holding the power rsrc mutex during the call, this is
 *		for internal callers that already hold this required lock.
 *
 * Return: error code.
 */
int sde_power_scale_reg_bus(struct sde_power_handle *phandle,
	u32 usecase_ndx, bool skip_lock);

/**
 * sde_power_data_bus_state_update() - update data bus state
 * @pdata:  power handle containing the resources
 * @enable: take enable vs disable path
 *
 * Return: error code.
 */
int sde_power_data_bus_state_update(struct sde_power_handle *phandle,
							bool enable);

/**
 * sde_power_clk_reserve_rate() - reserve the clock rate with mmrm
 * @pdata:  power handle containing the resources
 * @clock_name: clock name which needs rate update.
 * @rate:       Requested rate.
 *
 * Return: error code.
 */
int sde_power_clk_reserve_rate(struct sde_power_handle *pdata, char *clock_name, u64 rate);

/**
 * sde_power_clk_set_rate() - set the clock rate
 * @pdata:  power handle containing the resources
 * @clock_name: clock name which needs rate update.
 * @rate:       Requested rate.
 * @flags:      Flags to be set for this clk
 *
 * Return: error code.
 */
int sde_power_clk_set_rate(struct sde_power_handle *pdata, char *clock_name,
	u64 rate, u32 flags);

/**
 * sde_power_mmrm_set_clk_limit() - sets a limit for mdp core clk
 * @clk: pointer to the mdp core clk
 * @phandle: power handle containing the resources
 * @requested_clk: limit requested for the core clk
 *
 * This function must be called in a thread different than the
 * commit-thread, otherwise it will always fail, since this function
 * sends a notification to user-space to reduce the clk, and then it
 * waits for the next commit after this call to reduce the clk rate.
 * Hence, if the commit-thread is blocked (by this function waiting)
 * or if user-space does not send another commit to reduce the clk,
 * this function will timeout after some time and fail.
 *
 * Return: 0 upon succeeding setting the clk to a value lower or
 *  equal than the 'requested_clk', otherwise it returns an
 *  error code.
 */
int sde_power_mmrm_set_clk_limit(struct dss_clk *clk,
	struct sde_power_handle *phandle, unsigned long requested_clk);

/**
 * sde_power_mmrm_get_requested_clk() - get clk rate requested by mmrm
 * @pdata:  power handle containing the resources
 * @clock_name: clock name to get the rate requested by mmrm driver
 *   to decrease
 *
 * Return: clock rate requested by mmrm driver, if 0,
 *   then no active request by mmrm driver
 */
u64 sde_power_mmrm_get_requested_clk(struct sde_power_handle *pdata,
	char *clock_name);

/**
 * sde_power_clk_get_rate() - get the clock rate
 * @pdata:  power handle containing the resources
 * @clock_name: clock name to get the rate
 *
 * Return: current clock rate
 */
u64 sde_power_clk_get_rate(struct sde_power_handle *pdata, char *clock_name);

/**
 * sde_power_clk_get_max_rate() - get the maximum clock rate
 * @pdata:  power handle containing the resources
 * @clock_name: clock name to get the max rate.
 *
 * Return: maximum clock rate or 0 if not found.
 */
u64 sde_power_clk_get_max_rate(struct sde_power_handle *pdata,
		char *clock_name);

/**
 * sde_power_clk_get_clk() - get the clock
 * @pdata:  power handle containing the resources
 * @clock_name: clock name to get the clk pointer.
 *
 * Return: Pointer to clock
 */
struct clk *sde_power_clk_get_clk(struct sde_power_handle *phandle,
		char *clock_name);

/**
 * sde_power_data_bus_set_quota() - set data bus quota for power client
 * @phandle:  power handle containing the resources
 * @bus_id: identifier of data bus, see SDE_POWER_HANDLE_DBUS_ID
 * @ab_quota: arbitrated bus bandwidth
 * @ib_quota: instantaneous bus bandwidth
 *
 * Return: zero if success, or error code otherwise
 */
int sde_power_data_bus_set_quota(struct sde_power_handle *phandle,
	u32 bus_id, u64 ab_quota, u64 ib_quota);

/**
 * sde_power_data_bus_bandwidth_ctrl() - control data bus bandwidth enable
 * @phandle:  power handle containing the resources
 * @enable: true to enable bandwidth for data base
 *
 * Return: none
 */
void sde_power_data_bus_bandwidth_ctrl(struct sde_power_handle *phandle,
		int enable);

/**
 * sde_power_set_clk_retention() - enable/disable clock retention
 * @phandle:  power handle containing the resources
 * @clock_name: clock name
 * @enable: true to enable clock retention
 *
 * Return: none
 */
void sde_power_set_clk_retention(struct sde_power_handle *phandle,
		char *clock_name, bool enable);

/**
 * sde_power_handle_register_event - register a callback function for an event.
 *	Clients can register for multiple events with a single register.
 *	Any block with access to phandle can register for the event
 *	notification.
 * @phandle:	power handle containing the resources
 * @event_type:	event type to register; refer SDE_POWER_HANDLE_EVENT_*
 * @cb_fnc:	pointer to desired callback function
 * @usr:	user pointer to pass to callback on event trigger
 *
 * Return:	event pointer if success, or error code otherwise
 */
struct sde_power_event *sde_power_handle_register_event(
		struct sde_power_handle *phandle,
		u32 event_type, void (*cb_fnc)(u32 event_type, void *usr),
		void *usr, char *client_name);
/**
 * sde_power_handle_unregister_event - unregister callback for event(s)
 * @phandle:	power handle containing the resources
 * @event:	event pointer returned after power handle register
 */
void sde_power_handle_unregister_event(struct sde_power_handle *phandle,
		struct sde_power_event *event);

/**
 * sde_power_handle_get_dbus_name - get name of given data bus identifier
 * @bus_id:	data bus identifier
 * Return:	Pointer to name string if success; NULL otherwise
 */
const char *sde_power_handle_get_dbus_name(u32 bus_id);

/**
 * sde_power_mmrm_reserve - requests the mmrm supported clk reservation
 * @phandle:	pointer to power handle
 */
void sde_power_mmrm_reserve(struct sde_power_handle *phandle);

/**
 * sde_power_wakelock_ctrl - control wakelock
 * @phandle: power handle containing the resources
 * @enable: true to enable wakelock
 *
 * Return: 0 on success, error code otherwise
 */
int sde_power_wakelock_ctrl(struct sde_power_handle *phandle, bool enable);

#endif /* _SDE_POWER_HANDLE_H_ */
