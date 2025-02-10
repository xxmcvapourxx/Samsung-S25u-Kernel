// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2012-2021, The Linux Foundation. All rights reserved.
 * Copyright (c) 2022-2024 Qualcomm Innovation Center, Inc. All rights reserved.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/irq.h>
#include <linux/irqdesc.h>
#include <linux/sched.h>
#include <linux/usb/dwc3-msm.h>
#include <linux/usb/composite.h>
#include <linux/usb/android_configfs_uevent.h>
#include "core.h"
#include "debug-ipc.h"
#include "gadget.h"

#if IS_ENABLED(CONFIG_USB_NOTIFY_LAYER)
#include <linux/usb_notify.h>
#endif
#if IS_ENABLED(CONFIG_USB_CONFIGFS_F_SS_MON_GADGET)
#include <linux/usb/f_ss_mon_gadget.h>
#endif

union kprobe_data {
	struct {
		struct dwc3 *dwc;
		int xi0;
	};
	struct work_struct *data;
};

static int entry_dwc3_suspend_common(struct kretprobe_instance *ri,
				struct pt_regs *regs)
{
	struct dwc3 *dwc = (struct dwc3 *)regs->regs[0];
	int flag = 0;
	union kprobe_data *data = (union kprobe_data *)ri->data;

	if (dwc->current_dr_role == DWC3_GCTL_PRTCAP_HOST) {
		/*
		 * Storing the original values.
		 */
		if (dwc->dis_u2_susphy_quirk)
			flag |= BIT(0);
		if (dwc->dis_enblslpm_quirk)
			flag |= BIT(1);

		dev_info(dwc->dev, "saved SUSPHY=%u & ENABLSLPM=%u\n",
			dwc->dis_u2_susphy_quirk, dwc->dis_enblslpm_quirk);
		dwc->dis_u2_susphy_quirk = false;
		dwc->dis_enblslpm_quirk = false;
	}

	data->dwc = dwc;
	data->xi0 = flag;
	dev_info(dwc->dev, "dwc3 suspend common entry\n");
	return 0;
}

static int exit_dwc3_suspend_common(struct kretprobe_instance *ri,
				struct pt_regs *regs)
{
	union kprobe_data *data = (union kprobe_data *)ri->data;
	struct dwc3 *dwc = data->dwc;
	int flag = data->xi0;

	if (dwc->current_dr_role == DWC3_GCTL_PRTCAP_HOST) {
		/*
		 * Re-store the original quic values.
		 */
		if (flag & BIT(0))
			dwc->dis_u2_susphy_quirk = true;
		if (flag & BIT(1))
			dwc->dis_enblslpm_quirk = true;

		dev_info(dwc->dev, "restored SUSPHY=%u & ENABLSLPM=%u\n",
			dwc->dis_u2_susphy_quirk, dwc->dis_enblslpm_quirk);

	}

	dev_info(dwc->dev, "dwc3 suspend common exit\n");
	return 0;
}

static int entry_usb_ep_set_maxpacket_limit(struct kretprobe_instance *ri,
				struct pt_regs *regs)
{
	struct usb_ep *ep = (struct usb_ep *)regs->regs[0];
	struct dwc3_ep *dep;
	struct dwc3 *dwc;
	union kprobe_data *data = (union kprobe_data *)ri->data;

	dep =  to_dwc3_ep(ep);
	dwc = dep->dwc;

	data->dwc = dwc;
	data->xi0 = dep->number;

	return 0;
}

static int exit_usb_ep_set_maxpacket_limit(struct kretprobe_instance *ri,
				struct pt_regs *regs)
{
	union kprobe_data *data = (union kprobe_data *)ri->data;
	struct dwc3 *dwc = data->dwc;
	u8 epnum = data->xi0;
	struct dwc3_ep *dep = dwc->eps[epnum];
	struct usb_ep *ep = &dep->endpoint;

	if (epnum >= 2) {
		ep->maxpacket_limit = 1024;
		ep->maxpacket = 1024;
	}

	return 0;
}

static int entry_dwc3_gadget_run_stop(struct kretprobe_instance *ri,
				   struct pt_regs *regs)
{
#if IS_ENABLED(CONFIG_USB_CONFIGFS_F_SS_MON_GADGET)
	union kprobe_data *data = (union kprobe_data *)ri->data;
#endif
	struct dwc3 *dwc = (struct dwc3 *)regs->regs[0];
	int is_on = (int)regs->regs[1];

#if IS_ENABLED(CONFIG_USB_CONFIGFS_F_SS_MON_GADGET)
	data->dwc = dwc;
	data->xi0 = is_on;
#endif

	if (is_on) {
		/*
		 * DWC3 gadget IRQ uses a threaded handler which normally runs
		 * at SCHED_FIFO priority.  If it gets busy processing a high
		 * volume of events (usually EP events due to heavy traffic) it
		 * can potentially starve non-RT taks from running and trigger
		 * RT throttling in the scheduler; on some build configs this
		 * will panic.  So lower the thread's priority to run as non-RT
		 * (with a nice value equivalent to a high-priority workqueue).
		 * It has been found to not have noticeable performance impact.
		 */
		struct irq_desc *irq_desc = irq_to_desc(dwc->irq_gadget);
		struct irqaction *action = irq_desc ? irq_desc->action : NULL;

		dwc3_msm_notify_event(dwc, DWC3_GSI_EVT_BUF_SETUP, 0);
		for ( ; action != NULL; action = action->next) {
			if (action->thread) {
				dev_info(dwc->dev, "Set IRQ thread:%s pid:%d to SCHED_NORMAL prio\n",
					action->thread->comm, action->thread->pid);
				sched_set_normal(action->thread, MIN_NICE);
				break;
			}
		}
	} else {
		dwc3_core_stop_hw_active_transfers(dwc);
		dwc3_msm_notify_event(dwc, DWC3_GSI_EVT_BUF_CLEAR, 0);
		dwc3_msm_notify_event(dwc, DWC3_CONTROLLER_NOTIFY_CLEAR_DB, 0);
	}

	return 0;
}

#if IS_ENABLED(CONFIG_USB_CONFIGFS_F_SS_MON_GADGET)
static int exit_dwc3_gadget_run_stop(struct kretprobe_instance *ri,
				   struct pt_regs *regs)
{
	unsigned long long retval = regs_return_value(regs);
	union kprobe_data *data = (union kprobe_data *)ri->data;
	struct dwc3 *dwc = data->dwc;
	int is_on;

	is_on = data->xi0;

	vbus_session_notify(dwc->gadget, is_on, retval);

	if (retval) {
		pr_info("usb: dwc3_gadget_run_stop : dwc3_gadget %s failed (%d)\n",
			is_on ? "ON" : "OFF", (int)retval);
	}
	return 0;
}
#endif

static int entry_dwc3_send_gadget_ep_cmd(struct kretprobe_instance *ri,
				   struct pt_regs *regs)
{
	struct dwc3_ep *dep = (struct dwc3_ep *)regs->regs[0];
	unsigned int cmd = (unsigned int)regs->regs[1];
	struct dwc3 *dwc = dep->dwc;

	if (cmd == DWC3_DEPCMD_ENDTRANSFER)
		dwc3_msm_notify_event(dwc,
				DWC3_CONTROLLER_NOTIFY_DISABLE_UPDXFER,
				dep->number);

	return 0;
}

static int entry___dwc3_gadget_ep_enable(struct kretprobe_instance *ri,
				   struct pt_regs *regs)
{
	struct dwc3_ep *dep = (struct dwc3_ep *)regs->regs[0];
	unsigned int action = (unsigned int)regs->regs[1];

	/* DWC3_DEPCFG_ACTION_MODIFY is only done during CONNDONE */
	if (action == DWC3_DEPCFG_ACTION_MODIFY && dep->number == 1) {
		dwc3_msm_notify_event(dep->dwc, DWC3_CONTROLLER_CONNDONE_EVENT, 0);
#if IS_ENABLED(CONFIG_USB_NOTIFY_LAYER)
		switch (dep->dwc->speed) {
		case DWC3_DSTS_SUPERSPEED_PLUS:
			store_usblog_notify(NOTIFY_USBSTATE,
				(void *)"USB_STATE=ENUM:CONNDONE:PSS", NULL);
			break;
		case DWC3_DSTS_SUPERSPEED:
			store_usblog_notify(NOTIFY_USBSTATE,
				(void *)"USB_STATE=ENUM:CONNDONE:SS", NULL);
			break;
		case DWC3_DSTS_HIGHSPEED:
			store_usblog_notify(NOTIFY_USBSTATE,
				(void *)"USB_STATE=ENUM:CONNDONE:HS", NULL);
			break;
		case DWC3_DSTS_FULLSPEED:
			store_usblog_notify(NOTIFY_USBSTATE,
				(void *)"USB_STATE=ENUM:CONNDONE:FS", NULL);
			break;
		}
#endif
	}

	return 0;
}

static int entry_dwc3_gadget_reset_interrupt(struct kretprobe_instance *ri,
				   struct pt_regs *regs)
{
	struct dwc3 *dwc = (struct dwc3 *)regs->regs[0];

	dwc3_core_stop_hw_active_transfers(dwc);
	dwc3_msm_notify_event(dwc, DWC3_CONTROLLER_NOTIFY_CLEAR_DB, 0);
#if IS_ENABLED(CONFIG_USB_CONFIGFS_F_SS_MON_GADGET)
	usb_reset_notify(dwc->gadget);
#endif
	return 0;
}

static int entry_dwc3_gadget_pullup(struct kretprobe_instance *ri,
				   struct pt_regs *regs)
{
	union kprobe_data *data = (union kprobe_data *)ri->data;
	struct usb_gadget *g = (struct usb_gadget *)regs->regs[0];

	data->dwc = gadget_to_dwc(g);
	data->xi0 = (int)regs->regs[1];
	dwc3_msm_notify_event(data->dwc, DWC3_CONTROLLER_PULLUP_ENTER,
				data->xi0);

	/* Only write PID to IMEM if pullup is being enabled */
	if (data->xi0)
		dwc3_msm_notify_event(data->dwc, DWC3_IMEM_UPDATE_PID, 0);

	return 0;
}

static int exit_dwc3_gadget_pullup(struct kretprobe_instance *ri,
				   struct pt_regs *regs)
{
	union kprobe_data *data = (union kprobe_data *)ri->data;

	dwc3_msm_notify_event(data->dwc, DWC3_CONTROLLER_PULLUP_EXIT,
				data->xi0);

	return 0;
}

static int entry_trace_event_raw_event_dwc3_log_request(struct kretprobe_instance *ri,
				   struct pt_regs *regs)
{
	struct dwc3_request *req = (struct dwc3_request *)regs->regs[1];

	dbg_trace_ep_queue(req);

	return 0;
}

static int entry_trace_event_raw_event_dwc3_log_gadget_ep_cmd(struct kretprobe_instance *ri,
				   struct pt_regs *regs)
{
	struct dwc3_ep *dep = (struct dwc3_ep *)regs->regs[1];
	unsigned int cmd = regs->regs[2];
	struct dwc3_gadget_ep_cmd_params *param = (struct dwc3_gadget_ep_cmd_params *)regs->regs[3];
	int cmd_status = regs->regs[4];

	dbg_trace_gadget_ep_cmd(dep, cmd, param, cmd_status);

	return 0;
}

static int entry_trace_event_raw_event_dwc3_log_trb(struct kretprobe_instance *ri,
				   struct pt_regs *regs)
{
	struct dwc3_ep *dep = (struct dwc3_ep *)regs->regs[1];
	struct dwc3_trb *trb = (struct dwc3_trb *)regs->regs[2];

	dbg_trace_trb_prepare(dep, trb);

	return 0;
}

static int entry_trace_event_raw_event_dwc3_log_event(struct kretprobe_instance *ri,
				   struct pt_regs *regs)
{
	u32 event = regs->regs[1];
	struct dwc3 *dwc = (struct dwc3 *)regs->regs[2];

	dbg_trace_event(event, dwc);

	return 0;
}

static int entry_trace_event_raw_event_dwc3_log_ep(struct kretprobe_instance *ri,
				   struct pt_regs *regs)
{
	struct dwc3_ep *dep = (struct dwc3_ep *)regs->regs[1];

	dbg_trace_ep(dep);

	return 0;
}

static int entry_android_work(struct kretprobe_instance *ri,
			     struct pt_regs *regs)
{
	struct work_struct *data = (struct work_struct *)regs->regs[0];
	union kprobe_data *w_data = (union kprobe_data *)ri->data;

	w_data->data = data;
	return 0;
}

static int exit_android_work(struct kretprobe_instance *ri,
			    struct pt_regs *regs)
{
	union kprobe_data *w_data = (union kprobe_data *)ri->data;
	struct android_uevent_opts *opts = container_of(w_data->data,
			struct android_uevent_opts, work);

	if (opts->configured)
		pr_info("USB_STATE=CONFIGURED\n");
	else if (opts->sw_connected)
		pr_info(" USB_STATE=CONNECTED\n");
	else
		pr_info("USB_STATE=DISCONNECTED\n");

	return 0;
}

static int entry_dwc3_gadget_vbus_draw(struct kretprobe_instance *ri,
				   struct pt_regs *regs)
{

	unsigned int mA = (unsigned int)regs->regs[1];

	switch (mA) {
	case 2:
		pr_info("[USB] dwc3_gadget_vbus_draw: suspend -log only-\n");
		break;
	case 100:
		break;
	case 500:
		break;
	case 900:
		break;
	default:
		break;
	}
	return 0;
}

static int entry_configfs_composite_setup(struct kretprobe_instance *ri,
				   struct pt_regs *regs)
{
	struct usb_gadget *gadget = (struct usb_gadget *)regs->regs[0];
	const struct usb_ctrlrequest *ctrl = (const struct usb_ctrlrequest *)regs->regs[1];
	struct usb_composite_dev *cdev;
	struct usb_function		*f = NULL;
	struct usb_configuration *c = NULL;

	cdev = get_gadget_data(gadget);
	if (!cdev) {
		pr_info("[USB] cdev is NULL\n");
		return 0;
	}

	if (cdev->config) {
		list_for_each_entry(f, &cdev->config->functions, list)
			if (!strcmp(f->name, "ss_mon"))
				if (f->req_match && !f->req_match(f, ctrl, true))
					f->setup(f, ctrl);
	} else {
		list_for_each_entry(c, &cdev->configs, list)
			list_for_each_entry(f, &c->functions, list)
				if (!strcmp(f->name, "ss_mon"))
					if (f->req_match && !f->req_match(f, ctrl, true))
						f->setup(f, ctrl);
	}

	return 0;
}

#define ENTRY_EXIT(name) {\
	.handler = exit_##name,\
	.entry_handler = entry_##name,\
	.data_size = sizeof(union kprobe_data),\
	.maxactive = 8,\
	.kp.symbol_name = #name,\
}

#define ENTRY(name) {\
	.entry_handler = entry_##name,\
	.data_size = sizeof(union kprobe_data),\
	.maxactive = 8,\
	.kp.symbol_name = #name,\
}

static struct kretprobe dwc3_msm_probes[] = {
#if IS_ENABLED(CONFIG_USB_CONFIGFS_F_SS_MON_GADGET)
	ENTRY_EXIT(dwc3_gadget_run_stop),
#else
	ENTRY(dwc3_gadget_run_stop),
#endif
	ENTRY(dwc3_send_gadget_ep_cmd),
	ENTRY(dwc3_gadget_reset_interrupt),
	ENTRY(__dwc3_gadget_ep_enable),
	ENTRY_EXIT(dwc3_gadget_pullup),
	ENTRY_EXIT(android_work),
	ENTRY_EXIT(usb_ep_set_maxpacket_limit),
	ENTRY_EXIT(dwc3_suspend_common),
	ENTRY(trace_event_raw_event_dwc3_log_request),
	ENTRY(trace_event_raw_event_dwc3_log_gadget_ep_cmd),
	ENTRY(trace_event_raw_event_dwc3_log_trb),
	ENTRY(trace_event_raw_event_dwc3_log_event),
	ENTRY(trace_event_raw_event_dwc3_log_ep),
	ENTRY(dwc3_gadget_vbus_draw),
	ENTRY(configfs_composite_setup),
};


int dwc3_msm_kretprobe_init(void)
{
	int ret;
	int i;

	for (i = 0; i < ARRAY_SIZE(dwc3_msm_probes) ; i++) {
		ret = register_kretprobe(&dwc3_msm_probes[i]);
		if (ret < 0)
			pr_err("register_kretprobe failed for %s, returned %d\n",
					dwc3_msm_probes[i].kp.symbol_name, ret);
	}

	return 0;
}

void dwc3_msm_kretprobe_exit(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(dwc3_msm_probes); i++)
		unregister_kretprobe(&dwc3_msm_probes[i]);
}

