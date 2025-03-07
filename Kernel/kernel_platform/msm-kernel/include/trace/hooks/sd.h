/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM sd

#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH trace/hooks

#if !defined(_TRACE_HOOK_SD_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_HOOK_SD_H

#include <trace/hooks/vendor_hooks.h>
/*
 * Following tracepoints are not exported in tracefs and provide a
 * mechanism for vendor modules to hook and extend functionality
 */

struct scsi_disk;
struct scsi_vpd;
struct scsi_cmnd;

DECLARE_HOOK(android_vh_sd_init_unmap_multi_segment,
	TP_PROTO(struct scsi_disk *sdkp, struct scsi_vpd *vpd),
	TP_ARGS(sdkp, vpd));

DECLARE_HOOK(android_vh_sd_setup_unmap_multi_segment,
	TP_PROTO(struct scsi_cmnd *cmd, char *buf),
	TP_ARGS(cmd, buf));

#endif /* _TRACE_HOOK_SD_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
