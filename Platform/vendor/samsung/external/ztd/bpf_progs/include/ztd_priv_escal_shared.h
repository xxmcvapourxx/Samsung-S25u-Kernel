
#ifndef ZTD_PRIV_ESCAL_SHARED_H
#define ZTD_PRIV_ESCAL_SHARED_H

#include <sys/types.h>

#include <ztd_proc_shared.h>

#define PROG_PRIV_ESCAL "ztdPrivEscal"

#define ENTER_FOR_PRIV_ESCAL_PROG_PATH  BPF_FS_PATH PROG_(PROG_PRIV_ESCAL)  TRACEPOINT_ "raw_syscalls_sys_enter"
#define EXIT_FOR_PRIV_ESCAL_PROG_PATH   BPF_FS_PATH PROG_(PROG_PRIV_ESCAL)  TRACEPOINT_ "raw_syscalls_sys_exit"

#define PRIV_ESCAL_DATA_MAP_PATH        BPF_FS_PATH MAP_(PROG_PRIV_ESCAL)   "priv_escal_data_map"

// Events of PrivEscal(Privilege Escalation) trace
const static int TRACE_EVENT_PRIV_ESCAL = 150 * 100 + 1;

#endif /* ZTD_PRIV_ESCAL_SHARED_H */
