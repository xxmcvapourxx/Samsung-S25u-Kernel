#ifndef ZTD_TASK_SHARED_H
#define ZTD_TASK_SHARED_H

#include <sys/types.h>

#include <ztd_common.h>

#if USE_RINGBUF
# define DEFINE_TASK_TRACEPOINT(the_event) \
    DEFINE_BPF_PROG_KVER("tracepoint/task/" #the_event, AID_ROOT, AID_SYSTEM, tp_##the_event, KVER(5, 8, 0))
#else
# define DEFINE_TASK_TRACEPOINT(the_event) \
    DEFINE_BPF_PROG("tracepoint/task/" #the_event, AID_ROOT, AID_SYSTEM, tp_##the_event)
#endif

#define BUILD_TASK_RENAME_PROG_PATH(PROG_NAME) BPF_FS_PATH PROG_(PROG_NAME) TRACEPOINT_ "task_task_rename"

typedef struct task_rename_data {
    uint64_t common;
    int32_t pid;
    char oldcomm[MAX_TASK_COMM_LEN];
    char newcomm[MAX_TASK_COMM_LEN];
    int16_t oom_score_adj;
} task_rename_data_t;

#endif // ZTD_TASK_SHARED_H
