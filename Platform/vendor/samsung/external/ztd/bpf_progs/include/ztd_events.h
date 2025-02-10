
#ifndef ZTD_EVENTS_H
#define ZTD_EVENTS_H

#include <ztd_common.h>

#ifdef __cplusplus
#include <string>
#else
static unsigned long long (*bpf_get_current_task)(void) = (void*) BPF_FUNC_get_current_task;
#endif

typedef struct event_noti {
    int32_t type;
    uint64_t key;
} event_noti_t;

typedef struct proc_event_raw {
    int32_t event;
    uint64_t event_time;
    int32_t syscall;
    int32_t exit_code;
    pid_t tid;
    pid_t pid;
    pid_t ppid;
    uid_t uid;
    gid_t gid;
    uid_t suid;
    gid_t sgid;
    uid_t euid;
    gid_t egid;
    uid_t fsuid;
    gid_t fsgid;
    uid_t owner_uid;
    gid_t owner_gid;
    time64_t atime;
    time64_t mtime;
    time64_t ctime;
    char filepath[MAX_FP_LEN];
    char cwd[MAX_FP_LEN];
    char cmdline[MAX_FP_LEN];
    int64_t reserved_1;
    int64_t reserved_2;
    int64_t reserved_3;
} proc_event_raw_t;

#ifdef __cplusplus
typedef struct proc_event_data {
    int32_t event;
    uint64_t event_time;
    int32_t syscall;
    int32_t exit_code;
    int32_t tid;
    int32_t pid;
    int32_t ppid;
    uint32_t uid;
    uint32_t gid;
    uint32_t suid;
    uint32_t sgid;
    uint32_t euid;
    uint32_t egid;
    uint32_t fsuid;
    uint32_t fsgid;
    uint32_t owner_uid;
    uint32_t owner_gid;
    int64_t atime;
    int64_t mtime;
    int64_t ctime;
    std::string filepath;
    std::string cwd;
    std::string cmdline;
    int64_t reserved_1;
    int64_t reserved_2;
    int64_t reserved_3;
} proc_event_data_t;
#endif

typedef struct sock_event_raw {
    int32_t event;
    uint64_t event_time;
    int32_t syscall;
    int32_t exit_code;
    pid_t tid;
    pid_t pid;
    pid_t ppid;
    uid_t uid;
    gid_t gid;
    int32_t oldstate;
    int32_t newstate;
    int32_t fd;
    uint16_t family;
    uint16_t type;
    uint16_t protocol;
    uint16_t sport;
    uint16_t dport;
    uint8_t saddr[4];
    uint8_t daddr[4];
    uint8_t saddr_v6[16];
    uint8_t daddr_v6[16];
    char filepath[MAX_FP_LEN];
} sock_event_raw_t;

#ifdef __cplusplus
typedef struct sock_event_data {
    int32_t event;
    uint64_t event_time;
    int32_t syscall;
    int32_t exit_code;
    pid_t tid;
    pid_t pid;
    pid_t ppid;
    uid_t uid;
    gid_t gid;
    int32_t oldstate;
    int32_t newstate;
    int32_t fd;
    uint16_t family;
    uint16_t type;
    uint16_t protocol;
    uint16_t sport;
    uint16_t dport;
    std::string saddr;
    std::string daddr;
    std::string saddr_v6;
    std::string daddr_v6;
    std::string filepath;
} sock_event_data_t;
#endif

#endif // ZTD_EVENTS_H