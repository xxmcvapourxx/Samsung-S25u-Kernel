
#ifndef ZTD_SC_SHARED_H
#define ZTD_SC_SHARED_H

#include <sys/types.h>

#include <ztd_common.h>

#define PROG_SC_OPEN   "ztdScOpen"
#define PROG_SC_CLOSE  "ztdScClose"
#define PROG_SC_MOUNT  "ztdScMount"
#define PROG_SC_EXECVE "ztdScExecve"
#define PROG_SC_CHMOD  "ztdScChmod"
#define PROG_SC_CHOWN  "ztdScChown"
#define PROG_SC_MEMFD_CREATE    "ztdScMemfdCreate"

#define SYS_ENTER_FOR_OPEN_PROG_PATH   BPF_FS_PATH PROG_(PROG_SC_OPEN)   TRACEPOINT_ "raw_syscalls_sys_enter"
#define SYS_EXIT_FOR_OPEN_PROG_PATH    BPF_FS_PATH PROG_(PROG_SC_OPEN)   TRACEPOINT_ "raw_syscalls_sys_exit"
#define SYS_ENTER_FOR_CLOSE_PROG_PATH  BPF_FS_PATH PROG_(PROG_SC_CLOSE)  TRACEPOINT_ "raw_syscalls_sys_enter"
#define SYS_EXIT_FOR_CLOSE_PROG_PATH   BPF_FS_PATH PROG_(PROG_SC_CLOSE)  TRACEPOINT_ "raw_syscalls_sys_exit"
#define SYS_ENTER_FOR_MOUNT_PROG_PATH  BPF_FS_PATH PROG_(PROG_SC_MOUNT)  TRACEPOINT_ "raw_syscalls_sys_enter"
#define SYS_EXIT_FOR_MOUNT_PROG_PATH   BPF_FS_PATH PROG_(PROG_SC_MOUNT)  TRACEPOINT_ "raw_syscalls_sys_exit"
#define SYS_ENTER_FOR_EXECVE_PROG_PATH BPF_FS_PATH PROG_(PROG_SC_EXECVE) TRACEPOINT_ "raw_syscalls_sys_enter"
#define SYS_EXIT_FOR_EXECVE_PROG_PATH  BPF_FS_PATH PROG_(PROG_SC_EXECVE) TRACEPOINT_ "raw_syscalls_sys_exit"
#define SYS_ENTER_FOR_CHMOD_PROG_PATH  BPF_FS_PATH PROG_(PROG_SC_CHMOD)  TRACEPOINT_ "raw_syscalls_sys_enter"
#define SYS_EXIT_FOR_CHMOD_PROG_PATH   BPF_FS_PATH PROG_(PROG_SC_CHMOD)  TRACEPOINT_ "raw_syscalls_sys_exit"
#define SYS_ENTER_FOR_CHOWN_PROG_PATH  BPF_FS_PATH PROG_(PROG_SC_CHOWN) TRACEPOINT_ "raw_syscalls_sys_enter"
#define SYS_EXIT_FOR_CHOWN_PROG_PATH   BPF_FS_PATH PROG_(PROG_SC_CHOWN) TRACEPOINT_ "raw_syscalls_sys_exit"
#define SYS_ENTER_FOR_MEMFD_CREATE_PROG_PATH  BPF_FS_PATH PROG_(PROG_SC_MEMFD_CREATE) TRACEPOINT_ "raw_syscalls_sys_enter"
#define SYS_EXIT_FOR_MEMFD_CREATE_PROG_PATH   BPF_FS_PATH PROG_(PROG_SC_MEMFD_CREATE) TRACEPOINT_ "raw_syscalls_sys_exit"

#define SC_OPEN_DATA_MAP_PATH          BPF_FS_PATH MAP_(PROG_SC_OPEN)    "sc_open_data_map"
#define SC_CLOSE_DATA_MAP_PATH         BPF_FS_PATH MAP_(PROG_SC_CLOSE)   "sc_close_data_map"
#define SC_MOUNT_DATA_MAP_PATH         BPF_FS_PATH MAP_(PROG_SC_MOUNT)   "sc_mount_data_map"
#define SC_EXECVE_DATA_MAP_PATH        BPF_FS_PATH MAP_(PROG_SC_EXECVE)  "sc_execve_data_map"
#define SC_FCHMOD_DATA_MAP_PATH         BPF_FS_PATH MAP_(PROG_SC_CHMOD)   "sc_fchmod_data_map"
#define SC_FCHMODAT_DATA_MAP_PATH       BPF_FS_PATH MAP_(PROG_SC_CHMOD)   "sc_fchmodat_data_map"
#define SC_FCHOWNAT_DATA_MAP_PATH      BPF_FS_PATH MAP_(PROG_SC_CHOWN)   "sc_fchownat_data_map"
#define SC_FCHOWN_DATA_MAP_PATH        BPF_FS_PATH MAP_(PROG_SC_CHOWN)   "sc_fchown_data_map"
#define SC_MEMFD_CREATE_DATA_MAP_PATH  BPF_FS_PATH MAP_(PROG_SC_MEMFD_CREATE)   "sc_memfd_create_data_map"
#define SC_DATA_RINGBUF_PATH           BPF_FS_PATH MAP_(SHARED_OBJ)      "sc_data_ringbuf"
#define SC_TRACER_MAP_PATH             BPF_FS_PATH MAP_(SHARED_OBJ)      "sc_tracer_map"

#if USE_RINGBUF
# define DEFINE_SC_TRACEPOINT(the_system, the_event, the_prog) \
    DEFINE_BPF_PROG_KVER("tracepoint/" #the_system "/" #the_event, AID_ROOT, AID_SYSTEM, tp_##the_prog, KVER(5, 8, 0))
#else
# define DEFINE_SC_TRACEPOINT(the_system, the_event, the_prog) \
    DEFINE_BPF_PROG("tracepoint/" #the_system "/" #the_event, AID_ROOT, AID_SYSTEM, tp_##the_prog)
#endif

typedef struct sc_tracer {
    uid_t uid; // (idx:0)
} sc_tracer_t;

typedef struct sys_enter_data {
    uint64_t common;    //  8 bytes
    int64_t id;
    uint64_t args[6];
} sys_enter_data_t;

typedef struct sys_exit_data {
    uint64_t common;    //  8 bytes
    int64_t id;
    int64_t ret;
} sys_exit_data_t;

typedef struct sc_open_data {
    tp_base_data_t base_data;
    int dfd;
    char filename[256];
    int flags;
    mode_t mode;
    int64_t ret;
} sc_open_data_t;

typedef struct sc_close_data {
    tp_base_data_t base_data;
    uint32_t fd;
    int64_t ret;
} sc_close_data_t;

typedef struct sc_mount_data {
    tp_base_data_t base_data;
    char dev_name[128];     // 128 bytes
    char dir_name[128];     // 128 bytes
    char type[16];          //  16 bytes
    uint64_t flags;         //   8 bytes
    char data[32];          //  32 bytes
    int64_t ret;
} sc_mount_data_t;

#define ZT_MAX_ARGS 5
typedef struct sc_execve_data {
    tp_base_data_t base_data;
    char filename[160];             // 160 bytes
    char argv[ZT_MAX_ARGS][32];
//  char envp[ZT_MAX_ARGS][40];     // Not interested...
    int64_t ret;
} sc_execve_data_t;

typedef struct sc_fchmod_data {
    tp_base_data_t base_data;
    int dfd;
    mode_t mode;
    int64_t ret;
} sc_fchmod_data_t;

typedef struct sc_fchmodat_data {
    tp_base_data_t base_data;
    int dfd;
    char filename[256];
    mode_t mode;
    int64_t ret;
} sc_fchmodat_data_t;

typedef struct sc_fchownat_data {
    tp_base_data_t base_data;
    int dfd;
    char filename[256];
    uid_t owner;
    gid_t group;
    int flag;
    int64_t ret;
} sc_fchownat_data_t;

typedef struct sc_fchown_data {
    tp_base_data_t base_data;
    int fd;
    uid_t owner;
    gid_t group;
    int64_t ret;
} sc_fchown_data_t;

typedef struct sc_memfd_create_data {
    tp_base_data_t base_data;
    char uname_ptr[256];
    uint32_t flags;
    int64_t ret;
} sc_memfd_create_data_t;

typedef struct sc_data {
    int reserve;
    int event;
    int nr;
    union {
        struct {
            sc_open_data_t data;
        } sc_open;
        struct {
            sc_close_data_t data;
        } sc_close;
        struct {
            sc_mount_data_t data;
        } sc_mount;
        struct {
            sc_execve_data_t data;
        } sc_execve;
        struct {
            sc_fchmod_data_t data;
        } sc_fchmod;
        struct {
            sc_fchmodat_data_t data;
        } sc_fchmodat;
        struct {
            sc_fchownat_data_t data;
        } sc_fchownat;
        struct {
            sc_fchown_data_t data;
        } sc_fchown;
        struct {
            sc_memfd_create_data_t data;
        } sc_memfd_create;
    } u;
} sc_data_t;

#endif // ZTD_SC_SHARED_H