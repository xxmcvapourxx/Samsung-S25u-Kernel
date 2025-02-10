
#ifndef ZTD_COMMON_H
#define ZTD_COMMON_H

#include <sys/types.h>

#define BPF_FS_PATH "/sys/fs/bpf/"

#define SHARED_OBJ  ""
#define PROG_(name) "prog_" name "_"
#define MAP_(name)  "map_"  name "_"

#define SCHEDCLS_   "schedcls_"
#define TRACEPOINT_ "tracepoint_"
#define KPROBE_     "kprobe_"

// Configurations
#define USE_RINGBUF 1
#define DEFAULT_RINGBUF_TIMEOUT (-1)

#ifndef MAX_TASK_COMM_LEN
#define MAX_TASK_COMM_LEN 16
#endif

#ifndef MAX_FN_LEN
#define MAX_FN_LEN 256 // 255 + Null-termination
#endif

#ifndef MAX_FP_LEN
#define MAX_FP_LEN 4096
#endif

/*
 * The following Definitions must be synchronized with
 * the com.samsung.android.knox.zt.devicetrust.EndpointMonitorConst class
 */
static const int GENERIC_SYSCALL_NR_MOUNT         = 40;
static const int GENERIC_SYSCALL_NR_FCHMOD        = 52;
static const int GENERIC_SYSCALL_NR_FCHMODAT      = 53;
static const int GENERIC_SYSCALL_NR_FCHOWNAT      = 54;
static const int GENERIC_SYSCALL_NR_FCHOWN        = 55;
static const int GENERIC_SYSCALL_NR_OPEN          = 56;
static const int GENERIC_SYSCALL_NR_CLOSE         = 57;
static const int GENERIC_SYSCALL_NR_SETREGID      = 143;
static const int GENERIC_SYSCALL_NR_SETGID        = 144;
static const int GENERIC_SYSCALL_NR_SETREUID      = 145;
static const int GENERIC_SYSCALL_NR_SETUID        = 146;
static const int GENERIC_SYSCALL_NR_SETRESUID     = 147;
static const int GENERIC_SYSCALL_NR_SETRESGID     = 149;
static const int GENERIC_SYSCALL_NR_SETFSUID      = 151;
static const int GENERIC_SYSCALL_NR_SETFSGID      = 152;
static const int GENERIC_SYSCALL_NR_EXECVE        = 221;
static const int GENERIC_SYSCALL_NR_MEMFD_CREATE  = 279;

static const int FLAG_TRACING_FS                               = (0x01 << 0);
static const int FLAG_TRACING_SC_OPEN                          = (0x01 << 1);
static const int FLAG_TRACING_SC_CLOSE                         = (0x01 << 2);
static const int FLAG_TRACING_SC_MOUNT                         = (0x01 << 3);
static const int FLAG_TRACING_SC_EXECVE                        = (0x01 << 4);
static const int FLAG_TRACING_SK                               = (0x01 << 5);
static const int FLAG_TRACING_PKT                              = (0x01 << 6);
static const int FLAG_TRACING_FW                               = (0x01 << 7);
static const int FLAG_TRACING_SC_CHMOD                         = (0x01 << 8);
static const int FLAG_TRACING_SC_CHOWN                         = (0x01 << 9);
static const int FLAG_TRACING_SC_MEMFD_CREATE                  = (0x01 << 10);
static const int FLAG_TRACING_PROC                             = (0x01 << 11);
static const int FLAG_TRACING_PROCESS_CREATION                 = (0x01 << 12);
static const int FLAG_TRACING_PROCESS_TERMINATION              = (0x01 << 13);
static const int FLAG_TRACING_PROCESS_PERMISSIONS_MODIFICATION = (0x01 << 14);

// Trace Classification
static const int TRACE_CLASS_FILE_ACCESS   = 1;
static const int TRACE_CLASS_DOMAIN_ACCESS = 2;

// Trace Types that Ztd Supports
static const int TRACE_TYPE_SYSCALL                          = 1;
static const int TRACE_TYPE_FS                               = 2;
static const int TRACE_TYPE_SOCK                             = 3;
static const int TRACE_TYPE_PROC                             = 4;
static const int TRACE_TYPE_PKT                              = 5;
static const int TRACE_TYPE_DOMAIN                           = 6;
static const int TRACE_TYPE_APP_PROC                         = 7;
static const int TRACE_TYPE_PHISHING                         = 8;
static const int TRACE_TYPE_SIGNALS                          = 9;
static const int TRACE_TYPE_PROCESS_CREATION                 = 10;
static const int TRACE_TYPE_PROCESS_TERMINATION              = 11;
static const int TRACE_TYPE_PROCESS_PERMISSIONS_MODIFICATION = 12;

// Sub-systems of Tracepoint
static const int TRACE_SYSTEM_RAW_SYSCALL = 1;
static const int TRACE_SYSTEM_F2FS        = 2;
static const int TRACE_SYSTEM_SOCK        = 3;
static const int TRACE_SYSTEM_SCHED       = 4;
static const int TRACE_SYSTEM_ETC         = 5;

// Events of SC(System Call) trace
static const int TRACE_EVENT_SYS_ENTER            = 101;
static const int TRACE_EVENT_SYS_EXIT             = 102;
static const int TRACE_EVENT_SYS_OPEN             = 103;
static const int TRACE_EVENT_SYS_CLOSE            = 104;
static const int TRACE_EVENT_SYS_MOUNT            = 105;
static const int TRACE_EVENT_SYS_EXECVE           = 106;
static const int TRACE_EVENT_SYS_FCHMOD           = 107;
static const int TRACE_EVENT_SYS_FCHMODAT         = 108;
static const int TRACE_EVENT_SYS_FCHOWNAT         = 109;
static const int TRACE_EVENT_SYS_FCHOWN           = 110;
static const int TRACE_EVENT_SYS_MEMFD_CREATE     = 111;

static const int TRACE_EVENT_SYS_ENTER_SETREGID   = 1143;
static const int TRACE_EVENT_SYS_ENTER_SETGID     = 1144;
static const int TRACE_EVENT_SYS_ENTER_SETREUID   = 1145;
static const int TRACE_EVENT_SYS_ENTER_SETUID     = 1146;
static const int TRACE_EVENT_SYS_ENTER_SETRESUID  = 1147;
static const int TRACE_EVENT_SYS_ENTER_SETRESGID  = 1149;
static const int TRACE_EVENT_SYS_ENTER_SETFSUID   = 1151;
static const int TRACE_EVENT_SYS_ENTER_SETFSGID   = 1152;
static const int TRACE_EVENT_SYS_ENTER_EXECVE     = 1221;

static const int TRACE_EVENT_SYS_EXIT_SETREGID    = 2143;
static const int TRACE_EVENT_SYS_EXIT_SETGID      = 2144;
static const int TRACE_EVENT_SYS_EXIT_SETREUID    = 2145;
static const int TRACE_EVENT_SYS_EXIT_SETUID      = 2146;
static const int TRACE_EVENT_SYS_EXIT_SETRESUID   = 2147;
static const int TRACE_EVENT_SYS_EXIT_SETRESGID   = 2149;
static const int TRACE_EVENT_SYS_EXIT_SETFSUID    = 2151;
static const int TRACE_EVENT_SYS_EXIT_SETFSGID    = 2152;
static const int TRACE_EVENT_SYS_EXIT_EXECVE      = 2221;

// Events of FS(File System) Trace
static const int TRACE_EVENT_F2FS_IGET            = 201;
static const int TRACE_EVENT_F2FS_IGET_EXIT       = 202;
static const int TRACE_EVENT_F2FS_READDIR         = 203;
static const int TRACE_EVENT_F2FS_READPAGE        = 204;
static const int TRACE_EVENT_F2FS_READPAGES       = 205;
static const int TRACE_EVENT_F2FS_UNLINK_ENTER    = 206;
static const int TRACE_EVENT_F2FS_UNLINK_EXIT     = 207;
static const int TRACE_EVENT_F2FS_WRITEPAGE       = 208;
static const int TRACE_EVENT_F2FS_WRITEPAGES      = 209;
static const int TRACE_EVENT_F2FS_DATAREAD_START  = 210;
static const int TRACE_EVENT_F2FS_DATAREAD_END    = 211;
static const int TRACE_EVENT_F2FS_DATAWRITE_START = 212;
static const int TRACE_EVENT_F2FS_DATAWRITE_END   = 213;

// Events of SK(Socket) Trace
static const int TRACE_EVENT_INET_SOCK_SET_STATE  = 301;

// Events of PK(Packet) Trace
static const int TRACE_EVENT_SCHED_CLS_INGRESS    = 501;
static const int TRACE_EVENT_SCHED_CLS_EGRESS     = 502;

// Events of PROC(Process) Trace
static const int TRACE_EVENT_SCHED_PROCESS_EXEC   = 701;
static const int TRACE_EVENT_SCHED_PROCESS_EXIT   = 702;
static const int TRACE_EVENT_SCHED_PROCESS_FORK   = 703;

static const int TRACE_EVENT_TASK_RENAME          = 801;

typedef struct tp_base_data {
    uint64_t event_time;
    uint64_t pid_tgid;
    uint64_t uid_gid;
    char comm[MAX_TASK_COMM_LEN];
} tp_base_data_t;

typedef unsigned short __u16;
typedef unsigned int __u32;
typedef long long int __s64;
typedef long long unsigned int __u64;
typedef __u16 u16;
typedef __u32 u32;
typedef __u64 u64;
typedef __s64 time64_t;
typedef short unsigned int umode_t;

typedef struct {
    uid_t value;
} kuid_t;

typedef struct {
    gid_t value;
} kgid_t;

struct cred {
    kuid_t uid;
    kgid_t gid;
    kuid_t suid;
    kgid_t sgid;
    kuid_t euid;
    kgid_t egid;
    kuid_t fsuid;
    kgid_t fsgid;
};

struct task_struct {
    pid_t pid;
    pid_t tgid;
    struct task_struct *real_parent;
    int exit_code;
    u64 utime;
    u64 stime;
    u64 start_time;
    const struct cred *cred;
    struct fs_struct *fs;
    struct mm_struct *mm;
};

struct timespec64 {
    time64_t tv_sec;
};

struct inode {
    umode_t i_mode;
    kuid_t i_uid;
    kgid_t i_gid;
    long unsigned int i_ino;
    struct timespec64 i_atime;
    struct timespec64 i_mtime;
    struct timespec64 i_ctime;
};

struct qstr {
    union {
        struct {
            u32 hash;
            u32 len;
        };
        u64 hash_len;
    };
    const unsigned char *name;
};

struct dentry {
    struct dentry *d_parent;
    struct qstr d_name;
    struct inode *d_inode;
};

struct path {
    struct dentry *dentry;
};

struct fs_struct {
    struct path pwd;
};

struct file {
    struct path f_path;
};

struct mm_struct {
    struct {
        struct file *exe_file;
    };
};

struct sock {
    u16 sk_type;
    kuid_t sk_uid;
};

// Whenever there's a change in this definition,
// the version must be updated accordingly
enum offset_defs {
    /* struct task_struct */
    OFFSET_MM_IN_TASK_STRUCT,
    OFFSET_EXIT_CODE_IN_TASK_STRUCT,
    OFFSET_PID_IN_TASK_STRUCT,
    OFFSET_TGID_IN_TASK_STRUCT,
    OFFSET_REAL_PARENT_IN_TASK_STRUCT,
    OFFSET_UTIME_IN_TASK_STRUCT,
    OFFSET_STIME_IN_TASK_STRUCT,
    OFFSET_START_TIME_IN_TASK_STRUCT,
    OFFSET_CRED_IN_TASK_STRUCT,
    OFFSET_FS_IN_TASK_STRUCT,

    /* struct cred */
    OFFSET_UID_IN_CRED,
    OFFSET_GID_IN_CRED,
    OFFSET_SUID_IN_CRED,
    OFFSET_SGID_IN_CRED,
    OFFSET_EUID_IN_CRED,
    OFFSET_EGID_IN_CRED,
    OFFSET_FSUID_IN_CRED,
    OFFSET_FSGID_IN_CRED,

    /* struct fs_struct */
    OFFSET_PWD_IN_FS_STRUCT,

    /* struct mm_struct */
    OFFSET_EXE_FILE_IN_MM_STRUCT,

    /* struct file */
    OFFSET_F_PATH_IN_FILE,

    /* struct path */
    OFFSET_DENTRY_IN_PATH,

    /* struct dentry */
    OFFSET_D_PARENT_IN_DENTRY,
    OFFSET_D_NAME_IN_DENTRY,
    OFFSET_D_INODE_IN_DENTRY,

    /* struct qstr */
    OFFSET_NAME_IN_QSTR,

    /* struct inode */
    OFFSET_I_MODE_IN_INODE,
    OFFSET_I_UID_IN_INODE,
    OFFSET_I_GID_IN_INODE,
    OFFSET_I_INO_IN_INODE,
    OFFSET_I_ATIME_IN_INODE,
    OFFSET_I_MTIME_IN_INODE,
    OFFSET_I_CTIME_IN_INODE,

    /* struct timespec64 */
    OFFSET_TV_SEC_IN_TIMESPEC64,

    /* struct sock */
    OFFSET_SK_TYPE_IN_SOCK,
    OFFSET_SK_UID_IN_SOCK,

    NUM_OF_OFFSET_DEFS,
    VERSION_OF_OFFSET_DEFS = 1,
};

typedef struct offsets_frame_buf {
    uint32_t offsets[NUM_OF_OFFSET_DEFS];
} offsets_frame_buf_t;

#endif // ZTD_COMMON_H
