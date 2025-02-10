
#include "bpf_shared.h"
#include "bpf_read.h"
#include <stdbool.h>
#include <ztd_events.h>
#include <ztd_proc_shared.h>
#include <ztd_sc_shared.h>
#include <ztd_task_shared.h>

#define DEBUG 0
#define DEBUG_ENTRY 0

DEFINE_BPF_MAP_GRW(proc_creation_data_map, LRU_HASH, uint64_t, proc_event_raw_t, 1024, AID_SYSTEM);
DEFINE_BPF_MAP_GRW(proc_event_map, PERCPU_ARRAY, uint32_t, proc_event_raw_t, 1, AID_SYSTEM);
DEFINE_BPF_RINGBUF_EXT(proc_creation_event_noti, event_noti_t, 4096, AID_ROOT, AID_SYSTEM, 0660, "", "", PRIVATE,
                       BPFLOADER_MIN_VER, BPFLOADER_MAX_VER, LOAD_ON_ENG, LOAD_ON_USER, LOAD_ON_USERDEBUG)
DEFINE_BPF_SHARED_MAP_GRW(offsets_frame_map, ARRAY, uint32_t, offsets_frame_buf_t, 1, AID_SYSTEM);

#define MAX_PATH_DEPTH 128

#define MIN(a, b) (((a) < (b)) ? (a) : (b))

static int (*bpf_probe_read_kernel_str)(void* dst, int size, const void* safe_ptr) = (void*)BPF_FUNC_probe_read_kernel_str;

static inline __always_inline void updatePathName(struct path *path, char pathName[], offsets_frame_buf_t *ofb) {
    struct dentry *d_current = BPF_READ_AT(path, dentry, ofb->offsets[OFFSET_DENTRY_IN_PATH]);

    uint12_t idx = { .value = 0 };
    for (int d = 0; d < MAX_PATH_DEPTH ; d++) {
        struct dentry *d_parent = BPF_READ_AT(d_current, d_parent, ofb->offsets[OFFSET_D_PARENT_IN_DENTRY]);
        if (!d_current) {
            break;
        }
        struct qstr d_name = BPF_READ_AT(d_current, d_name, ofb->offsets[OFFSET_D_NAME_IN_DENTRY]);
        const unsigned char *name = BPF_READ_AT(&d_name, name, ofb->offsets[OFFSET_NAME_IN_QSTR]);
        if (d_parent == d_current) {
            if (idx.value <= (MAX_FP_LEN - MAX_FN_LEN)) {
                bpf_probe_read_kernel_str(&pathName[idx.value], MAX_FN_LEN, (void *) name);
            }
            break;
        } else {
            if (idx.value > 0 && idx.value < (MAX_FP_LEN - 1)) {
                pathName[idx.value++] = '/';
            }
            int ret = 0;
            if (idx.value <= (MAX_FP_LEN - MAX_FN_LEN)) {
                ret = bpf_probe_read_kernel_str(&pathName[idx.value], MAX_FN_LEN, (void *) name);
            }
            if (ret > 1) {
                idx.value += (ret - 1);
            } else {
                break;
            }
        }
        d_current = d_parent;
    }
}

static inline __always_inline void updateCmdline(uint64_t args, char cmdline[]) {

    uint64_t argv_addr;
    uint12_t idx = { .value = 0 };
    for (int d = 0; d < MAX_PATH_DEPTH ; d++) {
        void *argv_ptr = POINTER_OF_USER_SPACE(args + (d * sizeof(void *)));
        if (!argv_ptr) {
            break;
        }
        bpf_probe_read_user(&argv_addr, sizeof(argv_addr), argv_ptr);
        if (!argv_addr) {
            break;
        }
        if (idx.value > 0 && idx.value < (MAX_FP_LEN - 1)) {
            cmdline[idx.value++] = ' ';
        }
        int ret = 0;
        if (idx.value <= (MAX_FP_LEN - MAX_FN_LEN)) {
            ret = bpf_probe_read_user_str(&cmdline[idx.value], MAX_FN_LEN, POINTER_OF_USER_SPACE(argv_addr));
        }
        if (ret > 1) {
            idx.value += (ret - 1);
        } else {
            break;
        }
    }
}

static inline __always_inline void updateFilePath(char *filename_ptr, char *dst_ptr) {
    for (int ret, diff, i = 0 ; i < MAX_FP_LEN ; i+= (MAX_FN_LEN-1)) {
        diff = MAX_FP_LEN - i;
        ret = bpf_probe_read_kernel_str(
                &dst_ptr[i], MIN(diff, MAX_FN_LEN), filename_ptr);
        if (ret >= MAX_FN_LEN) {
            filename_ptr+=(MAX_FN_LEN-1);
        } else {
            break;
        }
    }
}

static inline __always_inline bool updateRawData(const char *tag,
                                                 int32_t event, uint64_t event_time,
                                                 int32_t syscall, uint64_t cmdline_addr,
                                                 bool updateCwd, bool updateFilepath,
                                                 proc_event_raw_t *data) {
    uint32_t zero = 0; // Look-up Key
    offsets_frame_buf_t *ofb = bpf_offsets_frame_map_lookup_elem(&zero);
    if (!ofb) {
        return false;
    }

    struct task_struct *task = (struct task_struct *) bpf_get_current_task();
    if (!task) {
        return false;
    }

    data->event = event;
    data->event_time = event_time;
    data->syscall = syscall;

    int exit_code = BPF_READ_AT(task, exit_code, ofb->offsets[OFFSET_EXIT_CODE_IN_TASK_STRUCT]);
    data->exit_code = exit_code;

    pid_t pid = BPF_READ_AT(task, pid, ofb->offsets[OFFSET_PID_IN_TASK_STRUCT]);
    data->tid = pid;

    pid_t tgid = BPF_READ_AT(task, tgid, ofb->offsets[OFFSET_TGID_IN_TASK_STRUCT]);
    data->pid = tgid;

    struct task_struct *real_parent = BPF_READ_AT(task, real_parent, ofb->offsets[OFFSET_REAL_PARENT_IN_TASK_STRUCT]);
    pid_t ptgid = BPF_READ_AT(real_parent, tgid, ofb->offsets[OFFSET_TGID_IN_TASK_STRUCT]);
    data->ppid = ptgid;

    struct cred *cred = (struct cred *)BPF_READ_AT(task, cred, ofb->offsets[OFFSET_CRED_IN_TASK_STRUCT]);
    kuid_t uid = BPF_READ_AT(cred, uid, ofb->offsets[OFFSET_UID_IN_CRED]);
    data->uid = uid.value;

    kgid_t gid = BPF_READ_AT(cred, gid, ofb->offsets[OFFSET_GID_IN_CRED]);
    data->gid = gid.value;

    kuid_t suid = BPF_READ_AT(cred, suid, ofb->offsets[OFFSET_SUID_IN_CRED]);
    data->suid = suid.value;

    kgid_t sgid = BPF_READ_AT(cred, sgid, ofb->offsets[OFFSET_SGID_IN_CRED]);
    data->sgid = sgid.value;

    kuid_t euid = BPF_READ_AT(cred, euid, ofb->offsets[OFFSET_EUID_IN_CRED]);
    data->euid = euid.value;

    kgid_t egid = BPF_READ_AT(cred, egid, ofb->offsets[OFFSET_EGID_IN_CRED]);
    data->egid = egid.value;

    kuid_t fsuid = BPF_READ_AT(cred, fsuid, ofb->offsets[OFFSET_FSUID_IN_CRED]);
    data->fsuid = fsuid.value;

    kgid_t fsgid = BPF_READ_AT(cred, fsgid, ofb->offsets[OFFSET_FSGID_IN_CRED]);
    data->fsgid = fsgid.value;

    struct mm_struct *mm = BPF_READ_AT(task, mm, ofb->offsets[OFFSET_MM_IN_TASK_STRUCT]);
    struct file *exe_file = BPF_READ_AT(mm, exe_file, ofb->offsets[OFFSET_EXE_FILE_IN_MM_STRUCT]);
    struct fs_struct *fs = BPF_READ_AT(task, fs, ofb->offsets[OFFSET_FS_IN_TASK_STRUCT]);
    struct path *pwd = BPF_READ_ADDR_AT(fs, pwd, ofb->offsets[OFFSET_PWD_IN_FS_STRUCT]);
    struct path *f_path = BPF_READ_ADDR_AT(exe_file, f_path, ofb->offsets[OFFSET_F_PATH_IN_FILE]);
    struct dentry *dentry = BPF_READ_AT(f_path, dentry, ofb->offsets[OFFSET_DENTRY_IN_PATH]);
    struct inode *d_inode = BPF_READ_AT(dentry, d_inode, ofb->offsets[OFFSET_D_INODE_IN_DENTRY]);
    struct timespec64 *i_atime = BPF_READ_ADDR_AT(d_inode, i_atime, ofb->offsets[OFFSET_I_ATIME_IN_INODE]);
    struct timespec64 *i_mtime = BPF_READ_ADDR_AT(d_inode, i_mtime, ofb->offsets[OFFSET_I_MTIME_IN_INODE]);
    struct timespec64 *i_ctime = BPF_READ_ADDR_AT(d_inode, i_ctime, ofb->offsets[OFFSET_I_CTIME_IN_INODE]);

    kuid_t owner_uid = BPF_READ_AT(d_inode, i_uid, ofb->offsets[OFFSET_I_UID_IN_INODE]);
    data->owner_uid = owner_uid.value;

    kgid_t owner_gid = BPF_READ_AT(d_inode, i_gid, ofb->offsets[OFFSET_I_GID_IN_INODE]);
    data->owner_gid = owner_gid.value;

    time64_t atime = BPF_READ_AT(i_atime, tv_sec, ofb->offsets[OFFSET_TV_SEC_IN_TIMESPEC64]);
    data->atime = atime;

    time64_t mtime = BPF_READ_AT(i_mtime, tv_sec, ofb->offsets[OFFSET_TV_SEC_IN_TIMESPEC64]);
    data->mtime = mtime;

    time64_t ctime = BPF_READ_AT(i_ctime, tv_sec, ofb->offsets[OFFSET_TV_SEC_IN_TIMESPEC64]);
    data->ctime = ctime;

    // umode_t umode = BPF_READ_AT(d_inode, i_mode, ofb->offsets[OFFSET_I_MODE_IN_INODE]);

    if (updateCwd) {
        updatePathName(pwd, data->cwd, ofb);
    } else {
        data->cwd[0] = '\0';
    }

    if (updateFilepath) {
        updatePathName(f_path, data->filepath, ofb);
    } else {
        data->filepath[0] = '\0';
    }

    if (cmdline_addr > 0) {
        updateCmdline(cmdline_addr, data->cmdline);
    } else {
        data->cmdline[0] = '\0';
    }

    data->reserved_1 = 0;
    data->reserved_2 = 0;
    data->reserved_3 = 0;

    return true;
}

#if DEBUG
static inline __always_inline void dumpRawData(const char tag[], int event, proc_event_raw_t *data) {
    bpf_printk("[ztd] %s :: event      = %d", tag, data->event);
    bpf_printk("[ztd] %s :: event_time = %lu", tag, data->event_time);
    bpf_printk("[ztd] %s :: event size = %d", tag, sizeof(proc_event_raw_t));
    bpf_printk("[ztd] %s :: tid        = %d", tag, data->tid);
    bpf_printk("[ztd] %s :: pid        = %d", tag, data->pid);
    bpf_printk("[ztd] %s :: ppid       = %d", tag, data->ppid);
    bpf_printk("[ztd] %s :: syscall    = %d", tag, data->syscall);
    bpf_printk("[ztd] %s :: exit_code  = %d", tag, data->exit_code);
    bpf_printk("[ztd] %s :: uid        = %u", tag, data->uid);
    bpf_printk("[ztd] %s :: gid        = %u", tag, data->gid);
    bpf_printk("[ztd] %s :: suid       = %u", tag, data->suid);
    bpf_printk("[ztd] %s :: sgid       = %u", tag, data->sgid);
    bpf_printk("[ztd] %s :: euid       = %u", tag, data->euid);
    bpf_printk("[ztd] %s :: egid       = %u", tag, data->egid);
    bpf_printk("[ztd] %s :: fsuid      = %u", tag, data->fsuid);
    bpf_printk("[ztd] %s :: fsgid      = %u", tag, data->fsgid);
    bpf_printk("[ztd] %s :: owner_uid  = %u", tag, data->owner_uid);
    bpf_printk("[ztd] %s :: owner_gid  = %u", tag, data->owner_gid);
    bpf_printk("[ztd] %s :: atime      = %ld", tag, data->atime);
    bpf_printk("[ztd] %s :: mtime      = %ld", tag, data->mtime);
    bpf_printk("[ztd] %s :: ctime      = %ld", tag, data->ctime);
    bpf_printk("[ztd] %s :: cwd        = %s", tag, data->cwd);
    bpf_printk("[ztd] %s :: filepath   = %s", tag, data->filepath);
    bpf_printk("[ztd] %s :: cmdline    = %s", tag, data->cmdline);
    bpf_printk("[ztd] %s :: reserved_1 = %ld", tag, data->reserved_1);
    bpf_printk("[ztd] %s :: reserved_2 = %ld", tag, data->reserved_2);
    bpf_printk("[ztd] %s :: reserved_3 = %ld", tag, data->reserved_3);
}
#endif

static inline __always_inline void sendRawData(const char *tag, int32_t type, uint64_t key_material,
                                               proc_event_raw_t *data) {
    event_noti_t *noti = bpf_proc_creation_event_noti_reserve();
    if (!noti) {
#if DEBUG
        bpf_printk("[ztd] %s :: no ringbuf to reserve!", tag);
#endif
        return;
    }
    uint64_t key = (bpf_get_smp_processor_id() & 0x00000000000000FF) << 56 | key_material;
#if DEBUG
    bpf_printk("[ztd] %s :: type : %d, key : %lu", tag, type, key);
#endif
    bpf_proc_creation_data_map_update_elem(&key, data, BPF_ANY);

    noti->type = type;
    noti->key = key;
    bpf_proc_creation_event_noti_submit(noti);
}

static inline __always_inline void onSysEnterExecve(sys_enter_data_t *args) {
    uint64_t event_time = bpf_ktime_get_boot_ns();
    int32_t event = TRACE_EVENT_SYS_ENTER_EXECVE;
    int32_t syscall = args->id;
    int64_t cmdline_addr = args->args[1];
    const char tag[] = "ScExecve.sys_enter";

    uint32_t zero = 0; // Look-up Key
    proc_event_raw_t *data = bpf_proc_event_map_lookup_elem(&zero);
    if (!data) {
        return;
    }

    bool res = updateRawData(tag, event, event_time, syscall, cmdline_addr, false, false, data);
    if (!res) {
        return;
    }

#if DEBUG
    dumpRawData(tag, event, data);
#endif
    sendRawData(tag, event, event_time, data);
}

static inline __always_inline void onSchedProcessExec(sched_process_exec_args_t *args) {
    uint64_t event_time = bpf_ktime_get_boot_ns();
    int32_t event = TRACE_EVENT_SCHED_PROCESS_EXEC;
    int32_t syscall = GENERIC_SYSCALL_NR_EXECVE;
    int64_t cmdline_addr = 0;
    const char tag[] = "ScExecve.sched_process_exec";

    uint32_t zero = 0; // Look-up Key
    proc_event_raw_t *data = bpf_proc_event_map_lookup_elem(&zero);
    if (!data) {
        return;
    }

    bool res = updateRawData(tag, event, event_time, syscall, cmdline_addr, true, false, data);
    if (!res) {
        return;
    }

    char *filename_ptr = (char *)((uint64_t)args + (uint64_t)(args->filename_loc & 0xffff));
    updateFilePath(filename_ptr, data->filepath);

#if DEBUG
    dumpRawData(tag, event, data);
#endif
    sendRawData(tag, event, event_time, data);
}

static inline __always_inline void onSysExitExecve(sys_exit_data_t *args) {
    uint64_t event_time = bpf_ktime_get_boot_ns();
    int32_t event = TRACE_EVENT_SYS_EXIT_EXECVE;
    int32_t syscall = args->id;
    int64_t cmdline_addr = 0;
    const char tag[] = "ScExecve.sys_exit";

    uint32_t zero = 0; // Look-up Key
    proc_event_raw_t *data = bpf_proc_event_map_lookup_elem(&zero);
    if (!data) {
        return;
    }

    bool res = updateRawData(tag, event, event_time, syscall, cmdline_addr, true, false, data);
    if (!res) {
        return;
    }

#if DEBUG
    dumpRawData(tag, event, data);
#endif
    sendRawData(tag, event, event_time, data);
}

static inline __always_inline void onTaskRename(task_rename_data_t *args) {
    uint64_t event_time = bpf_ktime_get_boot_ns();
    char oldcomm[MAX_TASK_COMM_LEN] = {};
    bpf_probe_read_kernel_str(&oldcomm, MAX_TASK_COMM_LEN, &args->oldcomm);
    if (oldcomm[0] != 'c' ||
            oldcomm[1] != 'h' ||
            oldcomm[2] != '_' ||
            oldcomm[3] != 'z' ||
            oldcomm[4] != 'y' ||
            oldcomm[5] != 'g' ||
            oldcomm[6] != 'o' ||
            oldcomm[7] != 't' ||
            oldcomm[8] != 'e' ||
            oldcomm[9] != '\0') {
        return;
    }
    int32_t event = TRACE_EVENT_TASK_RENAME;
    int32_t syscall = GENERIC_SYSCALL_NR_EXECVE;
    int64_t cmdline_addr = 0;
    const char tag[] = "ScExecve.task_rename";

    uint32_t zero = 0; // Look-up Key
    proc_event_raw_t *data = bpf_proc_event_map_lookup_elem(&zero);
    if (!data) {
        return;
    }

    bool res = updateRawData(tag, event, event_time, syscall, cmdline_addr, true, true, data);
    if (!res) {
        return;
    }

#if DEBUG
    dumpRawData(tag, event, data);
#endif
    sendRawData(tag, event, event_time, data);
}

DEFINE_SC_TRACEPOINT(raw_syscalls, sys_enter, sc_execve_enter)
(sys_enter_data_t *args) {
    if (args->id == GENERIC_SYSCALL_NR_EXECVE) {
#if DEBUG_ENTRY
        bpf_printk("[ztd] sys_enter :: NR = %ld", args->id);
#endif
        onSysEnterExecve(args);
    }
    return 1;
}

DEFINE_SC_TRACEPOINT(raw_syscalls, sys_exit, sc_execve_exit)
(sys_exit_data_t *args) {
    if (args->id == GENERIC_SYSCALL_NR_EXECVE) {
#if DEBUG_ENTRY
        bpf_printk("[ztd] sys_exit :: NR = %ld", args->id);
#endif
        onSysExitExecve(args);
    }
    return 1;
}

DEFINE_PROC_TRACEPOINT(sched_process_exec)
(sched_process_exec_args_t *args) {
#if DEBUG_ENTRY
    void *filename_ptr = (void *)((uint64_t)args + (uint64_t)(args->filename_loc & 0xffff));
    bpf_printk("[ztd] sched_process_exec :: filename = %s, pid = %d, old_pid = %d",
               (char *)filename_ptr, args->pid, args->old_pid);
#endif
    onSchedProcessExec(args);
    return 1;
}

DEFINE_TASK_TRACEPOINT(task_rename)
(task_rename_data_t *args) {
#if DEBUG_ENTRY
    bpf_printk("[ztd] task_rename :: pid = %d, oldcomm = %s, newcomm = %s",
               args->pid, args->oldcomm, args->newcomm);
#endif
    uint64_t pid_tgid = bpf_get_current_pid_tgid();
    int32_t pid = (int32_t) (pid_tgid);
    int32_t tgid = (int32_t) (pid_tgid >> 32);
    if (pid == tgid) {
        onTaskRename(args);
    }
    return 1;
}

LICENSE("GPL");