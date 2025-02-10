
#include "bpf_shared.h"
#include "bpf_read.h"
#include <ztd_events.h>
#include <ztd_sk_shared.h>

#define DEBUG 0
#define DEBUG_ENTRY 0

DEFINE_BPF_MAP_GRW(sock_data_map, LRU_HASH, uint64_t, sock_event_raw_t, 1024, AID_SYSTEM);
DEFINE_BPF_MAP_GRW(sock_event_map, PERCPU_ARRAY, uint32_t, sock_event_raw_t, 1, AID_SYSTEM);
DEFINE_BPF_RINGBUF_EXT(event_noti_ringbuf, event_noti_t, 4096, AID_ROOT, AID_SYSTEM, 0660, "", "", PRIVATE,
                       BPFLOADER_MIN_VER, BPFLOADER_MAX_VER, LOAD_ON_ENG, LOAD_ON_USER, LOAD_ON_USERDEBUG);
DEFINE_BPF_SHARED_MAP_GRW(offsets_frame_map, ARRAY, uint32_t, offsets_frame_buf_t, 1, AID_SYSTEM);

#define MAX_PATH_DEPTH 128

struct inet_sock_state_args {
    uint64_t common;                // 8 bytes
    const void* skaddr;
    int oldstate;
    int newstate;
    uint16_t sport;
    uint16_t dport;
    uint16_t family;
    uint16_t protocol;
    uint8_t saddr[4];
    uint8_t daddr[4];
    uint8_t saddr_v6[16];
    uint8_t daddr_v6[16];
};

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

static inline __always_inline void checkSocket(struct inet_sock_state_args *args) {

    uint64_t event_time = bpf_ktime_get_boot_ns();

    ENSURE_POSITIVE_STATE(args->newstate);

    uint32_t zero = 0; // Look-up Key
    offsets_frame_buf_t *ofb = bpf_offsets_frame_map_lookup_elem(&zero);
    if (!ofb) {
        return;
    }

    struct task_struct *task = (struct task_struct *) bpf_get_current_task();
    if (!task) {
        return;
    }

    sock_event_raw_t *data = bpf_sock_event_map_lookup_elem(&zero);
    if (!data) {
        return;
    }

    int event = TRACE_EVENT_INET_SOCK_SET_STATE;
    data->event = event;
    data->event_time = event_time;

    int syscall = 0;
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
    kgid_t gid = BPF_READ_AT(cred, gid, ofb->offsets[OFFSET_GID_IN_CRED]);
    data->gid = gid.value;

    data->oldstate = args->oldstate;
    data->newstate = args->newstate;
    data->fd = -1;
    data->family = args->family;

    struct sock *sock = NULL;
    bpf_probe_read_kernel(&sock, sizeof(void *), &args->skaddr);
    uint16_t sk_type = BPF_READ_AT(sock, sk_type, ofb->offsets[OFFSET_SK_TYPE_IN_SOCK]);
    data->type = sk_type;

    kuid_t sk_uid = BPF_READ_AT(sock, sk_uid, ofb->offsets[OFFSET_SK_UID_IN_SOCK]);
    data->uid = sk_uid.value;

    data->protocol = args->protocol;
    data->sport = args->sport;
    data->dport = args->dport;

    if (args->family == AF_INET) { // AF_INET(2)
        __builtin_memcpy(&data->saddr, args->saddr, sizeof(data->saddr));
        __builtin_memcpy(&data->daddr, args->daddr, sizeof(data->daddr));
    } else {                       // AF_INET6(10)
        __builtin_memcpy(&data->saddr_v6, args->saddr_v6, sizeof(data->saddr_v6));
        __builtin_memcpy(&data->daddr_v6, args->daddr_v6, sizeof(data->daddr_v6));
    }

    struct mm_struct *mm = BPF_READ_AT(task, mm, ofb->offsets[OFFSET_MM_IN_TASK_STRUCT]);
    struct file *exe_file = BPF_READ_AT(mm, exe_file, ofb->offsets[OFFSET_EXE_FILE_IN_MM_STRUCT]);
    struct path *f_path = BPF_READ_ADDR_AT(exe_file, f_path, ofb->offsets[OFFSET_F_PATH_IN_FILE]);

    updatePathName(f_path, data->filepath, ofb);
#if DEBUG
    bpf_printk("[ztd] Sk.inet_sock_state :: event      = %d", event);
    bpf_printk("[ztd] Sk.inet_sock_state :: event_time = %lu", event_time);
    bpf_printk("[ztd] Sk.inet_sock_state :: event size = %d", sizeof(sock_event_raw_t));
    bpf_printk("[ztd] Sk.inet_sock_state :: tid        = %d", pid);
    bpf_printk("[ztd] Sk.inet_sock_state :: pid        = %d", tgid);
    bpf_printk("[ztd] Sk.inet_sock_state :: ppid       = %d", ptgid);
    bpf_printk("[ztd] Sk.inet_sock_state :: syscall    = %d", syscall);
    bpf_printk("[ztd] Sk.inet_sock_state :: exit_code  = %d", exit_code);
    bpf_printk("[ztd] Sk.inet_sock_state :: uid        = %u", *((int *) &uid));
    bpf_printk("[ztd] Sk.inet_sock_state :: gid        = %u", *((int *) &gid));
    bpf_printk("[ztd] Sk.inet_sock_state :: oldstate   = %d", data->oldstate);
    bpf_printk("[ztd] Sk.inet_sock_state :: newstate   = %d", data->newstate);
    bpf_printk("[ztd] Sk.inet_sock_state :: fd         = %d", data->fd);
    bpf_printk("[ztd] Sk.inet_sock_state :: family     = %u", data->family);
    bpf_printk("[ztd] Sk.inet_sock_state :: type       = %u", data->type);
    bpf_printk("[ztd] Sk.inet_sock_state :: protocol   = %u", data->protocol);
    bpf_printk("[ztd] Sk.inet_sock_state :: sport      = %u", data->sport);
    bpf_printk("[ztd] Sk.inet_sock_state :: dport      = %u", data->dport);
    bpf_printk("[ztd] Sk.inet_sock_state :: filepath   = %s", data->filepath);
#endif

    uint64_t cpu_id = bpf_get_smp_processor_id();
    uint64_t key = (cpu_id & 0x00000000000000FF) << 56 | event_time;
#if DEBUG
    bpf_printk("[ztd] Sk.inet_sock_state :: cpu_id = %lu, event_time = %lu, key = %lu", cpu_id, event_time, key);
#endif
    bpf_sock_data_map_update_elem(&key, data, BPF_ANY);
    event_noti_t *noti = bpf_event_noti_ringbuf_reserve();
    if (!noti) {
#if DEBUG
        bpf_printk("[ztd] Sk.inet_sock_state :: no ringbuf to reserve!");
#endif
        return;
    }
    noti->type = TRACE_EVENT_INET_SOCK_SET_STATE;
    noti->key = key;
    bpf_event_noti_ringbuf_submit(noti);
}

DEFINE_SK_TRACEPOINT(sock, inet_sock_set_state)
(struct inet_sock_state_args *args) {
#if DEBUG_ENTRY
    bpf_printk("[ztd] inet_sock_set_state :: family = %u", args->family);
#endif
    checkSocket(args);
    return 1;
}

LICENSE("GPL");