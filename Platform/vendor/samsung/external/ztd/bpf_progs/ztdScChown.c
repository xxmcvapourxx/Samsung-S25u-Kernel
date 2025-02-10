
#include "bpf_shared.h"
#include <ztd_sc_shared.h>

#define DEBUG_ENTRY 0

DEFINE_BPF_MAP_GRW(sc_fchownat_data_map, HASH, uint64_t, sc_fchownat_data_t, 128, AID_SYSTEM);
DEFINE_BPF_MAP_GRW(sc_fchown_data_map, HASH, uint64_t, sc_fchown_data_t, 128, AID_SYSTEM);

#if USE_RINGBUF
DEFINE_BPF_RINGBUF_EXT(sc_data_ringbuf, sc_data_t, 4096, AID_ROOT, AID_SYSTEM, 0660, "", "", SHARED,
                       BPFLOADER_MIN_VER, BPFLOADER_MAX_VER, LOAD_ON_ENG, LOAD_ON_USER, LOAD_ON_USERDEBUG);
#endif

static inline __always_inline void onSyscallFchownatEnter(sys_enter_data_t *args) {
    sc_fchownat_data_t data = {};
    data.base_data.event_time = bpf_ktime_get_boot_ns();
    data.base_data.pid_tgid = bpf_get_current_pid_tgid();
    data.base_data.uid_gid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&data.base_data.comm, sizeof(data.base_data.comm));

    data.dfd = (int) args->args[0];
    bpf_probe_read_user_str(data.filename, sizeof(data.filename), POINTER_OF_USER_SPACE(args->args[1]));
    data.owner = (int) args->args[2];
    data.group = (int) args->args[3];
    data.flag = (int) args->args[4];

    uint64_t key = data.base_data.pid_tgid;
    bpf_sc_fchownat_data_map_update_elem(&key, &data, BPF_ANY);
}

static inline __always_inline void onSyscallFchownatExit(sys_exit_data_t *args) {
    uint64_t key = bpf_get_current_pid_tgid();
    sc_fchownat_data_t *data = bpf_sc_fchownat_data_map_lookup_elem(&key);

    if (data) {
        data->ret = args->ret;
#ifdef USE_RINGBUF
        sc_data_t *output = bpf_sc_data_ringbuf_reserve();
        if (output == NULL) return;

        output->event = TRACE_EVENT_SYS_FCHOWNAT;
        output->nr = args->id;
        __builtin_memcpy(&output->u.sc_fchownat.data, data, sizeof(sc_fchownat_data_t));

        bpf_sc_data_ringbuf_submit(output);
#endif
        bpf_sc_fchownat_data_map_delete_elem(&key);
    }
}

static inline __always_inline void onSyscallFchownEnter(sys_enter_data_t *args) {
    sc_fchown_data_t data = {};
    data.base_data.event_time = bpf_ktime_get_boot_ns();
    data.base_data.pid_tgid = bpf_get_current_pid_tgid();
    data.base_data.uid_gid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&data.base_data.comm, sizeof(data.base_data.comm));

    data.fd = (int) args->args[0];
    data.owner = (int) args->args[1];
    data.group = (int) args->args[2];

    uint64_t key = data.base_data.pid_tgid;
    bpf_sc_fchown_data_map_update_elem(&key, &data, BPF_ANY);
}

static inline __always_inline void onSyscallFchownExit(sys_exit_data_t *args) {
    uint64_t key = bpf_get_current_pid_tgid();
    sc_fchown_data_t *data = bpf_sc_fchown_data_map_lookup_elem(&key);

    if (data) {
        data->ret = args->ret;
#ifdef USE_RINGBUF
        sc_data_t *output = bpf_sc_data_ringbuf_reserve();
        if (output == NULL) return;

        output->event = TRACE_EVENT_SYS_FCHOWN;
        output->nr = args->id;
        __builtin_memcpy(&output->u.sc_fchown.data, data, sizeof(sc_fchown_data_t));

        bpf_sc_data_ringbuf_submit(output);
#endif
        bpf_sc_fchown_data_map_delete_elem(&key);
    }
}

DEFINE_SC_TRACEPOINT(raw_syscalls, sys_enter, sc_chown_enter)
(sys_enter_data_t *args) {
    if (args->id == GENERIC_SYSCALL_NR_FCHOWNAT) {
#if DEBUG_ENTRY
        bpf_printk("[ztd] sys_enter :: NR = %ld", args->id);
#endif
        onSyscallFchownatEnter(args);
    }
    if (args->id == GENERIC_SYSCALL_NR_FCHOWN) {
#if DEBUG_ENTRY
        bpf_printk("[ztd] sys_enter :: NR = %ld", args->id);
#endif
        onSyscallFchownEnter(args);
    }
    return 1;
}

DEFINE_SC_TRACEPOINT(raw_syscalls, sys_exit, sc_chown_exit)
(sys_exit_data_t *args) {
    if (args->id == GENERIC_SYSCALL_NR_FCHOWNAT) {
#if DEBUG_ENTRY
        bpf_printk("[ztd] sys_exit :: NR = %ld", args->id);
#endif
        onSyscallFchownatExit(args);
    }
    if (args->id == GENERIC_SYSCALL_NR_FCHOWN) {
#if DEBUG_ENTRY
        bpf_printk("[ztd] sys_exit :: NR = %ld", args->id);
#endif
        onSyscallFchownExit(args);
    }
    return 1;
}

LICENSE("GPL");