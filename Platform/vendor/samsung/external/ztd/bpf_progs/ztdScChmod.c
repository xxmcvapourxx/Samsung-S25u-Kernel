
#include "bpf_shared.h"
#include <ztd_sc_shared.h>

#define DEBUG_ENTRY 0

DEFINE_BPF_MAP_GRW(sc_fchmod_data_map, HASH, uint64_t, sc_fchmod_data_t, 128, AID_SYSTEM);
DEFINE_BPF_MAP_GRW(sc_fchmodat_data_map, HASH, uint64_t, sc_fchmodat_data_t, 128, AID_SYSTEM);
//DEFINE_BPF_SHARED_MAP_GRW(sc_tracer_map, ARRAY, uint32_t, sc_tracer_t, 1, AID_SYSTEM);

#if USE_RINGBUF
DEFINE_BPF_RINGBUF_EXT(sc_data_ringbuf, sc_data_t, 4096, AID_ROOT, AID_SYSTEM, 0660, "", "", SHARED,
                       BPFLOADER_MIN_VER, BPFLOADER_MAX_VER, LOAD_ON_ENG, LOAD_ON_USER, LOAD_ON_USERDEBUG);

#endif

static inline __always_inline void onSyscallChmodEnter(sys_enter_data_t *args) {
    uint64_t event_time = bpf_ktime_get_boot_ns();
    uint64_t uid_gid = bpf_get_current_uid_gid();

#if DEBUG_ENTRY
    bpf_printk("[ztd] sys_enter :: -----start----- : time %s", event_time);
#endif

    if (args->id == GENERIC_SYSCALL_NR_FCHMOD) {
        sc_fchmod_data_t data = {};
        data.base_data.event_time = event_time;
        data.base_data.uid_gid = uid_gid;
        data.base_data.pid_tgid = bpf_get_current_pid_tgid();
        bpf_get_current_comm(&data.base_data.comm, sizeof(data.base_data.comm));
        // syscall number 52	fchmod	arg[0]:unsigned int fd	arg[1]:umode_t mode
        data.dfd = (int) args->args[0];
        data.mode = (mode_t) args->args[1];
#if DEBUG_ENTRY
        bpf_printk("[ztd] sys_enter :: GENERIC_SYSCALL_NR_FCHMOD");
        bpf_printk("[ztd] sys_enter :: dfd = %10d", data.dfd);
        bpf_printk("[ztd] sys_enter :: mode = %10d", data.mode);
#endif
        uint64_t key = data.base_data.pid_tgid;
        bpf_sc_fchmod_data_map_update_elem(&key, &data, BPF_ANY);
    } else if (args->id == GENERIC_SYSCALL_NR_FCHMODAT) {
        sc_fchmodat_data_t data = {};
        data.base_data.event_time = event_time;
        data.base_data.uid_gid = uid_gid;
        data.base_data.pid_tgid = bpf_get_current_pid_tgid();
        bpf_get_current_comm(&data.base_data.comm, sizeof(data.base_data.comm));
        // syscall number 53	fchmodat	arg[0]:int dfd	arg[1]:const char * filename	arg[2]umode_t mode
        data.dfd = (int) args->args[0];
        bpf_probe_read_user_str(data.filename, sizeof(data.filename), POINTER_OF_USER_SPACE(args->args[1]));
        data.mode = (mode_t) args->args[2];
        //data.flags = (int) args->args[3];
#if DEBUG_ENTRY
        bpf_printk("[ztd] sys_enter :: GENERIC_SYSCALL_NR_FCHMODAT");
        bpf_printk("[ztd] sys_enter :: dfd = %10d", data.dfd);
        bpf_printk("[ztd] sys_enter :: filename = %s", data.filename);
        bpf_printk("[ztd] sys_enter :: mode = %10d", data.mode);
#endif
        uint64_t key = data.base_data.pid_tgid;
        bpf_sc_fchmodat_data_map_update_elem(&key, &data, BPF_ANY);
    }
#if DEBUG_ENTRY
    bpf_printk("[ztd] sys_enter :: -----end-----");
#endif
}

static inline __always_inline void onSyscallChmodExit(sys_exit_data_t *args) {
    uint64_t key = bpf_get_current_pid_tgid();

    if (args->id == GENERIC_SYSCALL_NR_FCHMOD) {
        sc_fchmod_data_t * data = bpf_sc_fchmod_data_map_lookup_elem(&key);

        if (data) {
            data->ret = args->ret;
#ifdef USE_RINGBUF
            sc_data_t *output = bpf_sc_data_ringbuf_reserve();
            if (output == NULL) return;

            output->event = TRACE_EVENT_SYS_FCHMOD;
            output->nr = args->id; //GENERIC_SYSCALL_NR_FCHMOD
            __builtin_memcpy(&output->u.sc_fchmod.data, data, sizeof(sc_fchmod_data_t));

            bpf_sc_data_ringbuf_submit(output);
#endif
            bpf_sc_fchmod_data_map_delete_elem(&key);
        }
    } else if (args->id == GENERIC_SYSCALL_NR_FCHMODAT) {
        sc_fchmodat_data_t * data = bpf_sc_fchmodat_data_map_lookup_elem(&key);

        if (data) {
            data->ret = args->ret;
#ifdef USE_RINGBUF
            sc_data_t *output = bpf_sc_data_ringbuf_reserve();
            if (output == NULL) return;

            output->event = TRACE_EVENT_SYS_FCHMODAT;
            output->nr = args->id; //GENERIC_SYSCALL_NR_FCHMODAT
            __builtin_memcpy(&output->u.sc_fchmodat.data, data, sizeof(sc_fchmodat_data_t));

            bpf_sc_data_ringbuf_submit(output);
#endif
            bpf_sc_fchmodat_data_map_delete_elem(&key);
        }
    }
}

DEFINE_SC_TRACEPOINT(raw_syscalls, sys_enter, sc_chmod_enter)
(sys_enter_data_t *args) {
    if (args->id == GENERIC_SYSCALL_NR_FCHMOD || args->id == GENERIC_SYSCALL_NR_FCHMODAT) {
#if DEBUG_ENTRY
        bpf_printk("[ztd] sys_enter :: NR = %ld", args->id);
#endif
        onSyscallChmodEnter(args);
    }
    return 1;
}

DEFINE_SC_TRACEPOINT(raw_syscalls, sys_exit, sc_chmod_exit)
(sys_exit_data_t *args) {
    if (args->id == GENERIC_SYSCALL_NR_FCHMOD || args->id == GENERIC_SYSCALL_NR_FCHMODAT) {
#if DEBUG_ENTRY
        bpf_printk("[ztd] sys_exit :: NR = %ld", args->id);
#endif
        onSyscallChmodExit(args);
    }
    return 1;
}

LICENSE("GPL");