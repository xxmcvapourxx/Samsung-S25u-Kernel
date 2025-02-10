
#include "bpf_shared.h"
#include <ztd_sc_shared.h>

#define DEBUG_ENTRY 0

DEFINE_BPF_MAP_GRW(sc_memfd_create_data_map, HASH, uint64_t, sc_memfd_create_data_t, 128, AID_SYSTEM);
//DEFINE_BPF_SHARED_MAP_GRW(sc_tracer_map, ARRAY, uint32_t, sc_tracer_t, 1, AID_SYSTEM);

#if USE_RINGBUF
DEFINE_BPF_RINGBUF_EXT(sc_data_ringbuf, sc_data_t, 4096, AID_ROOT, AID_SYSTEM, 0660, "", "", SHARED,
                       BPFLOADER_MIN_VER, BPFLOADER_MAX_VER, LOAD_ON_ENG, LOAD_ON_USER, LOAD_ON_USERDEBUG);

#endif

static inline __always_inline void onSyscallMemfd_createEnter(sys_enter_data_t *args) {
    uint64_t event_time = bpf_ktime_get_boot_ns();
    uint64_t uid_gid = bpf_get_current_uid_gid();

#if DEBUG_ENTRY
    bpf_printk("[ztd] sys_enter :: -----start----- : time %s", event_time);
#endif

    if (args->id == GENERIC_SYSCALL_NR_MEMFD_CREATE) {
        sc_memfd_create_data_t data = {};
        data.base_data.event_time = event_time;
        data.base_data.uid_gid = uid_gid;
        data.base_data.pid_tgid = bpf_get_current_pid_tgid();
        bpf_get_current_comm(&data.base_data.comm, sizeof(data.base_data.comm));
        // syscall number 279	memfd_create	arg[0]:const char * uname_ptr	arg[1]:unsigned int flags
        bpf_probe_read_user_str(data.uname_ptr, sizeof(data.uname_ptr), POINTER_OF_USER_SPACE(args->args[0]));
        data.flags = (uint32_t) args->args[1];
#if DEBUG_ENTRY
        bpf_printk("[ztd] sys_enter :: GENERIC_SYSCALL_NR_MEMFD_CREATE");
        bpf_printk("[ztd] sys_enter :: uname_ptr = %s", data.uname_ptr);
        bpf_printk("[ztd] sys_enter :: flags = %10d", data.flags);
#endif
        uint64_t key = data.base_data.pid_tgid;
        bpf_sc_memfd_create_data_map_update_elem(&key, &data, BPF_ANY);
    }

#if DEBUG_ENTRY
    bpf_printk("[ztd] sys_enter :: -----end-----");
#endif
}

static inline __always_inline void onSyscallMemfd_createExit(sys_exit_data_t *args) {
    uint64_t key = bpf_get_current_pid_tgid();

    if (args->id == GENERIC_SYSCALL_NR_MEMFD_CREATE) {
        sc_memfd_create_data_t * data = bpf_sc_memfd_create_data_map_lookup_elem(&key);

        if (data) {
            data->ret = args->ret;
#ifdef USE_RINGBUF
            sc_data_t *output = bpf_sc_data_ringbuf_reserve();
            if (output == NULL) return;

            output->event = TRACE_EVENT_SYS_MEMFD_CREATE;
            output->nr = args->id; //GENERIC_SYSCALL_NR_MEMFD_CREATE
            __builtin_memcpy(&output->u.sc_memfd_create.data, data, sizeof(sc_memfd_create_data_t));

            bpf_sc_data_ringbuf_submit(output);
#endif
            bpf_sc_memfd_create_data_map_delete_elem(&key);
        }
    }
}

DEFINE_SC_TRACEPOINT(raw_syscalls, sys_enter, sc_memfd_create_enter)
(sys_enter_data_t *args) {
    if (args->id == GENERIC_SYSCALL_NR_MEMFD_CREATE) {
#if DEBUG_ENTRY
        bpf_printk("[ztd] sys_enter :: NR = %ld", args->id);
#endif
        onSyscallMemfd_createEnter(args);
    }
    return 1;
}

DEFINE_SC_TRACEPOINT(raw_syscalls, sys_exit, sc_memfd_create_exit)
(sys_exit_data_t *args) {
    if (args->id == GENERIC_SYSCALL_NR_MEMFD_CREATE) {
#if DEBUG_ENTRY
        bpf_printk("[ztd] sys_exit :: NR = %ld", args->id);
#endif
        onSyscallMemfd_createExit(args);
    }
    return 1;
}

LICENSE("GPL");