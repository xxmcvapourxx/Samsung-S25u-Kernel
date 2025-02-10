#ifndef BPF_READ_H
#define BPF_READ_H

// #include <bpf_helpers.h>

static int (*bpf_probe_read_kernel)(void* dst, int size, const void* safe_ptr) = (void*)BPF_FUNC_probe_read_kernel;


// This macro must be used for variable which is either primitive or pointer type.
#define BPF_READ_AT(source, field, offset) ({ \
    typeof((source)->field) result; \
    bpf_probe_read_kernel(&result, sizeof(typeof((source)->field)), (void *) ((char *) source + (offset))); \
    result; \
})

// This macro must be used for variable which is not primitive nor pointer type.
#define BPF_READ_ADDR_AT(source, field, offset) ({ \
    typeof((source)->field) *addr = (void *) ((char *) source + (offset)); \
    addr; \
})

#endif // BPF_READ_H