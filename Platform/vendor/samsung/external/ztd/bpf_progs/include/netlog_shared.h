#pragma once

#include <sys/types.h>

#define PROG_INSECURE_PORTS     "insecureports"
#define PROG_ABNORMAL_PACKETS   "abnormalpackets"
#define PROG_LOCALNW_PACKETS    "localnwpackets"

#define XT_BPF_NETLOG(NAME) "/sys/fs/bpf/prog_netlog_skfilter_" NAME "_xtbpf"

#define XT_BPF_INSECUREPORTS_PROG_PATH XT_BPF_NETLOG(PROG_INSECURE_PORTS)
#define XT_BPF_ABNORMALPACKETS_PROG_PATH XT_BPF_NETLOG(PROG_ABNORMAL_PACKETS)
#define XT_BPF_LOCALNWPACKETS_PROG_PATH XT_BPF_NETLOG(PROG_LOCALNW_PACKETS)

#define INSECURE_PORTS_RINGBUF_PATH "/sys/fs/bpf/map_netlog_insecure_ports_ringbuf"
#define ABNORMAL_PKT_RINGBUF_PATH   "/sys/fs/bpf/map_netlog_abnormal_pkts_ringbuf"
#define LOCAL_NW_RINGBUF_PATH       "/sys/fs/bpf/map_netlog_localnw_pkts_ringbuf"
#define SOCKET_DATA_MAP_PATH        "/sys/fs/bpf/map_netlog_socket_data_map"

#define EVENT_TYPE_INSECURE_PORTS   1
#define EVENT_TYPE_ABNORMAL_PACKETS 2
#define EVENT_TYPE_LOCALNW_PACKETS  3

#ifndef AF_INET
#define AF_INET    2
#endif

typedef struct socket_data
{
    uint32_t event_type;
    uint64_t timestamp;
    uint32_t uid;
    uint32_t ifindex;
    uint16_t family;
    uint8_t protocol;
    uint16_t src_port;
    uint16_t dest_port;
    uint32_t src_ip;
    uint32_t dest_ip;
} socket_data_t;