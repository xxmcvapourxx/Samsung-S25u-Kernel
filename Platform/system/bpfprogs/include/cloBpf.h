#pragma once

// This header file is shared by eBPF kernel programs (C) and netd (C++) and
// some of the maps are also accessed directly from Java mainline module code.
//
// Hence: explicitly pad all relevant structures and assert that their size
// is the sum of the sizes of their fields.
#define STRUCT_SIZE(name, size) _Static_assert(sizeof(name) == (size), "Incorrect struct size.")

#define CLO_BPF_PATH "/sys/fs/bpf/"
// PATH - PROGRAM
#define PATH_CLO_INGRESS_PROG CLO_BPF_PATH "prog_cloBpf_schedcls_ingress_CloIngress"
#define PATH_CLO_EGRESS_PROG CLO_BPF_PATH "prog_cloBpf_schedcls_egress_CloEgress"

// PATH - MAP
#define PATH_CLO_RX_STATS_MAP CLO_BPF_PATH "map_cloBpf_clo_rx_stats_map"
#define PATH_CLO_TX_STATS_MAP CLO_BPF_PATH "map_cloBpf_clo_tx_stats_map"
#define PATH_CLO_RX_FLOW_STATS_MAP CLO_BPF_PATH "map_cloBpf_clo_rx_flow_stats_map"
#define PATH_CLO_TX_FLOW_STATS_MAP CLO_BPF_PATH "map_cloBpf_clo_tx_flow_stats_map"
#define PATH_CLO_RX_FLOW_LIST_INFO_MAP CLO_BPF_PATH "map_cloBpf_clo_rx_flow_list_info_map"
#define PATH_CLO_RX_FLOW_LIST CLO_BPF_PATH "map_cloBpf_clo_rx_flow_list_map"

#define PATH_CLO_GRO_POLICY_MAP CLO_BPF_PATH "map_cloBpf_clo_gro_policy_map"
#define PATH_CLO_HO_POLICY_MAP CLO_BPF_PATH "map_cloBpf_clo_ho_policy_map"
#define PATH_CLO_AP_TICK_MAP CLO_BPF_PATH "map_cloBpf_clo_ap_tick_map"

// RTT MEASUREMENT CONFIGURATION
#define CLO_RTT_TX_PIVOT_EXPIRE_INTERVAL_US 5000000L
#define CLO_RTT_RX_MAX_SAMPLE_COUNT 8

const int CLO_GRO_POLICY_MAP_SIZE = (1<<0);

const int CLO_HO_POLICY_MAP_SIZE = (1<<16);
typedef struct {
    uint16_t target_window;
} CloHoPolicy;
STRUCT_SIZE(CloHoPolicy, sizeof(CloHoPolicy));

const int CLO_TX_STATS_MAP_SIZE = (1 << 0);

const int CLO_RX_STATS_MAP_SIZE = (1 << 0);
typedef struct {
    uint64_t rx_bytes;
    uint64_t rx_count_pkt;
    uint64_t rx_count_psh;
} CloRxStats;
STRUCT_SIZE(CloRxStats, sizeof(CloRxStats));

const int CLO_TX_FLOW_STATS_MAP_SIZE = (1 << 16);
typedef struct {
    uint16_t sport;
    uint64_t tx_tick_num;
    uint64_t tx_pivot_ktime_us;
    uint64_t tx_pivot_ts;

    uint64_t tx_last_rx_bytes;
} CloTxFlowStats;
STRUCT_SIZE(CloTxFlowStats, sizeof(CloTxFlowStats));

const int CLO_RX_FLOW_STATS_MAP_SIZE = (1 << 16);
typedef struct {
    uint16_t dport;
    uint64_t rx_syn_tick;

    // RTT
    uint64_t rx_rtt_sum_ms;
    uint64_t rx_rtt_sum_count;
    uint64_t rx_rtt_last_tsecr;
    uint8_t  rx_rtt_sample_count;
    uint32_t rx_rtt_us;
    uint32_t rx_rtt_min_ms;
    uint64_t rx_rtt_tick_num;

    // BYTES
    uint64_t rx_sum_bytes;

    // LIST
    uint64_t rx_list_updated_tick;
} CloRxFlowStats;
STRUCT_SIZE(CloRxFlowStats, sizeof(CloRxFlowStats));

const int CLO_RX_FLOW_LIST_SIZE = (1<<16);
const int CLO_RX_FLOW_LIST_INFO_SIZE = (1<<0);
typedef struct {
    uint64_t last_tick_num;
    uint16_t flow_count;
} CloRxFlowListInfo;
STRUCT_SIZE(CloRxFlowListInfo, sizeof(CloRxFlowListInfo));

#define CLO_BPF_MAP_UNIQUE_KEY 0
const int CLO_AP_MONITOR_STATS_MAP_SIZE = (1<<0);

const int CLO_AP_TICK_SIZE = (1<<0);
typedef struct {
    uint64_t tick_us;
    uint64_t tick_num;
} CloApTick;
STRUCT_SIZE(CloApTick, sizeof(CloApTick));

#undef STRUCT_SIZE