#include <linux/bpf.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <stdbool.h>
#include <stdint.h>
#include <inttypes.h>
#include "bpf_helpers.h"
#include "include/cloBpf.h"

#include <linux/pkt_cls.h>
#include <linux/filter.h>

// bionic kernel uapi linux/udp.h header is munged...
#define __kernel_udphdr udphdr
#include <linux/udp.h>

#ifdef CLO_LOG
#include "include/cloBpfLogger.h"
#endif

DEFINE_BPF_MAP(clo_tx_stats_map, HASH, uint8_t, uint64_t, CLO_TX_STATS_MAP_SIZE)
DEFINE_BPF_MAP(clo_rx_stats_map, HASH, uint8_t, CloRxStats, CLO_RX_STATS_MAP_SIZE)
DEFINE_BPF_MAP(clo_tx_flow_stats_map, HASH, uint16_t, CloTxFlowStats, CLO_TX_FLOW_STATS_MAP_SIZE)
DEFINE_BPF_MAP(clo_rx_flow_stats_map, HASH, uint16_t, CloRxFlowStats, CLO_RX_FLOW_STATS_MAP_SIZE)
DEFINE_BPF_MAP(clo_rx_flow_list_info_map, HASH, uint8_t, CloRxFlowListInfo, CLO_RX_FLOW_LIST_INFO_SIZE)
DEFINE_BPF_MAP(clo_rx_flow_list_map, HASH, uint16_t, uint16_t, CLO_RX_FLOW_LIST_SIZE)

DEFINE_BPF_MAP(clo_gro_policy_map, HASH, uint8_t , uint8_t , CLO_GRO_POLICY_MAP_SIZE)
DEFINE_BPF_MAP(clo_ho_policy_map, HASH, uint16_t, CloHoPolicy, CLO_HO_POLICY_MAP_SIZE)
DEFINE_BPF_MAP(clo_ap_tick_map, HASH, uint8_t, CloApTick, CLO_AP_TICK_SIZE)

static int (*bpf_skb_load_bytes)(struct __sk_buff *skb, int off, void *to, int len) = (void *) BPF_FUNC_skb_load_bytes;
static int (*bpf_l4_csum_replace)(struct __sk_buff *skb, __u32 offset, __u64 from, __u64 to, __u64 flags) = (void *) BPF_FUNC_l4_csum_replace;
static int (*bpf_skb_store_bytes)(struct __sk_buff *skb, __u32 offset, const void *from, __u32 len, __u64 flags) = (void *) BPF_FUNC_skb_store_bytes;

#define CLO_TS_PASS 0
#define CLO_TS_SUCCESS 1
#define CLO_TS_FAILURE -1

#define TCP_ACK 0x10
#define TCP_PSH 0x08

#define TCP_FLAG_OFF 13

#define IP_HDR_PROTOCOL  (offsetof(struct iphdr, protocol))
#define IP_HDR_LENGTH    (sizeof(struct iphdr))

#define IPV6_HDR_PROTOCOL (offsetof(struct ipv6hdr, nexthdr))
#define IPV6_HDR_LENGTH   (sizeof(struct ipv6hdr))

#define TCP_HDR_LENGTH    (sizeof(struct tcphdr))
#define TCP_DPORT_OFF     offsetof(struct tcphdr, dest)
#define TCP_SPORT_OFF     offsetof(struct tcphdr, source)
#define TCP_CSUM_OFF      offsetof(struct tcphdr, check)

#define UDP_DPORT_OFF     offsetof(struct udphdr, dest)

// TCP OPTION FIELD
#define TCPOPT_NOP 1
#define TCPOPT_EOL 0
#define TCPOPT_TIMESTAMP 8

#define TCPOLEN_TIMESTAMP 10

// TCP DEFINES
#define TCP_MSS 1450
#define TCP_TS_HZ 1000
#define USEC_PER_SEC 1000000L
#define NSEC_PER_USEC 1000L
#define INT_MAX ((int)(~0U >> 1))

// Android only supports little endian architectures
#define htons(x) (__builtin_constant_p(x) ? ___constant_swab16(x) : __builtin_bswap16(x))
#define htonl(x) (__builtin_constant_p(x) ? ___constant_swab32(x) : __builtin_bswap32(x))
#define ntohs(x) htons(x)
#define ntohl(x) htonl(x)

#define IP_V4_NW htons(ETH_P_IP)
#define IP_V6_NW htons(ETH_P_IPV6)

static inline __attribute__((always_inline))
uint64_t div_u64(uint64_t dividend, uint64_t divisor) {
    return dividend / divisor;
}

static inline __attribute__((always_inline))
uint64_t clo_ktime_get_us() {
    return div_u64(bpf_ktime_get_ns(), NSEC_PER_USEC);
}

// Dynamic Right-Sizing (DRS)
static inline __attribute__((always_inline))
uint32_t clo_moving_average(uint32_t old, uint32_t new) {
    uint32_t new_sample = old;
    long m = new;

    if (new_sample != 0) {
        m -= (new_sample >> 3);
        new_sample += m;
    } else {
        new_sample = m << 3;
    }

    return new_sample;
}

static inline __attribute__((always_inline)) int
clo_read_tcp_option_field(struct __sk_buff *skb, uint8_t *fieldlength, uint8_t *ptr, uint32_t *ts, uint32_t *tsecr) {
    int ret;
    uint8_t opcode;
    uint8_t opsize;

    if (*fieldlength < 1) return CLO_TS_FAILURE; // No option field

    ret = bpf_skb_load_bytes(skb, *ptr, &opcode, 1);
    *ptr += 1;

    if (ret) return CLO_TS_FAILURE; // Load fail
    if (opcode == TCPOPT_EOL) return CLO_TS_FAILURE; // EOL
    if (opcode == TCPOPT_NOP) { *fieldlength -= 1; return CLO_TS_PASS; } // NOP

    // TCP Options
    ret = bpf_skb_load_bytes(skb, *ptr, &opsize, 1);
    *ptr += 1;
    if (ret) return CLO_TS_FAILURE; // Load Fail
    if (opsize < 2 || opsize > *fieldlength) return CLO_TS_FAILURE; // option size error

    if (opcode == TCPOPT_TIMESTAMP) { //Timestamp
        if (opsize == TCPOLEN_TIMESTAMP) {
            uint32_t _ts;
            uint32_t _tsecr;

            ret = bpf_skb_load_bytes(skb, *ptr, &_ts, 4);
            if (ret) return CLO_TS_FAILURE;
            _ts = ntohl(_ts);

            ret = bpf_skb_load_bytes(skb, *ptr + 4, &_tsecr, 4);
            if (ret) return CLO_TS_FAILURE;
            _tsecr = ntohl(_tsecr);

            *ts = _ts;
            *tsecr = _tsecr;
#ifdef CLO_LOG
            clo_printk("Timestamp: ts(%u), tsecr(%u)", _ts, _tsecr);
#endif
        }
        *ptr += opsize - 2;
        *fieldlength -= opsize;
        return CLO_TS_SUCCESS;
    }

    *ptr += opsize - 2;
    *fieldlength -= opsize;

    return CLO_TS_PASS;
}

// clo get ts option
static inline __attribute__((always_inline)) int
clo_get_timestamp_option(struct __sk_buff *skb, uint8_t offset, uint32_t *ts, uint32_t *tsecr) {
    int ret = 0;
    struct tcphdr th = {0};
    uint8_t field_length;
    uint8_t ptr;

    ret = bpf_skb_load_bytes(skb, offset, &th, TCP_HDR_LENGTH);
    if (ret) return CLO_TS_FAILURE;

    // Check tcp option fields and timestamp option
    field_length = (th.doff * 4) - TCP_HDR_LENGTH;
    ptr = offset + TCP_HDR_LENGTH + 1;

    // Try to check 4 times in tcp option field.
    ret = clo_read_tcp_option_field(skb, &field_length, &ptr, ts, tsecr);
    if (ret) return ret;
    ret = clo_read_tcp_option_field(skb, &field_length, &ptr, ts, tsecr);
    if (ret) return ret;
    ret = clo_read_tcp_option_field(skb, &field_length, &ptr, ts, tsecr);
    if (ret) return ret;
    ret = clo_read_tcp_option_field(skb, &field_length, &ptr, ts, tsecr);
    if (ret) return ret;

    return ret;
}

static inline __attribute__((always_inline)) CloRxFlowStats
clo_create_rx_stats(uint16_t dport) {
    // init rx_flow
    CloRxFlowStats new_rx_stats = {0};
    uint8_t tick_key = CLO_BPF_MAP_UNIQUE_KEY;
    CloApTick *tick = bpf_clo_ap_tick_map_lookup_elem(&tick_key);

    if (!tick) return new_rx_stats;

    new_rx_stats.dport = dport;
    new_rx_stats.rx_syn_tick = tick->tick_num;

    new_rx_stats.rx_rtt_sum_ms = 0;
    new_rx_stats.rx_rtt_sum_count = 0;
    new_rx_stats.rx_rtt_last_tsecr = 0;
    new_rx_stats.rx_rtt_sample_count = 0;
    new_rx_stats.rx_rtt_us = 0;
    new_rx_stats.rx_rtt_min_ms = 0xFFFFFFFF;
    new_rx_stats.rx_rtt_tick_num = 0;
    new_rx_stats.rx_sum_bytes = 0;
    new_rx_stats.rx_list_updated_tick = 0;

    return new_rx_stats;
}

static inline __attribute__((always_inline)) CloTxFlowStats
clo_create_tx_flow_stats(uint16_t sport) {
    // init tx_flow
    CloTxFlowStats new_tx_flow_stats = {0};

    new_tx_flow_stats.sport = sport;
    new_tx_flow_stats.tx_tick_num = 0;
    new_tx_flow_stats.tx_pivot_ktime_us = 0;
    new_tx_flow_stats.tx_pivot_ts = 0;
    new_tx_flow_stats.tx_last_rx_bytes = 0;

    return new_tx_flow_stats;
}

static inline __attribute__((always_inline)) void
clo_update_rx_flow_list(CloRxFlowStats *rx_stats) {
    uint8_t tick_key = CLO_BPF_MAP_UNIQUE_KEY;
    uint8_t flow_key = 0;

    CloRxFlowListInfo *list_info;
    CloApTick *tick;

    list_info = bpf_clo_rx_flow_list_info_map_lookup_elem(&flow_key);

    // init list_info
    if (!list_info) {
        CloRxFlowListInfo new_list_info = {0};
        new_list_info.last_tick_num = 0;
        new_list_info.flow_count = 0;

        bpf_clo_rx_flow_list_info_map_update_elem(&flow_key, &new_list_info, BPF_ANY);
        list_info = bpf_clo_rx_flow_list_info_map_lookup_elem(&flow_key);
        if (!list_info) return;
    }

    tick = bpf_clo_ap_tick_map_lookup_elem(&tick_key);
    if (!tick) return;

    if (tick->tick_num - list_info->last_tick_num > 4) { // 5 slots changed
        list_info->flow_count = 0;
        list_info->last_tick_num = tick->tick_num;
#ifdef CLO_LOG
        clo_printk("Ingress:%u list_info cleared", rx_stats->dport);
#endif
    }

    if (rx_stats->rx_list_updated_tick != list_info->last_tick_num) {
        uint16_t index = list_info->flow_count;

        list_info->flow_count += 1;
        bpf_clo_rx_flow_list_map_update_elem(&index, &rx_stats->dport, BPF_ANY);
        bpf_clo_rx_flow_list_info_map_update_elem(&flow_key, list_info, BPF_ANY);

        rx_stats->rx_list_updated_tick = list_info->last_tick_num;
#ifdef CLO_LOG
        clo_printk("Ingress:%u list_info inserted(%u)", list_info->flow_count);
        clo_printk("Ingress:%u list_info tick updated(%lu)", rx_stats->rx_list_updated_tick);
#endif
    }
}

static inline __attribute__((always_inline)) void
clo_update_tx_stats(struct __sk_buff *skb) {
    uint8_t unique_key = CLO_BPF_MAP_UNIQUE_KEY;
    uint64_t *tx_stats;

    tx_stats = bpf_clo_tx_stats_map_lookup_elem(&unique_key);
    if (!tx_stats) {
        uint64_t new_tx_stats = 0;
        bpf_clo_tx_stats_map_update_elem(&unique_key, &new_tx_stats, BPF_ANY);
        tx_stats = bpf_clo_tx_stats_map_lookup_elem(&unique_key);
        if (!tx_stats) return;
    }
    *tx_stats += skb->len;
    bpf_clo_tx_stats_map_update_elem(&unique_key, tx_stats, BPF_ANY);
}

static inline __attribute__((always_inline)) void
clo_update_rx_stats(struct __sk_buff *skb) {
    uint8_t unique_key = CLO_BPF_MAP_UNIQUE_KEY;
    CloRxStats *rx_stats;

    rx_stats = bpf_clo_rx_stats_map_lookup_elem(&unique_key);
    if (!rx_stats) {
        CloRxStats new_rx_stats = {0};

        new_rx_stats.rx_bytes = 0;
        new_rx_stats.rx_count_pkt = 0;
        new_rx_stats.rx_count_psh = 0;

        bpf_clo_rx_stats_map_update_elem(&unique_key, &new_rx_stats, BPF_ANY);
        rx_stats = bpf_clo_rx_stats_map_lookup_elem(&unique_key);
        if (!rx_stats) return;
    }
    rx_stats->rx_bytes += skb->len;
    rx_stats->rx_count_pkt += 1;
    bpf_clo_rx_stats_map_update_elem(&unique_key, rx_stats, BPF_ANY);
}

static inline __attribute__((always_inline)) void
clo_update_rx_flow_bytes(struct __sk_buff *skb, CloRxFlowStats *rx_stats) {
    rx_stats->rx_sum_bytes += skb->len;
}

static inline __attribute__((always_inline)) void
clo_update_rx_flow_rtt(struct __sk_buff *skb, uint8_t offset, CloRxFlowStats *rx_stats) {
    uint8_t tick_key = CLO_BPF_MAP_UNIQUE_KEY;
    CloTxFlowStats * tx_stats;
    CloApTick *tick;
    uint16_t dport = rx_stats->dport;

    // if ho flag , then reset rx_bytes, min rtt
    bpf_clo_rx_flow_stats_map_update_elem(&dport, rx_stats, BPF_EXIST);

    // rtt update
    tx_stats = bpf_clo_tx_flow_stats_map_lookup_elem(&dport);
#ifdef CLO_LOG
    if (!tx_stats) { clo_printk("Ingress:%u tx_flow null", dport); return; }
#else
    if (!tx_stats) return;
#endif

    tick = bpf_clo_ap_tick_map_lookup_elem(&tick_key);
    if (!tick) return;

    if (rx_stats->rx_rtt_tick_num != tick->tick_num) { // slot changed
        // operation per slot
        rx_stats->rx_rtt_tick_num = tick->tick_num;
        rx_stats->rx_rtt_last_tsecr = 0;
        rx_stats->rx_rtt_sample_count = 0;
        rx_stats->rx_rtt_sum_ms += ((rx_stats->rx_rtt_us >> 3) >> 10);
        rx_stats->rx_rtt_sum_count += 1;
#ifdef CLO_LOG
        clo_printk("Ingress:%u slot changed sum rtt %10lu", dport, rx_stats->rx_rtt_sum_ms);
        clo_printk("Ingress:%u slot changed sum count %10lu", dport, rx_stats->rx_rtt_sum_count);
#endif
    }

    if (rx_stats->rx_rtt_sample_count < CLO_RTT_RX_MAX_SAMPLE_COUNT) {
        uint32_t ts = 0;
        uint32_t tsecr = 0;
        uint32_t est_rtt;
        uint64_t ts_current;

        if (clo_get_timestamp_option(skb, offset, &ts, &tsecr) == CLO_TS_SUCCESS) { // hit timestamp
            uint64_t now_ktime = clo_ktime_get_us();
            ts_current = now_ktime - tx_stats->tx_pivot_ktime_us + tx_stats->tx_pivot_ts * (USEC_PER_SEC / TCP_TS_HZ);
            est_rtt = (uint32_t)(ts_current - tsecr * (USEC_PER_SEC / TCP_TS_HZ)); // us

            if (rx_stats->rx_rtt_last_tsecr != tsecr) {
                uint32_t rtt_ms;

                rx_stats->rx_rtt_us = clo_moving_average(rx_stats->rx_rtt_us, est_rtt);
                rtt_ms = ((rx_stats->rx_rtt_us >> 3) >> 10); // us to ms
                rx_stats->rx_rtt_last_tsecr = tsecr;
                rx_stats->rx_rtt_sample_count += 1;
                if (rx_stats->rx_rtt_min_ms > rtt_ms)
                    rx_stats->rx_rtt_min_ms = rtt_ms;
#ifdef CLO_LOG
                clo_printk("Ingress:%u now_ktime(%10lu)", dport, now_ktime);
                clo_printk("Ingress:%u tx_pivot_ktime_us(%10lu)", dport, tx_stats->tx_pivot_ktime_us);
                clo_printk("Ingress:%u tx_pivot_ts(%10lu)", dport, tx_stats->tx_pivot_ts);
                clo_printk("Ingress:%u rx_rtt_last_tsecr(%10lu)", dport, rx_stats->rx_rtt_last_tsecr);
                clo_printk("Ingress:%u ts_current(%10lu)", dport, ts_current);
                clo_printk("Ingress:%u tsecr(%10u)", dport, tsecr);
                clo_printk("Ingress:%u est_rtt(%10u)", dport, est_rtt);
                clo_printk("Ingress:%u sample(%u)", dport, rx_stats->rx_rtt_sample_count);
                clo_printk("Ingress:%u min_rtt_ms: %u updated", dport, rx_stats->rx_rtt_min_ms);
                clo_printk("Ingress:%u rx_rtt_us: %u updated", dport, (rx_stats->rx_rtt_us >> 3));
#endif
            }
        }
    }
}

static inline __attribute__((always_inline)) void
clo_update_tx_adv_wnd(struct __sk_buff *skb, uint8_t offset, CloTxFlowStats *tx_stats) {
    int ret = 0;
    uint8_t flag;
    uint16_t sport = tx_stats->sport;
    CloHoPolicy *ho_policy;

    ho_policy = bpf_clo_ho_policy_map_lookup_elem(&sport);
    if (!ho_policy) { // handover policy deactivated
        CloRxFlowStats * rx_stats = bpf_clo_rx_flow_stats_map_lookup_elem(&sport);
        if (!rx_stats) return;

        tx_stats->tx_last_rx_bytes = rx_stats->rx_sum_bytes;
        return;
    }

    //handover policy activated
    ret = bpf_skb_load_bytes(skb, offset + TCP_FLAG_OFF, &flag, 1);
    if (ret) return;
    if (flag & TCP_ACK) {
        uint16_t adv_window = 0;
        CloRxFlowStats * rx_stats;

        rx_stats = bpf_clo_rx_flow_stats_map_lookup_elem(&sport);
        if (!rx_stats) return;

        ret = bpf_skb_load_bytes(skb, offset + TCP_FLAG_OFF + 1, &adv_window, 2);
        if (!ret) {
            uint16_t origin_window = adv_window;
            uint16_t filled_window = (uint16_t)(rx_stats->rx_sum_bytes - tx_stats->tx_last_rx_bytes);

            adv_window = ntohs(adv_window);
#ifdef CLO_LOG
            clo_printk("Egress:%u adv_window: %u", sport, adv_window);
#endif

            if (filled_window >= adv_window) {
#ifdef CLO_LOG
                clo_printk("Egress:%u adv_window fulled");
#endif
                tx_stats->tx_last_rx_bytes = rx_stats->rx_sum_bytes;
                // increase target window
            }

            uint16_t new_window = htons(ho_policy->target_window);
            ret = bpf_l4_csum_replace(skb, offset + TCP_CSUM_OFF, origin_window, new_window, sizeof(new_window));
            if (ret) return;
            bpf_skb_store_bytes(skb, offset + TCP_FLAG_OFF + 1, &new_window, sizeof(new_window), 0);
        }
    }
}

static inline __attribute__((always_inline)) void
clo_update_rtt_tx_pivot_timestamp(struct __sk_buff *skb, uint8_t offset, CloTxFlowStats *tx_stats) {
    uint8_t tick_key = CLO_BPF_MAP_UNIQUE_KEY;
#ifdef CLO_LOG
    uint16_t sport = tx_stats->sport;
#endif
    CloApTick *tick;

    tick = bpf_clo_ap_tick_map_lookup_elem(&tick_key);
#ifdef CLO_LOG
    if (!tick) { clo_printk("Egress:%u no ap tick", sport); return; }
#else
    if (!tick) return;
#endif

    if (tx_stats->tx_tick_num != tick->tick_num) { // slot changed.
        uint64_t now_ktime = clo_ktime_get_us();

        // Need to check pivot
        if (now_ktime < tx_stats->tx_pivot_ktime_us + CLO_RTT_TX_PIVOT_EXPIRE_INTERVAL_US) {
            // valid pivot then reuse pivot
            tx_stats->tx_tick_num = tick->tick_num;
#ifdef CLO_LOG
            clo_printk("Egress:%u tx tick %lu updated", sport, tx_stats->tx_tick_num);
#endif
        } else { // different port or invalid pivot
            uint32_t ts = 0;
            uint32_t tsecr = 0;

            if (clo_get_timestamp_option(skb, offset, &ts, &tsecr) == CLO_TS_SUCCESS) { // hit timestamp!
                tx_stats->tx_tick_num = tick->tick_num;
                tx_stats->tx_pivot_ktime_us = now_ktime;
                tx_stats->tx_pivot_ts = (uint64_t) ts;
#ifdef CLO_LOG
                clo_printk("Egress:%u tx tick %lu fully updated", sport, tx_stats->tx_tick_num);
            } else {
                clo_printk("Egress:%u tx tick %lu fail to fully update", sport, tx_stats->tx_tick_num);
            }
#else
            }
#endif
        }
    }
}

// Read Timestamp tcp option and Read RX bytes
DEFINE_OPTIONAL_BPF_PROG("schedcls/ingress/CloIngress", AID_ROOT, AID_SYSTEM, sched_cls_ingress_CloIngress)
(struct __sk_buff *skb) {
    int ret = -1;
    uint8_t proto = 0;
    uint8_t offset = IP_HDR_LENGTH;

    // Fetch the port
    if (skb->protocol == IP_V4_NW) {
        ret = bpf_skb_load_bytes(skb, IP_HDR_PROTOCOL, &proto, 1);
    } else if (skb->protocol == IP_V6_NW) {
        ret = bpf_skb_load_bytes(skb, IPV6_HDR_PROTOCOL, &proto, 1);
        offset = IPV6_HDR_LENGTH;
    }

    if (ret) return TC_ACT_UNSPEC;

    clo_update_rx_stats(skb);

    if (proto == IPPROTO_TCP) {
        struct tcphdr th = {0};
        uint16_t dport = 0;
        CloRxFlowStats *rx_flow;

        // Fetch the port
        ret = bpf_skb_load_bytes(skb, offset + TCP_DPORT_OFF, &dport, 2);
        if (ret) return TC_ACT_UNSPEC;

        ret = bpf_skb_load_bytes(skb, offset, &th, TCP_HDR_LENGTH);
        if (ret) return TC_ACT_UNSPEC;

        if (th.syn) {
            CloRxFlowStats new_rx_stats = clo_create_rx_stats(dport);
            if (new_rx_stats.dport == 0) return TC_ACT_OK;
            bpf_clo_rx_flow_stats_map_update_elem(&dport, &new_rx_stats, BPF_ANY);
        }

        rx_flow = bpf_clo_rx_flow_stats_map_lookup_elem(&dport);
        if (!rx_flow) return TC_ACT_OK;

        clo_update_rx_flow_bytes(skb, rx_flow);
        clo_update_rx_flow_rtt(skb, offset, rx_flow);
        clo_update_rx_flow_list(rx_flow);
        bpf_clo_rx_flow_stats_map_update_elem(&dport, rx_flow, BPF_ANY);
    }

    return TC_ACT_OK;
}

// Read and Update advertise window
DEFINE_OPTIONAL_BPF_PROG("schedcls/egress/CloEgress", AID_ROOT, AID_SYSTEM, sched_cls_egress_CloEgress)
(struct __sk_buff *skb) {
    int ret = -1;
    uint8_t proto = 0;
    uint16_t sport = 0;
    uint8_t offset = IP_HDR_LENGTH;

    // Fetch the port
    if (skb->protocol == IP_V4_NW) {
        ret = bpf_skb_load_bytes(skb, IP_HDR_PROTOCOL, &proto, 1);
    } else if (skb->protocol == IP_V6_NW) {
        ret = bpf_skb_load_bytes(skb, IPV6_HDR_PROTOCOL, &proto, 1);
        offset = IPV6_HDR_LENGTH;
    }

    if (ret) return TC_ACT_UNSPEC;

    clo_update_tx_stats(skb);

    if (proto == IPPROTO_TCP) {
        struct tcphdr th = {0};

        CloTxFlowStats *tx_flow;

        ret = bpf_skb_load_bytes(skb, offset + TCP_SPORT_OFF, &sport, 2);
        if (ret) return TC_ACT_UNSPEC;

        ret = bpf_skb_load_bytes(skb, offset, &th, TCP_HDR_LENGTH);
        if (ret) return TC_ACT_UNSPEC;

        if (th.syn) {
            CloTxFlowStats new_tx_flow_stats = clo_create_tx_flow_stats(sport);
            bpf_clo_tx_flow_stats_map_update_elem(&sport, &new_tx_flow_stats, BPF_ANY);
        }

        tx_flow = bpf_clo_tx_flow_stats_map_lookup_elem(&sport);
        if (!tx_flow) return TC_ACT_OK;

        clo_update_rtt_tx_pivot_timestamp(skb, offset, tx_flow);
        clo_update_tx_adv_wnd(skb, offset, tx_flow);

        bpf_clo_tx_flow_stats_map_update_elem(&sport, tx_flow, BPF_ANY);
    }
    return TC_ACT_OK;
}

LICENSE("Apache 2.0");
CRITICAL("Advanced CP MX CLO");