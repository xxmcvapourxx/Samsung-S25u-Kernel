#include <linux/bpf.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/pkt_cls.h>
#include <linux/tcp.h>

#include <stdbool.h>
#include <stdint.h>
#include <netinet/in.h>

#include "bpf_shared.h"
#include <netlog_shared.h>

#define IP_ETH_OFFSET_SRC (offsetof(struct iphdr, saddr))
#define IP_ETH_OFFSET_DST (offsetof(struct iphdr, daddr))
#define IP_PROTOCOL_OFFSET (offsetof(struct iphdr, protocol))

#define TCP4_DPORT_OFFSET (sizeof(struct iphdr) + offsetof(struct tcphdr, dest))
#define TCP4_SPORT_OFFSET (sizeof(struct iphdr) + offsetof(struct tcphdr, source))

static int (*bpf_skb_load_bytes)(struct __sk_buff *skb, int off, void *to, int len) = (void *)BPF_FUNC_skb_load_bytes;
static uint32_t (*bpf_get_socket_uid)(struct __sk_buff *skb) = (void *)BPF_FUNC_get_socket_uid;

DEFINE_BPF_RINGBUF_EXT(insecure_ports_ringbuf, socket_data_t, 4096, AID_ROOT, AID_SYSTEM, 0660, "", "", PRIVATE,
                       BPFLOADER_MIN_VER, BPFLOADER_MAX_VER, LOAD_ON_ENG, LOAD_ON_USER, LOAD_ON_USERDEBUG);
DEFINE_BPF_RINGBUF_EXT(abnormal_pkts_ringbuf, socket_data_t, 4096, AID_ROOT, AID_SYSTEM, 0660, "", "", PRIVATE,
                       BPFLOADER_MIN_VER, BPFLOADER_MAX_VER, LOAD_ON_ENG, LOAD_ON_USER, LOAD_ON_USERDEBUG);
DEFINE_BPF_RINGBUF_EXT(localnw_pkts_ringbuf, socket_data_t, 4096, AID_ROOT, AID_SYSTEM, 0660, "", "", PRIVATE,
                       BPFLOADER_MIN_VER, BPFLOADER_MAX_VER, LOAD_ON_ENG, LOAD_ON_USER, LOAD_ON_USERDEBUG);
DEFINE_BPF_MAP_GRW(socket_data_map, PERCPU_ARRAY, uint32_t, socket_data_t, 1, AID_SYSTEM);

static inline __always_inline void extract_and_write_event_data(struct __sk_buff *skb, uint32_t packet_type)
{
    uint32_t zero = 0;
     // TODO - use bpf_ringbuf_reserve() instead and remove socket_data_map
    socket_data_t *output = bpf_socket_data_map_lookup_elem(&zero);
    if (output == NULL)
        return;

    output->event_type = packet_type;
    output->uid = bpf_get_socket_uid(skb);
    output->timestamp = bpf_ktime_get_boot_ns();
    output->ifindex = skb->ifindex;

    bpf_skb_load_bytes(skb, IP_PROTOCOL_OFFSET, &output->protocol, 1);

    if (skb->protocol == htons(ETH_P_IP))
    {
        bpf_skb_load_bytes(skb, IP_ETH_OFFSET_SRC, &output->src_ip, sizeof(output->src_ip));
        bpf_skb_load_bytes(skb, IP_ETH_OFFSET_DST, &output->dest_ip, sizeof(output->dest_ip));
        output->family = AF_INET;
    }
    else if (skb->protocol == htons(ETH_P_IPV6))
    {
        //todo for IPV6 addresses
        output->family = AF_INET6;
    }

    output->src_port = load_half(skb, TCP4_SPORT_OFFSET);
    output->dest_port = load_half(skb, TCP4_DPORT_OFFSET);

    switch (packet_type) {
        case EVENT_TYPE_INSECURE_PORTS:
            bpf_insecure_ports_ringbuf_output(output);
            break;
        case EVENT_TYPE_ABNORMAL_PACKETS:
            bpf_abnormal_pkts_ringbuf_output(output);
            break;
        case EVENT_TYPE_LOCALNW_PACKETS:
            bpf_localnw_pkts_ringbuf_output(output);
            break;
        default:
            break;
    }
}

DEFINE_BPF_PROG("skfilter/insecureports/xtbpf", AID_ROOT, AID_NET_ADMIN, xt_bpf_insecureports_prog)
(struct __sk_buff *skb)
{
    extract_and_write_event_data(skb, EVENT_TYPE_INSECURE_PORTS);
    return 1;
}

DEFINE_BPF_PROG("skfilter/abnormalpackets/xtbpf", AID_ROOT, AID_NET_ADMIN, xt_bpf_abnormalpackets_prog)
(struct __sk_buff *skb)
{
    extract_and_write_event_data(skb, EVENT_TYPE_ABNORMAL_PACKETS);
    return 1;
}

DEFINE_BPF_PROG("skfilter/localnwpackets/xtbpf", AID_ROOT, AID_NET_ADMIN, xt_bpf_localnwpackets_prog)
(struct __sk_buff *skb)
{
    extract_and_write_event_data(skb, EVENT_TYPE_LOCALNW_PACKETS);
    return 1;
}

LICENSE("GPL");
