#ifndef __TEST__
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/pkt_cls.h>
#include <linux/tcp.h>
#endif

#include <linux/types.h>

#ifndef __TEST__
#include <netinet/in.h>
#include <netinet/udp.h>
#endif

#include <stdint.h>
#include <string.h>
#include <stdbool.h>

#ifndef __TEST__
#include "bpf_helpers.h"
#else
#include "tos_marker_test.h"
#endif

#ifndef __TEST__
#define IP4_OFFSET(field, header) ((header) + offsetof(struct iphdr, field))
#endif
#define MAX_POLICIES 16

#define NO_MARKING 0
#define ALWAYS_OVERWRITE_ALL 1
#define ALWAYS_OVERWRITE_DSCP 2
#define ALWAYS_OVERWRITE_ECN 3
#define CONDITIONAL_OVERWRITE_ALL 4
#define CONDITIONAL_OVERWRITE_DSCP 5
#define CONDITIONAL_OVERWRITE_ECN 6

#define MATCH -1
#define MISMATCH 0

#ifndef __TEST__
static int (*bpf_l3_csum_replace)(struct __sk_buff *skb, __u32 offset, __u64 from, __u64 to,
                                  __u64 flags) = (void *)BPF_FUNC_l3_csum_replace;
static int (*bpf_skb_store_bytes)(void *ctx, int off, void *from, int len,
                                  int flags) = (void *)BPF_FUNC_skb_store_bytes;
static uint32_t (*bpf_get_socket_uid)(struct __sk_buff *skb) = (void *)BPF_FUNC_get_socket_uid;

#endif

DEFINE_BPF_MAP(tos_policy_mobile_map, HASH, uint32_t, uint16_t, MAX_POLICIES)

static inline int set_tos_ipv4(struct __sk_buff *skb, uint16_t value) {
#ifndef __TEST__
    void *data = (void *)(long)skb->data;
    const void *data_end = (void *)(long)skb->data_end;

    const struct iphdr *const iph = (struct iphdr *)data;
    int hdr_size = sizeof(struct iphdr);

    if (data + hdr_size > data_end) {
        return MISMATCH;
    }
    if (iph->version != 4 || iph->ihl < 5 || iph->ihl > 15) {
        return MISMATCH;
    }
#else
    const struct iphdr *const iph = (struct iphdr *)skb->iph;
#endif

    uint8_t action = value >> 8;
    uint8_t policy_tos = value & 0x00FF;
    uint8_t policy_dscp = policy_tos & 0xFC;
    uint8_t policy_ecn = policy_tos & 0x03;

    uint8_t old_tos = iph->tos;
    uint8_t old_dscp = old_tos & 0xFC;
    uint8_t old_ecn = old_tos & 0x03;

    uint8_t new_tos = old_tos;

    if (action == ALWAYS_OVERWRITE_ALL) {
        new_tos = policy_tos;
    } else if (action == ALWAYS_OVERWRITE_DSCP) {
        new_tos = policy_dscp | old_ecn;
    } else if (action == ALWAYS_OVERWRITE_ECN) {
        new_tos = policy_ecn | old_dscp;
    } else if (action == CONDITIONAL_OVERWRITE_ALL) {
        new_tos = (old_tos == 0) ? policy_tos : old_tos;
    } else if (action == CONDITIONAL_OVERWRITE_DSCP) {
        new_tos = (old_dscp == 0) ? policy_dscp | old_ecn : old_tos;
    } else if (action == CONDITIONAL_OVERWRITE_ECN) {
        new_tos = (old_ecn == 0) ? policy_ecn | old_dscp : old_tos;
    }

    bpf_l3_csum_replace(skb, IP4_OFFSET(check, 0), htons(old_tos), htons(new_tos), 2);
    bpf_skb_store_bytes(skb, IP4_OFFSET(tos, 0), &new_tos, sizeof(new_tos), 0);

    return MATCH;
}

static inline int set_tos_ipv6(struct __sk_buff *skb, uint16_t value) {
#ifndef __TEST__
    void *data = (void *)(long)skb->data;
    const void *data_end = (void *)(long)skb->data_end;

    const struct ipv6hdr *const iph = (struct ipv6hdr *)data;
    int hdr_size = sizeof(struct ipv6hdr);

    if (data + hdr_size > data_end) {
        return MISMATCH;
    }

    if (iph->version != 6) {
        return MISMATCH;
    }
#else
    const struct ipv6hdr *const iph = (struct ipv6hdr *)skb->ipv6h;
    const int eth_header_size = sizeof(struct ethhdr);
#endif

    uint8_t action = value >> 8;
    uint8_t policy_tos = value & 0x00FF;
    uint8_t policy_dscp = policy_tos & 0xFC;
    uint8_t policy_ecn = policy_tos & 0x03;

    // VTF consists of 3 parts; version(4), traffic class(8) and flow label(20).
    __be32 old_vtf = ntohl(*(__be32 *)iph);
    uint8_t old_tos = (old_vtf >> 20) & 0x0FF;
    uint8_t old_dscp = (old_vtf >> 20) & 0xFC;
    uint8_t old_ecn = (old_vtf >> 20) & 0x03;

    __be32 new_vtf = old_vtf;

    if (action == ALWAYS_OVERWRITE_ALL) {
        new_vtf = (old_vtf & 0xF00FFFFF) | (policy_tos << 20);
    } else if (action == ALWAYS_OVERWRITE_DSCP) {
        new_vtf = (old_vtf & 0xF03FFFFF) | (policy_dscp << 20);
    } else if (action == ALWAYS_OVERWRITE_ECN) {
        new_vtf = (old_vtf & 0xFFCFFFFF) | (policy_ecn << 20);
    } else if (action == CONDITIONAL_OVERWRITE_ALL) {
        new_vtf = (old_tos == 0) ? (old_vtf & 0xF00FFFFF) | (policy_tos << 20) : old_vtf;
    } else if (action == CONDITIONAL_OVERWRITE_DSCP) {
        new_vtf = (old_dscp == 0) ? (old_vtf & 0xF03FFFFF) | (policy_dscp << 20) : old_vtf;
    } else if (action == CONDITIONAL_OVERWRITE_ECN) {
        new_vtf = (old_ecn == 0) ? (old_vtf & 0xFFCFFFFF) | (policy_ecn << 20) : old_vtf;
    }

    new_vtf = htonl(new_vtf);

    bpf_skb_store_bytes(skb, 0, &new_vtf, sizeof(__be32), BPF_F_RECOMPUTE_CSUM);

    return MATCH;
}

static inline int classify_ack_icmp(struct __sk_buff *skb, bool is_ipv6) {
    void *pos = (void *)(long)skb->data;
    const void *data_end = (void *)(long)skb->data_end;

    // iph
    void *iph = pos;
    int size = is_ipv6 ? sizeof(struct ipv6hdr) : sizeof(struct iphdr);
    if (pos + size > data_end) {
        return MISMATCH;
    }

    uint8_t protocol;
    int iph_len;
    int iph_payload_len;

    if (is_ipv6) {
        if (((struct ipv6hdr *)iph)->version != 6) {
            return MISMATCH;
        }

        iph_len = sizeof(struct ipv6hdr);
        protocol = ((struct ipv6hdr *)iph)->nexthdr;

        if (protocol == IPPROTO_ICMPV6) {
            return MATCH;
        }

        iph_payload_len = ntohs(((struct ipv6hdr *)iph)->payload_len);
    } else {
        if (((struct iphdr *)iph)->version != 4) {
            return MISMATCH;
        }

        iph_len = ((struct iphdr *)iph)->ihl * 4;
        if (iph_len < 20 || iph_len > 60) {
            return MISMATCH;
        }

        protocol = ((struct iphdr *)iph)->protocol;

        if (protocol == IPPROTO_ICMP) {
            return MATCH;
        }

        iph_payload_len = ntohs(((struct iphdr *)iph)->tot_len) - iph_len;
    }

    if (iph + iph_len > data_end) {
        return MISMATCH;
    }

    pos += iph_len;

    // tcp
    if (protocol != IPPROTO_TCP) {
        return MISMATCH;
    }

    struct tcphdr *tcph = pos;
    if ((void *)(tcph + 1) > data_end) {
        return MISMATCH;
    }

    uint32_t tcphdr_len = tcph->doff * 4;
    if (iph_payload_len > tcphdr_len) {
        return MISMATCH;
    }

    __be16 tcph_flags = ntohs( *(__be16 *)((void*)tcph + 12) );
    if ((tcph_flags & 0xFF) != 0x10) {
        return MISMATCH;
    }

    return MATCH;
}

DEFINE_BPF_PROG("schedcls/egress/set_tos_mobile", AID_ROOT, AID_SYSTEM, schedcls_egress_set_tos_mobile)
(struct __sk_buff *skb) {
    int ret = TC_ACT_UNSPEC;

    if (skb->pkt_type != PACKET_HOST) {
        return TC_ACT_UNSPEC;
    }

    if (skb->protocol != htons(ETH_P_IP) && skb->protocol != htons(ETH_P_IPV6)) {
        return TC_ACT_UNSPEC;
    }

    uint32_t sockuid = bpf_get_socket_uid(skb);
    uint16_t *value = bpf_tos_policy_mobile_map_lookup_elem(&sockuid);

    if (value) {
        skb->queue_mapping = 1;

        if (*value >> 8 != NO_MARKING) {
            if (skb->protocol == htons(ETH_P_IP)) {
                set_tos_ipv4(skb, *value);
            } else if (skb->protocol == htons(ETH_P_IPV6)) {
                set_tos_ipv6(skb, *value);
            }
        }
    } else {
        skb->queue_mapping = 0;
    }

    return ret;
}

DEFINE_BPF_PROG("schedcls/egress/classify_ack_icmp", AID_ROOT, AID_SYSTEM, schedcls_egress_classify_ack_icmp)
(struct __sk_buff *skb) {
    int ret = MISMATCH;

    if (skb->pkt_type != PACKET_HOST) {
        return MISMATCH;
    }

    if (skb->protocol == htons(ETH_P_IP)) {
        ret = classify_ack_icmp(skb, false);
    } else if (skb->protocol == htons(ETH_P_IPV6)) {
        ret = classify_ack_icmp(skb, true);
    }

#ifdef __TEST__
    printf("schedlcls_egress_classify_ack: ret=%d(%s)\n", ret, (ret == MATCH) ? "MATCH" : "MISMATCH");
#endif

    return ret;
}

DEFINE_BPF_PROG("schedcls/egress/classify_uid", AID_ROOT, AID_SYSTEM, schedcls_egress_classify_uid)
(struct __sk_buff *skb) {
    int ret = MISMATCH;

    if (skb->pkt_type != PACKET_HOST) {
        return MISMATCH;
    }

    if (skb->protocol != htons(ETH_P_IP) && skb->protocol != htons(ETH_P_IPV6)) {
        return MISMATCH;
    }

    uint32_t sockuid = bpf_get_socket_uid(skb);
    uint16_t *value = bpf_tos_policy_mobile_map_lookup_elem(&sockuid);

    if (value) {
        ret = MATCH;
    }

    return ret;
}

LICENSE("Apache 2.0");
CRITICAL("Sem eBPF TOS");
