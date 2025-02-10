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
#include <ztd_events.h>
#include <ztd_pkt_shared.h>

#define DEBUG_ENTRY 0

#define IP_OFFSET_SRC       (offsetof(struct iphdr, saddr))
#define IP_OFFSET_DST       (offsetof(struct iphdr, daddr))
#define TCP4_DPORT_OFFSET   (sizeof(struct iphdr) + offsetof(struct tcphdr, dest))
#define TCP4_SPORT_OFFSET   (sizeof(struct iphdr) + offsetof(struct tcphdr, source))

#define IPV6_OFFSET_SRC     (offsetof(struct ipv6hdr, saddr))
#define IPV6_OFFSET_DST     (offsetof(struct ipv6hdr, daddr))
#define TCP6_DPORT_OFF      (sizeof(struct ipv6hdr) + offsetof(struct tcphdr, dest))
#define TCP6_SPORT_OFF      (sizeof(struct ipv6hdr) + offsetof(struct tcphdr, source))

#define TLS_DATA_OFFSET_IPV4 0x28
#define TLS_DATA_OFFSET_IPV6 TLS_DATA_OFFSET_IPV4 + 0x14
#define TLS_HELLO_MESSAGE_ID 0x16
#define TLS_CLIENT_HELLO_ID  0x01
#define TLS_SERVER_HELLO_ID  0x02
#define TLS_CHANGE_CIPHER_SPEC_MESSAGE_ID 0x14
#define TLS_CHANGE_CIPHER_SPEC_CONTENT_ID 0x01

#define TLS_HEADER_LEN  6
#define TLS_MESSAGE_TYPE_OFFSET         0x00
#define TLS_HELLO_MESSAGE_TYPE_OFFSET   0x05
#define TLS_CHANGE_CIPHER_SPEC_LEN      6
#define TLS_CHANGE_CIPHER_SPEC_CONTENT_OFFSET   0x05

#define CHUNK_SIZE_1_BYTE    1
#define CHUNK_SIZE_2_BYTES   2
#define CHUNK_SIZE_3_BYTES   3
#define CHUNK_SIZE_4_BYTES   4
#define BIG_CHUNK_SIZE          128
#define NUMBER_OF_BIG_CHUNKS    20
#define SMALL_CHUNK_SIZE        CHUNK_SIZE_4_BYTES
#define NUMBER_OF_SMALL_CHUNKS  43

static int (*bpf_skb_load_bytes)(struct __sk_buff* skb, int off, void* to, int len) = (void*)BPF_FUNC_skb_load_bytes;
static uint32_t(*bpf_get_socket_uid)(struct __sk_buff* skb) = (void*)BPF_FUNC_get_socket_uid;

#if USE_RINGBUF
DEFINE_BPF_RINGBUF_EXT(event_noti_ringbuf, event_noti_t, 4096, AID_ROOT, AID_SYSTEM, 0660, "", "", PRIVATE,
                       BPFLOADER_MIN_VER, BPFLOADER_MAX_VER, LOAD_ON_ENG, LOAD_ON_USER, LOAD_ON_USERDEBUG);
DEFINE_BPF_MAP_GRW(tls_pkt_event_map, PERCPU_ARRAY, uint32_t, tls_pkt_t, 1, AID_SYSTEM);
DEFINE_BPF_MAP_GRW(tls_pkt_map, LRU_HASH, uint64_t, tls_pkt_t, 2048, AID_SYSTEM);
#endif

DEFINE_BPF_MAP_GRW(ifindex_eth_map, HASH, int32_t, uint8_t, 128, AID_SYSTEM);

static inline __always_inline void copy_tls_hello_data(struct __sk_buff* skb, bool isIpv4, tls_pkt_t* output, bool hasEthHeader, uint8_t variableOffset) {
    uint8_t* pcursor = (uint8_t*)output->hello_data;
    uint32_t tls_data_offset, offset, offset1;
    bool readRemainingBytes = false;

    tls_data_offset = isIpv4 ? TLS_DATA_OFFSET_IPV4 : TLS_DATA_OFFSET_IPV6;
    tls_data_offset = hasEthHeader ? tls_data_offset + ETH_HLEN : tls_data_offset;
    tls_data_offset = tls_data_offset + variableOffset;

    //TODO: find a way to optimize data copy.
    //      as of now, bpf only provides bpf_skb_load_bytes() for reading skb bytes
    //      and bpf restricts its usage by forcing a constant value as data size for loading bytes.
    //      the bpf verifier does not allow passing a variable as data size to bpf_skb_load_bytes()

    // The tls_pkt_t data size is 1452 bytes, therefore logic below reads at most 1452 bytes in two steps:
    // Step 1: attempt to read 1280 in chunks of 128 bytes.
    // Step 2: attempt to read remaining bytes when any chunk fails or number of big chunk is reached.
    // (10 x 128) + (43 x 4) = (1280) + (172) = 1452
    for (int i = 0; i < NUMBER_OF_BIG_CHUNKS; i++) {
        offset1 = i * BIG_CHUNK_SIZE;
        pcursor = (uint8_t *)(output->hello_data + offset1);
        if (bpf_skb_load_bytes(skb, tls_data_offset + offset1, pcursor, BIG_CHUNK_SIZE) == 0) {
            output->data_len += BIG_CHUNK_SIZE;
        } else {
            readRemainingBytes = true;
        }

        // read remaining bytes from skb (in chunks of 4 bytes) until skb->len is reached
        if (i + 1 == NUMBER_OF_BIG_CHUNKS || readRemainingBytes){
            for (int j = 0; j < NUMBER_OF_SMALL_CHUNKS; j++) {
                offset = offset1 + j * SMALL_CHUNK_SIZE;
                pcursor = (uint8_t*)(output->hello_data + offset);
                if (bpf_skb_load_bytes(skb, tls_data_offset + offset, pcursor, SMALL_CHUNK_SIZE) == 0) {
                    output->data_len += SMALL_CHUNK_SIZE;
                }
                else if (bpf_skb_load_bytes(skb, tls_data_offset + offset, pcursor, CHUNK_SIZE_3_BYTES) == 0) {
                    output->data_len += CHUNK_SIZE_3_BYTES;
                }
                else if (bpf_skb_load_bytes(skb, tls_data_offset + offset, pcursor, CHUNK_SIZE_2_BYTES) == 0) {
                    output->data_len += CHUNK_SIZE_2_BYTES;
                }
                else if (bpf_skb_load_bytes(skb, tls_data_offset + offset, pcursor, CHUNK_SIZE_1_BYTE) == 0) {
                    output->data_len += CHUNK_SIZE_1_BYTE;
                }
                if (tls_data_offset + offset + 1 >= skb->len) {
                    return;
                }
            }
        }
    }
}

static inline __always_inline bool is_tls_packet(struct __sk_buff* skb, bool isIpv4, uint8_t direction, bool hasEthHeader, uint8_t* variableOffset) {
    void* data = (void*)(long)skb->data;
    void* data_end = (void*)(long)skb->data_end;
    struct ethhdr* eth = hasEthHeader ? data : NULL;

    uint32_t tls_data_offset = 0;
    if (isIpv4) {
        struct iphdr* ip = hasEthHeader ? (void*)(eth + 1) : data;
        struct tcphdr* tcph = (void*)(ip + 1);
        if (hasEthHeader && (((data + sizeof(*eth) + sizeof(*ip) + sizeof(*tcph)) > data_end)
                             || (eth->h_proto != htons(ETH_P_IP))
                             || (ip->protocol != IPPROTO_TCP)
                             || (tcph->syn || tcph->fin || tcph->rst)))
            return false;

        if (!hasEthHeader && (((data + sizeof(*ip) + sizeof(*tcph)) > data_end)
                              || (ip->protocol != IPPROTO_TCP)
                              || (tcph->syn || tcph->fin || tcph->rst)))
            return false;
        *variableOffset = (uint8_t) 4 * (tcph->doff - 5);   //Data offset value ranges from 5 to 15, and translates to TCP length of 20 to 60.
    } else {
        struct ipv6hdr* ip6 = hasEthHeader ? (void*)(eth + 1) : data;
        struct tcphdr* tcph = (void*)(ip6 + 1);
        if (hasEthHeader && (((data + sizeof(*eth) + sizeof(*ip6) + sizeof(*tcph)) > data_end)
                             || (eth->h_proto != htons(ETH_P_IPV6))
                             || (ip6->version != 6)
                             || (ip6->nexthdr != IPPROTO_TCP)
                             || (tcph->syn || tcph->fin || tcph->rst)))
            return false;

        if (!hasEthHeader && (((data + sizeof(*ip6) + sizeof(*tcph)) > data_end)
                              || (ip6->version != 6)
                              || (ip6->nexthdr != IPPROTO_TCP)
                              || (tcph->syn || tcph->fin || tcph->rst)))
            return false;
        *variableOffset = (uint8_t) 4 * (tcph->doff - 5);   //Data offset value ranges from 5 to 15, and translates to TCP length of 20 to 60.
    }
    tls_data_offset = *variableOffset;
    tls_data_offset = isIpv4 ? tls_data_offset + TLS_DATA_OFFSET_IPV4 : tls_data_offset + TLS_DATA_OFFSET_IPV6;
    tls_data_offset = hasEthHeader ? tls_data_offset + ETH_HLEN : tls_data_offset;

    uint8_t tlshdr[TLS_CHANGE_CIPHER_SPEC_LEN + TLS_HEADER_LEN];
    bpf_skb_load_bytes(skb, tls_data_offset, &tlshdr, sizeof(tlshdr));
    int changeCipherSpecOffset = 0;
    if (tlshdr[TLS_MESSAGE_TYPE_OFFSET] == TLS_CHANGE_CIPHER_SPEC_MESSAGE_ID
        && tlshdr[TLS_CHANGE_CIPHER_SPEC_CONTENT_OFFSET] == TLS_CHANGE_CIPHER_SPEC_CONTENT_ID) {
        changeCipherSpecOffset = TLS_CHANGE_CIPHER_SPEC_LEN;
        *variableOffset = *variableOffset + TLS_CHANGE_CIPHER_SPEC_LEN;
    }
    if ((tlshdr[TLS_MESSAGE_TYPE_OFFSET + changeCipherSpecOffset] != TLS_HELLO_MESSAGE_ID)
        || (direction == NET_EGRESS && tlshdr[TLS_HELLO_MESSAGE_TYPE_OFFSET + changeCipherSpecOffset] != TLS_CLIENT_HELLO_ID)
        || (direction == NET_INGRESS && tlshdr[TLS_HELLO_MESSAGE_TYPE_OFFSET + changeCipherSpecOffset] != TLS_SERVER_HELLO_ID))
        return false;


    return true;
}

static inline __always_inline int extract_tls_hello_packet(struct __sk_buff* skb, uint8_t direction) {

    bool isIpv4 = skb->protocol == htons(ETH_P_IP);
    bool isIpv6 = skb->protocol == htons(ETH_P_IPV6);
	
#if USE_RINGBUF

    int32_t key = skb->ifindex;
    uint8_t* status = bpf_ifindex_eth_map_lookup_elem(&key);
    bool hasEthHeader = (status && (*status) == 1);

    uint8_t variableOffset = 0;
    if ((!isIpv4 && !isIpv6) || !is_tls_packet(skb, isIpv4, direction, hasEthHeader, &variableOffset))
        return TC_ACT_UNSPEC;

    uint32_t zero = 0;
    tls_pkt_t* pdata = bpf_tls_pkt_event_map_lookup_elem(&zero);

    if (!pdata) return TC_ACT_UNSPEC;

    uint64_t event_time, cpu_id, pkt_key;
    event_time = bpf_ktime_get_boot_ns();
    cpu_id = bpf_get_smp_processor_id();
    pkt_key = (cpu_id & 0x00000000000000FF) << 56 | event_time;

    pdata->timestamp = event_time;
    bpf_tls_pkt_map_update_elem(&pkt_key, pdata, BPF_ANY);

    tls_pkt_t* output = bpf_tls_pkt_map_lookup_elem(&pkt_key);
    if (output != NULL) {
        output->len = skb->len;
        output->uid = bpf_get_socket_uid(skb);
        uint8_t _ETH_LEN = hasEthHeader ? ETH_HLEN : 0;

        if (isIpv4) {
            output->family = 2; // AF_INET
            bpf_skb_load_bytes(skb, _ETH_LEN + IP_OFFSET_SRC, &output->local_ip4, sizeof(output->local_ip4));
            bpf_skb_load_bytes(skb, _ETH_LEN + IP_OFFSET_DST, &output->remote_ip4, sizeof(output->remote_ip4));
            output->remote_port = load_half(skb, _ETH_LEN + TCP4_DPORT_OFFSET);
            output->local_port = load_half(skb, _ETH_LEN + TCP4_SPORT_OFFSET);
        } else {
            output->family = 10; // AF_INET6
            bpf_skb_load_bytes(skb, _ETH_LEN + IPV6_OFFSET_SRC , &output->local_ip6, sizeof(output->local_ip6));
            bpf_skb_load_bytes(skb, _ETH_LEN + IPV6_OFFSET_DST, &output->remote_ip6, sizeof(output->remote_ip6));
            output->remote_port = load_half(skb, _ETH_LEN + TCP6_DPORT_OFF);
            output->local_port = load_half(skb, _ETH_LEN + TCP6_SPORT_OFF);
        }

        output->type = direction;
        output->data_len = 0;
        copy_tls_hello_data(skb, isIpv4, output, hasEthHeader, variableOffset);
        bpf_tls_pkt_map_update_elem(&pkt_key, output, BPF_ANY);

        event_noti_t *noti = bpf_event_noti_ringbuf_reserve();
        if (!noti)  return TC_ACT_UNSPEC;

        noti->type = (direction == NET_EGRESS) ? TRACE_EVENT_SCHED_CLS_EGRESS : TRACE_EVENT_SCHED_CLS_INGRESS;
        noti->key = pkt_key;
        bpf_event_noti_ringbuf_submit(noti);
    }

#endif

    return TC_ACT_UNSPEC;
}

DEFINE_OPTIONAL_BPF_PROG("schedcls/ingress/tls_pkt", AID_ROOT, AID_NET_ADMIN, sched_cls_ingress_tls_pkt)
(struct __sk_buff* skb) {
#if DEBUG_ENTRY
    bpf_printk("[ztd] schedcls/ingress/tls_pkt");
#endif
    return extract_tls_hello_packet(skb, NET_INGRESS);
}

DEFINE_OPTIONAL_BPF_PROG("schedcls/egress/tls_pkt", AID_ROOT, AID_NET_ADMIN, sched_cls_egress_tls_pkt)
(struct __sk_buff* skb) {
#if DEBUG_ENTRY
    bpf_printk("[ztd] schedcls/egress/tls_pkt");
#endif
    return extract_tls_hello_packet(skb, NET_EGRESS);
}

LICENSE("GPL");