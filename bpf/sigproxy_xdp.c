#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>

#define COUNTRY_WORDS 11
#define XDP_POLICY_CIDR_ALLOW_ENABLED (1ULL << 0)
#define XDP_POLICY_GEO_ENABLED (1ULL << 1)
#define XDP_POLICY_GEO_UNKNOWN_ALLOW (1ULL << 2)
#define XDP_POLICY_GEO_ALLOW_HAS_ENTRIES (1ULL << 3)
#define XDP_POLICY_IP_RATE_LIMIT_ENABLED (1ULL << 4)
#define XDP_POLICY_FLOOD_ENABLED (1ULL << 5)
#define SIG_RATE_UDP_FLOOD 240
#define SIG_RATE_TCP_FLOOD 241
#define SIG_RATE_TCP_SYN_FLOOD 242
#define SIG_RATE_TCP_ACK_FLOOD 243
#define SIG_RATE_ICMP_FLOOD 244
#define ICMP_MIN_HEADER_BYTES 8
#define MAX_VLAN_DEPTH 4
#define MAX_IPV6_EXT_HEADERS 6

enum xdp_stat_index {
    XDP_STAT_PASS = 0,
    XDP_STAT_BLOCKLIST_DROP = 1,
    XDP_STAT_DENY_CIDR_DROP = 2,
    XDP_STAT_NOT_ALLOWED_CIDR_DROP = 3,
    XDP_STAT_GEO_UNKNOWN_DROP = 4,
    XDP_STAT_GEO_DENY_DROP = 5,
    XDP_STAT_GEO_NOT_ALLOWED_DROP = 6,
    XDP_STAT_RATE_LIMIT_DROP = 7,
    XDP_STAT_UDP_FLOOD_DROP = 8,
    XDP_STAT_TCP_FLOOD_DROP = 9,
    XDP_STAT_TCP_SYN_FLOOD_DROP = 10,
    XDP_STAT_TCP_ACK_FLOOD_DROP = 11,
    XDP_STAT_ICMP_FLOOD_DROP = 12,
    XDP_STAT_MAX = 13,
};

struct listener_key {
    __u8 l4_proto;
    __u8 pad;
    __be16 dport;
};

struct listener_policy {
    __u64 flags;
    __u32 packets_per_second;
    __u32 burst;
    __u32 udp_flood_packets_per_second;
    __u32 udp_flood_burst;
    __u32 tcp_flood_packets_per_second;
    __u32 tcp_flood_burst;
    __u32 tcp_syn_flood_packets_per_second;
    __u32 tcp_syn_flood_burst;
    __u32 tcp_ack_flood_packets_per_second;
    __u32 tcp_ack_flood_burst;
    __u32 icmp_flood_packets_per_second;
    __u32 icmp_flood_burst;
    __u64 geo_allow[COUNTRY_WORDS];
    __u64 geo_deny[COUNTRY_WORDS];
};

struct ip_key {
    __u8 family;
    __u8 l4_proto;
    __be16 dport;
    __u8 src[16];
};

struct ip_value {
    __u64 enabled;
};

struct lpm_ip_key {
    __u32 prefixlen;
    __u8 family;
    __u8 l4_proto;
    __be16 dport;
    __u8 addr[16];
};

struct cidr_value {
    __u8 enabled;
};

struct geo_value {
    __u16 country;
};

struct rate_bucket {
    __u64 tokens;
    __u64 updated_ns;
};

struct sig_vlan_hdr {
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
};

struct sig_ipv6_opt_hdr {
    __u8 nexthdr;
    __u8 hdrlen;
};

struct sig_ipv6_frag_hdr {
    __u8 nexthdr;
    __u8 reserved;
    __be16 frag_off;
    __be32 identification;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, struct listener_key);
    __type(value, struct listener_policy);
} listener_policies SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct ip_key);
    __type(value, struct ip_value);
} blocked_ips SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, 65536);
    __type(key, struct lpm_ip_key);
    __type(value, struct cidr_value);
} allow_cidrs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, 65536);
    __type(key, struct lpm_ip_key);
    __type(value, struct cidr_value);
} deny_cidrs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, 65536);
    __type(key, struct lpm_ip_key);
    __type(value, struct cidr_value);
} trusted_cidrs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, 262144);
    __type(key, struct lpm_ip_key);
    __type(value, struct geo_value);
} geo_cidrs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct ip_key);
    __type(value, struct rate_bucket);
} rate_buckets SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, XDP_STAT_MAX);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

static __always_inline void incr_stat(__u32 index)
{
    __u64 *value = bpf_map_lookup_elem(&stats, &index);
    if (value)
        __sync_fetch_and_add(value, 1);
}

static __always_inline int parse_eth(void **cursor, void *data_end, __u16 *eth_proto)
{
    struct ethhdr *eth = *cursor;
    if ((void *)(eth + 1) > data_end)
        return -1;

    *cursor = eth + 1;
    *eth_proto = eth->h_proto;

    #pragma unroll
    for (int i = 0; i < MAX_VLAN_DEPTH; i++) {
        if (*eth_proto != __constant_htons(ETH_P_8021Q) &&
            *eth_proto != __constant_htons(ETH_P_8021AD))
            break;
        struct sig_vlan_hdr *vlan = *cursor;
        if ((void *)(vlan + 1) > data_end)
            return -1;
        *cursor = vlan + 1;
        *eth_proto = vlan->h_vlan_encapsulated_proto;
    }

    return 0;
}

static __always_inline int parse_ipv6_l4(void **cursor, void *data_end, __u8 *nexthdr)
{
    #pragma unroll
    for (int i = 0; i < MAX_IPV6_EXT_HEADERS; i++) {
        if (*nexthdr == IPPROTO_UDP || *nexthdr == IPPROTO_TCP)
            return 0;

        if (*nexthdr == IPPROTO_HOPOPTS ||
            *nexthdr == IPPROTO_ROUTING ||
            *nexthdr == IPPROTO_DSTOPTS) {
            struct sig_ipv6_opt_hdr *hdr = *cursor;
            if ((void *)(hdr + 1) > data_end)
                return -1;
            __u32 len = ((__u32)hdr->hdrlen + 1) * 8;
            if ((void *)((char *)(*cursor) + len) > data_end)
                return -1;
            *nexthdr = hdr->nexthdr;
            *cursor = (void *)((char *)(*cursor) + len);
            continue;
        }

        if (*nexthdr == IPPROTO_AH) {
            struct sig_ipv6_opt_hdr *hdr = *cursor;
            if ((void *)(hdr + 1) > data_end)
                return -1;
            __u32 len = ((__u32)hdr->hdrlen + 2) * 4;
            if ((void *)((char *)(*cursor) + len) > data_end)
                return -1;
            *nexthdr = hdr->nexthdr;
            *cursor = (void *)((char *)(*cursor) + len);
            continue;
        }

        if (*nexthdr == IPPROTO_FRAGMENT) {
            struct sig_ipv6_frag_hdr *frag = *cursor;
            if ((void *)(frag + 1) > data_end)
                return -1;
            if (frag->frag_off & __constant_htons(0xfff8))
                return -1;
            *nexthdr = frag->nexthdr;
            *cursor = frag + 1;
            continue;
        }

        return -1;
    }
    return -1;
}

static __always_inline int country_bit_is_set(__u64 bits[COUNTRY_WORDS], __u16 country)
{
    __u8 first = country >> 8;
    __u8 second = country & 0xff;
    if (first < 'A' || first > 'Z' || second < 'A' || second > 'Z')
        return 0;
    __u32 bit = (first - 'A') * 26 + (second - 'A');
    __u32 word = bit / 64;
    __u32 shift = bit % 64;
    if (word >= COUNTRY_WORDS)
        return 0;
    return (bits[word] & (1ULL << shift)) != 0;
}

static __always_inline int check_bucket_rate_limit(struct ip_key *ip_key, __u32 packets_per_second, __u32 burst, int stat_index)
{
    if (packets_per_second == 0 || burst == 0)
        return XDP_PASS;

    __u64 now = bpf_ktime_get_ns();
    struct rate_bucket *bucket = bpf_map_lookup_elem(&rate_buckets, ip_key);
    if (!bucket) {
        struct rate_bucket initial = {};
        initial.tokens = burst - 1;
        initial.updated_ns = now;
        bpf_map_update_elem(&rate_buckets, ip_key, &initial, BPF_ANY);
        return XDP_PASS;
    }

    __u64 tokens = bucket->tokens;
    __u64 elapsed = now - bucket->updated_ns;
    __u64 refill = elapsed * packets_per_second / 1000000000ULL;
    if (refill > 0) {
        tokens += refill;
        if (tokens > burst)
            tokens = burst;
        bucket->updated_ns = now;
    }
    if (tokens == 0) {
        incr_stat(stat_index);
        return XDP_DROP;
    }
    bucket->tokens = tokens - 1;
    return XDP_PASS;
}

static __always_inline int check_rate_limit(struct listener_policy *policy, struct ip_key *ip_key)
{
    if (!(policy->flags & XDP_POLICY_IP_RATE_LIMIT_ENABLED))
        return XDP_PASS;
    return check_bucket_rate_limit(ip_key, policy->packets_per_second, policy->burst, XDP_STAT_RATE_LIMIT_DROP);
}

static __always_inline int check_flood_limit(struct listener_policy *policy, struct ip_key *ip_key, __u8 packet_class)
{
    if (!(policy->flags & XDP_POLICY_FLOOD_ENABLED))
        return XDP_PASS;

    struct ip_key rate_key = *ip_key;
    __u32 packets_per_second = 0;
    __u32 burst = 0;
    int stat = XDP_STAT_RATE_LIMIT_DROP;

    if (packet_class == SIG_RATE_UDP_FLOOD) {
        rate_key.l4_proto = SIG_RATE_UDP_FLOOD;
        packets_per_second = policy->udp_flood_packets_per_second;
        burst = policy->udp_flood_burst;
        stat = XDP_STAT_UDP_FLOOD_DROP;
    } else if (packet_class == SIG_RATE_TCP_SYN_FLOOD) {
        rate_key.l4_proto = SIG_RATE_TCP_SYN_FLOOD;
        packets_per_second = policy->tcp_syn_flood_packets_per_second;
        burst = policy->tcp_syn_flood_burst;
        stat = XDP_STAT_TCP_SYN_FLOOD_DROP;
    } else if (packet_class == SIG_RATE_TCP_ACK_FLOOD) {
        rate_key.l4_proto = SIG_RATE_TCP_ACK_FLOOD;
        packets_per_second = policy->tcp_ack_flood_packets_per_second;
        burst = policy->tcp_ack_flood_burst;
        stat = XDP_STAT_TCP_ACK_FLOOD_DROP;
    } else if (packet_class == SIG_RATE_TCP_FLOOD) {
        rate_key.l4_proto = SIG_RATE_TCP_FLOOD;
        packets_per_second = policy->tcp_flood_packets_per_second;
        burst = policy->tcp_flood_burst;
        stat = XDP_STAT_TCP_FLOOD_DROP;
    } else if (packet_class == SIG_RATE_ICMP_FLOOD) {
        rate_key.l4_proto = SIG_RATE_ICMP_FLOOD;
        packets_per_second = policy->icmp_flood_packets_per_second;
        burst = policy->icmp_flood_burst;
        stat = XDP_STAT_ICMP_FLOOD_DROP;
    }

    return check_bucket_rate_limit(&rate_key, packets_per_second, burst, stat);
}

static __always_inline int evaluate_packet(struct listener_key *listener, struct ip_key *ip_key, struct lpm_ip_key *lpm_key, __u8 packet_class)
{
    struct listener_policy *policy = bpf_map_lookup_elem(&listener_policies, listener);
    if (!policy) {
        incr_stat(XDP_STAT_PASS);
        return XDP_PASS;
    }

    if (bpf_map_lookup_elem(&deny_cidrs, lpm_key)) {
        incr_stat(XDP_STAT_DENY_CIDR_DROP);
        return XDP_DROP;
    }

    if ((policy->flags & XDP_POLICY_CIDR_ALLOW_ENABLED) &&
        !bpf_map_lookup_elem(&allow_cidrs, lpm_key)) {
        incr_stat(XDP_STAT_NOT_ALLOWED_CIDR_DROP);
        return XDP_DROP;
    }

    if (bpf_map_lookup_elem(&trusted_cidrs, lpm_key)) {
        incr_stat(XDP_STAT_PASS);
        return XDP_PASS;
    }

    struct ip_value *block = bpf_map_lookup_elem(&blocked_ips, ip_key);
    if (block) {
        incr_stat(XDP_STAT_BLOCKLIST_DROP);
        return XDP_DROP;
    }

    if (policy->flags & XDP_POLICY_GEO_ENABLED) {
        struct geo_value *geo = bpf_map_lookup_elem(&geo_cidrs, lpm_key);
        if (!geo) {
            if (!(policy->flags & XDP_POLICY_GEO_UNKNOWN_ALLOW)) {
                incr_stat(XDP_STAT_GEO_UNKNOWN_DROP);
                return XDP_DROP;
            }
        } else if (country_bit_is_set(policy->geo_deny, geo->country)) {
            incr_stat(XDP_STAT_GEO_DENY_DROP);
            return XDP_DROP;
        } else if ((policy->flags & XDP_POLICY_GEO_ALLOW_HAS_ENTRIES) &&
                   !country_bit_is_set(policy->geo_allow, geo->country)) {
            incr_stat(XDP_STAT_GEO_NOT_ALLOWED_DROP);
            return XDP_DROP;
        }
    }

    int rate = check_rate_limit(policy, ip_key);
    if (rate == XDP_DROP)
        return XDP_DROP;

    int flood = check_flood_limit(policy, ip_key, packet_class);
    if (flood == XDP_DROP)
        return XDP_DROP;

    incr_stat(XDP_STAT_PASS);
    return XDP_PASS;
}

static __always_inline int handle_l4(__u8 family, __u8 proto, __be16 dport, __u8 *src, __u8 packet_class)
{
    struct listener_key listener = {};
    listener.l4_proto = proto;
    listener.dport = dport;

    struct ip_key ip_key = {};
    ip_key.family = family;
    ip_key.l4_proto = proto;
    ip_key.dport = dport;
    __builtin_memcpy(ip_key.src, src, family == 4 ? 4 : 16);

    struct lpm_ip_key lpm_key = {};
    lpm_key.prefixlen = family == 4 ? 64 : 160;
    lpm_key.family = family;
    lpm_key.l4_proto = proto;
    lpm_key.dport = dport;
    __builtin_memcpy(lpm_key.addr, src, family == 4 ? 4 : 16);

    return evaluate_packet(&listener, &ip_key, &lpm_key, packet_class);
}

static __always_inline int handle_icmp(__u8 family, __u8 *src)
{
    struct listener_key listener = {};
    listener.l4_proto = IPPROTO_ICMP;
    listener.dport = 0;

    struct ip_key ip_key = {};
    ip_key.family = family;
    ip_key.l4_proto = IPPROTO_ICMP;
    ip_key.dport = 0;
    __builtin_memcpy(ip_key.src, src, family == 4 ? 4 : 16);

    struct lpm_ip_key lpm_key = {};
    lpm_key.prefixlen = family == 4 ? 64 : 160;
    lpm_key.family = family;
    lpm_key.l4_proto = IPPROTO_ICMP;
    lpm_key.dport = 0;
    __builtin_memcpy(lpm_key.addr, src, family == 4 ? 4 : 16);

    return evaluate_packet(&listener, &ip_key, &lpm_key, SIG_RATE_ICMP_FLOOD);
}

SEC("xdp")
int sigproxy_xdp(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    void *cursor = data;
    __u16 eth_proto;

    if (parse_eth(&cursor, data_end, &eth_proto) < 0)
        return XDP_PASS;

    if (eth_proto == __constant_htons(ETH_P_IP)) {
        struct iphdr *iph = cursor;
        if ((void *)(iph + 1) > data_end)
            return XDP_PASS;
        if (iph->ihl < 5)
            return XDP_PASS;

        cursor = (void *)iph + (iph->ihl * 4);
        if (cursor > data_end)
            return XDP_PASS;

        if (iph->protocol == IPPROTO_UDP) {
            struct udphdr *udp = cursor;
            if ((void *)(udp + 1) > data_end)
                return XDP_PASS;
            return handle_l4(4, IPPROTO_UDP, udp->dest, (__u8 *)&iph->saddr, SIG_RATE_UDP_FLOOD);
        }
        if (iph->protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = cursor;
            if ((void *)(tcp + 1) > data_end)
                return XDP_PASS;
            __u8 packet_class = SIG_RATE_TCP_FLOOD;
            if (tcp->syn && !tcp->ack)
                packet_class = SIG_RATE_TCP_SYN_FLOOD;
            else if (tcp->ack && !tcp->syn)
                packet_class = SIG_RATE_TCP_ACK_FLOOD;
            return handle_l4(4, IPPROTO_TCP, tcp->dest, (__u8 *)&iph->saddr, packet_class);
        }
        if (iph->protocol == IPPROTO_ICMP) {
            if ((void *)cursor + ICMP_MIN_HEADER_BYTES > data_end)
                return XDP_PASS;
            return handle_icmp(4, (__u8 *)&iph->saddr);
        }
        return XDP_PASS;
    }

    if (eth_proto == __constant_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6h = cursor;
        if ((void *)(ip6h + 1) > data_end)
            return XDP_PASS;

        cursor = ip6h + 1;
        __u8 nexthdr = ip6h->nexthdr;
        if (parse_ipv6_l4(&cursor, data_end, &nexthdr) < 0)
            return XDP_PASS;

        if (nexthdr == IPPROTO_UDP) {
            struct udphdr *udp = cursor;
            if ((void *)(udp + 1) > data_end)
                return XDP_PASS;
            return handle_l4(6, IPPROTO_UDP, udp->dest, (__u8 *)&ip6h->saddr, SIG_RATE_UDP_FLOOD);
        }
        if (nexthdr == IPPROTO_TCP) {
            struct tcphdr *tcp = cursor;
            if ((void *)(tcp + 1) > data_end)
                return XDP_PASS;
            __u8 packet_class = SIG_RATE_TCP_FLOOD;
            if (tcp->syn && !tcp->ack)
                packet_class = SIG_RATE_TCP_SYN_FLOOD;
            else if (tcp->ack && !tcp->syn)
                packet_class = SIG_RATE_TCP_ACK_FLOOD;
            return handle_l4(6, IPPROTO_TCP, tcp->dest, (__u8 *)&ip6h->saddr, packet_class);
        }
        if (nexthdr == IPPROTO_ICMPV6) {
            if ((void *)cursor + ICMP_MIN_HEADER_BYTES > data_end)
                return XDP_PASS;
            return handle_icmp(6, (__u8 *)&ip6h->saddr);
        }
        return XDP_PASS;
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
