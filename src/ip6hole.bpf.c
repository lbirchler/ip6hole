#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "ip6hole.h"

#define TC_ACT_OK 0
#define TC_ACT_SHOT 2

#ifndef ETH_P_IPV6
#define ETH_P_IPV6 0x86DD
#endif

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} ip6hole_ringbuf SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 100);
	__type(key, __u32);
	__type(value, struct prog_ctx);
} ip6hole_interface_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} ip6hole_display_map SEC(".maps");

static __always_inline void parse_udp(void *data, void *data_end, __u64 off,
				      struct event_t *e)
{
	struct udphdr *udp;

	udp = data + off;
	off += sizeof(*udp);
	if ((void *)udp + off > data_end)
		return;

	e->port16[0] = udp->dest;
	e->port16[1] = udp->source;
}

static __always_inline void parse_tcp(void *data, void *data_end, __u64 off,
				      struct event_t *e)
{
	struct tcphdr *tcp;

	tcp = data + off;
	off += sizeof(*tcp);
	if ((void *)tcp + off > data_end)
		return;

	e->port16[0] = tcp->dest;
	e->port16[1] = tcp->source;
}

static __always_inline int process_packet(void *data, void *data_end, __u64 off,
					  __u32 ifindex, int filter_type)
{
	struct event_t *e, event = {};
	struct ipv6hdr *ip6h;
	__u32 key = 0, *value = NULL;

	/* only display if display_map value set to 1 */
	value = bpf_map_lookup_elem(&ip6hole_display_map, &key);
	if (!value || (*value != 1))
		return 0;

	ip6h = data + off;
	off += sizeof(*ip6h);
	if ((void *)ip6h + off > data_end)
		return 0;

	event.ifindex = ifindex;
	event.filter_type = filter_type;
	event.protocol = ip6h->nexthdr;
	event.saddr = ip6h->saddr;
	event.daddr = ip6h->daddr;
	event.pkt_bytes = __bpf_ntohs(ip6h->payload_len);

	if (event.protocol == IPPROTO_TCP)
		parse_tcp(data, data_end, off, &event);
	else if (event.protocol == IPPROTO_UDP)
		parse_udp(data, data_end, off, &event);

	e = bpf_ringbuf_reserve(&ip6hole_ringbuf, sizeof(event), 0);
	if (e) {
		*e = event;
		bpf_ringbuf_submit(e, 0);
	}

	return 0;
}

SEC("tc")
int ip6hole_egress(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct ethhdr *eth = data;
	__u64 off;

	off = sizeof(*eth);
	if (data + off > data_end)
		return TC_ACT_OK;

	if (eth->h_proto == __bpf_ntohs(ETH_P_IPV6)) {
		process_packet(data, data_end, off, skb->ifindex, EGRESS);
		return TC_ACT_SHOT;
	}

	return TC_ACT_OK;
}

SEC("xdp")
int ip6hole_ingress(struct xdp_md *xdp)
{
	void *data = (void *)(long)xdp->data;
	void *data_end = (void *)(long)xdp->data_end;
	struct ethhdr *eth = data;
	__u64 off;

	off = sizeof(*eth);
	if (data + off > data_end)
		return XDP_PASS;

	if (eth->h_proto == __bpf_htons(ETH_P_IPV6)) {
		process_packet(data, data_end, off, xdp->ingress_ifindex,
			       INGRESS);
		return XDP_DROP;
	}

	return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";