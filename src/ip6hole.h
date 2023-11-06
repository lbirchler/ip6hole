#ifndef __IP6HOLE_H
#define __IP6HOLE_H

struct prog_ctx {
	int ifindex;
	__u32 egress_id;
	__u32 ingress_id;
};

struct event_t {
	__u32 ifindex;
	__u32 filter_type;
	struct in6_addr saddr;
	struct in6_addr daddr;
	__u16 port16[2];
	__u8 protocol;
	__u16 pkt_bytes;
};

enum { EGRESS, INGRESS };

#endif /* __IP6HOLE_H */