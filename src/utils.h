#ifndef __UTILS_H
#define __UTILS_H

#include <bpf/libbpf.h>
#include <netinet/in.h>

int id_from_prog_fd(int fd);
int id_from_map(struct bpf_map *map);
int bump_memlock_rlimit(void);

int xdp_attach(int ifindex, int prog_fd);
int xdp_detach(int ifindex);
int tc_attach(int ifindex, int prog_fd, enum bpf_tc_attach_point attach_point);
int tc_detach(int ifindex, enum bpf_tc_attach_point attach_point);

int pin_map(struct bpf_map *map, const char *path);
int pin_prog(struct bpf_program *prog, const char *path);

static const char *const protocol_names[] = {
	[IPPROTO_IP] = "IP",	     [IPPROTO_ICMP] = "ICMP",
	[IPPROTO_ICMPV6] = "ICMPV6", [IPPROTO_IGMP] = "IGMP",
	[IPPROTO_IPIP] = "IPIP",     [IPPROTO_TCP] = "TCP",
	[IPPROTO_EGP] = "EGP",	     [IPPROTO_PUP] = "PUP",
	[IPPROTO_UDP] = "UDP",	     [IPPROTO_IDP] = "IDP",
	[IPPROTO_TP] = "TP",	     [IPPROTO_DCCP] = "DCCP",
	[IPPROTO_IPV6] = "IPV6",     [IPPROTO_RSVP] = "RSVP",
	[IPPROTO_GRE] = "GRE",	     [IPPROTO_ESP] = "ESP",
	[IPPROTO_AH] = "AH",	     [IPPROTO_MTP] = "MTP",
	[IPPROTO_BEETPH] = "BEETPH", [IPPROTO_ENCAP] = "ENCAP",
	[IPPROTO_PIM] = "PIM",	     [IPPROTO_COMP] = "COMP",
	[IPPROTO_SCTP] = "SCTP",     [IPPROTO_UDPLITE] = "UDPLITE",
	[IPPROTO_MPLS] = "MPLS",     [IPPROTO_ETHERNET] = "ETHERNET",
	[IPPROTO_RAW] = "RAW",	     [IPPROTO_MPTCP] = "MPTCP"
};

#endif /* __UTILS_H */