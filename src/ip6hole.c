#include <argp.h>
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <signal.h>
#include <sys/stat.h>
#include <unistd.h>
#include "ip6hole.h"
#include "ip6hole.skel.h"
#include "utils.h"

#define MAX_IFACE_NUM 32
static int ifaces[MAX_IFACE_NUM] = {};

static struct env {
	bool add;
	bool remove;
	bool remove_all;
	bool status;
	bool display;
	bool verbose;
} env;

const char *pindir = "/sys/fs/bpf/ip6hole";
const char *interface_map_path = "/sys/fs/bpf/ip6hole/interface_map";
const char *ringbuf_map_path = "/sys/fs/bpf/ip6hole/ringbuf_map";
const char *display_map_path = "/sys/fs/bpf/ip6hole/display_map";
const char *ingress_prog_path = "/sys/fs/bpf/ip6hole/ingress_prog";
const char *egress_prog_path = "/sys/fs/bpf/ip6hole/egress_prog";

static const char
	*const filter_map[] = { [EGRESS] = "EGRESS", [INGRESS] = "INGRESS" };

const char doc[] = "Drop IPv6 Traffic.\n"
		   "\n"
		   "USAGE: ip6hole [-a DEV] [-A] [-r DEV] [-R] [-s] [-d]\n";

static const struct argp_option options[] = {
	{ "add", 'a', "DEV", 0, "Add device" },
	{ "add-all", 'A', 0, 0, "Add all devices" },
	{ "remove", 'r', "DEV", 0, "Remove device" },
	{ "remove-all", 'R', 0, 0, "Remove all devices" },
	{ "status", 's', NULL, 0, "Display devices dropping IPv6 traffic" },
	{ "display", 'd', NULL, 0, "Display dropped IPv6 traffic" },
	{ "verbose", 'v', 0, 0, "Verbose debug output" },
	{ 0 },
};

static int get_ifaces()
{
	int i;
	struct if_nameindex *if_nis, *if_ni;

	if_nis = if_nameindex();
	if (if_nis == NULL) {
		perror("if_nameindex");
		return -1;
	}

	for (i = 0, if_ni = if_nis;
	     !(if_ni->if_index == 0 && if_ni->if_name == NULL); if_ni++, i++)
		ifaces[i] = if_ni->if_index;

	if_freenameindex(if_nis);

	return 0;
}

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	static int pos_args;

	switch (key) {
	case 's':
		env.status = true;
		break;
	case 'd':
		env.display = true;
		break;
	case 'v':
		env.verbose = true;
		break;
	case 'a':
		ifaces[0] = if_nametoindex(arg);
		if (!ifaces[0]) {
			fprintf(stderr, "Invalid interface: %s\n", arg);
			goto ret;
		}
		env.add = true;
		break;
	case 'A':
		if (get_ifaces())
			goto ret;
		env.add = true;
		break;
	case 'r':
		ifaces[0] = if_nametoindex(arg);
		if (!ifaces[0]) {
			fprintf(stderr, "Invalid interface: %s\n", arg);
			goto ret;
		}
		env.remove = true;
		break;
	case 'R':
		if (get_ifaces())
			goto ret;
		env.remove_all = true;
		break;
	case ARGP_KEY_ARG:
		if (pos_args++) {
			fprintf(stderr,
				"Unrecognized positional argument: %s\n", arg);
			argp_usage(state);
		}
		errno = 0;
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;

ret:
	return 1;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
			   va_list args)
{
	if (level == LIBBPF_DEBUG && env.verbose)
		vfprintf(stderr, format, args);
	return 0;
}

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

static int attach_progs(int ingress_prog, int egress_prog)
{
	int map_fd, i, err = 0;
	__u32 ifindex;
	struct prog_ctx ctx = {};

	map_fd = bpf_obj_get(interface_map_path);
	if (map_fd < 0) {
		fprintf(stderr, "ERR: Failed to open interface map: %d\n",
			map_fd);
		return map_fd;
	}

	for (i = 0; ifaces[i] > 0; i++) {
		ifindex = ifaces[i];

		err = bpf_map_lookup_elem(map_fd, &ifindex, &ctx);
		if (err) /* doesn't exist */ {
			/* Attach progs */
			if (xdp_attach(ifindex, ingress_prog) != 0)
				break;
			if (tc_attach(ifindex, egress_prog, BPF_TC_EGRESS) != 0)
				break;

			/* Update interface map */
			ctx.ifindex = ifindex;
			ctx.egress_id = id_from_prog_fd(egress_prog);
			ctx.ingress_id = id_from_prog_fd(ingress_prog);

			err = bpf_map_update_elem(map_fd, &ifindex, &ctx,
						  BPF_ANY);
			if (err && err != -EEXIST) {
				fprintf(stderr,
					"ERR: Failed to add dev %d to interface map: %d\n",
					ifindex, -err);
				break;
			}
		}
	}

	close(map_fd);

	return err;
}

static void cleanup_progs()
{
	int map_fd;
	__u32 key, *prev_key = NULL;
	struct prog_ctx value = {};

	map_fd = bpf_obj_get(interface_map_path);
	if (map_fd < 0) {
		fprintf(stderr, "ERR: Failed to open interface map: %d\n",
			map_fd);
		return;
	}

	while (bpf_map_get_next_key(map_fd, prev_key, &key) == 0) {
		if ((bpf_map_lookup_elem(map_fd, &key, &value)) == 0) {
			xdp_detach(value.ifindex);
			tc_detach(value.ifindex, BPF_TC_EGRESS);
		}
		prev_key = &key;
	}

	close(map_fd);
}

static void cleanup_prog()
{
	int map_fd, i, err;
	__u32 key;
	struct prog_ctx value = {};

	map_fd = bpf_obj_get(interface_map_path);
	if (map_fd < 0) {
		fprintf(stderr, "ERR: Failed to open interface map: %d\n",
			map_fd);
		return;
	}

	for (i = 0; ifaces[i] > 0; i++) {
		key = ifaces[i];
		if ((bpf_map_lookup_elem(map_fd, &key, &value)) == 0) {
			xdp_detach(value.ifindex);
			tc_detach(value.ifindex, BPF_TC_EGRESS);
			err = bpf_map_delete_elem(map_fd, &key);
			if (err) {
				fprintf(stderr,
					"ERR: Failed to delete dev %d from interface map: %d\n",
					key, err);
			}
		}
	}

	close(map_fd);
}

static inline void ip6_addr(const struct in6_addr *addr, uint16_t port,
			    char *dst)
{
	/* add port to end of address for TCP and UDP traffic */
	if (port) {
		char ip6[INET6_ADDRSTRLEN];
		inet_ntop(AF_INET6, addr, ip6, INET6_ADDRSTRLEN);
		sprintf(dst, "%s.%d", ip6, port);
	} else
		inet_ntop(AF_INET6, addr, dst, INET6_ADDRSTRLEN);
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event_t *e = data;
	char ip6_src[INET6_ADDRSTRLEN + 6];
	char ip6_dst[INET6_ADDRSTRLEN + 6];

	ip6_addr(&(e->saddr), ntohs(e->port16[0]), ip6_src);
	ip6_addr(&(e->daddr), ntohs(e->port16[1]), ip6_dst);

	printf("[%d] %-7s %-7s %s > %s, pkt_bytes %d\n", e->ifindex,
	       protocol_names[e->protocol], filter_map[e->filter_type], ip6_src,
	       ip6_dst, e->pkt_bytes);

	return 0;
}

static void print_events()
{
	int rb_map_fd, disp_map_fd, err, key = 0, value;
	struct ring_buffer *rb;

	rb_map_fd = bpf_obj_get(ringbuf_map_path);
	if (rb_map_fd < 0) {
		if (rb_map_fd != -ENOENT)
			fprintf(stderr, "ERR: Failed to open ringbuf map: %d\n",
				rb_map_fd);
		return;
	}

	disp_map_fd = bpf_obj_get(display_map_path);
	if (disp_map_fd < 0) {
		fprintf(stderr, "ERR: Failed to open display map: %d\n",
			disp_map_fd);
		close(rb_map_fd);
		return;
	}

	/* update display_map value */
	value = 1;
	bpf_map_update_elem(disp_map_fd, &key, &value, BPF_ANY);

	rb = ring_buffer__new(rb_map_fd, handle_event, NULL, NULL);
	if (!rb) {
		fprintf(stderr, "ERR: Failed to create ringbuf\n");
		close(rb_map_fd);
		close(disp_map_fd);
		return;
	}

	while (!exiting) {
		err = ring_buffer__poll(rb, -1);
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			fprintf(stderr, "ERR: ring buffer poll: %d\n", err);
			break;
		}
	}

	/* update display_map value */
	value = 0;
	bpf_map_update_elem(disp_map_fd, &key, &value, BPF_ANY);

	close(rb_map_fd);
	close(disp_map_fd);
}

static void print_interface_map()
{
	int map_fd;
	__u32 key, *prev_key = NULL;
	struct prog_ctx value = {};

	map_fd = bpf_obj_get(interface_map_path);
	if (map_fd < 0) {
		if (map_fd != -ENOENT)
			fprintf(stderr,
				"ERR: Failed to open interface map: %d\n",
				-map_fd);
		return;
	}

	while (bpf_map_get_next_key(map_fd, prev_key, &key) == 0) {
		if ((bpf_map_lookup_elem(map_fd, &key, &value)) == 0) {
			printf("dev: %d ingress prog id: %d egress prog id: %d\n",
			       value.ifindex, value.ingress_id,
			       value.egress_id);
		}
		prev_key = &key;
	}

	close(map_fd);
}

static struct ip6hole_bpf *skel = NULL;

static int setup()
{
	int err = 0;
	struct stat statbuf;

	if (stat(pindir, &statbuf) == 0) /* maps and programs already pinned */
		return 0;

	/* initial setup */
	skel = ip6hole_bpf__open_and_load();
	if (!skel) {
		err = errno;
		fprintf(stderr, "ERR: Failed to open and load skeleton\n");
		return err;
	}

	/* pin ingress and egress programs */
	err = pin_prog(skel->progs.ip6hole_ingress, ingress_prog_path);
	if (err)
		goto ret;

	err = pin_prog(skel->progs.ip6hole_egress, egress_prog_path);
	if (err)
		goto ret;

	/* pin interface ringbuf and display maps */
	err = pin_map(skel->maps.ip6hole_interface_map, interface_map_path);
	if (err)
		goto ret;

	err = pin_map(skel->maps.ip6hole_ringbuf, ringbuf_map_path);
	if (err)
		goto ret;

	err = pin_map(skel->maps.ip6hole_display_map, display_map_path);
	if (err)
		goto ret;

	return err;

ret:
	unlink(ingress_prog_path);
	unlink(egress_prog_path);
	unlink(interface_map_path);
	unlink(ringbuf_map_path);
	unlink(display_map_path);
	rmdir(pindir);
	ip6hole_bpf__destroy(skel);
	return err;
}

int main(int argc, char **argv)
{
	static const struct argp argp = {
		.options = options,
		.parser = parse_arg,
		.doc = doc,
	};
	int ingress_prog, egress_prog, err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	/* setup libbpf errors and debug info callback */
	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	libbpf_set_print(libbpf_print_fn);

	/* bump RLIMIT_MEMLOCK to create BPF maps */
	err = bump_memlock_rlimit();
	if (err && errno == EPERM)
		exit(1);

	/* cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* commands */
	if (env.display) {
		print_events();
		return 0;
	}

	if (env.status) {
		print_interface_map();
		return 0;
	}

	if (setup() != 0)
		return 1;

	if (env.add) {
		if (skel) {
			ingress_prog =
				bpf_program__fd(skel->progs.ip6hole_ingress);
			egress_prog =
				bpf_program__fd(skel->progs.ip6hole_egress);
			err = attach_progs(ingress_prog, egress_prog);
		} else {
			ingress_prog = bpf_obj_get(ingress_prog_path);
			egress_prog = bpf_obj_get(egress_prog_path);
			err = attach_progs(ingress_prog, egress_prog);
			close(ingress_prog);
			close(egress_prog);
		}
		return err;
	}

	if (env.remove) {
		cleanup_prog();
		return 0;
	}

	if (env.remove_all) {
		cleanup_progs();
		unlink(ingress_prog_path);
		unlink(egress_prog_path);
		unlink(interface_map_path);
		unlink(ringbuf_map_path);
		unlink(display_map_path);
		rmdir(pindir);
		return 0;
	}
}