#include <bpf/bpf.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <linux/if_link.h>
#include "utils.h"

int id_from_prog_fd(int fd)
{
	struct bpf_prog_info prog_info = {};
	__u32 prog_info_len = sizeof(prog_info);
	int err;

	err = bpf_obj_get_info_by_fd(fd, &prog_info, &prog_info_len);
	if (err) {
		fprintf(stderr, "ERR: bfp_obj_get_info_by_fd %d:%s\n", err,
			strerror(-err));
		return 0;
	}

	return prog_info.id;
}

int id_from_map(struct bpf_map *map)
{
	struct bpf_map_info info;
	__u32 info_len = sizeof(info);
	int err;

	memset(&info, 0, info_len);
	err = bpf_map_get_info_by_fd(bpf_map__fd(map), &info, &info_len);
	if (err)
		return 0;

	return info.id;
}

int bump_memlock_rlimit(void)
{
	int err;

	struct rlimit rlim_new = {
		.rlim_cur = RLIM_INFINITY,
		.rlim_max = RLIM_INFINITY,
	};

	err = setrlimit(RLIMIT_MEMLOCK, &rlim_new);
	if (err == -1) {
		fprintf(stderr,
			"ERR: Failed to increase RLIMIT_MEMLOCK limit: %s\n",
			strerror(errno));
		return err;
	}

	return 0;
}

int xdp_attach(int ifindex, int prog_fd)
{
	int err;

	err = bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_UPDATE_IF_NOEXIST,
			     NULL);
	if (err) {
		fprintf(stderr,
			"ERR: Failed to attach xdp program to dev %d: %d\n",
			ifindex, -err);
		return -err;
	}

	return err;
}

int xdp_detach(int ifindex)
{
	int err;

	err = bpf_xdp_detach(ifindex, 0, NULL);
	if (err) {
		fprintf(stderr,
			"ERR: Failed to detach xdp program from dev %d: %d\n",
			ifindex, err);
		return err;
	}

	return err;
}

int tc_attach(int ifindex, int prog_fd, enum bpf_tc_attach_point attach_point)
{
	LIBBPF_OPTS(bpf_tc_hook, hook, .ifindex = ifindex,
		    .attach_point = attach_point);
	LIBBPF_OPTS(bpf_tc_opts, opts, .handle = 1, .priority = 1,
		    .prog_fd = prog_fd);
	int err;

	err = bpf_tc_hook_create(&hook);
	if (err && err != -EEXIST) {
		fprintf(stderr,
			"ERR: Failed to create tc hook for dev %d: %d\n",
			ifindex, -err);
	}

	err = bpf_tc_attach(&hook, &opts);
	if (err) {
		fprintf(stderr,
			"ERR: Failed to attach tc program to dev %d: %d\n",
			ifindex, -err);
	}

	return err;
}

int tc_detach(int ifindex, enum bpf_tc_attach_point attach_point)
{
	int err;
	DECLARE_LIBBPF_OPTS(bpf_tc_hook, tc_hook, .ifindex = ifindex,
			    .attach_point = attach_point);

	err = bpf_tc_hook_destroy(&tc_hook);
	if (err) {
		fprintf(stderr,
			"ERR: Failed to destroy tc hook from dev %d: %d\n",
			ifindex, err);
		return err;
	}

	return err;
}

int pin_map(struct bpf_map *map, const char *path)
{
	int err;
	struct stat statbuf;

	err = bpf_map__reuse_fd(map, bpf_map__fd(map));
	if (err) {
		fprintf(stderr, "ERR: reuse fd %s: %d\n", path, err);
		return err;
	}

	if (stat(path, &statbuf) == -1) {
		err = bpf_map__pin(map, path);
		if (err) {
			fprintf(stderr, "ERR: Failed to pin map to %s: %d\n",
				path, err);
			return err;
		}
	}

	return 0;
}

int pin_prog(struct bpf_program *prog, const char *path)
{
	struct stat statbuf;
	int err;

	if (stat(path, &statbuf) == -1) {
		err = bpf_program__pin(prog, path);
		if (err) {
			fprintf(stderr, "ERR: Failed to pin program: %d\n",
				-err);
			return err;
		}
	}

	return 0;
}