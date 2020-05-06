// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2016 PLUMgrid
 */
#include <linux/bpf.h>
#include <linux/if_link.h>
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libgen.h>
#include <sys/resource.h>
#include <net/if.h>

#include "bpf_util.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <arpa/inet.h>
#include <netinet/in.h>

static int ifindex;
static __u32 xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST;
static __u32 prog_id;

static void int_exit(int sig)
{
	__u32 curr_prog_id = 0;

	if (bpf_get_link_xdp_id(ifindex, &curr_prog_id, xdp_flags)) {
		printf("bpf_get_link_xdp_id failed\n");
		exit(1);
	}
	if (prog_id == curr_prog_id)
		bpf_set_link_xdp_fd(ifindex, -1, xdp_flags);
	else if (!curr_prog_id)
		printf("couldn't find a prog id on a given interface\n");
	else
		printf("program on interface changed, not removing\n");
	exit(0);
}

/* simple per-protocol drop counter
 */
static void poll_stats(int map_fd, int interval, __be32 key)
{
	unsigned int nr_cpus = bpf_num_possible_cpus();
	__u64 values[nr_cpus], old[nr_cpus];
	__u64 sum = 0;
	int i;

	memset(old, 0, sizeof(old));

	while (1) {
		int err;

		sleep(2);
		err = bpf_map_lookup_elem(map_fd, &key, &values);
		if (err) {
			printf("failed map lookup - %s\n", strerror(errno));
			exit(1);
		}
		for (i = 0; i < nr_cpus; i++)
			if (values[i] > old[i]) {
				sum += values[i];
				old[i] = values[i];
			}
		printf("Dropped packets: %lld\n", sum);
	}
}

static void usage(const char *prog)
{
	fprintf(stderr,
		"usage: %s IFACE IP_to_drop\n",
		prog);
}

int main(int argc, char **argv)
{
	struct bpf_prog_load_attr prog_load_attr = {
		.prog_type	= BPF_PROG_TYPE_XDP,
	};
	struct bpf_prog_info info = {};
	__u32 info_len = sizeof(info);
	int prog_fd, map_fd;
	struct bpf_object *obj;
	struct bpf_map *map;
	char filename[256];
	int err;
	__be32 daddr;
	unsigned int nr_cpus = bpf_num_possible_cpus();
	__u64 values[nr_cpus];

	if (argc != 3) {
		usage(argv[0]);
		return 1;
	}

	memset(values, 0, sizeof(values));


	ifindex = if_nametoindex(argv[1]);
	if (!ifindex) {
		perror("if_nametoindex");
		return 1;
	}

	err = inet_pton(AF_INET, argv[2], &daddr);
	if (err != 1) {
		printf("can't translate IP to filter - %s\n", strerror(errno));
		return err;
	}

	snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);
	prog_load_attr.file = filename;

	if (bpf_prog_load_xattr(&prog_load_attr, &obj, &prog_fd))
		return 1;

	map = bpf_object__find_map_by_name(obj, "rx_drop");
	if (!map) {
		printf("finding a map in obj file failed\n");
		return 1;
	}
	map_fd = bpf_map__fd(map);

	if (!prog_fd) {
		printf("bpf_prog_load_xattr: %s\n", strerror(errno));
		return 1;
	}

	signal(SIGINT, int_exit);
	signal(SIGTERM, int_exit);

	if (bpf_set_link_xdp_fd(ifindex, prog_fd, xdp_flags) < 0) {
		printf("link set xdp fd failed\n");
		return 1;
	}

	err = bpf_obj_get_info_by_fd(prog_fd, &info, &info_len);
	if (err) {
		printf("can't get prog info - %s\n", strerror(errno));
		return err;
	}
	prog_id = info.id;


	err = bpf_map_update_elem(map_fd, &daddr, &values, BPF_ANY);
	if (err == -1) {
		printf("can't add IP to filter - %s\n", strerror(errno));
		return err;
	}

	poll_stats(map_fd, 2, daddr);

	return 0;
}
