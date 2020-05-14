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
#include <arpa/inet.h>

#include "bpf_util.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "flow_counter_common.h"

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

static void flow_id_to_string(__u32 flow_id, char* str, int len)
{
	inet_ntop(AF_INET, &flow_id, str, len);
}

static void print_flow(__u32 flow_id, const struct entry* value)
{
	char str[256];

	flow_id_to_string(flow_id, str, sizeof(str));
	printf("%s\t%lld\t%lld\n",
		str,
		value->n_packets,
		value->n_bytes);
}

static void poll_flow_stats(int map_fd, int interval)
{
	struct entry value;

	while (1) {
		__u32 current_key = UINT32_MAX;
		__u32 next_key;

		sleep(interval);

		while (bpf_map_get_next_key(map_fd, &current_key, &next_key) != -1) {
			current_key = next_key;
			bpf_map_lookup_elem(map_fd, &current_key, &value);
			print_flow(current_key, &value);
		}
	}
}

int main(int argc, char **argv)
{
	struct bpf_prog_load_attr prog_load_attr = {
		.prog_type	= BPF_PROG_TYPE_XDP,
		.file = "flow_counter_kern.o",
	};
	struct bpf_prog_info info = {};
	__u32 info_len = sizeof(info);
	struct bpf_object *obj;
	struct bpf_map *map;
	const char *if_name;
	int prog_fd, map_fd, err;

	if (argc != 2) {
		printf("Usage: %s IF_NAME\n", argv[0]);
		return 1;
	}
	if_name = argv[1];

//	snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);
//	prog_load_attr.file = filename;

	if (bpf_prog_load_xattr(&prog_load_attr, &obj, &prog_fd))
		return 1;

	map = bpf_map__next(NULL, obj);
	if (!map) {
		printf("finding a map in obj file failed\n");
		return 1;
	}
	map_fd = bpf_map__fd(map);

	ifindex = if_nametoindex(if_name);
	if (!ifindex) {
		perror("if_nametoindex");
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

	poll_flow_stats(map_fd, 2);
	return 0;
}
