#define KBUILD_MODNAME "xdp_drop"
#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <bpf/bpf_helpers.h>

#include "xdp_drop_common.h"

struct bpf_map_def SEC("maps") rx_drop = {
	.type = BPF_MAP_TYPE_PERCPU_HASH,
	.key_size = sizeof(__be32), // IP
	.value_size = sizeof(__u64), // Bytes transmitted
	.max_entries = 100,
};

static int parse_ipv4(void *data, u64 nh_off, void *data_end)
{
	struct iphdr *iph = data + nh_off;

	if (iph + 1 > data_end)
		return 0;
	return iph->protocol;
}

static __u32 parse_ipv4_daddr(void *data, u64 nh_off, void *data_end)
{
	struct iphdr *iph = data + nh_off;

	if (iph + 1 > data_end)
		return 0;
	return iph->daddr;
}


static int parse_ipv6(void *data, u64 nh_off, void *data_end)
{
	struct ipv6hdr *ip6h = data + nh_off;

	if (ip6h + 1 > data_end)
		return 0;
	return ip6h->nexthdr;
}

SEC("xdp1")
int xdp_prog1(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	__u64 *value;
	u16 h_proto;
	u64 nh_off;

	nh_off = sizeof(*eth);
	if (data + nh_off > data_end)
		return XDP_DROP;

	h_proto = eth->h_proto;

	if (h_proto == htons(ETH_P_8021Q) || h_proto == htons(ETH_P_8021AD)) {
		struct vlan_hdr *vhdr;

		vhdr = data + nh_off;
		nh_off += sizeof(struct vlan_hdr);
		if (data + nh_off > data_end)
			return XDP_DROP;
		h_proto = vhdr->h_vlan_encapsulated_proto;
	}

	if (h_proto != htons(ETH_P_IP)) {
		return XDP_PASS;
	}

	__be32 daddr = parse_ipv4_daddr(data, nh_off, data_end);
	value = bpf_map_lookup_elem(&rx_drop, &daddr);	
	if (value) {
		bpf_printk("Dest IP matched\n");
		*value += 1;
		return XDP_DROP;
	}
	bpf_printk("Dest IP didn't msssatch\n");

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
