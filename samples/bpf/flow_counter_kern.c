#include <uapi/linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/if_vlan.h>

#include "flow_counter_common.h"

struct bpf_map_def SEC("maps") rx_flows = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct entry),
	.max_entries = 100,
};

static __u32 get_ipv4_saddr(void *data, u64 nh_off, void *data_end)
{
	struct iphdr *iph = data + nh_off;

	if (iph + 1 > data_end)
		return 0;
	return iph->saddr;
}

SEC("xdp_counter")
int _xdp_counter(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	struct entry *value;
	u16 h_proto;
	u64 nh_off;
	u32 ipproto;
	__u32 saddr;

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

	if (h_proto == htons(ETH_P_IP))
		saddr = get_ipv4_saddr(data, nh_off, data_end);
	else
		return XDP_PASS;

	value = bpf_map_lookup_elem(&rx_flows, &saddr);
	if (!value) {
		struct entry new_value = {
			.n_packets = 1,
			.n_bytes = (__u64)(data_end - data) - nh_off,
		};

		bpf_map_update_elem(&rx_flows, &saddr, &new_value, BPF_NOEXIST);
	} else {
		value->n_packets += 1;
		value->n_bytes   += (__u64)(data_end - data) - nh_off;
	}

	return XDP_PASS;
}
