#include <uapi/linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/if_vlan.h>

//      (name, key_type, value_type)
BPF_HASH(rx_flows, u32, int);

static u32 get_ipv4_saddr(void *data, u64 nh_off, void *data_end)
{
	struct iphdr *iph = data + nh_off;

	if ((void *)(iph + 1) > data_end)
		return 0;
	return iph->saddr;
}

int xdp_counter(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	int *value;
	u16 h_proto;
	u64 nh_off;
	u32 ipproto;
	u32 saddr;

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

	value = rx_flows.lookup(&saddr);
	if (value)
		*value += 1;
	else {
		int value = 1;
		rx_flows.update(&saddr, &value);
	}

	return XDP_PASS;
}
