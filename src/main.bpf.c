#include "../vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>
#include "../include/omega.h"


#define ETH_P_IP 0x0800

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");


SEC("xdp")
int receive_egress(struct xdp_md *ctx) {
	struct packet_evt *evt = {0};
	
	evt = bpf_ringbuf_reserve(&rb, sizeof(*evt), 0);
	if (!evt) {
    	return XDP_PASS;
	}
    
	void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
		goto failure;
    }

    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
		goto failure;
    }

    struct iphdr *ip = data + sizeof(struct ethhdr);
    if ((void *)(ip + 1) > data_end) {
		goto failure;
    }

    if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + sizeof(struct iphdr);
        if ((void *)(udp + 1) > data_end) {
			goto failure;
        }

        __u16 src_port = bpf_ntohs(udp->source);
        __u16 dest_port = bpf_ntohs(udp->dest);

		if (evt) {
	    	evt->src_ip = ip->saddr;
    		evt->dst_ip = ip->daddr;
	    	evt->src_port = src_port;
    		evt->dst_port = dest_port;

    		bpf_printk("Submitting Event: SRC IP: %x DST IP: %x SRC PORT: %d DST PORT: %d\n",
        	evt->src_ip, evt->dst_ip, evt->src_port, evt->dst_port);
		} else {
    		bpf_printk("Ring buffer reservation failed\n");
			goto failure;
		}
    } else if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + sizeof(struct iphdr);
        if ((void *)(tcp + 1) > data_end) {
			goto failure;
        }

        __u16 src_port = bpf_ntohs(tcp->source);
        __u16 dest_port = bpf_ntohs(tcp->dest);

		if (evt) {
	    	evt->src_ip = ip->saddr;
    		evt->dst_ip = ip->daddr;
	    	evt->src_port = src_port;
    		evt->dst_port = dest_port;

    		bpf_printk("Submitting Event: SRC IP: %x DST IP: %x SRC PORT: %d DST PORT: %d\n",
        	evt->src_ip, evt->dst_ip, evt->src_port, evt->dst_port);
		} else {
    		bpf_printk("Ring buffer reservation failed\n");
			goto failure;
		}
    }

	bpf_ringbuf_submit(evt, 0);
	bpf_printk("Evt submit done!\n");
    return XDP_PASS;

	failure:
		bpf_printk("Failure!\n");
		bpf_ringbuf_discard(evt, 0);
		return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
