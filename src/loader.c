#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <linux/if_link.h>
#include <linux/bpf.h>
#include <sys/resource.h>
#include <net/if.h>
#include "../include/omega.h"


#define INTERFACE "enp4s0"


// Improvement: Checking for signal and when program exists properly cleanup and detach from network interface


// Print MAC address
void print_mac(__u8 *mac) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

// Callback for received events
static int handle_evt(void *ctx, void *data, size_t sz) {
    const struct packet_evt *evt = data;

    fprintf(stdout, "Received Event: SRC IP: %u DST IP: %u SRC PORT: %u DST PORT: %u\n",
        evt->src_ip, evt->dst_ip, evt->src_port, evt->dst_port);
    fflush(stdout);

    return 0;
}

int main() {
    struct bpf_object *obj;
    struct ring_buffer *rb = NULL;
    int map_fd, prog_fd, ifindex;

    ifindex = if_nametoindex(INTERFACE);
    if (!ifindex) {
        perror("Failed to get interface index");
        return 1;
    }
	printf("IF INDEX:%d\n", ifindex);

    obj = bpf_object__open_file("omega.bpf.o", NULL);
    if (!obj) {
        perror("Failed to open eBPF object file");
        return 1;
    }

// Load the BPF program into the kernel
if (bpf_object__load(obj)) {
    perror("Failed to load eBPF object");
    return 1;
}

// Debug: List all programs
struct bpf_program *prog;
bpf_object__for_each_program(prog, obj) {
    printf("Found BPF program: %s\n", bpf_program__name(prog));
}


    prog_fd = bpf_program__fd(bpf_object__find_program_by_name(obj, "receive_egress"));
    if (prog_fd < 0) {
        perror("Failed to find BPF program");
        return 1;
    }

    if (bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_UPDATE_IF_NOEXIST, NULL) < 0) {
        perror("Failed to attach XDP program");
        return 1;
    }

    map_fd = bpf_map__fd(bpf_object__find_map_by_name(obj, "rb"));
    if (map_fd < 0) {
        perror("Failed to find BPF ring buffer map");
        return 1;
    }

    rb = ring_buffer__new(map_fd, handle_evt, NULL, NULL);
    if (!rb) {
        perror("Failed to create ring buffer");
        return 1;
    }

    printf("Listening for packets on %s...\n", INTERFACE);

    while (1) {
        ring_buffer__poll(rb, 100);
    }

    return 0;
}

