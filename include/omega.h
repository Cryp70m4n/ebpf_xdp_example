#ifndef __OMEGA_H__
#define __OMEGA_H__


#define MAX_EVENT_LEN 24



struct packet_evt {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
};

#endif // __OMEGA_H__
