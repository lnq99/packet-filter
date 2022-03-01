#ifndef INIT_H
#define INIT_H

#define NAME "+NF: "
#define IP_FMT "%15pI4"

struct packet
{
    char proto[8];      // Protocol
    u32 saddr, daddr;   // Source and destination addresses
    unsigned int size;  // Total size
    unsigned char type; // 0-incoming, 1-outgoing
    char info[128];
};

#endif