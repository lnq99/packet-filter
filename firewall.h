#ifndef FIREWALL_H
#define FIREWALL_H

#include <linux/list.h>
#include "init.h"

// is_block type proto addr
struct firewall_rule
{
    struct list_head list;
    char proto[8];           // ''-all
    u32 addr;                // Source and destination addresses
    unsigned short type;     // 0-incoming, 1-outgoing
    unsigned short is_block; // 1-block
};

void firewall_init(void);

void firewall_free(void);

void add_rule(struct firewall_rule *rule);

int accept_packet(struct packet *packet);

int compare_rule(struct firewall_rule *r1, struct firewall_rule *r2);

#endif