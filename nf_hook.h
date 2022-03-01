#ifndef NF_HOOK_H
#define NF_HOOK_H

#include <linux/netfilter.h>
#include <linux/skbuff.h>
#include "init.h"

unsigned int nf_hook_in(void *priv,
                        struct sk_buff *skb,
                        const struct nf_hook_state *state);

unsigned int nf_hook_out(void *priv,
                         struct sk_buff *skb,
                         const struct nf_hook_state *state);

#endif