#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include "init.h"
#include "firewall.h"
#include "nf_hook.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Le Nhu Quang");
MODULE_DESCRIPTION("Log and filter packets");

struct nf_hook_ops in_nfho = {
    .hook = nf_hook_in,
    .hooknum = NF_INET_LOCAL_IN,
    .pf = PF_INET,
    .priority = NF_IP_PRI_FIRST,
};
struct nf_hook_ops out_nfho = {
    .hook = nf_hook_out,
    .hooknum = NF_INET_LOCAL_OUT,
    .pf = PF_INET,
    .priority = NF_IP_PRI_FIRST,
};

static int __init md_init(void)
{
    firewall_init();

    int res1, res2;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
    res1 = nf_register_net_hook(&init_net, &in_nfho);
    res2 = nf_register_net_hook(&init_net, &out_nfho);
#else
    res1 = nf_register_hook(&in_nfho);
    res2 = nf_register_hook(&out_nfho);
#endif
    if (res1 < 0 || res2 < 0)
    {
        printk(KERN_DEBUG NAME "error nf_register_net_hook\n");
        return -1;
    }

    printk(KERN_INFO NAME "module loaded\n");
    return 0;
}

static void __exit md_exit(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
    nf_unregister_net_hook(&init_net, &in_nfho);
    nf_unregister_net_hook(&init_net, &out_nfho);
#else
    nf_unregister_hook(&in_nfho);
    nf_unregister_hook(&out_nfho);
#endif

    firewall_free();
    printk(KERN_INFO NAME "module unloaded\n");
}

module_init(md_init);
module_exit(md_exit);
