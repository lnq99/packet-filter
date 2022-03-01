#include "firewall.h"
#include <linux/proc_fs.h>
#include <linux/slab.h>

static struct proc_dir_entry *fw_proc;
static LIST_HEAD(rules);

static char buff[1024];

ssize_t fw_write(struct file *file, const char __user *buf,
                 size_t len, loff_t *ppos)
{
    if (copy_from_user(buff, buf, len))
        return -EFAULT;

    struct firewall_rule *r;
    r = kmalloc(sizeof(*r), GFP_KERNEL);

    // is_block type proto addr
    // 1 0 TCP 64.233.164.113
    int ip[4];
    sscanf(buff, "%hu %hu %s %d.%d.%d.%d",
           &r->is_block, &r->type, r->proto,
           &ip[0], &ip[1], &ip[2], &ip[3]);

    if (!strcmp(r->proto, "*"))
        r->proto[0] = '\0';

    r->addr = (ip[3] << 24) + (ip[2] << 16) + (ip[1] << 8) + ip[0];

    add_rule(r);
    return len;
}

ssize_t fw_read(struct file *file, char __user *buf,
                size_t len, loff_t *ppos)
{
    if (*ppos > 0)
        return 0;

    struct list_head *pos;
    struct firewall_rule *r;
    char *tmp = buff;

    if (list_empty(&rules))
    {
        sprintf(buff, "(empty)\n");
    }
    else
    {
        list_for_each(pos, &rules)
        {
            r = list_entry(pos, struct firewall_rule, list);
            if (r->is_block)
                sprintf(tmp, "%s [%4s] " IP_FMT "\n",
                        r->type ? "OUT" : "IN ", r->proto, &r->addr);
            tmp += strlen(tmp);
        }
        tmp[0] = '\0';
    }

    int l = strlen(buff);
    if (copy_to_user(buf, buff, l + 1))
        return -EFAULT;

    *ppos = 1;
    return l;
}

struct proc_ops fw_fops = {
    .proc_read = fw_read,
    .proc_write = fw_write,
};

void firewall_init(void)
{
    fw_proc = proc_create("fw", 0666, NULL, &fw_fops);
    if (fw_proc == NULL)
    {
        printk(KERN_INFO NAME "Couldn't create proc entry\n");
        return;
    }
}

void firewall_free(void)
{
    proc_remove(fw_proc);
    struct firewall_rule *ptr;
    struct firewall_rule *next;
    list_for_each_entry_safe(ptr, next, &rules, list)
    {
        kfree(ptr);
    }
}

int accept_packet(struct packet *p)
{
    struct list_head *pos;
    struct firewall_rule *r;
    list_for_each(pos, &rules)
    {
        r = list_entry(pos, struct firewall_rule, list);
        if (r->is_block && r->type == p->type &&
            (!strcmp(r->proto, "") || !strcmp(r->proto, p->proto)))
        {
            if ((!r->type && r->addr == p->saddr) ||
                (r->type && r->addr == p->daddr))
            {
                return 0; // drop packet
            }
        }
    }
    return 1; // accept packet
}

void add_rule(struct firewall_rule *rule)
{
    struct firewall_rule *ptr;
    struct firewall_rule *next;
    list_for_each_entry_safe(ptr, next, &rules, list)
    {
        if (compare_rule(ptr, rule) == 0)
        {
            ptr->is_block = rule->is_block;
            return;
        }
    }

    INIT_LIST_HEAD(&rule->list);
    list_add_tail(&rule->list, &rules);
}

int compare_rule(struct firewall_rule *r1, struct firewall_rule *r2)
{
    int r;
    if ((r = strcmp(r1->proto, r2->proto)))
        return r;
    if ((r = r1->addr - r2->addr))
        return r;
    if (r1->type != r2->type)
        return 1;
    return 0;
}
