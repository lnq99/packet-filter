#include "nf_hook.h"
#include <linux/list.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <net/icmp.h>
#include <net/protocol.h>
#include "firewall.h"

char buff[128];
void printk_packet(const struct packet *p);
void parse_packet_data(struct packet *pkt, struct sk_buff *skb, int is_incoming);

unsigned int nf_hook_in(void *priv,
                        struct sk_buff *skb,
                        const struct nf_hook_state *state)
{
    struct packet pkt = {.proto = "*", .type = 0};

    parse_packet_data(&pkt, skb, 1);

    printk_packet(&pkt);

    if (!accept_packet(&pkt))
    {
        pr_info(NAME "===DROP===\n");
        return NF_DROP;
    }

    return NF_ACCEPT;
}

unsigned int nf_hook_out(void *priv,
                         struct sk_buff *skb,
                         const struct nf_hook_state *state)
{
    struct packet pkt = {.proto = "*", .type = 1};

    parse_packet_data(&pkt, skb, 0);

    printk_packet(&pkt);

    if (!accept_packet(&pkt))
    {
        pr_info(NAME "===DROP===\n");
        return NF_DROP;
    }

    return NF_ACCEPT;
}

void parse_packet_data(struct packet *pkt, struct sk_buff *skb, int is_incoming)
{
    struct iphdr *iph = ip_hdr(skb);
    pkt->saddr = iph->saddr;
    pkt->daddr = iph->daddr;
    pkt->size = ntohs(iph->tot_len);

    switch (iph->protocol)
    {
    case IPPROTO_ICMP:
        sprintf(pkt->proto, "ICMP");
        struct icmphdr *icmph = icmp_hdr(skb);

        sprintf(pkt->info, "code=%d, sum=%-5d, id=%d, seq=%d, ",
                icmph->code, icmph->checksum,
                icmph->un.echo.id, icmph->un.echo.sequence);

        char *pos = pkt->info + strlen(pkt->info);

        switch (icmph->type)
        {
        case ICMP_ECHOREPLY:
            sprintf(pos, "Echo reply");
            break;
        case ICMP_ECHO:
            sprintf(pos, "Echo request");
            break;
        case ICMP_TIME_EXCEEDED:
            sprintf(pos, "Time exceeded");
            break;
        }
        break;

    case IPPROTO_TCP:
        sprintf(pkt->proto, "TCP");
        struct tcphdr *tcph;

        if (is_incoming)
            tcph = (struct tcphdr *)((u32 *)iph + iph->ihl);
        else
            tcph = tcp_hdr(skb);

        // only handle flag FIN, SYN, ACK
        char flag_str[12] = "";
        if (tcph->fin)
            strcat(flag_str, "FIN,");
        if (tcph->syn)
            strcat(flag_str, "SYN,");
        if (tcph->ack)
            strcat(flag_str, "ACK");
        int l = strlen(flag_str);
        if (flag_str[l - 1] == ',')
            flag_str[l - 1] = '\0';

        sprintf(pkt->info, "%d -> %d, seq=%-10u, ack=%-10u, sum=%-5d, [%s]",
                ntohs(tcph->source), ntohs(tcph->dest),
                ntohl(tcph->seq), ntohl(tcph->ack_seq), ntohs(tcph->check), flag_str);
        break;

    case IPPROTO_UDP:
        sprintf(pkt->proto, "UDP");
        struct udphdr *udph;

        if (is_incoming)
            udph = (struct udphdr *)((u32 *)iph + iph->ihl);
        else
            udph = udp_hdr(skb);

        sprintf(pkt->info, "%d -> %d, sum=%-5d, len=%-4d",
                ntohs(udph->source), ntohs(udph->dest),
                ntohs(udph->check), ntohs(udph->len));
        break;
    }
}

void printk_packet(const struct packet *p)
{
    sprintf(buff, "[%4s]  " IP_FMT " -> " IP_FMT "  len %d\t%s\n",
            p->proto, &p->saddr, &p->daddr, p->size, p->info);
    pr_info(NAME "%s", buff);
}