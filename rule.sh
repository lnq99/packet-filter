#!/bin/bash

# ./rule.sh is_block type proto domain
# ./rule.sh 1 0 ICMP google.com

while IFS= read -r ip; do
    echo $1 $2 ${3:-'*'} $ip > /proc/fw
done < <(dig +short $4)
