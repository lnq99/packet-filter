ifneq ($(KERNELRELEASE),)
	obj-m := net_monitor.o
	net_monitor-objs := net_monitor_md.o nf_hook.o firewall.o
else
	CURRENT = $(shell uname -r)
	KDIR = /lib/modules/$(CURRENT)/build
	PWD = $(shell pwd)
default:
	$(MAKE) -C $(KDIR) M=$(PWD) modules
clean:
	@rm -f *.o .*.cmd .*.flags *.mod *.mod.c *.order
	@rm -f .*.*.cmd *~ *.*~ TODO.*
	@rm -fR .tmp*
	@rm -rf .tmp_versions
	@rm -f *.symvers
disclean: clean
	@rm *.ko
endif

# Useful commands:

# insmod net_monitor.ko
# rmmod net_monitor

# sudo dmesg -WH
# dmesg | tail -100 | grep "+ "

# ping google.com
# curl google.com

# ./rule.sh 1 0 ICMP google.com
# cat /proc/fw
# echo "1 0 TCP 173.194.73.138" > /proc/fw