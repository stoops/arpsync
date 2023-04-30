# arpsync

Pseudo-Bridging Layer-2 ARP-Sync

# LAN-to-WAN

SYS=nix EXC='(192.168.1.1 |192.168.1.2 )' python3 arpsync.py 192.168.1.1 br-lan 192.168.1.2 >/dev/null 2>&1 &

SYS=nix EXC='(192.168.1.1 |192.168.1.2 )' python3 arpsync.py 192.168.1.2 br-lan 192.168.1.1 >/dev/null 2>&1 &

# LAN-to-LAN

echo 1 > /proc/sys/net/ipv4/conf/br-lan/proxy_arp

echo 1 > /proc/sys/net/ipv4/conf/br-lan/proxy_arp_pvlan

