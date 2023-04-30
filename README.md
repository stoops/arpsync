# arpsync

Pseudo-Bridging Layer-2 ARP-Sync

# LAN-to-WAN

TAB=main EXC='(192.168.1.1 |192.168.1.2 )' python3 /root/arpsync.py br-lan,192.168.1.1 br-lan,192.168.9.1 /root/*.leases,/tmp/*.leases
TAB=main EXC='(192.168.1.1 |192.168.1.2 )' python3 /root/arpsync.py br-lan,192.168.1.1 br-wan,192.168.9.3 /root/*.leases,/tmp/*.leases

# LAN-to-LAN

echo 1 > /proc/sys/net/ipv4/conf/br-lan/proxy_arp
echo 1 > /proc/sys/net/ipv4/conf/br-lan/proxy_arp_pvlan

# CONFIGS

echo 2000 > /proc/sys/net/ipv4/neigh/default/gc_thresh3
echo 2000 > /proc/sys/net/ipv4/neigh/default/gc_thresh2
echo 5 > /proc/sys/net/ipv4/neigh/default/gc_thresh1
echo 5 > /proc/sys/net/ipv4/neigh/default/gc_interval
for f in /proc/sys/net/ipv4/neigh/*/locktime ; do echo 1 > "$f" ; done
for f in /proc/sys/net/ipv4/neigh/*/retrans_time ; do echo 1 > "$f" ; done
for f in /proc/sys/net/ipv4/neigh/*/delay_first_probe_time ; do echo 1 > "$f" ; done
for f in /proc/sys/net/ipv4/neigh/*/base_reachable_time ; do echo 19 > "$f" ; done
for f in /proc/sys/net/ipv4/neigh/*/gc_stale_time ; do echo 24 > "$f" ; done

