#!/bin/sh
# Copyright Zhuofei Wang <semigodking@gmail.com>
#
INPUT_IFACE=eth0

SCRIPT_PATH=$(dirname "$0")
SCRIPT_PATH=$(cd $SCRIPT_PATH && pwd)

RESOLVEIP_BIN=/usr/bin/resolveip
#
# transparent UDP proxy with TPROXY
#
#[ -z "$(ip route list table 100)" ] && {
#    ip rule add fwmark 0x01/0x01 table 100
#    ip route add local 0.0.0.0/0 dev lo table 100
#    }
#[ -z "$(iptables -t mangle -nL PREROUTING |grep REDSOCKS)" ] && { 
#    iptables -t mangle -N REDSOCKS
#    iptables -t mangle -I PREROUTING -j REDSOCKS
#    }
#iptables -t mangle -F REDSOCKS
#
#iptables -t mangle -A REDSOCKS -p udp -d 127.0.0.1 --dport 1054 -j TPROXY --on-port 10000 --tproxy-mark 0x01/0x01
#iptables -t mangle -A REDSOCKS -p udp --dport 6969 -j TPROXY --on-port 10000 --tproxy-mark 0x01/0x01

# Prepare ipsets
set_names=$(ipset list -n)
[ -z "$(echo $set_names | grep redsocks_blacklist)" ] && {
    ipset create redsocks_blacklist list:set
}
[ -z "$(echo $set_names | grep redsocks_blacklist_net)" ] && {
    # Limit hash size of your device has limitation.
    # ipset create redsocks_blacklist_net hash:net maxelem 16384 hashsize 8192
    ipset create redsocks_blacklist_net hash:net
}
[ -z "$(echo $set_names | grep redsocks_whitelist)" ] && {
    ipset create redsocks_whitelist list:set
}
[ -z "$(echo $set_names | grep redsocks_whitelist_net)" ] && {
    # Limit hash size of your device has limitation.
    #ipset create redsocks_whitelist_net hash:net maxelem 16384 hashsize 8192
    ipset create redsocks_whitelist_net hash:net
}
ipset -F redsocks_blacklist_net
ipset -F redsocks_blacklist
ipset add redsocks_blacklist redsocks_blacklist_net

ipset -F redsocks_whitelist_net
ipset -F redsocks_whitelist
ipset add redsocks_whitelist redsocks_whitelist_net

# Anti-GFW
[ -z "$(iptables -t nat -nL PREROUTING |grep GFW)" ] && { 
               iptables -t nat -N GFW 
               iptables -t nat -I PREROUTING -i $INPUT_IFACE -p tcp -j GFW
               }
iptables -t nat -F GFW 
iptables -t nat -A GFW -p tcp -m set --match-set redsocks_blacklist dst -j REDIRECT --to-ports 1082

# Transparent Proxy
[ -z "$(iptables -t nat -nL PREROUTING |grep REDSOCKS)" ] && {
               iptables -t nat -N REDSOCKS
               iptables -t nat -A PREROUTING -i $INPUT_IFACE -p tcp -j REDSOCKS
	       }
iptables -t nat -F REDSOCKS

# Do not redirect traffic to the followign address ranges
# IP range for Ad filter.
iptables -t nat -A REDSOCKS -p tcp --dport 80 -m iprange --src-range 192.168.1.201-192.168.1.210 -j REDIRECT --to-ports 8118
# No transparent proxy range: 192.168.1.201--192.168.1.220
iptables -t nat -A REDSOCKS -p tcp -m iprange --src-range 192.168.1.201-192.168.1.220 -j RETURN
iptables -t nat -A REDSOCKS -p tcp -m set --match-set redsocks_whitelist dst -j RETURN
iptables -t nat -A REDSOCKS -p tcp --sport 51413 -j RETURN
# Redirect normal HTTP and HTTPS traffic
iptables -t nat -A REDSOCKS -p tcp -m multiport --dports 21:1024,8080 -j REDIRECT --to-ports 1082
#iptables -t nat -A REDSOCKS -p tcp --dport 80 -j REDIRECT --to-ports 1082
#iptables -t nat -A REDSOCKS -p tcp --dport 443 -j REDIRECT --to-ports 1082
#iptables -t nat -A REDSOCKS -p tcp --dport 8080 -j REDIRECT --to-ports 1082
#iptables -t nat -A REDSOCKS -p tcp --dport 25 -j REDIRECT --to-ports 1082
#iptables -t nat -A REDSOCKS -p tcp --dport 110 -j REDIRECT --to-ports 1082
#iptables -t nat -A REDSOCKS -p tcp --dport 465 -j REDIRECT --to-ports 1082
#iptables -t nat -A REDSOCKS -p tcp --dport 143 -j REDIRECT --to-ports 1082
#iptables -t nat -A REDSOCKS -p tcp --dport 993 -j REDIRECT --to-ports 1082
#iptables -t nat -A REDSOCKS -p tcp --dport 995 -j REDIRECT --to-ports 1082
#iptables -t nat -A REDSOCKS -p tcp --dport 587 -j REDIRECT --to-ports 1082
##iptables -t nat -A REDSOCKS -p tcp --dport 24129 -j REDIRECT --to-ports 1082

##############################################################################
# Prepare blacklist and whitelist
ipset restore -! << EOF
add redsocks_whitelist_net 192.168.0.0/16
add redsocks_whitelist_net 10.0.0.0/8 
add redsocks_whitelist_net 172.16.0.0/12
add redsocks_whitelist_net 224.0.0.0/4
add redsocks_whitelist_net 240.0.0.0/4
add redsocks_whitelist_net 127.0.0.0/8
EOF

awk '{print "add redsocks_blacklist_net " $0}' $SCRIPT_PATH/blacklist_net.txt | ipset restore -!
awk '{print "add redsocks_whitelist_net " $0}' $SCRIPT_PATH/china_ip_list.txt | ipset restore -!
# Use loop below instead in some routers.
# for ip in $(head -n 8000 $SCRIPT_PATH/china_ip_list.txt) ; do ipset add redsocks_whitelist_net $ip ; done

nslist=$(sed -e 's/#.*$//' -e '/^$/d' $SCRIPT_PATH/nslist)
for domain in $nslist ;
do
    case $domain in
    -*/[0-9]*)
       domain=$(echo $domain | cut -d - -f 2)
       ipset add redsocks_whitelist_net $domain
       ;;
    -*)
       domain=$(echo $domain | cut -d - -f 2)
       #echo $domain
       for ip in $($RESOLVEIP_BIN -4 $domain) ;
       do
           ipset add redsocks_whitelist_net $ip
       done
       ;;
     */[0-9]*)
       ipset add redsocks_blacklist_net $domain
       ;;
     *)
       #echo $domain
       for ip in $($RESOLVEIP_BIN -4 $domain) ;
       do
           ipset add redsocks_blacklist_net $ip
       done
     ;;
    esac
done

# UDP TPROXY
iptables -t mangle -A REDSOCKS -p udp -m set --match-set redsocks_whitelist dst -j RETURN
iptables -t mangle -A REDSOCKS -p udp --sport 51413 -j RETURN
iptables -t mangle -A REDSOCKS -p udp --dport 80 -j TPROXY --on-port 1082 --tproxy-mark 0x01/0x01
iptables -t mangle -A REDSOCKS -p udp --dport 443 -j TPROXY --on-port 1082 --tproxy-mark 0x01/0x01

# TODO: Lines below are used by OpenWRT based bypass gateway.
# MSS fix
# iptables -t nat -I postrouting_lan_rule -o eth0 -j MASQUERADE
# iptables -t mangle -F FORWARD
# iptables -t mangle -A FORWARD -p tcp -o eth0 -m tcp --tcp-flags SYN,RST SYN -m comment --comment "MTU fixing" -j TCPMSS --clamp-mss-to-pmtu
