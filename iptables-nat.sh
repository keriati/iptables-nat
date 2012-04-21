#!/bin/bash
##
# Iptables firewall script for *nix systems with nat and portforward
# author: Attila Kerekes (@keriati)

##
# Configuration
#

# iptables command
IPTABLES="iptables"

# External interface and ip
INET_IFACE="eth1"
INET_IP="213.222.161.156"

# internal interface and ip
LAN_IFACE="eth0"
LAN_IP="10.0.0.1"

# localhost
LO_IFACE="lo"
LO_IP="127.0.0.1"

# Secure interfaces (for ACCEPT policy)
SECURE_IFACE="$LAN_IFACE $LO_IFACE"

# List of external open ports (syntax:  <port>:<type>)
# Examples:
#   elit: 31337:tcp
#   http: 80:tcp
#   https: 443:tcp
#   imap: 143:tcp
#   smtpd: 25:tcp
INET_OPEN_PORTS="80:tcp 443:tcp 31337:tcp"

# List of portforwards to internal address (syntax: <ip>:<port>:<type>)
# Examples:
#   rdesktop: 10.0.0.3:3389:tcp
#   www: 10.0.03:80:tcp
PORTFW="10.0.0.3:3389:tcp"

##
# Functions from here
#

# Reset the default policies, flush all, erase all
IPT_CLEAR(){
    $IPTABLES -F
    $IPTABLES -X
    $IPTABLES -Z
    $IPTABLES -t nat -F
    $IPTABLES -t nat -X
    $IPTABLES -t nat -Z
    $IPTABLES -t mangle -F
    $IPTABLES -t mangle -X
    $IPTABLES -t mangle -Z

    $IPTABLES -P INPUT ACCEPT
    $IPTABLES -P FORWARD ACCEPT
    $IPTABLES -P OUTPUT ACCEPT

    $IPTABLES -t nat -P PREROUTING ACCEPT
    $IPTABLES -t nat -P POSTROUTING ACCEPT
    $IPTABLES -t nat -P OUTPUT ACCEPT

    $IPTABLES -t mangle -P INPUT ACCEPT
    $IPTABLES -t mangle -P FORWARD ACCEPT
    $IPTABLES -t mangle -P OUTPUT ACCEPT
    $IPTABLES -t mangle -P PREROUTING ACCEPT
    $IPTABLES -t mangle -P POSTROUTING ACCEPT
}

# Set policies
IPT_DROP_POL(){
    $IPTABLES -P INPUT DROP
    $IPTABLES -P FORWARD DROP
    #$IPTABLES -P OUTPUT DROP
    $IPTABLES -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
    $IPTABLES -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
    #$IPTABLES -A OUTPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
}

# Set policies for secure interfaces.
IPT_ALLOW_SEC(){
    for i in $SECURE_IFACE
    do
        $IPTABLES -A INPUT -i $i -m state --state NEW -j ACCEPT
    done
}

# Basic nat
IPT_NAT(){
    $IPTABLES -t nat -A POSTROUTING -o $INET_IFACE -j SNAT --to-source $INET_IP
    $IPTABLES -A FORWARD -i $LAN_IFACE -m state --state NEW -j ACCEPT
}

# INPUT rules.
IPT_INPUT(){
    for i in $INET_OPEN_PORTS
    do
        PORT=`echo $i | cut -d: -f1`
        PROT=`echo $i | cut -d: -f2`
        $IPTABLES -A INPUT -p $PROT -m $PROT --dport $PORT -m state --state NEW -j ACCEPT
    done

    # Costum rules
    #$IPTABLES -A INPUT -p tcp -m tcp --dport 31022 -m limit --limit 6/minute -m state --state NEW -j ACCEPT
    #$IPTABLES -A INPUT -p icmp -m icmp --icmp-type 8 -m state --state NEW -m limit --limit 1/second -j ACCEPT
}

# FORWARD rules.
IPT_PORTFW(){
    for i in $PORTFW
    do
        IP=`echo $i | cut -d: -f1`
        PORT=`echo $i | cut -d: -f2`
        PROT=`echo $i | cut -d: -f3`
        $IPTABLES -t nat -A PREROUTING -d $INET_IP -p $PROT -m $PROT --dport $PORT -j DNAT --to-destination $IP:$PORT
        $IPTABLES -A FORWARD -d $IP -p $PROT -m $PROT --dport $PORT -m state --state NEW -j ACCEPT
    done
}

case $1 in
    start|restart)
        IPT_CLEAR
        IPT_DROP_POL
        IPT_ALLOW_SEC
        IPT_NAT
        IPT_INPUT
        IPT_PORTFW
    ;;
    stop)
        IPT_CLEAR
    ;;
    nopf)
        IPT_CLEAR
        IPT_DROP_POL
        IPT_ALLOW_SEC
        IPT_NAT
        IPT_INPUT
    ;;
    natonly)
        IPT_CLEAR
        IPT_NAT
    ;;
    *)
        FN=`echo $0 | cut -d/ -f2`
        echo "Usage: $FN [start|restart|stop|nopf|natonly]"
    ;;
esac
