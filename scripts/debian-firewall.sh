#!/bin/bash
# Debian host firewall setup for Threat2Signal
# Run on the Debian host (192.168.231.1) with sudo
# Usage: sudo bash debian-firewall.sh

set -euo pipefail

PUBLIC_IP="62.210.212.87"
VM_IP="192.168.231.175"
PORT="8001"
BRIDGE="virbr0"
BACKUP_DIR="/home/user/firewall-backup"

# Backup current rules
mkdir -p "$BACKUP_DIR"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
iptables-save > "$BACKUP_DIR/iptables-backup-$TIMESTAMP.rules"
nft list ruleset > "$BACKUP_DIR/nft-backup-$TIMESTAMP.rules" 2>/dev/null || true
echo "Backed up firewall rules to $BACKUP_DIR/*-$TIMESTAMP.rules"

# DNAT: forward public:8001 to VM
iptables -t nat -C PREROUTING -d "$PUBLIC_IP/32" -p tcp --dport "$PORT" \
  -m comment --comment "DNAT Threat2Signal $PUBLIC_IP:$PORT to VM $VM_IP:$PORT" \
  -j DNAT --to-destination "$VM_IP:$PORT" 2>/dev/null \
  && echo "DNAT rule already exists, skipping" \
  || { iptables -t nat -A PREROUTING -d "$PUBLIC_IP/32" -p tcp --dport "$PORT" \
         -m comment --comment "DNAT Threat2Signal $PUBLIC_IP:$PORT to VM $VM_IP:$PORT" \
         -j DNAT --to-destination "$VM_IP:$PORT"
       echo "Added DNAT rule: $PUBLIC_IP:$PORT -> $VM_IP:$PORT"; }

# FORWARD: allow forwarded traffic into virbr0
iptables -C LIBVIRT_FWI -d "$VM_IP/32" -o "$BRIDGE" -p tcp --dport "$PORT" \
  -m conntrack --ctstate NEW,RELATED,ESTABLISHED \
  -m comment --comment "Allow forwarded Threat2Signal to VM $VM_IP" \
  -j ACCEPT 2>/dev/null \
  && echo "FORWARD rule already exists, skipping" \
  || { iptables -I LIBVIRT_FWI 1 -d "$VM_IP/32" -o "$BRIDGE" -p tcp --dport "$PORT" \
         -m conntrack --ctstate NEW,RELATED,ESTABLISHED \
         -m comment --comment "Allow forwarded Threat2Signal to VM $VM_IP" \
         -j ACCEPT
       echo "Added FORWARD rule: allow TCP $PORT to $VM_IP via $BRIDGE"; }

echo ""
echo "Threat2Signal reachable at http://$PUBLIC_IP:$PORT"
echo ""
echo "To make rules persistent across reboot:"
echo "  apt install iptables-persistent"
echo "  iptables-save > /etc/iptables/rules.v4"
