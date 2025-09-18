#!/usr/bin/env bash
# IPMAC - Tool to change/revert MAC and IP (auto-detect gateway & auto-random IP/MAC)
# Creator: sarfraj2886
# Usage: sudo ./ipmac.sh

set -euo pipefail
IFS=$'\n\t'

TOOL_NAME="IPMAC"
CREATOR="sarfraj2886"
BACKUP_DIR="/var/tmp/ipmac_backups"

# Colors
RED="\e[31m"
GREEN="\e[32m"
YELLOW="\e[33m"
BLUE="\e[34m"
BOLD="\e[1m"
RESET="\e[0m"

mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"

ensure_root() {
  if (( EUID != 0 )); then
    echo -e "${RED}This tool must be run as root. Use sudo.${RESET}"
    exit 1
  fi
}

# Detect default gateway IP and interface (if any)
detect_gateway_and_iface() {
  # Try to find default route line
  # sample: default via 192.168.1.1 dev ens33 proto dhcp metric 100
  local gw_line
  gw_line=$(ip route 2>/dev/null | awk '/^default/ {print; exit}')
  if [[ -n "$gw_line" ]]; then
    local gw iface
    gw=$(awk '{for(i=1;i<=NF;i++) if($i=="via") print $(i+1)}' <<<"$gw_line" || true)
    iface=$(awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' <<<"$gw_line" || true)
    echo "${gw} ${iface}"
    return 0
  fi

  # fallback: pick first non-loopback UP interface, no gateway
  iface=$(ip -o link show up | awk -F': ' '{print $2}' | grep -v '^lo$' | head -n1 || true)
  if [[ -n "$iface" ]]; then
    echo " ${iface}"
    return 0
  fi

  # fallback: any non-loopback
  iface=$(ip -o link show | awk -F': ' '{print $2}' | grep -v '^lo$' | head -n1 || true)
  echo " ${iface}"
  return 0
}

# Show header
show_header() {
  clear
  echo -e "${BOLD}${BLUE}========================================${RESET}"
  echo -e "${BOLD}${GREEN}  $TOOL_NAME${RESET}    ${YELLOW}by ${CREATOR}${RESET}"
  echo -e "${BOLD}${BLUE}========================================${RESET}"
  echo
}

# Get current interface (auto-detected)
detect_interface() {
  local gw_if
  gw_if=$(detect_gateway_and_iface 2>/dev/null || true)
  # detect_gateway_and_iface returns "GATEWAY IFACE" or " IFACE" (leading space)
  local iface
  iface=$(awk '{print $2}' <<<"$gw_if" || true)
  if [[ -z "$iface" ]]; then
    # if not present as second field, maybe only one token present
    iface=$(awk '{print $1}' <<<"$gw_if" || true)
  fi
  # final fallback: use first non-loopback
  if [[ -z "$iface" ]]; then
    iface=$(ip -o link show | awk -F': ' '{print $2}' | grep -v '^lo$' | head -n1 || true)
  fi
  echo "$iface"
}

# Get gateway for detected default route (may be empty)
detect_gateway() {
  local gw_if
  gw_if=$(detect_gateway_and_iface 2>/dev/null || true)
  local gw
  gw=$(awk '{print $1}' <<<"$gw_if" || true)
  # If first field is empty or not an IP, check if it's empty
  if [[ "$gw" == "" ]]; then
    echo ""
  else
    # If original returned " IFACE" (leading space), gw will be empty; handle that
    if [[ "$gw" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
      echo "$gw"
    else
      echo ""
    fi
  fi
}

# Show current MAC
show_current_mac() {
  local iface="$1"
  ip link show dev "$iface" 2>/dev/null | awk '/link\/ether/ {print $2}' || echo "unknown"
}

# Show current IPv4 addresses (one per line)
show_current_ips() {
  local iface="$1"
  ip -o -4 addr show dev "$iface" 2>/dev/null | awk '{print $4}' || echo "none"
}

validate_mac() {
  local mac="$1"
  if [[ "$mac" =~ ^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$ ]]; then
    return 0
  fi
  return 1
}

# Generate locally administered MAC (02:xx:xx:xx:xx:xx)
random_mac() {
  printf '02:%02x:%02x:%02x:%02x:%02x\n' $((RANDOM%256)) $((RANDOM%256)) $((RANDOM%256)) $((RANDOM%256)) $((RANDOM%256)) | tr '[:upper:]' '[:lower:]'
}

# Generate a random usable IP within provided CIDR, excluding specified addresses.
# Uses python3 ipaddress module to compute usable hosts.
# Args: <cidr> "<exclude_csv>" (exclude list comma separated, entries are plain IPv4)
random_ip_in_cidr() {
  local cidr="$1"
  local exclude_csv="${2:-}"
  # Use python3, ensure available
  if ! command -v python3 >/dev/null 2>&1; then
    echo ""
    return 1
  fi

  python3 - <<PY
import ipaddress, random, os, sys
cidr = "$cidr"
exclude_csv = "$exclude_csv"
try:
    net = ipaddress.ip_network(cidr, strict=False)
except Exception as e:
    # if malformed, exit empty
    sys.exit(0)

# build list of usable hosts:
# For /31 or /32, ip_network.hosts() might be empty - still handle gracefully
hosts = [str(h) for h in net.hosts()]
excludes = set(x.strip() for x in exclude_csv.split(',') if x.strip())
candidates = [h for h in hosts if h not in excludes]
if not candidates:
    # no candidate found: attempt to pick any address in network excluding network, broadcast and excludes
    all_addrs = [str(a) for a in net]
    picks = [a for a in all_addrs if a not in excludes]
    if not picks:
        sys.exit(0)
    print(random.choice(picks))
else:
    print(random.choice(candidates))
PY
}

backup_mac() {
  local iface="$1"
  local file="$BACKUP_DIR/${iface}.mac"
  if [[ ! -f "$file" ]]; then
    show_current_mac "$iface" > "$file" 2>/dev/null || true
    chmod 600 "$file" || true
  fi
}

backup_ip() {
  local iface="$1"
  local ipfile="$BACKUP_DIR/${iface}.ip"
  local routefile="$BACKUP_DIR/${iface}.route"
  if [[ ! -f "$ipfile" ]]; then
    ip -o -4 addr show dev "$iface" | awk '{print $4}' > "$ipfile" 2>/dev/null || true
    chmod 600 "$ipfile" || true
  fi
  if [[ ! -f "$routefile" ]]; then
    ip route show default | awk -v IF="$iface" '$0 ~ IF {print}' > "$routefile" 2>/dev/null || true
    chmod 600 "$routefile" || true
  fi
}

# Apply MAC change (auto random if blank)
change_mac() {
  local iface
  iface=$(detect_interface)
  if [[ -z "$iface" ]]; then
    echo -e "${RED}No network interface detected.${RESET}"
    return 1
  fi
  local oldmac newmac current
  oldmac=$(show_current_mac "$iface")
  echo -e "${BOLD}Detected interface:${RESET} ${YELLOW}${iface}${RESET}"
  echo -e "${BOLD}Current MAC:${RESET} ${YELLOW}${oldmac}${RESET}"
  read -rp "Enter new MAC (leave empty for RANDOM auto-generate): " newmac
  if [[ -z "$newmac" ]]; then
    newmac=$(random_mac)
    echo -e "${GREEN}Generated random MAC: ${newmac}${RESET}"
  else
    if ! validate_mac "$newmac"; then
      echo -e "${RED}Invalid MAC format. Expected aa:bb:cc:dd:ee:ff${RESET}"
      return 1
    fi
  fi

  backup_mac "$iface"

  echo -e "${BLUE}Applying new MAC to ${iface}...${RESET}"
  ip link set dev "$iface" down
  ip link set dev "$iface" address "$newmac"
  ip link set dev "$iface" up
  current=$(show_current_mac "$iface")

  echo -e "${BOLD}MAC change result:${RESET}"
  echo -e "  Old: ${YELLOW}${oldmac}${RESET}"
  echo -e "  New: ${GREEN}${current}${RESET}"
}

# Apply IP change. If newip left blank, auto-generate random IP in same subnet as existing address or gateway.
change_ip() {
  local iface gw cidr current_ip chosen_ip gateway
  iface=$(detect_interface)
  if [[ -z "$iface" ]]; then
    echo -e "${RED}No network interface detected.${RESET}"
    return 1
  fi

  gw=$(detect_gateway)
  gateway="$gw" # may be empty

  echo -e "${BOLD}Detected interface:${RESET} ${YELLOW}${iface}${RESET}"
  echo -e "${BOLD}Current IPv4 addresses:${RESET}"
  current_ip=$(ip -o -4 addr show dev "$iface" | awk '{print $4}' | head -n1 || true)
  show_current_ips "$iface" || true
  if [[ -n "$gateway" ]]; then
    echo -e "${BOLD}Detected gateway:${RESET} ${YELLOW}${gateway}${RESET}"
  else
    echo -e "${YELLOW}No default gateway detected.${RESET}"
  fi

  # detect existing CIDR for iface; if none, fall back to gateway's /24 or 192.168.1.0/24
  cidr=$(ip -o -4 addr show dev "$iface" | awk '{print $4}' | head -n1 || true)
  if [[ -z "$cidr" ]]; then
    if [[ -n "$gateway" && "$gateway" =~ ^([0-9]+\.){3}[0-9]+$ ]]; then
      # derive /24 from gateway
      base=$(awk -F. '{print $1"."$2"."$3}' <<<"$gateway")
      cidr="${base}.0/24"
      echo -e "${YELLOW}No CIDR on interface; inferred CIDR ${cidr} from gateway.${RESET}"
    else
      cidr="192.168.1.0/24"
      echo -e "${YELLOW}No CIDR or gateway; defaulting to ${cidr}.${RESET}"
    fi
  fi

  read -rp "Enter new IP with CIDR (leave empty to auto-generate RANDOM in same subnet): " newip

  # If newip empty: auto-generate random IP using python helper
  if [[ -z "$newip" ]]; then
    # Build exclude list: network's gateway, current_ip (without CIDR), plus any other addresses under iface
    local exclude_list=""
    if [[ -n "$gateway" ]]; then
      exclude_list="$gateway"
    fi
    # add current ip without cidr
    if [[ -n "$current_ip" ]]; then
      exclude_list="${exclude_list},$(awk -F/ '{print $1}' <<<"$current_ip")"
    fi
    # add IPs currently in use on the host (all IPv4 on machine) - optional
    ip -o -4 addr show | awk '{print $4}' | while read -r a; do
      ip_only=$(awk -F/ '{print $1}' <<<"$a")
      if [[ -n "$ip_only" ]]; then
        if [[ -z "$exclude_list" ]]; then
          exclude_list="$ip_only"
        else
          exclude_list="${exclude_list},$ip_only"
        fi
      fi
    done

    # random_ip_in_cidr expects CIDR network (like 192.168.1.0/24) - if cidr is like 192.168.1.55/24, it's fine
    # But if we got the interface CIDR as the address/cidr (like 192.168.1.55/24), that's acceptable: ip_network will normalize.
    echo -e "${BLUE}Generating random IP in ${cidr}, excluding: ${exclude_list}${RESET}"
    chosen_ip=$(random_ip_in_cidr "$cidr" "$exclude_list" | tr -d '[:space:]' || true)
    if [[ -z "$chosen_ip" ]]; then
      echo -e "${RED}Failed to generate random IP in ${cidr}. Aborting.${RESET}"
      return 1
    fi
    # chosen_ip may be plain address (no CIDR). Append original prefix length from cidr if needed.
    if [[ "$chosen_ip" =~ / ]]; then
      newip="$chosen_ip"
    else
      # get prefix length from cidr (split on /)
      prefix=$(awk -F/ '{print $2}' <<<"$cidr" || true)
      if [[ -z "$prefix" ]]; then
        prefix="24"
      fi
      newip="${chosen_ip}/${prefix}"
    fi
    echo -e "${GREEN}Auto-selected IP: ${newip}${RESET}"
  fi

  # optional: ask gateway to use if not detected
  if [[ -z "$gateway" ]]; then
    read -rp "No gateway auto-detected. Enter gateway IP to add default route (leave empty to skip): " gw_input
    if [[ -n "$gw_input" ]]; then
      gateway="$gw_input"
    fi
  else
    # confirm we will keep detected gateway
    echo -e "${YELLOW}Using gateway: ${gateway}${RESET}"
  fi

  # Backup current ip and routes
  backup_ip "$iface"

  echo -e "${BLUE}Applying IP ${newip} to ${iface}...${RESET}"
  # Remove existing IPv4 addresses on iface
  ip -4 addr flush dev "$iface"
  # Add new ip
  ip addr add "$newip" dev "$iface"
  ip link set dev "$iface" up

  # Reset default route(s) for iface: remove any default via this iface then optionally add new gateway
  # First remove default routes using this iface
  if [[ -f "$BACKUP_DIR/${iface}.route" ]]; then
    while IFS= read -r route; do
      [[ -z "$route" ]] && continue
      gw_old=$(awk '{for(i=1;i<=NF;i++) if($i=="via") print $(i+1)}' <<<"$route" || true)
      if [[ -n "$gw_old" ]]; then
        ip route del default via "$gw_old" dev "$iface" 2>/dev/null || true
      fi
    done < "$BACKUP_DIR/${iface}.route" || true
  else
    # remove any default route that references this iface now
    ip route show default | awk -v IF="$iface" '$0 ~ IF {print}' | while IFS= read -r r; do
      gw_old=$(awk '{for(i=1;i<=NF;i++) if($i=="via") print $(i+1)}' <<<"$r" || true)
      if [[ -n "$gw_old" ]]; then
        ip route del default via "$gw_old" dev "$iface" 2>/dev/null || true
      fi
    done
  fi

  if [[ -n "$gateway" ]]; then
    ip route add default via "$gateway" dev "$iface" 2>/dev/null || true
  fi

  echo -e "${GREEN}IP applied.${RESET}"
  echo -e "${BOLD}Current IPv4 addresses for ${iface}:${RESET}"
  show_current_ips "$iface"
  if [[ -n "$gateway" ]]; then
    echo -e "${BOLD}Current default routes (for this iface):${RESET}"
    ip route show default | awk -v IF="$iface" '$0 ~ IF {print}' || true
  fi
}

revert_mac() {
  local iface
  iface=$(detect_interface)
  if [[ -z "$iface" ]]; then
    echo -e "${RED}No network interface detected.${RESET}"
    return 1
  fi
  local macfile="$BACKUP_DIR/${iface}.mac"
  if [[ ! -f "$macfile" ]]; then
    echo -e "${YELLOW}No MAC backup found for ${iface}.${RESET}"
    return 1
  fi
  local orig
  orig=$(<"$macfile")
  if [[ -z "$orig" ]]; then
    echo -e "${RED}Backup MAC is empty. Cannot revert.${RESET}"
    return 1
  fi
  echo -e "${BLUE}Reverting MAC for ${iface} -> ${orig}${RESET}"
  ip link set dev "$iface" down
  ip link set dev "$iface" address "$orig"
  ip link set dev "$iface" up
  echo -e "${GREEN}MAC reverted. Current: $(show_current_mac "$iface")${RESET}"
}

revert_ip() {
  local iface
  iface=$(detect_interface)
  if [[ -z "$iface" ]]; then
    echo -e "${RED}No network interface detected.${RESET}"
    return 1
  fi
  local ipfile="$BACKUP_DIR/${iface}.ip"
  local routefile="$BACKUP_DIR/${iface}.route"

  if [[ ! -f "$ipfile" && ! -f "$routefile" ]]; then
    echo -e "${YELLOW}No IP backup data found for ${iface}.${RESET}"
    return 1
  fi

  echo -e "${BLUE}Flushing current IPv4 addresses on ${iface}...${RESET}"
  ip -4 addr flush dev "$iface"

  if [[ -f "$ipfile" ]]; then
    while IFS= read -r addr; do
      [[ -z "$addr" ]] && continue
      echo -e "${BLUE}Restoring address ${addr}...${RESET}"
      ip addr add "$addr" dev "$iface" || true
    done < "$ipfile"
  fi

  # Delete default routes for this iface, then re-add saved defaults
  ip route show default | awk -v IF="$iface" '$0 ~ IF {print}' | while IFS= read -r r; do
    gw=$(awk '{for(i=1;i<=NF;i++) if($i=="via") print $(i+1)}' <<<"$r" || true)
    if [[ -n "$gw" ]]; then
      ip route del default via "$gw" dev "$iface" 2>/dev/null || true
    fi
  done

  if [[ -f "$routefile" ]]; then
    while IFS= read -r r; do
      [[ -z "$r" ]] && continue
      gw=$(awk '{for(i=1;i<=NF;i++) if($i=="via") print $(i+1)}' <<<"$r" || true)
      if [[ -n "$gw" ]]; then
        echo -e "${BLUE}Restoring default via ${gw} dev ${iface}${RESET}"
        ip route add default via "$gw" dev "$iface" 2>/dev/null || true
      fi
    done < "$routefile"
  fi

  ip link set dev "$iface" up
  echo -e "${GREEN}IP revert finished for ${iface}.${RESET}"
  echo -e "${BOLD}Current IPv4 addresses:${RESET}"
  show_current_ips "$iface"
  echo -e "${BOLD}Default routes for this iface:${RESET}"
  ip route show default | awk -v IF="$iface" '$0 ~ IF {print}' || true
}

revert_all() {
  local iface
  iface=$(detect_interface)
  if [[ -z "$iface" ]]; then
    echo -e "${RED}No network interface detected.${RESET}"
    return 1
  fi
  echo -e "${BLUE}Attempting full revert (MAC + IP) for ${iface}...${RESET}"
  if [[ -f "$BACKUP_DIR/${iface}.mac" ]]; then
    revert_mac || true
  else
    echo -e "${YELLOW}No MAC backup found for ${iface}.${RESET}"
  fi
  if [[ -f "$BACKUP_DIR/${iface}.ip" || -f "$BACKUP_DIR/${iface}.route" ]]; then
    revert_ip || true
  else
    echo -e "${YELLOW}No IP backup found for ${iface}.${RESET}"
  fi
  echo -e "${GREEN}Full revert attempt completed.${RESET}"
}

show_menu() {
  echo
  echo -e "${BOLD}Options:${RESET}"
  echo -e "  ${GREEN}1)${RESET} Change MAC address (auto-random if blank)"
  echo -e "  ${GREEN}2)${RESET} Change IP address (auto-random in subnet if blank)"
  echo -e "  ${GREEN}3)${RESET} Revert IP (restore backup)"
  echo -e "  ${GREEN}4)${RESET} Revert MAC (restore backup)"
  echo -e "  ${GREEN}5)${RESET} Revert ALL (MAC + IP)"
  echo -e "  ${GREEN}6)${RESET} Show detected interface, gateway & current values"
  echo -e "  ${GREEN}7)${RESET} Exit"
  echo
  read -rp "Choice [1-7]: " CHOICE
  case "$CHOICE" in
    1) change_mac ;;
    2) change_ip ;;
    3) revert_ip ;;
    4) revert_mac ;;
    5) revert_all ;;
    6)
       local iface gw
       iface=$(detect_interface)
       gw=$(detect_gateway)
       if [[ -z "$iface" ]]; then
         echo -e "${RED}No interface detected.${RESET}"
       else
         echo -e "${BOLD}Detected interface:${RESET} ${YELLOW}${iface}${RESET}"
         echo -e "${BOLD}MAC:${RESET} $(show_current_mac "$iface")"
         echo -e "${BOLD}IPv4:${RESET}"
         show_current_ips "$iface"
         if [[ -n "$gw" ]]; then
           echo -e "${BOLD}Default gateway:${RESET} ${YELLOW}${gw}${RESET}"
         else
           echo -e "${YELLOW}No default gateway detected.${RESET}"
         fi
         echo -e "${BOLD}Default routes for this iface:${RESET}"
         ip route show default | awk -v IF="$iface" '$0 ~ IF {print}' || true
       fi
       ;;
    7) echo -e "${BLUE}Goodbye.${RESET}"; exit 0 ;;
    *) echo -e "${RED}Invalid choice.${RESET}" ;;
  esac
}

main() {
  ensure_root
  while true; do
    show_header
    local iface gw
    iface=$(detect_interface || true)
    gw=$(detect_gateway || true)
    if [[ -n "$iface" ]]; then
      echo -e "${BOLD}Auto-detected interface:${RESET} ${YELLOW}${iface}${RESET}"
    else
      echo -e "${YELLOW}Warning: no network interface auto-detected.${RESET}"
      echo -e "${BOLD}Available interfaces:${RESET}"
      ip -o link show | awk -F': ' '{print $2}' | grep -v '^lo$' || true
    fi
    if [[ -n "$gw" ]]; then
      echo -e "${BOLD}Auto-detected gateway:${RESET} ${YELLOW}${gw}${RESET}"
    fi

    show_menu
    echo
    read -rp "Press Enter to continue..." _ || true
  done
}

main
