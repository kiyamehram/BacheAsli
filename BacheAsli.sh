#!/bin/bash
# Advanced Automated Penetration Testing Tool
# Author: Enhanced by Grok
# Version: 2.2


CONFIG_FILE="$HOME/.pentest_tool.conf"
VERSION="2.2"

DEFAULT_WORDLIST="/usr/share/wordlists/rockyou.txt"
DEFAULT_INTERFACE="eth0"
OUTPUT_DIR="pentest_results_$(date +%Y%m%d_%H%M%S)"
LOG_FILE="$OUTPUT_DIR/scan.log"
REPORT_FILE="$OUTPUT_DIR/comprehensive_report.html"
CONFIG_BACKUP="$OUTPUT_DIR/config_backup.conf"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' 

mkdir -p "$OUTPUT_DIR"

log_message() {
    local severity=$1
    local message=$2
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    case $severity in
        INFO) color="$GREEN" ;;
        WARN) color="$YELLOW" ;;
        ERROR) color="$RED" ;;
        *) color="$NC" ;;
    esac
    echo -e "[$timestamp] [$severity] ${color}${message}${NC}" | tee -a "$LOG_FILE"
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_message ERROR "This script requires root privileges. Please run with sudo."
        exit 1
    fi
}

check_dependencies() {
    local tools=("nmap" "masscan" "netdiscover" "arp-scan" "enum4linux" "onesixtyone" "snmp-check" "nikto" "dirb" "gobuster" "whatweb" "wpscan" "sqlmap" "xsstrike" "airmon-ng" "airodump-ng" "wash" "reaver" "aircrack-ng" "smbclient" "rpcclient" "showmount" "ldapsearch" "hydra" "metasploit-framework" "testssl.sh")
    local missing_tools=()

    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing_tools+=("$tool")
        fi
    done

    if [ ${#missing_tools[@]} -ne 0 ]; then
        log_message ERROR "Missing dependencies: ${missing_tools[*]}."
        log_message INFO "Suggested installation command for Debian/Ubuntu: sudo apt-get install ${missing_tools[*]}"
        log_message INFO "Suggested installation command for RedHat/CentOS: sudo yum install ${missing_tools[*]}"
        exit 1
    fi
}

load_config() {
    if [ -f "$CONFIG_FILE" ]; then
        cp "$CONFIG_FILE" "$CONFIG_BACKUP"
        source "$CONFIG_FILE"
        log_message INFO "Loaded configuration from $CONFIG_FILE (backup saved to $CONFIG_BACKUP)"
    else
        log_message WARN "No config file found. Using defaults."
        DEFAULT_WORDLIST=${DEFAULT_WORDLIST:-"/usr/share/wordlists/rockyou.txt"}
        DEFAULT_INTERFACE=${DEFAULT_INTERFACE:-"eth0"}
        THREAD_COUNT=4
        SCAN_TIMEOUT=3600
    fi
}

save_config() {
    {
        echo "DEFAULT_WORDLIST=\"$WORDLIST\""
        echo "DEFAULT_INTERFACE=\"$interface\""
        echo "THREAD_COUNT=$THREAD_COUNT"
        echo "SCAN_TIMEOUT=$SCAN_TIMEOUT"
    } > "$CONFIG_FILE"
    log_message INFO "Configuration saved to $CONFIG_FILE"
}

prompt_wordlist() {
    read -p "Use default wordlist ($DEFAULT_WORDLIST)? [y/n]: " use_default
    if [[ "$use_default" =~ ^[Yy]$ ]]; then
        WORDLIST="$DEFAULT_WORDLIST"
    else
        read -p "Enter path to custom wordlist: " custom_wordlist
        if [ -f "$custom_wordlist" ]; then
            WORDLIST="$custom_wordlist"
            log_message INFO "Using custom wordlist: $WORDLIST"
            save_config
        else
            log_message ERROR "Invalid wordlist file: $custom_wordlist. Falling back to default: $DEFAULT_WORDLIST"
            WORDLIST="$DEFAULT_WORDLIST"
        fi
    fi
}

validate_ip() {
    local ip=$1
    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(/[0-9]{1,2})?$ ]]; then
        return 0
    else
        log_message ERROR "Invalid IP or CIDR format: $ip"
        return 1
    fi
}

validate_url() {
    local url=$1
    if [[ $url =~ ^https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(/.*)?$ ]]; then
        return 0
    else
        log_message ERROR "Invalid URL format: $url"
        return 1
    fi
}

find_ip() {
    log_message INFO "Available network interfaces:"
    ip addr show | grep "state UP" | awk -F': ' '{print $2}' | awk '{print $1}' | tee -a "$LOG_FILE"
    
    read -p "Enter interface name (default: $DEFAULT_INTERFACE): " interface
    interface=${interface:-$DEFAULT_INTERFACE}
    
    if ! ip addr show "$interface" > /dev/null 2>&1; then
        log_message ERROR "Invalid interface: $interface. Exiting."
        exit 1
    fi
    
    IP=$(ip addr show "$interface" | grep "inet " | awk '{print $2}' | cut -d/ -f1)
    if [ -z "$IP" ]; then
        log_message ERROR "No IP found for interface $interface. Exiting."
        exit 1
    fi
    log_message INFO "Selected IP: $IP"
    SUBNET="$IP/24"
    save_config
}

prompt_target() {
    read -p "Enter target IP, range, or URL (e.g., 192.168.1.1, 192.168.1.0/24, http://example.com): " TARGET
    if [ -z "$TARGET" ]; then
        log_message WARN "No target provided. Using default subnet $SUBNET."
        TARGET="$SUBNET"
    elif [[ "$TARGET" =~ ^https?:// ]]; then
        validate_url "$TARGET" || exit 1
    else
        validate_ip "$TARGET" || exit 1
    fi
}

generate_summary() {
    log_message INFO "Generating comprehensive HTML report..."
    {
        echo "<!DOCTYPE html><html><head><title>Penetration Testing Report</title>"
        echo "<style>body{font-family:Arial,sans-serif;background:#f4f4f4;color:#333;padding:20px;}"
        echo "h1,h2{color:#2c3e50;}table{border-collapse:collapse;width:100%;margin:10px 0;}"
        echo "th,td{border:1px solid #ddd;padding:8px;text-align:left;}th{background:#2c3e50;color:#fff;}"
        echo "tr:nth-child(even){background:#f2f2f2;}</style></head><body>"
        echo "<h1>Penetration Testing Report</h1>"
        echo "<p><b>Date:</b> $(date)</p>"
        echo "<p><b>Target:</b> $TARGET</p>"
        echo "<p><b>Interface:</b> $interface</p>"
        echo "<p><b>IP:</b> $IP</p>"
        echo "<p><b>Wordlist:</b> $WORDLIST</p>"
        echo "<h2>Key Findings</h2>"
        
        for file in "$OUTPUT_DIR"/*.txt; do
            if [ -f "$file" ]; then
                echo "<h3>Results from $(basename "$file")</h3>"
                echo "<table><tr><th>Output</th></tr>"
                while IFS= read -r line; do
                    echo "<tr><td>$line</td></tr>"
                done < "$file"
                echo "</table>"
            fi
        done
        echo "</body></html>"
    } > "$REPORT_FILE"
    log_message INFO "Comprehensive HTML report generated: $REPORT_FILE"
}

show_menu() {
    echo -e "\n${BLUE}=== Advanced Automated Penetration Testing Menu (v$VERSION) ===${NC}"
    echo "1) Network Discovery and Basic Scans"
    echo "2) Comprehensive Network Reconnaissance"
    echo "3) Vulnerability Scanning"
    echo "4) Web Application Scanning"
    echo "5) Wireless Network Scanning (requires wireless interface)"
    echo "6) Enumeration and Service Probing"
    echo "7) Custom Command Sequence"
    echo "8) Exploit Scanning with Metasploit"
    echo "9) SSL/TLS Vulnerability Scanning"
    echo "10) Generate Comprehensive Report"
    echo "11) Exit"
    echo ""
}

run_network_discovery() {
    find_ip
    prompt_target
    log_message INFO "Running network discovery and basic scans on $TARGET..."
    
    nmap -sn "$TARGET" -oN "$OUTPUT_DIR/ping_sweep.txt" &
    nmap -sS -O --top-ports 1000 "$TARGET" -oN "$OUTPUT_DIR/basic_syn_os.txt" &
    netdiscover -i "$interface" -r "$TARGET" -P > "$OUTPUT_DIR/netdiscover_results.txt" &
    arp-scan --localnet --interface="$interface" > "$OUTPUT_DIR/arp_scan.txt" &
    wait
    log_message INFO "Basic scans completed. Results saved in $OUTPUT_DIR."
}

run_comprehensive_recon() {
    find_ip
    prompt_target
    log_message INFO "Running comprehensive network reconnaissance on $TARGET..."
    
    nmap -A -T4 -p- "$TARGET" -oA "$OUTPUT_DIR/comprehensive_scan" &
    masscan -p1-65535 --rate=1000 "$TARGET" > "$OUTPUT_DIR/masscan_results.txt" &
    enum4linux -a "$IP" | tee "$OUTPUT_DIR/enum4linux_results.txt" &
    onesixtyone -c /usr/share/doc/onesixtyone/dict.txt "$TARGET" > "$OUTPUT_DIR/snmp_enum.txt" &
    snmp-check "$IP" > "$OUTPUT_DIR/snmp_check.txt" &
    wait
    log_message INFO "Comprehensive recon completed. Results saved in $OUTPUT_DIR."
}

run_vuln_scan() {
    find_ip
    prompt_target
    log_message INFO "Running specific vulnerability scans on $TARGET..."
    
    nmap -sV --script vuln "$TARGET" -oN "$OUTPUT_DIR/vuln_scan.txt" &
    nmap --script http-vuln* "$TARGET" -oN "$OUTPUT_DIR/http_vuln.txt" &
    nikto -h "$TARGET" -o "$OUTPUT_DIR/nikto_vuln.txt" &
    wait
    log_message INFO "Vulnerability scans completed. Results saved in $OUTPUT_DIR."
}

run_web_scan() {
    find_ip
    prompt_target
    if ! [[ "$TARGET" =~ ^https?:// ]]; then
        log_message ERROR "Web scanning requires a URL (e.g., http://example.com). Exiting."
        return
    fi
    prompt_wordlist
    log_message INFO "Running web application scans on $TARGET with wordlist $WORDLIST..."
    
    nikto -h "$TARGET" -o "$OUTPUT_DIR/nikto_web.txt" &
    dirb "$TARGET" "$WORDLIST" -o "$OUTPUT_DIR/dirb_results.txt" &
    gobuster dir -u "$TARGET" -w "$WORDLIST" -o "$OUTPUT_DIR/gobuster.txt" &
    whatweb "$TARGET" > "$OUTPUT_DIR/whatweb.txt" &
    wpscan --url "$TARGET" --enumerate vp,vt,cb,dbe -o "$OUTPUT_DIR/wpscan.txt" &
    sqlmap -u "$TARGET" --batch --dbs > "$OUTPUT_DIR/sqlmap_dbs.txt" &
    xsstrike -u "$TARGET" > "$OUTPUT_DIR/xsstrike_xss.txt" &
    wait
    log_message INFO "Web scans completed. Results saved in $OUTPUT_DIR."
}

run_wireless_scan() {
    log_message INFO "Running wireless network scans. Ensure wireless interface is available."
    read -p "Enter wireless interface (e.g., wlan0): " wireless_interface
    if ! iwconfig "$wireless_interface" > /dev/null 2>&1; then
        log_message ERROR "Invalid wireless interface: $wireless_interface. Exiting."
        return
    fi
    prompt_wordlist
    log_message INFO "Using wordlist: $WORDLIST"
    
    airmon-ng start "$wireless_interface" > "$OUTPUT_DIR/airmon_start.txt"
    airodump-ng "${wireless_interface}mon" -w "$OUTPUT_DIR/wireless_dump" &
    wash -i "${wireless_interface}mon" > "$OUTPUT_DIR/wps_scan.txt" &
    aircrack-ng -w "$WORDLIST" "$OUTPUT_DIR/wireless_dump-01.cap" > "$OUTPUT_DIR/aircrack_results.txt" &
    wait
    airmon-ng stop "${wireless_interface}mon" > /dev/null
    log_message INFO "Wireless scans completed. Results saved in $OUTPUT_DIR."
}

run_enumeration() {
    find_ip
    prompt_target
    prompt_wordlist
    log_message INFO "Running enumeration and service probing on $TARGET with wordlist $WORDLIST..."
    
    nmap -sV -sC "$TARGET" -oN "$OUTPUT_DIR/service_enum.txt" &
    smbclient -L //"$TARGET" -N > "$OUTPUT_DIR/smb_enum.txt" &
    rpcclient -U "" -N "$TARGET" > "$OUTPUT_DIR/rpc_enum.txt" &
    showmount -e "$TARGET" > "$OUTPUT_DIR/nfs_enum.txt" &
    ldapsearch -x -H ldap://"$TARGET" -b "" -s base "(objectclass=*)" > "$OUTPUT_DIR/ldap_enum.txt" &
    hydra -L "$WORDLIST" -P "$WORDLIST" "$TARGET" ssh > "$OUTPUT_DIR/hydra_ssh.txt" &
    wait
    log_message INFO "Enumeration completed. Results saved in $OUTPUT_DIR."
}

run_custom_commands() {
    log_message INFO "Enter custom commands one by one. Type 'done' to finish."
    while true; do
        read -p "Enter command: " cmd
        if [ "$cmd" == "done" ]; then
            break
        fi
        log_message INFO "Executing custom command: $cmd"
        if ! eval "$cmd" >> "$OUTPUT_DIR/custom_commands.txt" 2>&1; then
            log_message ERROR "Command failed: $cmd"
        fi
    done
    log_message INFO "Custom commands executed. Results saved in $OUTPUT_DIR/custom_commands.txt"
}

run_metasploit_scan() {
    find_ip
    prompt_target
    log_message INFO "Running Metasploit exploit scan on $TARGET..."
    
    msfconsole -q -x "use auxiliary/scanner/portscan/tcp; set RHOSTS $TARGET; set THREADS $THREAD_COUNT; run; exit" > "$OUTPUT_DIR/metasploit_tcp_scan.txt"
    msfconsole -q -x "use auxiliary/scanner/http/http_version; set RHOSTS $TARGET; run; exit" > "$OUTPUT_DIR/metasploit_http_scan.txt"
    log_message INFO "Metasploit scans completed. Results saved in $OUTPUT_DIR."
}

run_ssl_scan() {
    find_ip
    prompt_target
    log_message INFO "Running SSL/TLS vulnerability scan on $TARGET..."
    
    testssl.sh --quiet "$TARGET" > "$OUTPUT_DIR/testssl_results.txt"
    log_message INFO "SSL/TLS scan completed. Results saved in $OUTPUT_DIR/testssl_results.txt."
}

display_warning
check_root
check_dependencies
load_config

while true; do
    show_menu
    read -p "Select option [1-11]: " choice
    
    case $choice in
        1) run_network_discovery ;;
        2) run_comprehensive_recon ;;
        3) run_vuln_scan ;;
        4) run_web_scan ;;
        5) run_wireless_scan ;;
        6) run_enumeration ;;
        7) run_custom_commands ;;
        8) run_metasploit_scan ;;
        9) run_ssl_scan ;;
        10) generate_summary ;;
        11) 
            log_message INFO "Goodbye!"
            exit 0
            ;;
        *) log_message ERROR "Invalid option!" ;;
    esac
done
