#!/bin/bash
# Demo: AI searching hunt repository for exfiltration coverage
# Shows Level 2 capability - AI reads and summarizes hunts

set -e
export TERM=${TERM:-xterm-256color}

BOLD='\033[1m'
DIM='\033[2m'
CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
PURPLE='\033[0;35m'
RESET='\033[0m'

clear
echo -e "${BOLD}AI Assistant - ATHF Repository${RESET}"
echo -e "${DIM}AI-powered threat hunt search${RESET}"
echo ""
sleep 2

# User query
echo -e "${CYAN}You:${RESET} search for past hunts where we looked at exfiltration"
echo ""
sleep 2

# AI processing
echo -e "${PURPLE}AI Assistant:${RESET} ${DIM}Let me search your hunt repository...${RESET}"
echo ""
sleep 1

echo -e "${DIM}Searching hunts/ directory...${RESET}"
sleep 0.5
echo -e "${DIM}  • Reading H-0001.md...${RESET}"
sleep 0.3
echo -e "${DIM}  • Reading H-0002.md...${RESET}"
sleep 0.3
echo -e "${DIM}  • Reading H-0003.md...${RESET}"
sleep 0.3
echo -e "${DIM}  • Found 3 hunts matching 'exfiltration'${RESET}"
sleep 1

echo ""
echo -e "${DIM}Analyzing coverage patterns...${RESET}"
sleep 1
echo ""

# Output table
echo -e "${BOLD}Summary of Exfiltration Coverage${RESET}"
echo ""
sleep 0.5

echo -e "${BOLD}Hunt ID   Primary Technique                 Data Volume          Findings                  Status${RESET}"
echo -e "${DIM}─────────────────────────────────────────────────────────────────────────────────────────────────────${RESET}"
sleep 0.5

# H-0001
echo ""
echo -e "${YELLOW}H-0001${RESET}    T1041 - Exfiltration Over C2     67.6M network        No exfiltration           ${GREEN}✓${RESET} Complete"
echo -e "                                            events               detected"
sleep 1

# H-0003
echo ""
echo -e "${YELLOW}H-0003${RESET}    T1071.004 - DNS Tunneling         2.2B DNS records     Methodology               ${GREEN}✓${RESET} Complete"
echo -e "                                                                 validated"
sleep 1

# H-0004
echo ""
echo -e "${YELLOW}H-0004${RESET}    T1105 - Ingress Tool Transfer     29.5B EDR events     3 suspicious findings     ${GREEN}✓${RESET} Complete"
sleep 1.5

# Telemetry gaps
echo ""
echo ""
echo -e "${DIM}All three hunts documented ${BOLD}telemetry gaps${RESET}${DIM} that could impact exfiltration detection:${RESET}"
echo ""
sleep 1

echo -e "  ${YELLOW}•${RESET} Missing HTTP URI paths in network logs"
sleep 0.5
echo -e "  ${YELLOW}•${RESET} No file read/access monitoring"
sleep 0.5
echo -e "  ${YELLOW}•${RESET} Limited visibility into failed DNS resolutions (NXDOMAIN)"
sleep 1.5

# Follow-up question
echo ""
echo ""
echo -e "${PURPLE}AI Assistant:${RESET} ${DIM}Would you like me to provide more details on any${RESET}"
echo -e "${DIM}specific exfiltration technique or detection method used in these hunts?${RESET}"
echo ""
sleep 3

# Summary
echo ""
echo -e "${GREEN}✓${RESET} ${BOLD}AI Search Benefits:${RESET}"
echo -e "  • Instant recall of past work (3 hunts found)"
echo -e "  • Structured summaries with key metrics"
echo -e "  • Identifies coverage patterns and gaps"
echo -e "  • 20 minutes of manual search → 5 seconds"
echo ""
sleep 2
