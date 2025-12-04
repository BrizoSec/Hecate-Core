#!/bin/bash
# Level 3: Generative Capabilities (AI Executes)
# Shows AI running queries via MCP tools

set -e
export TERM=${TERM:-xterm-256color}

BOLD='\033[1m'
DIM='\033[2m'
CYAN='\033[0;36m'
GREEN='\033[0;32m'
PURPLE='\033[0;35m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
RESET='\033[0m'

clear
echo -e "${BOLD}Level 3: Generative Capabilities${RESET}"
echo -e "${DIM}AI connects to your tools through MCP servers${RESET}"
echo ""
sleep 2

echo -e "${DIM}AI runs queries, enriches results, and updates hunts:${RESET}"
echo ""
echo -e "  ${CYAN}•${RESET} Run SIEM searches in Splunk, Elastic, or Chronicle"
echo -e "  ${CYAN}•${RESET} Query EDR telemetry from CrowdStrike, SentinelOne, or Microsoft Defender"
echo -e "  ${CYAN}•${RESET} Create tickets in Jira, ServiceNow, or GitHub"
echo -e "  ${CYAN}•${RESET} Update hunt markdown files with findings"
echo ""
sleep 3

# First interaction - ask for coverage gaps
echo -e "${BOLD}You:${RESET} ${CYAN}\"what other exfil techniques can i hunt\"${RESET}"
echo ""
sleep 2

echo -e "${PURPLE}AI Assistant:${RESET} ${DIM}Let me analyze your hunt-vault coverage...${RESET}"
sleep 1
echo ""
echo -e "${DIM}Based on your hunt-vault coverage, here are additional exfiltration${RESET}"
echo -e "${DIM}techniques you can hunt for:${RESET}"
echo ""
sleep 1

echo -e "${BOLD}High-Priority Exfiltration Techniques (Not Yet Covered)${RESET}"
echo ""
sleep 0.5

echo -e "${YELLOW}1. T1567 - Exfiltration Over Web Service${RESET}"
echo ""
echo -e "${DIM}Cloud storage and collaboration platforms used for data theft.${RESET}"
echo ""
echo -e "${DIM}Sub-techniques:${RESET}"
sleep 0.5
echo -e "  • ${CYAN}T1567.001${RESET} - Exfiltration to Code Repository ${DIM}(GitHub, GitLab, Bitbucket)${RESET}"
sleep 0.3
echo -e "  • ${CYAN}T1567.002${RESET} - Exfiltration to Cloud Storage ${DIM}(Dropbox, Google Drive, OneDrive, Box, AWS S3)${RESET}"
sleep 0.3
echo -e "  • ${CYAN}T1567.003${RESET} - Exfiltration to Text Storage Sites ${DIM}(Pastebin, GitHub Gist)${RESET}"
sleep 0.3
echo -e "  • ${CYAN}T1567.004${RESET} - Exfiltration Over Webhook ${DIM}(Slack, Discord, Microsoft Teams webhooks)${RESET}"
sleep 2

echo ""
echo ""
echo -e "${DIM}This shift replaces \"copy and paste between five tools\"${RESET}"
echo -e "${DIM}with \"ask and validate.\"${RESET}"
echo ""
sleep 2

# Second interaction - create the hunt
echo -e "${BOLD}You:${RESET} ${CYAN}\"hunt for T1567 - Exfiltration Over Web Service\"${RESET}"
echo ""
sleep 2

echo -e "${PURPLE}AI Assistant:${RESET} ${DIM}Creating comprehensive hunt plan...${RESET}"
sleep 1
echo ""

echo -e "${GREEN}I've created a comprehensive hunt plan for ${CYAN}H-0005: Exfiltration Over Web${RESET}"
echo -e "${GREEN}Service Detection!${RESET}"
echo ""
sleep 1

echo -e "${BOLD}What I Built${RESET}"
echo ""
sleep 0.5

echo -e "${BOLD}Coverage: All T1567 Sub-techniques${RESET}"
echo ""
sleep 0.5
echo -e "  ${GREEN}1.${RESET} ${CYAN}T1567.001${RESET} - Exfiltration to Code Repository ${DIM}(GitHub, GitLab, Bitbucket)${RESET}"
sleep 0.3
echo -e "  ${GREEN}2.${RESET} ${CYAN}T1567.002${RESET} - Exfiltration to Cloud Storage ${DIM}(Dropbox, Drive, OneDrive, AWS S3, Azure Blob)${RESET}"
sleep 0.3
echo -e "  ${GREEN}3.${RESET} ${CYAN}T1567.003${RESET} - Exfiltration to Text Storage Sites ${DIM}(Pastebin, GitHub Gist)${RESET}"
sleep 0.3
echo -e "  ${GREEN}4.${RESET} ${CYAN}T1567.004${RESET} - Exfiltration Over Webhook ${DIM}(Discord, Slack, Teams)${RESET}"
sleep 2

echo ""
echo ""
echo -e "${BOLD}8 Hunting Queries Ready to Execute${RESET}"
echo ""
sleep 0.5

# Query table header
echo -e "${BOLD}Query                Focus                              Priority  Expected Hits${RESET}"
echo -e "${DIM}──────────────────────────────────────────────────────────────────────────────────${RESET}"
sleep 0.5

# Q1
echo ""
echo -e "${YELLOW}Q1: Cloud CLI Tools${RESET}  AWS CLI, gsutil, rclone from          ${RED}HIGH${RESET}      Low (DevOps"
echo -e "                     workstations                                     only)"
sleep 0.5

# Q2
echo ""
echo -e "${YELLOW}Q2: Git Large File${RESET}   Git push to external repos with        ${RED}CRITICAL${RESET}  Medium"
echo -e "${YELLOW}Pushes${RESET}               sensitive files"
sleep 0.5

# Q3
echo ""
echo -e "${YELLOW}Q3: Curl/Wget Cloud${RESET}  File uploads to cloud storage via      ${RED}HIGH${RESET}      Low"
echo -e "${YELLOW}Uploads${RESET}              curl"
sleep 0.5

# Q4
echo ""
echo -e "${YELLOW}Q4: PowerShell Web${RESET}   Invoke-WebRequest POST uploads         ${RED}HIGH${RESET}      Low"
echo -e "${YELLOW}Uploads${RESET}              (Windows)"
sleep 0.5

# Q5
echo ""
echo -e "${YELLOW}Q5: Webhook${RESET}          CLI webhook posts to                   ${CYAN}MEDIUM${RESET}    Low-Medium"
echo -e "${YELLOW}Exfiltration${RESET}         Discord/Slack"
sleep 0.5

# Q6
echo ""
echo -e "${YELLOW}Q6: Pastebin${RESET}         Text storage site uploads              ${CYAN}MEDIUM${RESET}    Low"
echo -e "${YELLOW}Uploads${RESET}"
sleep 0.5

# Q7
echo ""
echo -e "${YELLOW}Q7: Compress →${RESET}       Data staging workflow detection        ${RED}CRITICAL${RESET}  Low"
echo -e "${YELLOW}Upload${RESET}"
sleep 0.5

# Q8
echo ""
echo -e "${YELLOW}Q8: DNS Query${RESET}        High DNS queries to cloud storage      ${DIM}LOW${RESET}       Context only"
echo -e "${YELLOW}Volume${RESET}"
sleep 2

echo ""
echo ""
echo -e "${GREEN}✓${RESET} ${BOLD}Level 3 Benefits:${RESET}"
echo -e "  • AI generates complete hunt plans from a single request"
echo -e "  • Coverage mapped to all sub-techniques automatically"
echo -e "  • Queries prioritized based on environment and threat intel"
echo -e "  • Ready to execute via MCP tools (EDR, SIEM, ticketing)"
echo ""
sleep 2
