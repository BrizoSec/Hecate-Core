#!/bin/bash
# Demo script for ATHF Level 1: Getting Started with CLI
# Usage: ./demo-level1.sh
# Record with: asciinema rec -c "./demo-level1.sh" athf-level1-demo.cast

set -e

# Set TERM if not set (for non-interactive environments)
export TERM=${TERM:-xterm-256color}

# Colors and formatting
BOLD='\033[1m'
DIM='\033[2m'
CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RESET='\033[0m'

# Helper function to simulate typing
type_command() {
    echo -e "${CYAN}\$ $1${RESET}"
    sleep 0.5
}

# Helper function for output with delay
output() {
    echo -e "$1"
    sleep 0.3
}

# Helper function for section headers
section() {
    echo ""
    echo -e "${BOLD}━━━ $1 ━━━${RESET}"
    echo ""
    sleep 0.5
}

# Clear screen and show intro
clear
echo -e "${BOLD}Level 1: Documented Hunts${RESET}"
echo -e "${DIM}Analysts document hunts using LOCK structured markdown files${RESET}"
echo ""
sleep 2

# Step 1: Initialize workspace
section "Step 1: Initialize your workspace"
type_command "athf init"
sleep 1
output "${GREEN}✓${RESET} Created workspace configuration"
output "${GREEN}✓${RESET} Initialized hunts/ directory"
output "${GREEN}✓${RESET} Created templates/"
output "${GREEN}✓${RESET} Context files ready"
output ""
output "${DIM}Workspace ready at:${RESET} /Users/demo/threat-hunting"
sleep 2

# Step 2: Create first hunt
section "Step 2: Create your first hunt"
type_command "athf hunt new --technique T1567 --title \"Exfiltration Over Web Service Detection\""
sleep 1
output ""
output "${GREEN}✓${RESET} Created hunt: ${BOLD}H-0005${RESET}"
output ""
output "${DIM}  Hunt ID:${RESET} H-0005"
output "${DIM}  Title:${RESET} Exfiltration Over Web Service Detection"
output "${DIM}  Technique:${RESET} T1567 - Exfiltration Over Web Service"
output "${DIM}  Platform:${RESET} Multi-Platform (Windows, macOS, Linux)"
output "${DIM}  Status:${RESET} In Progress"
output ""
output "${DIM}Hunt file created:${RESET} hunts/H-0005.md"
sleep 3

# Step 3: Show the hunt metadata
section "Step 3: View hunt metadata"
type_command "head -30 hunts/H-0005.md"
sleep 1
output ""
output "${BOLD}H-0005: Exfiltration Over Web Service Detection${RESET}"
output ""
output "${BOLD}Hunt Metadata${RESET}"
output ""
output "  ${DIM}•${RESET} ${BOLD}Date:${RESET} 2025-11-22"
output "  ${DIM}•${RESET} ${BOLD}Hunter:${RESET} Sydney Marrone"
output "  ${DIM}•${RESET} ${BOLD}Status:${RESET} In Progress"
output "  ${DIM}•${RESET} ${BOLD}Platform:${RESET} Multi-Platform (Windows, macOS, Linux)"
output "  ${DIM}•${RESET} ${BOLD}MITRE ATT&CK:${RESET} T1567 (Exfiltration Over Web Service)"
output "  ${DIM}•${RESET} ${BOLD}Data Source:${RESET} EDR logs (29.5B records), DNS logs (2.2B records)"
output ""
output "${DIM}LOCK sections:${RESET} Learn, Observe, Check, Keep"
sleep 3

# Step 4: Validate hunts
section "Step 4: Validate hunt structure"
type_command "athf hunt validate"
sleep 1
output ""
output "${GREEN}✓${RESET} H-0005.md - Valid LOCK structure"
output "  ${GREEN}✓${RESET} YAML frontmatter valid"
output "  ${GREEN}✓${RESET} LOCK sections present"
output "  ${GREEN}✓${RESET} Metadata complete"
output ""
output "${GREEN}All hunts validated!${RESET}"
sleep 2

# Step 5: List hunts
section "Step 5: View your hunt catalog"
type_command "athf hunt list"
sleep 1
output ""
output "${BOLD}Hunt Catalog${RESET}"
output "${DIM}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
output ""
output "${YELLOW}H-0005${RESET} │ ${BOLD}Exfiltration Over Web Service Detection${RESET}"
output "       │ T1567 • Multi-Platform • exfiltration"
output "       │ Status: ${CYAN}In Progress${RESET}"
output "       │ ${DIM}Cloud storage and collaboration platforms for data theft${RESET}"
output ""
output "${DIM}Total: 1 hunt${RESET}"
sleep 3

# Closing
echo ""
echo ""
echo -e "${GREEN}✓${RESET} ${BOLD}Level 1 Benefits:${RESET}"
output "  • Reliable history - Hunt persists with full context"
output "  • Repeatable knowledge transfer"
output "  • Structured LOCK methodology"
output "  • Ready for AI assistance (Level 2+)"
output ""
sleep 2

echo -e "${DIM}You've documented your first hunt. AI can now read and recall it.${RESET}"
echo ""
sleep 1
