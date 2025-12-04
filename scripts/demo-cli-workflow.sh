#!/bin/bash
# Demo script for ATHF CLI Workflow
# Shows: init → hunt new → validate → coverage
# Record with: asciinema rec -c "./demo-cli-workflow.sh" athf-cli-workflow.cast

set -e

# Set TERM if not set
export TERM=${TERM:-xterm-256color}

# Colors
BOLD='\033[1m'
DIM='\033[2m'
CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
RESET='\033[0m'

type_command() {
    echo -e "${CYAN}\$ $1${RESET}"
    sleep 0.5
}

output() {
    echo -e "$1"
    sleep 0.3
}

section() {
    echo ""
    echo -e "${BOLD}━━━ $1 ━━━${RESET}"
    echo ""
    sleep 0.5
}

# Clear and intro
clear
echo -e "${BOLD}A Quick Look at the CLI Workflow${RESET}"
echo ""
sleep 2

# Step 1: Initialize workspace
section "1. Initialize your workspace"
type_command "git clone https://github.com/Nebulock-Inc/agentic-threat-hunting-framework"
sleep 0.5
output "${DIM}Cloning into 'agentic-threat-hunting-framework'...${RESET}"
output "${DIM}Receiving objects: 100% (523/523), done.${RESET}"
sleep 0.5

echo ""
type_command "cd agentic-threat-hunting-framework"
sleep 0.3

echo ""
type_command "pip install -e ."
sleep 0.5
output "${DIM}Obtaining file:///path/to/agentic-threat-hunting-framework${RESET}"
output "${DIM}Installing collected packages: athf${RESET}"
output "${GREEN}Successfully installed athf-0.1.0${RESET}"
sleep 0.5

echo ""
type_command "athf init"
sleep 1
output ""
output "${GREEN}✓${RESET} Created workspace configuration: ${DIM}.athfconfig.yaml${RESET}"
output "${GREEN}✓${RESET} Initialized directories:"
output "  ${DIM}• hunts/${RESET}"
output "  ${DIM}• templates/${RESET}"
output "  ${DIM}• knowledge/${RESET}"
output "  ${DIM}• queries/${RESET}"
output "${GREEN}✓${RESET} Context files ready: ${DIM}AGENTS.md, environment.md${RESET}"
output ""
output "${BOLD}This command builds the full workspace:${RESET} hunts, templates, knowledge"
output "files, and context files. It gives your program a ${BOLD}consistent memory layer.${RESET}"
sleep 3

# Step 2: Create new hunt
section "2. Create a new hunt"
type_command "athf hunt new --technique T1005 --title \"macOS Data Collection Review\""
sleep 1
output ""
output "${GREEN}✓${RESET} Created hunt: ${BOLD}H-0001${RESET}"
output ""
output "${DIM}Hunt Details:${RESET}"
output "  ${YELLOW}ID:${RESET}        H-0001"
output "  ${YELLOW}Title:${RESET}     macOS Data Collection Review"
output "  ${YELLOW}Technique:${RESET} T1005 - Data from Local System"
output "  ${YELLOW}Status:${RESET}    in-progress"
output "  ${YELLOW}File:${RESET}      hunts/H-0001.md"
output ""
output "${BOLD}The CLI generates a LOCK-ready hunt file${RESET} with every required"
output "section in place."
sleep 3

# Step 3: Validate hunts
section "3. Validate your hunts"
type_command "athf hunt validate"
sleep 1
output ""
output "${DIM}Validating hunt structure...${RESET}"
output ""
output "${GREEN}✓${RESET} H-0001.md"
output "  ${GREEN}✓${RESET} YAML frontmatter valid"
output "  ${GREEN}✓${RESET} LOCK sections present (Learn, Observe, Check, Keep)"
output "  ${GREEN}✓${RESET} Required metadata found"
output ""
output "${GREEN}All hunts validated successfully!${RESET}"
output ""
output "${BOLD}Validation ensures structure stays consistent${RESET} across hunts. AI tools"
output "rely on this consistency once they start reading and reasoning over"
output "your repository."
sleep 3

# Step 4: Track coverage
section "4. Track ATT&CK coverage"
type_command "athf hunt coverage"
sleep 1
output ""
output "${BOLD}MITRE ATT&CK Coverage Report${RESET}"
output "${DIM}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
output ""
output "${BLUE}Collection${RESET} (TA0009)"
output "  ${GREEN}✓${RESET} T1005 - Data from Local System ${DIM}(1 hunt)${RESET}"
output ""
output "${DIM}Coverage Summary:${RESET}"
output "  Total Techniques: ${BOLD}1${RESET}"
output "  Tactics Covered:  ${BOLD}1${RESET}"
output "  Hunt Count:       ${BOLD}1${RESET}"
output ""
output "${YELLOW}Suggested next hunts:${RESET}"
output "  • T1003 - OS Credential Dumping"
output "  • T1059 - Command and Scripting Interpreter"
output "  • T1560 - Archive Collected Data"
output ""
output "${BOLD}This command shows which techniques you cover and where gaps${RESET}"
output "${BOLD}remain.${RESET} It removes the need to maintain your own spreadsheets."
sleep 3

# Step 5: AI Assistants
section "5. Use AI assistants with your repo"
output ""
output "${BOLD}Open your repo in an AI coding assistant${RESET}"
output ""
sleep 1

output "${DIM}You ask:${RESET} ${CYAN}\"What should I hunt for next based on H-0001?\"${RESET}"
sleep 1
output ""
output "${DIM}AI reads:${RESET}"
output "  ${DIM}• hunts/H-0001.md (your hunt context)${RESET}"
output "  ${DIM}• AGENTS.md (your environment)${RESET}"
output "  ${DIM}• knowledge/hunting-knowledge.md (expert frameworks)${RESET}"
sleep 2

output ""
output "${DIM}AI responds:${RESET}"
output "${GREEN}\"Based on H-0001's findings (Atomic Stealer targeting Safari/Chrome),${RESET}"
output "${GREEN}I suggest extending to Firefox and Brave browsers. Your H-0001${RESET}"
output "${GREEN}query pattern (unsigned process + rapid file access) can be adapted.${RESET}"
output "${GREEN}Run:${RESET} ${CYAN}athf hunt new --technique T1005 --title \"Firefox Data Collection\"${RESET}${GREEN}\"${RESET}"
sleep 3

output ""
output "${BOLD}AI assistants use your hunt memory to provide context-aware${RESET}"
output "${BOLD}suggestions,${RESET} referencing past work automatically."
sleep 2

# Closing
echo ""
echo ""
echo -e "${BOLD}✨ Complete CLI Workflow!${RESET}"
echo ""
output "You now have:"
output "  ${GREEN}✓${RESET} Initialized workspace with full memory layer"
output "  ${GREEN}✓${RESET} LOCK-structured hunt documentation (H-0001)"
output "  ${GREEN}✓${RESET} Validated hunt format for AI consistency"
output "  ${GREEN}✓${RESET} ATT&CK coverage visibility"
output "  ${GREEN}✓${RESET} AI-readable context for intelligent assistance"
output ""
output "${DIM}Your threat hunting program now has memory and agency.${RESET}"
echo ""
sleep 3
