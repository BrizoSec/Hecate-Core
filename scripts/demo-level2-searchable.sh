#!/bin/bash
# Level 2: Searchable Memory (AI-Assisted)
# Shows AI reading hunt history and providing context

set -e
export TERM=${TERM:-xterm-256color}

BOLD='\033[1m'
DIM='\033[2m'
CYAN='\033[0;36m'
GREEN='\033[0;32m'
PURPLE='\033[0;35m'
RESET='\033[0m'

clear
echo -e "${BOLD}Level 2: Searchable Memory${RESET}"
echo -e "${DIM}AI reads your hunt history and provides context${RESET}"
echo ""
sleep 2

echo -e "${BOLD}You:${RESET} ${DIM}\"We need to hunt for macOS information stealers. What do we know?\"${RESET}"
echo ""
sleep 1

echo -e "${PURPLE}AI Assistant:${RESET} ${DIM}Let me check your hunt history...${RESET}"
sleep 1
echo ""
echo -e "  ${DIM}Searching hunts/ for macOS and information stealers...${RESET}"
sleep 0.5
echo -e "  ${DIM}Reading AGENTS.md for environment context...${RESET}"
sleep 0.5
echo -e "  ${DIM}Checking knowledge/hunting-knowledge.md for best practices...${RESET}"
sleep 1

echo ""
echo -e "${PURPLE}AI:${RESET} ${GREEN}Found relevant context!${RESET}"
echo ""
echo -e "${DIM}You already investigated this in H-0001 (2025-11-15):${RESET}"
echo -e "${DIM}• Detected Atomic Stealer via unsigned process monitoring${RESET}"
echo -e "${DIM}• Query refined: 247 events → 1 true positive, 0 false positives${RESET}"
echo -e "${DIM}• Detection: 2 minutes, Containment: 4 minutes${RESET}"
echo -e "${DIM}• Detection rule deployed for Safari/Chrome${RESET}"
echo ""
sleep 2

echo -e "${DIM}Your H-0001 findings suggest expanding to:${RESET}"
echo -e "  ${GREEN}1.${RESET} Firefox/Brave browser data - mentioned as 'next step'"
echo -e "  ${GREEN}2.${RESET} Keychain access attempts - identified in threat intel"
echo -e "  ${GREEN}3.${RESET} Deploy EDR to remaining 15% of macOS fleet"
echo ""
sleep 2

echo -e "${BOLD}You:${RESET} ${DIM}\"Good idea! Let's hunt for Firefox browser data. What data sources?\"${RESET}"
echo ""
sleep 1

echo -e "${PURPLE}AI:${RESET} ${DIM}Reading your AGENTS.md...${RESET}"
sleep 0.5
echo ""
echo -e "${DIM}Your environment has:${RESET}"
echo -e "  ${CYAN}•${RESET} macOS EDR (85% coverage, file access monitoring)"
echo -e "  ${CYAN}•${RESET} Process signature validation enabled"
echo -e "  ${CYAN}•${RESET} 90-day retention"
echo ""
echo -e "${DIM}Building on H-0001's query patterns, I'll create${RESET} ${CYAN}H-0002${RESET}"
sleep 3

echo ""
echo ""
echo -e "${GREEN}✓${RESET} ${BOLD}Level 2 Benefits:${RESET}"
echo -e "  • AI recalls past hunts automatically"
echo -e "  • Context-aware suggestions based on your environment"
echo -e "  • 20 minutes of research → 5 seconds"
echo ""
sleep 2
