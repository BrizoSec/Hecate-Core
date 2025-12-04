#!/bin/bash
# Level 0: Ad-hoc Hunting (The Problem)
# Shows scattered, undocumented hunt notes

set -e
export TERM=${TERM:-xterm-256color}

BOLD='\033[1m'
DIM='\033[2m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
RESET='\033[0m'

clear
echo -e "${BOLD}Level 0: Ad-hoc Hunting${RESET}"
echo -e "${DIM}(The problem we're solving)${RESET}"
echo ""
sleep 2

echo -e "${BOLD}The Reality:${RESET}"
echo ""
sleep 0.5

echo -e "${YELLOW}Slack #security channel:${RESET}"
echo -e "${DIM}@analyst1:${RESET} Did we check for macOS info stealers after that phishing campaign?"
echo -e "${DIM}@analyst2:${RESET} I think someone looked at it? Not sure..."
echo -e "${DIM}@analyst3:${RESET} I ran some EDR queries but didn't save them"
sleep 2

echo ""
echo -e "${YELLOW}Scattered notes:${RESET}"
echo -e "${DIM}• \"Check unsigned processes\" - notebook, page 47${RESET}"
echo -e "${DIM}• Query for Safari cookies - lost in ~/Desktop/queries.txt${RESET}"
echo -e "${DIM}• \"Found SystemHelper suspicious\" - email thread buried${RESET}"
echo -e "${DIM}• Detection logic - in analyst's head only${RESET}"
sleep 2

echo ""
echo -e "${RED}Problems:${RESET}"
echo -e "  ${RED}✗${RESET} No memory - hunts forgotten after 3 months"
echo -e "  ${RED}✗${RESET} Redundant work - same hunt run multiple times"
echo -e "  ${RED}✗${RESET} No knowledge transfer - context lost when analyst leaves"
echo -e "  ${RED}✗${RESET} Can't track coverage - no idea what's been tested"
sleep 3

echo ""
echo ""
echo -e "${BOLD}Solution: Move to Level 1 (Documented Hunts)${RESET}"
echo ""
sleep 2
