---
name: Hunt Contribution
about: Share a hunt example with the community (optional)
title: '[HUNT] '
labels: hunt-example
assignees: ''

---

## Hunt Overview

**Hunt ID:** (e.g., H-0025)
**Title:** (e.g., "AWS Lambda Backdoor Detection")
**MITRE ATT&CK Technique:** (e.g., T1098.003)
**Platform:** (e.g., AWS, Azure, Windows, Linux, macOS)

## Why Share This Hunt?

Explain what makes this hunt valuable to share:
- Unique detection technique
- Addresses common blind spot
- Novel query approach
- High success rate

## Hunt Summary

Brief summary (3-5 sentences) of:
- What behavior you hunted for
- How you detected it
- What you found

## Redaction Notice

**Important:** Please ensure all sensitive information is removed:
- [ ] No real IP addresses, hostnames, or domains
- [ ] No usernames or email addresses
- [ ] No internal tool names or proprietary systems
- [ ] No specific company or customer details
- [ ] Queries use example/placeholder data

## Hunt File

Please attach or paste your hunt markdown file below. Must include:
- YAML frontmatter with required fields
- All four LOCK sections (LEARN, OBSERVE, CHECK, KEEP)
- Sanitized queries
- Results summary (can be anonymized metrics)

**Option 1: Attach File**
Drag and drop your `H-XXXX.md` file here.

**Option 2: Paste Content**
```markdown
---
hunt_id: H-0025
title: "Your Hunt Title"
status: completed
date: 2025-12-02
hunter: "Your Name"
techniques: [T1098.003]
tactics: [persistence]
platforms: [aws]
data_sources: [cloudtrail]
findings_count: 2
true_positives: 1
false_positives: 1
tags: [cloud, lambda, backdoor]
---

# H-0025: Your Hunt Title

(Paste your hunt content here)
```

## Additional Context

- **Environment Type:** (e.g., Enterprise AWS, Azure, on-prem Windows domain)
- **Data Sources Used:** (e.g., CloudTrail, EDR, SIEM)
- **Hunt Duration:** (e.g., 7 days, 30 days)
- **Success Metrics:** (e.g., 2 TPs, 1 FP, 50% success rate)

## Learning and Impact

What did this hunt teach you? What impact did it have?

## License Acknowledgment

By submitting this hunt, you acknowledge:
- [ ] I own this content or have permission to share it
- [ ] I agree to share it under the same license as ATHF (check repository LICENSE)
- [ ] I understand this becomes part of the public ATHF repository
- [ ] I have removed all sensitive/proprietary information

## Optional: Detection Rule

If you converted this hunt to an automated detection, consider sharing:
- Detection logic (pseudocode or actual rule)
- False positive rate
- Tuning notes

## Note on Contribution Philosophy

ATHF is a framework to internalize, not a platform requiring contributions. Sharing hunts is **optional** and appreciated, but not expected. See [USING_ATHF.md](../../USING_ATHF.md) for the full philosophy.

If you prefer to keep your hunts private, that's completely fine! This template is here only for those who want to share specific examples that might help others.
