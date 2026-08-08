"""Render hunt templates with metadata."""

from datetime import datetime
from pathlib import Path
from typing import Optional

from jinja2 import Template

# Default bundled template - used when no custom template exists
HUNT_TEMPLATE = """---
hunt_id: {{ hunt_id }}
title: {{ title }}
status: {{ status }}
date: {{ date }}
hunter: {{ hunter }}
platform: {{ platform }}
tactics: {{ tactics }}
techniques: {{ techniques }}
data_sources: {{ data_sources }}
related_hunts: []
{% if spawned_from %}spawned_from: {{ spawned_from }}
{% endif %}{% if hypothesis_duration_minutes %}hypothesis_duration_minutes: {{ hypothesis_duration_minutes }}
{% endif %}findings_count: 0
true_positives: 0
false_positives: 0
customer_deliverables: []
tags: {{ tags }}
---

# {{ hunt_id }}: {{ title }}

**Hunt Metadata**

- **Date:** {{ date }}
- **Hunter:** {{ hunter }}
- **Status:** {{ status }}
- **MITRE ATT&CK:** {{ techniques[0] if techniques else '[Primary Technique]' }}

---

## LEARN: Prepare the Hunt

### Hypothesis Statement

{{ hypothesis if hypothesis else '[What behavior are you looking for? What will you observe if the hypothesis is true?]' }}

### Threat Context

{{ threat_context if threat_context else '[What threat actor/malware/TTP motivates this hunt?]' }}

### ABLE Scoping

| **Field**   | **Your Input** |
|-------------|----------------|
| **Actor** *(Optional)* | {{ actor if actor else '[Threat actor or malware family]' }} |
| **Behavior** | {{ behavior if behavior else '[TTP or behavior pattern]' }} |
| **Location** | {{ location if location else '[Systems, networks, or environments to hunt]' }} |
| **Evidence** | {{ evidence if evidence else '[Data sources and key fields to examine]' }} |

### Threat Intel & Research

- **MITRE ATT&CK Techniques:** {{ ', '.join(techniques) if techniques else '[List relevant techniques]' }}
- **CTI Sources & References:** [Links to reports, blogs, etc.]
{% if spawned_from %}- **Research Document:** See [{{ spawned_from }}](../research/{{ spawned_from }}.md) for detailed pre-hunt research
{% endif %}

### Related Tickets

| **Team** | **Ticket/Details** |
|----------|-------------------|
| **SOC/IR** | [Ticket numbers or N/A] |

---

## OBSERVE: Expected Behaviors

### What Normal Looks Like

[Describe legitimate activity that should not trigger alerts]

### What Suspicious Looks Like

[Describe adversary behavior patterns to hunt for]

### Expected Observables

- **Processes:** [Process names, command lines]
- **Network:** [Connections, protocols, domains]
- **Files:** [File paths, extensions, sizes]
- **Registry:** [Registry keys if applicable]
- **Authentication:** [Login patterns if applicable]

---

## CHECK: Execute & Analyze

### Data Source Information

- **Index/Data Source:** {{ data_sources_list[0] if data_sources_list else '[SIEM index or data source]' }}
- **Time Range:** [Date range for hunt]
- **Events Analyzed:** [Approximate count]
- **Data Quality:** [Assessment of data completeness]

### Hunting Queries

#### Initial Query

```
[Your initial query]
```

**Query Notes:**
- [What did this query return?]
- [What worked? What didn't?]

### Query Performance

**What Worked Well:**
- [Effective filters or techniques]

**What Didn't Work:**
- [Challenges or limitations]

**Iterations Made:**
- [Document query evolution]

---

## KEEP: Findings & Response

### Executive Summary

[Concise summary of hunt results and key findings]

### Findings

| **Finding** | **Ticket** | **Description** |
|-------------|-----------|-----------------|
| [Type] | [Ticket] | [Description] |

**True Positives:** 0
**False Positives:** 0

### Lessons Learned

**What Worked Well:**
- [Successes]

**What Could Be Improved:**
- [Areas for improvement]

**Telemetry Gaps Identified:**
- [Missing data sources or visibility gaps]

### Follow-up Actions

- [ ] [Action item 1]
- [ ] [Action item 2]

---

**Hunt Completed:** [Date]
**Next Review:** [Date for recurring hunt if applicable]
"""


# Baseline (EDA) hunt template — PEAK's "Baseline Hunting" execute-phase type.
# Deliberately reuses the LOCK top-level headings (LEARN/OBSERVE/CHECK/KEEP)
# so hunt_parser.py's section extraction, `hunt validate`'s required-section
# check, and `hunt export` all keep working unmodified for this hunt type —
# only the subsection labels underneath are baseline-specific. There is no
# hypothesis: the point of a baseline hunt is establishing what "normal"
# looks like for a dimension, not testing a specific TTP.
BASELINE_TEMPLATE = """---
hunt_id: {{ hunt_id }}
title: {{ title }}
hunt_type: baseline
status: {{ status }}
date: {{ date }}
hunter: {{ hunter }}
platform: {{ platform }}
data_sources: {{ data_sources }}
dimension: {{ dimension if dimension else '[Field or behavior being characterized]' }}
related_hunts: []
findings_count: 0
true_positives: 0
false_positives: 0
customer_deliverables: []
tags: {{ tags }}
---

# {{ hunt_id }}: {{ title }}

**Hunt Metadata**

- **Type:** Baseline (EDA) — no hypothesis; establishing ground truth
- **Date:** {{ date }}
- **Hunter:** {{ hunter }}
- **Status:** {{ status }}
- **Dimension:** {{ dimension if dimension else '[Field or behavior being characterized]' }}

---

## LEARN: Prepare the Baseline

### Baseline Objective

{{ objective if objective else '[What dimension/field are we characterizing, and why does establishing "normal" here matter?]' }}

### Scope

| **Field**   | **Your Input** |
|-------------|----------------|
| **Dimension** | {{ dimension if dimension else '[e.g., "parent_process -> child_process pairs"]' }} |
| **Location** | [Systems, networks, or environments in scope] |
| **Evidence** | [Data source(s) and key fields to examine] |

### Related Context

[Why now? Gap in visibility? Precursor to a specific hypothesis-driven hunt?]

---

## OBSERVE: Expected Normal

### Hypothesized Normal Range

[Best guess, before running anything, at what "normal" will look like -- cardinality, top values, expected distribution]

### What Would Be Anomalous

[What deviation from normal would actually be worth a hypothesis-driven follow-up hunt]

---

## CHECK: Characterize & Analyze

### Data Source Information

- **Index/Data Source:** {{ data_sources_list[0] if data_sources_list else '[SIEM index or data source]' }}
- **Time Range:** [Date range for baseline]
- **Events Analyzed:** [Approximate count]
- **Data Quality:** [Assessment of data completeness]

### Baseline Queries

#### Initial Query

```
[Frequency count / cardinality / rare-value query]
```

**Query Notes:**
- [What did this query return?]
- [What worked? What didn't?]

### Results: What Normal Actually Looks Like

[The actual characterization -- distributions, common values, established baseline]

---

## KEEP: Candidate Anomalies & Follow-up

### Candidate Anomalies

| **Anomaly** | **Rarity/Deviation** | **Worth a Hypothesis-Driven Hunt?** |
|-------------|----------------------|--------------------------------------|
| [Description] | [e.g., "seen on 1/500 hosts"] | [Yes/No/Maybe] |

**Candidate Anomalies Found:** 0

### Baseline Knowledge Captured

[Reusable "what's normal here" reference for future hunts to cite]

### Spawned Hunts

[Hunt IDs created from this baseline's anomalies -- keep related_hunts in frontmatter in sync]

### Lessons Learned

**What Worked Well:**
- [Successes]

**What Could Be Improved:**
- [Areas for improvement]

**Telemetry Gaps Identified:**
- [Missing data sources or visibility gaps]

---

**Baseline Completed:** [Date]
**Next Review:** [Date for re-baselining if this dimension drifts over time]
"""


MATH_TEMPLATE = """---
hunt_id: {{ hunt_id }}
title: {{ title }}
hunt_type: model-assisted
status: {{ status }}
date: {{ date }}
hunter: {{ hunter }}
platform: {{ platform }}
data_sources: {{ data_sources }}
model_type: {{ model_type if model_type else '[clustering|z-score|IQR|isolation-forest|other]' }}
features: {{ features if features else '[]' }}
anomaly_threshold: {{ anomaly_threshold if anomaly_threshold else '[value]' }}
related_hunts: []
findings_count: 0
true_positives: 0
false_positives: 0
customer_deliverables: []
tags: {{ tags }}
---

# {{ hunt_id }}: {{ title }}

**Hunt Metadata**

- **Type:** Model-Assisted (M-ATH) — statistical/ML model over telemetry to surface anomalies at scale
- **Date:** {{ date }}
- **Hunter:** {{ hunter }}
- **Status:** {{ status }}
- **Model Type:** {{ model_type if model_type else '[clustering|z-score|IQR|isolation-forest|other]' }}
- **Features:** {{ features if features else '[Key fields/dimensions being analyzed]' }}

---

## LEARN: Prepare the Model Run

### Model Objective

{{ objective if objective else '[What anomaly pattern are we trying to surface, and why does volume or complexity make manual EDA insufficient here?]' }}

### Scope

| **Field**       | **Your Input** |
|-----------------|----------------|
| **Dataset**     | {{ dataset if dataset else '[Table, index, or data source]' }} |
| **Features**    | {{ features if features else '[Fields/dimensions fed into the model]' }} |
| **Time Range**  | [Date range — recommend ≥30 days for stable baselines] |
| **Location**    | [Systems, networks, or environments in scope] |
| **Evidence**    | [Data source(s) and key fields] |

### Related Context

[Why model-assisted over manual EDA? Precursor baseline hunt? Volume too high for COUNT-FIRST approach?]

---

## OBSERVE: Model Design

### Model Type & Rationale

**Chosen approach:** {{ model_type if model_type else '[Model type]' }}

[Why this model type for this data? Clustering for unknown groupings? Z-score/IQR for univariate outliers? Isolation Forest for high-dimensional sparse anomalies?]

### Feature Selection Rationale

[Why these fields? What signal do they carry for adversary behavior? What noise might they introduce?]

### Tuning Parameters

| **Parameter**          | **Value** | **Rationale** |
|------------------------|-----------|---------------|
| Anomaly threshold      | {{ anomaly_threshold if anomaly_threshold else '[value]' }} | [Why this cutoff?] |
| [Algorithm parameter]  | [value]   | [Rationale] |

### Expected Anomaly Profile

[What would a true positive look like in the model output? What false positive patterns are anticipated?]

---

## CHECK: Run & Interpret

### Data Source Information

- **Index/Data Source:** {{ data_sources_list[0] if data_sources_list else '[SIEM index or data source]' }}
- **Time Range:** [Date range for model run]
- **Events Analyzed:** [Approximate count]
- **Data Quality:** [Assessment of data completeness and field population rates]

### Model Queries / Code

#### Feature Extraction Query

```
[Query to extract feature vectors from the data source]
```

#### Anomaly Scoring

```
[Model run code or query — e.g., SQL window functions for z-score, Python snippet for isolation forest]
```

**Notes:**
- [What did the model return? Score distribution?]
- [Threshold tuning observations]

### Results: Anomalies Surfaced

[Summary of model output — score distribution, anomaly count above threshold, notable clusters or outliers]

---

## KEEP: Candidate Leads & Follow-up

### Candidate Leads

| **Entity** | **Anomaly Score** | **Description** | **Worth a Hypothesis Hunt?** |
|------------|-------------------|-----------------|-------------------------------|
| [Entity]   | [score]           | [What made it anomalous] | [Yes/No/Maybe] |

**Candidate Leads Found:** 0

### Model Parameters to Reuse

[Feature set, threshold, and algorithm settings that produced useful signal — reference for re-runs or related hunts]

### Spawned Hunts

[Hunt IDs created from anomaly leads — keep related_hunts in frontmatter in sync]

### Lessons Learned

**What Worked Well:**
- [Effective features, thresholds, or approaches]

**What Could Be Improved:**
- [Noise sources, missing features, data quality issues]

**Telemetry Gaps Identified:**
- [Missing fields that would improve model signal]

---

**Model Run Completed:** [Date]
**Next Re-run:** [Date — model-assisted hunts often benefit from periodic re-runs as baselines shift]
"""


def _load_math_template() -> str:
    """Load model-assisted hunt template, preferring workspace custom template over bundled default.

    Checks for a Jinja2 template at ./templates/MATH_TEMPLATE.j2 first.
    Falls back to the bundled MATH_TEMPLATE constant.

    Returns:
        Jinja2 template string
    """
    custom_template = Path("templates") / "MATH_TEMPLATE.j2"
    if custom_template.exists():
        try:
            content = custom_template.read_text(encoding="utf-8")
            if "{{" in content and "}}" in content:
                return content
        except (OSError, UnicodeDecodeError):
            pass
    return MATH_TEMPLATE


def render_math_template(
    hunt_id: str,
    title: str,
    model_type: Optional[str] = None,
    features: Optional[list] = None,
    anomaly_threshold: Optional[str] = None,
    dataset: Optional[str] = None,
    platform: Optional[list] = None,
    data_sources: Optional[list] = None,
    hunter: str = "[Your Name]",
    objective: Optional[str] = None,
) -> str:
    """Render a model-assisted (M-ATH) hunt template with provided metadata.

    Args:
        hunt_id: Hunt identifier (e.g., H-0001)
        title: Hunt title
        model_type: Statistical/ML model type (clustering, z-score, IQR, isolation-forest, other)
        features: List of fields/dimensions fed into the model
        anomaly_threshold: Anomaly score cutoff value
        dataset: Table, index, or data source being modeled
        platform: List of platforms (Windows, Linux, macOS, Cloud)
        data_sources: List of data sources
        hunter: Hunter name
        objective: Why model-assisted over manual EDA

    Returns:
        Rendered model-assisted hunt markdown content
    """
    platform_str = f"[{', '.join(platform)}]" if platform else "[]"
    data_sources_str = f"[{', '.join(data_sources)}]" if data_sources else "[]"
    features_str = f"[{', '.join(features)}]" if features else "[]"
    tags_str = "[model-assisted]"

    template = Template(_load_math_template())

    result: str = template.render(
        hunt_id=hunt_id,
        title=title,
        status="planning",
        date=datetime.now().strftime("%Y-%m-%d"),
        hunter=hunter,
        platform=platform_str,
        data_sources=data_sources_str,
        data_sources_list=data_sources,
        tags=tags_str,
        model_type=model_type,
        features=features_str,
        anomaly_threshold=anomaly_threshold,
        dataset=dataset,
        objective=objective,
    )
    return result


def _load_baseline_template() -> str:
    """Load baseline hunt template, preferring workspace custom template over bundled default.

    Checks for a Jinja2 template at ./templates/BASELINE_TEMPLATE.j2 first.
    Falls back to the bundled BASELINE_TEMPLATE constant.

    Returns:
        Jinja2 template string
    """
    custom_template = Path("templates") / "BASELINE_TEMPLATE.j2"
    if custom_template.exists():
        try:
            content = custom_template.read_text(encoding="utf-8")
            if "{{" in content and "}}" in content:
                return content
        except (OSError, UnicodeDecodeError):
            pass  # Fall through to default
    return BASELINE_TEMPLATE


def render_baseline_template(
    hunt_id: str,
    title: str,
    dimension: Optional[str] = None,
    platform: Optional[list] = None,
    data_sources: Optional[list] = None,
    hunter: str = "[Your Name]",
    objective: Optional[str] = None,
) -> str:
    """Render a baseline (EDA) hunt template with provided metadata.

    Args:
        hunt_id: Hunt identifier (e.g., H-0001)
        title: Baseline hunt title
        dimension: Field or behavior being characterized (e.g., "parent-child process pairs")
        platform: List of platforms (Windows, Linux, macOS, Cloud)
        data_sources: List of data sources
        hunter: Hunter name
        objective: Why this baseline matters / what it's establishing

    Returns:
        Rendered baseline hunt markdown content
    """
    platform_str = f"[{', '.join(platform)}]" if platform else "[]"
    data_sources_str = f"[{', '.join(data_sources)}]" if data_sources else "[]"
    tags_str = "[baseline]"

    template = Template(_load_baseline_template())

    result: str = template.render(
        hunt_id=hunt_id,
        title=title,
        status="planning",
        date=datetime.now().strftime("%Y-%m-%d"),
        hunter=hunter,
        platform=platform_str,
        data_sources=data_sources_str,
        data_sources_list=data_sources,
        tags=tags_str,
        dimension=dimension,
        objective=objective,
    )
    return result


def _load_hunt_template() -> str:
    """Load hunt template, preferring workspace custom template over bundled default.

    Checks for a Jinja2 template at ./templates/HUNT_TEMPLATE.j2 first.
    Falls back to the bundled HUNT_TEMPLATE constant.

    Returns:
        Jinja2 template string
    """
    custom_template = Path("templates") / "HUNT_TEMPLATE.j2"
    if custom_template.exists():
        try:
            content = custom_template.read_text(encoding="utf-8")
            # Basic sanity check: must contain Jinja2 syntax
            if "{{" in content and "}}" in content:
                return content
        except (OSError, UnicodeDecodeError):
            pass  # Fall through to default
    return HUNT_TEMPLATE


def render_hunt_template(
    hunt_id: str,
    title: str,
    technique: Optional[str] = None,
    tactics: Optional[list] = None,
    platform: Optional[list] = None,
    data_sources: Optional[list] = None,
    hunter: str = "[Your Name]",
    hypothesis: Optional[str] = None,
    threat_context: Optional[str] = None,
    actor: Optional[str] = None,
    behavior: Optional[str] = None,
    location: Optional[str] = None,
    evidence: Optional[str] = None,
    spawned_from: Optional[str] = None,
    hypothesis_duration_minutes: Optional[float] = None,
) -> str:
    """Render a hunt template with provided metadata.

    Args:
        hunt_id: Hunt identifier (e.g., H-0001)
        title: Hunt title
        technique: Primary MITRE technique (e.g., T1003.001)
        tactics: List of MITRE tactics
        platform: List of platforms (Windows, Linux, macOS, Cloud)
        data_sources: List of data sources
        hunter: Hunter name
        hypothesis: Hypothesis statement
        threat_context: Threat context description
        actor: Threat actor (for ABLE)
        behavior: Behavior description (for ABLE)
        location: Location/scope (for ABLE)
        evidence: Evidence description (for ABLE)
        spawned_from: Research document ID (e.g., R-0001) that this hunt is based on
        hypothesis_duration_minutes: Time spent generating hypothesis (from athf agent run)

    Returns:
        Rendered hunt markdown content
    """
    # Build techniques list
    techniques_list = [technique] if technique else []

    # Format lists as YAML arrays
    tactics_str = f"[{', '.join(tactics)}]" if tactics else "[]"
    platform_str = f"[{', '.join(platform)}]" if platform else "[]"
    data_sources_str = f"[{', '.join(data_sources)}]" if data_sources else "[]"
    tags_str = "[]"

    template = Template(_load_hunt_template())

    result: str = template.render(
        hunt_id=hunt_id,
        title=title,
        status="planning",
        date=datetime.now().strftime("%Y-%m-%d"),
        hunter=hunter,
        platform=platform_str,
        tactics=tactics_str,
        techniques=techniques_list,
        data_sources=data_sources_str,
        data_sources_list=data_sources,
        tags=tags_str,
        hypothesis=hypothesis,
        threat_context=threat_context,
        actor=actor,
        behavior=behavior,
        location=location,
        evidence=evidence,
        spawned_from=spawned_from,
        hypothesis_duration_minutes=hypothesis_duration_minutes,
    )
    return result
