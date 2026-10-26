"""Multi-target EDR and SIEM Sigma query transpilation engine.

Transpiles vendor-agnostic Sigma rules (YAML) into native, copy-paste and
deployment-ready search queries for major enterprise EDRs and SIEMs:
- Microsoft Defender for Endpoint (MDE) / Microsoft Sentinel (KQL)
- CrowdStrike Falcon (LogScale / Raptor / FDR) (CQL)
- Rapid7 InsightIDR (Log Entry Query Language - LEQL)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, ClassVar, Dict, List, Optional

import yaml

try:
    from sigma.backends.crowdstrike import LogScaleBackend
    from sigma.backends.kusto import KustoBackend
    from sigma.collection import SigmaCollection
    from sigma.conversion.base import TextQueryBackend
    from sigma.conversion.state import ConversionState
    from sigma.pipelines.crowdstrike import crowdstrike_fdr_pipeline
    from sigma.pipelines.microsoft365defender import microsoft_365_defender_pipeline
    from sigma.processing.conditions import IncludeFieldCondition, LogsourceCondition
    from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
    from sigma.processing.transformations import FieldMappingTransformation
    from sigma.rule import SigmaRule

    PYSIGMA_AVAILABLE = True
except ImportError:
    PYSIGMA_AVAILABLE = False
    LogScaleBackend = None  # type: ignore
    KustoBackend = None  # type: ignore
    SigmaCollection = None  # type: ignore
    TextQueryBackend = object  # type: ignore
    ConversionState = Any  # type: ignore
    SigmaRule = Any  # type: ignore
    ProcessingPipeline = Any  # type: ignore
    ProcessingItem = Any  # type: ignore
    FieldMappingTransformation = Any  # type: ignore
    LogsourceCondition = Any  # type: ignore
    IncludeFieldCondition = Any  # type: ignore

logger = logging.getLogger(__name__)


def build_insight_idr_pipeline() -> Optional[Any]:
    """Build a comprehensive, modern pySigma processing pipeline for Rapid7 InsightIDR LEQL."""
    if not PYSIGMA_AVAILABLE:
        return None
    return ProcessingPipeline(
        items=[
            ProcessingItem(
                transformation=FieldMappingTransformation(
                    {
                        "ProcessId": "process.pid",
                        "Image": "process.exe_path",
                        "OriginalFileName": "process.name",
                        "CommandLine": "process.cmd_line",
                        "CurrentDirectory": "process.working_directory",
                        "User": "process.username",
                        "ParentProcessId": "parent_process.pid",
                        "ParentImage": "parent_process.exe_path",
                        "ParentCommandLine": "parent_process.cmd_line",
                        "ParentUser": "parent_process.username",
                        "TargetFilename": "file.path",
                        "DestinationIp": "destination_address",
                        "DestinationPort": "destination_port",
                        "SourceIp": "source_address",
                        "SourcePort": "source_port",
                        "QueryName": "query",
                        "QueryResults": "query_results",
                        "TargetObject": "registry.key",
                        "Details": "registry.value",
                        "TargetUserName": "account",
                        "SubjectUserName": "account",
                        "WorkstationName": "source_asset",
                        "cs-method": "http_method",
                        "cs-uri-stem": "uri_path",
                        "cs-uri-query": "uri_query",
                        "c-useragent": "user_agent",
                        "sc-status": "http_status",
                    }
                )
            )
        ]
    )


class InsightIDRBackend(TextQueryBackend):
    """Native Rapid7 InsightIDR Log Entry Query Language (LEQL) Backend."""

    name: ClassVar[str] = "Rapid7 InsightIDR LEQL"
    formats: ClassVar[Dict[str, str]] = {
        "default": "where(query)",
        "leql_advanced_search": "Advanced Log Entry Query Language (LEQL) queries",
    }
    requires_pipeline: ClassVar[bool] = False

    group_expression: ClassVar[str] = "({expr})"
    or_token: ClassVar[str] = "OR"
    and_token: ClassVar[str] = "AND"
    not_token: ClassVar[str] = "NOT"
    eq_token: ClassVar[str] = "="
    icontains_token: ClassVar[str] = "ICONTAINS"
    istarts_with_token: ClassVar[str] = "ISTARTS-WITH"
    str_double_quote: ClassVar[str] = '"'
    wildcard_multi: ClassVar[str] = "*"
    wildcard_single: ClassVar[str] = "*"
    re_expression: ClassVar[str] = "{field}=/{regex}/i"
    re_escape_char: ClassVar[str] = "\\"
    re_escape: ClassVar[List[str]] = ["/"]

    def __init__(self, processing_pipeline: Optional[Any] = None):
        if processing_pipeline is None and PYSIGMA_AVAILABLE:
            processing_pipeline = build_insight_idr_pipeline()
        super().__init__(processing_pipeline=processing_pipeline)

    def finalize_query_default(self, rule: Any, query: str, index: int, state: Any) -> str:
        return f"where({query})"

    def finalize_query_leql_advanced_search(self, rule: Any, query: str, index: int, state: Any) -> str:
        return f"where({query})"


@dataclass
class TranspiledQuery:
    """A transpiled search query for a specific EDR or SIEM platform."""

    target: str
    platform_name: str
    dialect: str
    file_extension: str
    query: Optional[str]
    success: bool
    error_message: Optional[str] = None


class SigmaTranspiler:
    """Multi-target query transpiler for Sigma detection rules."""

    TARGET_MDE = "sentinel_kql"
    TARGET_CROWDSTRIKE = "crowdstrike_cql"
    TARGET_RAPID7 = "rapid7_leql"

    SUPPORTED_TARGETS = [
        TARGET_MDE,
        TARGET_CROWDSTRIKE,
        TARGET_RAPID7,
    ]

    TARGET_METADATA = {
        TARGET_MDE: {
            "name": "Microsoft Defender / Microsoft Sentinel",
            "dialect": "kql",
            "extension": ".kql",
        },
        TARGET_CROWDSTRIKE: {
            "name": "CrowdStrike Falcon (LogScale / Raptor)",
            "dialect": "cql",
            "extension": ".cql",
        },
        TARGET_RAPID7: {
            "name": "Rapid7 InsightIDR",
            "dialect": "leql",
            "extension": ".leql",
        },
    }

    def __init__(self) -> None:
        if not PYSIGMA_AVAILABLE:
            logger.warning("pySigma and required backends not installed; transpilation will fail open.")

    @classmethod
    def normalize_rule_for_backends(cls, rule_yaml: str) -> str:
        """Alias for backward-compatible logsource normalization without target."""
        return cls.normalize_rule_for_backend(rule_yaml, target="")

    @classmethod
    def normalize_rule_for_backend(cls, rule_yaml: str, target: str = "") -> str:
        """Ensure standard logsource and field mappings are aligned with vendor pipelines."""
        try:
            parsed = yaml.safe_load(rule_yaml)
            if not isinstance(parsed, dict):
                return rule_yaml

            logsource = parsed.get("logsource", {})
            if not isinstance(logsource, dict):
                return rule_yaml

            category = logsource.get("category", "")
            product = logsource.get("product")
            service = logsource.get("service")

            # General Windows normalization for endpoint events
            if not product and not service:
                endpoint_cats = {
                    "process_creation",
                    "file_event",
                    "image_load",
                    "registry_event",
                    "network_connection",
                    "dns_query",
                }
                detection_str = str(parsed.get("detection", ""))
                if category in endpoint_cats or "\\" in detection_str or ".exe" in detection_str.lower():
                    logsource["product"] = "windows"
                    parsed["logsource"] = logsource

            return yaml.dump(parsed, sort_keys=False)
        except Exception:
            return rule_yaml

    def transpile(
        self,
        rule_yaml: str,
        targets: Optional[List[str]] = None,
    ) -> Dict[str, TranspiledQuery]:
        """Transpile a Sigma rule YAML string to multiple target EDR/SIEM query dialects.

        Args:
            rule_yaml: The canonical Sigma rule in YAML string format.
            targets: List of target identifiers to generate (defaults to all supported).

        Returns:
            Dictionary mapping target ID to TranspiledQuery instance.
        """
        if targets is None:
            targets = list(self.SUPPORTED_TARGETS)

        results: Dict[str, TranspiledQuery] = {}

        if not PYSIGMA_AVAILABLE:
            for target in targets:
                meta = self.TARGET_METADATA.get(target, {"name": target, "dialect": "txt", "extension": ".txt"})
                results[target] = TranspiledQuery(
                    target=target,
                    platform_name=meta["name"],
                    dialect=meta["dialect"],
                    file_extension=meta["extension"],
                    query=None,
                    success=False,
                    error_message="pySigma or backend packages not available in environment",
                )
            return results

        for target in targets:
            meta = self.TARGET_METADATA.get(target, {"name": target, "dialect": "txt", "extension": ".txt"})
            normalized_yaml = self.normalize_rule_for_backend(rule_yaml, target)
            try:
                query = self._transpile_single_target(normalized_yaml, target)
                results[target] = TranspiledQuery(
                    target=target,
                    platform_name=meta["name"],
                    dialect=meta["dialect"],
                    file_extension=meta["extension"],
                    query=query,
                    success=True,
                )
            except Exception as exc:
                logger.debug("Transpilation failed for target %s: %s", target, exc)
                results[target] = TranspiledQuery(
                    target=target,
                    platform_name=meta["name"],
                    dialect=meta["dialect"],
                    file_extension=meta["extension"],
                    query=None,
                    success=False,
                    error_message=str(exc),
                )

        return results

    def _transpile_single_target(self, rule_yaml: str, target: str) -> str:
        """Internal helper to convert a Sigma rule for a specific backend."""
        # Always parse a fresh collection to avoid in-place pipeline AST mutation
        col = SigmaCollection.from_yaml(rule_yaml)

        if target == self.TARGET_MDE:
            pipeline = microsoft_365_defender_pipeline()
            kusto_backend: Any = KustoBackend(processing_pipeline=pipeline)  # type: ignore[arg-type]
            queries = kusto_backend.convert(col)
            if not queries:
                raise ValueError("No query returned from Kusto/MDE backend")
            return "\n\n".join(queries)

        if target == self.TARGET_CROWDSTRIKE:
            cs_pipeline = crowdstrike_fdr_pipeline()
            cs_backend: Any = LogScaleBackend(processing_pipeline=cs_pipeline)
            queries = cs_backend.convert(col)
            if not queries:
                raise ValueError("No query returned from CrowdStrike backend")
            return "\n\n".join(queries)

        if target == self.TARGET_RAPID7:
            idr_backend: Any = InsightIDRBackend()
            queries = idr_backend.convert(col)
            if not queries:
                raise ValueError("No query returned from Rapid7 InsightIDR backend")
            return "\n\n".join(queries)

        raise ValueError(f"Unsupported transpilation target: {target}")

    def format_markdown_queries(
        self,
        results: Dict[str, TranspiledQuery],
        include_heading: bool = True,
    ) -> str:
        """Format transpiled queries into readable GitHub markdown code blocks."""
        lines = []
        if include_heading:
            lines.append("##### Native EDR & SIEM Queries")
            lines.append("")

        for target in self.SUPPORTED_TARGETS:
            res = results.get(target)
            if not res:
                continue

            lines.append(f"**{res.platform_name} ({res.dialect.upper()}):**")
            if res.success and res.query:
                code_lang = "kql" if res.dialect == "kql" else ("text" if res.dialect == "leql" else res.dialect)
                lines.append(f"```{code_lang}")
                lines.append(res.query.strip())
                lines.append("```")
            else:
                lines.append(f"> *Query conversion unavailable: {res.error_message or 'unsupported log source'}*")
            lines.append("")

        return "\n".join(lines).strip()
