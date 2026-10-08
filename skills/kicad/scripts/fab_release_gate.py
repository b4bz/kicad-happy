#!/usr/bin/env python3
"""
Fabrication release gate for KiCad designs.

"Ready for fab?" check that consumes existing analyzer JSON outputs and
produces a structured pass/fail gate with categorized checks.

Usage:
    python3 fab_release_gate.py --schematic sch.json --pcb pcb.json
    python3 fab_release_gate.py --schematic sch.json --pcb pcb.json --gerbers gerbers.json
    python3 fab_release_gate.py --schematic sch.json --pcb pcb.json --text
    python3 fab_release_gate.py --schematic sch.json --pcb pcb.json --strict

Zero external dependencies — Python 3.8+ stdlib only.
"""

import argparse
import json
import math
import sys
import time
from typing import Any, Dict, List, Optional

from finding_schema import normalize_severity


GATE_VERSION = "1.1-local"


# ---------------------------------------------------------------------------
# Check result structure
# ---------------------------------------------------------------------------

def _check(category: str, check_id: str, status: str, message: str,
           details: Optional[Dict] = None) -> Dict[str, Any]:
    """Build a gate check result."""
    return {
        "category": category,
        "check_id": check_id,
        "status": status,  # pass, warn, fail, skip
        "message": message,
        "details": details,
    }


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------

def check_routing(pcb: Dict) -> List[Dict]:
    """Check PCB routing completeness."""
    conn = pcb.get("connectivity", {})
    total = conn.get("total_nets_with_pads", 0)
    unrouted = conn.get("unrouted_count", 0)
    complete = conn.get("routing_complete", False)

    if complete and unrouted == 0:
        return [_check("routing", "routing_completeness", "pass",
                        f"All nets routed ({total}/{total})")]

    unrouted_list = [u.get("net_name", "?")
                     for u in conn.get("unrouted", [])[:10]]
    return [_check("routing", "routing_completeness", "fail",
                    f"{unrouted} unrouted net(s) out of {total}",
                    {"unrouted_count": unrouted, "unrouted_nets": unrouted_list})]


def check_bom(sch: Dict) -> List[Dict]:
    """Check BOM completeness — MPNs and footprints."""
    checks = []
    stats = sch.get("statistics", {})
    sourcing = sch.get("sourcing_audit", {})

    # MPN coverage
    missing_mpn = (sourcing.get("missing_mpn", [])
                   or stats.get("missing_mpn", []))
    total = stats.get("total_components", 0)

    if not missing_mpn:
        coverage = sourcing.get("mpn_coverage", f"{total}/{total}")
        checks.append(_check("bom", "mpn_coverage", "pass",
                              f"All components have MPNs ({coverage})"))
    else:
        checks.append(_check("bom", "mpn_coverage", "fail",
                              f"{len(missing_mpn)} component(s) missing MPN",
                              {"missing_mpn": missing_mpn[:20],
                               "coverage": sourcing.get("mpn_coverage", "?")}))

    # Footprint assignment
    missing_fp = stats.get("missing_footprint", [])
    if not missing_fp:
        checks.append(_check("bom", "footprint_assignment", "pass",
                              "All components have footprints assigned"))
    else:
        checks.append(_check("bom", "footprint_assignment", "fail",
                              f"{len(missing_fp)} component(s) missing footprint",
                              {"missing_footprint": missing_fp[:20]}))

    return checks


def check_dfm(pcb: Dict) -> List[Dict]:
    """Check DFM tier and violations."""
    # dfm_summary holds tier/metrics; violations are in findings[]
    dfm = pcb.get("dfm_summary", {})
    tier = dfm.get("dfm_tier", "unknown")
    violations = [f for f in pcb.get("findings", [])
                  if isinstance(f, dict) and f.get("category") == "dfm"]

    if tier == "standard" and not violations:
        return [_check("dfm", "fab_capability", "pass",
                        "Design within standard fab capability")]
    elif tier == "advanced":
        v_summary = [{"parameter": v.get("parameter", v.get("rule_id", "?")),
                       "actual_mm": v.get("actual_mm"),
                       "limit_mm": v.get("standard_limit_mm")}
                      for v in violations[:5]]
        return [_check("dfm", "fab_capability", "warn",
                        f"Design requires advanced process tier ({len(violations)} violation(s))",
                        {"dfm_tier": tier, "violations": v_summary})]
    elif tier in ("challenging", "extreme"):
        v_summary = [{"parameter": v.get("parameter", v.get("rule_id", "?")),
                       "actual_mm": v.get("actual_mm"),
                       "limit_mm": v.get("advanced_limit_mm")}
                      for v in violations[:5]]
        return [_check("dfm", "fab_capability", "fail",
                        f"Design requires {tier} process — verify fab house capability",
                        {"dfm_tier": tier, "violations": v_summary})]
    else:
        return [_check("dfm", "fab_capability", "skip",
                        f"No recognized passing DFM assessment (tier: {tier})")]


def check_documentation(pcb: Dict) -> List[Dict]:
    """Check board documentation (revision, board name)."""
    checks = []
    silk = pcb.get("silkscreen", {})
    doc_warnings = silk.get("documentation_warnings", [])

    # Revision
    has_rev_warning = any(w.get("type") == "missing_revision"
                          for w in doc_warnings)
    if has_rev_warning:
        checks.append(_check("documentation", "revision_marking", "warn",
                              "No revision marking found on silkscreen"))
    else:
        checks.append(_check("documentation", "revision_marking", "pass",
                              "Revision marking found"))

    # Board name
    has_name_warning = any(w.get("type") == "missing_board_name"
                           for w in doc_warnings)
    if has_name_warning:
        checks.append(_check("documentation", "board_name", "warn",
                              "No board name found on silkscreen"))
    else:
        checks.append(_check("documentation", "board_name", "pass",
                              "Board name found on silkscreen"))

    return checks


def check_consistency(sch: Dict, pcb: Dict) -> List[Dict]:
    """Check schematic ↔ PCB consistency."""
    checks = []
    sch_stats = sch.get("statistics", {})
    pcb_stats = pcb.get("statistics", {})

    # Component count comparison
    # Schematic count: total minus power symbols, test points, mounting holes, DNP
    sch_total = sch_stats.get("total_components", 0)
    types = sch_stats.get("component_types", {})
    # These are already excluded from total_components in the schematic analyzer
    # (power_symbol, power_flag, flag are filtered out). DNP parts are counted
    # separately but included in total.
    dnp = sch_stats.get("dnp_parts", 0)
    sch_placeable = sch_total - dnp

    pcb_fp = pcb_stats.get("footprint_count",
                            len(pcb.get("footprints", [])))

    comp_diff = abs(sch_placeable - pcb_fp)
    pct_diff = (comp_diff / max(sch_placeable, 1)) * 100

    if comp_diff == 0:
        checks.append(_check("consistency", "component_count", "pass",
                              f"Schematic ({sch_placeable} placeable) matches "
                              f"PCB ({pcb_fp} footprints)"))
    elif comp_diff <= 3 or pct_diff <= 5:
        checks.append(_check("consistency", "component_count", "warn",
                              f"Small component count gap: schematic {sch_placeable} "
                              f"vs PCB {pcb_fp} (diff {comp_diff})",
                              {"schematic_placeable": sch_placeable,
                               "pcb_footprints": pcb_fp, "difference": comp_diff}))
    else:
        checks.append(_check("consistency", "component_count", "fail",
                              f"Component count mismatch: schematic {sch_placeable} "
                              f"vs PCB {pcb_fp} (diff {comp_diff}, {pct_diff:.0f}%)",
                              {"schematic_placeable": sch_placeable,
                               "pcb_footprints": pcb_fp, "difference": comp_diff}))

    # Net count comparison
    sch_nets = sch_stats.get("total_nets", 0)
    pcb_nets = pcb_stats.get("net_count",
                              pcb.get("connectivity", {}).get("total_nets_with_pads", 0))

    net_diff = abs(sch_nets - pcb_nets)
    if net_diff == 0:
        checks.append(_check("consistency", "net_count", "pass",
                              f"Net counts match ({sch_nets})"))
    elif net_diff <= 5:
        checks.append(_check("consistency", "net_count", "warn",
                              f"Small net count gap: schematic {sch_nets} "
                              f"vs PCB {pcb_nets} (diff {net_diff})",
                              {"schematic_nets": sch_nets, "pcb_nets": pcb_nets}))
    else:
        checks.append(_check("consistency", "net_count", "fail",
                              f"Net count mismatch: schematic {sch_nets} "
                              f"vs PCB {pcb_nets} (diff {net_diff})",
                              {"schematic_nets": sch_nets, "pcb_nets": pcb_nets}))

    return checks


def check_gerbers(gerber_data: Optional[Dict]) -> List[Dict]:
    """Check Gerber layer completeness and alignment."""
    if not gerber_data:
        return [_check("gerbers", "layer_completeness", "skip",
                        "Gerber analysis not provided"),
                _check("gerbers", "layer_alignment", "skip",
                        "Gerber analysis not provided")]

    checks = []

    # Layer completeness
    completeness = gerber_data.get("completeness", {})
    # Current Gerber analyzer uses missing_required/missing_recommended or
    # missing (gbrjob). Never interpret a missing legacy field as no defects.
    missing = (completeness.get("missing_required", [])
               + completeness.get("missing_recommended", [])
               + completeness.get("missing", [])
               + completeness.get("missing_layers", []))
    critical_missing = [l for l in missing
                        if any(k in l.upper() for k in
                               ("F.CU", "B.CU", "EDGE", "F.MASK", "B.MASK",
                                "FRONT_COPPER", "BACK_COPPER", "BOARD_OUTLINE",
                                "FRONT_SOLDERMASK", "BACK_SOLDERMASK"))]
    silk_missing = [l for l in missing
                    if any(k in l.upper() for k in ("SILK", "LEGEND"))]

    if not completeness["complete"]:
        checks.append(_check("gerbers", "layer_completeness", "fail",
                              "Gerber/drill completeness assessment failed",
                              {"missing_layers": missing}))
    elif not missing:
        checks.append(_check("gerbers", "layer_completeness", "pass",
                              "All expected layers present"))
    elif critical_missing:
        checks.append(_check("gerbers", "layer_completeness", "fail",
                              f"Critical layers missing: {', '.join(critical_missing)}",
                              {"missing_layers": missing}))
    elif silk_missing:
        checks.append(_check("gerbers", "layer_completeness", "warn",
                              f"Non-critical layers missing: {', '.join(silk_missing)}",
                              {"missing_layers": missing}))
    else:
        checks.append(_check("gerbers", "layer_completeness", "warn",
                              f"Some layers missing: {', '.join(missing[:5])}",
                              {"missing_layers": missing}))

    # Alignment
    alignment = gerber_data.get("alignment", {})
    aligned = alignment["aligned"]
    if aligned:
        checks.append(_check("gerbers", "layer_alignment", "pass",
                              "Layer coordinate ranges consistent"))
    else:
        checks.append(_check("gerbers", "layer_alignment", "fail",
                              "Layer alignment issue detected — coordinate ranges inconsistent",
                              {"alignment": alignment}))

    return checks


def check_thermal(thermal_data: Optional[Dict]) -> List[Dict]:
    """Check for critical thermal findings."""
    if not thermal_data:
        return [_check("thermal", "thermal_risk", "skip",
                        "Thermal analysis not provided")]

    findings = thermal_data.get("findings", [])
    active = [f for f in findings if not f.get("suppressed")]
    # Accept both v1.4 (error/warning/info) and legacy (CRITICAL/HIGH/MEDIUM/LOW)
    # severities so cached pre-v1.4 thermal outputs still gate correctly.
    errors = [f for f in active if normalize_severity(f.get("severity")) == "error"]
    warnings = [f for f in active if normalize_severity(f.get("severity")) == "warning"]

    if errors:
        refs = [f.get("components", ["?"])[0] for f in errors[:3]]
        return [_check("thermal", "thermal_risk", "fail",
                        f"{len(errors)} error-severity thermal finding(s): {', '.join(refs)}",
                        {"error_count": len(errors), "warning_count": len(warnings)})]
    elif warnings:
        return [_check("thermal", "thermal_risk", "warn",
                        f"{len(warnings)} warning-severity thermal finding(s)",
                        {"warning_count": len(warnings)})]
    else:
        score = thermal_data.get("summary", {}).get("thermal_score", "?")
        return [_check("thermal", "thermal_risk", "pass",
                        f"Thermal score {score}/100 — no critical/high findings")]


def check_emc(emc_data: Optional[Dict]) -> List[Dict]:
    """Check EMC risk (advisory only — never FAIL)."""
    if not emc_data:
        return [_check("emc", "emc_risk", "skip",
                        "EMC analysis not provided")]

    summary = emc_data.get("summary", {})
    score = summary.get("emc_risk_score", 0)
    active = [f for f in emc_data.get("findings", []) if not f.get("suppressed")]
    crits = max(summary.get("critical", 0),
                summary.get("by_severity", {}).get("error", 0),
                sum(normalize_severity(f.get("severity")) == "error" for f in active))
    warnings = sum(normalize_severity(f.get("severity")) == "warning" for f in active)

    if crits > 0 or warnings > 0:
        return [_check("emc", "emc_risk", "warn",
                        f"EMC score {score}/100 — {crits} error, {warnings} warning finding(s) (advisory)",
                        {"emc_risk_score": score, "critical": crits, "warnings": warnings})]
    else:
        return [_check("emc", "emc_risk", "pass",
                        f"EMC score {score}/100 — no critical findings")]


def _compute_trust_posture(sch, pcb, thermal_data, emc_data):
    """Aggregate trust_summary from all analyzer inputs into a gate posture.

    Returns a dict with overall trust_level, per-analyzer breakdown,
    aggregate confidence counts, and evidence blockers.
    """
    sources = []
    if sch:
        sources.append(('schematic', sch.get('trust_summary')))
    if pcb:
        sources.append(('pcb', pcb.get('trust_summary')))
    if thermal_data:
        sources.append(('thermal', thermal_data.get('trust_summary')))
    if emc_data:
        sources.append(('emc', emc_data.get('trust_summary')))

    sources = [(name, ts) for name, ts in sources if ts]
    if not sources:
        return None

    total = 0
    det = 0
    heu = 0
    ds_backed = 0
    unknown = 0
    for _, ts in sources:
        total += ts.get('total_findings', 0)
        bc = ts.get('by_confidence', {})
        det += bc.get('deterministic', 0)
        heu += bc.get('heuristic', 0)
        ds_backed += bc.get('datasheet_backed', 0)
        unknown += ts.get('unknown_confidence', 0)

    levels = [ts.get('trust_level', 'high') for _, ts in sources]
    if 'low' in levels:
        overall = 'low'
    elif 'mixed' in levels:
        overall = 'mixed'
    else:
        overall = 'high'

    blockers = []
    if unknown > 0:
        blockers.append(f"{unknown} findings with unknown confidence")
    if sch:
        bom_cov = (sch.get('trust_summary') or {}).get('bom_coverage')
        if bom_cov and bom_cov.get('mpn_pct', 100) < 50:
            blockers.append(f"Low MPN coverage ({bom_cov['mpn_pct']:.0f}%)")

    prov_values = [ts.get('provenance_coverage_pct', 0) for _, ts in sources
                   if ts.get('total_findings', 0) > 0]
    avg_prov = round(sum(prov_values) / len(prov_values), 1) if prov_values else 0.0

    posture = {
        'trust_level': overall,
        'total_findings': total,
        'by_confidence': {
            'deterministic': det,
            'heuristic': heu,
            'datasheet_backed': ds_backed,
        },
        'provenance_coverage_pct': avg_prov,
        'per_analyzer': {name: ts.get('trust_level', '?') for name, ts in sources},
    }
    if unknown:
        posture['unknown_confidence'] = unknown
    if blockers:
        posture['evidence_blockers'] = blockers

    return posture


def _integer(value):
    return type(value) is int and value >= 0


def _score(value):
    return (type(value) in (int, float) and math.isfinite(value)
            and 0 <= value <= 100)


def _findings(value):
    return isinstance(value, list) and all(isinstance(item, dict) for item in value)


def _issues(value):
    return _findings(value) and all(
        isinstance(item.get("severity"), str)
        and item["severity"].upper() in {
            "ERROR", "WARNING", "INFO", "CRITICAL", "HIGH", "MEDIUM", "LOW",
        } for item in value
    )


def _strings(value):
    return isinstance(value, list) and all(isinstance(item, str) for item in value)


def _input_evidence(name, data, fields):
    """Check the facts consumed by this gate, without inventing defaults.

    This is intentionally not full analyzer-schema validation or CAD verification.
    Missing/malformed evidence is a skipped check and blocks a passing verdict.
    """
    missing = []
    for path, predicate in fields.items():
        value = data
        for key in path.split("."):
            value = value.get(key) if isinstance(value, dict) else None
        if not predicate(value):
            missing.append(path)
    if missing:
        return _check("evidence", name + "_inputs", "skip",
                      f"{name}: missing or malformed release evidence",
                      {"fields": missing})
    return _check("evidence", name + "_inputs", "pass",
                  f"{name}: required gate fields present")


def _analysis_findings(name, data):
    """Do not let known errors disappear behind aggregate release metrics."""
    active = [f for f in data.get("findings", []) if not f.get("suppressed")]
    errors = [f for f in active if normalize_severity(f.get("severity")) == "error"]
    warnings = [f for f in active if normalize_severity(f.get("severity")) == "warning"]
    return _check("evidence", name + "_findings",
                  "fail" if errors else "warn" if warnings else "pass",
                  f"{name}: {len(errors)} error, {len(warnings)} warning finding(s)")


# ---------------------------------------------------------------------------
# Gate orchestrator
# ---------------------------------------------------------------------------

def run_gate(sch: Dict, pcb: Dict,
             gerber_data: Optional[Dict] = None,
             thermal_data: Optional[Dict] = None,
             emc_data: Optional[Dict] = None,
             strict: bool = False,
             ) -> Dict[str, Any]:
    """Run all gate checks and compute overall status."""
    t0 = time.monotonic()

    all_checks: List[Dict] = []
    fields = {
        "schematic": {
            "statistics.total_components": lambda v: _integer(v) and v > 0,
            "statistics.total_nets": _integer,
            "statistics.missing_mpn": _strings,
            "statistics.missing_footprint": _strings,
            "findings": _issues,
        },
        "pcb": {
            "connectivity.total_nets_with_pads": _integer,
            "connectivity.unrouted_count": _integer,
            "connectivity.routing_complete": lambda v: type(v) is bool,
            "statistics.footprint_count": lambda v: _integer(v) and v > 0,
            "statistics.net_count": _integer,
            "dfm_summary.dfm_tier": lambda v: isinstance(v, str) and bool(v),
            "findings": _issues,
            "silkscreen.documentation_warnings": _findings,
        },
        "gerbers": {
            "completeness.complete": lambda v: type(v) is bool,
            "alignment.aligned": lambda v: type(v) is bool,
            "findings": _issues,
        },
        "thermal": {"findings": _issues, "summary.thermal_score": _score},
        "emc": {"findings": _issues, "summary.emc_risk_score": _score},
    }
    data = {"schematic": sch, "pcb": pcb, "gerbers": gerber_data,
            "thermal": thermal_data, "emc": emc_data}
    valid = {}
    for name, item in data.items():
        check = _input_evidence(name, item, fields[name])
        all_checks.append(check)
        valid[name] = check["status"] == "pass"
        if valid[name]:
            summary = item.get("summary", {})
            if summary.get("skipped_reason") or summary.get("components_skipped", 0):
                all_checks.append(_check("evidence", name + "_coverage", "skip",
                                         f"{name}: analyzer reports skipped analysis"))
            if name != "emc":
                all_checks.append(_analysis_findings(name, item))

    if valid["pcb"]:
        all_checks.extend(check_routing(pcb))
        all_checks.extend(check_dfm(pcb))
        all_checks.extend(check_documentation(pcb))
    if valid["schematic"]:
        all_checks.extend(check_bom(sch))
    if valid["schematic"] and valid["pcb"]:
        all_checks.extend(check_consistency(sch, pcb))
    if valid["gerbers"]:
        all_checks.extend(check_gerbers(gerber_data))
    if valid["thermal"]:
        all_checks.extend(check_thermal(thermal_data))
    if valid["emc"]:
        all_checks.extend(check_emc(emc_data))

    trust = _compute_trust_posture(
        sch if isinstance(sch, dict) else None,
        pcb if isinstance(pcb, dict) else None,
        thermal_data if isinstance(thermal_data, dict) else None,
        emc_data if isinstance(emc_data, dict) else None,
    )
    if trust and trust.get("evidence_blockers"):
        all_checks.append(_check("evidence", "trust_blockers", "skip",
                                 "Unresolved analyzer evidence blockers",
                                 {"blockers": trust["evidence_blockers"]}))

    # Apply strict mode
    if strict:
        for c in all_checks:
            if c["status"] == "warn":
                c["status"] = "fail"

    # Compute summary
    counts = {"pass": 0, "warn": 0, "fail": 0, "skip": 0}
    for c in all_checks:
        counts[c["status"]] = counts.get(c["status"], 0) + 1

    if counts["fail"] > 0:
        overall = "FAIL"
    elif counts["skip"] > 0:
        overall = "INCOMPLETE"
    elif counts["warn"] > 0:
        overall = "WARN"
    elif counts["pass"] > 0:
        overall = "PASS"
    else:
        overall = "INCOMPLETE"

    elapsed = time.monotonic() - t0

    result = {
        "gate_version": GATE_VERSION,
        "overall_status": overall,
        "release_ready": overall == "PASS",
        "limitations": ["Analyzer gate only; native ERC/DRC, current supplier rules, "
                        "CAM/assembly inspection and human release approval remain required."],
        "summary": {
            "total_checks": len(all_checks),
            **counts,
        },
        "checks": all_checks,
        "elapsed_s": round(elapsed, 3),
    }
    if trust:
        result["trust_posture"] = trust
    return result


# ---------------------------------------------------------------------------
# Text report
# ---------------------------------------------------------------------------

_STATUS_ICONS = {
    "pass": "PASS",
    "warn": "WARN",
    "fail": "FAIL",
    "skip": "SKIP",
}

_OVERALL_ICONS = {
    "PASS": "PASS — Analyzer checks passed; engineering release review required",
    "WARN": "WARN — Review warnings before ordering",
    "FAIL": "FAIL — Issues must be resolved",
    "INCOMPLETE": "INCOMPLETE — Missing or skipped release checks; submission blocked",
}


def format_text_report(result: Dict) -> str:
    """Format gate result as human-readable text."""
    lines = []
    overall = result["overall_status"]
    summary = result["summary"]

    lines.append("=" * 60)
    lines.append(f"FABRICATION RELEASE GATE — {_OVERALL_ICONS.get(overall, overall)}")
    lines.append("=" * 60)
    lines.append("")
    for limitation in result.get("limitations", []):
        lines.append(f"  Limit: {limitation}")
    lines.append(f"  {summary['pass']} pass  {summary['warn']} warn  "
                 f"{summary['fail']} fail  {summary['skip']} skip")
    lines.append("")

    trust = result.get("trust_posture")
    if trust:
        level = trust["trust_level"]
        bc = trust["by_confidence"]
        total = trust["total_findings"]
        if total > 0:
            det_pct = round(100 * bc["deterministic"] / total)
            heu_pct = round(100 * bc["heuristic"] / total)
        else:
            det_pct = heu_pct = 0
        lines.append(f"  Trust: {level.upper()} — "
                     f"{det_pct}% deterministic, {heu_pct}% heuristic "
                     f"({total} findings)")
        prov = trust.get("provenance_coverage_pct", 0)
        lines.append(f"  Provenance: {prov}% of findings carry detector provenance")
        blockers = trust.get("evidence_blockers", [])
        if blockers:
            for b in blockers:
                lines.append(f"  Evidence blocker: {b}")
        lines.append("")

    # Group by category
    categories: Dict[str, List] = {}
    for c in result["checks"]:
        categories.setdefault(c["category"], []).append(c)

    for cat, cat_checks in categories.items():
        lines.append(f"--- {cat.upper()} ---")
        for c in cat_checks:
            icon = _STATUS_ICONS.get(c["status"], "????")
            lines.append(f"  [{icon}] {c['message']}")
            if c.get("details") and c["status"] in ("fail", "warn"):
                for k, v in c["details"].items():
                    if isinstance(v, list):
                        val = ", ".join(str(x) for x in v[:8])
                        if len(v) > 8:
                            val += f" (+{len(v)-8} more)"
                    else:
                        val = str(v)
                    lines.append(f"         {k}: {val}")
        lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Fabrication release gate for KiCad designs")
    parser.add_argument("--schematic", "-s", required=True,
                        help="Schematic analyzer JSON")
    parser.add_argument("--pcb", "-p", required=True,
                        help="PCB analyzer JSON")
    parser.add_argument("--gerbers", "-g", default=None,
                        help="Gerber analyzer JSON (optional)")
    parser.add_argument("--thermal", "-t", default=None,
                        help="Thermal analyzer JSON (optional)")
    parser.add_argument("--emc", "-e", default=None,
                        help="EMC analyzer JSON (optional)")
    parser.add_argument("--output", "-o",
                        help="Output JSON file (default: stdout)")
    parser.add_argument("--text", action="store_true",
                        help="Output human-readable text report")
    parser.add_argument("--compact", action="store_true",
                        help="Compact JSON output")
    parser.add_argument("--strict", action="store_true",
                        help="Treat warnings as failures")

    args = parser.parse_args()

    def _load(path):
        if not path:
            return None
        with open(path) as f:
            return json.load(f)

    try:
        sch, pcb = _load(args.schematic), _load(args.pcb)
        gerbers, thermal, emc = (_load(args.gerbers), _load(args.thermal), _load(args.emc))
    except (OSError, ValueError) as exc:
        print(f"Error: could not load analyzer input ({type(exc).__name__})", file=sys.stderr)
        sys.exit(2)

    result = run_gate(
        sch, pcb,
        gerber_data=gerbers,
        thermal_data=thermal,
        emc_data=emc,
        strict=args.strict,
    )

    if args.text:
        print(format_text_report(result))
    elif args.output:
        indent = None if args.compact else 2
        with open(args.output, "w") as f:
            json.dump(result, f, indent=indent)
        overall = result["overall_status"]
        total = result["summary"]["total_checks"]
        print(f"Gate: {overall} — {total} checks → {args.output}",
              file=sys.stderr)
    else:
        indent = None if args.compact else 2
        json.dump(result, sys.stdout, indent=indent)
        print(file=sys.stdout)

    # A failed, warning or incomplete release gate must never look successful
    # to shell automation. Missing checks remain blocking even without --strict.
    return {"PASS": 0, "FAIL": 1, "INCOMPLETE": 2, "WARN": 3}[result["overall_status"]]


if __name__ == "__main__":
    sys.exit(main())
