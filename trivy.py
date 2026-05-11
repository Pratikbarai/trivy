"""
DevSecOps Scanner Pipeline

Features:
- Scans Git repositories, local paths, or Docker images
- Runs:
    - Trivy (vulnerabilities, secrets, misconfigurations)
    - SBOM generation (CycloneDX + SPDX)
- Produces HTML report
- Determines pipeline status:
    CLEAN / WARNING / BLOCKED / FAILED_SCAN

Exit Codes:
    0 -> Success (no blocking issues)
    1 -> Security issues found
    2 -> Scan failure

Usage:
    python scanner.py --repo <url1> <url2> --parallel 5
"""

import os
import sys
import json
import logging
import argparse
import subprocess
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# ---------------------------------------------------------
# Logging — structured, pipeline-friendly output to stderr
# stdout stays clean for downstream piping
# ---------------------------------------------------------
logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
    stream=sys.stderr,
    level=logging.INFO,
)
log = logging.getLogger(__name__)

MAX_PARALLEL_WORKERS = 20

# Default configuration - will be overridden by benchmark_values_user.jsonc if present
DEFAULT_SEVERITIES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
DEFAULT_BLOCKING_SEVERITIES = ["CRITICAL"]

# ---------------------------------------------------------
# Load user configuration from benchmark_values_user.jsonc
# ---------------------------------------------------------
def load_user_config():
    """Load severity and blocking configuration from benchmark_values_user.jsonc."""
    config = {
        "severities": DEFAULT_SEVERITIES,
        "blocking_severities": DEFAULT_BLOCKING_SEVERITIES
    }
    
    # In GitLab CI, CI_PROJECT_DIR is the repository root
    # Fall back to current directory for local runs
    project_dir = os.environ.get("CI_PROJECT_DIR", os.getcwd())
    config_file = os.path.join(project_dir, "benchmark_values_user.jsonc")
    
    if not os.path.exists(config_file):
        log.info("No benchmark_values_user.jsonc found at %s, using defaults", config_file)
        return config
    
    log.info("Found config file: %s", config_file)
    
    try:
        with open(config_file, 'r') as f:
            # Remove comments (simple approach for JSONC)
            content = f.read()
            # Remove single-line comments
            lines = []
            for line in content.split('\n'):
                # Find comment position (outside of strings)
                in_string = False
                for i, char in enumerate(line):
                    if char == '"' and (i == 0 or line[i-1] != '\\'):
                        in_string = not in_string
                    if char == '/' and not in_string:
                        if i + 1 < len(line) and line[i+1] == '/':
                            line = line[:i]
                            break
                lines.append(line)
            
            clean_json = '\n'.join(lines)
            user_config = json.loads(clean_json)
            
            # Extract only the "trivy" section - ignore qualityGate and other sections
            trivy_config = user_config.get("trivy", {})
            
            if not trivy_config:
                # Fallback: try flat structure for backward compatibility
                log.info("No 'trivy' section found, checking flat structure")
                trivy_config = user_config
            
            # Validate and extract trivy configuration
            if "severities" in trivy_config:
                severities = trivy_config["severities"]
                if isinstance(severities, list) and all(s in ["LOW", "MEDIUM", "HIGH", "CRITICAL"] for s in severities):
                    config["severities"] = severities
                    log.info("User-configured severities: %s", severities)
                else:
                    log.warning("Invalid severities in config file, using defaults")
            
            if "blocking_severities" in trivy_config:
                blocking = trivy_config["blocking_severities"]
                if isinstance(blocking, list) and all(s in ["LOW", "MEDIUM", "HIGH", "CRITICAL"] for s in blocking):
                    # Always ensure CRITICAL is included in blocking severities
                    if "CRITICAL" not in blocking:
                        blocking.append("CRITICAL")
                        log.info("CRITICAL automatically added to blocking_severities")
                    
                    # Remove duplicates while preserving order
                    seen = set()
                    blocking = [x for x in blocking if not (x in seen or seen.add(x))]
                    
                    config["blocking_severities"] = blocking
                    log.info("User-configured blocking severities: %s", blocking)
                else:
                    log.warning("Invalid blocking_severities in config file, using defaults")
                    
    except (json.JSONDecodeError, IOError) as exc:
        log.warning("Failed to parse benchmark_values_user.jsonc: %s. Using defaults.", exc)
    
    return config

# Load user configuration
USER_CONFIG = load_user_config()
TRIVY_SEVERITIES = ",".join(USER_CONFIG["severities"])
BLOCKING_SEVERITIES = set(USER_CONFIG["blocking_severities"])

# ---------------------------------------------------------
# Report output base directory
# In GitLab CI, CI_PROJECT_DIR is the repo root that the
# runner uses as its working directory — artifacts paths in
# .gitlab-ci.yml are relative to it, so we must write there.
# Fall back to cwd for local runs.
# ---------------------------------------------------------
_PROJECT_DIR = os.environ.get("CI_PROJECT_DIR", os.getcwd())
TRIVY_REPORT_DIR = os.path.join(_PROJECT_DIR, "trivy_reports")
SBOM_REPORT_DIR  = os.path.join(_PROJECT_DIR, "sbom_reports")

# Trivy scanner types included in every scan
# Note: 'config' was renamed to 'misconfig' in Trivy v0.38+
TRIVY_SCANNERS = "vuln,secret,misconfig"

# ---------------------------------------------------------
# Trivy vulnerability class constants
# ---------------------------------------------------------
TRIVY_CLASS_OS   = "os-pkgs"
TRIVY_CLASS_LANG = "lang-pkgs"

# ---------------------------------------------------------
# Execute a shell command safely with timeout handling
# ---------------------------------------------------------
def run(cmd, timeout=3600):
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.returncode, result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        log.error("Command timed out: %s", " ".join(cmd))
        return 99, "TIMEOUT"
    except FileNotFoundError:
        log.error("Command not found: %s", cmd[0])
        return 98, "NOT_FOUND"

# ---------------------------------------------------------
# Check whether the given source is a Git repository URL
# ---------------------------------------------------------
def is_git_url(src):
    return (
        src.startswith("http://")
        or src.startswith("https://")
        or src.startswith("git@")
        or src.endswith(".git")
    )

def is_docker_image(src):
    """Detect if input is a Docker image reference."""
    return ":" in src and not os.path.exists(src)

# ---------------------------------------------------------
# Clone a Git repository or update if already present
# ---------------------------------------------------------
def clone_repo(url, base_dir="repos"):
    os.makedirs(base_dir, exist_ok=True)

    name = url.rstrip("/").split("/")[-1].replace(".git", "")
    target = os.path.join(base_dir, name)

    if os.path.exists(target):
        log.info("Updating repo: %s", name)
        code, output = run(["git", "-C", target, "pull"])
        if code not in (0, 1):
            raise RuntimeError(
                f"git pull failed for '{name}' (exit {code}): {output.strip()}"
            )
    else:
        log.info("Cloning repo: %s", name)
        code, output = run(["git", "clone", url, target])
        if code != 0:
            raise RuntimeError(
                f"git clone failed for '{url}' (exit {code}): {output.strip()}"
            )

    return target, name

# ---------------------------------------------------------
# Resolve input source into a local filesystem path
# ---------------------------------------------------------
def resolve_source(src):
    if is_git_url(src):
        log.info("Mode: Git URL -- %s", src)
        return clone_repo(src)

    src = os.path.abspath(os.path.expanduser(src))

    if not os.path.exists(src):
        raise RuntimeError(f"Path not found: {src}")

    log.info("Mode: local path -- %s", src)
    return src, os.path.basename(src)

# ---------------------------------------------------------
# Parse a single Trivy Results entry and bucket findings
# ---------------------------------------------------------
def _parse_trivy_result(scan_result, counts, top_vulns, top_secrets,
                        top_misconfigs):
    target     = scan_result.get("Target", "")
    vuln_class = scan_result.get("Class", "unknown")

    # --- vulnerabilities ---
    for vuln in scan_result.get("Vulnerabilities") or []:
        sev           = vuln.get("Severity", "UNKNOWN")
        fixed_version = vuln.get("FixedVersion") or ""
        has_fix       = bool(fixed_version.strip()) if fixed_version else False

        if has_fix:
            # Severity is actionable — a fix exists, you can remediate it
            counts["vuln_fixable"][sev] = counts["vuln_fixable"].get(sev, 0) + 1
            top_vulns.append({
                "type":              "vuln",
                "id":                vuln.get("VulnerabilityID"),
                "package":           vuln.get("PkgName"),
                "severity":          sev,
                "installed_version": vuln.get("InstalledVersion"),
                "fixed_version":     fixed_version,
                "has_fix":           True,
                "vuln_class":        vuln_class,
                "title":             vuln.get("Title"),
                "target":            target,
            })
        else:
            # No fix available — severity is meaningless, track only as informational
            counts["vuln_no_fix"] = counts.get("vuln_no_fix", {})
            counts["vuln_no_fix"][sev] = counts["vuln_no_fix"].get(sev, 0) + 1
            top_vulns.append({
                "type":              "vuln",
                "id":                vuln.get("VulnerabilityID"),
                "package":           vuln.get("PkgName"),
                "severity":          None,           # no severity — no fix exists
                "installed_version": vuln.get("InstalledVersion"),
                "fixed_version":     None,
                "has_fix":           False,
                "vuln_class":        vuln_class,
                "title":             vuln.get("Title"),
                "target":            target,
            })

    # --- secrets ---
    for secret in scan_result.get("Secrets") or []:
        sev = secret.get("Severity", "UNKNOWN")
        counts["secret"][sev] = counts["secret"].get(sev, 0) + 1
        top_secrets.append({
                "type":       "secret",
                "rule_id":    secret.get("RuleID"),
                "title":      secret.get("Title"),
                "severity":   sev,
                "target":     target,
                "start_line": secret.get("StartLine"),
            })

    # --- misconfigurations ---
    for mc in scan_result.get("Misconfigurations") or []:
        sev = mc.get("Severity", "UNKNOWN")
        counts["config"][sev] = counts["config"].get(sev, 0) + 1
        top_misconfigs.append({
                "type":       "misconfig",
                "id":         mc.get("ID"),
                "title":      mc.get("Title"),
                "severity":   sev,
                "target":     target,
                "resolution": mc.get("Resolution"),
            })

# ---------------------------------------------------------
# Run Trivy scan with vuln + secret + misconfig scanners
# ---------------------------------------------------------
def run_trivy(path, name, timestamp, mode="repo"):
    os.makedirs(TRIVY_REPORT_DIR, exist_ok=True)

    # JSON report for internal processing
    report_file = os.path.join(TRIVY_REPORT_DIR, f"{name}_{timestamp}.json")

    cmd = [
        "trivy",
        mode,
        "--scanners", TRIVY_SCANNERS,
        "--severity", TRIVY_SEVERITIES,
        "--format", "json",
        "--quiet",
        "--no-progress","--timeout", "60m",
        "-o", report_file,
        
    ]
    # Don't pull images from registry - use local images only
    if mode == "image":
        cmd.append("--pull=never")

    cmd.append(path)

    code, output = run(cmd,timeout=3600)

    result = {
        "report": report_file,
        "raw_data": {},
        "vulnerabilities_found": False,
        "secrets_found": False,
        "misconfigs_found": False,
        "vuln_severity_counts": {},       # fixable vulns only — severity is actionable
        "vuln_no_fix_counts": {},         # no-fix vulns — informational only
        "vuln_fixable_counts": {},
        "secret_severity_counts": {},
        "config_severity_counts": {},
        "top_vulnerabilities": [],
        "top_secrets": [],
        "top_misconfigs": [],
        "os_vulns_with_fix": [],
        "os_vulns_no_fix": [],
        "lib_vulns_with_fix": [],
        "lib_vulns_no_fix": [],
        "exit_code": code,
        "error": None,
    }

    if code not in (0, 1):
        result["error"] = f"Trivy exited with code {code}: {output.strip()}"
        log.error("Trivy error for '%s': %s", name, result["error"])
        return result

    if not os.path.exists(report_file) or os.path.getsize(report_file) == 0:
        result["error"] = f"Trivy produced no report for '{name}'"
        log.error(result["error"])
        return result

    try:
        with open(report_file, "r") as f:
            data = json.load(f)
    except json.JSONDecodeError as exc:
        result["error"] = f"Trivy report is invalid JSON: {exc}"
        log.error(result["error"])
        return result

    result["raw_data"] = data

    # Normalize: Trivy may return a bare dict or a list
    if isinstance(data, dict):
        items = [data]
    elif isinstance(data, list):
        items = data
    else:
        result["error"] = "Unexpected Trivy report structure"
        log.error(result["error"])
        return result

    counts = {"vuln_fixable": {}, "vuln_no_fix": {}, "secret": {}, "config": {}}
    top_vulns, top_secrets, top_misconfigs = [], [], []

    for item in items:
        for scan_result in item.get("Results") or []:
            _parse_trivy_result(
                scan_result, counts, top_vulns, top_secrets, top_misconfigs
            )

    result["vuln_severity_counts"]   = counts["vuln_fixable"]   # severity only for fixable
    result["vuln_no_fix_counts"]     = counts["vuln_no_fix"]     # informational
    result["vuln_fixable_counts"]    = counts["vuln_fixable"]
    result["secret_severity_counts"] = counts["secret"]
    result["config_severity_counts"] = counts["config"]
    result["vulnerabilities_found"]  = bool(top_vulns)
    result["secrets_found"]          = bool(top_secrets)
    result["misconfigs_found"]       = bool(top_misconfigs)
    result["top_vulnerabilities"]    = top_vulns
    result["top_secrets"]            = top_secrets
    result["top_misconfigs"]         = top_misconfigs

    # Two-level patch breakdown
    for v in top_vulns:
        cls      = v.get("vuln_class", "unknown")
        has_fix  = v.get("has_fix", False)
        is_os    = cls == TRIVY_CLASS_OS
        is_lib   = cls == TRIVY_CLASS_LANG

        if is_os and has_fix:
            result["os_vulns_with_fix"].append(v)
        elif is_os and not has_fix:
            result["os_vulns_no_fix"].append(v)
        elif is_lib and has_fix:
            result["lib_vulns_with_fix"].append(v)
        elif is_lib and not has_fix:
            result["lib_vulns_no_fix"].append(v)

    log.info(
        "Trivy '%s': vulns=%d  secrets=%d  misconfigs=%d  "
        "[os+fix=%d  os-fix=%d  lib+fix=%d  lib-fix=%d]",
        name, len(top_vulns), len(top_secrets), len(top_misconfigs),
        len(result["os_vulns_with_fix"]),
        len(result["os_vulns_no_fix"]),
        len(result["lib_vulns_with_fix"]),
        len(result["lib_vulns_no_fix"]),
    )

    return result

# ---------------------------------------------------------
# Severity colour mapping
# ---------------------------------------------------------
SEV_COLOURS = {
    "CRITICAL": ("#7b1fa2", "#f3e5f5"),
    "HIGH":     ("#c62828", "#ffebee"),
    "MEDIUM":   ("#e65100", "#fff3e0"),
    "LOW":      ("#1565c0", "#e3f2fd"),
    "UNKNOWN":  ("#424242", "#f5f5f5"),
}

def _sev_badge(sev):
    """Return an inline HTML severity badge."""
    import html as _html
    bg, _ = SEV_COLOURS.get(sev.upper(), SEV_COLOURS["UNKNOWN"])
    return (
        f'<span style="background:{bg};color:#fff;padding:2px 8px;'
        f'border-radius:3px;font-size:.78rem;font-weight:700;'
        f'letter-spacing:.5px;">{_html.escape(sev)}</span>'
    )

def _summary_card(label, count, colour):
    """Return a summary stat card."""
    return (
        f'<div style="background:{colour};border-radius:6px;padding:14px 20px;'
        f'min-width:110px;text-align:center;box-shadow:0 1px 3px rgba(0,0,0,.15);">'
        f'<div style="font-size:1.8rem;font-weight:700;color:#212121;">{count}</div>'
        f'<div style="font-size:.8rem;color:#555;margin-top:2px;">{label}</div>'
        f'</div>'
    )

# ---------------------------------------------------------
# Generate custom HTML report from already-parsed scan data
# ---------------------------------------------------------
def run_trivy_html_report(path, name, timestamp, mode="repo", t_result=None):
    """
    Build a fully custom HTML report directly from the parsed t_result data.
    No second Trivy run — uses the same data that drives blocking logic.
    Sections: Summary | Vulnerabilities | Secrets | Misconfigurations
    """
    import html as _html
    from datetime import datetime as _dt

    os.makedirs(TRIVY_REPORT_DIR, exist_ok=True)
    html_file = os.path.join(TRIVY_REPORT_DIR, f"{name}_{timestamp}_report.html")

    result = {"html_report": None, "error": None}

    if t_result is None:
        result["error"] = "No scan data passed to HTML report generator"
        log.warning(result["error"])
        return result

    # ── Counters ────────────────────────────────────────────────────────────
    vuln_counts    = t_result.get("vuln_severity_counts",   {})  # fixable only
    vuln_no_fix    = t_result.get("vuln_no_fix_counts",     {})  # informational
    secret_counts  = t_result.get("secret_severity_counts", {})
    config_counts  = t_result.get("config_severity_counts", {})

    fixable_vulns   = [v for v in t_result.get("top_vulnerabilities", []) if v.get("has_fix")]
    no_fix_vulns    = [v for v in t_result.get("top_vulnerabilities", []) if not v.get("has_fix")]

    total_fixable    = len(fixable_vulns)
    total_no_fix     = len(no_fix_vulns)
    total_secrets    = sum(secret_counts.values())
    total_misconfigs = sum(config_counts.values())
    total_all        = total_fixable + total_secrets + total_misconfigs
    # no-fix vulns excluded from total — informational only

    pipeline_status = "FAILED_SCAN" if t_result.get("error") else (
        "BLOCKED"  if any(
            t_result.get("trivy_block_reasons") if hasattr(t_result, "get") else []
        ) else (
        "WARNING"  if total_all > 0 else "CLEAN"
    ))

    status_colour = {
        "CLEAN":       "#27ae60",
        "WARNING":     "#e65100",
        "BLOCKED":     "#c62828",
        "FAILED_SCAN": "#7b1fa2",
    }.get(pipeline_status, "#424242")

    # ── Summary cards ───────────────────────────────────────────────────────
    cards_html = "".join([
        _summary_card("Actionable Findings", total_all,        "#e8eaf6"),
        _summary_card("Fixable Vulns",        total_fixable,   "#ffebee"),
        _summary_card("No-Fix Vulns",         total_no_fix,    "#f5f5f5"),
        _summary_card("Secrets",              total_secrets,   "#fff8e1"),
        _summary_card("Misconfigurations",    total_misconfigs,"#f3e5f5"),
    ])

    # ── Severity breakdown bar ──────────────────────────────────────────────
    def _sev_bar(counts):
        if not counts:
            return '<span style="color:#999;font-size:.85rem;">None</span>'
        parts = []
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]:
            n = counts.get(sev, 0)
            if n:
                bg, _ = SEV_COLOURS.get(sev, SEV_COLOURS["UNKNOWN"])
                parts.append(
                    f'<span style="background:{bg};color:#fff;padding:2px 9px;'
                    f'margin-right:4px;border-radius:3px;font-size:.8rem;">'
                    f'{_html.escape(sev)}: {n}</span>'
                )
        return "".join(parts)

    # ── Fixable vulnerabilities table (severity matters) ───────────────────
    fixable_rows = ""
    for v in fixable_vulns:
        fixable_rows += (
            f"<tr>"
            f"<td>{_html.escape(v.get('id') or '')}</td>"
            f"<td>{_sev_badge(v.get('severity','UNKNOWN'))}</td>"
            f"<td>{_html.escape(v.get('package') or '')}</td>"
            f"<td>{_html.escape(v.get('installed_version') or '')}</td>"
            f"<td><span style='color:#27ae60;font-weight:600;'>{_html.escape(v.get('fixed_version',''))}</span></td>"
            f"<td>{_html.escape(v.get('vuln_class') or '')}</td>"
            f"<td style='max-width:280px;'>{_html.escape(v.get('title') or '')}</td>"
            f"<td style='max-width:200px;font-size:.8rem;color:#666;'>{_html.escape(v.get('target') or '')}</td>"
            f"</tr>\n"
        )

    # ── No-fix vulnerabilities table (informational only) ──────────────────
    no_fix_rows = ""
    for v in no_fix_vulns:
        no_fix_rows += (
            f"<tr>"
            f"<td>{_html.escape(v.get('id') or '')}</td>"
            f"<td>{_html.escape(v.get('package') or '')}</td>"
            f"<td>{_html.escape(v.get('installed_version') or '')}</td>"
            f"<td>{_html.escape(v.get('vuln_class') or '')}</td>"
            f"<td style='max-width:320px;'>{_html.escape(v.get('title') or '')}</td>"
            f"<td style='max-width:200px;font-size:.8rem;color:#666;'>{_html.escape(v.get('target') or '')}</td>"
            f"</tr>\n"
        )

    vuln_table = f"""
    <h2 style="color:#c62828;margin-top:0;"> Fixable Vulnerabilities
      <span style="font-size:.9rem;font-weight:400;color:#666;">({total_fixable} — severity is actionable)</span>
    </h2>
    <div style="margin-bottom:10px;">{_sev_bar(vuln_counts)}</div>
    """ + (f"""
    <div style="overflow-x:auto;">
    <table>
      <tr>
        <th>CVE / ID</th><th>Severity</th><th>Package</th>
        <th>Installed</th><th>Fixed In</th><th>Class</th>
        <th>Title</th><th>Target</th>
      </tr>
      {fixable_rows}
    </table>
    </div>""" if fixable_rows else
    '<p style="color:#999;">No fixable vulnerabilities found.</p>') + f"""

    <h2 style="color:#757575;margin-top:32px;"> No-Fix Vulnerabilities
      <span style="font-size:.9rem;font-weight:400;color:#999;">
        ({total_no_fix} — informational only, no remediation available)
      </span>
    </h2>
    """ + (f"""
    <div style="overflow-x:auto;">
    <table style="opacity:.85;">
      <tr>
        <th>CVE / ID</th><th>Package</th><th>Installed</th>
        <th>Class</th><th>Title</th><th>Target</th>
      </tr>
      {no_fix_rows}
    </table>
    </div>""" if no_fix_rows else
    '<p style="color:#999;">None.</p>')

    # ── Secrets table ───────────────────────────────────────────────────────
    secret_rows = ""
    for s in t_result.get("top_secrets", []):
        secret_rows += (
            f"<tr>"
            f"<td>{_html.escape(s.get('rule_id') or '')}</td>"
            f"<td>{_sev_badge(s.get('severity','UNKNOWN'))}</td>"
            f"<td>{_html.escape(s.get('title') or '')}</td>"
            f"<td style='font-size:.8rem;color:#666;'>{_html.escape(s.get('target') or '')}</td>"
            f"<td>{_html.escape(str(s.get('start_line') or ''))}</td>"
            f"</tr>\n"
        )
    secret_table = f"""
    <h2 style="color:#e65100;margin-top:40px;"> Secrets
      <span style="font-size:.9rem;font-weight:400;color:#666;">({total_secrets} total)</span>
    </h2>
    <div style="margin-bottom:10px;">{_sev_bar(secret_counts)}</div>
    """ + (f"""
    <div style="overflow-x:auto;">
    <table>
      <tr>
        <th>Rule ID</th><th>Severity</th><th>Title</th>
        <th>Target File</th><th>Line</th>
      </tr>
      {secret_rows}
    </table>
    </div>""" if secret_rows else
    '<p style="color:#999;">No secrets found.</p>')

    # ── Misconfigurations table ─────────────────────────────────────────────
    mc_rows = ""
    for mc in t_result.get("top_misconfigs", []):
        mc_rows += (
            f"<tr>"
            f"<td>{_html.escape(mc.get('id') or '')}</td>"
            f"<td>{_sev_badge(mc.get('severity','UNKNOWN'))}</td>"
            f"<td>{_html.escape(mc.get('title') or '')}</td>"
            f"<td style='max-width:300px;font-size:.85rem;'>{_html.escape(mc.get('resolution') or '')}</td>"
            f"<td style='font-size:.8rem;color:#666;'>{_html.escape(mc.get('target') or '')}</td>"
            f"</tr>\n"
        )
    mc_table = f"""
    <h2 style="color:#7b1fa2;margin-top:40px;"> Misconfigurations
      <span style="font-size:.9rem;font-weight:400;color:#666;">({total_misconfigs} total)</span>
    </h2>
    <div style="margin-bottom:10px;">{_sev_bar(config_counts)}</div>
    """ + (f"""
    <div style="overflow-x:auto;">
    <table>
      <tr>
        <th>ID</th><th>Severity</th><th>Title</th>
        <th>Resolution</th><th>Target</th>
      </tr>
      {mc_rows}
    </table>
    </div>""" if mc_rows else
    '<p style="color:#999;">No misconfigurations found.</p>')

    # ── Full HTML ───────────────────────────────────────────────────────────
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Trivy Security Report — {_html.escape(name)}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: Arial, sans-serif; background: #f5f5f5; color: #212121; padding: 30px; }}
  h1 {{ color: #1a237e; margin-bottom: 4px; }}
  h2 {{ margin-bottom: 8px; }}
  .meta {{ color: #666; font-size: .9rem; margin: 6px 0 24px; }}
  .status-badge {{
    display: inline-block; padding: 6px 18px; border-radius: 4px;
    color: #fff; background: {status_colour};
    font-size: 1rem; font-weight: 700; letter-spacing: .5px;
  }}
  .cards {{ display: flex; gap: 16px; flex-wrap: wrap; margin: 20px 0 30px; }}
  table {{ border-collapse: collapse; width: 100%; background: #fff;
           box-shadow: 0 1px 4px rgba(0,0,0,.1); font-size: .88rem; }}
  th {{ background: #1a237e; color: #fff; padding: 10px 12px; text-align: left;
        white-space: nowrap; }}
  td {{ padding: 8px 12px; border-bottom: 1px solid #eee; vertical-align: top; }}
  tr:hover td {{ background: #fafafa; }}
  .section {{ background: #fff; border-radius: 6px; padding: 24px;
              box-shadow: 0 1px 4px rgba(0,0,0,.08); margin-bottom: 28px; }}
</style>
</head>
<body>

<h1> Trivy Security Report</h1>
<p class="meta">
  Target: <strong>{_html.escape(name)}</strong> &nbsp;|&nbsp;
  Scanners: <strong>Vulnerabilities · Secrets · Misconfigurations</strong> &nbsp;|&nbsp;
  Severities: <strong>{_html.escape(TRIVY_SEVERITIES)}</strong> &nbsp;|&nbsp;
  Generated: <strong>{_dt.utcnow().strftime("%Y-%m-%d %H:%M UTC")}</strong>
</p>

<p style="margin-bottom:20px;">
  Pipeline Status: <span class="status-badge">{_html.escape(pipeline_status)}</span>
</p>

<div class="section">
  <h2 style="color:#1a237e;margin-bottom:16px;">📊 Summary</h2>
  <div class="cards">{cards_html}</div>
</div>

<div class="section">
  {vuln_table}
</div>

<div class="section">
  {secret_table}
</div>

<div class="section">
  {mc_table}
</div>

</body>
</html>"""

    try:
        with open(html_file, "w", encoding="utf-8") as f:
            f.write(html_content)
        result["html_report"] = html_file
        log.info("Custom HTML report saved: %s", html_file)
    except OSError as exc:
        result["error"] = f"Could not write HTML report: {exc}"
        log.error(result["error"])

    return result

# ---------------------------------------------------------
# Generate SBOM using CycloneDX and SPDX formats
# ---------------------------------------------------------
def run_sbom(path, name, timestamp, mode="repo"):
    """Generate Software Bill of Materials using Trivy."""
    os.makedirs(SBOM_REPORT_DIR, exist_ok=True)

    result = {
        "cyclonedx_file":   None,
        "spdx_file":        None,
        "component_count":  0,
        "components":       [],
        "error":            None,
        "spdx_error":       None,
    }

    # --- CycloneDX JSON SBOM ---
    cdx_file = os.path.join(SBOM_REPORT_DIR, f"{name}_{timestamp}_sbom.cdx.json")
    cdx_cmd  = [
        "trivy",
        mode,
        "--format",     "cyclonedx",
        "--quiet",
        "--no-progress",
        "-o", cdx_file,
        
    ]
    # Don't pull images from registry - use local images only
    if mode == "image":
        cdx_cmd.append("--pull=never")

    cdx_cmd.append(path)
    code, output = run(cdx_cmd,timeout=3600)

    if code not in (0, 1):
        result["error"] = f"SBOM (CycloneDX) generation failed (exit {code}): {output.strip()}"
        log.error("SBOM error for '%s': %s", name, result["error"])
        return result

    result["cyclonedx_file"] = cdx_file

    # Parse CycloneDX to extract component inventory
    try:
        with open(cdx_file, "r") as f:
            cdx_data = json.load(f)

        components = cdx_data.get("components", [])
        result["component_count"] = len(components)

        for comp in components:
            result["components"].append({
                "name":    comp.get("name"),
                "version": comp.get("version"),
                "type":    comp.get("type"),
                "purl":    comp.get("purl"),
                "licenses": [
                    lic.get("expression") or lic.get("license", {}).get("id")
                    for lic in comp.get("licenses", [])
                ],
            })

        log.info(
            "SBOM (CycloneDX) for '%s': %d components  saved: %s",
            name, result["component_count"], cdx_file,
        )

    except (json.JSONDecodeError, OSError) as exc:
        log.warning("Could not parse CycloneDX SBOM for '%s': %s", name, exc)

    # --- SPDX JSON SBOM (non-fatal if unsupported by Trivy version) ---
    spdx_file = os.path.join(SBOM_REPORT_DIR, f"{name}_{timestamp}_sbom.spdx.json")
    spdx_cmd  = [
        "trivy",
        mode,
        "--format",     "spdx-json",
        "--quiet",
        "--no-progress",
        "-o", spdx_file,
        
    ]
        # Don't pull images from registry - use local images only
    if mode == "image":
        spdx_cmd.append("--pull=never")

    spdx_cmd.append(path)
    code_spdx, output_spdx = run(spdx_cmd,timeout=3600)

    if code_spdx not in (0, 1):
        log.warning(
            "SBOM (SPDX) generation failed for '%s' (exit %d): %s -- continuing",
            name, code_spdx, output_spdx.strip(),
        )
        result["spdx_error"] = f"SPDX failed (exit {code_spdx}): {output_spdx.strip()}"
    else:
        result["spdx_file"] = spdx_file
        log.info("SBOM (SPDX) for '%s' saved: %s", name, spdx_file)

    return result

# ---------------------------------------------------------
# Check if Trivy findings are blocking
# ---------------------------------------------------------
def trivy_is_blocking(t_result):
    """Determine if Trivy findings should block the pipeline.
    
    Rules:
    - Vulnerabilities: Block if severity is in BLOCKING_SEVERITIES AND fix is available
    - Secrets/Misconfigs: Block if severity is in BLOCKING_SEVERITIES
    """
    reasons = []

    # Check all vulnerabilities - block if severity is in blocking list AND fix is available
    for vuln in t_result.get("top_vulnerabilities", []):
        severity = vuln.get("severity", "UNKNOWN")
        has_fix = vuln.get("has_fix", False)
        package = vuln.get("package", "unknown")
        vuln_id = vuln.get("id", "unknown")
        installed = vuln.get("installed_version", "?")
        fixed = vuln.get("fixed_version", "?")
        
        # Block only if severity is in BLOCKING_SEVERITIES AND a fix is available
        if has_fix and severity in BLOCKING_SEVERITIES:
            reasons.append(
                f"{severity} vulnerability with fix available: {package} ({vuln_id}) - "
                f"installed: {installed}, fixed: {fixed}"
            )
            log.warning(
                "BLOCKING: %s vuln - %s in %s (installed: %s, fix: %s)",
                severity, vuln_id, package, installed, fixed
            )

    # Check secrets - block if severity in blocking list
    for sev in BLOCKING_SEVERITIES:
        if t_result.get("secret_severity_counts", {}).get(sev, 0) > 0:
            reasons.append(f"{sev} secret finding")
            log.warning("BLOCKING: %s secret(s) found", sev)

    # Check misconfigs - block if severity in blocking list
    for sev in BLOCKING_SEVERITIES:
        if t_result.get("config_severity_counts", {}).get(sev, 0) > 0:
            reasons.append(f"{sev} misconfiguration finding")
            log.warning("BLOCKING: %s misconfiguration(s) found", sev)

    is_blocking = bool(reasons)
    return is_blocking, reasons
# ---------------------------------------------------------
# Check if Trivy has any findings
# ---------------------------------------------------------
def trivy_has_findings(t_result):
    return (
        t_result["vulnerabilities_found"]
        or t_result["secrets_found"]
        or t_result["misconfigs_found"]
    )

# ---------------------------------------------------------
# Scan a single repository, directory, or Docker image
# ---------------------------------------------------------
def scan_target(src):
    timestamp = datetime.now().isoformat().replace(":", "-")

    # Detect Docker image vs repo
    if is_docker_image(src):
        log.info("Mode: Docker image -- %s", src)
        path = src
        name = src.replace(":", "_").replace("/", "_")
        trivy_mode = "image"
    else:
        try:
            path, name = resolve_source(src)
        except RuntimeError as exc:
            log.error("Source resolution failed for '%s': %s", src, exc)
            return {
                "source": src,
                "target": None,
                "status": "FAILED_SCAN",
                "error": str(exc),
                "exit_code": 2,
                "timestamp": timestamp,
            }

        trivy_mode = "repo"

    # Run Trivy scan
    t_result = run_trivy(path, name, timestamp, mode=trivy_mode)

    # Determine blocking status BEFORE generating HTML so the report
    # can show the correct pipeline status badge
    trivy_blocking, trivy_block_reasons = trivy_is_blocking(t_result)
    t_result["trivy_block_reasons"] = trivy_block_reasons

    # Generate HTML report (uses already-parsed data — no second Trivy run)
    html_result = run_trivy_html_report(path, name, timestamp, mode=trivy_mode, t_result=t_result)

    # Generate SBOM
    sbom_result = run_sbom(path, name, timestamp, mode=trivy_mode)

    # Determine pipeline status
    scan_failed = t_result["error"] is not None

    if scan_failed:
        status    = "FAILED_SCAN"
        exit_code = 2
    elif trivy_blocking:
        status    = "BLOCKED"
        exit_code = 1
    elif trivy_has_findings(t_result):
        status    = "WARNING"
        exit_code = 0
    else:
        status    = "CLEAN"
        exit_code = 0

    if trivy_block_reasons:
        for reason in trivy_block_reasons:
            log.warning("Trivy block reason: %s", reason)

    log.info("Result: %s -> %s", name, status)

    return {
        "target":      name,
        "source":      src,
        "path":        path,
        "status":      status,
        "exit_code":   exit_code,
        "timestamp":   timestamp,
        "trivy_mode":  trivy_mode,
        
        # Trivy results
        "trivy_report":                    t_result["report"],
        "trivy_error":                     t_result["error"],
        "trivy_vulnerabilities_found":     t_result["vulnerabilities_found"],
        "trivy_secrets_found":             t_result["secrets_found"],
        "trivy_misconfigs_found":          t_result["misconfigs_found"],
        "trivy_vuln_severity_counts":      t_result["vuln_severity_counts"],
        "trivy_vuln_fixable_counts":       t_result["vuln_fixable_counts"],
        "trivy_secret_severity_counts":    t_result["secret_severity_counts"],
        "trivy_config_severity_counts":    t_result["config_severity_counts"],
        "trivy_os_vulns_with_fix":         t_result["os_vulns_with_fix"],
        "trivy_os_vulns_no_fix":           t_result["os_vulns_no_fix"],
        "trivy_lib_vulns_with_fix":        t_result["lib_vulns_with_fix"],
        "trivy_lib_vulns_no_fix":          t_result["lib_vulns_no_fix"],
        "trivy_block_reasons":             trivy_block_reasons,
        "trivy_top_vulnerabilities":       t_result["top_vulnerabilities"],
        "trivy_top_secrets":               t_result["top_secrets"],
        "trivy_top_misconfigs":            t_result["top_misconfigs"],
        "trivy_raw":                       t_result["raw_data"],
        
        # HTML report
        "trivy_html_report":               html_result["html_report"],
        "trivy_html_error":                 html_result["error"],
        
        # SBOM
        "sbom_cyclonedx_file":             sbom_result["cyclonedx_file"],
        "sbom_spdx_file":                  sbom_result["spdx_file"],
        "sbom_component_count":            sbom_result["component_count"],
        "sbom_components":                 sbom_result["components"],
        "sbom_error":                      sbom_result["error"],
        "sbom_spdx_error":                 sbom_result["spdx_error"],
        
        # Configuration used
        "severities_scanned":              USER_CONFIG["severities"],
        "blocking_severities":             USER_CONFIG["blocking_severities"],
    }

# ---------------------------------------------------------
# Execute scans in parallel using a thread pool
# ---------------------------------------------------------
def parallel_scan(sources, workers):
    results = []

    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_src = {executor.submit(scan_target, s): s for s in sources}

        for future in as_completed(future_to_src):
            src = future_to_src[future]
            try:
                results.append(future.result())
            except Exception as exc:
                log.error("Unhandled thread error for '%s': %s", src, exc)
                results.append({
                    "source":    src,
                    "target":    None,
                    "status":    "FAILED_SCAN",
                    "error":     str(exc),
                    "exit_code": 2,
                    "timestamp": datetime.now().isoformat(),
                })

    return results

# ---------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="DevSecOps scanner -- Trivy (vuln, secret, config) with HTML reports and SBOM"
    )
    parser.add_argument("--repo",  nargs="*", help="Git repository URLs")
    parser.add_argument("--path",  nargs="*", help="Local directory paths or Docker images")
    parser.add_argument(
        "--output",
        default="security_scan_results.json",
        help="Output JSON report file (default: security_scan_results.json)",
    )
    parser.add_argument(
        "--parallel",
        type=int,
        default=1,
        help=f"Parallel workers, 1-{MAX_PARALLEL_WORKERS} (default: 1)",
    )
    args = parser.parse_args()

    if not (1 <= args.parallel <= MAX_PARALLEL_WORKERS):
        log.error("--parallel must be between 1 and %d", MAX_PARALLEL_WORKERS)
        sys.exit(2)

    sources = []
    if args.repo:
        sources.extend(args.repo)
    if args.path:
        sources.extend(args.path)

    if not sources:
        log.error("No input provided. Use --repo or --path.")
        sys.exit(2)

    log.info("Configuration loaded:")
    log.info("  Severities scanned: %s", USER_CONFIG["severities"])
    log.info("  Blocking severities: %s", USER_CONFIG["blocking_severities"])
    log.info("Targets  : %d", len(sources))
    log.info("Workers  : %d", args.parallel)
    log.info("Scanner  : Trivy (%s)", TRIVY_SCANNERS)
    log.info("Reports  : HTML + SBOM (CycloneDX + SPDX)")

    # Run all scans
    results = parallel_scan(sources, args.parallel)

    # Write results to JSON
    try:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=4)
        log.info("Report saved: %s", args.output)
    except OSError as exc:
        log.error("Could not write report: %s", exc)
        sys.exit(2)

    # Print HTML report and SBOM locations
    for r in results:
        target = r.get("target") or r.get("source")
        log.info("── %s ──", target)
        if r.get("trivy_html_report"):
            log.info("  HTML Report: %s", r["trivy_html_report"])
        if r.get("sbom_cyclonedx_file"):
            log.info("  SBOM CycloneDX: %s  (%d components)",
                     r["sbom_cyclonedx_file"], r.get("sbom_component_count", 0))
        if r.get("sbom_spdx_file"):
            log.info("  SBOM SPDX: %s", r["sbom_spdx_file"])
        if r.get("trivy_error"):
            log.error("  Error: %s", r["trivy_error"])
        if r.get("sbom_error"):
            log.warning("  SBOM error: %s", r["sbom_error"])

    # Pipeline decision - break after all scans complete
    has_failed = any(r["status"] == "FAILED_SCAN" for r in results)
    has_blocked = any(r["status"] == "BLOCKED" for r in results)

    if has_failed:
        log.error("PIPELINE FAILED -- scan error detected")
        sys.exit(2)

    if has_blocked:
        log.error(
            "PIPELINE FAILED -- blocking severity issues detected "
            "(%s)", ", ".join(USER_CONFIG["blocking_severities"])
        )
        sys.exit(1)

    log.info("PIPELINE PASSED -- no blocking issues detected")
    sys.exit(0)

# ---------------------------------------------------------
# Program entry point
# ---------------------------------------------------------
if __name__ == "__main__":
    main()
