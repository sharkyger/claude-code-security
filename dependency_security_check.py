#!/usr/bin/env python3
"""
Dependency Security Check — queries 3 vulnerability databases before any install.

Sources:
  1. OSV.dev (Google) — primary, supports version filtering natively, batch API for trees
  2. GitHub Advisory Database — supports version filtering via vulnerable_version_range
  3. NIST NVD — keyword search, filtered by CPE version match when available

Transitive dependency checking (default-on for pip + npm + composer + gem):
  Resolves the full transitive tree via the package manager's own dry-run mode,
  then batch-queries OSV. Use --no-deps to disable and check only the named
  package. Brew + other ecosystems use the legacy single-package path regardless.

Fresh-version hold (default-on for pip + npm, --min-age N):
  Holds packages whose latest release is younger than N days. Defends against
  typosquatting and zero-hour publish attacks where a malicious version is
  published minutes after credential theft, before any CVE database knows.
  Use --min-age 0 to disable.

Fail-closed posture (env var STRICT_FAIL_CLOSED=1):
  Default behaviour: CVE database lookups are best-effort. If OSV times out
  but GHSA + NVD return clean, we allow. Set STRICT_FAIL_CLOSED=1 to flip
  this — any DB error during a clean check becomes a hard block (exit 2).
  Useful for enterprise / CI postures that prefer false-blocks over
  false-allows when databases hiccup.

Usage:
  python3 dependency_security_check.py <ecosystem> <package_name> [version] [--no-deps] [--min-age N]

Ecosystems: pip, npm, composer, cargo, go, maven, gem, brew
Exit codes: 0 = clean, 1 = vulnerabilities or fresh-hold, 2 = resolver error / strict-fail-closed block

No API keys required. All three databases are free and public.
"""

import argparse
import datetime
import json
import os
import re
import ssl
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

# Build SSL context — use certifi bundle if available (needed on macOS)
try:
    import certifi

    SSL_CONTEXT = ssl.create_default_context(cafile=certifi.where())
except ImportError:
    SSL_CONTEXT = ssl.create_default_context()

USER_AGENT = "claude-code-security/1.1"

# Maximum NVD fallback calls for transitive deps that OSV reported as clean.
# Keeps worst-case latency bounded under the rate limit (5 req / 30s anonymous).
TRANSITIVE_NVD_BUDGET = 3

# Default minimum age (in days) for a published version before we accept it.
# Defends against typosquatting and zero-hour publish attacks where a malicious
# version is published minutes after credential theft, before any CVE database
# has learned about it. Override with --min-age 0 to disable.
DEFAULT_MIN_AGE_DAYS = 3


def _urlopen(req, timeout=15):
    """Open URL with proper SSL context."""
    return urllib.request.urlopen(req, timeout=timeout, context=SSL_CONTEXT)


def get_release_age_days(package_name, version, ecosystem):
    """Return integer days since the package version was published.

    Returns None if the lookup failed, the ecosystem isn't supported, or the
    registry doesn't expose a timestamp for this package/version. The caller
    must NOT interpret None as "old enough to install" — its policy on
    unknown-age packages is decided separately (we treat it as a warning,
    not a block).
    """
    try:
        if ecosystem == "pip":
            url = f"https://pypi.org/pypi/{urllib.parse.quote(package_name)}/{urllib.parse.quote(version)}/json"
            req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            with _urlopen(req, timeout=8) as resp:
                data = json.loads(resp.read())
            urls = data.get("urls", [])
            if not urls:
                return None
            # Stick to the timezone-aware ISO field. The naive `upload_time`
            # fallback would crash the tz-aware subtraction below.
            iso = urls[0].get("upload_time_iso_8601")
        elif ecosystem == "npm":
            url = f"https://registry.npmjs.org/{urllib.parse.quote(package_name)}"
            req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            with _urlopen(req, timeout=8) as resp:
                data = json.loads(resp.read())
            iso = data.get("time", {}).get(version)
        else:
            return None

        if not iso:
            return None
        dt = datetime.datetime.fromisoformat(iso.replace("Z", "+00:00"))
        return (datetime.datetime.now(datetime.UTC) - dt).days
    except (urllib.error.URLError, json.JSONDecodeError, TimeoutError, ValueError):
        return None


def check_min_age(package_name, version, ecosystem, min_age_days):
    """Return a hold dict if the package is too fresh; None otherwise.

    Only applies to pip + npm (the ecosystems we resolve transitively and where
    the registry exposes per-version publish timestamps). For other ecosystems
    or when min_age_days <= 0, returns None.

    If the registry lookup fails (network error, missing timestamp), we treat
    the age as unknown and return None — the caller logs a soft warning rather
    than blocking. Failing closed on every transient PyPI/npm hiccup would be
    too disruptive; the CVE checks remain authoritative.
    """
    if min_age_days <= 0 or ecosystem not in ("pip", "npm"):
        return None
    age = get_release_age_days(package_name, version, ecosystem)
    if age is None or age >= min_age_days:
        return None
    return {
        "package": package_name,
        "version": version,
        "ecosystem": ecosystem,
        "age_days": age,
        "min_age_days": min_age_days,
    }


# Map ecosystem names to each source's expected format
ECOSYSTEM_MAP = {
    "osv": {
        "pip": "PyPI",
        "npm": "npm",
        "composer": "Packagist",
        "cargo": "crates.io",
        "go": "Go",
        "maven": "Maven",
        "gem": "RubyGems",
        "brew": None,
    },
    "github": {
        "pip": "pip",
        "npm": "npm",
        "composer": "composer",
        "cargo": "rust",
        "go": "go",
        "maven": "maven",
        "gem": "rubygems",
        "brew": None,
    },
}


def resolve_latest_version(package_name, ecosystem):
    """Resolve the latest version of a package from its registry."""
    try:
        if ecosystem == "pip":
            url = f"https://pypi.org/pypi/{urllib.parse.quote(package_name)}/json"
            req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            with _urlopen(req, timeout=8) as resp:
                data = json.loads(resp.read())
            return data.get("info", {}).get("version")
        elif ecosystem == "npm":
            url = f"https://registry.npmjs.org/{urllib.parse.quote(package_name)}/latest"
            req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            with _urlopen(req, timeout=8) as resp:
                data = json.loads(resp.read())
            return data.get("version")
    except Exception:
        return None


def parse_version(v):
    """Parse a version string into a tuple for comparison."""
    if not v:
        return ()
    # Strip leading 'v' or '=' prefixes
    v = re.sub(r"^[v=]+", "", v.strip())
    parts = []
    for p in v.split("."):
        m = re.match(r"(\d+)", p)
        if m:
            parts.append(int(m.group(1)))
        else:
            parts.append(0)
    return tuple(parts)


def version_in_range(version, range_str):
    """Check if a version falls within a vulnerable version range.

    Supports GitHub Advisory range format: "< 1.2.3", ">= 1.0, < 2.0", etc.
    Returns True if the version IS affected (vulnerable).
    """
    if not version or not range_str:
        return True  # Can't determine — assume affected for safety

    v = parse_version(version)
    if not v:
        return True

    conditions = [c.strip() for c in range_str.split(",")]

    for cond in conditions:
        cond = cond.strip()
        if not cond:
            continue

        m = re.match(r"([<>=!]+)\s*([\d][\d.]*\w*)", cond)
        if not m:
            if parse_version(cond) == v:
                return True
            continue

        op, ref_str = m.group(1), m.group(2)
        ref = parse_version(ref_str)

        if (
            (op == "<" and not (v < ref))
            or (op == "<=" and not (v <= ref))
            or (op == ">" and not (v > ref))
            or (op == ">=" and not (v >= ref))
            or ((op == "=" or op == "==") and v != ref)
            or (op == "!=" and v == ref)
        ):
            return False

    return True


def query_osv(package_name, ecosystem, version=None):
    """Query OSV.dev — supports native version filtering."""
    findings = []
    osv_ecosystem = ECOSYSTEM_MAP["osv"].get(ecosystem)
    if not osv_ecosystem:
        return findings

    try:
        payload = {"package": {"name": package_name, "ecosystem": osv_ecosystem}}
        if version:
            payload["version"] = version
        body = json.dumps(payload).encode()
        req = urllib.request.Request(
            "https://api.osv.dev/v1/query",
            data=body,
            headers={"Content-Type": "application/json"},
        )
        with _urlopen(req) as resp:
            data = json.loads(resp.read())

        for vuln in data.get("vulns", []):
            severity_info = vuln.get("database_specific", {})
            severity = severity_info.get("severity", "UNKNOWN")

            for s in vuln.get("severity", []):
                if s.get("type") == "CVSS_V3" and "CRITICAL" in str(severity_info):
                    severity = "CRITICAL"

            aliases = vuln.get("aliases", [])
            cve_id = next((a for a in aliases if a.startswith("CVE-")), vuln.get("id", "unknown"))

            findings.append(
                {
                    "source": "OSV.dev",
                    "id": cve_id,
                    "severity": severity,
                    "score": 0,
                    "summary": vuln.get("summary", "No summary")[:200],
                }
            )
    except (urllib.error.URLError, json.JSONDecodeError, TimeoutError) as e:
        findings.append(
            {
                "source": "OSV.dev",
                "id": "ERROR",
                "severity": "UNKNOWN",
                "score": 0,
                "summary": f"Query failed: {e}",
            }
        )
    return findings


def query_github(package_name, ecosystem, version=None):
    """Query GitHub Advisory Database — filter by affected version range."""
    findings = []
    gh_ecosystem = ECOSYSTEM_MAP["github"].get(ecosystem)
    if not gh_ecosystem:
        return findings

    try:
        url = (
            f"https://api.github.com/advisories"
            f"?ecosystem={urllib.parse.quote(gh_ecosystem)}"
            f"&affects={urllib.parse.quote(package_name)}"
            f"&per_page=20"
        )
        req = urllib.request.Request(
            url,
            headers={"Accept": "application/vnd.github+json", "User-Agent": USER_AGENT},
        )
        with _urlopen(req) as resp:
            data = json.loads(resp.read())

        for adv in data:
            severity = adv.get("severity", "unknown").upper()

            if version:
                not_affected = False
                for vuln_pkg in adv.get("vulnerabilities", []):
                    pkg_info = vuln_pkg.get("package", {})
                    if pkg_info.get("name", "").lower() != package_name.lower():
                        continue
                    vrange = vuln_pkg.get("vulnerable_version_range", "")
                    patched = vuln_pkg.get("first_patched_version")
                    if isinstance(patched, dict):
                        patched_ver = patched.get("identifier")
                    elif isinstance(patched, str):
                        patched_ver = patched
                    else:
                        patched_ver = None

                    if patched_ver and parse_version(version) >= parse_version(patched_ver):
                        not_affected = True
                        break

                    if vrange and not version_in_range(version, vrange):
                        not_affected = True
                        break

                if not_affected:
                    continue

            findings.append(
                {
                    "source": "GitHub Advisory",
                    "id": adv.get("ghsa_id") or adv.get("cve_id", "unknown"),
                    "severity": severity,
                    "score": 0,
                    "summary": adv.get("summary", "No summary")[:200],
                }
            )
    except (urllib.error.URLError, json.JSONDecodeError, TimeoutError) as e:
        findings.append(
            {
                "source": "GitHub Advisory",
                "id": "ERROR",
                "severity": "UNKNOWN",
                "score": 0,
                "summary": f"Query failed: {e}",
            }
        )
    return findings


def query_nvd(package_name, ecosystem, version=None):
    """Query NIST NVD — keyword search with version filtering via CPE match."""
    findings = []

    # NVD keyword search is too noisy for short/ambiguous names
    if len(package_name) < 4:
        return findings

    try:
        url = (
            f"https://services.nvd.nist.gov/rest/json/cves/2.0"
            f"?keywordSearch={urllib.parse.quote(package_name)}"
            f"&keywordExactMatch"
            f"&resultsPerPage=10"
        )
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with _urlopen(req) as resp:
            data = json.loads(resp.read())

        for vuln in data.get("vulnerabilities", []):
            cve = vuln.get("cve", {})
            cve_id = cve.get("id", "unknown")

            # Skip disputed CVEs — upstream doesn't consider them valid
            vuln_status = cve.get("vulnStatus", "")
            if "DISPUTED" in vuln_status.upper() or "REJECTED" in vuln_status.upper():
                continue

            desc_list = cve.get("descriptions", [])
            desc = next((d["value"] for d in desc_list if d["lang"] == "en"), "No description")

            # Skip CVEs explicitly marked as disputed in description
            if desc.strip().startswith("** DISPUTED **"):
                continue

            # Filter out CVEs that mention the keyword but are about different software.
            # Use boundary matching that prevents "claude-code" from matching
            # "claude-code-router" — hyphens connect compound package names, so
            # the match must not be followed or preceded by [-\w].
            desc_lower = desc.lower()
            pkg_lower = package_name.lower()
            pkg_nodash = pkg_lower.replace("-", "")

            pkg_re = re.compile(r"(?<![a-z0-9\-])" + re.escape(pkg_lower) + r"(?![a-z0-9\-])")
            pkg_nodash_re = re.compile(r"(?<![a-z0-9])" + re.escape(pkg_nodash) + r"(?![a-z0-9])")

            if not pkg_re.search(desc_lower) and not pkg_nodash_re.search(desc_lower):
                continue

            # Reject if the first sentence names a different product as the subject
            first_sentence = desc.split(". ")[0].split(" is ")[0].split(" before ")[0].split(" through ")[0].strip()
            first_word = first_sentence.split()[0] if first_sentence.split() else ""
            first_lower = first_word.lower()
            if first_lower != pkg_lower and first_lower != pkg_nodash and not pkg_re.search(first_lower):
                continue

            severity = "UNKNOWN"
            score = 0.0
            for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                metrics = cve.get("metrics", {}).get(metric_key, [])
                if metrics:
                    cvss = metrics[0].get("cvssData", {})
                    severity = cvss.get("baseSeverity", severity)
                    score = cvss.get("baseScore", score)
                    break

            # Version filtering via CPE matches
            if version:
                affected = False
                has_cpe = False
                has_any_cpe = False
                # Distro-specific vendors whose package versions don't match upstream
                distro_vendors = {
                    "opensuse",
                    "suse",
                    "redhat",
                    "debian",
                    "ubuntu",
                    "canonical",
                    "fedoraproject",
                    "oracle",
                    "centos",
                }
                configurations = cve.get("configurations", [])
                for config in configurations:
                    for node in config.get("nodes", []):
                        for cpe in node.get("cpeMatch", []):
                            if not cpe.get("vulnerable", False):
                                continue
                            has_any_cpe = True
                            # Skip distro/OS-specific CPEs — their versions don't match upstream
                            cpe_str = cpe.get("criteria", "")
                            cpe_parts = cpe_str.split(":")
                            if len(cpe_parts) >= 5:
                                cpe_type = cpe_parts[2].lower()  # a=app, o=os, h=hw
                                cpe_vendor = cpe_parts[3].lower()
                                # OS-type CPEs are distro packages, not upstream
                                if cpe_type == "o":
                                    continue
                                if cpe_vendor in distro_vendors:
                                    continue
                            has_cpe = True
                            ver_end_exc = cpe.get("versionEndExcluding")
                            ver_end_inc = cpe.get("versionEndIncluding")
                            ver_start_inc = cpe.get("versionStartIncluding")
                            ver_start_exc = cpe.get("versionStartExcluding")

                            if ver_end_exc or ver_end_inc or ver_start_inc or ver_start_exc:
                                # Range-based CPE — check if our version falls within
                                in_range = True
                                if ver_start_inc and parse_version(version) < parse_version(ver_start_inc):
                                    in_range = False
                                if ver_start_exc and parse_version(version) <= parse_version(ver_start_exc):
                                    in_range = False
                                if ver_end_exc and parse_version(version) >= parse_version(ver_end_exc):
                                    in_range = False
                                if ver_end_inc and parse_version(version) > parse_version(ver_end_inc):
                                    in_range = False
                                if in_range:
                                    affected = True
                            else:
                                # Exact version match — extract from CPE URI
                                # Format: cpe:2.3:a:vendor:product:VERSION:...
                                cpe_str = cpe.get("criteria", "")
                                cpe_parts = cpe_str.split(":")
                                if len(cpe_parts) >= 6:
                                    cpe_ver = cpe_parts[5]
                                    if cpe_ver in ("*", "-", ""):
                                        affected = True  # Wildcard — can't determine
                                    elif parse_version(version) == parse_version(cpe_ver):
                                        affected = True

                # If CPE data exists and our version isn't in any affected range, skip
                if has_cpe and not affected:
                    continue

                # All CPEs were distro-specific — not relevant to upstream/Homebrew
                if has_any_cpe and not has_cpe:
                    continue

                # Fallback: if no CPE data, try to extract version range from description.
                # GitHub-style advisories often read "Starting in version X and prior to
                # version Y" — handle the optional "version"/"v" prefix and inclusive vs
                # exclusive boundaries.
                if not has_cpe:
                    v_re = r"(?:version\s+)?v?([\d]+(?:\.[\d]+)*)"

                    # Exclusive upper bound: fixed at the matched version
                    end_exc = re.search(
                        rf"(?:before|prior to|up to but not including|fixed in|patched in)\s+{v_re}",
                        desc,
                        re.IGNORECASE,
                    )
                    if end_exc:
                        upper = parse_version(end_exc.group(1))
                        if upper and parse_version(version) >= upper:
                            continue  # version is at or above the fix — not affected

                    # Inclusive upper bound: last affected version
                    end_inc = re.search(rf"\bthrough\s+{v_re}", desc, re.IGNORECASE)
                    if end_inc:
                        upper = parse_version(end_inc.group(1))
                        if upper and parse_version(version) > upper:
                            continue

                    # Lower bound: affected starts at this version
                    start_inc = re.search(
                        rf"(?:starting in|introduced in|since)\s+{v_re}",
                        desc,
                        re.IGNORECASE,
                    )
                    if start_inc:
                        lower = parse_version(start_inc.group(1))
                        if lower and parse_version(version) < lower:
                            continue

            findings.append(
                {
                    "source": "NIST NVD",
                    "id": cve_id,
                    "severity": severity,
                    "score": score,
                    "summary": desc[:200],
                }
            )
    except (urllib.error.URLError, json.JSONDecodeError, TimeoutError) as e:
        findings.append(
            {
                "source": "NIST NVD",
                "id": "ERROR",
                "severity": "UNKNOWN",
                "score": 0,
                "summary": f"Query failed: {e}",
            }
        )
    return findings


def deduplicate(findings):
    """Remove duplicate CVEs reported by multiple sources."""
    seen = set()
    unique = []
    for f in findings:
        if f["id"] in ("ERROR", "SKIP"):
            unique.append(f)
            continue
        if f["id"] not in seen:
            seen.add(f["id"])
            unique.append(f)
        else:
            for u in unique:
                if u["id"] == f["id"]:
                    u["source"] += f" + {f['source']}"
                    break
    return unique


def resolve_pip_deps(package_name, version=None):
    """Resolve the full transitive dependency tree for a pip package.

    Uses `pip install --dry-run --quiet --report=-` (pip 23.1+). Does not
    install anything. Returns list[(name, version)] with the top-level
    package as the first entry.

    Raises RuntimeError if pip is missing, the dry-run fails, or the
    resolution report is unparseable. Caller should treat that as a
    strict block (exit 2) — do not silently fall back.
    """
    spec = f"{package_name}=={version}" if version else package_name
    try:
        result = subprocess.run(  # noqa: S603 — args list, no shell, hardcoded executable
            ["pip", "install", "--dry-run", "--quiet", "--report=-", spec],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        raise RuntimeError(f"pip resolution failed: {e}") from e

    if result.returncode != 0:
        err = (result.stderr or "").strip() or (result.stdout or "").strip()
        raise RuntimeError(f"pip dry-run failed (exit {result.returncode}): {err[:300]}")

    try:
        report = json.loads(result.stdout)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"pip report not valid JSON: {e}") from e

    direct = []
    transitive = []
    for entry in report.get("install", []):
        meta = entry.get("metadata", {})
        name = (meta.get("name") or "").strip().lower()
        ver = meta.get("version")
        if not name or not ver:
            continue
        item = (name, ver)
        if entry.get("is_direct"):
            direct.append(item)
        else:
            transitive.append(item)

    return direct + transitive


def resolve_npm_deps(package_name, version=None):
    """Resolve the full transitive tree for an npm package.

    Uses `npm install --dry-run --no-save --json`. The --no-save flag
    prevents package.json mutation. Returns list[(name, version)] with
    the top-level package as the first entry.

    Raises RuntimeError on resolver failure — caller treats as strict block.
    """
    spec = f"{package_name}@{version}" if version else package_name
    try:
        result = subprocess.run(  # noqa: S603 — args list, no shell, hardcoded executable
            ["npm", "install", "--dry-run", "--no-save", "--json", spec],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        raise RuntimeError(f"npm resolution failed: {e}") from e

    if result.returncode != 0:
        err = (result.stderr or "").strip() or (result.stdout or "").strip()
        raise RuntimeError(f"npm dry-run failed (exit {result.returncode}): {err[:300]}")

    try:
        report = json.loads(result.stdout)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"npm report not valid JSON: {e}") from e

    # npm --json output has an "added" array with {name, version} per package.
    # Top-level position varies; we find the named package and put it first.
    direct = []
    transitive = []
    target = package_name.lower()
    for entry in report.get("added", []):
        name = (entry.get("name") or "").strip().lower()
        ver = entry.get("version")
        if not name or not ver:
            continue
        if name == target and not direct:
            direct.append((name, ver))
        else:
            transitive.append((name, ver))

    # Fall back: if pip-style "name" key wasn't matched, treat first entry as direct
    if not direct and transitive:
        direct = [transitive.pop(0)]

    return direct + transitive


def resolve_composer_deps(package_name, version=None):
    """Resolve the full transitive tree for a composer package.

    Creates a throwaway composer.json in a temp dir and runs
    `composer update --dry-run`. Parses "Locking <name> (<version>)"
    lines to extract the resolved set. Returns list[(name, version)]
    with the top-level package first.

    Raises RuntimeError on resolver failure — caller treats as strict block.
    """
    # Function-scope imports keep the auto-formatter from stripping these as
    # unused at module top — they're only needed by this single resolver and
    # the import cost on first call is negligible.
    import tempfile
    from pathlib import Path

    constraint = version or "*"
    # No `minimum-stability` key — composer's default is "stable", and pinning
    # it here would cause valid pre-release version specs to be rejected.
    manifest = {
        "name": "claude-code-security/dep-check",
        "require": {package_name: constraint},
        "prefer-stable": True,
    }

    with tempfile.TemporaryDirectory() as tmpdir:
        (Path(tmpdir) / "composer.json").write_text(json.dumps(manifest))
        try:
            result = subprocess.run(  # noqa: S603, S607 — args list, no shell, system composer is trusted
                [
                    "composer",
                    "update",
                    "--dry-run",
                    "--no-interaction",
                    "--no-progress",
                    "--working-dir",
                    tmpdir,
                ],
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            raise RuntimeError(f"composer resolution failed: {e}") from e

        if result.returncode != 0:
            err = (result.stderr or "").strip() or (result.stdout or "").strip()
            raise RuntimeError(f"composer dry-run failed (exit {result.returncode}): {err[:300]}")

    # Parse "Locking <name> (<version>)" — emitted once per resolved package.
    # Composer 2.x writes the operations log to stderr for `composer update`;
    # older 1.x and some commands use stdout. Scan both streams so the parser
    # works regardless of which stream the local composer version chose.
    pattern = re.compile(r"\bLocking\s+([\w./\-]+)\s+\(([\w.\-+]+)\)")
    direct = []
    transitive = []
    target = package_name.lower()
    combined_output = (result.stdout or "") + "\n" + (result.stderr or "")
    for line in combined_output.splitlines():
        m = pattern.search(line)
        if not m:
            continue
        name = m.group(1).lower()
        ver = m.group(2)
        if name == target and not direct:
            direct.append((name, ver))
        else:
            transitive.append((name, ver))

    if not direct and transitive:
        # Composer didn't emit the top-level by name — promote the first entry
        direct = [transitive.pop(0)]

    if not direct:
        raise RuntimeError(f"composer dry-run produced no resolved packages for {package_name}")

    return direct + transitive


def resolve_gem_deps(package_name, version=None):
    """Resolve the full transitive tree for a Ruby gem.

    Uses `gem install <pkg> --explain --no-doc --no-document` (RubyGems 2+).
    The --explain flag lists what would be installed without writing to disk.
    Returns list[(name, version)] with the top-level package first.

    Raises RuntimeError on resolver failure — caller treats as strict block.
    """
    cmd = ["gem", "install", package_name, "--explain", "--no-doc", "--no-document"]
    if version:
        cmd.extend(["-v", version])

    try:
        result = subprocess.run(  # noqa: S603, S607 — args list, no shell, system gem is trusted
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        raise RuntimeError(f"gem resolution failed: {e}") from e

    if result.returncode != 0:
        err = (result.stderr or "").strip() or (result.stdout or "").strip()
        raise RuntimeError(f"gem --explain failed (exit {result.returncode}): {err[:300]}")

    # Output format:
    #   Gems to install:
    #     <name>-<version>
    #     <name>-<version>
    # Version may contain dots and dashes (pre-releases like "1.0.0-pre"). The
    # split point is the LAST dash before a digit-led version segment.
    pattern = re.compile(r"^\s+([\w./\-]+?)-(\d[\w.\-+]*)\s*$")
    direct = []
    transitive = []
    target = package_name.lower()
    in_block = False
    for line in result.stdout.splitlines():
        if "Gems to install:" in line:
            in_block = True
            continue
        if not in_block:
            continue
        m = pattern.match(line)
        if not m:
            continue
        name = m.group(1).lower()
        ver = m.group(2)
        if name == target and not direct:
            direct.append((name, ver))
        else:
            transitive.append((name, ver))

    if not direct and transitive:
        direct = [transitive.pop(0)]

    if not direct:
        raise RuntimeError(f"gem --explain produced no resolved packages for {package_name}")

    return direct + transitive


def query_osv_batch(packages, ecosystem):
    """Batch-query OSV for many (name, version) pairs in a single POST.

    OSV's /v1/querybatch returns vuln IDs only (no severity/details). For
    packages that come back with vulns, we follow up with per-package
    /v1/query calls (via the existing query_osv) to get full details.
    Packages with no vulns require no follow-up.

    Args:
        packages: list[(name, version)]
        ecosystem: agency-system ecosystem name

    Returns:
        dict[(name, version)] -> list[finding] for packages with vulns.
        Packages with no vulns are NOT in the dict.

    Raises RuntimeError if the batch endpoint itself fails (network error,
    malformed response). Caller should treat as strict block.
    """
    if not packages:
        return {}
    osv_ecosystem = ECOSYSTEM_MAP["osv"].get(ecosystem)
    if not osv_ecosystem:
        return {}

    queries = [{"package": {"name": name, "ecosystem": osv_ecosystem}, "version": ver} for name, ver in packages]
    body = json.dumps({"queries": queries}).encode()

    try:
        req = urllib.request.Request(
            "https://api.osv.dev/v1/querybatch",
            data=body,
            headers={"Content-Type": "application/json"},
        )
        with _urlopen(req, timeout=20) as resp:
            data = json.loads(resp.read())
    except (urllib.error.URLError, json.JSONDecodeError, TimeoutError) as e:
        raise RuntimeError(f"OSV batch query failed: {e}") from e

    batch_results = data.get("results", [])
    if len(batch_results) != len(packages):
        # Misaligned response — can't trust positional mapping
        raise RuntimeError(f"OSV batch returned {len(batch_results)} results for {len(packages)} queries")

    vulnerable = []
    for (name, ver), result in zip(packages, batch_results, strict=False):
        if result.get("vulns"):
            vulnerable.append((name, ver))

    findings_by_pkg = {}
    for name, ver in vulnerable:
        findings = query_osv(name, ecosystem, ver)
        if findings:
            findings_by_pkg[(name, ver)] = findings

    return findings_by_pkg


def _print_findings(top_pkg, findings_by_pkg, errors, sources_checked):
    """Emit the human-readable report to stderr. Returns total vuln count + critical_high."""
    total_vulns = 0
    total_critical_high = 0
    severity_order = {
        "CRITICAL": 0,
        "HIGH": 1,
        "MEDIUM": 2,
        "LOW": 3,
        "MODERATE": 3,
        "UNKNOWN": 4,
    }

    for e in errors:
        print(f"  Warning: {e}", file=sys.stderr)

    if not findings_by_pkg:
        print(
            f"  No known vulnerabilities found ({sources_checked})",
            file=sys.stderr,
        )
        return 0, 0

    # Sort packages: top-level first, then by vuln count desc
    items = list(findings_by_pkg.items())
    items.sort(key=lambda kv: (kv[0] != top_pkg, -len(kv[1])))

    for (name, ver), vulns in items:
        vulns_sorted = sorted(vulns, key=lambda f: severity_order.get(f["severity"], 5))
        critical_high = [v for v in vulns_sorted if v["severity"] in ("CRITICAL", "HIGH")]
        total_vulns += len(vulns_sorted)
        total_critical_high += len(critical_high)
        marker = "[TOP-LEVEL]" if (name, ver) == top_pkg else "[transitive]"
        print(
            f"\n  {marker} {name}=={ver}: {len(vulns_sorted)} vulnerabilities ({len(critical_high)} critical/high)",
            file=sys.stderr,
        )
        for v in vulns_sorted:
            score_str = f" (CVSS {v['score']})" if v["score"] > 0 else ""
            print(f"    [{v['severity']}] {v['id']}{score_str}", file=sys.stderr)
            print(f"      Source: {v['source']}", file=sys.stderr)
            print(f"      {v['summary']}", file=sys.stderr)

    return total_vulns, total_critical_high


def _check_with_deps(ecosystem, package_name, version, min_age_days=0):
    """Transitive-checking path for pip + npm. Returns (status, details_dict).

    status: "clean" | "vulnerable" | "fresh"
    details_dict: full output structure ready for json.dump

    Raises RuntimeError on resolver or batch-query failure — caller exits 2.
    """
    print(
        f"  Resolving full transitive dependency tree for {package_name}...",
        file=sys.stderr,
    )

    if ecosystem == "pip":
        deps = resolve_pip_deps(package_name, version)
    elif ecosystem == "npm":
        deps = resolve_npm_deps(package_name, version)
    elif ecosystem == "composer":
        deps = resolve_composer_deps(package_name, version)
    elif ecosystem == "gem":
        deps = resolve_gem_deps(package_name, version)
    else:
        raise RuntimeError(f"Transitive resolution not implemented for: {ecosystem}")

    if not deps:
        raise RuntimeError(f"Resolver returned no packages for {package_name}")

    top_pkg = deps[0]
    transitive = deps[1:]
    # Update version from the resolver if it wasn't pinned on the CLI
    resolved_name, resolved_version = top_pkg

    print(
        f"  Resolved {len(deps)} packages ({len(transitive)} transitive). "
        f"Top-level: {resolved_name}=={resolved_version}",
        file=sys.stderr,
    )

    fresh_packages = []
    fresh = check_min_age(resolved_name, resolved_version, ecosystem, min_age_days)
    if fresh:
        fresh_packages.append(fresh)
        print(
            f"  Fresh-version hold: {resolved_name}=={resolved_version} is "
            f"{fresh['age_days']}d old (< --min-age {min_age_days}d). "
            f"Defends against zero-hour publish attacks. "
            f"Re-run with --min-age 0 if you need this version now.",
            file=sys.stderr,
        )

    print(
        "  Querying vulnerability databases...",
        file=sys.stderr,
    )

    findings_by_pkg = {}
    errors = []

    # 1. Top-level: full 3-source check (OSV + GHSA + NVD always)
    top_findings = []
    top_findings.extend(query_osv(resolved_name, ecosystem, resolved_version))
    top_findings.extend(query_github(resolved_name, ecosystem, resolved_version))
    top_findings.extend(query_nvd(resolved_name, ecosystem, resolved_version))

    top_errors = [f for f in top_findings if f["id"] in ("ERROR", "SKIP")]
    top_vulns = [f for f in top_findings if f["id"] not in ("ERROR", "SKIP")]
    for e in top_errors:
        errors.append(f"top-level {e['source']}: {e['summary']}")
    if top_vulns:
        findings_by_pkg[top_pkg] = deduplicate(top_vulns)

    # 2. Transitive: batch OSV (this raises on failure → strict block)
    if transitive:
        batch_findings = query_osv_batch(transitive, ecosystem)
        for pkg, vulns in batch_findings.items():
            real_vulns = [f for f in vulns if f["id"] not in ("ERROR", "SKIP")]
            if real_vulns:
                findings_by_pkg[pkg] = deduplicate(real_vulns)

        # 3. NVD fallback for transitive deps OSV reported as clean.
        # Bounded by TRANSITIVE_NVD_BUDGET to keep latency under rate limits.
        clean_transitive = [pkg for pkg in transitive if pkg not in batch_findings]
        for idx, (name, ver) in enumerate(clean_transitive):
            if idx >= TRANSITIVE_NVD_BUDGET:
                skipped = len(clean_transitive) - TRANSITIVE_NVD_BUDGET
                if skipped > 0:
                    errors.append(
                        f"NVD fallback budget exhausted: {skipped} transitive packages "
                        f"checked via OSV only (rate-limit guard)"
                    )
                break
            nvd_findings = query_nvd(name, ecosystem, ver)
            real = [f for f in nvd_findings if f["id"] not in ("ERROR", "SKIP")]
            nvd_errors = [f for f in nvd_findings if f["id"] in ("ERROR", "SKIP")]
            for e in nvd_errors:
                errors.append(f"transitive NVD ({name}): {e['summary']}")
            if real:
                existing = findings_by_pkg.get((name, ver), [])
                findings_by_pkg[(name, ver)] = deduplicate(existing + real)

    sources_checked = (
        f"OSV-batch on {len(deps)} packages, NVD+GHSA on top-level, "
        f"NVD fallback on first {TRANSITIVE_NVD_BUDGET} OSV-clean transitive"
    )
    total_vulns, total_critical_high = _print_findings(top_pkg, findings_by_pkg, errors, sources_checked)

    # Build output JSON
    flat_vulns = []
    for (name, ver), vulns in findings_by_pkg.items():
        for v in vulns:
            flat_vulns.append({**v, "package": name, "version": ver})

    if not flat_vulns and not fresh_packages:
        return "clean", {
            "status": "clean",
            "package": resolved_name,
            "ecosystem": ecosystem,
            "version": resolved_version,
            "include_deps": True,
            "transitive_count": len(transitive),
            "vulnerabilities": [],
            "fresh_packages": [],
            "errors": errors,
        }

    # Vulnerabilities outrank freshness — known CVE wins the status label.
    status = "vulnerable" if flat_vulns else "fresh"
    return status, {
        "status": status,
        "package": resolved_name,
        "ecosystem": ecosystem,
        "version": resolved_version,
        "include_deps": True,
        "transitive_count": len(transitive),
        "count": total_vulns,
        "critical_high": total_critical_high,
        "vulnerabilities": flat_vulns,
        "fresh_packages": fresh_packages,
        "errors": errors,
    }


def _check_single(ecosystem, package_name, version, min_age_days=0):
    """Legacy single-package path. Returns (status, details_dict)."""
    print(
        "  Querying 3 vulnerability databases (NVD + OSV + GitHub)...\n",
        file=sys.stderr,
    )

    fresh_packages = []
    # Freshness gate is intentionally skipped when version is None — there is
    # nothing concrete to date-check. Caller in main() resolves the latest
    # version before dispatching, so this branch is rare in practice.
    if version:
        fresh = check_min_age(package_name, version, ecosystem, min_age_days)
        if fresh:
            fresh_packages.append(fresh)
            print(
                f"  Fresh-version hold: {package_name}=={version} is "
                f"{fresh['age_days']}d old (< --min-age {min_age_days}d). "
                f"Defends against zero-hour publish attacks. "
                f"Re-run with --min-age 0 if you need this version now.\n",
                file=sys.stderr,
            )

    all_findings = []
    all_findings.extend(query_osv(package_name, ecosystem, version))
    all_findings.extend(query_github(package_name, ecosystem, version))
    all_findings.extend(query_nvd(package_name, ecosystem, version))

    errors = [f for f in all_findings if f["id"] in ("ERROR", "SKIP")]
    vulns = [f for f in all_findings if f["id"] not in ("ERROR", "SKIP")]
    vulns = deduplicate(vulns)

    severity_order = {
        "CRITICAL": 0,
        "HIGH": 1,
        "MEDIUM": 2,
        "LOW": 3,
        "MODERATE": 3,
        "UNKNOWN": 4,
    }
    vulns.sort(key=lambda f: severity_order.get(f["severity"], 5))

    for e in errors:
        print(f"  Warning: {e['source']}: {e['summary']}", file=sys.stderr)

    # Normalize errors to strings for the output dict — same shape as
    # _check_with_deps so consumers (the audit log, the fail-closed gate)
    # see a consistent type across both paths.
    error_strs = [f"{e['source']}: {e['summary']}" for e in errors]

    if not vulns:
        sources_ok = 3 - len(errors)
        print(
            f"  No known vulnerabilities found ({sources_ok}/3 sources checked)",
            file=sys.stderr,
        )
        if not fresh_packages:
            return "clean", {
                "status": "clean",
                "package": package_name,
                "ecosystem": ecosystem,
                "version": version,
                "vulnerabilities": [],
                "fresh_packages": [],
                "errors": error_strs,
            }
        return "fresh", {
            "status": "fresh",
            "package": package_name,
            "ecosystem": ecosystem,
            "version": version,
            "vulnerabilities": [],
            "fresh_packages": fresh_packages,
            "errors": error_strs,
        }

    critical_high = [v for v in vulns if v["severity"] in ("CRITICAL", "HIGH")]
    print(
        f"  {len(vulns)} vulnerabilities found ({len(critical_high)} critical/high):\n",
        file=sys.stderr,
    )

    for v in vulns:
        severity_label = v["severity"]
        score_str = f" (CVSS {v['score']})" if v["score"] > 0 else ""
        print(f"  [{severity_label}] {v['id']}{score_str}", file=sys.stderr)
        print(f"    Source: {v['source']}", file=sys.stderr)
        print(f"    {v['summary']}\n", file=sys.stderr)

    return "vulnerable", {
        "status": "vulnerable",
        "package": package_name,
        "ecosystem": ecosystem,
        "version": version,
        "count": len(vulns),
        "critical_high": len(critical_high),
        "vulnerabilities": vulns,
        "fresh_packages": fresh_packages,
        "errors": error_strs,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Pre-install vulnerability gate. Checks a package + its transitive deps "
        "against OSV, GitHub Advisory, and NVD before install.",
    )
    parser.add_argument("ecosystem", help="One of: pip, npm, composer, cargo, go, maven, gem, brew")
    parser.add_argument("package", help="Package name to check")
    parser.add_argument("version", nargs="?", default=None, help="Version (resolved from registry if omitted)")
    parser.add_argument(
        "--no-deps",
        action="store_true",
        help="Skip transitive dependency resolution (pip + npm only). By default, transitive deps are checked.",
    )
    parser.add_argument(
        "--min-age",
        type=int,
        default=DEFAULT_MIN_AGE_DAYS,
        metavar="N",
        help=(
            f"Hold packages whose latest release is younger than N days "
            f"(pip + npm only). Defends against typosquatting and zero-hour "
            f"publish attacks. Default: {DEFAULT_MIN_AGE_DAYS}. "
            f"Use --min-age 0 to disable."
        ),
    )
    args = parser.parse_args()

    ecosystem = args.ecosystem.lower()
    package_name = args.package
    version = args.version

    # Input validation — prevent SSRF via crafted package names and shell metachars
    # via crafted versions (we pass them to subprocess as args, but defense in depth).
    if not re.match(r"^[a-zA-Z0-9@._/\-]+$", package_name):
        print(f"Invalid package name: {package_name}", file=sys.stderr)
        sys.exit(2)
    if version and not re.match(r"^[a-zA-Z0-9._\-+]+$", version):
        print(f"Invalid version: {version}", file=sys.stderr)
        sys.exit(2)

    valid_ecosystems = ["pip", "npm", "composer", "cargo", "go", "maven", "gem", "brew"]
    if ecosystem not in valid_ecosystems:
        print(
            f"Unknown ecosystem: {ecosystem}. Valid: {', '.join(valid_ecosystems)}",
            file=sys.stderr,
        )
        sys.exit(2)

    if not version:
        version = resolve_latest_version(package_name, ecosystem)

    print(f"\nSecurity check: {package_name} ({ecosystem})", file=sys.stderr)
    if version:
        print(f"  Version: {version}", file=sys.stderr)
    else:
        print("  Version: unknown (checking all known CVEs)", file=sys.stderr)

    # Dispatch: transitive path for ecosystems we can resolve. pip + npm need
    # a known version (we use it for OSV before the resolver runs); composer
    # and gem self-resolve from a "*" constraint, no pre-pinning needed.
    can_check_deps = not args.no_deps and (
        (ecosystem in ("pip", "npm") and version is not None) or ecosystem in ("composer", "gem")
    )

    if can_check_deps:
        try:
            status, output = _check_with_deps(ecosystem, package_name, version, args.min_age)
        except RuntimeError as e:
            print(
                f"\n  BLOCKED: transitive dependency resolution failed.\n"
                f"  Reason: {e}\n"
                f"  To proceed without transitive checking (less safe), re-run with --no-deps.",
                file=sys.stderr,
            )
            sys.exit(2)
    else:
        status, output = _check_single(ecosystem, package_name, version, args.min_age)

    # STRICT_FAIL_CLOSED upgrades a clean-with-DB-errors result to a hard block.
    # Normal posture: CVE checks are best-effort; if OSV times out but GHSA + NVD
    # came back clean, we allow. Strict posture (env var = "1"/"true"/"yes"):
    # ANY DB error during a clean lookup blocks the install. Used by enterprise
    # setups that prefer false-blocks over false-allows when databases hiccup.

    fail_closed = os.environ.get("STRICT_FAIL_CLOSED", "").lower() in ("1", "true", "yes")
    if status == "clean" and fail_closed and output.get("errors"):
        output["status"] = "error"
        output["fail_closed"] = True
        print(
            "\n  BLOCKED: STRICT_FAIL_CLOSED=1 and at least one vulnerability "
            "database returned an error. Cannot determine safety with the "
            "configured strict posture. Set STRICT_FAIL_CLOSED=0 to fall back "
            "to best-effort allow.",
            file=sys.stderr,
        )
        json.dump(output, sys.stdout)
        sys.exit(2)

    json.dump(output, sys.stdout)
    sys.exit(0 if status == "clean" else 1)


if __name__ == "__main__":
    main()
