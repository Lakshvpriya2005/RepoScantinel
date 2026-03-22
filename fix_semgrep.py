"""
One-shot script: patch the run_semgrep function in scanner.py
Run from anywhere:  python fix_semgrep.py
"""
import re, pathlib, sys

SCANNER_PATH = pathlib.Path(
    r"C:\Users\vlpri\Downloads\ReposSantinelnew\backend\scanner.py"
)

NEW_FUNC = '''def run_semgrep(repo_path: str) -> List[Dict]:
    """
    Run Semgrep on repo_path.  ALWAYS runs, regardless of language.

    Strategy (tries in order until one produces results):
      1. --config auto             (best rules, needs network first time)
      2. --config p/python --config p/security-audit --config p/secrets
      3. --config p/default        (minimal, always available)

    Key fixes:
    - NO --quiet  (that flag can swallow the JSON output block)
    - --error exits 0/1 on success, >=2 on real errors
    - Captures stdout AND stderr and scans both for the JSON block
    - Meaningful logs at every stage so you can see exactly what failed
    """

    SEV_MAP = {
        "ERROR":    "HIGH",
        "WARNING":  "MEDIUM",
        "INFO":     "LOW",
        "HIGH":     "HIGH",
        "MEDIUM":   "MEDIUM",
        "LOW":      "LOW",
        "CRITICAL": "CRITICAL",
    }

    # Try these configs in order
    CONFIGS_TO_TRY = [
        ["--config", "auto"],
        ["--config", "p/python", "--config", "p/security-audit", "--config", "p/secrets"],
        ["--config", "p/default"],
    ]

    def _extract_json(text: str):
        """Pull the first {...} JSON block out of mixed output."""
        if not text:
            return None
        idx = text.find("{")
        if idx == -1:
            return None
        try:
            return json.loads(text[idx:])
        except json.JSONDecodeError:
            pass
        # Line-by-line fallback
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("{"):
                try:
                    return json.loads(line)
                except Exception:
                    continue
        return None

    def _try_config(config_args: list):
        """Run semgrep with config_args; return raw results list or None."""
        cmd = [
            "semgrep",
            *config_args,
            "--json",          # output JSON
            "--error",         # exit 1 when findings found, >=2 on real errors
            "--timeout", "60",
            "--max-memory", "2000",
            "--jobs", "2",
            repo_path,
        ] + EXCLUDE_PATH_FLAGS_SEMGREP

        logger.info(f"Semgrep trying: {config_args}")
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=600
            )
            logger.info(
                f"Semgrep exit={proc.returncode}  "
                f"stdout={len(proc.stdout)}B  stderr={len(proc.stderr)}B"
            )

            if proc.returncode >= 2:
                # Real configuration / network error — log it and try next
                logger.warning(
                    f"Semgrep config failed (exit {proc.returncode}): "
                    f"{proc.stderr[:500].strip()}"
                )
                return None

            # exit 0 = no findings, exit 1 = findings found — both have JSON
            data = _extract_json(proc.stdout) or _extract_json(proc.stderr)
            if data is None:
                logger.warning(
                    f"Semgrep: could not extract JSON. "
                    f"stdout={proc.stdout[:200]!r}  stderr={proc.stderr[:200]!r}"
                )
                return None

            results = data.get("results", [])
            logger.info(f"Semgrep raw results with {config_args[1]}: {len(results)}")
            return results

        except subprocess.TimeoutExpired:
            logger.warning(f"Semgrep timed out with {config_args}")
            return None
        except FileNotFoundError:
            logger.error("semgrep not found — install: pip install semgrep")
            raise   # Don\'t try other configs; semgrep itself is missing
        except Exception as exc:
            logger.warning(f"Semgrep unexpected error: {exc}")
            return None

    # ── Try each strategy ────────────────────────────────────────────────────
    raw_results = None
    for config_args in CONFIGS_TO_TRY:
        try:
            raw_results = _try_config(config_args)
        except FileNotFoundError:
            return []   # semgrep not installed at all
        if raw_results is not None:
            logger.info(f"Semgrep succeeded with: {config_args}")
            break
        logger.info(f"Config {config_args} produced nothing — trying next")

    if raw_results is None:
        logger.error("All Semgrep strategies exhausted — 0 findings returned")
        return []

    # ── Parse results ────────────────────────────────────────────────────────
    findings = []
    for issue in raw_results:
        extra    = issue.get("extra", {})
        raw_sev  = extra.get("severity", "WARNING").upper()
        if raw_sev not in SEV_MAP:
            raw_sev = extra.get("metadata", {}).get("confidence", "WARNING").upper()
        severity = SEV_MAP.get(raw_sev, "MEDIUM")

        rel_file = issue.get("path", "")
        if rel_file.startswith(repo_path):
            rel_file = rel_file[len(repo_path):].lstrip("/\\\\")

        # Skip test / doc / build directories
        rel_lower = rel_file.lower().replace("\\\\", "/")
        if any(
            f"/{skip}/" in f"/{rel_lower}" or rel_lower.startswith(f"{skip}/")
            for skip in ["tests", "test", "examples", "docs", "build", "fixtures"]
        ):
            continue

        check_id = issue.get("check_id", "")
        message  = extra.get("message", check_id)
        metadata = extra.get("metadata", {})

        findings.append({
            "file":           rel_file,
            "line_number":    issue.get("start", {}).get("line", 0),
            "severity":       severity,
            "confidence":     "MEDIUM",
            "issue_text":     message,
            "test_id":        check_id,
            "scanner_source": "semgrep",
            "_cwe_meta":      metadata.get("cwe", metadata.get("cwe-id", "")),
            "_owasp_meta":    metadata.get("owasp", ""),
        })

    logger.info(f"Semgrep found {len(findings)} issues after filtering")
    return findings

'''

src = SCANNER_PATH.read_text(encoding="utf-8")

# Match from 'def run_semgrep' up to (but not including) the next top-level 'def '
pattern = re.compile(
    r"(def run_semgrep\(repo_path.*?)(\n# ─+\n# Deduplication)",
    re.DOTALL,
)

if not pattern.search(src):
    # Fallback: match from def run_semgrep to next def at column 0
    pattern = re.compile(
        r"(def run_semgrep\(repo_path.*?)(^def )",
        re.DOTALL | re.MULTILINE,
    )

m = pattern.search(src)
if m is None:
    print("ERROR: Could not locate run_semgrep function — check scanner.py manually")
    sys.exit(1)

if m is not None:
    func_start = m.start(1)
    func_end = m.start(2)
    new_src = src[:func_start] + NEW_FUNC + src[func_end:]
    SCANNER_PATH.write_text(new_src, encoding="utf-8")
    print(f"✅ Patched {SCANNER_PATH}")
    print(f"   Old run_semgrep: {len(m.group(1))} chars → New: {len(NEW_FUNC)} chars")
