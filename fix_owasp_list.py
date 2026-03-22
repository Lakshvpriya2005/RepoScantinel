"""
fix_owasp_list.py — Normalize Semgrep OWASP list values in scanner.py

Semgrep metadata.owasp is sometimes a list like:
  ["A03:2021 – Injection", "A07:2021 – ..."]

This means each finding's 'owasp' field might be a list, which crashes
anything that uses it as a dict key (unhashable type: 'list').

Fix: wherever we read metadata.get('owasp', ...) in scanner.py,
normalize the value to a string immediately.
"""
import pathlib, sys

SCANNER = pathlib.Path(
    r"C:\Users\vlpri\Downloads\ReposSantinelnew\backend\scanner.py"
)

src = SCANNER.read_text(encoding="utf-8")

# ── Helper function to add at top of file (after imports) ────────────────────
NORMALIZE_HELPER = '''
def _norm_str(val, default=""):
    """Normalize a value that might be a list or None into a plain string."""
    if val is None:
        return default
    if isinstance(val, list):
        return val[0] if val else default
    return str(val)

'''

# ── Fix 1: add helper after the logger line ───────────────────────────────────
OLD_LOGGER = "logger = logging.getLogger(__name__)\n"
if OLD_LOGGER in src and "_norm_str" not in src:
    src = src.replace(OLD_LOGGER, OLD_LOGGER + NORMALIZE_HELPER, 1)
    print("  ✅ Added _norm_str helper")
else:
    print("  ℹ️  Helper already present or logger line not found — skipping")

# ── Fix 2: normalize _owasp_meta when reading Semgrep metadata ────────────────
OLD_META = 'cwe_from_meta  = metadata.get("cwe", metadata.get("cwe-id", ""))\n        owasp_from_meta = metadata.get("owasp", "")'
NEW_META = 'cwe_from_meta  = _norm_str(metadata.get("cwe", metadata.get("cwe-id", "")))\n        owasp_from_meta = _norm_str(metadata.get("owasp", ""))'

if OLD_META in src:
    src = src.replace(OLD_META, NEW_META, 1)
    print("  ✅ Fixed owasp normalization in Semgrep result parsing")
else:
    # Try single-quote variant
    OLD_META2 = "cwe_from_meta  = metadata.get('cwe', metadata.get('cwe-id', ''))\n        owasp_from_meta = metadata.get('owasp', '')"
    NEW_META2 = "cwe_from_meta  = _norm_str(metadata.get('cwe', metadata.get('cwe-id', '')))\n        owasp_from_meta = _norm_str(metadata.get('owasp', ''))"
    if OLD_META2 in src:
        src = src.replace(OLD_META2, NEW_META2, 1)
        print("  ✅ Fixed owasp normalization in Semgrep result parsing (single-quote variant)")
    else:
        print("  ⚠️  Could not find owasp metadata read — patching inline with broader replace")
        # Broader fix: replace any metadata.get("owasp"...) assignment
        import re
        src = re.sub(
            r'owasp_from_meta\s*=\s*metadata\.get\(["\']owasp["\'][^)]*\)',
            '_norm_str(metadata.get("owasp", ""))',
            src
        )
        src = re.sub(
            r'cwe_from_meta\s*=\s*metadata\.get\(["\']cwe["\']',
            '_norm_str(metadata.get("cwe"',
            src
        )
        print("  ✅ Applied broader regex replacement")

# ── Fix 3: normalize in enrich_finding where _owasp_meta is applied ──────────
OLD_ENRICH = "if f.get('_owasp_meta'):\n            f['owasp'] = f['_owasp_meta']"
NEW_ENRICH = "if f.get('_owasp_meta'):\n            f['owasp'] = _norm_str(f['_owasp_meta'])"
if OLD_ENRICH in src:
    src = src.replace(OLD_ENRICH, NEW_ENRICH, 1)
    print("  ✅ Fixed owasp normalization in enrich_finding application")
else:
    print("  ℹ️  enrich_finding owasp apply block not found — may use different pattern")

# ── Also fix the 'owasp' field set in enrich_finding from KB ─────────────────
# The KB always returns strings so that's fine. But the _DEFAULT_KB owasp is already a string.

SCANNER.write_text(src, encoding="utf-8")
print(f"\n✅ Done — scanner.py patched ({SCANNER.stat().st_size} bytes)")
print("   Restart python app.py to pick up changes.")
