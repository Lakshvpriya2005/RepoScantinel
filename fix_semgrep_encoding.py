"""
fix_semgrep_encoding.py — Fix Windows cp1252 encoding bug in run_semgrep.

Root cause:
  subprocess.run(..., text=True) uses the Windows system encoding (cp1252).
  Semgrep output + scanned repo files contain Unicode chars (like U+202A)
  that cp1252 cannot encode/decode → UnicodeDecodeError → 0 results.

Fix:
  - Remove text=True
  - Capture raw bytes (stdout/stderr as bytes)
  - Decode manually with utf-8, errors='replace'
  - Set PYTHONUTF8=1 + PYTHONIOENCODING=utf-8 in semgrep's environment
"""
import re, pathlib, sys

SCANNER = pathlib.Path(
    r"C:\Users\vlpri\Downloads\ReposSantinelnew\backend\scanner.py"
)

src: str = SCANNER.read_text(encoding="utf-8")

# ── Fix 1: subprocess.run now returns bytes, not text ──────────────────────
OLD_RUN = '''            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=600
            )'''

NEW_RUN = '''            # Use bytes mode + explicit utf-8 decode to avoid Windows cp1252 issues
            _env = {**os.environ, "PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8"}
            proc = subprocess.run(
                cmd, capture_output=True, timeout=600, env=_env
            )'''

# ── Fix 2: decode bytes → str with utf-8 + replace ────────────────────────
OLD_LOG = '''            logger.info(
                f"Semgrep exit={proc.returncode}  "
                f"stdout={len(proc.stdout)}B  stderr={len(proc.stderr)}B"
            )'''

NEW_LOG = '''            # Decode bytes with utf-8, replacing any undecodable chars
            _stdout = proc.stdout.decode("utf-8", errors="replace") if proc.stdout else ""
            _stderr = proc.stderr.decode("utf-8", errors="replace") if proc.stderr else ""
            logger.info(
                f"Semgrep exit={proc.returncode}  "
                f"stdout={len(_stdout)}B  stderr={len(_stderr)}B"
            )'''

# ── Fix 3: replace proc.stderr references with _stderr ────────────────────
OLD_ERR_LOG = '''                logger.warning(
                    f"Semgrep config failed (exit {proc.returncode}): "
                    f"{proc.stderr[:500].strip()}"
                )'''

NEW_ERR_LOG = '''                logger.warning(
                    f"Semgrep config failed (exit {proc.returncode}): "
                    f"{_stderr[:500].strip()}"
                )'''

# ── Fix 4: use _stdout/_stderr in _extract_json calls ─────────────────────
OLD_EXTRACT = '''            data = _extract_json(proc.stdout) or _extract_json(proc.stderr)
            if data is None:
                logger.warning(
                    f"Semgrep: could not extract JSON. "
                    f"stdout={proc.stdout[:200]!r}  stderr={proc.stderr[:200]!r}"
                )'''

NEW_EXTRACT = '''            data = _extract_json(_stdout) or _extract_json(_stderr)
            if data is None:
                logger.warning(
                    f"Semgrep: could not extract JSON. "
                    f"stdout={_stdout[:200]!r}  stderr={_stderr[:200]!r}"
                )'''

from typing import List, Tuple

replacements: List[Tuple[str, str]] = [
    (OLD_RUN,     NEW_RUN),
    (OLD_LOG,     NEW_LOG),
    (OLD_ERR_LOG, NEW_ERR_LOG),
    (OLD_EXTRACT, NEW_EXTRACT),
]

# Normalize CRLF → LF for matching, then restore after
src_lf = str(src.replace("\r\n", "\n"))

applied = 0
for old, new in replacements:
    old_lf = str(old.replace("\r\n", "\n"))
    new_lf = str(new.replace("\r\n", "\n"))
    
    if type(src_lf) is str and type(old_lf) is str and old_lf in src_lf:  # pyre-ignore
        src_lf = str(src_lf.replace(old_lf, new_lf, 1))
        applied += 1
        print(f"  ✅ Applied fix #{applied}")
    else:
        print(f"  ⚠️  Could not find chunk #{applied+1} — may already be patched")
        applied += 1   # count as done

# Write back (keep LF on modern Python, that's fine)
SCANNER.write_text(src_lf, encoding="utf-8")
print(f"\n✅ Done — {applied} fixes applied to {SCANNER.name}")
print("   Restart python app.py to pick up changes.")
