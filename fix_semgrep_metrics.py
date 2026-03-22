import pathlib

SCANNER = pathlib.Path(r"C:\Users\vlpri\Downloads\ReposSantinelnew\backend\scanner.py")

src = SCANNER.read_text(encoding="utf-8")

OLD = '''            "--jobs", "2",              # fewer jobs = less memory pressure
            "--metrics", "off",         # no telemetry network calls
            "--no-git-ignore",           # don't wait for git index — faster'''

NEW = '''            "--jobs", "2",              # fewer jobs = less memory pressure
            "--no-git-ignore",           # don't wait for git index — faster'''

old_lf = OLD.replace("\r\n", "\n")
new_lf = NEW.replace("\r\n", "\n")
src_lf = src.replace("\r\n", "\n")

if old_lf in src_lf:
    src_lf = src_lf.replace(old_lf, new_lf, 1)
    # Ensure any trailing newlines are handled
    SCANNER.write_text(src_lf, encoding="utf-8")
    print("✅ Successfully patched duplicate --metrics in scanner.py")
else:
    print("⚠️ Could not find duplicate --metrics block. Was it already patched?")
