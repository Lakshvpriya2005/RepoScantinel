import pathlib

SCANNER = pathlib.Path(r"C:\Users\vlpri\Downloads\ReposSantinelnew\backend\scanner.py")
src = SCANNER.read_text(encoding="utf-8")

OLD = '''            # Use bytes mode + explicit utf-8 decode to avoid Windows cp1252 issues
            _env = {**os.environ, "PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8"}
            proc = subprocess.run('''

NEW = '''            # Use bytes mode + explicit utf-8 decode to avoid Windows cp1252 issues
            _env = {**os.environ, "PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8"}
            import sysconfig
            _user_scripts = sysconfig.get_path("scripts", f"{os.name}_user")
            _global_scripts = sysconfig.get_path("scripts")
            _paths = _env.get("PATH", "")
            if _user_scripts and os.path.exists(_user_scripts):
                _paths = _user_scripts + os.pathsep + _paths
            if _global_scripts and os.path.exists(_global_scripts):
                _paths = _global_scripts + os.pathsep + _paths
            _env["PATH"] = _paths
            proc = subprocess.run('''

old_lf = OLD.replace("\r\n", "\n")
new_lf = NEW.replace("\r\n", "\n")
src_lf = src.replace("\r\n", "\n")

if old_lf in src_lf:
    src_lf = src_lf.replace(old_lf, new_lf, 1)
    SCANNER.write_text(src_lf, encoding="utf-8")
    print("Successfully added Scripts directory to PATH for Semgrep.")
else:
    print("Could not find environment block. Was it already patched?")
