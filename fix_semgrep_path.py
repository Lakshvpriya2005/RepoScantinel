import sys, re, pathlib, sysconfig, os

SCANNER = pathlib.Path(r"C:\Users\vlpri\Downloads\ReposSantinelnew\backend\scanner.py")

src = SCANNER.read_text(encoding="utf-8")

OLD_FUNC = '''def _get_executable(name: str) -> str:
    """Resolve executable path reliably relative to the active Python environment."""
    script_dir = os.path.dirname(sys.executable)
    exe_name = f"{name}.exe" if os.name == 'nt' else name
    exe_path = os.path.join(script_dir, exe_name)
    if os.path.exists(exe_path):
        return exe_path
    
    import shutil
    return shutil.which(name) or name'''

NEW_FUNC = '''def _get_executable(name: str) -> str:
    """Resolve executable path reliably relative to the active Python environment, including user site-packages."""
    import sysconfig
    
    exe_name = f"{name}.exe" if os.name == 'nt' else name
    
    # 1. Check same dir as python executable
    script_dir = os.path.dirname(sys.executable)
    exe_path = os.path.join(script_dir, exe_name)
    if os.path.exists(exe_path):
        return exe_path
        
    # 2. Check user site-packages scripts (where pip install --user puts it on Windows)
    try:
        user_scripts = sysconfig.get_path("scripts", f"{os.name}_user")
        if user_scripts:
            exe_path = os.path.join(user_scripts, exe_name)
            if os.path.exists(exe_path):
                return exe_path
    except Exception:
        pass
        
    # 3. Check global site-packages scripts
    try:
        global_scripts = sysconfig.get_path("scripts")
        if global_scripts:
            exe_path = os.path.join(global_scripts, exe_name)
            if os.path.exists(exe_path):
                return exe_path
    except Exception:
        pass

    import shutil
    return shutil.which(name) or name'''

old_lf = OLD_FUNC.replace("\r\n", "\n")
new_lf = NEW_FUNC.replace("\r\n", "\n")
src_lf = src.replace("\r\n", "\n")

if old_lf in src_lf:
    src_lf = src_lf.replace(old_lf, new_lf, 1)
    SCANNER.write_text(src_lf, encoding="utf-8")
    print("✅ Successfully patched _get_executable in scanner.py to find pip installed scripts!")
else:
    print("⚠️ Could not find _get_executable block to patch. It may have already been patched or modified.")
