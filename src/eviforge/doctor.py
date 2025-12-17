import shutil
import subprocess
import sys
import importlib
import requests
from typing import Dict, Any, List

def check_binary(name: str) -> Dict[str, Any]:
    path = shutil.which(name)
    return {
        "ok": path is not None,
        "path": path,
        "details": f"Found at {path}" if path else "Not found in PATH"
    }

def check_python_module(name: str) -> Dict[str, Any]:
    try:
        importlib.import_module(name)
        return {"ok": True, "details": "Imported successfully"}
    except ImportError:
        return {"ok": False, "details": "ImportError"}

def check_tika(url: str = "http://tika:9998/tika") -> Dict[str, Any]:
    # Try localhost if generic hostname fails (helper for local doctor run)
    try:
        r = requests.get(url, timeout=2)
        if r.status_code == 200:
             return {"ok": True, "details": f"Connected to {url} (200 OK)"}
    except:
        pass
    
    # Try versions
    for u in [url, "http://127.0.0.1:9998/tika", "http://tika:9998/version"]:
        try:
            r = requests.get(u, timeout=1)
            if r.status_code in [200, 405, 400]: 
                return {"ok": True, "details": f"Connected to {u} ({r.status_code})"}
        except:
            continue
    return {"ok": False, "details": "Connection failed"}

def run_doctor() -> Dict[str, Any]:
    checks = []
    
    # SYSTEM BINARIES
    for bin in ["file", "strings", "sha256sum", "exiftool", "yara", "tshark", "foremost", "bulk_extractor"]:
        res = check_binary(bin)
        res["name"] = f"binary:{bin}"
        checks.append(res)
        
    # PYTHON MODULES
    # Some are standard, some external
    for mod in ["Evtx.Evtx", "Registry", "yara", "pyshark"]:
        # Note: 'Evtx' is python-evtx? check import name. Usually 'Evtx.Evtx' or similar.
        # python-registry -> 'Registry'
        # yara-python -> 'yara'
        res = check_python_module(mod)
        res["name"] = f"python:{mod}"
        checks.append(res)

    # SERVICES
    res_tika = check_tika()
    res_tika["name"] = "service:tika"
    checks.append(res_tika)

    all_ok = all(c["ok"] for c in checks)
    return {
        "ok": all_ok,
        "checks": checks
    }
