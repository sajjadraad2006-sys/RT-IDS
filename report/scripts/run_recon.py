import os
import json
from pathlib import Path

root_dir = Path(r".")
results_dir = root_dir / "report" / "results"
results_dir.mkdir(parents=True, exist_ok=True)

extensions = {
    ".py": "Python",
    ".js": "JavaScript",
    ".jsx": "JavaScript (React)",
    ".ts": "TypeScript",
    ".tsx": "TypeScript (React)",
    ".html": "HTML",
    ".css": "CSS",
    ".json": "JSON",
    ".md": "Markdown",
    ".sh": "Shell",
    ".bash": "Shell",
    ".bat": "Batch",
    ".ps1": "PowerShell",
    ".yml": "YAML",
    ".yaml": "YAML",
    ".ini": "INI",
    ".txt": "Text",
    ".sql": "SQL"
}

modules = [
    "backend/detection",
    "backend/suricata",
    "backend/decision",
    "backend/actuators",
    "backend/safety",
    "backend/api",
    "backend/mitre",
    "backend/llm",
    "backend",
    "cyberguard",
    "scripts",
    "tests",
    "frontend/src",
    "frontend",
    "docs",
    "."
]

inventory = {
    "total_files": 0,
    "total_lines": 0,
    "by_language": {},
    "by_module": {},
    "file_details": []
}

def analyze_file(filepath):
    ext = filepath.suffix.lower()
    lang = extensions.get(ext, "Other")
    
    total = 0
    blank = 0
    comment = 0
    code = 0
    
    try:
        # Don't analyze files larger than 2MB as text
        if filepath.stat().st_size > 2 * 1024 * 1024:
            return {
                "path": str(filepath.relative_to(root_dir)).replace("\\", "/"),
                "ext": ext,
                "lang": "Large Binary/Data",
                "total": 0,
                "blank": 0,
                "comment": 0,
                "code": 0,
                "size_bytes": filepath.stat().st_size
            }
            
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
            total = len(lines)
            for line in lines:
                s = line.strip()
                if not s:
                    blank += 1
                elif s.startswith("#") or s.startswith("//") or s.startswith("/*") or s.startswith("*"):
                    comment += 1
                else:
                    code += 1
    except Exception:
        total = -1
        
    return {
        "path": str(filepath.relative_to(root_dir)).replace("\\", "/"),
        "ext": ext,
        "lang": lang,
        "total": total,
        "blank": blank,
        "comment": comment,
        "code": code,
        "size_bytes": filepath.stat().st_size
    }

skip_dirs = {".git", ".pytest_cache", "__pycache__", "node_modules", ".agent", "dist", ".system_generated"}

for root, dirs, files in os.walk(root_dir):
    dirs[:] = [d for d in dirs if d not in skip_dirs]
    for file in files:
        filepath = Path(root) / file
        rel_str = str(filepath.relative_to(root_dir)).replace("\\", "/")
        if rel_str.startswith("report/dist") or rel_str.startswith("report/results"):
            continue
            
        details = analyze_file(filepath)
        inventory["file_details"].append(details)
        inventory["total_files"] += 1
        if details["total"] > 0:
            inventory["total_lines"] += details["total"]
            
        lang = details["lang"]
        if lang not in inventory["by_language"]:
            inventory["by_language"][lang] = {"files": 0, "lines": 0, "code": 0, "comment": 0, "blank": 0}
        inventory["by_language"][lang]["files"] += 1
        if details["total"] > 0:
            inventory["by_language"][lang]["lines"] += details["total"]
            inventory["by_language"][lang]["code"] += details["code"]
            inventory["by_language"][lang]["comment"] += details["comment"]
            inventory["by_language"][lang]["blank"] += details["blank"]

# Module aggregation
for mod in modules:
    mod_files = []
    mod_lines = 0
    mod_code = 0
    for f in inventory["file_details"]:
        p = f["path"]
        if mod == ".":
            if "/" not in p and p != "":
                mod_files.append(f)
                mod_lines += max(0, f["total"])
                mod_code += max(0, f["code"])
        else:
            if p.startswith(mod + "/") or (mod == "backend" and p.startswith("backend/") and p.count("/") == 1):
                mod_files.append(f)
                mod_lines += max(0, f["total"])
                mod_code += max(0, f["code"])
                
    inventory["by_module"][mod] = {
        "file_count": len(mod_files),
        "total_lines": mod_lines,
        "code_lines": mod_code
    }

out_file = results_dir / "loc_inventory.json"
with open(out_file, "w", encoding="utf-8") as f:
    json.dump(inventory, f, indent=2)

print(f"Total Scanned Files: {inventory['total_files']}")
print(f"Total Lines: {inventory['total_lines']}")
print("\n--- By Language ---")
for lang, stats in sorted(inventory["by_language"].items(), key=lambda x: x[1]["lines"], reverse=True):
    print(f"{lang:20}: {stats['files']:4} files, {stats['lines']:7} lines ({stats['code']:7} code, {stats['comment']:5} comments)")

print("\n--- By Module ---")
for mod, stats in inventory["by_module"].items():
    print(f"{mod:25}: {stats['file_count']:3} files, {stats['total_lines']:6} lines ({stats['code_lines']:6} code)")
