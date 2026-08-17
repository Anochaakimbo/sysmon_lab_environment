#!/usr/bin/env bash
# check_atomics.sh (v2) - list atomic tests that ACTUALLY support Linux
#
# v1 was unreliable: it grepped for the word "linux" in test names, which misses
# tests like "Cron - Add script to cron folder" that are Linux-only but do not
# say so in the name. This version reads supported_platforms from the YAML.
#
# Output is ASCII only, so redirecting to a file will not mangle characters.
set -uo pipefail

ATOMICS="${ATOMICS:-/opt/AtomicRedTeam/atomics}"

if [ ! -d "$ATOMICS" ]; then
    echo "[!] atomics folder not found: $ATOMICS"
    exit 1
fi

# make sure pyyaml is available
python3 -c "import yaml" 2>/dev/null || {
    echo "[*] installing python3-yaml ..."
    apt-get install -y -qq python3-yaml >/dev/null 2>&1 || pip3 install pyyaml -q
}

python3 - "$ATOMICS" <<'PYEOF'
import sys, os, yaml

atomics = sys.argv[1]

# techniques used by scenarios/*.sh
WANT = """T1083 T1074.001 T1486 T1490 T1070.004 T1082 T1057 T1033
T1059.004 T1053.003 T1543.002 T1005 T1027 T1016 T1049 T1071.001 T1105
T1548.001 T1222.002 T1552.001 T1055 T1548 T1496 T1562.001
T1543 T1546.004 T1070.002 T1036 T1204.002 T1132.001 T1573""".split()

# tests that are destructive beyond a sandbox - do not run in the lab
DENY = {
    ("T1070.004", 8),   # Delete Filesystem - wipes the box
    ("T1485", 0),       # placeholder: data destruction
    ("T1561", 0),       # disk wipe
}

print("=" * 70)
print("  ATOMIC TESTS WITH LINUX SUPPORT")
print("=" * 70)

summary = {}

for tech in WANT:
    path = os.path.join(atomics, tech, f"{tech}.yaml")
    if not os.path.isfile(path):
        print(f"\n[{tech}]  (no yaml found)")
        summary[tech] = []
        continue
    try:
        with open(path, encoding="utf-8") as f:
            doc = yaml.safe_load(f)
    except Exception as e:
        print(f"\n[{tech}]  (yaml parse error: {e})")
        summary[tech] = []
        continue

    tests = doc.get("atomic_tests") or []
    linux = []
    for idx, t in enumerate(tests, start=1):
        plats = [p.lower() for p in (t.get("supported_platforms") or [])]
        if "linux" not in plats:
            continue
        exec_ = t.get("executor") or {}
        name = t.get("name", "?")
        elev = " [needs root]" if exec_.get("elevation_required") else ""
        deny = " *** DESTRUCTIVE - DO NOT RUN ***" if (tech, idx) in DENY else ""
        linux.append((idx, name, exec_.get("name", "?"), elev, deny))

    summary[tech] = [i for i, *_ in linux if (tech, i) not in DENY]

    if linux:
        print(f"\n[{tech}]  {len(linux)} linux test(s)")
        for idx, name, ex, elev, deny in linux:
            print(f"    {idx:>3}. {name[:58]:<58} ({ex}){elev}{deny}")
    else:
        print(f"\n[{tech}]  -- NO linux test --")

# ---------------- ready-to-paste lines ----------------
print("\n" + "=" * 70)
print("  PASTE THESE INTO scenarios/*.sh")
print("=" * 70)
for tech in WANT:
    nums = summary.get(tech) or []
    if nums:
        print(f"    atomic {tech} {','.join(map(str, nums))}")
    else:
        print(f"    # atomic {tech}   <- no linux test, remove this line")
PYEOF