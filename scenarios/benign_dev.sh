#!/usr/bin/env bash
# benign_dev.sh - งานนักพัฒนาปกติ  label = 0
#
# เขียนโค้ด / รันสคริปต์ / git / encode-decode ไฟล์ / โหลดไฟล์จากเซิร์ฟเวอร์ในแล็บ
# หลายคำสั่งหน้าตาเหมือน ART (base64 -d, curl, chmod +x, bash -c) แต่เป็นงานปกติ
# ทำทั้งหมดใน $WORK และไม่ออกเน็ตนอกแล็บ
set -uo pipefail
source "$(dirname "$0")/_lib.sh"

banner "benign_dev"
setup_sandbox

WORK="/tmp/benign_dev/project"
mkdir -p "$WORK"
trap 'rm -rf /tmp/benign_dev' EXIT
cd "$WORK"
export GIT_AUTHOR_NAME=dev GIT_AUTHOR_EMAIL=dev@lab.local GIT_COMMITTER_NAME=dev GIT_COMMITTER_EMAIL=dev@lab.local

have() { command -v "$1" >/dev/null 2>&1; }
have git && git init -q . 2>/dev/null

for round in 1 2 3 4; do
    echo "[benign_dev] รอบ $round"

    # ---- เขียนโค้ด + config ----
    cat > app.py <<EOF
import json, sys, hashlib
data = {"round": $round, "items": list(range(50))}
print(json.dumps(data))
print(hashlib.sha256(json.dumps(data).encode()).hexdigest(), file=sys.stderr)
EOF
    printf 'name: demo\nversion: 0.%d\nport: 8080\n' "$round" > config.yml
    printf '#!/usr/bin/env bash\nset -e\npython3 app.py > out.json\nwc -c out.json\n' > build.sh
    chmod +x build.sh

    # ---- build / test ----
    ./build.sh > build.log 2>&1 || true
    python3 -m json.tool out.json > /dev/null 2>&1 || true
    python3 -c "import sys, platform; print(platform.python_version(), sys.executable)" > /dev/null
    python3 - <<'EOF' > /dev/null
import os, re
for root, _, files in os.walk("."):
    for f in files:
        if f.endswith((".py", ".yml", ".sh")):
            with open(os.path.join(root, f)) as fh:
                [l for l in fh if re.search(r"TODO|FIXME", l)]
EOF
    if have gcc; then
        printf '#include <stdio.h>\nint main(void){printf("build %d\\n");return 0;}\n' "$round" > hello.c
        gcc -O2 -o hello hello.c 2>/dev/null && ./hello > /dev/null
    fi

    # ---- encode / decode (base64 ของ secret ใน config เป็นงานปกติ) ----
    base64 config.yml > config.yml.b64
    base64 -d config.yml.b64 > config.check
    diff -q config.yml config.check > /dev/null && rm -f config.check
    sha256sum app.py config.yml > SHA256SUMS
    sha256sum -c SHA256SUMS > /dev/null

    # ---- ค้นโค้ด / เครื่องมือ ----
    grep -rn "import" --include='*.py' . > /dev/null
    find . -type f \( -name '*.py' -o -name '*.sh' \) -newer config.yml.b64 -print > /dev/null
    sed -n '1,5p' app.py | awk '{print NR": "$0}' > /dev/null
    have pip3 && pip3 list 2>/dev/null | head -20 > /dev/null
    dpkg -l python3 2>/dev/null | tail -1 > /dev/null
    env | grep -E '^(PATH|HOME|SHELL)=' > /dev/null

    # ---- โหลด artifact จากเซิร์ฟเวอร์ในแล็บ (T1105 ใช้คำสั่งเดียวกัน) ----
    curl -s -m 5 -o "artifact_${round}.html" http://192.168.56.1:8080/ || true
    wget -q -T 5 -O "artifact_${round}.wget" http://192.168.56.1:8080/ 2>/dev/null || true

    # ---- version control ----
    if have git; then
        git add -A >/dev/null 2>&1
        git commit -qm "round $round: update build and config" >/dev/null 2>&1
        git log --oneline -n 3 > /dev/null 2>&1
        git diff HEAD~1 --stat > /dev/null 2>&1 || true
    fi

    # ---- แพ็กส่ง + ล้าง build เก่า ----
    tar -czf "../release_${round}.tar.gz" --exclude=.git .
    rm -f hello hello.c out.json build.log artifact_*

    # คำสั่งยาวแบบ one-liner ของนักพัฒนา
    bash -c 'for f in $(find . -name "*.py" -o -name "*.yml"); do printf "%-20s %6s lines %s\n" "$f" "$(wc -l < "$f")" "$(sha1sum "$f" | cut -c1-12)"; done | sort -k2 -n' > /dev/null

    sleep 5
done

done_banner "benign_dev"
