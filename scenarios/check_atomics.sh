#!/usr/bin/env bash
# check_atomics.sh - ตรวจว่า technique ไหนมี Linux test บ้าง (รันใน VM)
# สำคัญ: เลข test ของ ART เปลี่ยนตามเวอร์ชัน ต้องเช็คก่อนใช้จริง
set -uo pipefail

TECHNIQUES="T1083 T1074.001 T1486 T1490 T1070.004 T1082 T1057 T1033 \
T1059.004 T1053.003 T1543.002 T1005 T1027 T1016 T1049 T1071.001 T1105 \
T1548.001 T1222.002 T1552.001 T1055 T1548 T1496 T1562.001"

echo "ตรวจ Atomic tests ที่รองรับ Linux"
echo "=================================="

for t in $TECHNIQUES; do
    out=$(pwsh -NoProfile -Command "
      Import-Module '/opt/AtomicRedTeam/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1' -Force
      \$PSDefaultParameterValues = @{'Invoke-AtomicTest:PathToAtomicsFolder'='/opt/AtomicRedTeam/atomics'}
      Invoke-AtomicTest $t -ShowDetailsBrief 2>&1
    " 2>/dev/null | grep -iE 'linux' | head -5)

    if [ -n "$out" ]; then
        echo ""
        echo "[$t]"
        echo "$out" | sed 's/^/    /'
    else
        echo "[$t]  -- ไม่มี Linux test --"
    fi
done

echo ""
echo "=================================="
echo "เอาเลข test ที่ได้ไปใส่ใน scenarios/*.sh"
echo "เช่น:  atomic T1486 2,3"