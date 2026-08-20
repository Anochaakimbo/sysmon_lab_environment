# RUNBOOK_WIN — เก็บ dataset ฝั่ง Windows

ต่อยอดจาก lab Linux เพื่อ merge เป็น dataset ข้ามแพลตฟอร์ม (แนวทาง B: 6 event ร่วม)

## โครงสร้างที่วางไว้แล้ว

```
sysmon-lab/
├── Vagrantfile                         # เพิ่ม wintarget (multi-machine, autostart:false)
├── provision/windows/
│   ├── sysmon-config-win.xml           # ✅ research config (log ครบ ไม่ filter)
│   ├── install_sysmon_win.ps1          # ✅ ติดตั้ง Sysmon + config
│   ├── install_art_win.ps1             # ✅ Invoke-AtomicRedTeam
│   └── export_sysmon_win.ps1           # ✅ export Event Log -> XML (แทน rsyslog)
├── scenarios_win/
│   ├── _lib.ps1                        # ✅ Atomic/Setup-Sandbox/Banner (PowerShell)
│   ├── benign.ps1                      # ✅ template
│   └── (ransomware/botnet/miner/... )  # ⬜ ยังต้องเขียน (.ps1)
└── host/                               # ★ ใช้ร่วมกับ Linux
    ├── label_events.py enrich_events.py merge_dataset.py   # ✅ ใช้ได้เลย
    └── parse_sysmon.py                 # ⬜ ต้องเพิ่ม --platform windows (parse EVTX/XML)
```

## ความต่างหลักจาก Linux

| | Linux | Windows |
|---|---|---|
| Sysmon | eBPF port | Sysmon64.exe (ตัวจริง) |
| config | exclude ว่าง (6-7 event) | exclude ว่าง (12 event ตามเปเปอร์) |
| log transport | rsyslog → **TCP 5514 realtime** | **batch export EVTX** หลัง scenario |
| scenario | `.sh` (bash) | `.ps1` (PowerShell) |
| communicator | ssh | winrm |
| sandbox seed | `/tmp/lab_sandbox` | `C:\lab_sandbox` |

**log transport คือจุดต่างที่สุด** — Windows ไม่มี syslog ท่อ realtime แบบ Linux
ใช้ไม่ได้ แทนด้วย `export_sysmon_win.ps1` ที่ดึง event ในช่วงเวลา scenario ออกมา
เป็น XML แล้ววางที่ `host/logs_win/` ผ่าน shared folder (`C:\vagrant`)

## Flow การเก็บ 1 scenario (Windows)

```
1. vagrant snapshot restore wintarget clean   (ล้างเครื่อง)
2. vagrant up wintarget                        (winrm)
3. รัน scenario:  powershell C:\vagrant\scenarios_win\<name>.ps1
4. export:  powershell export_sysmon_win.ps1 -Session <name> -StartUtc <t0>
              -> C:\vagrant\host\logs_win\<name>_*.xml  (sync มา host)
5. host: parse_sysmon.py --platform windows <xml> -> enrich -> label
6. vagrant halt wintarget
```

## สิ่งที่ยังต้องทำ (เรียงลำดับ)

1. **`parse_sysmon.py --platform windows`** — ตอนนี้ parse syslog XML ของ Linux
   ต้องรับ Sysmon Event XML (`<Event xmlns=...>`) ที่ `export_sysmon_win.ps1` ผลิต
   โครงสร้าง `<EventData><Data Name="X">` เหมือนกัน — regex ปรับเล็กน้อย
2. **scenario `.ps1`** ที่เหลือ — port จาก `.sh` โดยใช้ Windows Atomic tests
   (ransomware T1486, botnet T1071, miner T1496, trojan T1059.001, exploit T1548.002)
   Windows ART มี test เยอะกว่า Linux มาก
3. **orchestrator รองรับ Windows** — เพิ่ม branch: winrm exec + export แทน ssh + rsyslog
   (หรือเขียน `orchestrator_win.py` แยก)
4. **เก็บ + merge** — เก็บ Windows dataset แล้ว `merge_dataset.py` รวมกับ Linux
   (คอลัมน์ `platform` แยก linux/windows อยู่แล้ว)

## ⚠️ กับดักสำคัญ

### Platform leakage (สำคัญสุดต่อธีสิส)
Windows มี event ที่ Linux ไม่มี (Registry 12/13, ImageLoad 7, CreateRemoteThread 8)
→ ดู EventID อย่างเดียวก็แยก platform ได้ 100%
**ตอน merge ต้องใช้แนวทาง B:** เหลือเฉพาะ 6 event ร่วม (1,3,5,9,11,23) +
drop `platform`, `EventID` ที่เป็น Windows-only ออกจาก feature (เก็บไว้ trace ได้)
มิฉะนั้นโมเดลเรียน "เห็น Registry = Windows" แทนพฤติกรรมมัลแวร์

### Config: อย่าใช้ SwiftOnSecurity ตรงๆ
`reference/sysmonconfig-export.xml` เป็น **detection config** (onmatch=include กรองทิ้ง)
เก็บ dataset วิจัยจะ bias — ใช้ `sysmon-config-win.xml` (research, log ครบ) แทน
เก็บ SwiftOnSecurity ไว้อ้างอิง MITRE mapping เท่านั้น

### box Windows ใหญ่
`gusztavvargadr/windows-10` ~15-25GB, license eval 180 วัน — เตรียมดิสก์ + เวลาโหลด

### ImageLoad/Registry event เยอะมาก
config เปิด ImageLoad(7) + Registry(12,13) = event มหาศาล dataset ใหญ่
ถ้าดิสก์ไม่พอ comment 2 RuleGroup นั้นใน `sysmon-config-win.xml` (แต่จะไม่ตรงเปเปอร์)

## เริ่มยังไง

```powershell
# 1. โหลด box + provision (ครั้งแรก ~30-60 นาที)
vagrant up wintarget

# 2. save clean snapshot
vagrant snapshot save wintarget clean

# 3. ทดสอบ benign 1 รอบ (manual ก่อน automate)
vagrant winrm wintarget -c "powershell C:\vagrant\scenarios_win\benign.ps1"
vagrant winrm wintarget -c "powershell C:\vagrant\provision\windows\export_sysmon_win.ps1 -Session benign_test"

# 4. เช็ค host\logs_win\benign_test_*.xml เกิดขึ้น -> parse
```
