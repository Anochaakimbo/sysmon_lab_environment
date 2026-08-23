# CLAUDE.md — Sysmon Malware Detection Dataset (Linux + Windows)

โปรเจคจบ: สร้าง dataset สำหรับ ML-based malware detection จาก **Sysmon event logs**
ทำ **สองแพลตฟอร์มคู่ขนาน** — Linux (Sysmon for Linux) และ Windows (Sysmon)
ต่อยอดจากเปเปอร์อ้างอิงที่ทำเฉพาะ Windows
(Achmad et al., *Cyber Security and Applications* 3, 2025, 100110)

---

## สภาพแวดล้อม

| รายการ | ค่า |
|--------|-----|
| Host | Windows 11, Ryzen 7 9700X, RAM 32GB |
| Hypervisor | **VMware Workstation Pro** + Vagrant (ไม่ใช่ VirtualBox — บูตไม่ผ่านเพราะ Hyper-V) |
| Guest (Linux) | Ubuntu 22.04 (`bento/ubuntu-22.04`), 2 vCPU / 2GB |
| Guest (Windows) | Windows VM + Sysmon + Atomic Red Team (ติดตั้งแล้ว) |
| Network | NAT + host-only `192.168.56.0/24`, host = `192.168.56.1` |
| Log transport (Linux) | Sysmon → journald → rsyslog → TCP 5514 → Python listener |
| Attack emulation | Atomic Red Team ทั้งสองฝั่ง |

RAM 32GB รันหลาย VM พร้อมกันไม่ได้ → **รันทีละเครื่อง** (sequential)

---

## โครงสร้างโปรเจค

```
sysmon-lab/
├── Vagrantfile
├── provision/
│   ├── install_sysmon.sh          # Sysmon + rsyslog (ปิด rate limit)
│   ├── install_tools.sh           # net-tools, gpg, 7z, ccrypt ฯลฯ
│   ├── install_art.sh             # PowerShell Core + Atomic Red Team
│   └── sysmon-config.xml          # schema 4.81
├── scenarios/                     # ---- LINUX (bash) ----
│   ├── _lib.sh                    # atomic(), banner(), setup_sandbox()
│   ├── benign.sh                  # label = 0
│   ├── ransomware.sh  trojan.sh  botnet.sh  exploit.sh  miner.sh
│   └── check_atomics.sh           # list Linux tests จาก YAML
├── scenarios_win/                 # ---- WINDOWS (PowerShell) ----
│   ├── _lib.ps1                   # Atomic(), Atomic-Cleanup(), Banner(), Setup-Sandbox()
│   ├── benign.ps1                 # label = 0
│   ├── ransomware_win.ps1         # ART-driven (T1486 ทำ encryption ทั้งหมด)
│   ├── miner_win.ps1              # ART-driven (T1496 + CPU load + pool ในแล็บ)
│   ├── trojan_win.ps1             # ART-driven
│   ├── botnet_win.ps1             # ART-driven
│   ├── exploit_win.ps1            # ART-driven
│   └── check_atomics.ps1          # list Windows tests จาก YAML + คัดตัวอันตรายออก
└── host/
    ├── log_receiver.py            # รับ syslog → logs/*.log
    ├── c2_server.py               # C2/mining-pool จำลอง (8080, 3333, 4444)
    ├── orchestrator.py            # revert→boot→scenario→halt→pipeline
    ├── parse_sysmon.py            # syslog XML → CSV (49 คอลัมน์)
    ├── enrich_events.py           # เติม process-level → 54 คอลัมน์
    ├── label_events.py            # session / lineage labeling → 56 คอลัมน์
    ├── explore_events.py          # สำรวจ event/field ที่ใช้ได้
    ├── logs/                      # raw syslog + metadata json
    └── dataset/                   # *_events.csv, *_enriched.csv, *_labeled.csv
```

ชื่อไฟล์ฝั่ง Windows ใช้รูปแบบ `<scenario>_win.ps1` เหมือนกันหมดแล้ว
(เดิมมี `*_real_win.ps1` ที่เขียน payload เอง — ถูกแทนด้วยเวอร์ชัน ART-driven ทั้งคู่)

---

## Pipeline

```
scenario ใน VM
   → Sysmon
   → (Linux) journald → rsyslog → TCP 5514  |  (Windows) Sysmon Event Log
   → host/log_receiver.py           → logs/<session>.log
   → parse_sysmon.py                → 49 คอลัมน์
   → enrich_events.py               → 54 คอลัมน์ (เติม CommandLine/Hashes/Parent*)
   → label_events.py                → 56 คอลัมน์ (label + is_seed)
```

`orchestrator.py` เรียก parse→enrich→label ให้อัตโนมัติหลังจบ scenario

---

## ข้อค้นพบสำคัญ — LINUX

### Sysmon for Linux ให้ event แค่ 5-6 ชนิด
ใช้ได้จริง: **1** ProcessCreate, **3** NetworkConnect, **5** ProcessTerminate,
**9** RawAccessRead, **11** FileCreate, **23** FileDelete
(ProcessAccess 10 ยังไม่เคยเห็นออกมา)

### คอลัมน์ที่ว่างเสมอบน Linux (14 ตัว) — ตัดทิ้งได้
`RuleName, FileVersion, Description, Product, Company, OriginalFileName,
SourceHostname, SourcePortName, DestinationHostname, DestinationPortName,
IsExecutable, Archived`
→ ผลคือ **35/49 คอลัมน์มีข้อมูล** (เปเปอร์ Windows มี 41)

### แต่ Linux ให้ของที่เปเปอร์ไม่มี — นี่คือ contribution
`CommandLine`, `ParentImage`, `ParentCommandLine`, `ParentUser`, `Hashes`, `CurrentDirectory`
เปเปอร์อ้างอิงระบุเองว่าข้อจำกัดของงานเขาคือ Windows event ไม่มี parent-child correlation
→ **งานนี้แก้ข้อจำกัดนั้นได้**

### ความผิดพลาดที่เคยเจอและวิธีแก้ (Linux)

| อาการ | สาเหตุ | แก้แล้วโดย |
|-------|--------|-----------|
| VM บูตค้าง "Loading essential drivers" | VirtualBox + Hyper-V | ย้ายไป VMware |
| `Failed to start the virtual machine` | `vhv.enable = TRUE` ขอ nested virt | ลบบรรทัดนั้น |
| `sysmon: Segmentation fault` | config มี `FieldSizes` + schema 4.90 | ใช้ schema **4.81** ไม่ใส่ FieldSizes |
| field ทั้งหมดว่างใน explore | regex ใช้ `Name='...'` แต่ log ใช้ `"..."` | แก้ regex รับทั้งสองแบบ |
| malicious แค่ 5.1% | scenario รันจาก `/vagrant/` ไม่ตรง seed | ก๊อป scenario ไป `/tmp/lab_sandbox` ก่อนรัน |
| `atomic T1070.004` ไม่ระบุเลข | test 8 = **Delete Filesystem ล้างเครื่อง** | ล็อกเป็น `1,2,3` เท่านั้น |
| checker v1 บอก "ไม่มี Linux test" ผิด | grep คำว่า "linux" ในชื่อ test | v2 อ่าน `supported_platforms` จาก YAML |
| `vagrant ssh -c` ค้างเงียบ ไม่มีเอาต์พุต | ACL ของ `private_key` กว้างเกิน (Authenticated Users) → OpenSSH ทิ้ง key แล้วตกไปถาม **password ของ vagrant** | `icacls /inheritance:r /grant:r "$USER:(R)"` + `preflight_ssh_key()` เช็คให้ทุกรอบ |
| log ไม่ถึง host เลยหลัง revert (Send-Q บวมค้าง) | snapshot คืน **memory state** มาด้วย → rsyslogd ตื่นมาพร้อม TCP socket เก่าที่ host ตายไปแล้ว | `systemctl restart rsyslog` หลังบูตทุกครั้ง (orchestrator ทำให้แล้ว) |
| **FileCreate(11) + RawAccessRead(9) หายเกลี้ยงทั้งรอบ** (event อื่นมาปกติ) | ไม่ใช่ rate limit! snapshot คืน memory state → **eBPF probe ของ sysmon อยู่ในสภาพ stale** ยิง 2 event นี้ไม่ออก | `systemctl restart sysmon` หลังบูต — ยืนยันแล้ว event 11 กลับมา 108 ตัวใน 15 วินาที |

### เลข Atomic test ที่ยืนยันบน Linux VM แล้ว

```
T1083 3,4,8          T1074.001 2        T1486 1,2,3,4
T1070.004 1,2,3      (⚠️ ห้าม 8)        T1082 3,4,5,6,8,12,25,26
T1057 1              T1033 2            T1059.004 1..17
T1053.003 1,2,3,4    T1543.002 1,2,3    T1005 2
T1027 1              T1016 3            T1049 4,5,6
T1071.001 3          T1105 1,2,3,4,5,6,14,27
T1548.001 1..10      T1222.002 1..14    T1552.001 1,3,6,15,16,17
T1496 1              T1546.004 1..7     T1132.001 1,2

ไม่มี Linux test: T1490, T1055, T1548, T1562.001, T1543, T1070.002, T1036, T1204.002, T1573
```

---

## ข้อค้นพบสำคัญ — WINDOWS

### API ของ `scenarios_win/_lib.ps1`

```powershell
Setup-Sandbox                       # สร้าง C:\lab_sandbox + import ART module
Atomic <Technique> [TestNumbers]    # รัน atomic test (job + timeout กันค้าง)
Atomic-Cleanup <Technique> [Nums]   # ล้าง artifact ที่ test ทิ้งไว้
Banner <Name> / Done-Banner <Name>  # แสดงหัว/ท้าย scenario
```

`$AtomicTimeout` default 240s ปรับผ่าน env `ATOMIC_TIMEOUT`
Job ถูก spawn จาก `C:\lab_sandbox` เพื่อให้ lineage labeling จับ seed ได้

### 🚨 `Atomic` ที่ไม่ระบุ TestNumbers = รัน **ทุก test** ของ technique นั้น

จุดเดียวกับที่ฝั่ง Linux เกือบพัง (`T1070.004` test 8 = Delete Filesystem)
**ระบุเลขเสมอ** — ตรวจก่อนด้วย `check_atomics.ps1` หรือ `Invoke-AtomicTest T#### -ShowDetailsBrief`

### `scenarios_win/check_atomics.ps1` — ที่มาของเลข test

รันในเครื่อง Windows VM (ต้องมี `C:\AtomicRedTeam\atomics`):

```powershell
powershell -ExecutionPolicy Bypass -File .\scenarios_win\check_atomics.ps1 > C:\atomic_report_win.txt
.\scenarios_win\check_atomics.ps1 -Technique T1486,T1490    # เช็คเฉพาะบางตัว
.\scenarios_win\check_atomics.ps1 -PasteOnly                # ข้ามรายการละเอียด
```

อ่าน `supported_platforms` จาก YAML ตรงๆ (ไม่ grep ชื่อ test — บทเรียนจาก checker v1 ฝั่ง Linux)
parse เองตาม indentation ไม่ต้องลง `powershell-yaml`

**เลข index นับทุก test ในไฟล์ รวม test ที่ไม่ใช่ Windows** — ตรงกับที่ `-TestNumbers` ใช้
เช่น T1082 ที่ test 2 เป็น Linux-only จะได้ `1,3` ไม่ใช่ `1,2`

เอาต์พุต 4 ส่วน: รายการละเอียด → **บรรทัดพร้อมวางแยกตามไฟล์ scenario** →
ตัวที่ถูกตัดออกพร้อมเหตุผล → สรุปจำนวน

ตัดออกอัตโนมัติ (ยังแสดงในส่วน EXCLUDED เสมอ ไม่เงียบ):

| tag | หมายถึง |
|-----|---------|
| `DENY-TECH` | technique อยู่ใน deny list ด้านล่าง |
| `DESTRUCTIVE` | vssadmin/wbadmin/bcdedit/`cipher /w`/diskpart/format |
| `LOGKILL` | `wevtutil cl`, `Clear-EventLog`, stop Sysmon, ลบ USN journal |
| `REBOOT` | `shutdown /r`, `Restart-Computer` — ตัด log กลางคัน |
| executor `manual` | ต้องทำมือ รันอัตโนมัติไม่ได้ |

⚠️ **`LOGKILL` สำคัญเป็นพิเศษกับงานนี้** — ฝั่ง Windows Sysmon เขียนลง Event Log
test ที่สั่ง `wevtutil cl` จะ**ลบ event ที่เพิ่งเก็บมาทั้งรอบ** โดยไม่มี error
เป็นความเสี่ยงที่ฝั่ง Linux ไม่มี (Linux ส่งออก syslog ทันที)

### 🚨 กับดักร้ายที่สุด: ART module import ไม่ติด แล้ว scenario ยัง exit 0

**เกิดจริง 23 ส.ค. 2026 — รัน `trojan_win` แล้วไม่มี atomic test ทำงานเลยสักตัว
แต่ orchestrator รายงานสำเร็จ, pipeline ครบ, ได้ CSV 18,072 แถว label malicious 59.5%**
ไม่มีอะไรสะดุดตาเลยถ้าไม่ไล่อ่าน log ทีละบรรทัด

สาเหตุ: `Install-AtomicRedTeam -InstallPath "C:\AtomicRedTeam"` **ไม่ได้วาง module
ลง `PSModulePath`** module อยู่ที่ `C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1`
แต่ `_lib.ps1` เรียก `Import-Module Invoke-AtomicRedTeam` ตามชื่อ + `-ErrorAction SilentlyContinue`
กลืน error ทิ้ง → `Invoke-AtomicTest` ไม่มีอยู่จริง → ทุก `Atomic` เงียบ

แก้แล้วใน `_lib.ps1`:
- import ตาม path เต็ม (`$ARTRoot` override ด้วย env `ART_ROOT`)
- `Setup-Sandbox` **throw ทันที** ถ้าไม่เจอ module หรือ import แล้วไม่มี `Invoke-AtomicTest`
- ส่ง path เข้า `Start-Job` ด้วย (runspace ของ job ไม่เห็นตัวแปรของ scope แม่)

เช็คเร็วๆ ว่ายังดีอยู่ไหม:
```powershell
vagrant winrm wintarget -c "Get-Module -ListAvailable Invoke-AtomicRedTeam"   # ว่าง = ปกติ
vagrant winrm wintarget -c "cd C:\lab_sandbox; . .\_lib.ps1; Setup-Sandbox"  # ต้องขึ้น [setup] ART module พร้อม
```

**บทเรียนทั่วไป**: ทุกอย่างที่ใช้ `-ErrorAction SilentlyContinue` ในเส้นทางเก็บข้อมูล
ต้องมี preflight ที่ throw คู่กันเสมอ ไม่งั้นได้ dataset ที่ดูปกติแต่ไม่มีสัญญาณที่ต้องการ

### Technique ที่ห้ามรันบน Windows (deny list)

```
T1490  Inhibit System Recovery   (ลบ shadow copy / ปิด recovery)
T1485  Data Destruction
T1561  Disk Wipe
T1529  System Shutdown/Reboot    (ตัด log กลางคัน)
T1491  Defacement
```

`ransomware_win.ps1` **ไม่เรียก `vssadmin` เอง** — บล็อก T1490 ถูกคอมเมนต์ไว้ท้ายไฟล์
ถ้าจะเปิดใช้ (เป็นพฤติกรรม hallmark ของ ransomware จริง มีค่าต่อ detection):
ต้องมั่นใจว่า revert snapshot ทุกรอบ + บันทึกในธีสิสว่าเปิด

### ⚠️ Windows Defender จะขวางการเก็บข้อมูล

| ตัวที่โดน | อาการ |
|-----------|-------|
| `miner_win.ps1` (T1496) | ART บาง test โหลด miner จริง → `Trojan:Win32/CoinMiner` ลบไฟล์ทิ้ง |
| `ransomware_win.ps1` (T1486) | behavior detection จับ mass encryption |
| `trojan_win.ps1` (T1027/T1036.003) | obfuscated payload + rename system utility |
| `exploit_win.ps1` (T1055/T1548.002) | process injection + UAC bypass โดนแน่ |
| `Atomic ... -GetPrereqs` | ตัวโหลด prereq เองก็โดนบล็อกได้ ทำให้ test fail เงียบ |

#### 🚨 Tamper Protection ทำให้ปิด Defender ไม่ลง และมันพังแบบเงียบ

**เกิดจริง 23 ส.ค. 2026** — `disable_defender_win.ps1` รันตอน provision ครบทุกบรรทัด
ไม่มี error แต่ `Get-MpComputerStatus` บอกว่า:

```
RealTimeProtectionEnabled : True
IsTamperProtected         : True
BehaviorMonitorEnabled    : True
```

**Tamper Protection ย้อน `Set-MpPreference -Disable*` ทุกตัวกลับเงียบๆ**
(`Add-MpPreference -ExclusionPath` ยังติด แต่ช่วยไม่ได้ — ดูด้านล่าง)

ผลที่ตามมา วัดจาก `Get-MpThreatDetection`: Defender บล็อก command line ของ

| test | ThreatID |
|------|----------|
| `T1059.001-5` Invoke-AppPathBypass (DownloadString) | 2147726248 |
| `T1059.001-7` Powershell XML requests (XmlDocument.Load) | 2147849223 |
| `T1074.001` Discovery.bat download | 2147849223 |

ซึ่งคือ **test ที่โหลดไฟล์ทั้งหมด = test ที่จะสร้าง NetworkConnect**
→ `trojan_win` เก็บ NetworkConnect ที่เป็น malicious ได้ **0 แถว** จาก 77 แถว
(ที่เหลือเป็น OS ล้วน: svchost DNS, Defender, WinRM)
ทั้งที่ ART รายงาน `Done executing test` ครบทุกตัว

⚠️ **`Add-MpPreference -ExclusionPath` แก้ปัญหานี้ไม่ได้**
exclusion กันแค่การสแกน **ไฟล์** แต่ตัวที่บล็อกคือ **AMSI / command-line scanning**
ซึ่งดูที่ข้อความคำสั่ง ไม่ได้ดู path

#### วิธีแก้ (ทำมือครั้งเดียว — ปิดผ่านสคริปต์/registry ไม่ได้)

Tamper Protection ปิดได้ทางเดียวคือ GUI (Microsoft กันไว้ตั้งแต่ปี 2020)
Vagrantfile ตั้ง `v.gui = true` อยู่แล้ว เปิดหน้าจอ VM ได้เลย

```
1. Windows Security > Virus & threat protection > Manage settings
2. ปิด Tamper Protection
3. บนโฮสต์:
     vagrant provision wintarget      # ให้ disable_defender_win.ps1 ทำงานจริง
     vagrant halt wintarget
     vagrant snapshot save wintarget clean --force
```

#### preflight กันพลาดซ้ำ

`Setup-Sandbox` เรียก `Assert-DefenderOff` แล้ว — **throw ทันที**ถ้า
`RealTimeProtectionEnabled = True` พร้อมพิมพ์ขั้นตอนแก้ให้
ตั้ง `$env:ALLOW_DEFENDER = "1"` ถ้าจงใจจะเก็บทั้งที่ Defender เปิด

ตรวจเร็วๆ: `vagrant winrm wintarget -c "powershell -File C:\vagrant\scenarios_win\_diag_defender.ps1"`

**ต้องบันทึกในธีสิสว่าปิดอะไรไป** เพราะกระทบ event ที่เก็บได้

### Registry event กลืน dataset — วัดจริงแล้วต้องกรอง

`sysmon-config-win.xml` ตั้งใจใช้ `onmatch="exclude"` ว่างเพื่อไม่ให้ bias
แบบ SwiftOnSecurity (ที่ include เฉพาะของน่าสงสัย → benign class หาย)
แต่บน Windows การเก็บ RegistryEvent ทุกตัวคือท่อน้ำ

**วัดจริง 23 ส.ค. 2026 (`trojan_win` 1 รอบ, ก่อนกรอง):**

| event | จำนวน | สัดส่วน |
|-------|-------|---------|
| 12 RegistryAddDelete | 88,447 | 74.5% |
| 13 RegistrySetValue | 19,895 | 16.7% |
| 255 (Sysmon error) | 2,838 | 2.4% |
| 1 ProcessCreate | **370** | **0.3%** |

ที่มาเป็น OS ล้วน: `svchost` 44,582 / `CompatTelRunner` 6,526 / `EdgeUpdate` 6,521
/ `taskhostw` 6,417 / `MoUsoCoreWorker` 5,471 / `WmiPrvSE` 3,049 / `MsMpEng` 1,791

→ เพิ่ม exclude เฉพาะ **OS housekeeping** ใน `RegistryEvent`
ไม่ได้กรองตามความน่าสงสัย registry event จาก process ผู้ใช้/ผู้โจมตียังเก็บครบ 100%

⚠️ **ต้องใช้ `condition="is"` path เต็ม ห้ามใช้ `end with` ชื่อไฟล์**
`T1036.003` test 5 ปลอม powershell เป็นชื่อ `taskhostw.exe` และ test 1 ปลอมเป็น `lsass.exe`
ถ้ากรองตามชื่อจะกลืน telemetry ของ test ตัวเอง — สำเนาปลอมอยู่คนละ path จึงยังถูก log

**ผลหลังกรอง:** 118,796 → 23,018 events (OS noise หายเกลี้ยง)

### EventID 255 ไม่ใช่ telemetry

`The "C:\Sysmon\" owner is not System. Archiving is disabled.` ยิงทุกครั้งที่มี FileDelete
(2,838 ครั้ง ≈ จำนวน FileDelete พอดี) field อื่นว่างหมด → `parse_sysmon.py` ตัดทิ้งแล้ว

ไม่แก้ ownership ที่ต้นทางเพราะการแก้จะ **เปิด** archiving = Sysmon ก๊อปทุกไฟล์ที่ถูกลบเก็บไว้

### หลังแก้ config ต้องบันทึก snapshot ใหม่

ไม่ต้อง `vagrant provision` (จะโหลด atomics ใหม่ 1-2GB) ใช้วิธี apply สดแล้ว snapshot:
```powershell
vagrant up wintarget
vagrant winrm wintarget -c "& C:\Sysmon\Sysmon64.exe -c C:\vagrant\provision\windows\sysmon-config-win.xml"
vagrant halt wintarget
vagrant snapshot save wintarget clean --force
```

### ต้องรัน PowerShell แบบ Administrator

จำเป็นสำหรับ: `vssadmin` / `wbadmin` (ransomware), UAC bypass (T1548.002),
token manipulation (T1134), process injection (T1055)

ถ้าไม่ใช่ admin จะ **fail เงียบๆ** (เพราะมี `-ErrorAction SilentlyContinue`)
แล้วจะได้ event น้อยผิดปกติโดยไม่รู้ตัว → `exploit_win.ps1` เช็คและเตือนให้แล้ว

### ต้องเรียก `Atomic-Cleanup` ท้าย scenario ที่มี persistence

`trojan_win.ps1` และ `exploit_win.ps1` สร้าง Run key / Scheduled Task ผ่าน ART
ถ้าไม่ล้าง artifact จะค้างข้ามรอบ → session ถัดไปปนเปื้อน → label ผิด

ไม่ใช่แค่ persistence — **T1105 (โหลดไฟล์ลงเครื่อง), T1074.001 (staging),
T1027 (obfuscated payload), T1552.001 (ไฟล์ credential ล่อ) ก็ทิ้งไฟล์ไว้เหมือนกัน**
ทั้ง 5 scenario เรียก `Atomic-Cleanup` ครบทุก technique ที่ทิ้ง artifact แล้ว (23 ส.ค. 2026)

(cleanup ไม่ได้แทน snapshot revert — orchestrator revert ทุกรอบอยู่แล้ว
แต่จำเป็นตอนรัน scenario ซ้อนกันหลายตัวใน VM เดียวโดยไม่ revert ระหว่างกลาง)

### Encoding

ไฟล์ `.ps1` มีคอมเมนต์ภาษาไทย → ต้องเป็น **UTF-8 with BOM**
ไม่งั้น PowerShell 5.1 อ่านเป็น ANSI แล้วเพี้ยน

**เคยพลาดมาแล้ว (23 ส.ค. 2026):** `botnet/exploit/ransomware/trojan_win.ps1`
ถูกบันทึกเป็น UTF-8 ไม่มี BOM — syntax ผ่านแต่คอมเมนต์ไทยเละ แก้แล้วทั้งหมด
ตรวจเร็วๆ: 3 ไบต์แรกต้องเป็น `EF BB BF`

```bash
for f in scenarios_win/*.ps1; do echo "$f $(head -c3 "$f" | od -An -tx1)"; done
```

### ทำไม scenario Windows ทั้ง 5 ตัวเป็น ART-driven

**อย่าเปลี่ยนกลับไปเขียน payload เอง** — เหตุผล:

1. ฝั่ง Windows คือบ้านเกิดของ ART มี test ครอบคลุมครบทั้ง 5 เทคนิค
   (ต่างจาก Linux ที่ ART มี test น้อยจนต้องเขียนชดเชย)
   ได้ event ไม่แพ้กัน + map ATT&CK ตรง อ้างอิงในธีสิสง่ายกว่า
2. payload ที่เขียนเอง (backdoor, C2 agent ที่รับคำสั่งมารัน, encryptor, miner จริง)
   คือเครื่องมือที่เปลี่ยน IP/path แล้วใช้นอกแล็บได้ทันที — ไม่ควรมีในรีโป
3. ของที่เขียนเองในไฟล์เหล่านี้จำกัดอยู่แค่ **operation ปกติของ Windows**:
   สร้าง/คัดลอก/ลบไฟล์ล่อใน `C:\lab_sandbox`, คำนวณเลขกิน CPU,
   เปิด TCP/HTTP ไป `c2_server.py` ของตัวเอง — ไม่ใช่ malware routine

`botnet_win.ps1` beacon แบบ **ส่งอย่างเดียว ไม่รับคำสั่งกลับมารัน** —
ได้ NetworkConnect telemetry เท่ากันโดยไม่ต้องมีตัวรับคำสั่ง

### Technique ที่ scenario Windows ใช้

```
ransomware_win : T1083 T1005 T1074.001 T1486 T1070.004   (T1490 คอมเมนต์ไว้)
miner_win      : T1082 T1057 T1105 T1496 T1053.005       (+ CPU load 90s, pool 20 รอบ)
botnet_win     : T1016 T1049 T1018 T1071.001 T1132.001 T1105  (+ beacon 30 รอบ)
trojan_win     : T1082 T1033 T1057 T1087.001 T1059.001 T1547.001
                 T1053.005 T1112 T1005 T1074.001 T1027 T1036.003
exploit_win    : T1069.001 T1012 T1497.001 T1552.001 T1548.002 T1134 T1055 T1218.011
```

รายการนี้ **ต้องตรงกับ `$SCENARIOS` ใน `check_atomics.ps1`** — แก้ scenario แล้วแก้ checker ด้วย
ไม่งั้น checker จะไม่ออกบรรทัดพร้อมวางให้ technique ที่เพิ่มใหม่

### เลข Atomic test ที่ยืนยันบน Windows VM แล้ว (23 ส.ค. 2026)

รันจาก `check_atomics.ps1` บน `wintarget` (ART 342 technique folder) แล้ว cross-check ครบ 202 เลข

```
T1005 1              T1012 1,2,3,6        T1016 1,2,4,9
T1018 1,4,5          T1027 2,3,7,11       T1033 1,4,5,6
T1036.003 1,3,5,7    T1049 1,2,3          T1053.005 2,4,7,9
T1055 3,4,6,7,11     T1057 2,3,4,5,6      T1059.001 5,7,8
T1069.001 2,3,5,6    T1070.004 4,5,6,7,10 T1071.001 1
T1074.001 1,3        T1082 1,7,9,11,27,35 T1083 1,2,5,9
T1087.001 8,9,10     T1105 7,9,10,15,16,25
T1112 1,6,7,40,41    T1132.001 3          T1134.001 1,2
T1134.002 1          T1218.011 2,3,9,13,15
T1486 5,8,10         T1496 2              T1497.001 3,5
T1547.001 1,2,8,9,11 T1548.002 1,3,5,7,9  T1552.001 4,5,13,14
```

**สิ่งที่ค่าเดาเดิมพลาด** (ถ้าไม่รัน checker จะ fail เงียบทั้งหมด):

| เดาไว้ | ของจริง |
|--------|---------|
| `T1496 "1,2"` | มี windows test เดียวคือ **เลข 2** — test 1 เป็น Linux |
| `T1132.001 "1"` | windows test คือ **เลข 3** |
| `T1134 "1,2"` | **ART ไม่มีโฟลเดอร์ `T1134` เปล่าๆ** มีแต่ `.001/.002/.004/.005` |
| `T1486 "1,2"` | windows test คือ 5,8,9,10 |
| `T1070.004 "1,2"` | windows test เริ่มที่เลข 4 |
| `T1087.001 "1,2"` | windows test เริ่มที่เลข 8 |

**เกณฑ์ที่ใช้เลือก** (ไม่ได้เอาทุก test ที่รันได้ — T1112 มีถึง 90 ตัว):

1. เลี่ยง test ที่มี `[prereq]` ซึ่งดาวน์โหลดเครื่องมือจากเน็ต
   (WinPwn, UACME, Adfind, SharpHound, Mimikatz, BloodHound, Process Hacker, NSudo)
   — ช้า, Defender บล็อก, และพังทั้ง scenario ถ้าเน็ตไม่มี
2. เลี่ยง test ที่ต้องมี Active Directory (`nltest`, `net group Domain Computers`, PowerView)
   — VM เป็น workgroup จะ fail
3. เลี่ยง test ที่ทำ VM ใช้งานไม่ได้ — `T1112` ที่ปิด cmd/regedit/taskmgr/Defender,
   `T1547.001` 14/15/17 ที่แก้ Winlogon Userinit / Shell / BootExecute (เสี่ยงบูตไม่ขึ้น)
4. เลือก 3-6 ตัวต่อ technique ให้จบใน `$AtomicTimeout` 240s
5. เอาทั้ง `command_prompt` และ `powershell` ปนกัน ให้ได้ ProcessCreate หลากหลาย

⚠️ **`T1486` test 9 (DiskCryptor) ตัดออกด้วยมือ ไม่ใช่ checker จับได้**
มันติดตั้ง driver เข้ารหัสทั้ง volume — keyword scan ไม่โดนเพราะ command ไม่มีคำที่สแกนไว้
บทเรียน: **checker ช่วยกรอง ไม่ได้แทนการอ่านชื่อ test เอง**

⚠️ `T1486` test 8 (GPG4Win) ต้องโหลด+ติดตั้งผ่านเน็ต ใช้เวลาราว 1-2 นาที
ถ้าอยากให้ ransomware scenario เร็วขึ้นและไม่พึ่งเน็ต ให้เหลือ `"5,10"`

---

## ผลตรวจ scenario ฝั่ง Windows ครบทั้ง 6 (24 ส.ค. 2026)

เก็บด้วยเงื่อนไขเดียวกันหมด: Defender ปิด (Tamper Protection ปิดแล้ว), repeat loop,
sysmon config ที่กรอง CreateKey + OS housekeeping, `c2_server.py` + `mining_pool.py` เปิดค้าง

| scenario | แถว | รอบ | atomic | cleanup | ท่อ C2/pool | ผล |
|----------|-----|-----|--------|---------|-------------|-----|
| `benign` | 9,293 | 18 | — | — | — | ✅ label 0 ล้วน |
| `ransomware_win` | 9,970 | 4 | ครบ | ครบ | — | ✅ |
| `trojan_win` | 4,100 | 2 | ครบ | ครบ | — | ✅ |
| `botnet_win` | 3,678 | 2 | ครบ | ครบ | `beacon ok=30 fail=0` | ✅ |
| `miner_win` | 2,522 | 2 | ครบ | ครบ | `pool connect ok=20 fail=0` | ✅ |
| `exploit_win` | 2,803 | 1 | ครบ | ครบ | — | ✅ |

**รวม 32,366 แถว** (ก่อนแก้ repeat loop ทั้งฝั่ง Windows ได้แค่ 3,546)

เกณฑ์ "ผ่าน" ที่ใช้ตรวจ — ไม่ใช่แค่มีข้อมูลออกมา:
1. atomic รันครบทุก technique ไม่มีตัวโดน `$AtomicTimeout` ตัด
2. `Atomic-Cleanup` รันจนจบ (นับจำนวนบรรทัด `[cleanup]` ให้ตรงกับที่เรียก)
3. event ครบชนิดที่ scenario ควรสร้าง — โดยเฉพาะ `NetworkConnect` ของ botnet/miner
4. lineage จับ seed ได้ (`is_seed=1` > 0 process)
5. ไม่มีสัญญาณ fail เงียบ (ART module / Defender / c2 / pool)

### 🚨 orchestrator_win รัน scenario ครั้งเดียว — `--duration` ไม่มีผลจริง

**เจอ 23 ส.ค. 2026** `orchestrator.py` ฝั่ง Linux วนซ้ำ scenario จนครบเวลา
แต่ `orchestrator_win.py` รัน `.ps1` **ครั้งเดียว** `--duration` จึงมีผลแค่กับ timeout

ผลกระทบวัดได้: `benign_win` ได้ **528 แถว** เทียบ `benign` ฝั่ง Linux **5,330 แถว**
และทำให้สัดส่วน label สองแพลตฟอร์มต่างกัน **33.5 จุด** → platform กลายเป็น proxy ของ label

แก้แล้ว: เพิ่ม repeat loop + `--no-repeat` ไว้ย้อนพฤติกรรมเดิม
พิมพ์ `รวม N รอบ` ทุกครั้งเพื่อให้เห็นว่าวนจริงกี่รอบ
→ `benign_win` เพิ่มเป็น **9,293 แถว (18 รอบ)** และ label balance เหลือต่างกัน **0.5 จุด**

### 🚨 GUIBLOCK — atomic test ที่เปิดหน้าต่างแล้วรอผู้ใช้

`T1218.011` test 13 `Rundll32 with desk.cpl` เปิด Control Panel แล้วรอตลอดไป
→ job ค้างจนโดน `$AtomicTimeout` 360s ตัด → กิน duration ทั้งรอบ
`exploit_win` เลยรันได้แค่ 1 รอบ ขณะที่ตัวอื่นได้ 2-4 รอบ

ตัด test 13 และ 15 (`FileProtocolHandler` เปิด default handler ได้เหมือนกัน) ออกแล้ว
เหลือ `Atomic "T1218.011" "2,3,9"` → รอบใหม่ timeout เหลือ 0 ครั้ง

เพิ่ม tag **`GUIBLOCK`** ใน `check_atomics.ps1` จับ `.cpl`, `Control_RunDLL`,
`FileProtocolHandler`, `OpenAs_RunDLL`

⚠️ นี่คือเคสที่ 2 ที่ checker จับไม่ได้ (เคสแรกคือ T1486 test 9 DiskCryptor)
**checker ช่วยกรอง ไม่ได้แทนการอ่านชื่อ test เอง**

### Dashboard รองรับสองแพลตฟอร์มแล้ว

**เจอ 24 ส.ค. 2026:** `dashboard.py` `import orchestrator` อย่างเดียว และฮาร์ดโค้ด
`vm="target1"` → กดเก็บผ่านหน้าเว็บได้เฉพาะ Linux **ฝั่ง Windows ไม่มีปุ่มให้กดด้วยซ้ำ**

แก้แล้ว:
- `REGISTRY` รวมทั้งสอง orchestrator (Linux 9 + Windows 6 = 15 scenario)
- `_run_one` เลือก orchestrator ตาม `platform`
- `start_collectors(session, platform)` — ข้าม `log_receiver` ตอนรัน Windows
  (ฝั่งนั้นไม่ได้ส่ง syslog แต่ export EVTX ตอนจบ) แต่ยังเปิด `mining_pool` + `c2_server`
- UI แยกกลุ่ม 🐧 Linux — VM target1 / 🪟 Windows — VM wintarget + ปุ่มเลือกชุดแยกฝั่ง
- เตือนเมื่อเลือกคิวข้ามแพลตฟอร์ม (ต้องสลับ VM ไปมา ใช้เวลานานขึ้นมาก)
- ชื่อ scenario ฝั่ง Windows ใน Dashboard เป็น `benign_win` (กันชนกับ `benign` ของ Linux)

---

## merge Linux + Windows — สถานะจริงหลังเก็บครบ

เครื่องมือ: `python host/check_merge.py` (รันซ้ำได้ทุกครั้งที่เก็บเพิ่ม)

**ข้อมูล ณ 24 ส.ค. 2026: Linux 24,583 + Windows 32,366 = 56,949 แถว**

### ✅ แก้ได้แล้ว — สัดส่วน label

| | ก่อน | หลัง |
|---|------|------|
| Linux malicious | 34.3% | 34.3% |
| Windows malicious | 67.8% | **33.8%** |
| ต่างกัน | 33.5 จุด | **0.5 จุด** |

แก้ด้วยการเก็บ `benign_win` + repeat loop ไม่ต้องแตะโมเดลเลย

### ❌ ยังแก้ไม่ได้ — โมเดลแยก platform ได้ 100%

ทายมั่วได้ 56.8% แต่โมเดลทำได้ **100.00%** feature ที่รั่วมากสุด:

| feature | importance | ทำไมรั่ว |
|---------|-----------|----------|
| `IntegrityLevel` | 0.1581 | เป็น concept ของ Windows ล้วน Linux ว่าง |
| `TerminalSessionId` | 0.1475 | Linux ว่างเสมอ |
| `User` | 0.1088 | `root`/`vagrant` vs `DESKTOP-xxx\vagrant` — ค่าไม่ทับกันเลย |
| `Image` | 0.0793 | `/usr/bin/x` vs `C:\...\x.exe` |
| `ParentUser`, `LogonId`, `CurrentDirectory`, `ParentCommandLine` | | เหตุผลเดียวกัน |

**ไล่ตัดทีละรอบแล้ววัดใหม่:**

| รอบ | ตัดอะไร | platform acc |
|-----|---------|--------------|
| 0 | — | 100.00% |
| 1 | Image, IntegrityLevel, LogonId, ParentUser | 100.00% |
| 2 | CommandLine, CurrentDirectory, Hashes, ParentCommandLine | 99.91% |
| 3 | EventID, ParentProcessId, TargetFilename, ancestor_depth | 99.44% |
| 4 | Archived, Device, IsExecutable, enriched | **78.63%** |
| 5 | EventType, PreviousCreationUtcTime, Product, TargetObject | **67.35%** |
| จบ | เหลือ 74 feature | **64.22%** |

→ ตัด 20 คอลัมน์แล้วลดจาก 100% เหลือ 64.22% (ทายมั่ว 56.8%) **ยังไม่หมดแต่ลดได้จริง**

### ❌ event type ที่มีฝั่งเดียว — ตัดคอลัมน์ไม่ช่วย ต้องตัดทั้งแถว

| EventID | event | Linux | Windows |
|---------|-------|-------|---------|
| 2 | FileCreateTime | 0 | 1,743 |
| 8 | CreateRemoteThread | 0 | 1 |
| 12 | RegistryAddDelete | 0 | 106 |
| 13 | RegistrySetValue | 0 | 4,624 |
| 4 | (Linux only) | 6 | 0 |

`RegistrySetValue` คือ event ที่แบก signal มากสุดของเปเปอร์ (malicious 56.8%)
**ตัดทิ้ง = ทิ้งจุดแข็งของฝั่ง Windows**

### ⚠️ โมเดลทำนาย malicious ใช้ feature เดียวกับที่บอก platform 12/15 ตัว

acc 99.43% แต่ top-15 feature ซ้ำกับตัวที่บอก platform ถึง 12 ตัว
→ ความแม่นนั้นน่าจะมาจากทางลัด platform ไม่ใช่การเรียนพฤติกรรมมัลแวร์

⚠️ **ตัวเลข F1/acc ทุกตัวข้างบนใช้ `train_test_split` แบบสุ่มแถว จึงสูงเกินจริง**
event หลายแถวมาจาก process เดียวกัน สุ่มแล้วไปอยู่ทั้ง train และ test
**ตอนเทรนจริงต้องแบ่งตาม session หรือ `ProcessGuid` (GroupKFold)**

### สิ่งที่เปเปอร์ทำไว้แล้วและใช้ได้เลย

อ่าน `reference/1-s2.0-S277291842500027X-main.pdf` หัวข้อ 3.1:

- **ตัด `Image` เพราะ leakage** — เปเปอร์เขียนเองว่า "removed due to its direct
  association with the target variable (label)" ตรงกับที่เราวัดได้
- ตัดด้วย: `ProcessId`, `ProcessGUID`, `node_id`, `parent_node_id`, `UtcTime`,
  `timestamp`, `host_name`
- encode: null → `-1` ทุกที่ / categorical < 21 ค่า → label encoding /
  categorical ≥ 21 ค่า → **ความยาวสตริง** / numeric คงค่าเดิม
- เลือก feature ด้วย PCA ไล่ n=1..N เอา n ที่ F1 ดีสุด → RF 20 feature ได้ F1 0.8868

⚠️ **ลองใช้ encoder ของเปเปอร์แล้วยังแยก platform ได้ 100%**
เพราะเทคนิคความยาวสตริงใช้กับคอลัมน์ ≥21 ค่าเท่านั้น ส่วน `User`/`IntegrityLevel`
มีค่าน้อยจึง label encode แล้วได้เลขคนละชุดสองฝั่ง
เปเปอร์ไม่เจอปัญหานี้เพราะมี platform เดียว → **เราใช้ตามตรงๆ ไม่ได้**

### เครื่องมือที่มี (ไม่ได้อยู่ในท่อข้อมูล เป็นตัววินิจฉัย)

| ไฟล์ | ทำอะไร |
|------|--------|
| `host/check_merge.py` | ตรวจ 5 อย่างว่า merge ได้ไหม |
| `host/paper_encoding.py` | preprocessing ตามเปเปอร์เป๊ะ |
| `host/select_merge_features.py` | greedy backward elimination หา feature ที่ไม่รั่ว |
| `host/compare_nlme.py` | เทียบองค์ประกอบกับ NLME + พิสูจน์พฤติกรรมมัลแวร์ 4 ระดับ |
| `host/rebuild_dataset.py` | สร้าง CSV ใหม่จาก raw log |
| `host/merge_dataset.py` | รวมทุก session เป็น CSV เดียว **ดิบ 79 คอลัมน์ ไม่ encode** |

CSV ที่เอาไปเข้าเฟส ML คือผลจาก `merge_dataset.py` — ดิบทั้งหมด
การ encode/PCA/เลือก feature เป็นงานของโค้ด ML ไม่ใช่ของท่อเก็บข้อมูล

---

## 🚨 กับดักด้านระเบียบวิธี (สำคัญต่อความน่าเชื่อถือของธีสิส)

### 1. VM leakage
ถ้า VM1 = benign เท่านั้น, VM2 = ransomware เท่านั้น → โมเดลเรียนแค่ hostname
ได้ F1 สูงปลอม **ทุก VM ต้องรันทั้ง benign และ malicious**

### 2. Enrichment leakage
process ที่เกิด**หลัง** Sysmon มี CommandLine, daemon ที่เกิด**ก่อน**ไม่มี
ถ้า benign เป็น daemon ล้วน โมเดลจะเรียน "CommandLine ว่าง = benign"
→ `benign.sh` / `benign.ps1` ต้องสร้าง process ใหม่เยอะๆ ไม่ใช่ปล่อย idle

**วัดจริง 18 ส.ค. 2026:** CommandLine ว่าง 592 แถว (5.1%) เป็น benign **97.8%**
ยังมี leak เหลืออยู่แต่เล็ก — ตอนเทรนให้ลอง drop แถวที่ CommandLine ว่าง
หรือใส่ `has_commandline` เป็น feature ตรงๆ แล้ววัดเทียบ

### 3. คอลัมน์ที่ห้ามใส่เป็น feature
```
recv_timestamp, record_id, session, computer, host_ip,
ProcessGuid, LogonGuid, ParentProcessGuid, UtcTime,
CreationUtcTime, root_image, is_seed, label_method, enrich_method
```
เก็บใน CSV ได้ (เพื่อ trace) แต่ต้อง drop ก่อน `fit()`

### 4. Session labeling ทำ label ผิดยับ
เคยวัดแล้ว: session mode label malicious 100% ทั้งที่ lineage บอกแค่ 8.9%
→ **ใช้ lineage mode สำหรับ malicious เสมอ** ใช้ session แค่กับ benign

### 5. Platform leakage (ตอน merge Linux + Windows)
missing pattern ต่างกันชัดมาก — Windows มี `FileVersion/Description/Product/Signature`
แต่ Linux ว่าง 100%; Linux มี `CommandLine/Parent*` ครบแต่เปเปอร์ Windows ไม่มี
→ โมเดลแยก platform ได้ทันทีจาก missing pattern

**3 ทางเลือก:**
1. Intersection — ใช้เฉพาะคอลัมน์ที่มีทั้งสองฝั่ง (ปลอดภัยสุด แต่ทิ้ง CommandLine)
2. Union + `platform` เป็น feature (ต้อง balance สัดส่วน label ให้เท่ากันทั้งสอง platform)
3. **แยกเทรนแล้วเทียบผล** — ปลอดภัยที่สุดทางสถิติ และเขียนธีสิสได้น่าสนใจ
   ("Linux vs Windows feature effectiveness")

→ เอนไปทาง **3 หรือ 2** ส่วน 1 เสียของเปล่า

### 7. เทียบกับ NLME.csv ของเปเปอร์ — หลักฐานว่าเป็นพฤติกรรมมัลแวร์จริง

เครื่องมือ: `python host/compare_nlme.py host/dataset/<ชื่อ>_labeled.csv`
(ต้องมี `reference/NLME.csv` ซึ่ง gitignore ไว้)

**สิ่งที่วัดได้จาก NLME.csv (71,017 แถว) 23 ส.ค. 2026**

| EventID | เปเปอร์ | %mal | หมายเหตุ |
|---------|---------|------|----------|
| 11 FileCreate | 39.0% | 11.0% | |
| 1 ProcessCreate | 29.5% | 22.8% | |
| 13 RegistrySetValue | 19.6% | **56.8%** | event ที่แบก signal มากสุด |
| 8 CreateRemoteThread | 6.3% | 0.1% | |
| 5 ProcessTerminate | 2.1% | 70.9% | |
| 2 FileCreateTime | 1.8% | 29.3% | |
| 12 RegistryAddDelete | **1.6%** | **0.1%** | |
| 3 NetworkConnect | 0.03% | 100% | มีแค่ 20 แถว |

label เปเปอร์: benign 75.8% / malicious 24.2%

**ข้อค้นพบชี้ขาด: EventID 12 ของเปเปอร์ไม่มี `CreateKey` เลยสักแถว**
มีแต่ `DeleteValue` 1,126 + `DeleteKey` 20 → config ของเปเปอร์กรอง CreateKey ออก

ของเราก่อนแก้: EventID 12 = `CreateKey` 20,332 จาก 20,356 (99.9%) เจ้าของคือ `powershell.exe`
→ เพิ่ม `<EventType condition="is">CreateKey</EventType>` ใน RegistryEvent exclude
**นี่คือการทำให้ตรงเปเปอร์ ไม่ใช่แค่ลด noise** — อ้างอิงได้ว่าวัดจาก NLME.csv โดยตรง

**ผลหลังตัด CreateKey (trojan_win, 1,776 events):**

| EventID | เปเปอร์ | เรา | ต่าง |
|---------|---------|-----|------|
| 13 RegistrySetValue | 19.6% | 21.7% | **+2.1** |
| 1 ProcessCreate | 29.5% | 20.1% | −9.4 |
| 11 FileCreate | 39.0% | 15.0% | **−24.0** |
| 5 ProcessTerminate | 2.1% | 20.1% | **+18.0** |
| 23 FileDelete | 0% | 13.0% | +13.0 |
| 12 RegistryAddDelete | 1.6% | 1.4% | −0.3 |

ผลรวมความต่างสัมบูรณ์ = **83.1 จุด** (0 = เหมือนเป๊ะ, 200 = ไม่ทับกันเลย)
118,796 → 23,018 → **1,776** events

### หลักฐาน 4 ระดับ — ต้องรายงานแยก ห้ามนับรวมเป็น "มัลแวร์" ทั้งหมด

`label = 1` แปลว่า "สืบสายจาก `C:\lab_sandbox`" ไม่ได้แปลว่า event นั้นเป็นมัลแวร์ในตัวเอง
`compare_nlme.py` จึงแยกความแรงของหลักฐานเป็น 4 ระดับ (วัด trojan_win 1,118 แถว malicious):

| ระดับ | จำนวน | % | ความหมาย |
|-------|-------|---|----------|
| DIRECT | 509 | 45.5% | artifact อยู่ในคอลัมน์ของ event เอง — อ้างอิงได้เต็มปาก |
| PARENT | 168 | 15.0% | ตัว event ไม่มี artifact แต่ `ParentCommandLine` เป็นคำสั่งของ test |
| OSBOOK | 188 | 16.8% | OS จดของมันเอง (BAM, PowerShell startup profile) — **ไม่ใช่พฤติกรรมมัลแวร์** |
| LINEAGE | 253 | 22.6% | ไม่มีหลักฐานในตัว event ติด label เพราะสายเลือดล้วนๆ |

ตัวอย่าง DIRECT ที่ยกไปอ้างในธีสิสได้ตรงๆ:
```
T1112       HKU\<SID>\SOFTWARE\NetWire\HostId          (NetWire RAT registry key)
T1547.001   HKU\<SID>\...\CurrentVersion\Run\
T1036.003   C:\Users\vagrant\AppData\Roaming\taskhostw.exe   (powershell ถูกก๊อปมาสวมชื่อ)
T1053.005   schtasks /delete /tn "ATOMIC-T1053.005" /F
T1074.001   C:\lab_sandbox\trojan_stage\collected.zip
```

⚠️ **`compare_nlme.py` ต้องแมตช์แยกคอลัมน์** ห้ามเอาทุกคอลัมน์มาต่อกันแล้วยิง regex เดียว
เวอร์ชันแรกทำแบบนั้นแล้ว `-ExecutionPolicy` ใน CommandLine ไปโดน regex ของ registry
รายงาน T1112 = 549 แถวปลอม (ของจริง 120) ตัวที่โดนคือ BAM ของ Windows

### ใกล้เปเปอร์พอหรือยัง — วัดด้วยความแปรปรวนของเปเปอร์เอง

`python host/compare_nlme.py <labeled.csv> --variance`

เทียบเฉพาะแถว malicious (benign สองฝั่งมาจากคนละสภาพแวดล้อม เทียบไม่ได้)
วัดด้วย "ระยะห่างองค์ประกอบ" = ผลรวมความต่างสัมบูรณ์เป็นจุดเปอร์เซ็นต์ (0-200)

**วัดจริง 23 ส.ค. 2026 (trojan_win):**

| เทียบอะไร | ระยะ |
|-----------|------|
| WKSTN-3 vs ค่าเฉลี่ยเปเปอร์ | 41.3 |
| WKSTN-1 | 41.7 |
| WKSTN-2 | 55.1 |
| WKSTN-4 | 58.6 |
| WKSTN-5 | 67.7 |
| **trojan_win ของเรา** | **61.4** |

**host ของเปเปอร์เองต่างกันสูงสุด 122.3 จุด** (WKSTN-2 กับ WKSTN-5)
WKSTN-2 มี RegSetValue 72.7% / ProcessCreate 11.1%
WKSTN-5 มี RegSetValue 13.6% / ProcessCreate 59.2%

→ **"องค์ประกอบเดียวของเปเปอร์" ไม่มีอยู่จริง** การไล่ให้ตรงเป๊ะไม่ใช่เป้าหมายที่มีความหมาย
ของเราอยู่ในช่วงความแปรปรวนปกติของเขาแล้ว

**ปรับเพิ่มได้ตอน preprocessing ไม่ต้องเก็บใหม่:**

| ทำอะไร | ระยะ | เหลือแถว |
|--------|------|----------|
| ปัจจุบัน | 61.4 | 1,239 |
| ตัด event 23 FileDelete | **46.2** | 1,106 |
| ตัด 23 + 5 ProcessTerminate | 26.1 | 801 |

- **ตัด 23 มีเหตุผลรองรับ** — เปเปอร์ไม่ได้เก็บ event 23 และ 9 เลยสักแถว
  เราเปิดไว้เพื่อ merge กับ Linux → กรองออกตอนเทียบเปเปอร์ ใส่กลับตอน merge
- **ตัด 5 ต้องคิดให้ดี** — เปเปอร์มี ProcessCreate 27.8% แต่ ProcessTerminate 6.2%
  อัตราส่วน 4.5:1 ทั้งที่ทุก process ที่เกิดต้องตาย
  → การเก็บของเขาถูกตัดจบก่อน process ปิด **ตัดตามเขา = ลอกข้อบกพร่องมาด้วย**
  แนะนำให้เก็บไว้แล้วเขียนว่าเป็นข้อได้เปรียบ

ช่องว่างจริงที่เหลือ: `RegistrySetValue` ต่ำกว่า 19.3 จุด (26.7% vs 46.0%)
เพราะ `trojan_win` ใช้ T1112 แค่ 5 จาก 90 test — เพิ่มได้ถ้าต้องการ

### ที่ยังต้องแก้ก่อนเก็บจริง

1. ~~NetworkConnect malicious = 0%~~ → **แก้แล้วและยืนยันแล้ว 23 ส.ค. 2026**
   สาเหตุคือ Windows Defender ไม่ใช่ lineage และไม่ใช่ VM ต่อเน็ตไม่ได้ (ทดสอบได้ HTTP 200)
   หลังปิด Tamper Protection + provision + snapshot ใหม่ แล้วเก็บซ้ำ:

   | | Defender เปิด | Defender ปิด |
   |---|---|---|
   | NetworkConnect รวม | 77 | 121 |
   | NetworkConnect malicious | **0** | **6** |
   | events รวม | 1,776 | 1,894 |
   | FileCreate %mal | 46.2% | 56.4% |

   6 แถวที่ได้คือ telemetry จริงของ T1059.001 ที่เคยหายทั้งหมด:
   ```
   powershell.exe -> 185.199.109-111.133:443   (raw.githubusercontent.com CDN)
   mshta.exe      -> 104.18.21.213:80 / 23.50.237.120:80
   ```
   ตรงกับ test 5 (DownloadString), 7 (XmlDocument.Load), 8 (mshta download) พอดี

   ⚠️ ยังไม่เท่าเปเปอร์ (100% mal จาก 20 แถว) เพราะ `trojan_win` มี test ที่แตะเน็ตแค่ 3 ตัว
   ส่วน benign 108 แถวเป็น DNS ของ `svchost` — ตัวที่ออกแบบมาเก็บ network telemetry
   คือ `botnet_win` (beacon 30 รอบ) ซึ่งต้องเปิด `host/c2_server.py` ก่อนรัน
2. **FileCreate 15.0% เทียบเปเปอร์ 39.0%** — เปเปอร์เก็บ FileCreate เยอะกว่ามาก
   อาจเพราะ sample มัลแวร์จริงเขียนไฟล์เยอะกว่า ART test
3. **ProcessTerminate 20.1% เทียบเปเปอร์ 2.1%** — เปเปอร์แทบไม่มี event 5
   ควรพิจารณาตัดทิ้งตอน merge เพื่อให้องค์ประกอบใกล้กันขึ้น

---

### 6. Harness leakage — ฝั่ง Windows หนักกว่าที่คิด

**วัดจริง 23 ส.ค. 2026 (`trojan_win` รอบสมบูรณ์ หลังกรอง OS noise แล้ว, 23,018 events):**

| event | รวม | benign | malicious |
|-------|-----|--------|-----------|
| RegistryAddDelete | 20,356 (88.4%) | 23.2% | **76.8%** |
| RegistrySetValue | 806 | 65.5% | 34.5% |
| ProcessCreate | 378 | 23.3% | 76.7% |
| ProcessTerminate | 375 | 22.4% | 77.6% |
| FileCreate | 334 | 63.5% | 36.5% |
| RawAccessRead | 315 | **100%** | **0%** |
| FileDelete | 298 | 57.7% | 42.3% |
| NetworkConnect | 150 | **100%** | **0%** |
| CreateRemoteThread | 4 | 100% | 0% |

**ปัญหาที่ 1 — RegistryAddDelete = 88% ของ dataset และ 76.8% เป็น malicious**
เจ้าของคือ `powershell.exe` (malicious 15,194 / benign 3,846)
นี่ไม่ใช่พฤติกรรมมัลแวร์ แต่เป็น **registry churn ของตัว PowerShell เอง**
(โหลด module, resolve .NET assembly) ซึ่งเกิดเพราะ ART รันทุกอย่างผ่าน PowerShell

→ โมเดลจะเรียน "powershell เขียน registry รัวๆ = malicious" ซึ่งคือการเรียนรู้ **harness**
ไม่ใช่เรียนรู้มัลแวร์ ได้ F1 สูงปลอมแบบเดียวกับ VM leakage

ทางแก้ที่ต้องลอง (ยังไม่ได้ทำ):
- ตัด EventID 12 ทิ้ง เหลือ 13 (RegistrySetValue) ซึ่งเปเปอร์ใช้จริงและสมดุลกว่ามาก
- หรือ downsample event 12 ให้เหลือสัดส่วนใกล้ event อื่น
- หรือทำ benign scenario ให้รันผ่าน PowerShell เท่าๆ กัน เพื่อให้ churn ไม่ผูกกับ label

**ปัญหาที่ 2 — NetworkConnect / RawAccessRead / CreateRemoteThread malicious = 0%**
`trojan_win` มี T1059.001 test 8 (mshta download) แต่ไม่มี NetworkConnect ติด label เลย
แปลว่า test ที่ต้องใช้เน็ตไม่ทำงาน หรือ process ที่ต่อเน็ตไม่ถูกนับเข้า lineage
**ต้องไล่ก่อนเก็บข้อมูลจริง** ไม่งั้น 3 event type นี้กลายเป็น "benign เสมอ" = leakage ตรงๆ

**ปัญหาที่ 3 — สัดส่วน label แกว่งแรงตาม noise ที่กรอง**
ก่อนกรอง OS noise: malicious 24.2% / หลังกรอง: **72.8%**
สัดส่วน label ไม่ใช่คุณสมบัติของ scenario แต่ขึ้นกับว่าเก็บ background noise มาเท่าไหร่
→ อย่าอ้างตัวเลขนี้ในธีสิสโดยไม่ระบุ config ที่ใช้เก็บ

---

## สถานะปัจจุบัน

### raw log คือแหล่งความจริง — CSV สร้างใหม่ได้เสมอ

`host/dataset/*.csv` เป็นของที่ derive มาทั้งหมด ถ้าหาย/เสีย/อยากเปลี่ยนวิธี label
**ห้ามรัน VM เก็บใหม่** เพราะจะได้ข้อมูลคนละชุด เทียบกับของเก่าไม่ได้ ให้สร้างใหม่จาก raw log:

```powershell
python host/rebuild_dataset.py --platform linux --list     # ดูว่ามีอะไรทำได้
python host/rebuild_dataset.py --platform linux            # ทำตัวที่ยังไม่มี CSV
python host/rebuild_dataset.py --platform windows --force  # ทับของเดิม
```

อ่าน `label_spec` จาก `*_meta.json` ที่ orchestrator เขียนคู่กับ log
และ `seed_dir`/`seed_cmd` จาก `SCENARIOS` ของ orchestrator ตัวที่ตรงแพลตฟอร์ม

| เก็บไว้ที่ | คืออะไร | หายแล้วเป็นไง |
|-----------|---------|---------------|
| `host/logs/*.log` | syslog ดิบฝั่ง Linux | **เก็บใหม่อย่างเดียว** |
| `host/logs_win/*.xml` | EVTX export ฝั่ง Windows | **เก็บใหม่อย่างเดียว** |
| `host/logs*/*_meta.json` | label spec + ช่วงเวลา | เก็บใหม่ หรือเดาจาก SCENARIOS |
| `host/dataset/*.csv` | ของ derive | `rebuild_dataset.py` |

⚠️ ทั้ง `logs/`, `logs_win/`, `dataset/` ถูก gitignore — **ไม่มีสำเนาใน git**
raw log 2 โฟลเดอร์แรกควร backup ไว้ที่อื่นด้วย

**เสร็จแล้ว (Linux):**
- lab 1 VM + Sysmon + ท่อ log ทะลุถึง host
- pipeline parse→enrich→label ทำงานครบ
- Atomic Red Team ติดตั้งและรันได้ (ทุก test exit 0)
- enrichment ดันจาก 41.8% → 90.2%
- เก็บได้ **24,583 events จาก 6 scenario** (malicious 34.3%) — เกินเป้า 20,000 แล้ว

| scenario | แถว | malicious |
|----------|-----|-----------|
| benign | 5,330 | 0.0% |
| botnet | 2,249 | 45.5% |
| exploit_real | 6,646 | 39.6% |
| miner_real | 872 | 19.8% |
| ransomware | 5,591 | 64.0% |
| trojan_real | 3,895 | 26.2% |

(สร้างใหม่จาก raw log ด้วย `rebuild_dataset.py` เมื่อ 23 ส.ค. 2026 หลัง CSV หาย
raw log รอบ 21 ส.ค. ยังอยู่ครบจึงไม่ต้องเก็บใหม่)

**เสร็จแล้ว (Windows):**
- ART ติดตั้งแล้ว รัน `Invoke-AtomicTest` ได้
- `_lib.ps1` + `benign.ps1` + `ransomware_win.ps1` + `miner_win.ps1`
- `trojan_win.ps1` + `botnet_win.ps1` + `exploit_win.ps1` (ART-driven)
- เลข test ยืนยันกับ ART จริงบน VM แล้วครบทั้ง 5 scenario (202 เลข cross-check ผ่าน)
- `check_atomics.ps1` เขียนแล้ว — ทดสอบ parser ผ่าน fixture ครบทุกเคสยาก
  (decoy `supported_platforms` ในบล็อก description, test ที่ไม่ใช่ Windows แต่ index ต้องไม่เลื่อน,
  `input_arguments` ที่มี key ชื่อ `name`, executor `manual`, vssadmin/wevtutil)
- ทุก `.ps1` เป็น UTF-8 with BOM + syntax ผ่าน `[Parser]::ParseFile` ครบ

**ค้างอยู่:**
1. ~~FileCreate หาย~~ → แก้แล้ว (`restart sysmon` หลังบูต)
2. ~~malicious % ต่ำ~~ → ปิดแล้ว 30.9%
3. ~~process ถาม password ค้าง~~ → แก้โค้ดแล้ว รอยืนยันบน VM จริง
4. ~~Windows: ปิด Tamper Protection~~ → เสร็จแล้ว 23 ส.ค. 2026
   `RealTimeProtectionEnabled = False`, `IsTamperProtected = False` ใน snapshot `clean`
   ยืนยันด้วย `_diag_defender.ps1` และ NetworkConnect malicious กลับมา
   **dataset ทุกชุดที่เก็บก่อนหน้านี้ใช้ไม่ได้ ต้องเก็บใหม่ทั้ง 5 scenario**
5. ~~Windows: รัน `check_atomics.ps1` แก้เลข test~~ → เสร็จแล้ว 23 ส.ค. 2026
   (ดูตาราง "เลข Atomic test ที่ยืนยันบน Windows VM แล้ว")
6. ~~Windows: ทดสอบ `trojan_win.ps1` ตัวเดียว~~ → เสร็จแล้ว 23 ส.ค. 2026
   23,018 events / enrich 79.9% / lineage malicious 72.8% / atomic ครบ 12 technique + cleanup
   **แต่เจอ harness leakage ต้องแก้ก่อนเก็บจริง (ดูกับดักข้อ 6)**
7. ขยายเป็น 5 VM (loop ใน Vagrantfile)
8. เก็บข้อมูลจริง ≥20,000 events ตามตาราง 15 รอบใน RUNBOOK.md
9. **เฟส 3**: preprocessing + PCA + เทรน 7 โมเดลตามเปเปอร์
   (Naive Bayes, Decision Tree, Random Forest, SVM / Isolation Forest, LOF, One-Class SVM)
10. Merge Linux + Windows — ระวัง platform leakage (ดูข้อ 5 ด้านบน)

---

## คำสั่งที่ใช้บ่อย

```powershell
# terminal 1
python host\log_receiver.py --session r01_target1_benign
# terminal 2
python host\c2_server.py
# terminal 3
python host\orchestrator.py --save-snapshot --vm target1
python host\orchestrator.py --scenario ransomware --vm target1 --duration 5
python host\orchestrator.py --list

# ตรวจ atomic test ที่มี
vagrant ssh target1 -c "sudo bash /vagrant/scenarios/check_atomics.sh" > atomic_report.txt
# (ใน Windows VM) - ต้องรันในเครื่องที่มี C:\AtomicRedTeam\atomics เท่านั้น
# หรือสั่งจาก host โดยไม่ต้องเปิดหน้าจอ VM:
#   vagrant up wintarget
#   vagrant powershell wintarget -c "& C:\vagrant\scenarios_win\check_atomics.ps1 > C:\vagrant\atomic_report_win.txt"
# ⚠️ `>` ของ PowerShell 5.1 เขียนไฟล์เป็น UTF-16LE ต้องแปลงก่อนอ่านบน host
powershell -ExecutionPolicy Bypass -File .\scenarios_win\check_atomics.ps1 > atomic_report_win.txt
.\scenarios_win\check_atomics.ps1 -PasteOnly          # เอาแค่บรรทัดพร้อมวาง
.\scenarios_win\check_atomics.ps1 -Technique T1486    # เจาะดูตัวเดียว

# vagrant
vagrant provision target1        # รัน provisioner ซ้ำ (ต้องทำหลังแก้ provision/*)
vagrant snapshot list target1
```

⚠️ **หลัง `vagrant provision` ทุกครั้ง ต้อง `--save-snapshot` ใหม่**
ไม่งั้น revert จะย้อนไปสภาพก่อนแก้

---

## แนวทางการทำงานกับโปรเจคนี้

- **ห้ามเขียน payload มัลแวร์เพิ่ม** — สาม scenario ฝั่ง Windows (trojan/botnet/exploit,miner,ransomware)
  ตั้งใจให้เป็น ART-driven ดูเหตุผลในหัวข้อ "ทำไม trojan/botnet/exploit เป็น ART-driven"
- ระบุเลข test เสมอเมื่อเรียก `atomic` / `Atomic` — ไม่ระบุ = รันทุก test = อันตราย
- ทุกอย่างที่ scenario สร้างต้องอยู่ใน `/tmp/lab_sandbox` (Linux) หรือ `C:\lab_sandbox` (Windows)
- revert snapshot ก่อนทุก scenario (orchestrator ทำให้แล้ว)
- ก่อน commit dataset ให้รันตรวจ 4 อย่างในส่วน F ของ `RUNBOOK.md`
  (สัดส่วน label / hostname leak / CommandLine leak / event type ครบ)
- ตรวจ syntax ก่อนทุกครั้ง: `bash -n` (sh) / `[ScriptBlock]::Create((Get-Content -Raw x.ps1))` (ps1)
- ไฟล์ `.sh` ต้องเป็น **LF** / ไฟล์ `.ps1` ต้องเป็น **UTF-8 with BOM**