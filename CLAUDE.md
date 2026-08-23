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

แก้ (รันตอน provision, ต้อง Administrator):
```powershell
Add-MpPreference -ExclusionPath "C:\lab_sandbox"
Add-MpPreference -ExclusionPath "C:\AtomicRedTeam"
# ถ้ายังโดนบล็อก (VM revert ได้อยู่แล้ว):
Set-MpPreference -DisableRealtimeMonitoring $true
```
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

**เสร็จแล้ว (Linux):**
- lab 1 VM + Sysmon + ท่อ log ทะลุถึง host
- pipeline parse→enrich→label ทำงานครบ
- Atomic Red Team ติดตั้งและรันได้ (ทุก test exit 0)
- enrichment ดันจาก 41.8% → 90.2%
- เก็บได้ 11,691 events จาก 2 รอบ (malicious 30.9%)

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
4. **Windows: ตั้ง Defender exclusion** ก่อนรัน scenario ใดๆ (โดนทั้ง 5 ตัว ไม่ใช่แค่ miner/ransomware)
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