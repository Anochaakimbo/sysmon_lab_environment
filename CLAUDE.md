# CLAUDE.md — Sysmon for Linux Malware Detection Dataset

โปรเจคจบ: สร้าง dataset สำหรับ ML-based malware detection จาก **Sysmon for Linux**
ต่อยอดจากเปเปอร์อ้างอิงที่ทำบน Windows (Achmad et al., *Cyber Security and Applications* 3, 2025, 100110)

---

## สภาพแวดล้อม

| รายการ | ค่า |
|--------|-----|
| Host | Windows 11, Ryzen 7 9700X, RAM 32GB |
| Hypervisor | **VMware Workstation Pro** + Vagrant (ไม่ใช่ VirtualBox — บูตไม่ผ่านเพราะ Hyper-V) |
| Guest | Ubuntu 22.04 (`bento/ubuntu-22.04`), 2 vCPU / 2GB |
| Network | NAT + host-only `192.168.56.0/24`, host = `192.168.56.1` |
| Log transport | Sysmon → journald → rsyslog → TCP 5514 → Python listener บน host |
| Attack emulation | Atomic Red Team (ผ่าน PowerShell Core ใน VM) |

RAM 32GB รัน 5 VM พร้อมกันไม่ได้ → **รันทีละเครื่อง** (sequential)

---

## โครงสร้างโปรเจค

```
sysmon-lab/
├── Vagrantfile                    # VMware provider
├── provision/
│   ├── install_sysmon.sh          # Sysmon + rsyslog (ปิด rate limit)
│   ├── install_tools.sh           # net-tools, gpg, 7z, ccrypt ฯลฯ
│   ├── install_art.sh             # PowerShell Core + Atomic Red Team
│   └── sysmon-config.xml          # schema 4.81
├── scenarios/
│   ├── _lib.sh                    # ฟังก์ชันร่วม (atomic, banner, setup_sandbox)
│   ├── benign.sh                  # label = 0
│   ├── ransomware.sh  trojan.sh  botnet.sh  exploit.sh  miner.sh
│   └── check_atomics.sh           # list Linux tests จาก YAML
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

---

## Pipeline

```
scenario ใน VM
   → Sysmon (eBPF)
   → journald → rsyslog → TCP 5514
   → host/log_receiver.py           → logs/<session>.log
   → parse_sysmon.py                → 49 คอลัมน์
   → enrich_events.py               → 54 คอลัมน์ (เติม CommandLine/Hashes/Parent*)
   → label_events.py                → 56 คอลัมน์ (label + is_seed)
```

`orchestrator.py` เรียก parse→enrich→label ให้อัตโนมัติหลังจบ scenario

---

## ข้อค้นพบสำคัญ (อย่าทำซ้ำความผิดเดิม)

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

### ความผิดพลาดที่เคยเจอและวิธีแก้

| อาการ | สาเหตุ | แก้แล้วโดย |
|-------|--------|-----------|
| VM บูตค้าง "Loading essential drivers" | VirtualBox + Hyper-V | ย้ายไป VMware |
| `Failed to start the virtual machine` | `vhv.enable = TRUE` ขอ nested virt | ลบบรรทัดนั้น |
| `sysmon: Segmentation fault` | config มี `FieldSizes` + schema 4.90 | ใช้ schema **4.81** ไม่ใส่ FieldSizes |
| field ทั้งหมดว่างใน explore | regex ใช้ `Name='...'` แต่ log ใช้ `"..."` | แก้ regex รับทั้งสองแบบ |
| FileCreate event หายทั้งหมด | rsyslog/journald rate limiting ทิ้ง burst | ปิด rate limit 3 ชั้น |
| malicious แค่ 5.1% | scenario รันจาก `/vagrant/` ไม่ตรง seed | ก๊อป scenario ไป `/tmp/lab_sandbox` ก่อนรัน |
| `atomic T1070.004` ไม่ระบุเลข | test 8 = **Delete Filesystem ล้างเครื่อง** | ล็อกเป็น `1,2,3` เท่านั้น |
| checker v1 บอก "ไม่มี Linux test" ผิด | grep คำว่า "linux" ในชื่อ test | v2 อ่าน `supported_platforms` จาก YAML |
| `vagrant ssh -c` ค้างเงียบ ไม่มีเอาต์พุต | ACL ของ `private_key` กว้างเกิน (Authenticated Users) → OpenSSH ทิ้ง key แล้วตกไปถาม **password ของ vagrant** | `icacls /inheritance:r /grant:r "$USER:(R)"` + `preflight_ssh_key()` เช็คให้ทุกรอบ |
| log ไม่ถึง host เลยหลัง revert (Send-Q บวมค้าง) | snapshot คืน **memory state** มาด้วย → rsyslogd ตื่นมาพร้อม TCP socket เก่าที่ host ตายไปแล้ว | `systemctl restart rsyslog` หลังบูตทุกครั้ง (orchestrator ทำให้แล้ว) |
| **FileCreate(11) + RawAccessRead(9) หายเกลี้ยงทั้งรอบ** (event อื่นมาปกติ) | ไม่ใช่ rate limit! snapshot คืน memory state → **eBPF probe ของ sysmon อยู่ในสภาพ stale** ยิง 2 event นี้ไม่ออก | `systemctl restart sysmon` หลังบูต — ยืนยันแล้ว event 11 กลับมา 108 ตัวใน 15 วินาที |

---

## เลข Atomic test ที่ยืนยันบนเครื่องนี้แล้ว

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

## 🚨 กับดักด้านระเบียบวิธี (สำคัญต่อความน่าเชื่อถือของธีสิส)

### 1. VM leakage
ถ้า VM1 = benign เท่านั้น, VM2 = ransomware เท่านั้น → โมเดลเรียนแค่ hostname
ได้ F1 สูงปลอม **ทุก VM ต้องรันทั้ง benign และ malicious**

### 2. Enrichment leakage
process ที่เกิด**หลัง** Sysmon มี CommandLine, daemon ที่เกิด**ก่อน**ไม่มี
ถ้า benign เป็น daemon ล้วน โมเดลจะเรียน "CommandLine ว่าง = benign"
→ `benign.sh` ต้องสร้าง process ใหม่เยอะๆ ไม่ใช่ปล่อย idle
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

---

## สถานะปัจจุบัน

**เสร็จแล้ว:**
- lab 1 VM + Sysmon + ท่อ log ทะลุถึง host
- pipeline parse→enrich→label ทำงานครบ (ทดสอบแล้ว 3,074 events)
- Atomic Red Team ติดตั้งและรันได้ (ทุก test exit 0)
- enrichment ดันจาก 41.8% → 90.2%

**ค้างอยู่:**
1. ~~ยืนยันว่า FileCreate กลับมาหลังปิด rate limit~~ → **เจอสาเหตุจริงแล้ว: ไม่ใช่ rate limit**
   snapshot restore ทำให้ eBPF probe ของ sysmon stale → ต้อง `restart sysmon` หลังบูต (ใส่ใน orchestrator แล้ว)
   หมายเหตุ: rate limit ถูกปิดอยู่แล้วจริง (`systemd-analyze cat-config` ยืนยัน `RateLimitIntervalSec=0`)
2. ~~ยืนยันว่า malicious % ขึ้นเป็น 15-40%~~ → **ปิดแล้ว 18 ส.ค. 2026: รวม 2 รอบได้ 30.9%**
   (ransomware 65.1% + benign 0% = 11,691 events) lineage ไม่ over-label, benign สะอาด 100%
3. ~~process ที่ถาม password/passphrase ค้าง terminal~~ → **แก้โค้ดแล้ว รอยืนยันบน VM จริง**
   `atomic()` = `setsid --wait` + `timeout` + `< /dev/null` + `reap_stuck` (pkill)
   `vm_exec()` = `stdin=DEVNULL` + timeout + `vm_kill_stuck()`; ฝั่ง VM ครอบ `sudo timeout` อีกชั้น
   ปรับเวลาได้ด้วย `--atomic-timeout` (default 240s)
4. ขยายเป็น 5 VM (loop ใน Vagrantfile)
5. เก็บข้อมูลจริง ≥20,000 events ตามตาราง 15 รอบใน RUNBOOK.md
   (มีแล้ว 11,691 จาก 2 รอบ: `fix3_final_*` ransomware + `fix3_benign_*`)
6. **เฟส 3**: preprocessing + PCA + เทรน 7 โมเดลตามเปเปอร์
   (Naive Bayes, Decision Tree, Random Forest, SVM / Isolation Forest, LOF, One-Class SVM)
7. แผนอนาคต: merge กับ dataset ฝั่ง Windows (มีคอลัมน์ `platform` เตรียมไว้แล้ว)
   — ระวัง platform leakage เพราะ missing pattern ต่างกันชัด

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

# ตรวจ Linux test ที่มี
vagrant ssh target1 -c "sudo bash /vagrant/scenarios/check_atomics.sh" > atomic_report.txt

# vagrant
vagrant provision target1        # รัน provisioner ซ้ำ (ต้องทำหลังแก้ provision/*)
vagrant snapshot list target1
```

⚠️ **หลัง `vagrant provision` ทุกครั้ง ต้อง `--save-snapshot` ใหม่**
ไม่งั้น revert จะย้อนไปสภาพก่อนแก้

---

## แนวทางการทำงานกับโปรเจคนี้

- อย่ารันมัลแวร์จริง — ใช้ Atomic Red Team เท่านั้น
- ทุกอย่างที่ scenario สร้างต้องอยู่ใน `/tmp/lab_sandbox`
- revert snapshot ก่อนทุก scenario (orchestrator ทำให้แล้ว)
- ก่อน commit dataset ให้รันตรวจ 4 อย่างในส่วน F ของ `RUNBOOK.md`
  (สัดส่วน label / hostname leak / CommandLine leak / event type ครบ)
- เวลาแก้ scenario ให้ตรวจ `bash -n` ก่อนทุกครั้ง
- ไฟล์ `.sh` ต้องเป็น **LF** ไม่ใช่ CRLF