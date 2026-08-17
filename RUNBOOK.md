# RUNBOOK — Sysmon for Linux Malware Dataset

ลำดับการรันและวิธีทดสอบ ตั้งแต่ setup จนได้ dataset พร้อมเทรน

**หลักการ:** แต่ละขั้นมี ✅ CHECK — ถ้าไม่ผ่าน **หยุดแก้ก่อน** อย่าข้ามไปขั้นถัดไป
เพราะ error ต้นทางจะทำให้ dataset เสียทั้งชุดโดยไม่รู้ตัว

---

## ส่วน A — ตรวจความพร้อม (ทำครั้งเดียว)

### A1. เครื่องมือบน Windows host

```powershell
vagrant --version
vagrant plugin list                      # ต้องมี vagrant-vmware-desktop
Get-Service vagrant-vmware-utility       # ต้อง Running
python --version                         # 3.10+
```

✅ **CHECK:** ทุกคำสั่งขึ้นผลลัพธ์ ไม่มี error

### A2. Firewall

```powershell
# รันใน PowerShell (Admin) — เปิดพอร์ตทั้งหมดที่ใช้
New-NetFirewallRule -DisplayName "Sysmon Lab Listener" -Direction Inbound -LocalPort 5514 -Protocol TCP -Action Allow
New-NetFirewallRule -DisplayName "Lab C2 HTTP"        -Direction Inbound -LocalPort 8080 -Protocol TCP -Action Allow
New-NetFirewallRule -DisplayName "Lab C2 TCP"         -Direction Inbound -LocalPort 3333,4444 -Protocol TCP -Action Allow
```

✅ **CHECK:** `Get-NetFirewallRule -DisplayName "Lab*"` เห็น 3 rules

### A3. โครงสร้างไฟล์

```
sysmon-lab\
├── Vagrantfile                       (เวอร์ชัน VMware, ไม่มี vhv.enable)
├── provision\
│   ├── install_sysmon.sh
│   ├── install_art.sh
│   └── sysmon-config.xml             (เวอร์ชัน fixed — schema 4.81)
├── scenarios\
│   ├── _lib.sh  benign.sh  ransomware.sh  trojan.sh
│   ├── botnet.sh  exploit.sh  miner.sh  check_atomics.sh
└── host\
    ├── log_receiver.py  orchestrator.py  c2_server.py
    ├── parse_sysmon.py  enrich_events.py  label_events.py
    └── explore_events.py
```

✅ **CHECK:** ไฟล์ `.sh` ทุกตัวเป็น **LF** ไม่ใช่ CRLF (ดูมุมขวาล่าง VS Code)

---

## ส่วน B — สร้าง VM (ทำครั้งเดียวต่อ VM)

### B1. Provision

```powershell
vagrant up target1
```
ใช้เวลา ~20-30 นาที (Ubuntu box + Sysmon + PowerShell + atomics)

✅ **CHECK:**
```powershell
vagrant ssh target1 -c "sudo systemctl is-active sysmon"      # active
vagrant ssh target1 -c "sudo systemctl is-active rsyslog"     # active
vagrant ssh target1 -c "pwsh --version"                       # PowerShell 7.x
vagrant ssh target1 -c "ls /opt/AtomicRedTeam/atomics | wc -l"  # > 100
vagrant ssh target1 -c "ls -l /tmp/lab_sandbox/run_atomic.sh"  # มีไฟล์ +x
```

### B2. ตรวจว่า atomic test ไหนรองรับ Linux ⚠️ ขั้นที่คนข้าม

```powershell
vagrant ssh target1 -c "sudo bash /vagrant/scenarios/check_atomics.sh" > atomic_report.txt
notepad atomic_report.txt
```

✅ **CHECK:** เปิดไฟล์ดู แล้ว **แก้ scenarios/*.sh** ให้ใส่เลข test ที่รองรับ Linux

```bash
atomic T1486          # เดิม — รันทุก test (บาง test เป็น Windows รันเปล่า)
atomic T1486 2,3      # แก้เป็น — เฉพาะเลขที่ report บอกว่า Linux
```

### B3. บันทึก clean snapshot

```powershell
cd host
python orchestrator.py --save-snapshot --vm target1
```

✅ **CHECK:** `vagrant snapshot list target1` เห็น `clean`

> ⚠️ ต้องทำ **หลัง** provision เสร็จและ check ผ่านแล้ว ไม่งั้น revert จะกลับไปสภาพที่ยังไม่มี ART

---

## ส่วน C — Smoke test (พิสูจน์ pipeline ก่อนเก็บของจริง)

รอบนี้ใช้เวลาสั้น แค่ยืนยันว่าทุกชิ้นต่อกันติด

### C1. เปิด 3 terminal

```powershell
# Terminal 1 — listener
cd host
python log_receiver.py --session smoke_test

# Terminal 2 — C2 จำลอง
cd host
python c2_server.py

# Terminal 3 — สั่งงาน
cd host
```

### C2. รัน benign สั้นๆ

```powershell
python orchestrator.py --scenario benign --vm target1 --duration 2
```

✅ **CHECK ทีละชั้น:**

| ชั้น | ดูที่ | ต้องเห็น |
|------|-------|---------|
| VM ทำงาน | Terminal 3 | `[1/6]...[6/6]` ครบ ไม่มี error |
| log ไหล | Terminal 1 | `...รับแล้ว N events` เพิ่มขึ้นเรื่อยๆ |
| parse | Terminal 3 | `เขียนแล้ว: ...events.csv (N แถว x 49 คอลัมน์)` |
| enrich | Terminal 3 | `แถวที่ถูกเติมข้อมูล : N` |
| label | Terminal 3 | `สัดส่วน label: 0=N (100.0%)` |

### C3. รัน malicious สั้นๆ

```powershell
python orchestrator.py --scenario ransomware --vm target1 --duration 3
```

✅ **CHECK สำคัญที่สุด:**
```
[lineage] seed process : > 0        ← ถ้าเป็น 0 คือ labeling พัง!
[lineage] events = 1   : > 0
```

**ถ้า seed = 0** แปลว่า labeler หา process ของ ART ไม่เจอ ให้ debug:
```powershell
# ดูว่ามี process ที่มาจาก sandbox จริงไหม
python -c "import csv; rows=list(csv.DictReader(open('dataset/smoke_test_enriched.csv',encoding='utf-8'))); [print(r['Image'], '|', r['CommandLine'][:60]) for r in rows if 'sandbox' in (r['Image']+r['CommandLine']).lower()][:10]"
```

### C4. ตรวจว่า C2 ได้รับการเชื่อมต่อ

```powershell
python orchestrator.py --scenario botnet --vm target1 --duration 3
```

✅ **CHECK:** Terminal 2 เห็น `[http] ... GET /beacon?id=bot1` และ `[tcp:4444]`

### C5. สำรวจ event ที่ได้

```powershell
python explore_events.py (Get-ChildItem logs\*.log | Sort-Object LastWriteTime -Last 1).FullName
```

✅ **CHECK:** เห็น EventID 1, 3, 5, 11, 23 และ field ที่ useful% > 0

**ถ้า smoke test ผ่านทั้งหมด → พร้อมเก็บของจริง**

---

## ส่วน D — ขยายเป็น 5 VM

### D1. แก้ Vagrantfile

แทน block `config.vm.define "target1"` ด้วย loop:

```ruby
  (1..5).each do |i|
    config.vm.define "target#{i}" do |node|
      node.vm.hostname     = "target#{i}"
      node.vm.boot_timeout = 600
      node.vm.network "private_network", ip: "192.168.56.#{10+i}"

      node.vm.provider "vmware_desktop" do |v|
        v.vmx["displayname"]    = "lab-target#{i}"
        v.memory = 2048
        v.cpus   = 2
        v.gui    = false
        v.vmx["sound.present"]  = "FALSE"
        v.vmx["usb.present"]    = "FALSE"
        v.vmx["msg.autoAnswer"] = "TRUE"
      end

      node.vm.provision "shell", path: "provision/install_sysmon.sh",
        env: { "HOST_IP" => HOST_IP, "LOG_PORT" => LOG_PORT.to_s }
      node.vm.provision "shell", path: "provision/install_art.sh"
    end
  end
```

### D2. สร้างทีละเครื่อง (RAM 32GB รันพร้อมกันไม่ไหว)

```powershell
vagrant up target2
python host\orchestrator.py --save-snapshot --vm target2
vagrant halt target2
# ทำซ้ำสำหรับ target3, 4, 5
```

✅ **CHECK:** `vagrant snapshot list target5` เห็น `clean`

---

## ส่วน E — เก็บข้อมูลจริง (Collection Campaign)

### ⚠️ กฎเหล็ก: ทุก VM ต้องรันทั้ง benign และ malicious

ถ้า VM1 = benign เท่านั้น, VM2 = ransomware เท่านั้น โมเดลจะเรียนแค่ชื่อเครื่อง
ได้ F1 สูงปลอม พอเจอเครื่องใหม่จะพัง

### E1. ตารางเก็บข้อมูล (รอบละ ~15 นาที)

| รอบ | VM | scenario | นาที |
|-----|----|----------|------|
| 1 | target1 | benign | 10 |
| 2 | target1 | ransomware | 10 |
| 3 | target2 | benign | 10 |
| 4 | target2 | trojan | 10 |
| 5 | target3 | benign | 10 |
| 6 | target3 | botnet | 10 |
| 7 | target4 | benign | 10 |
| 8 | target4 | exploit | 10 |
| 9 | target5 | benign | 10 |
| 10 | target5 | miner | 10 |
| 11 | target1 | trojan | 10 |
| 12 | target2 | ransomware | 10 |
| 13 | target3 | miner | 10 |
| 14 | target4 | botnet | 10 |
| 15 | target5 | exploit | 10 |

รอบ 11-15 คือการ **สลับคู่** ให้มัลแวร์แต่ละชนิดอยู่บนหลาย VM
ทำให้ hostname ทำนายทั้ง label และ family ไม่ได้

### E2. คำสั่งแต่ละรอบ

```powershell
# Terminal 1 — เปลี่ยน --session ทุกรอบ
python log_receiver.py --session r01_target1_benign

# Terminal 2 — เปิดค้างไว้ทุกรอบ
python c2_server.py

# Terminal 3
python orchestrator.py --scenario benign --vm target1 --duration 10
```

จบรอบแล้ว **กด Ctrl+C ที่ Terminal 1** แล้วเปิดใหม่ด้วย `--session` ของรอบถัดไป
(เพื่อให้ log แยกไฟล์ต่อรอบ ไม่ปนกัน)

### E3. วัดปริมาณข้อมูล

```powershell
python -c "import glob,csv; t=sum(len(list(csv.DictReader(open(f,encoding='utf-8')))) for f in glob.glob('dataset/*_labeled.csv')); print(f'รวม {t:,} events')"
```

✅ **CHECK:** เป้าหมายอย่างน้อย **20,000 events** (เปเปอร์อ้างอิงใช้ 71,017)
ถ้าได้น้อย ให้เพิ่มรอบหรือเพิ่ม `--duration`

---

## ส่วน F — ตรวจคุณภาพ dataset ก่อนเทรน

### F1. รวมไฟล์

```powershell
python -c @"
import glob, csv
files = sorted(glob.glob('dataset/*_labeled.csv'))
rows, cols = [], None
for f in files:
    r = list(csv.DictReader(open(f, encoding='utf-8')))
    if r:
        cols = cols or list(r[0].keys())
        rows += r
with open('dataset/ALL.csv','w',newline='',encoding='utf-8') as o:
    w = csv.DictWriter(o, fieldnames=cols); w.writeheader(); w.writerows(rows)
print(f'รวม {len(rows):,} แถว จาก {len(files)} ไฟล์')
"@
```

### F2. ตรวจ 4 อย่าง (ทำทุกครั้งก่อนเทรน)

```powershell
python -c @"
import csv
from collections import Counter, defaultdict
rows = list(csv.DictReader(open('dataset/ALL.csv', encoding='utf-8')))
n = len(rows)

# 1. สัดส่วน label
c = Counter(r['label'] for r in rows)
print('LABEL:', dict(c), f'  malicious = {c[\"1\"]/n*100:.1f}%')

# 2. hostname ทำนาย label ได้ไหม  <-- สำคัญสุด
print()
print('HOSTNAME vs LABEL:')
m = defaultdict(Counter)
for r in rows: m[r['computer']][r['label']] += 1
for h, cc in sorted(m.items()):
    tot = sum(cc.values())
    pct = cc['1']/tot*100
    flag = '  <-- LEAK! VM นี้มี label เดียว' if (cc['0']==0 or cc['1']==0) else ''
    print(f'  {h:<12} n={tot:<7} malicious={pct:5.1f}%{flag}')

# 3. CommandLine ว่าง/ไม่ว่าง ทำนาย label ได้ไหม
print()
has = Counter(); non = Counter()
for r in rows:
    (has if r['CommandLine'].strip() else non)[r['label']] += 1
print(f'CommandLine มีค่า  : malicious {has[\"1\"]/max(sum(has.values()),1)*100:5.1f}%')
print(f'CommandLine ว่าง   : malicious {non[\"1\"]/max(sum(non.values()),1)*100:5.1f}%')
print('  (ถ้าต่างกันมาก = enrichment leakage ต้องเพิ่ม benign process activity)')

# 4. event type distribution
print()
print('EVENT:', dict(Counter(r['event_name'] for r in rows)))
"@
```

✅ **CHECK ทั้ง 4:**

| ตรวจ | เกณฑ์ผ่าน |
|------|-----------|
| สัดส่วน label | malicious 5-40% (ไม่ต้อง 50/50 แต่ห้ามน้อยกว่า 5%) |
| hostname | **ทุก VM ต้องมีทั้ง label 0 และ 1** — ไม่มี `LEAK!` |
| CommandLine | สองกลุ่มมี malicious% ใกล้กัน (ห่างไม่เกิน ~30 จุด) |
| event type | มีครบ 5 ชนิด (1, 3, 5, 11, 23) |

### F3. ตัดคอลัมน์ที่โกงได้ก่อนเทรน

ห้ามใส่เป็น feature:
```
recv_timestamp, record_id, session, computer, host_ip,
ProcessGuid, LogonGuid, ParentProcessGuid, UtcTime,
CreationUtcTime, root_image, is_seed, label_method, enrich_method
```

เก็บไว้ใน CSV ได้ (เพื่อ trace) แต่ drop ก่อน `fit()`

---

## Troubleshooting

| อาการ | สาเหตุ | แก้ |
|-------|--------|-----|
| ไม่มี log เข้า Terminal 1 | firewall / IP ผิด | `vagrant ssh target1 -c "ping -c 3 192.168.56.1"` |
| `sysmon: Segmentation fault` | config schema ผิด | ใช้ sysmon-config เวอร์ชัน 4.81 ไม่ใส่ FieldSizes |
| `Failed to start the virtual machine` | `vhv.enable` เปิดอยู่ | ลบบรรทัดนั้นจาก Vagrantfile |
| `[lineage] seed process : 0` | labeler หา seed ไม่เจอ | เช็คว่า `/tmp/lab_sandbox/run_atomic.sh` ยังอยู่หลัง revert |
| atomic test ไม่เกิดอะไร | เป็น test ของ Windows | รัน `check_atomics.sh` แล้วใส่เลข test |
| events น้อยเกินไป | scenario สั้น | เพิ่ม `--duration` หรือเพิ่มรอบใน loop ของ scenario |
| C2 ไม่เห็นการเชื่อมต่อ | firewall 8080/3333/4444 | เพิ่ม rule ตาม A2 |

---

## สรุปลำดับสั้นๆ

```
A. ตรวจเครื่องมือ + firewall + ไฟล์
B. vagrant up → check sysmon/ART → check_atomics.sh → save snapshot
C. smoke test: benign 2 นาที → ransomware 3 นาที → ตรวจ seed > 0
D. ขยาย 5 VM → snapshot ทุกเครื่อง
E. เก็บ 15 รอบตามตาราง (ทุก VM มีทั้ง benign และ malicious)
F. รวมไฟล์ → ตรวจ 4 อย่าง → ตัดคอลัมน์โกง → พร้อมเทรน
```