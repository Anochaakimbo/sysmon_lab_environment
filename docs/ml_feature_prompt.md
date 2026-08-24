# Prompt สำหรับ Cross-platform Malware Feature Engineering

ปรับจากฉบับร่าง โดยเพิ่มข้อมูลที่ **วัดได้จริง** จากโปรเจคนี้ (ดู CLAUDE.md)
ตัวเลขทุกตัวในนี้มาจากการทดลอง ไม่ใช่การคาดเดา

---

## บริบทที่ต้องบอกโมเดล/ผู้ช่วยก่อนเสมอ

ฉันทำ Cross-platform Malware Detection จาก **Sysmon for Windows** และ **Sysmon for Linux**
CSV มาจากแล็บ VM ที่รัน Atomic Red Team ตาม scenario แล้ว label ด้วย **lineage**

**สิ่งที่ต้องรู้เกี่ยวกับ label ก่อนทำ feature:**

- `label = 1` แปลว่า **"event นี้เกิดจาก process ที่สืบสายมาจากโฟลเดอร์ sandbox"**
  (`/tmp/lab_sandbox` บน Linux, `C:\lab_sandbox` บน Windows)
  **ไม่ได้แปลว่า event นั้นมีลักษณะเป็นมัลแวร์ในตัวเอง**
- วัดจริงจาก `trojan_win` 1,239 แถวที่ label=1:
  | ระดับหลักฐาน | % | ความหมาย |
  |---|---|---|
  | DIRECT | 44.9% | artifact อยู่ในคอลัมน์ของ event เอง (Run key, schtasks, ไฟล์ staging) |
  | PARENT | 14.9% | ตัว event ไม่มี artifact แต่ parent เป็นคำสั่งของ test |
  | OSBOOK | 16.5% | **OS จดของมันเอง** (BAM, PowerShell startup profile) ไม่ใช่พฤติกรรมมัลแวร์ |
  | LINEAGE | 23.7% | ไม่มีหลักฐานในตัว event ติด label เพราะสายเลือดล้วนๆ |

→ ราว **40% ของแถว malicious ไม่มีพฤติกรรมมัลแวร์ในตัวเอง** ถ้าเอาไปสอนตรงๆ
โมเดลจะเรียน noise ให้พิจารณาว่าจะ aggregate ขึ้นระดับ process/tree
(ซึ่งกลบปัญหานี้ได้) หรือจะกรอง OSBOOK ออก

---

## 1. ตรวจ Dataset

- rows / columns / missing values
- label distribution **แยกตาม platform** (ไม่ใช่รวม)
- EventID distribution **แยกตาม platform**
- จำนวน session และจำนวนแถวต่อ session
- จำนวน `ProcessGuid` ไม่ซ้ำ ต่อ session

---

## 2. Data Leakage — ใช้รายการที่วัดมาแล้ว

### กลุ่ม A: bookkeeping ของ pipeline (drop เสมอ)

```
recv_timestamp, record_id, session, computer, host_ip, platform,
ProcessGuid, LogonGuid, ParentProcessGuid, UtcTime, CreationUtcTime,
root_image, is_seed, label_method, enrich_method, label
```

### กลุ่ม B: เปเปอร์อ้างอิงตัดเอง เพราะรั่ว label

Achmad et al. 2025 หัวข้อ 3.1 เขียนไว้ตรงๆ ว่าตัด `Image`
*"removed due to its direct association with the target variable (label)"*
พร้อมกับ `ProcessId`, `node_id`, `parent_node_id`, `timestamp`, `host_name`

### กลุ่ม C: รั่ว **platform** (เฉพาะงาน cross-platform — เปเปอร์ไม่เจอเพราะมี OS เดียว)

วัดด้วย Random Forest ทำนายคอลัมน์ `platform` ได้ **100.00%** (ทายมั่ว 56.8%)

| feature | importance | ทำไมรั่ว |
|---|---|---|
| `IntegrityLevel` | 0.158 | concept ของ Windows ล้วน Linux ว่าง |
| `TerminalSessionId` | 0.148 | Linux ว่างเสมอ |
| `User` | 0.109 | `root`/`vagrant` vs `DESKTOP-xxx\vagrant` ค่าไม่ทับกันเลย |
| `Image` | 0.079 | `/usr/bin/x` vs `C:\...\x.exe` |
| `ParentUser`, `LogonId`, `CurrentDirectory`, `ParentCommandLine` | | เหตุผลเดียวกัน |

ตัด 20 คอลัมน์แล้วเหลือ 64.22% — **ลดได้แต่ไม่หมด**

### กลุ่ม D: harness leakage (ของเราเอง)

- `CurrentDirectory` มีคำว่า `lab_sandbox` = เฉลย label ตรงๆ
- ART รันทุกอย่างผ่าน PowerShell → registry churn ของ PowerShell เอง
  ผูกกับ label โดยไม่ใช่พฤติกรรมมัลแวร์ (เคยวัดได้ 88% ของ dataset)
- `benign` ต้องรันผ่าน interpreter เดียวกันกับ malicious ไม่งั้นโมเดลเรียน
  "มี powershell/bash = malware"

**เกณฑ์ผ่าน:** หลังตัด feature แล้ว โมเดลทำนาย `platform` ต้องได้ใกล้ baseline
(สัดส่วนคลาสที่มากกว่า) ถ้ายังสูงกว่ามาก แปลว่ายังรั่ว

---

## 3. Normalize เป็น Behavior Concept

| EventID | Windows | Linux | Concept |
|---|---|---|---|
| 1 | ✓ | ✓ | `PROCESS_CREATE` |
| 3 | ✓ | ✓ | `NETWORK_CONNECT` |
| 5 | ✓ | ✓ | `PROCESS_TERMINATE` |
| 9 | ✓ | ✓ | `RAW_ACCESS_READ` |
| 11 | ✓ | ✓ | `FILE_CREATE` |
| 23 | ✓ | ✓ | `FILE_DELETE` |
| 2 | ✓ | ✗ | `FILE_TIME_MODIFY` |
| 12/13 | ✓ | ✗ | `CONFIG_CHANGE` (registry) |

⚠️ **ปัญหาที่ตัดคอลัมน์ไม่ช่วย ต้องตัดทั้งแถวหรือ map ใหม่**

`RegistrySetValue` (13) มีแต่ฝั่ง Windows แต่เป็น event ที่แบก signal มากสุด
ของเปเปอร์ (**malicious 56.8%**) ตัดทิ้ง = ทิ้งจุดแข็งฝั่ง Windows

**ทางที่ควรลอง:** map ทั้งสองฝั่งเป็น `CONFIG_CHANGE` โดยฝั่ง Linux ใช้
`FILE_CREATE`/`FILE_DELETE` ที่ target อยู่ใน `/etc/`, `~/.bashrc`,
`/etc/systemd/`, cron directory — เป็น persistence/config เหมือน Run key ของ Windows
แล้วพิสูจน์ด้วยตัวเลขว่า map แล้ว platform ยังแยกไม่ออก

**อย่าใช้ EventID เป็น feature ตรงๆ** เพราะเป็น fingerprint ของ platform ทันที

---

## 4. Behavioral Features

### ระดับ process (aggregate ตาม `ProcessGuid`)

```
process_create_count, child_process_count, process_tree_depth
file_create_count, file_delete_count, file_create_to_delete_ratio
network_connect_count, unique_destination_ip, unique_destination_port
config_change_count
is_shell, is_interpreter, is_system_binary
file_is_temp, file_is_executable, file_in_user_dir
destination_is_external, destination_is_private, destination_is_loopback
lifetime_seconds (จาก ProcessCreate ถึง ProcessTerminate)
```

หมายเหตุ: pipeline เติม `ParentProcessGuid` และ `ancestor_depth` ให้แล้ว
(`enrich_events.py` เติมได้ราว 80-90%) ใช้สร้าง tree ได้เลย

### ระดับ time window (10s / 30s / 60s)

```
events_per_second, burstiness
distinct_concept_count, concept_entropy
```

### Sequence / transition

```
PROCESS_CREATE -> NETWORK_CONNECT      (download / C2)
PROCESS_CREATE -> FILE_CREATE          (drop payload)
FILE_CREATE    -> PROCESS_CREATE       (execute dropped file)
FILE_CREATE    -> FILE_DELETE          (staging แล้วลบ / ransomware)
FILE_CREATE    -> CONFIG_CHANGE        (persistence)
NETWORK_CONNECT -> NETWORK_CONNECT     (beaconing - ดู interval variance)
```

**เพิ่ม `beacon_interval_std`** — botnet ของเรายิงทุก 2 วินาทีสม่ำเสมอ
ส่วน traffic ปกติกระจายตัว เป็น feature ที่ข้าม platform ได้จริง

---

## 5. หน่วยของ ML sample และการแบ่ง train/test

⚠️ **ห้ามใช้ 1 Sysmon row = 1 sample แล้ว `train_test_split` แบบสุ่ม**

event หลายแถวมาจาก process เดียวกัน สุ่มแล้วไปอยู่ทั้ง train และ test
→ โมเดลจำ process ได้ ไม่ได้เรียนพฤติกรรม → F1 สูงปลอม
(วัดแล้วได้ acc 99.43% ด้วยวิธีนี้ ซึ่งเชื่อไม่ได้)

**ต้องใช้:**
- sample = process หรือ process-tree หรือ time-window
- แบ่งด้วย `GroupKFold` โดย group = `session` (ดีสุด) หรือ `ProcessGuid`
- ให้ session ที่เป็น test ไม่เคยปรากฏใน train เลย

---

## 6. คัด Feature

- Mutual Information
- Random Forest Importance
- Permutation Importance
- SHAP
- correlation / redundancy

**ทุกวิธีต้องรันคู่กับการทดสอบ platform-leakage:**
เทรนทำนาย `platform` ด้วย feature ชุดเดียวกัน ถ้าแยกได้ดีกว่า baseline มาก
แปลว่าชุดนั้นยังใช้ไม่ได้ ไม่ว่าจะทำนาย malware ได้ดีแค่ไหน

เทียบ 3 ทาง แล้วรายงานตัวเลขทั้งหมด:
- **A** union ทุก feature (ฐานอ้างอิง — ตัวเลขสวยแต่หลอก)
- **B** union ตัด feature ที่รั่ว (ตัวเลขที่รายงานได้จริง)
- **C** แยกเทรน Linux / Windows แล้วเทียบผล

---

## 7. ผลลัพธ์ที่ต้องการ

ตาราง:

```
Feature | Behavior Concept | Windows | Linux | Transform | Leakage Risk | Keep/Drop | Reason
```

แล้วเสนอ 3 ชุด: **Minimal / Recommended / Full**

พร้อมอธิบายต่อ feature ว่า:
1. บอกพฤติกรรมมัลแวร์อย่างไร
2. **พฤติกรรมนั้นเกิดใน benign ได้ไหม และเกิดบ่อยแค่ไหน**
3. ค่าของมันต่างกันระหว่าง Windows/Linux หรือไม่ (ถ้าต่าง = เสี่ยงรั่ว platform)
