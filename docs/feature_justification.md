# ทำไมถึงใช้ feature เท่านี้ — และผลที่ออกมาไม่สวยเท่าที่รายงานไว้ก่อนหน้า

วัดด้วย `python host/ml_feature_study.py` (25 ส.ค. 2026)
ผลดิบ: `reference/feature_study_process.csv`, `reference/feature_study_event.csv`

---

## ตอบคำถามตรงๆ ก่อน

**"35 feature พิสูจน์ได้ไหมว่าทำไมต้อง 35"** — ตอบ: **ไม่ได้ ตอนที่รายงานไปยังไม่ได้พิสูจน์**
35 มาจากการออกแบบของคนเขียนสคริปต์ ไม่ได้มาจากการวัด:

```
11 EventID x 2 (นับ + สัดส่วน)                                    = 22
n_events n_files n_dst_ip n_dst_port n_regobj n_device
dur_s rate cmd_len img_len pcmd_len depth enriched               = 13
                                                          รวม     = 35
```

**"48 ทำ PCA หรือยัง"** — ตอบ: **ยัง** ตัวเลขที่รายงานไปทั้งหมดเป็น `--pca 0`
(ไม่ใช้ PCA) กับ `--pca 9` ที่ลอกค่ามาจากไฟล์ v5 เฉยๆ
`--pca-search` มีอยู่ในสคริปต์แต่ไม่เคยรัน

เอกสารนี้คือผลจากการวัดจริง และผลออกมาแย่กว่าที่เคยรายงาน

---

## 1. PCA ไม่ช่วยอะไรเลยกับ dataset นี้

ไล่ n=1..30 เลือกจาก validation ที่แยกจาก test:

| level | n ที่ดีสุดบน val | test RF F1 | ไม่ใช้ PCA | ต่าง |
|-------|------------------|-----------|-----------|------|
| process (35) | 18 | 0.9575 | 0.9579 | −0.0004 |
| event (48) | 29 | 0.9355 | 0.9512 | **−0.0157** |

n ที่ชนะคือ 18/35 กับ 29/48 — เกือบเท่าจำนวนเต็ม แปลว่า PCA
**ไม่ได้ตัดอะไรออกอย่างมีความหมาย** และที่ event-level ยังทำให้แย่ลงด้วย

เหตุผล: feature ส่วนใหญ่ผ่าน label encoding / ความยาวสตริงมาแล้ว
ค่าที่ได้เป็นเลขจำนวนเต็มไม่มีความสัมพันธ์เชิงเส้นระหว่างกัน
PCA ซึ่งมองหาแกนที่แปรปรวนสูงตามแนวเส้นตรง จึงไม่มีอะไรให้รวบ

→ **`--pca 0` เป็นค่าที่ถูกต้องแล้ว** และมีหลักฐานรองรับ (ไม่ใช่แค่ตั้งไว้เฉยๆ)
เปเปอร์ใช้ PCA เพราะเขามีคอลัมน์ 41 ตัวจากแพลตฟอร์มเดียว ไม่ได้แปลว่าเราต้องใช้ตาม

---

## 2. 🚨 ผลจริง: feature 35 กับ 48 ตัวไม่ได้ทำงานจริง — 4-5 ตัวแบกไว้หมด

greedy backward elimination (เลือกจาก validation):

| level | ใช้ทั้งหมด | ชุดเล็กสุดที่ยังอยู่ใน 1% ของค่าดีสุด | test F1 |
|-------|-----------|--------------------------------------|---------|
| process | 35 → F1 0.9579 | **5 ตัว** | 0.9585 |
| event | 48 → F1 0.9512 | **4 ตัว** | 0.9419 |

**ตัดได้ 30 จาก 35 และ 44 จาก 48 โดยเสีย F1 ไม่ถึง 1%**

feature ที่เหลือคืออะไร:

```
process : depth, cmd_len, img_len, pcmd_len, dur_s
event   : CommandLine, ancestor_depth, CurrentDirectory, ParentProcessId
```

ไม่มีตัวไหนเป็น "พฤติกรรม" เลย — ไม่มีจำนวนไฟล์ที่เขียน ไม่มีจำนวน IP ที่ต่อ
ไม่มีสัดส่วน registry event ทั้งที่นั่นคือเหตุผลที่สร้าง feature พวกนั้นขึ้นมา

---

## 3. 🚨 3 ใน 5 ตัวนั้นเป็นการรั่วของ pipeline ไม่ใช่สัญญาณมัลแวร์

### `CurrentDirectory` — รั่วตรงที่สุด

```
CurrentDirectory                    benign  malicious   %mal
/tmp/lab_sandbox/exploit                 0      1,367   100.0
C:\lab_sandbox\                          1        949    99.9
/home/vagrant                       14,798     14,012    48.6
```

`/tmp/lab_sandbox` และ `C:\lab_sandbox` คือ **seed directory ที่ lineage labeler
ใช้ตัดสิน label** การใส่คอลัมน์นี้เป็น feature = บอกคำตอบให้โมเดลตรงๆ

### `ancestor_depth` / `depth` — มาจาก lineage tree เดียวกับที่สร้าง label

```
depth   -1 -> benign 99.3%      depth >= 6 -> malicious 100%
```

ไม่ได้รั่ว 100% เหมือน `is_seed` (ซึ่งตัดไปแล้ว) แต่มาจากกระบวนการเดียวกัน

### `cmd_len` / `img_len` / `pcmd_len` — harness artifact

```
ความยาว CommandLine   median benign 22  |  malicious 76
Linux                 18 | 51        Windows  34 | 94
```

ใช้ threshold `len > 79` อย่างเดียวไม่ต้องมีโมเดล ได้ **accuracy 0.760**
(ทายคลาสใหญ่ได้ 0.662)

นี่ไม่ใช่ลักษณะของมัลแวร์ แต่เป็นลักษณะของ **Atomic Red Team** ที่เรียกทุกอย่าง
ผ่าน PowerShell พร้อม argument ยาวๆ ส่วน benign เป็นคำสั่งสั้น
→ โมเดลเรียน "คำสั่งยาว = ART = malicious" ซึ่งคือ **harness leakage**
(CLAUDE.md กับดักข้อ 6) ย้ายไปเครื่องจริงที่มัลแวร์ไม่ได้ถูกเรียกด้วย ART จะใช้ไม่ได้

⚠️ `img_len` ยังขัดกับเปเปอร์ด้วย — เปเปอร์ตัด `Image` ทิ้งเองโดยเขียนเหตุผลว่า
*"removed due to its direct association with the target variable"*
การเอา `Image` กลับมาในรูปความยาวสตริงคือการเลี่ยงข้อสรุปของเขา

---

## 4. ตัวเลขหลังตัดของที่รั่ว

เพิ่ม flag `--drop-derived` ใน `ml_train.py` และ `ml_feature_study.py`
ตัด `ancestor_depth`, `depth`, `enriched`, `parent_known`, `img_len`, `CurrentDirectory`

| level | feature | RF acc | RF F1 | LOF AUC |
|-------|---------|--------|-------|---------|
| process | 35 (ทั้งหมด) | 0.9651 | 0.9475 | 0.8657 |
| process | **32 (--drop-derived)** | **0.9491** | **0.9241** | **0.8492** |
| event | 48 (ทั้งหมด) | 0.8832 | 0.8181 | 0.7612 |
| event | **44 (--drop-derived)** | **0.8824** | **0.8122** | **0.6698** |

**ยังดีอยู่** — supervised เสียไปแค่ 1.6-2.3 จุด แปลว่าไม่ได้พึ่งของที่รั่วทั้งหมด
แต่ฝั่ง unsupervised ที่ event-level เสียหนัก (AUC 0.761 → 0.670)

### ตัดลึกกว่านั้น: เอาความยาวคำสั่งออกด้วย

| process-level | feature | RF acc | RF F1 | LOF AUC |
|---------------|---------|--------|-------|---------|
| ทั้งหมด | 35 | 0.9715 | 0.9579 | 0.8657 |
| ตัด artifact | 33 | 0.9689 | 0.9536 | 0.8220 |
| + ตัด `img_len` | 32 | 0.9630 | 0.9447 | 0.8492 |
| **+ ตัด `cmd_len`, `pcmd_len` = พฤติกรรมล้วน** | **30** | **0.7692** | **0.6100** | **0.6294** |

**F1 ตกจาก 0.9447 เหลือ 0.6100** — ตัวเลข 0.95 ที่รายงานไว้ ~35 จุดมาจาก
ความยาวคำสั่ง ไม่ได้มาจากพฤติกรรมที่เก็บผ่าน Sysmon

และเคส zero-day หนักกว่านั้น:

| leave-scenario-out | feature | RF F1 | LOF AUC |
|--------------------|---------|-------|---------|
| ทั้งหมด | 35 | 0.6272 | 0.8215 |
| ตัด artifact + img_len | 32 | 0.5808 | **0.5592** |

LOF AUC 0.82 ที่เคยรายงานว่า "unsupervised ชนะ supervised ในเคส zero-day"
**ตกเหลือ 0.56 = เกือบเท่าโยนเหรียญ** เมื่อตัดของที่รั่วออก
→ **ต้องถอนข้อสรุปนั้น** ยังสรุปแบบนั้นไม่ได้จนกว่าจะวัดใหม่บนข้อมูลที่สะอาด

---

## 5. สรุปสิ่งที่ต้องเขียนในธีสิส

1. **PCA ไม่ช่วย** — มีหลักฐาน (sweep n=1..30 ทั้งสอง level) ไม่ใช่การละเลย
2. **จำนวน feature ที่รายงานควรเป็น 32 (process) / 44 (event)** ไม่ใช่ 35/48
   เพราะ 3-4 ตัวที่ตัดออกเป็น artifact ของวิธี label ไม่ใช่สัญญาณ
3. **ต้องรายงานตัวเลข 2 ชุดคู่กัน** — with/without derived features
   ตัวเลขชุดที่ไม่ตัดคือ upper bound ที่ไม่ควรอ้างเดี่ยวๆ
4. **ยอมรับข้อจำกัดเรื่อง harness leakage ตรงๆ** ว่าความยาว CommandLine
   สะท้อน ART มากกว่าสะท้อนมัลแวร์ — เขียนไว้ใน limitations
   จะน่าเชื่อถือกว่าปล่อยให้กรรมการถามเอง
5. **ถอนข้อสรุป "unsupervised ทนต่อ zero-day มากกว่า supervised"** ไปก่อน
   หลักฐานเดิมมาจาก feature ที่รั่ว

## 6. ทางแก้ที่ควรทำต่อ (เรียงตามผลตอบแทน)

1. **ทำ benign ให้รันผ่าน PowerShell/bash ด้วยคำสั่งยาวพอกัน** — ตอนนี้ benign
   เป็นคำสั่งสั้นล้วน ทำให้ `cmd_len` แยกได้ฟรี ถ้า benign มีคำสั่งยาวบ้าง
   feature นี้จะหมดฤทธิ์เอง โดยไม่ต้องตัดทิ้ง (ตัดทิ้ง = เสียของ เพราะ
   CommandLine คือสิ่งที่เปเปอร์ไม่มีและเป็น contribution ของงานนี้)
2. **เพิ่ม feature พฤติกรรมที่ยังไม่มี** — entropy ของชื่อไฟล์ที่เขียน,
   สัดส่วนไฟล์นอก path ปกติ, จำนวน child process, ความสม่ำเสมอของช่วงเวลา
   ระหว่าง NetworkConnect (beacon), สัดส่วน event ใน 1 วินาทีแรก
   ชุด 30 ตัวที่เหลือได้ F1 0.61 — ต้องดันตรงนี้ ไม่ใช่ดันด้วยความยาวคำสั่ง
3. **เก็บซ้ำหลายรอบ** (`run_id` + `--split run`) เพื่อให้มี error bar

## คำสั่ง

```powershell
python host/ml_feature_study.py --level process --split process
python host/ml_feature_study.py --level event --split process --max-rows 25000
python host/ml_feature_study.py --level process --drop-derived     # หลังตัดของที่รั่ว
python host/ml_train.py --level process --split process --drop-derived
```
