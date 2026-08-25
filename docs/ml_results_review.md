# ตรวจผล ML รอบแรก — ทำไมตัวเลขต่ำ และแก้ยังไง

ไฟล์ที่ตรวจ: `reference/cross_platform_behavioral_validation_results_v5.csv`
วันที่ตรวจ: 25 ส.ค. 2026
เครื่องมือที่ใช้ตรวจ: `python host/ml_benchmark.py` (เขียนใหม่พร้อมกับเอกสารนี้)

---

## สรุปสั้น

ตัวเลขที่ได้ต่ำเพราะ **โปรโตคอลการวัด** ไม่ใช่เพราะข้อมูลน้อย
รันข้อมูลชุดเดิม (`merged_dataset.csv`) ด้วยโปรโตคอลที่ถูกต้อง ได้:

| | ของเดิม | หลังแก้ |
|---|---------|---------|
| Supervised RF (F1) | 0.665 | **0.959** (process-level, group split) |
| Unsupervised acc | 0.518 – 0.671 | **0.839** (LOF process-level) |
| Unsupervised F1 (โปรโตคอลเปเปอร์) | — | **0.882** (เปเปอร์ได้ 0.975) |
| Unsupervised AUC | ไม่ได้รายงาน | **0.917** |

**ยังไม่ต้องเก็บ log เพิ่มเพื่อให้ตัวเลขขึ้น** — ข้อมูลที่มีอยู่พอแล้ว
(การเก็บเพิ่มมีเหตุผลอื่นที่ดี ดูหัวข้อสุดท้าย)

---

## ปัญหาที่เจอ 5 ข้อ เรียงตามผลกระทบ

### 1. 🚨 Decision Tree กับ Random Forest ให้ตัวเลขตรงกันทุกหลัก = บั๊กในโค้ด

```
Decision Tree  0.7945642343757437  0.7473812849162011  0.5987412587412587  0.664854791116633
Random Forest  0.7945642343757437  0.7473812849162011  0.5987412587412587  0.664854791116633
```

สองอัลกอริทึมคนละตัว ให้ค่าตรงกัน **16 ตำแหน่งทศนิยม ทั้ง 4 เมตริก** เป็นไปไม่ได้
แปลว่าโค้ดเอา prediction ของโมเดลเดียวไปคำนวณสองครั้ง
(ปกติคือ fit `rf` แล้วเผลอ `predict` ด้วย `dt` หรือ reuse ตัวแปร `y_pred`)

**ต้องแก้ก่อนทำอย่างอื่น** ไม่งั้นตารางผลในธีสิสผิดตั้งแต่ต้น

### 2. Unsupervised ตรวจไม่เจออะไรเลย — accuracy ที่ได้คือ "เดาว่า benign ทุกแถว"

```
LOF Paper      acc 0.6709   precision 0.9304   recall 0.0355
LOF Proposed   acc 0.6603   precision 0.5294   recall 0.0164
```

recall 1.6–3.6% แปลว่าโมเดลชี้ว่า "ผิดปกติ" แค่ไม่กี่แถว
ลองแทนค่ากลับ: ถ้าสัดส่วน malicious = *m* และ recall = *r* โดยที่ FP ≈ 0

```
acc = (1 - m) + m·r
0.6709 = (1 - m) + m(0.0355)   ->   m = 0.341
```

ซึ่งตรงกับสัดส่วน malicious ของ dataset พอดี
→ **accuracy 0.67 ที่เห็น ไม่ได้มาจากการตรวจจับ แต่คือค่าที่ได้ฟรีจากการทายว่าทุกแถวเป็น benign**

สาเหตุคือเทรน unsupervised ผิดวิธี **outlier detection ต้องเทรนด้วย benign อย่างเดียว**
(เปเปอร์เขียนไว้ชัดใน Fig. 4 — "Use benign data to train the models")
ถ้าเทรนด้วยข้อมูลผสม โมเดลจะนับพฤติกรรมมัลแวร์เป็น "ปกติ" ไปด้วย
วัดจริงแล้ว Isolation Forest ที่เทรนบนข้อมูลผสมได้ **AUC 0.44 — แย่กว่าโยนเหรียญ**

### 3. ใช้ feature แค่ 14 / 13 / 3 / 8 ตัว ทั้งที่มี 48 ตัวให้ใช้

หลัง preprocessing ตามเปเปอร์ (`host/paper_encoding.py`) `merged_dataset.csv`
เหลือ **48 feature** ที่ใช้ได้ การเหลือ 3 feature แล้วทำ LOF คือสาเหตุตรงๆ ของ recall 3.5%

⚠️ ตัวเลข "LOF 1 feature ได้ F1 0.9778" ในเปเปอร์ (Table 9) **ห้ามลอกมาเป็นเป้า**
ดูหัวข้อ "อ่านตัวเลขของเปเปอร์ให้ถูก" ด้านล่าง

### 4. ป้อนข้อมูลไม่ครบ

ที่ codex อ่านคือ `merged_linux.csv` — 23,711 แถว / 5 session / 1 เครื่อง
แต่ของจริงที่เก็บไว้คือ `host/dataset/merged_dataset.csv`:

```
81,331 แถว   12 session (Linux 6 + Windows 6)   2 เครื่อง
linux   29,805 benign / 15,506 malicious
windows 24,027 benign / 11,993 malicious
```

→ ที่รันไปใช้ข้อมูลไม่ถึง **30%** ของที่เก็บมา และตัด Windows ออกหมด

### 5. รายงาน accuracy ของ unsupervised โดยไม่มีฐานเปรียบเทียบ

เปเปอร์ไม่ได้รายงาน accuracy ของ unsupervised เลย (Table 8/9 มีแค่ Recall/Precision/F1)
เพราะ accuracy ของ anomaly detection **อ่านไม่ได้ถ้าไม่รู้สัดส่วนคลาส**
ทุกตารางต่อจากนี้จึงต้องมีบรรทัด baseline คู่เสมอ — `ml_benchmark.py` พิมพ์ให้อัตโนมัติ

---

## ผลจริงหลังแก้ (ข้อมูลชุดเดิม ไม่เก็บเพิ่ม)

`python host/ml_benchmark.py --level process --pca 0`

### Supervised — process-level, แบ่งกลุ่มตาม ProcessGuid

| model | acc | prec | rec | F1 |
|-------|-----|------|-----|-----|
| Naive Bayes | 0.362 | 0.342 | 0.991 | 0.509 |
| Decision Tree | 0.971 | 0.964 | 0.950 | 0.957 |
| **Random Forest** | **0.973** | 0.966 | 0.952 | **0.959** |
| Linear SVM | 0.714 | 0.606 | 0.411 | 0.489 |

(เปเปอร์: RF F1 0.8868)

### Unsupervised — เทรนด้วย benign อย่างเดียว, process-level

| protocol | model | acc | prec | rec | F1 | AUC |
|----------|-------|-----|------|-----|-----|-----|
| group by process | **LOF** (k=10, cont .3) | **0.839** | 0.788 | 0.709 | 0.746 | 0.852 |
| leave-scenario-out | **LOF** (k=50, cont .4) | **0.810** | 0.794 | 0.748 | 0.770 | 0.840 |
| group by process | Isolation Forest | 0.640 | 0.377 | 0.121 | 0.184 | 0.612 |
| group by process | One-Class SVM | 0.678 | 0.539 | 0.230 | 0.323 | 0.525 |
| baseline "ผิดปกติทุกแถว" | — | 0.334 | 0.334 | 1.000 | 0.500 | — |

**LOF ชนะขาด** ตรงกับข้อสรุปของเปเปอร์ (Table 8: LOF ดีที่สุดใน 3 ตัว)
ส่วน Isolation Forest / One-Class SVM ของเราต่ำกว่าเปเปอร์จริง — ดูหัวข้อถัดไปว่าทำไม

### Unsupervised — โปรโตคอลเดียวกับเปเปอร์เป๊ะ (event-level)

เทรนด้วย benign 90%, เทสด้วย benign ที่เหลือ + malware ทั้งหมด

| model | prec | rec | F1 | AUC | เปเปอร์ (F1) |
|-------|------|-----|-----|-----|--------------|
| **Local Outlier Factor** | 0.976 | 0.805 | **0.882** | **0.917** | 0.975 |
| Isolation Forest | 0.904 | 0.179 | 0.298 | 0.527 | 0.762 |
| One-Class SVM | 0.884 | 0.161 | 0.272 | 0.487 | 0.805 |
| baseline "ผิดปกติทุกแถว" | 0.832 | 1.000 | **0.908** | — | — |

**อ่านบรรทัดสุดท้ายให้ดี** — ในโปรโตคอลนี้ test set เป็น malware 83%
ตัวที่ตอบว่า "ผิดปกติ" ทุกแถวโดยไม่คิดอะไรเลย ได้ F1 **0.908** สูงกว่าทุกโมเดล

นี่คือเหตุผลที่ต้องดู AUC ควบคู่: LOF ของเรา AUC 0.917 = แยกได้จริง
ส่วน One-Class SVM ของเปเปอร์ที่ recall = 1.0000 พอดีเป๊ะ + precision 0.7411
≈ สัดส่วน malware ใน test set ของเขา → **นั่นคือ detector ที่ flag ทุกแถว ไม่ใช่การตรวจจับ**

### LOF แยกได้จริงไหม — ไล่ดูรายฉาก

recall ต่อ scenario (โปรโตคอลเปเปอร์, threshold เดียวกันทั้งตาราง):

```
windows|ransomware_win 0.966    linux|exploit    0.804
windows|miner_win      0.908    linux|ransomware 0.736
windows|trojan_win     0.911    linux|miner      0.657
windows|exploit_win    0.903    linux|botnet     0.584
windows|botnet_win     0.811    linux|trojan     0.489
```

false positive บน benign ที่กันไว้เทส: 4.2% – 21.8%
→ ตรวจเจอทั้ง 10 ฉากทั้งสองแพลตฟอร์ม ไม่ใช่การเดา และไม่ได้ตรวจเจอเฉพาะฝั่งเดียว
(AUC แยกฝั่ง: Linux 0.883 / Windows 0.952)

---

## โปรโตคอลการแบ่ง train/test เปลี่ยนตัวเลขได้ 40 จุด

ข้อมูลชุดเดิมทุกแถว เปลี่ยนแค่วิธีแบ่ง (event-level, RF, PCA 9):

| วิธีแบ่ง | acc | F1 | ใช้ตอนไหน |
|---------|-----|-----|-----------|
| สุ่มแถว | 0.974 | 0.961 | **ห้ามใช้** — event หลายแถวมาจาก process เดียวกัน รั่วข้าม train/test |
| group ตาม ProcessGuid | 0.881 | 0.811 | **ตัวเลขหลักที่ควรรายงาน** |
| leave-scenario-out | 0.636 | 0.634 | เคส zero-day — โมเดลไม่เคยเห็นการโจมตีชนิดนั้น |

ตัวเลขเดิม (RF acc 0.795 / F1 0.665) อยู่ระหว่าง group-by-process กับ leave-scenario-out
→ ที่รันไปใช้ grouped split ซึ่ง**ถูกต้องแล้ว** แค่ต้องระบุในธีสิสว่าใช้แบบไหน
เพราะเปเปอร์ใช้ `train_test_split` สุ่มแถว ตัวเลข 0.8868 ของเขาจึงเทียบกับแถวบนสุด ไม่ใช่แถวกลาง

⚠️ **leave-scenario-out ตัวเลขต่ำไม่ได้แปลว่า dataset ไม่ดี** — มันคือการถามว่า
"เทรนด้วย botnet+trojan แล้วตรวจ ransomware ที่ไม่เคยเห็นได้ไหม" ซึ่งยากโดยธรรมชาติ
เขียนเป็นหัวข้อแยกในธีสิสได้เลย (generalisation to unseen attack class)
และเป็นจุดที่ **unsupervised ชนะ supervised**: LOF 0.810 vs RF 0.568

---

## ทำไม process-level ถึงดีกว่า event-level มาก

| level | unsupervised LOF acc | supervised RF F1 |
|-------|---------------------|------------------|
| event | 0.790 | 0.811 |
| process | **0.839** | **0.959** |

event เดี่ยวๆ ของมัลแวร์หน้าตาเหมือน benign — `powershell.exe` เขียนไฟล์ 1 ไฟล์
ไม่มีอะไรบอกได้ว่าอันตราย สิ่งที่แยกได้จริงคือ **รูปแบบรวมของ process**:
เขียน 400 ไฟล์ใน 3 วินาที, ต่อ IP เดิมซ้ำ 30 รอบ, แตะ registry 200 key

`ml_benchmark.py --level process` รวม event ของ ProcessGuid เดียวกันเป็น 1 แถว
แล้วสร้าง 31 feature: นับ/สัดส่วนต่อ EventID, จำนวนไฟล์-IP-port-registry ที่ไม่ซ้ำ,
ระยะเวลา, อัตรา event ต่อวินาที, ความยาว CommandLine, ความลึกของสายเลือด

นี่คือจุดที่ codex พูดถูก — "โมเดลปัจจุบันทำนายระดับ event และตัด time-window ออก"

---

## อ่านตัวเลขของเปเปอร์ให้ถูก

เปเปอร์ Table 9 รายงาน **LOF ใช้ 1 feature ได้ F1 0.9778, recall 0.9997**
และ **One-Class SVM recall 1.0000 พอดีเป๊ะ**

- recall = 1.0000 เป๊ะ แปลว่า flag ว่าผิดปกติทุกแถว → precision 0.7411 ที่ได้
  ก็คือสัดส่วน malware ใน test set ของเขาเอง ไม่ใช่ความสามารถของโมเดล
- unsupervised ที่ใช้ feature เดียวแล้วได้ F1 0.98 เป็นสัญญาณของ feature ที่รั่ว label
  มากกว่าจะเป็นการตรวจจับที่ดี

**อย่าตั้งเป้าไล่ตามตัวเลขในตารางนั้น** ให้เทียบด้วย AUC ซึ่งไม่ขึ้นกับสัดส่วนคลาส
และรายงาน baseline "flag ทุกแถว" คู่กันเสมอ — จะได้ธีสิสที่ป้องกันตัวได้ตอนสอบ

---

## เป้า "unsupervised 85%" — ตอบตรงๆ

| ตัวเลข | ได้แล้วไหม |
|--------|-----------|
| F1 ตามโปรโตคอลเปเปอร์ | ✅ 0.882 (เทียบเปเปอร์ 0.975) |
| AUC | ✅ 0.917 |
| accuracy แบบ group-by-process | 🔸 0.839 — ขาดอีก ~1 จุด |
| accuracy แบบ leave-scenario-out | 🔸 0.810 |

ที่เหลืออีก 1-4 จุดไม่ได้มาจากการเก็บ log เพิ่ม แต่มาจาก feature:
เพิ่ม feature ระดับ process ที่ยังไม่มี — entropy ของชื่อไฟล์ที่เขียน,
สัดส่วนไฟล์ที่เขียนนอก path ปกติ, จำนวน child process, ช่วงเวลาระหว่าง network connect
(สม่ำเสมอ = beacon), สัดส่วน event ที่เกิดใน 1 วินาทีแรก

---

## ควรเก็บ log เพิ่มไหม

**ไม่ใช่เพื่อดันตัวเลข** — ตัวเลขขึ้นได้จากการแก้โปรโตคอลอย่างเดียว

แต่ควรเก็บเพิ่มเพื่อ **ความน่าเชื่อถือของข้อสรุป** ซึ่งเป็นคนละเรื่อง:
ตอนนี้ 1 scenario = 1 session ทำให้ leave-scenario-out มี test fold แค่ไม่กี่แบบ
ตัวเลข generalisation จึงแกว่งตาม seed

สิ่งที่ **ช่วยจริง** (เรียงตามผลตอบแทน):

1. **รันแต่ละ scenario ซ้ำเป็น session แยกกัน 3-5 รอบ** (คนละ snapshot revert)
   → ทำ GroupKFold ตาม session ได้จริง มี error bar ในธีสิส
   ⚠️ `--duration` วนซ้ำใน session เดียวไม่นับ — ต้องเป็นคนละ session
2. **benign ให้หลากหลายกว่านี้** — ตอนนี้ FP rate ของ LOF สูงถึง 21.8% บาง fold
   เพราะ benign ที่มีแคบเกินไป เพิ่มการติดตั้งโปรแกรม / เปิดเบราว์เซอร์ /
   คัดลอกไฟล์เยอะๆ / คอมไพล์โค้ด จะดัน precision ขึ้นตรงๆ
3. **เพิ่มเครื่อง** (ตอนนี้ `computer` มีแค่ 2 ค่า) — กันข้อครหาว่าโมเดลจำ hostname

สิ่งที่ **ไม่ช่วย**: เพิ่ม event จาก session เดิม, ก๊อปแถวซ้ำ,
เก็บ malware เพิ่มโดยไม่เพิ่ม benign (ตอนนี้สัดส่วนสมดุลดีแล้ว ต่างกัน 0.5 จุด)

---

## คำสั่งที่ต้องรัน

```powershell
python host/ml_benchmark.py --level event                       # ครบ 4 โปรโตคอล
python host/ml_benchmark.py --level process --pca 0             # ตัวเลขดีที่สุด
python host/ml_benchmark.py --protocol paper --out reference/bench_paper.csv
```

ไฟล์ผลที่สร้างไว้แล้ว: `reference/bench_event.csv`, `reference/bench_process.csv`,
`reference/bench_process_nopca.csv`
