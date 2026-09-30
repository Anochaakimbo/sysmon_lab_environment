# บันทึกการแก้ paper NCCY — v6 (30 ก.ย. 2026)

ไฟล์ที่ได้: `docs/paper_draft_NCCY_v6_revised.docx` (แก้จาก `paper_draft_NCCY.docx` ที่แนบมา โดยคง template เดิม)
โค้ดทดลองใหม่: `host/revised_experiments.py` → ผลอยู่ที่ `reference/revised_results/`

## 1. สิ่งที่แก้ตามแผน 8 ข้อ

| ข้อ | สิ่งที่ทำ | ตำแหน่งใน paper |
|---|---|---|
| 1 Scope | เปลี่ยนเป็น *simulated attack activity classification* ทั้ง Title, Abstract TH/EN, Keywords, Intro (ย่อหน้า 5–6), Discussion 5.1, Conclusion — ระบุชัดว่าไม่ได้รันมัลแวร์จริงและไม่ได้อ้างการตรวจจับมัลแวร์จริง | หน้า 1–3, 5.1, 6 |
| 2 C001 | anomaly detector ฝึกจาก benign อย่างเดียว และตั้ง threshold ที่ percentile 95 ของ benign calibration split (target FPR 5%) **ไม่ใช้ label=1 เลย** (ฉบับเดิมเลือก quantile จาก F1 ซึ่งใช้ label ทั้งสองคลาส และใช้ข้อมูลซ้ำกับชุดฝึก) | 3.5 ย่อหน้าสุดท้าย |
| 2 C002 | แบ่งตาม lineage (P1), run (P2), scenario ทั้งสอง OS (P3) + independent runs (P4) | 3.6, ภาพ 2 |
| 2 C003 | ระบุ benign train/test ทุกโปรโตคอล: P1 แบ่ง benign ตาม lineage (ทดสอบเฉลี่ย 1,404 จากรอบ benign + 1,788 จากรอบโจมตีต่อ fold), P2/P3 test benign = โปรเซสเบื้องหลังของรอบที่กันออก, รอบ benign อยู่ในชุดฝึกเสมอ | 3.6 |
| 3 เพิ่ม runs | พบรอบอิสระที่ใช้ได้ 2 รอบ (Linux ransomware/trojan 25 ส.ค.) → ใช้เป็น P4; ที่เหลือต้องเก็บเพิ่ม ดูหัวข้อ 3 | 3.1, 4.4 |
| 4 mean±SD | P1 25 fold, P2 10 fold, P3 5 fold รายงาน mean±SD + เส้นฐาน all-positive + FPR | ตาราง 6, 7, ภาพ 3 |
| 5 Config table | ตาราง 1 (environment/Sysmon/ART/session) + ตาราง 2 เต็มหน้า (ATT&CK ต่อสถานการณ์และต่อ OS, จำนวนโปรเซส, lineage groups) | 3.1, 3.2 |
| 6 Composite key | (platform, run_id, ProcessGuid) + ตัด GUID ศูนย์/ว่าง, รายงานผลกระทบ | 3.4, 4.2, ตาราง 5 |
| 7 Figure 1 | วาดใหม่เป็น research overview 4 ส่วน, dashboard เป็นกรอบเส้นประ "optional/future (not evaluated)" ; ภาพ 2 วาดใหม่เป็น pipeline + protocols | ภาพ 1, 2 |
| 8 ตัวเลข | อัปเดต Abstract, Results, Discussion, Conclusion ทุกจุด — ตรวจอัตโนมัติแล้วว่าตัวเลข ± ทุกค่าในเอกสารตรงกับ `numbers.json` | ทั้งฉบับ |

## 2. ตัวเลขหลัก เก่า → ใหม่

| รายการ | ฉบับเดิม | v6 |
|---|---|---|
| RF หลัก | F1 0.924 (split เดียว) | F1 0.920±0.008, AUC 0.986±0.002 (P1) |
| RF กันกลุ่ม OS×scenario | F1 0.764 | P2 0.768±0.150 (ชนะ baseline 8/10) |
| RF กันสถานการณ์ทั้งสอง OS | – | P3 0.767±0.093 (ชนะ baseline 3/5) |
| RF รอบใหม่ | – | P4 0.915, FPR 0.039, AUC 0.978 |
| LOF | F1 0.714 (threshold จาก F1) / 0.728 (contamination 0.3) | F1 0.462±0.064, AUC 0.839±0.016, FPR 0.048 |
| Composite key | – | ตัวอย่างเท่าเดิม 23,971 (ตัด pseudo-process 1, แยก GUID ซ้ำ 1) ; RF F1 0.918 → 0.919 |

ข้อสังเกตที่ควรรู้ก่อนตอบ reviewer
* LOF ตกจาก 0.714 เป็น 0.462 เพราะวิธีตั้ง threshold ถูกต้องขึ้น ไม่ใช่เพราะโมเดลแย่ลง (AUC ใกล้เดิม 0.849 → 0.839)
* P1 ≈ random process split (0.920 vs 0.919) → ภายในรอบเดียวกัน lineage leakage แทบไม่มีผล ; ตัวเลขตกเมื่อเปลี่ยน run/scenario
* ใน P2/P3 ชุดทดสอบหลาย fold มี label=1 เกินครึ่ง → baseline F1 สูง (0.679/0.648) ต้องอ่านคู่กับ AUC และ FPR เสมอ

## 3. แผนเก็บข้อมูลเพิ่ม (ข้อ 3) — ต้องรันบนเครื่องจริง

เป้าหมาย: ≥ 3 runs อิสระต่อ OS × scenario เพื่อให้ P2 กลายเป็น leave-one-run-out ที่สถานการณ์เดียวกันยังอยู่ในชุดฝึก

| OS | ต้องเก็บเพิ่ม | เวลาโดยประมาณ |
|---|---|---|
| Linux | benign ×2, botnet ×2, exploit ×2, miner ×2, ransomware ×1, trojan ×1 | 10 runs × ~12 นาที ≈ 2 ชม. |
| Windows | benign, ransomware, trojan, botnet, miner, exploit อย่างละ ×2 | 12 runs × ~15 นาที ≈ 3 ชม. |

เงื่อนไข (ต้องเหมือนรอบ 24 ส.ค. ทุกข้อ)
1. กดรันทีละรอบใน dashboard (revert snapshot `clean` ทุกรอบ) — ห้ามเพิ่ม `--duration` แทน
2. Linux `--duration 10`, Windows ค่าเดิม; `c2_server.py` + `mining_pool.py` เปิดค้าง
3. Windows: Defender + Tamper Protection ปิด (ตรวจด้วย `_diag_defender.ps1`), ใช้สคริปต์ **เวอร์ชัน Git HEAD** (working copy ถูกแก้ 16 ก.ย. — ถ้าใช้ตัวใหม่ต้องรายงานเป็นเงื่อนไขใหม่)
4. แยกวันเก็บอย่างน้อย 1 รอบต่อสถานการณ์ และถ้าทำได้ให้เพิ่มเครื่อง VM ที่สอง (ช่วยข้อจำกัด "เครื่องเดียว")
5. benign: เพิ่มความหลากหลายของกิจกรรม (ลด FP ของ anomaly detector)

หลังเก็บเสร็จ: `python host/merge_dataset.py` → `python host/revised_experiments.py` (P2 จะใช้ run ที่เพิ่มอัตโนมัติ) → อัปเดตตาราง 1, 2, 6, 7 และ Abstract

## 4. Supplementary material (ตอบ Verification Limitation)

ควรแนบ (หรือใส่ลิงก์ repository แทน `[ใส่ลิงก์ repository]` ท้ายหัวข้อ 6):
* `supplementary/dataset_schema.md` (เขียนให้แล้ว) + `merged_dataset.csv` + 2 independent runs
* `host/revised_experiments.py`, `host/parse_sysmon.py`, `host/enrich_events.py`, `host/label_events.py`, `host/merge_dataset.py`
* `reference/revised_results/` (per-fold CSV ทุกโมเดล) และ `numbers.json`
* Sysmon configs และสคริปต์สถานการณ์ — **ตัดสินใจเองว่าจะเผยแพร่แค่ไหน**: สคริปต์ Linux บางตัวมีขั้นตอนที่เขียนเอง (exploit/backdoor/miner) อาจเลือกเผยแพร่เฉพาะรายการ technique + test number แทนสคริปต์เต็ม

## 5. สิ่งที่ตัดออก / ต้องตรวจเอง

* **ตัดหัวข้อ 4.4 เดิม** (event-level split, PCA 9, split เดียว) — ขัดกับข้อ 4 และซ้ำกับ P1–P3 ; ถ้าอยากเก็บไว้ต้องรันใหม่แบบ mean±SD
* เอกสารยาวขึ้นจาก ~11 เป็น ~13 หน้า (render ด้วยฟอนต์ทดแทน) — ถ้าเกิน page limit ย้ายตาราง 1 หรือตาราง 8 ไปวัสดุเสริมได้
* เปิดใน Word ตรวจ layout จริง (ตารางเต็มหน้า ตาราง 2 อยู่ใน section คอลัมน์เดียวเดียวกับภาพ 1–2)
* ใส่ลิงก์ repository ท้ายหัวข้อ 6
* ระยะเวลา Windows 11–16 นาที/รอบ คำนวณจาก `scenario_start_utc`→`end_utc` ใน meta.json ; Sysmon รายงานเป็น config schema เพราะไม่มีบันทึกเลขเวอร์ชันไบนารี — ถ้าจำเวอร์ชันได้ให้เติมในตาราง 1

## 6. v7 — ย่อให้ไม่เกิน 8 หน้า (`docs/paper_draft_NCCY_v7_8pages.docx`)

Render ด้วยฟอนต์ทดแทนได้ ~6.3 หน้า (เทียบ v2: Word 9 หน้า vs render 8 หน้า → คาดว่าใน Word ~7–7.5 หน้า) — ต้องเปิดใน Word ยืนยัน

เก็บไว้ครบ: Scope ใหม่, ภาพ 1 ใหม่, ตาราง 1 การตั้งค่า (ATT&CK/Sysmon/ART/session), คีย์ผสม + ผลกระทบ, โปรโตคอล P1–P4 + นิยาม benign train/test, threshold จาก benign เท่านั้น, ตาราง 2 (P1 mean±SD ทั้ง 7 โมเดล), ตาราง 3 (P2–P4: RF, LOF, เส้นฐาน), ข้อจำกัด, อ้างอิงครบ 19 รายการ
ตัดออก/ย่อ (ยังอยู่ใน v6 และ supplementary):
* ภาพ 2 (pipeline/protocol) และภาพ 3 (bar chart) → รายละเอียดอยู่ในข้อความและตาราง 2
* ตารางคุณลักษณะ, ตารางจำนวนเหตุการณ์ตาม platform, ตารางผลคีย์ผสม, ตาราง EventID → เขียนเป็นประโยค / ตัด
* แถว Decision Tree ในตาราง P2–P4 (ตัวเลขอยู่ใน `p2_summary.csv`, `p3_summary.csv`)
* สมการ (1)–(3) → นิยาม FPR ในข้อความ
* หัวข้อย่อย 2.1–2.3 และ 5.1–5.2 รวมเป็นย่อหน้าเดียว; บทคัดย่อ EN ~140 คำ (template กำหนด 100–150)
