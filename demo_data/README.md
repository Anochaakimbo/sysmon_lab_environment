# ไฟล์สาธิตหน้าเว็บ model_web

ข้อมูลภายนอกที่แปลงแล้ว ใช้คู่กับ `models/paper_rf_<os>.pkl` (อยู่ใน git แล้ว หรือสร้างใหม่ด้วย `python host/export_model.py`)

**License ของข้อมูลต้นทาง** (ไฟล์ในโฟลเดอร์นี้เป็นงานดัดแปลง: เลือกแถว เปลี่ยนชื่อคอลัมน์ ปิดชื่อไฟล์ และเพิ่มคอลัมน์ label)
- BarongTrace: Copyright the authors of bazz-066/linux-malware-dataset, Apache License 2.0
- OTRF Security-Datasets (APT29): Copyright Open Threat Research Forge, MIT License
เปิดเว็บ: `python model_web/model_web.py` → http://127.0.0.1:8765 → โหมด "Sysmon Event ดิบ"

| ไฟล์ | ใช้กับโมเดล | ใช้ทำอะไร | ที่มา |
|---|---|---|---|
| `linux_barong_benign_calib.csv` | `paper_rf_linux.pkl` | ปุ่ม "ตั้งเกณฑ์จาก CSV ข้อมูลปกติ" | BarongTrace ไฟล์ 1, 10, 12 เฉพาะโปรเซสปกติ (label 0) |
| `linux_barong_test_file9.csv` | `paper_rf_linux.pkl` | CSV ทดสอบ | BarongTrace ไฟล์ 9 |
| `windows_apt29_benign_calib_day2.csv` | `paper_rf_windows.pkl` | ตั้งเกณฑ์ | OTRF APT29 day2 เครื่อง NASHUA/NEWYORK/SCRANTON เฉพาะ label 0 |
| `windows_apt29_test_day1.csv` | `paper_rf_windows.pkl` | CSV ทดสอบ | OTRF APT29 day1 ทั้ง 4 เครื่อง |

**แหล่งข้อมูลต้นทาง**
- BarongTrace: https://github.com/bazz-066/linux-malware-dataset → `Dataset/Original_Linux/<n>result.zip`
  เตรียมด้วย `host/public_eval.py` (`barong()`): ใช้เฉพาะสายโปรเซสของ sample และปิดชื่อไฟล์เป็น `/tmp/SAMPLE`
- OTRF APT29: https://github.com/OTRF/Security-Datasets/tree/master/datasets/compound/apt29 (MIT)
  แปลงด้วย `host/public_sets/apt29_convert.py` + `apt29_label.py` (label ติดเองด้วย lineage)
  และตัด EventID ที่เว็บไม่รับ (7, 10, 17, 18, 22) รวมถึง 1 แถวที่ไม่มี UtcTime

**ผลที่ควรเห็นในเว็บ** กับโมเดลที่เทรนจาก 50 run (`data/FINAL_DATASET_50runs.csv.gz`) ตรวจด้วยโค้ดของเว็บแล้ว 16 ต.ค. 2026

| คู่ไฟล์ | เกณฑ์ | Accuracy | F1 | Recall | FPR | AUC | baseline (ทายปกติทั้งหมด / F1 ทายโจมตีทั้งหมด) |
|---|---|---|---|---|---|---|---|
| BarongTrace | predict() | 0.548 | 0.074 | 0.039 | 0.002 | 0.789 | 0.530 / 0.639 |
| BarongTrace | 0.114 (จากไฟล์ปกติ) | **0.718** | 0.589 | 0.430 | 0.027 | 0.789 | 0.530 / 0.639 |
| APT29 day1 | predict() | 0.797 | 0.332 | 0.500 | 0.169 | 0.818 | 0.900 / 0.183 |
| APT29 day1 | 0.566 (จาก day2) | 0.791 | 0.257 | 0.359 | 0.161 | 0.818 | 0.900 / 0.183 |

ทดสอบผ่านเบราว์เซอร์จริงแล้ว 16 ต.ค. 2026 (BarongTrace ผ่านหน้าเว็บ, APT29 ผ่าน API เดียวกัน) ตัวเลขข้างบนคือที่หน้าเว็บแสดง
แถบเลื่อนปัดเกณฑ์เป็น 3 ตำแหน่ง (0.11428 → 0.114) ผลจึงต่างจากการเรียกโค้ดตรงเล็กน้อย (0.721)

**ลำดับสาธิต:** อัปโหลด `models/paper_rf_linux.pkl` + ติ๊กยืนยัน → โหลดโมเดล → เลือก "Sysmon Event ดิบ" + ติ๊กยืนยัน schema
→ กด "ตั้งเกณฑ์จาก CSV ข้อมูลปกติ" เลือก `linux_barong_benign_calib.csv` → เลือก `linux_barong_test_file9.csv` → ทดสอบโมเดล
(ถ้าอยากโชว์ก่อนและหลัง: ทดสอบครั้งแรกโดยไม่ติ๊ก "ปรับเกณฑ์เอง" แล้วค่อยตั้งเกณฑ์และทดสอบซ้ำ)

ใช้คู่ BarongTrace เป็นตัวสาธิตหลัก ส่วนคู่ APT29 ใช้แสดงข้อจำกัด:
- การตั้งเกณฑ์จากวันอื่นได้ FPR จริง 16% ไม่ใช่ 5% เพราะข้อมูลปกติต่างวันและต่างเครื่องไม่เหมือนกัน
- ตัวเลขต่ำกว่าใน `docs/public_dataset_eval.md` (AUC 0.87) เพราะใช้แค่ day1 และตัด EventID 7/10 ที่เว็บไม่รับ

โมเดล 12 run (ตามเปเปอร์) ได้ BarongTrace 0.569 → 0.725 และ APT29 AUC 0.776 สร้างได้ด้วย
`python host/export_model.py --dataset data/FINAL_DATASET_fixed.csv.gz`
