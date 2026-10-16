# ทดสอบโมเดลกับ Sysmon public dataset (16 ต.ค. 2026)

โจทย์จากอาจารย์: นำโมเดลที่ฝึกในแล็บไปตรวจ Sysmon dataset สาธารณะ แล้ววัดผล (เป้า 70–80%)

**สรุปสั้น** (โมเดลที่เทรนจาก dataset สุดท้าย 50 run)

- ชุดข้อมูลที่ "เก็บ Sysmon ครบทุก event" ใช้โมเดลได้จริง:
  - APT29: AUC 0.84–0.87, balanced accuracy 0.72
  - BarongTrace: balanced accuracy 0.72 และ accuracy 0.747 เมื่อปรับเกณฑ์จากข้อมูลปกติ
- ชุดที่ "กรองเป็น alert" หรือ "ขาด CommandLine" ใช้ไม่ได้:
  - Windows-APT 2025: AUC 0.44–0.55
  - NLME: AUC 0.693 แต่แทบไม่ชนะการทายว่าปกติทั้งหมด
- **accuracy ดิบหลอกตาได้ทั้งสองทาง** เพราะสัดส่วนการโจมตีในแต่ละชุดต่างกันมาก (6.7% ถึง 84.7%) จึงรายงาน AUC และ balanced accuracy คู่กับ baseline เสมอ
- โมเดล 12 run ของเปเปอร์ได้ผลใกล้เคียงกัน (ตารางเทียบท้ายหัวข้อ 3)

---

## 1. วิธีทดสอบ

| ส่วน | รายละเอียด |
|---|---|
| โมเดล | Random Forest ตามเปเปอร์ (Table 3) ฝึกบน dataset สุดท้าย 50 run (`data/FINAL_DATASET_50runs.csv.gz`) แยกตาม OS |
| ระดับ | โปรเซส (รวม event ของ `ProcessGuid` เดียวกัน) |
| ฟีเจอร์ 3 ชุด | **paper32** = 32 ตัวของเปเปอร์ · **clean** = 53 ตัว เพิ่มฟีเจอร์พฤติกรรมและตัดโปรเซสของตัวรันทดสอบ (harness) ออกตอนฝึก · **neutral** = 29 ตัวที่ไม่ผูกกับ OS/ความยาวคำสั่ง |
| เกณฑ์ตัดสิน 3 แบบ | (1) 0.5 · (2) เปอร์เซ็นไทล์ 95 ของคะแนนโปรเซสปกติจาก **กลุ่มอื่น** (host/ไฟล์อื่น) · (3) เปอร์เซ็นไทล์ 95 ของโปรเซสปกติ **ครึ่งแรกของกลุ่มเดียวกัน** แล้ววัดเฉพาะครึ่งหลัง |
| การตัดสิน | `score > threshold` (ใช้ `>` เพราะโปรเซสปกติจำนวนมากได้คะแนนเท่ากันพอดี) |
| ตัวชี้วัด | AUC (ไม่ขึ้นกับสัดส่วนคลาส), balanced accuracy = (recall + (1 − FPR)) / 2, accuracy และ F1 คู่กับ baseline |
| baseline | ทายว่าปกติทั้งหมด (accuracy = สัดส่วนปกติ) และทายว่าโจมตีทั้งหมด (F1) |

โมเดลไม่เคยเห็น label ของชุดภายนอก ยกเว้นตอนตั้งเกณฑ์แบบ (2) และ (3) ซึ่งใช้ **เฉพาะโปรเซสที่เป็นพฤติกรรมปกติ**

---

## 2. ชุดข้อมูลที่ลอง

| ชุด | OS | ที่มา | event / โปรเซส | สัดส่วนโจมตี | ใช้ได้ไหม |
|---|---|---|---|---|---|
| **BarongTrace** | Linux | [bazz-066/linux-malware-dataset](https://github.com/bazz-066/linux-malware-dataset) Cuckoo + มัลแวร์จริง 12 ไฟล์ | 14,192 โปรเซส | 43.5% | ✅ |
| **OTRF APT29 Evals** | Windows | [OTRF Security-Datasets](https://github.com/OTRF/Security-Datasets/tree/master/datasets/compound/apt29) จำลอง APT29 ตามแผนของ MITRE 2 วัน 4 เครื่อง | 551k Sysmon event, 1,533 โปรเซส | 6.7% | ✅ |
| **NLME** | Windows | ชุดของเปเปอร์อ้างอิง ([cerberus-trace](https://github.com/bazz-066/cerberus-trace)) 5 เครื่อง | 24,368 โปรเซส | 19.6% | ⚠️ ไม่มี CommandLine |
| **Windows-APT 2025** | Windows | [Mendeley b8fmtzvpy8 v3](https://data.mendeley.com/datasets/b8fmtzvpy8/3) Caldera + Wazuh | 18,705 โปรเซส | 84.7% | ❌ กรองเป็น alert |
| **Splunk attack_data** | Linux | [splunk/attack_data](https://github.com/splunk/attack_data) 71 ไฟล์ Sysmon for Linux | 6,900 โปรเซส | ไม่มี label | ⚠️ วัดเชิงคุณภาพ |
| CSU-Ransomware-Data | Windows | [CSCRC-SCREED](https://github.com/CSCRC-SCREED/CSU-Ransomware-Data) | — | — | ❌ มีแต่ฟีเจอร์สำเร็จรูป ไม่มี event ดิบ |

### label มาจากไหน (สำคัญ: ส่วนใหญ่ไม่ได้ให้มา)

| ชุด | วิธีติด label |
|---|---|
| BarongTrace | label ของเจ้าของชุดติดทั้งรอบวิเคราะห์ → ใช้เฉพาะโปรเซสสาย sample (`/tmp/<ชื่อ>` + ลูกหลาน) และ **ปิดชื่อไฟล์เป็น `/tmp/SAMPLE`** เพราะมัลแวร์ชื่อ `VirusShare_<md5>` ซึ่งบอกคำตอบผ่านความยาวคำสั่ง |
| APT29 | ติดเองด้วย lineage จากจุดเริ่มตามแผนของ MITRE: `cod.3aka3.scr` (RTLO), PowerShell ซ่อนคำสั่งในรูป, PsExec + `python.exe`/`sdelete64`/`Rar` บน NASHUA, `javamtsup.exe`, `hostui`, `.lnk` → PowerShell, WMI persistence, `kxwn.lock`, WinRM `wsmprovhost.exe` |
| NLME | label ของเจ้าของชุด |
| Windows-APT 2025 | ติดเองด้วย lineage จาก agent ของ Caldera (`C:\Users\Public\splunkd.exe`, `caldera-agent3.exe`) และตัดโปรเซสที่สายขาดผ่าน shell ทิ้ง 18,002 ตัว |
| Splunk | ไม่มี → ดูว่าโปรเซสที่ได้คะแนนสูงสุดในแต่ละไฟล์คือคำสั่งโจมตีหรือไม่ |

---

## 3. ผลหลัก (โมเดล 50 run, ค่าที่ดีที่สุดที่ยุติธรรมของแต่ละชุด)

| ชุด | ฟีเจอร์ / เกณฑ์ | AUC | recall | FPR | balanced acc | accuracy | baseline acc |
|---|---|---|---|---|---|---|---|
| **APT29** | neutral / 0.5 | 0.835 | 0.618 | 0.188 | **0.715** | 0.799 | 0.933 |
| APT29 | clean / 0.5 | **0.869** | 0.431 | 0.094 | 0.669 | 0.874 | 0.933 |
| **BarongTrace** | clean / ข้อมูลปกติจากไฟล์อื่น | 0.611 | 0.484 | 0.050 | **0.717** | **0.747** | 0.565 |
| BarongTrace | paper32 / ข้อมูลปกติครึ่งแรกของไฟล์เดียวกัน | 0.756 | 0.461 | 0.053 | 0.704 | 0.722 | 0.565 |
| NLME | paper32 / ข้อมูลปกติจาก host อื่น | 0.693 | 0.141 | 0.010 | 0.566 | 0.823 | 0.804 |
| Windows-APT 2025 | paper32 / ข้อมูลปกติจาก host อื่น | 0.464 | 0.315 | 0.042 | 0.637 | 0.413 | 0.847 |

**อ่านตารางอย่างไร**
- **APT29:** accuracy 0.799 *ต่ำกว่า* baseline 0.933 เพราะการโจมตีมีแค่ 6.7% แต่ AUC 0.84–0.87 และ balanced accuracy 0.72 แสดงว่าโมเดลแยกได้จริง
- **BarongTrace:** accuracy ขึ้นเป็น 0.747 เฉพาะเมื่อปรับเกณฑ์จากข้อมูลปกติ ถ้าใช้ 0.5 จะได้ 0.653 และ recall 0.208
- **NLME:** ที่เกณฑ์ 0.5 โมเดล flag ไป 61% ของโปรเซสปกติ (accuracy 0.496) เพราะไม่มี CommandLine
- **Windows-APT 2025:** balanced accuracy 0.637 แต่ AUC ต่ำกว่า 0.5 จึงเป็นผลของการตั้งเกณฑ์ต่อ host ไม่ใช่โมเดลแยกได้จริง **ไม่ควรอ้าง**

### ผลแยกตามเกณฑ์ตัดสิน (โมเดล 50 run)

| ชุด / ฟีเจอร์ | เกณฑ์ 0.5 (acc / F1 / FPR) | ปกติจากกลุ่มอื่น | ปกติครึ่งแรกของกลุ่มเดียวกัน |
|---|---|---|---|
| BarongTrace / paper32 | 0.575 / 0.061 / 0.007 | 0.717 / 0.562 / 0.051 | 0.722 / 0.605 / 0.053 |
| BarongTrace / clean | 0.653 / 0.343 / 0.004 | **0.747 / 0.625 / 0.050** | 0.724 / 0.610 / 0.054 |
| APT29 / paper32 | 0.913 / 0.330 / 0.045 | 0.904 / 0.335 / 0.057 | 0.795 / 0.211 / 0.185 |
| APT29 / clean | 0.874 / 0.313 / 0.094 | 0.907 / 0.304 / 0.050 | 0.768 / 0.240 / 0.223 |
| APT29 / neutral | 0.799 / 0.290 / 0.188 | 0.901 / 0.255 / 0.053 | 0.774 / 0.217 / 0.211 |
| NLME / paper32 | 0.496 / 0.419 / 0.609 | 0.823 / 0.238 / 0.010 | 0.814 / 0.088 / 0.012 |
| Windows-APT / paper32 | 0.435 / 0.595 / 0.869 | 0.413 / 0.476 / 0.042 | 0.411 / 0.487 / 0.039 |

baseline F1 (ทายว่าโจมตีทั้งหมด): BarongTrace 0.607 · APT29 0.125 · NLME 0.328 · Windows-APT 0.917

### BarongTrace: ฝึกและทดสอบในชุดเดียวกัน (leave-one-file-out, ไม่มี cmd_len)
accuracy 0.696, recall 0.433, FPR 0.102, AUC 0.683 (ไม่ใช้ข้อมูลแล็บ)

ตอนลองแค่ 4 ไฟล์ได้ 0.86 พอใช้ครบ 12 ไฟล์ตกเหลือ 0.70 แปลว่า **ตัวเลขจากไฟล์น้อยสูงเกินจริง**

### Splunk attack_data (Linux, ไม่มี label, โมเดล 50 run)
- **ครอบคลุม:** 71 ไฟล์ 6,900 โปรเซส มีอย่างน้อย 1 โปรเซสถูก flag ที่ 0.5 ใน 61 ไฟล์ (14.9% ของโปรเซสทั้งหมด)
- **อันดับแรกตรงคำสั่งโจมตีและถูก flag:** ใน **47 จาก 71 ไฟล์** ตัดสินโดยอ่าน command line เอง เช่น `sudo find . -exec /bin/sh`, `docker run -v /:/mnt/`, `curl -F userfile=@/root/.aws/credentials`, reverse shell `/dev/tcp/...`, `systemctl start hello_evil`
- **กระบวนการเบื้องหลังที่รู้ว่าปกติ** (Splunk forwarder, systemd, journald): ถูก flag แค่ **0.3%**
- **พลาด:** exploit แบบ binary เดี่ยว (`./exp`, pkexec, dirtyfrag), การติดตั้งแพ็กเกจที่เป็นขั้นเตรียมการ, wiper `acidrain`, `awfulshred`
- ⚠️ 13 ไฟล์มีไม่เกิน 3 โปรเซส (Splunk ตัดมาเฉพาะคำสั่งโจมตี) จึงติดอันดับแรกง่าย และหลายไฟล์ใช้ Atomic Red Team / GTFOBins เหมือนแล็บ **ผลจึงค่อนข้างเข้าทางโมเดล**

### เทียบโมเดล 12 run (เปเปอร์) กับ 50 run (dataset สุดท้าย)

`data/FINAL_DATASET_50runs.csv.gz` = ชุดหลัก 12 run + รอบใหม่ 2 + เก็บซ้ำ 24 + เครื่องที่สอง 12 (487,873 event, 4 เครื่อง)
สร้างด้วย `python host/build_dataset50.py` ใช้เทรนโมเดลในเว็บ (`models/paper_rf_*.pkl`) ตารางในเปเปอร์ยังใช้ชุด 12 run

| ชุด / ตัวชี้วัด | เทรน 12 run | เทรน 50 run |
|---|---|---|
| BarongTrace clean + เกณฑ์จากไฟล์อื่น: acc / F1 | 0.757 / 0.644 | 0.747 / 0.625 |
| BarongTrace AUC paper32 / clean | 0.774 / 0.683 | 0.756 / 0.611 |
| APT29 AUC paper32 / clean | 0.832 / 0.861 | 0.858 / 0.869 |
| APT29 balanced acc ดีที่สุด | 0.759 (clean, 0.5) | 0.715 (neutral, 0.5) |
| NLME AUC paper32 | 0.705 | 0.693 |
| Windows-APT AUC paper32 | 0.474 | 0.464 |
| Splunk อันดับแรกตรง / background ถูก flag | 49/71 · 0.5% | 47/71 · 0.3% |

**ข้อมูลมากขึ้นไม่ได้ทำให้ผลนอกแล็บดีขึ้นชัด**: AUC ต่างกันไม่เกิน 0.03 ยกเว้น BarongTrace clean (−0.07)
โมเดล 50 run ระวังขึ้น คือ FPR ต่ำลงแต่ recall ที่เกณฑ์ 0.5 ลดลง
เหตุผล: 24 จาก 38 run ที่เพิ่มเป็นรอบซ้ำบนเครื่องเดิมด้วยสถานการณ์และ ART ชุดเดิม → สิ่งที่ขาดคือความหลากหลาย ไม่ใช่ปริมาณ

---

## 4. ทำไมบางชุดใช้ไม่ได้

| สาเหตุ | ชุดที่โดน | ผลต่อโมเดล |
|---|---|---|
| **กรองเป็น alert** (เก็บเฉพาะ event ที่ชนกฎ) | Windows-APT 2025 (Wazuh) | ฟีเจอร์นับจำนวน/อัตรา event (`n_events`, `rate`, `dur_s`) เพี้ยนทั้งชุด → AUC ~0.5 |
| **ขาดคอลัมน์** CommandLine, ParentCommandLine, Device | NLME | ฟีเจอร์ที่แบก importance 68% เป็นค่าคงที่ |
| **ข้อมูลปกติไม่ใช่การใช้งานจริง** | Windows-APT 2025 | ฝั่งปกติ 92% คือ `net user administrator` ที่ Wazuh สั่งรัน ดูเหมือน discovery ทุกอย่าง |
| **ไม่มี event ดิบ** | CSU-Ransomware | คำนวณฟีเจอร์ระดับโปรเซสไม่ได้เลย |
| **label ติดทั้งรอบ** | BarongTrace | daemon ของ OS ได้ label มัลแวร์ → ต้องตัดเหลือสาย sample |
| **ชื่อไฟล์บอกคำตอบ** | BarongTrace | `VirusShare_<md5>` ยาว 43 ตัว → cmd_len รั่ว label ต้องปิดชื่อ |

**ข้อสรุป:** โมเดลใช้กับข้อมูลนอกแล็บได้เมื่อ (1) เก็บ Sysmon ครบทุก event ไม่กรอง (2) มี CommandLine/ParentProcessGuid (3) ตั้งเกณฑ์จากข้อมูลปกติของสภาพแวดล้อมนั้น

---

## 5. ข้อจำกัดที่ต้องเขียนในเล่ม

1. **label ของ APT29 และ Windows-APT เป็นของเราเอง** (lineage จากจุดเริ่มตามแผน) ถ้าจับรากไม่ครบ การโจมตีที่ตกหล่นจะไปอยู่ฝั่งปกติ
2. **APT29 มีโปรเซสโจมตีแค่ 102 ตัว** ความไม่แน่นอนของ recall จึงกว้าง
3. **การตั้งเกณฑ์แบบ (2) และ (3) ต้องมีข้อมูลปกติของสภาพแวดล้อมปลายทาง** ใช้ได้จริงในการติดตั้ง แต่ไม่ใช่ zero-shot
4. **ผลบน Splunk เป็นการตัดสินด้วยตาจากการอ่านคำสั่ง** ไม่ใช่ตัวเลขที่คำนวณจาก label
5. **ทุกชุดเป็นการจำลองหรือ sandbox** ไม่ใช่เครื่องผู้ใช้จริง

---

## 6. รันซ้ำ

ข้อมูลภายนอกอ่านเป็นข้อมูลเท่านั้น ไม่รันสคริปต์ที่มากับ dataset (เช่น `scripts/` ของ Windows-APT 2025)

```bash
gunzip -c data/FINAL_DATASET_fixed.csv.gz > host/dataset/merged_dataset.csv     # ข้อมูลแล็บ 12 run (ไม่ใส่ --lab = โมเดลของเปเปอร์)

# BarongTrace + NLME
python host/public_eval.py --lab data/FINAL_DATASET_50runs.csv.gz --barong <โฟลเดอร์ที่แตก Original_Linux/*result.zip> --nlme reference/NLME.csv

# APT29: แตก apt29_evals_day{1,2}_manual.zip แล้วแปลง + ติด label
python host/public_sets/apt29_convert.py <day1.json> <dir>/apt29_day1.csv
python host/public_sets/apt29_convert.py <day2.json> <dir>/apt29_day2.csv
python host/public_sets/apt29_label.py <dir>                       # -> <dir>/apt29_events.csv

# Windows-APT 2025: ไฟล์ CSV รายช่วง (ไม่ใช้ combined.csv) ตรวจ checksums.sha256 ก่อน
python host/public_sets/wapt2025_convert.py <โฟลเดอร์ CSV> <dir>/wapt_events.csv

python host/public_eval.py --lab data/FINAL_DATASET_50runs.csv.gz --events <dir>/apt29_events.csv "OTRF APT29" windows \
                           --events <dir>/wapt_events.csv "Windows-APT 2025" windows

# Splunk attack_data (Linux): โหลด sysmon_linux*.log ผ่าน git-lfs แล้ว
python host/public_sets/splunk_parse.py <โฟลเดอร์ log> <dir>/splunk_events.csv
python host/export_model.py && python host/public_sets/splunk_rank.py <dir> models/paper_rf_linux.pkl
```

หน้าเว็บ (`python model_web/model_web.py`) ทดสอบไฟล์ CSV ใดๆ ได้ด้วยโมเดล `.pkl` และมีปุ่ม **"ตั้งเกณฑ์จาก CSV ข้อมูลปกติ"** ตามเกณฑ์แบบ (2)

ตัวอย่างที่ทดสอบในเว็บ (โมเดล 50 run): BarongTrace ไฟล์ 9 ใช้เกณฑ์ 0.114 จากไฟล์ 1/10/12
- ไม่ปรับเกณฑ์: accuracy 0.548
- ปรับเกณฑ์: accuracy 0.721, F1 0.595, FPR 0.027
- ไฟล์และผลที่ควรเห็นอยู่ใน `demo_data/README.md`
