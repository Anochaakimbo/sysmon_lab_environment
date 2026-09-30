# (ร่างบทความ NCCY — sync กับ paper_draft_NCCY.docx)

> ฉบับข้อความสำหรับแก้ถ้อยคำ ก่อนย้ายเข้า Word (ตัวจริงคือ `docs/paper_draft_NCCY.docx`)
> ตัวเลขทุกตัวดึงจาก `reference/ml_results.csv`, `ml_loso.csv`, `bench_process_nopca.csv`,
> `merged_dataset.csv` — ตรวจซ้ำได้

---

## ชื่อเรื่อง

**ไทย:** การสร้างชุดข้อมูลข้ามแพลตฟอร์มสำหรับการตรวจจับมัลแวร์ด้วยการเรียนรู้ของเครื่อง
จากบันทึกเหตุการณ์ Sysmon บนระบบปฏิบัติการ Linux และ Windows

**EN:** A CROSS-PLATFORM SYSMON-BASED DATASET FOR MACHINE-LEARNING MALWARE DETECTION ON LINUX AND WINDOWS

---

## บทคัดย่อ

งานวิจัยด้านการตรวจจับมัลแวร์ด้วยการเรียนรู้ของเครื่องส่วนใหญ่อาศัยบันทึกเหตุการณ์จากระบบปฏิบัติการ
Windows เพียงแพลตฟอร์มเดียว บทความนี้นำเสนอการสร้างชุดข้อมูลสำหรับตรวจจับมัลแวร์จากบันทึกเหตุการณ์
Sysmon แบบสองแพลตฟอร์มคู่ขนานคือ Linux และ Windows โดยจำลองพฤติกรรมด้วยชุดทดสอบ Atomic Red Team
ครอบคลุม 6 ประเภทสถานการณ์ ได้แก่ พฤติกรรมปกติ เรียกค่าไถ่ โทรจัน บอตเน็ต ขุดเหรียญ และการใช้ช่องโหว่
ชุดข้อมูลที่ได้มีทั้งสิ้น 81,331 เหตุการณ์ (Linux 45,311 และ Windows 36,020) มีสัดส่วนตัวอย่างอันตราย
33.8% ใกล้เคียงกันทั้งสองแพลตฟอร์ม การกำหนดป้ายกำกับใช้การสืบสายกระบวนการจากไดเรกทอรีทดสอบ ผลการทดลอง
พบว่าเมื่อประเมินด้วยการแบ่งข้อมูลแบบ GroupKFold ตามกระบวนการเพื่อป้องกันการรั่วไหลของข้อมูล แบบจำลอง
Random Forest ระดับกระบวนการให้ความแม่นยำ 94.9% และค่า F1 เท่ากับ 0.924 ขณะที่แบบจำลองไม่มีผู้สอน
Local Outlier Factor ให้พื้นที่ใต้เส้นโค้ง 0.849 บทความนี้ยังวิเคราะห์แหล่งการรั่วไหลของข้อมูลอย่างเป็น
ระบบ และชี้ให้เห็นว่าโปรโตคอลการประเมินมีผลต่อค่าที่รายงานมากกว่าปริมาณข้อมูล

**คำสำคัญ** -- การตรวจจับมัลแวร์, Sysmon, การเรียนรู้ของเครื่อง, ชุดข้อมูลข้ามแพลตฟอร์ม, การรั่วไหลของข้อมูล

*(ABSTRACT ภาษาอังกฤษ — ดูในไฟล์ .docx)*

---

## 1. บทนำ

การเปลี่ยนผ่านสู่ยุคดิจิทัลทำให้ภัยคุกคามจากมัลแวร์ทวีความรุนแรงและตรวจจับได้ยากขึ้น การเฝ้าระวังแบบ
อาศัยลายเซ็น (signature-based) เพียงอย่างเดียวจึงตามไม่ทันมัลแวร์รูปแบบใหม่ ทำให้การตรวจจับเชิงพฤติกรรม
ด้วยการเรียนรู้ของเครื่องได้รับความสนใจ [1], [8]

เครื่องมือ Sysmon เป็นแหล่งบันทึกเหตุการณ์ระดับโฮสต์ที่ให้รายละเอียดการสร้างกระบวนการ การเชื่อมต่อเครือข่าย
และการเข้าถึงไฟล์ [20] งานอ้างอิงหลัก [1] สร้างชุดข้อมูลและเปรียบเทียบ 7 แบบจำลองจาก Sysmon บน Windows
ได้ RF F1 0.8868 แต่มีข้อจำกัดสองข้อ: (1) ครอบคลุมเฉพาะ Windows — โอนโมเดลข้าม OS ทำให้ F1 ตกมาก [4]
(2) ขาด parent–child correlation [11]

**ส่วนสนับสนุน 4 ข้อ:** (1) ชุดข้อมูล Sysmon สองแพลตฟอร์มคู่ขนาน (2) เพิ่ม parent–child + CommandLine
(3) ครอบคลุม NetworkConnect (C2/beaconing) ที่เปเปอร์อ้างอิงแทบไม่มี (4) วิเคราะห์ data leakage อย่างเป็น
ระบบตาม [2], [3] และแสดงว่าโปรโตคอลการประเมินสำคัญกว่าปริมาณข้อมูล

## 2. งานที่เกี่ยวข้อง

**2.1 การตรวจจับจากบันทึกเหตุการณ์และ Sysmon** — [1] เก็บ Sysmon 5 เครื่องใน AD 31 ชม. ได้ NLME 71,017
เหตุการณ์; [5] Sysmon+ELK สร้าง AAU_MalData จากมัลแวร์ 2,800 ตัวอย่าง เชื่อมกับ MITRE ATT&CK [21]

**2.2 ชุดข้อมูลเชิงพลวัต** — EldeRan [6] ใช้ Cuckoo Sandbox เก็บ API/registry; [7] ชุด ransomware เชิงพลวัต;
[8] deep learning กับมัลแวร์ บทความนี้ใช้ Sysmon โดยตรงแทน Cuckoo

**2.3 ระดับกระบวนการและข้ามแพลตฟอร์ม** — [9] แสดง process-level ดีกว่า machine-level (F1 0.87);
BarongTrace [4] พบว่าโมเดล Windows ทำนาย Linux แล้ว F1 ตกได้ถึง 0.54

**2.4 อคติในการประเมินและ data leakage** — Arp et al. [2] ทบทวน 30 บทความ ชี้กับดัก data snooping;
TESSERACT [3] ขจัดอคติเชิงพื้นที่/เวลา บทความนี้ปฏิบัติตามด้วย GroupKFold + leave-one-scenario-out

**2.5 การตรวจจับด้วย Provenance** — UNICORN [10] และ Kairos [11] ใช้กราฟสืบสาย บทความนี้นำหลักการสืบสาย
มาใช้ในการกำหนดป้ายกำกับ

## 3. ระเบียบวิธีวิจัย

**3.1 สภาพแวดล้อม** — VMware + Vagrant, Linux = Ubuntu 22.04 + Sysmon for Linux (journald→rsyslog→TCP),
Windows = Sysmon→EVTX; รันทีละเครื่อง revert snapshot ทุกครั้ง; benign+malicious อยู่เครื่องเดียวกัน (กัน VM leakage)

**3.2 การจำลอง** — Atomic Red Team [22] รันบนเป้าหมายเอง + C2/pool จำลองในแล็บ; 6 สถานการณ์/แพลตฟอร์ม
(ตาราง 1) เลือกมัลแวร์ 5 ตระกูลให้ครอบพฤติกรรมโฮสต์ต่างกัน (ไฟล์/registry/เครือข่าย/CPU/injection)

**3.3 ท่อข้อมูล** — parse → enrich (CommandLine, Hashes, Parent*) → label; รวมทุกรอบเป็นชุดเดียว คงคอลัมน์
platform/computer/run ไว้ trace

**3.4 การกำหนดป้ายกำกับ (lineage)** — เหตุการณ์ที่สืบสายจากกระบวนการที่ปล่อยในไดเรกทอรีทดสอบ = อันตราย
สอดคล้อง [10], [11]; แม่นกว่า session labeling; แยกความแรงหลักฐานเป็นระดับ (หลักฐานตรง → สายเลือดล้วน)

**3.5 คุณลักษณะ** — รวมเหตุการณ์ต่อกระบวนการ (ProcessGuid + machine + run) เป็นเวกเตอร์ 32 ตัว 5 กลุ่ม
(ตาราง 2); แยก "ไม่มีพฤติกรรม" ออกจาก "แหล่งข้อมูลไม่รองรับ"

**3.6 PCA + การเลือกคุณลักษณะ** — StandardScaler → PCA (กวาด component เลือกด้วย validation) และ greedy
backward elimination เพื่อคัด derived features ที่รั่ว; fit เฉพาะ train แล้ว transform ไป val/test [2];
พิจารณา SMOTE [18] เฉพาะ train

**3.7 โปรโตคอลการประเมิน** — รายงานหลักด้วย **GroupKFold ตาม ProcessGuid** + ประเมิน zero-day ด้วย
leave-one-scenario-out; วัด Accuracy, Precision, Recall, F1, AUC

**ตาราง 1 สถานการณ์**

| สถานการณ์ | label | เทคนิค ATT&CK |
|-----------|-------|---------------|
| Benign | 0 | กิจกรรมผู้ใช้ปกติ |
| Ransomware | 1 | T1486, T1083, T1005, T1070.004 |
| Trojan | 1 | T1027, T1036.003, T1547.001, T1112 |
| Botnet | 1 | T1071.001, T1132.001, T1105 |
| Cryptominer | 1 | T1496, T1053, T1057 |
| Exploitation | 1 | T1055, T1548.002, T1134, T1218.011 |

**ตาราง 2 กลุ่มคุณลักษณะ**

| กลุ่ม | ตัวอย่าง |
|-------|----------|
| วงจรกระบวนการ | จำนวน ProcessCreate/Terminate, child, ระยะเวลา |
| กิจกรรมไฟล์ | จำนวน FileCreate/Delete, พาธที่ต่างกัน |
| กิจกรรมเครือข่าย | จำนวน NetworkConnect, IP/พอร์ตปลายทางที่ต่างกัน |
| กิจกรรม registry | จำนวน RegistrySetValue/AddDelete |
| คำสั่ง/เมทาดาทา | ความยาวคำสั่ง, integrity, ข้อมูลกระบวนการแม่ |

## 4. การทดลองและผลลัพธ์

**4.1 องค์ประกอบ** — 81,331 เหตุการณ์ 80 คอลัมน์ → รวมเป็น 23,971 กระบวนการ; อันตราย Linux 34.2% / Windows 33.3%

**ตาราง 3 องค์ประกอบ**

| แพลตฟอร์ม | ปกติ | อันตราย | รวม | %อันตราย |
|-----------|------|---------|-----|----------|
| Linux | 29,805 | 15,506 | 45,311 | 34.2% |
| Windows | 24,027 | 11,993 | 36,020 | 33.3% |
| รวม | 53,832 | 27,499 | 81,331 | 33.8% |

**4.2 ผลจำแนกระดับกระบวนการ (ตาราง 4)** — RF ดีสุด acc 0.949 F1 0.924 AUC 0.988; LOF ดีสุดในกลุ่ม
unsupervised AUC 0.849 (ดู ROC ภาพ 1)

**ตาราง 4 ผล (GroupKFold, 32 feature)**

| ชนิด | แบบจำลอง | Acc | Prec | Rec | F1 | AUC |
|------|----------|-----|------|-----|-----|-----|
| มีผู้สอน | Random Forest | 0.949 | 0.919 | 0.929 | 0.924 | 0.988 |
| มีผู้สอน | Decision Tree | 0.871 | 0.817 | 0.792 | 0.804 | 0.930 |
| มีผู้สอน | SVM | 0.733 | 0.597 | 0.619 | 0.607 | 0.786 |
| มีผู้สอน | Naive Bayes | 0.359 | 0.340 | 0.980 | 0.505 | 0.594 |
| ไม่มีผู้สอน | Local Outlier Factor | 0.771 | 0.612 | 0.857 | 0.714 | 0.849 |
| ไม่มีผู้สอน | Isolation Forest | 0.647 | 0.479 | 0.667 | 0.558 | 0.622 |
| ไม่มีผู้สอน | One-Class SVM | 0.554 | 0.376 | 0.513 | 0.434 | 0.499 |
| เส้นฐาน | flag ทุกแถว | 0.334 | 0.334 | 1.000 | 0.500 | - |

**4.3 zero-day (LOSO, ตาราง 5)** — RF ชนะ baseline 8/10, LOF 10/10

| แบบจำลอง | F1 เฉลี่ย | AUC เฉลี่ย | ชนะ baseline |
|----------|-----------|-----------|--------------|
| Random Forest | 0.764 | 0.897 | 8/10 |
| Local Outlier Factor | 0.728 | 0.780 | 10/10 |
| Decision Tree | 0.688 | 0.820 | 7/10 |

**4.4 การวิเคราะห์ data leakage** — ตรวจ 4 ประเภท: (1) protocol (2) platform (100%→เดาสุ่มหลังตัดคอลัมน์)
(3) enrichment (CommandLine ว่าง=benign) (4) derived feature (CurrentDirectory=seed dir, depth จาก lineage)

**ตาราง 6 ความอ่อนไหวต่อโปรโตคอล (RF, ข้อมูลชุดเดียวกัน)**

| วิธีแบ่ง | Accuracy | F1 |
|----------|----------|-----|
| สุ่มรายแถว | 0.974 | 0.961 |
| GroupKFold ตาม ProcessGuid | 0.881 | 0.811 |
| Leave-one-scenario-out | 0.636 | 0.634 |

**4.5 ผลการเลือกคุณลักษณะและ PCA** — ตัด derived ออก F1 0.948→0.924; ตัดความยาวคำสั่งเหลือพฤติกรรมล้วน
F1 ร่วง 0.610 → คะแนนส่วนหนึ่งมาจาก harness ไม่ใช่พฤติกรรม; PCA ให้ประโยชน์จำกัด (event-level แย่ลง
0.951→0.936) เพราะ feature ผ่าน encoding มาแล้ว

**ตาราง 7 ความอ่อนไหวต่อชุดคุณลักษณะ**

| ชุดคุณลักษณะ | จำนวน | RF F1 | LOF AUC |
|--------------|-------|-------|---------|
| ทั้งหมด | 35 | 0.948 | 0.866 |
| ตัด derived | 32 | 0.924 | 0.849 |
| พฤติกรรมล้วน | 30 | 0.610 | - |

**4.6 เทียบองค์ประกอบกับ NLME [1] (ตาราง 8)**

| ชนิดเหตุการณ์ | บทความนี้ | NLME [1] |
|---------------|-----------|----------|
| NetworkConnect (3) | 2.8 | 0.03 |
| FileDelete (23) | 9.6 | 0 |
| RawAccessRead (9) | 6.1 | 0 |
| ProcessTerminate (5) | 33.0 | 2.1 |
| ProcessCreate (1) | 28.7 | 29.5 |
| FileCreate (11) | 11.7 | 39.0 |

## 5. อภิปรายผล

RF ดีสุด (มีผู้สอน), LOF ดีสุด (ไม่มีผู้สอน) สอดคล้อง [1], [14]; process-level > event-level [9]
**ประเด็นเน้น:** ค่าที่รายงานขึ้นกับโปรโตคอล (ตาราง 6) และชุดคุณลักษณะ (ตาราง 7) มากกว่าปริมาณข้อมูล [2], [3]
การควบคุม leakage สำคัญกว่าเพิ่มจำนวน event, PCA ช่วยจำกัด **ข้อจำกัด:** เครื่องน้อย, benign แคบ, ART < มัลแวร์จริง

## 6. สรุปและงานในอนาคต

ชุดข้อมูล Sysmon สองแพลตฟอร์ม 81,331 เหตุการณ์ + วิเคราะห์ leakage; RF process-level acc 94.9% F1 0.924
อนาคต: benign หลากหลายขึ้น, เพิ่มเครื่อง/รอบ, หลอมรวมสัญญาณเครือข่าย

## เอกสารอ้างอิง

[1] R. M. R. Achmad, D. P. Nariswari, B. A. Pratomo, and H. Studiawan, "Sysmon event logs for machine learning-based malware detection," *Cyber Security and Applications*, vol. 3, 100110, 2025.
[2] D. Arp et al., "Dos and Don'ts of Machine Learning in Computer Security," *USENIX Security*, 2022, pp. 3971-3988.
[3] F. Pendlebury et al., "TESSERACT: Eliminating Experimental Bias in Malware Classification across Space and Time," *USENIX Security*, 2019, pp. 729-746.
[4] B. A. Pratomo et al., "BarongTrace: A Malware Event Log Dataset for Linux," *AINA, LNDECT*, vol. 202, pp. 48-60, 2024.
[5] R. V. Mahmoud et al., "Redefining Malware Sandboxing: Enhancing Analysis Through Sysmon and ELK Integration," *IEEE Access*, vol. 12, pp. 68624-68636, 2024.
[6] D. Sgandurra et al., "Automated Dynamic Analysis of Ransomware," arXiv:1609.03020, 2016.
[7] J. A. Herrera-Silva and M. Hernandez-Alvarez, "Dynamic Feature Dataset for Ransomware Detection," *Sensors*, vol. 23, no. 3, 1053, 2023.
[8] R. Vinayakumar et al., "Robust Intelligent Malware Detection Using Deep Learning," *IEEE Access*, vol. 7, pp. 46717-46738, 2019.
[9] B. A. Pratomo et al., "Enhancing Enterprise Network Security: Comparing Machine-Level and Process-Level Analysis," arXiv:2310.18165, 2023.
[10] X. Han et al., "UNICORN: Runtime Provenance-Based Detector for Advanced Persistent Threats," *NDSS*, 2020.
[11] Z. Cheng et al., "Kairos: Practical Intrusion Detection and Investigation using Whole-system Provenance," *IEEE S&P*, 2024.
[12] L. Breiman, "Random Forests," *Machine Learning*, vol. 45, no. 1, pp. 5-32, 2001.
[13] F. T. Liu, K. M. Ting, and Z. H. Zhou, "Isolation Forest," *IEEE ICDM*, 2008, pp. 413-422.
[14] M. M. Breunig et al., "LOF: Identifying Density-Based Local Outliers," *ACM SIGMOD*, 2000, pp. 93-104.
[15] B. Scholkopf et al., "Estimating the Support of a High-Dimensional Distribution," *Neural Computation*, vol. 13, no. 7, pp. 1443-1471, 2001.
[16] C. Cortes and V. Vapnik, "Support-Vector Networks," *Machine Learning*, vol. 20, no. 3, pp. 273-297, 1995.
[17] V. Chandola, A. Banerjee, and V. Kumar, "Anomaly Detection: A Survey," *ACM Computing Surveys*, vol. 41, no. 3, pp. 1-58, 2009.
[18] N. V. Chawla et al., "SMOTE: Synthetic Minority Over-sampling Technique," *JAIR*, vol. 16, pp. 321-357, 2002.
[19] F. Pedregosa et al., "Scikit-learn: Machine Learning in Python," *JMLR*, vol. 12, pp. 2825-2830, 2011.
[20] M. Russinovich and T. Garnier, "Sysmon (System Monitor)," Microsoft Sysinternals, 2024.
[21] B. E. Strom et al., "MITRE ATT&CK: Design and Philosophy," The MITRE Corporation, 2020.
[22] Red Canary, "Atomic Red Team," GitHub repository, 2024.
