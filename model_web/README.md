# เว็บทดสอบโมเดล Sysmon (.pkl / .joblib)

เว็บนี้ใช้โมเดล scikit-learn ที่ผู้ใช้อัปโหลด ไม่มีการฝึกหรือเลือกโมเดลให้อัตโนมัติ
รันเฉพาะเครื่องนี้ที่ http://127.0.0.1:8765

## เปิดเว็บ
จากโฟลเดอร์ sysmon_lab_environment/model_web:
    powershell -ExecutionPolicy Bypass -File .\start_model_web.ps1

สคริปต์เลือก .venv ของโครงการก่อน หากไม่มีจึงใช้ runtime ที่จัดไว้บนเครื่องนี้
กรณีติดตั้งเอง ให้ใช้ Python และเวอร์ชันไลบรารีตรงกับตอนบันทึกโมเดล
requirements.txt ระบุ environment ที่ทดสอบเว็บนี้ ไม่ใช่เวอร์ชันที่ใช้กับทุกโมเดลได้

## ใช้งาน
1. เลือกไฟล์ .pkl, .pickle หรือ .joblib ที่ฝึกแล้ว ยืนยันแหล่งที่มา แล้วกดโหลดโมเดล
2. ตรวจชื่อและลำดับฟีเจอร์ เว็บอ่าน feature_names_in_ หรือ columns ในไฟล์
   หากโมเดลไม่มีชื่อฟีเจอร์ ให้กรอกชื่อคั่นด้วย comma ตามลำดับตอนฝึก
3. อัปโหลด CSV ฟีเจอร์ UTF-8 ที่มีคอลัมน์ตรงกับโมเดล หนึ่งแถวต่อหนึ่งตัวอย่าง
4. ระบุคอลัมน์ label จริง (ค่าเริ่มต้น label) หากมี เพื่อคำนวณคะแนน
5. กดทดสอบโมเดล ดูผล/กรอง OS/ดาวน์โหลดผล CSV

รองรับโมเดลจำแนกสองคลาสที่ใช้ตัวเลข 0 = ปกติ และ 1 = การโจมตี
รองรับ outlier detector ที่มี predict() เช่น IsolationForest, OneClassSVM และ LOF ที่ฝึกด้วย novelty=True:
แปลง -1 เป็นผิดปกติ (1), +1 เป็นปกติ (0) และกลับทิศคะแนนให้ค่าสูงหมายถึงผิดปกติ
ไม่รองรับ regression, multiclass, clustering หรือ LOF ที่ไม่มี predict()

รับได้ทั้ง estimator, Pipeline หรือ dict ที่มี model/pipeline/classifier/rf/estimator
dict อาจมี scaler และ columns (รายชื่อฟีเจอร์เรียงตาม input) รวมมาด้วย
ตัวอย่างการบันทึกหลังฝึก:
    joblib.dump(pipeline, "model.pkl")
    joblib.dump({"model": model, "scaler": scaler, "columns": list(X.columns)}, "model.joblib")

หากใช้ scaling, PCA, imputation หรือ encoding ตอนฝึก ควรรวมไว้ใน Pipeline เดียว
เว็บไม่ fit preprocessing ใหม่ และไม่เดาว่าต้องใช้ scaler ตัวไหน
ห้ามแนบ scaler แยกซ้ำกับ Pipeline; CSV ของโมเดลเดี่ยวต้องเตรียมเหมือนตอนฝึกแล้ว

## ผลและคะแนน
ค่าเริ่มต้นใช้ model.predict() โดยตรง
ปรับ threshold ได้เฉพาะโมเดลที่มี predict_proba และผู้ใช้เปิดตัวเลือกเอง
คะแนนจาก predict_proba เป็นค่าของคลาส 1; decision_function/anomaly score ไม่ใช่ความน่าจะเป็น
มี label จึงคำนวณ Accuracy, Precision, Recall, F1, FPR และ confusion matrix
ROC-AUC ต้องมี label ทั้งสองคลาสและคะแนนต่อเนื่องจากโมเดล
ไม่มี label ยังคงทำนายได้; ไม่เติม label สมมติให้ข้อมูล
เว็บไม่ทราบชุดฝึกของโมเดลที่อัปโหลด จึงไม่ยืนยันว่าผลเป็น independent test
seen_in_training ในผล CSV เว้นว่างเพื่อระบุว่าไม่ทราบ

## CSV แบบ Event ดิบ (ตัวเลือกเสริม)
ใช้ได้เฉพาะโมเดลที่ฝึกด้วย aggregate() ของ feature_processing.py รุ่นเดียวกัน (แยกมาจากโค้ดวิจัย)
ต้องยืนยันในหน้าเว็บก่อนใช้ โหมดนี้รวม Event เป็น 32 ฟีเจอร์ของโครงการ
ต้องมี platform, run_id และคอลัมน์ที่แสดงในหน้าเว็บ; label ไม่บังคับ
ถ้าไม่มี platform/run_id ระบุเองได้เมื่อทั้งไฟล์เป็นข้อมูลรอบเดียวบน OS เดียว
ถ้า preprocessing หรือการรวม Event ต่างกัน ให้เตรียม CSV ฟีเจอร์จากโค้ดตอนฝึกแทน

## ขอบเขตและการเก็บข้อมูล
ไฟล์ละไม่เกิน 100 MB, CSV ไม่เกิน 200,000 แถว
โมเดลที่อัปโหลดเก็บในหน่วยความจำล่าสุด 3 ไฟล์ ผลดาวน์โหลดล่าสุด 5 ชุด
รีสตาร์ตเซิร์ฟเวอร์แล้วต้องอัปโหลดใหม่ รีเฟรชหน้าแล้วเลือกโมเดลใหม่
ไม่ได้ส่งไฟล์ไปบริการภายนอก
pickle/joblib สามารถรันโค้ดขณะโหลดได้: ใช้เฉพาะไฟล์ที่เชื่อถือ
ช่องยืนยันไม่ใช่ sandbox จึงห้ามเปิดบริการนี้รับไฟล์จากคนทั่วไป
รายละเอียด: https://scikit-learn.org/stable/model_persistence.html

## ตรวจสอบ
    python -m unittest discover -s . -p "test_uploaded_model.py" -v

ทดสอบ Pipeline, pickle, compressed joblib+scaler, ลำดับฟีเจอร์, label,
SVC decision score, IsolationForest และ threshold เทียบกับการเรียกโมเดลโดยตรง
test_model_web.py เป็น regression test ของตัวรวม Event และต้องมี fixture รุ่นเก่าใน models/web_tester
คำสั่ง model_web.py --train รุ่นเก่ายังมีเพื่อสร้าง fixture เท่านั้น ไม่ถูกเรียกเมื่อเปิดเว็บ

## ตัวอย่างงานวิจัยภายนอก (SAP / ACSAC 2023)
ไฟล์ที่เตรียมไว้บนเครื่องนี้อยู่ใน examples/research
ใช้ sap_research_model_web.pkl คู่กับ research_demo_200.csv ในโหมดฟีเจอร์
โมเดลเป็น XGBoost ที่มี sklearn API ต้องมีไลบรารีใน requirements_research.txt เพิ่ม
แปลงรูปแบบจากโมเดลที่ผู้วิจัยเผยแพร่โดยไม่ฝึกใหม่ และตรวจผลตรงกับต้นฉบับทุก 1,940 แถว
CSV ตัวอย่างมาจากข้อมูลที่ใช้ฝึก final model จึงใช้ตรวจการทำงานของเว็บเท่านั้น ไม่ใช่ independent evaluation
รายละเอียดที่มาและขั้นตอนแปลงอยู่ใน วิธีทดลอง.txt ของโฟลเดอร์ตัวอย่าง


ไฟล์เว็บทั้งหมดอยู่ในโฟลเดอร์นี้: model_web.py, uploaded_model.py, feature_processing.py, assets/, start_model_web.ps1, requirements*.txt, examples/ และ models/ (fixture สำหรับทดสอบเดิม)
หากย้ายไปเครื่องอื่น ให้สร้าง .venv ในโฟลเดอร์นี้และติดตั้ง requirements.txt; ตัวอย่างวิจัยต้องติดตั้ง requirements_research.txt เพิ่ม

## ส่งออก Random Forest จากข้อมูลที่แก้ไขแล้ว

รันจากราก repository ด้วย environment ที่มี scikit-learn, pandas, numpy, scipy และ joblib:

```powershell
python model_web/export_updated_rf.py --combined --out model_web/exports/my_combined_run
```

ตัด `--combined` ออกหากต้องการฝึกแยก OS ใช้โฟลเดอร์ผลลัพธ์ใหม่ที่ยังว่าง
สคริปต์ใช้ข้อมูลหลัก `data/FINAL_DATASET_fixed.csv.gz` และ `data/repeat/` ฝึกบนเครื่องที่ 1
แล้วทดสอบกับ `data/machine2/` โดยไม่ใช้ข้อมูลเครื่องที่ 2 ฝึกหรือปรับ threshold
ใช้ฟีเจอร์พฤติกรรม 53 ตัวตาม `host/replay_detect.py` และคัดโปรเซสเครื่องมือทดลองออก
ผลรวมเป็น estimator ตัวเดียว ไม่ได้เลือกโมเดลย่อยตาม OS

อัปโหลด `.pkl` กับ CSV `test_*_features.csv` ที่ส่งออกคู่กัน โดยเลือกโหมดฟีเจอร์ที่เตรียมแล้ว
ไม่ใช้โหมด Event ดิบ 32 ฟีเจอร์กับโมเดลรุ่นนี้ คะแนนรวมและแยก OS อยู่ในไฟล์ metrics
เก็บรายการข้อมูลและเวอร์ชันโค้ดใน manifest เพื่อแยกจากผลหลัก 32 ฟีเจอร์ของบทความ

สำหรับ Event CSV ใหม่ตาม schema ของโครงการ ใช้ `prepare_behavior_csv.py --csv <ไฟล์> --os both --out <ไฟล์ฟีเจอร์>`
หรือเลือก `--os linux` / `--os windows` ต้องมี `platform` และ `run_id` ตามจริง
หากต้องการให้ preprocessing ตรงกับโมเดลเดิม ให้ใช้สคริปต์และ `preprocessing_source/` ในโฟลเดอร์ export รุ่นนั้น

`exports/`, `models/`, log และ CSV ที่คลายจากไฟล์ `.gz` เป็นไฟล์ในเครื่อง ไม่ commit ซ้ำใน Git
ไฟล์เหล่านี้ไม่ได้ถูกลบ สามารถสร้างใหม่จากสคริปต์หรือแจกเป็นชุดดาวน์โหลดแยกได้
