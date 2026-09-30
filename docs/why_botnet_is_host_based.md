# ทำไม Botnet ถึงอยู่ในชุดข้อมูล Host-based

> เอกสารตอบคำถาม: *"Botnet เป็นการโจมตีทางเครือข่าย ทำไมถึงมาอยู่ในงาน host-based?"*
> สรุปสั้น: **คำถามสมเหตุสมผล แต่เกิดจากการปนคนละแกนกัน 2 แกน**
> `botnet` ไม่ใช่ *แหล่งข้อมูล* — มันคือ *ชนิดของมัลแวร์* เหมือน ransomware/trojan ที่เหลือ

---

## 1. สองแกนที่ถูกปนกัน

| แกน | ค่าที่เป็นไปได้ | งานนี้เลือก |
|---|---|---|
| **แหล่งข้อมูล** (data source) | host-based / network-based | **host-based ล้วน** (Sysmon) |
| **ชนิดการโจมตี** (malware family) | ransomware, trojan, botnet, miner, exploit | **ทั้ง 5 ตัว** |

ทั้ง 5 scenario เป็น *malware family* ที่ถูกสังเกตผ่าน *host telemetry* เดียวกัน
`botnet` ไม่ได้อยู่คนละแกนกับเพื่อน — มันอยู่แกนเดียวกันเป๊ะ

คำถามที่ถูกต้องจึงไม่ใช่ *"ทำไม botnet มาอยู่ใน host-based"*
แต่คือ **"โฮสต์ที่ถูกจับเข้า botnet ทิ้งร่องรอยอะไรไว้บนเครื่องบ้าง"** — ซึ่งมีคำตอบชัดเจน

---

## 2. หลักฐานจากโค้ดจริง: botnet scenario มี 4 stage มีแค่ 1 stage ที่แตะเน็ต

จาก `scenarios_win/botnet_win.ps1` และ `scenarios/botnet.sh`:

| Stage | ทำอะไร | Sysmon event ที่ได้ | เป็น network? |
|---|---|---|---|
| **1. Recon** | `T1016` `T1049` `T1018` + `ipconfig` `arp` `netstat` `route` `nslookup` | ProcessCreate (1), FileCreate (11) | ❌ host ล้วน |
| **2. Beacon** | HTTP + TCP ไป C2 ในแล็บ 30 รอบ | NetworkConnect (3) | ⚠️ ดูข้อ 3 |
| **3. Transfer** | `T1105` `T1132.001` `T1071.001` | ProcessCreate, FileCreate | ❌ host ล้วน |
| **4. Staging** | `systeminfo` → zip → base64 → POST | ProcessCreate, FileCreate, FileDelete (23) | ❌ host ล้วน |

**3 ใน 4 stage ไม่แตะเครือข่ายเลย** และสร้าง event ชนิดเดียวกับ ransomware/trojan ทุกประการ

ถ้าตัด botnet ออกเพราะ "เป็น network attack" ก็ต้องตัด `T1016`/`T1049`/`T1018`
ซึ่งเป็น *discovery* บนเครื่องออกไปด้วย — ซึ่งไม่มีเหตุผล

---

## 3. NetworkConnect (EventID 3) เป็น host-based artifact เต็มตัว

จุดนี้คือหัวใจของคำตอบ **Sysmon EventID 3 ไม่ใช่การดักแพ็กเก็ต**
มันคือ **บันทึกของระบบปฏิบัติการว่า "process ตัวนี้เปิด socket ไปที่นี่"**

```
Network-based (Zeek / Suricata / NIDS) เห็น:
    192.168.56.21:52134 -> 192.168.56.1:8080   TCP   1,204 bytes
    └─ ไม่รู้ว่า process ไหนเป็นคนเปิด ไม่รู้ว่าใครเป็นพ่อ ไม่รู้คำสั่ง

Host-based (Sysmon EventID 3) เห็น:
    Image             : C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
    ProcessGuid       : {a1b2c3d4-...}
    User              : DESKTOP-XXX\vagrant
    SourceIp:Port     : 192.168.56.21:52134
    DestinationIp:Port: 192.168.56.1:8080
    └─ รู้ครบว่าใครทำ สั่งด้วยอะไร สืบสายมาจากไหน
```

**สิ่งที่ NIDS ทำไม่ได้แต่ Sysmon ทำได้คือ process attribution**
และนั่นคือเหตุผลที่ botnet **ควร**อยู่ในชุด host-based เป็นพิเศษ ไม่ใช่เหตุผลที่ควรตัดออก

> ถ้าตรวจ botnet จาก network อย่างเดียว จะรู้แค่ "มีเครื่องคุยกับ C2"
> แต่ไม่รู้ว่า **ต้องไปฆ่า process ตัวไหน ลบ persistence ที่ไหน** — ซึ่งคือสิ่งที่ผู้ตอบสนองเหตุการณ์ต้องการ

---

## 4. Botnet คือช่องว่างที่เปเปอร์อ้างอิงไม่ได้ครอบคลุม

วัดจาก `reference/NLME.csv` (71,017 แถว) ของ Achmad et al. (2025):

| EventID | เปเปอร์อ้างอิง | สัดส่วน |
|---|---|---|
| 11 FileCreate | 27,709 | 39.0% |
| 1 ProcessCreate | 20,956 | 29.5% |
| 13 RegistrySetValue | 13,936 | 19.6% |
| **3 NetworkConnect** | **20** | **0.03%** |

เปเปอร์มี NetworkConnect **20 แถว จาก 5 เครื่อง ตลอด 31 ชั่วโมง**
(ตรวจจาก EVTX ดิบใน repo ของเขาแล้ว ไม่ใช่การถูกตัดตอนทำ CSV — Sysmon config
ของเขาไม่ได้เก็บ event นี้)

ของเรา `botnet` ได้ NetworkConnect หลักร้อยถึงพันต่อ scenario

> **ดังนั้น botnet scenario ไม่ใช่ของแปลกปลอม แต่คือ contribution**
> เราครอบคลุมพฤติกรรม Command-and-Control ที่เปเปอร์อ้างอิงเก็บไม่ได้

---

## 5. การปรับที่แนะนำ: เปลี่ยน "คำเรียก" ไม่ใช่เปลี่ยน "ของ"

ปัญหาอยู่ที่ชื่อ `botnet` ชวนให้นึกถึง "network attack"
แก้ด้วยการเล่าเรื่องด้วยแกน **ATT&CK tactic** ซึ่งเป็นภาษามาตรฐานที่โต้แย้งได้ยาก

| scenario ในโค้ด | เรียกในธีสิส/สไลด์ว่า | ATT&CK Tactic หลัก |
|---|---|---|
| `ransomware` / `ransomware_win` | Ransomware | **Impact** (TA0040) |
| `trojan` / `trojan_win` | Trojan / Backdoor | **Persistence** (TA0003) + **Defense Evasion** (TA0005) |
| `miner` / `miner_win` | Cryptojacking | **Impact** (TA0040) |
| `exploit` / `exploit_win` | Privilege Escalation | **Privilege Escalation** (TA0004) |
| **`botnet` / `botnet_win`** | **C2 Beaconing** | **Command and Control** (TA0011) |

### ประโยคที่ใช้ตอบได้ตรงๆ

> "Botnet ในงานนี้ไม่ใช่การโจมตีทางเครือข่าย แต่คือ **มัลแวร์ตระกูลหนึ่ง** ที่เราสังเกต
> **ร่องรอยบนโฮสต์** ของมัน ครอบคลุม tactic Command-and-Control (TA0011) ซึ่งเป็น
> tactic เดียวที่ tactic อื่นทั้ง 4 scenario ไม่ได้ครอบคลุม
>
> Sysmon EventID 3 ที่เราใช้ **ไม่ใช่การดักแพ็กเก็ต** แต่เป็นบันทึกของ OS ที่ผูก
> การเชื่อมต่อเข้ากับ ProcessGuid, Image และ User — ข้อมูลที่ระบบ network-based
> ให้ไม่ได้ และเปเปอร์อ้างอิงเก็บไว้เพียง 20 แถวจาก 71,017 แถว"

---

## 6. ⚠️ ไม่แนะนำให้ rename ในโค้ด

คอลัมน์ `session` / `run_id` ในข้อมูลที่เก็บไว้แล้ว **56,949 แถว** ใช้ค่า `botnet` / `botnet_win`
การ rename หมายถึงต้อง:

1. แก้ `SCENARIOS` ทั้ง `orchestrator.py` และ `orchestrator_win.py`
2. แก้ `REGISTRY` + `CLEAN_SET` ใน `dashboard.py`
3. เปลี่ยนชื่อไฟล์ scenario ทั้ง 2 ฝั่ง
4. `rebuild_dataset.py` ใหม่ทั้งหมดจาก raw log เพื่อให้คอลัมน์ `session` เปลี่ยนตาม
5. ตัวเลขทุกตัวในเอกสารเดิม (`docs/*.md`, สไลด์) ที่อ้างชื่อ `botnet` ต้องแก้ตาม

**ต้นทุนสูง ผลได้เป็นศูนย์** — ชื่อตัวแปรในโค้ดไม่ได้ปรากฏในธีสิส
ใช้ตาราง map ในข้อ 5 ตอนเขียน/ทำสไลด์ก็เพียงพอ

---

## 7. ถ้าอยากตอบให้แข็งกว่านี้: เพิ่ม Zeek แล้วเทียบสามทาง

ดู `docs/zeek_fusion.md`

การเพิ่ม Zeek (network-based) เข้ามา **ไม่ใช่การยอมรับว่า botnet ไม่เข้าพวก**
แต่เปลี่ยนคำถามให้กลายเป็นคำถามวิจัย:

> **Host-based (Sysmon) vs Network-based (Zeek) vs Fused — ตัวไหนตรวจจับ C2 ได้ดีกว่ากัน**

และ botnet กลายเป็น scenario ที่ **จำเป็นต้องมี** เพราะเป็นตัวเดียวที่ทำให้
คำถามนี้มีความหมาย (scenario อื่นแทบไม่มี network flow ให้เทียบ)
