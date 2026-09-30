# Zeek Fusion — รวม network-based เข้ากับ host-based

> เพิ่มมุมมอง **network-based (Zeek)** เข้ามาคู่กับ **host-based (Sysmon)** ที่มีอยู่
> แล้ว **join เข้าด้วยกัน** เพื่อให้ทุก network flow มีเจ้าของเป็น process
>
> เอกสารคู่กัน: `docs/why_botnet_is_host_based.md`

---

## 1. ทำไมต้องมี

| | Sysmon EventID 3 | Zeek conn.log | Fused |
|---|---|---|---|
| process ที่เป็นเจ้าของ | ✅ `Image`, `ProcessGuid`, `User` | ❌ | ✅ |
| สายเลือด / label | ✅ lineage labeling | ❌ | ✅ |
| จำนวนไบต์ที่ส่ง/รับ | ❌ | ✅ `orig_bytes` `resp_bytes` | ✅ |
| ระยะเวลาของ flow | ❌ | ✅ `duration` | ✅ |
| โปรโตคอลชั้นบน | ❌ | ✅ `service`, `http.*`, `dns.*`, `ssl.*` | ✅ |
| ผลของการเชื่อมต่อ | ❌ (log ตอน "เริ่ม" เท่านั้น) | ✅ `conn_state` | ✅ |

**Sysmon บอกว่า "ใครเปิด socket" แต่ไม่บอกว่า "เกิดอะไรขึ้นในนั้น"**
Zeek บอกตรงกันข้าม — การรวมสองอย่างคือ contribution ของเฟสนี้

คำถามวิจัยที่ทำได้หลังมีของนี้:

> **Host-based vs Network-based vs Fused — ตัวไหนตรวจจับ C2 beaconing ได้ดีกว่ากัน**

---

## 2. สถาปัตยกรรม

```
                VM (target1 / wintarget)
                  |            |
        Sysmon ---+            +--- packets
          |                          |
          v                          v
   syslog / EVTX              VMware virtual switch
          |                          |
          v                     VMnet1 + VMnet8 (host adapter)
   host/logs*/                       |
          |                          v
          v                  host/pcap_capture.py  (dumpcap)
   parse -> enrich -> label          |
          |                          v
          |                   host/pcap/<session>.pcapng   <- raw #3
          |                          |
          |                          v
          |                   host/run_zeek.py   (zeek -C -r)
          |                          |
          |                          v
          |                   host/zeek/<session>/*.log
          |                          |
          |                          v
          |                   host/dataset/<session>_zeek.csv
          |                          |
          +-----------+--------------+
                      v
             host/fuse_network.py
                      |
        +-------------+--------------+
        v                            v
 <session>_fused_events.csv   <session>_netproc.csv
 (Sysmon ev3 + คอลัมน์ Zeek)   (สรุประดับ process = feature จริง)
```

### ทำไม capture บน host ไม่ใช่ใน VM

1. Zeek รันบน Windows ไม่ได้ และการลง agent ใน guest จะกลายเป็น noise ใน Sysmon เอง
2. `.pcapng` กลายเป็น **raw source of truth ตัวที่ 3** ต่อจาก `logs/` และ `logs_win/`
   → เปลี่ยนวิธีวิเคราะห์แล้วรันซ้ำได้ ไม่ต้องเก็บ VM ใหม่ (หลักการเดียวกับ `rebuild_dataset.py`)
3. ใช้โค้ดชุดเดียวได้ทั้ง Linux guest และ Windows guest
4. ไม่ต้องแก้ Vagrantfile / provision / snapshot เลย

### adapter ที่เก็บ

| adapter | subnet | ใช้ทำอะไร |
|---|---|---|
| **VMnet1** | `192.168.56.0/24` | host-only — beacon ไป `c2_server.py` (:8080/:4444), `mining_pool.py` (:3333) |
| **VMnet8** | `192.168.205.0/24` | NAT — `T1105` โหลดไฟล์ออกอินเทอร์เน็ต |

`dumpcap` เขียนทั้งสอง adapter ลง `.pcapng` ไฟล์เดียว (pcapng รองรับหลาย interface)

---

## 3. วิธีใช้

### ติดตั้งครั้งเดียว

```powershell
# 1. Wireshark + Npcap  (ตรวจแล้วว่ามีบนเครื่องนี้: C:\Program Files\Wireshark)
#    https://www.wireshark.org/download.html   <- ตอนติดตั้งต้องติ๊ก Npcap

# 2. Zeek — เลือกทางใดทางหนึ่ง
wsl --install Ubuntu
wsl -e bash -c "sudo apt update && sudo apt install -y zeek"
#    หรือ
#    เปิด Docker Desktop แล้ว  docker pull zeek/zeek:latest
#    (ต้องแชร์ไดรฟ์ S: ใน Settings > Resources > File sharing)

python host\run_zeek.py --check        # ต้องขึ้นชื่อ backend ถึงจะพร้อม
```

### เก็บข้อมูล

pcap เก็บ **อัตโนมัติ** เมื่อกดรันผ่าน Dashboard — `start_collectors()` เปิด `PcapCapture`
พร้อม `mining_pool` + `c2_server` และปิดให้ตอนจบ scenario

```powershell
python host\dashboard.py               # กดรัน scenario ตามปกติ
# ปิดการเก็บ pcap:  $env:PCAP = "0"
```

เก็บเองแบบแยก:

```powershell
python host\pcap_capture.py --list                      # ดู adapter
python host\pcap_capture.py --session mytest            # Ctrl-C เพื่อหยุด
```

### แปลงและ fuse

```powershell
python host\run_zeek.py --all                  # pcap -> zeek -> <session>_zeek.csv
python host\fuse_network.py --all              # join กับ Sysmon
python host\fuse_network.py --session X --window 10    # ถ้า match rate ต่ำ
```

---

## 4. การจับคู่ทำอย่างไร

join ด้วย **4-tuple + โปรโตคอล** แล้วเลือก flow ที่เวลาใกล้ที่สุดในหน้าต่างที่กำหนด

```
Sysmon : SourceIp:SourcePort -> DestinationIp:DestinationPort  (Protocol)  @ UtcTime
Zeek   : id.orig_h:id.orig_p -> id.resp_h:id.resp_p            (proto)     @ ts
```

### clock skew วัดเอง ไม่สมมติว่านาฬิกาตรงกัน

`UtcTime` มาจากนาฬิกาใน VM ส่วน `ts` ของ pcap มาจากนาฬิกา host — ไม่ตรงกันเสมอ

`estimate_offset()` เลือกเฉพาะ 4-tuple ที่ **ไม่กำกวม** (มี flow เดียวและ event เดียว)
ซึ่งจับคู่ได้แน่นอนโดยไม่ต้องใช้เวลาเลย แล้วเอา **median** ของผลต่างเป็น offset
จากนั้นค่อยจับคู่ที่เหลือโดยใช้ offset นั้น

รายงานออกมาทุกครั้งเพื่อให้ตรวจสอบได้ ไม่ใช่ค่าที่ซ่อนอยู่:

```
clock offset       : +7.290 s  (วัดจาก 395 คู่)
```

---

## 5. Feature ที่ได้เพิ่ม (`<session>_netproc.csv`)

ระดับ process — ตรงกับที่วัดแล้วว่าดีกว่า event-level (RF F1 0.959 vs 0.811)

| คอลัมน์ | ความหมาย | มาจาก |
|---|---|---|
| `flow_n` / `flow_matched` | จำนวน connection / ที่จับคู่กับ Zeek ได้ | Sysmon + Zeek |
| `dst_ip_n` / `dst_port_n` | ปลายทางที่ไม่ซ้ำ | Sysmon |
| `ext_dst_n` | ปลายทางนอกวงแล็บ (ไม่ใช่ `192.168.*`) | Sysmon |
| `bytes_sent` / `bytes_recv` | ปริมาณข้อมูล | **Zeek เท่านั้น** |
| `dur_total_s` / `dur_max_s` | ระยะเวลา flow | **Zeek เท่านั้น** |
| `svc_set` / `conn_state_set` | โปรโตคอลชั้นบน / ผลการเชื่อมต่อ | **Zeek เท่านั้น** |
| `dns_n` / `dns_qlen_max` / `dns_ent_max` | จำนวน query / ความยาว / entropy — จับ **DNS tunneling** | **Zeek เท่านั้น** |
| `http_n` / `http_ua_set` | จำนวน HTTP / user-agent | **Zeek เท่านั้น** |
| `ssl_n` / `ssl_sni_set` | จำนวน TLS / SNI (อ่านได้แม้ payload เข้ารหัส) | **Zeek เท่านั้น** |
| `beacon_n` / `beacon_mean_s` / `beacon_sd_s` / **`beacon_cv`** / `beacon_dst` | ความสม่ำเสมอของจังหวะ beacon | Sysmon timestamp |

### `beacon_cv` — ตัวที่น่าจะแรงที่สุด

`cv = stddev(ช่วงห่าง) / mean(ช่วงห่าง)` — **ยิ่งต่ำยิ่งเป็นจังหวะ = ยิ่งเหมือน C2**

⚠️ **ต้องวัดแยกตามปลายทาง** ไม่ใช่รวมทุก destination ของ process
process ที่คุยหลายปลายทางพร้อมกันจะได้ gap สลับไปมาจนดูไม่สม่ำเสมอ
ทั้งที่แต่ละช่องทางเป็นจังหวะเป๊ะ — `beacon_stats()` จึงรายงานช่องทางที่ CV ต่ำสุด
ที่มีอย่างน้อย 4 ครั้ง (`beacon_dst` บอกว่าเป็นช่องไหน)

วัดจริงจากข้อมูล `botnet_win` ที่มีอยู่ (ทดสอบท่อด้วย Zeek CSV สังเคราะห์):

| Image | label | `beacon_cv` |
|---|---|---|
| `powershell.exe` (beacon 30 รอบ, `Start-Sleep 2`) | 1 | **0.0079** |
| `powershell.exe` | 1 | **0.015** |
| `svchost.exe` | 0 | 1.05 – 1.90 |
| `System` | 0 | 1.33 |

แยกได้สองระดับความเข้ม **ก่อนแตะโมเดลเลย**

---

## 6. ⚠️ ข้อจำกัดที่ต้องเขียนลงธีสิส

| เรื่อง | ผลกระทบ | สถานะ |
|---|---|---|
| **HTTPS** | `T1105` โหลดจาก `raw.githubusercontent.com:443` → `http.log` ว่าง เหลือแค่ `ssl.log` + `conn.log` (ได้ SNI แต่ไม่ได้ URI) | ยอมรับ + รายงานตามจริง; C2 ในแล็บเป็น HTTP อ่านได้เต็ม |
| **NAT translation** | traffic ออกเน็ตถูก VMware NAT แปลง IP — ยังไม่ยืนยันว่า host adapter VMnet8 เห็น traffic ก่อนหรือหลังแปลง ถ้าเห็นหลังแปลง 4-tuple จะไม่ตรงกับที่ Sysmon เห็น | **ต้องทดสอบจริง** — วัดจาก match rate ของ flow ที่ปลายทางเป็น IP นอกวง |
| **checksum offload** | NIC ของ host ทำ checksum offload → packet มี checksum ผิด Zeek จะทิ้งเงียบ | แก้แล้ว: `run_zeek.py` ใส่ `-C` เสมอ |
| **หน่วยข้อมูลต่างกัน** | Zeek = flow-level, Sysmon = event-level | fuse ที่ **process-level** เท่านั้น |
| **leakage ตัวใหม่** | ถ้า benign แทบไม่มี network flow เลย `flow_n > 0` จะกลายเป็น feature รั่วทันที | **ต้องทำ benign ให้มี network activity พอกัน** — ดูข้อ 7 |
| **pcap ย้อนหลังไม่มี** | ข้อมูล 56,949 แถวที่เก็บไว้แล้วไม่มี pcap คู่ | ส่วน fusion ต้องเก็บรอบใหม่ทั้งหมด |

### 🚨 leakage ตัวใหม่ที่ต้องระวังที่สุด

โปรเจคนี้เคยเจอ `cmd_len` ที่ทำให้ RF F1 ตกจาก 0.9447 → 0.6100 เมื่อเอาออก
**`flow_n` / `bytes_sent` มีความเสี่ยงแบบเดียวกันเป๊ะ** ถ้า benign ไม่มี network activity

ก่อนอ้างตัวเลขใดๆ จาก netproc ต้องวัดคู่กันเสมอ:

```powershell
# benign กับ malicious มี network activity ต่างกันแค่ไหน
python host\fuse_network.py --all
# แล้วเทียบสัดส่วน process ที่มี flow_n > 0 ในสองคลาส - ต้องไม่ต่างกันมาก
```

---

## 7. สิ่งที่ยังต้องทำ

| # | งาน | สถานะ |
|---|---|---|
| 1 | ติดตั้ง Zeek (WSL Ubuntu หรือ Docker) | ❌ ยังไม่ได้ทำ — `run_zeek.py --check` แจ้งวิธี |
| 2 | เก็บ `botnet_win` 1 รอบพร้อม pcap แล้ววัด match rate จริง | ❌ รอข้อ 1 |
| 3 | ตรวจ NAT: flow ที่ออกเน็ตจับคู่ได้ไหม | ❌ รอข้อ 2 |
| 4 | เพิ่ม network activity ใน `benign.ps1` / `benign.sh` ให้สมมาตร | ❌ **จำเป็นก่อนใช้ feature เหล่านี้เทรน** |
| 5 | รวม `_netproc.csv` เข้า `merge_dataset.py` + `ml_train.py` | ❌ รอข้อ 2-4 |

### เกณฑ์ "ผ่าน" ของ PoC (ตั้งไว้ก่อนวัด เพื่อไม่ให้ตีความเข้าข้างตัวเอง)

1. `match rate ≥ 70%` สำหรับ traffic ในวงแล็บ (VMnet1)
2. `clock offset` เสถียร — วัดซ้ำสอง session แล้วต่างกันไม่เกิน 1 วินาที
3. `beacon_cv` ของ process ที่ beacon จริง **< 0.2** และของ `svchost` **> 0.5**
4. `orphan flows` อธิบายได้ว่าเป็น traffic ของ host เอง ไม่ใช่ของ guest ที่หลุด

---

## 8. สถานะโค้ด

| ไฟล์ | ทำอะไร | ทดสอบแล้ว |
|---|---|---|
| `host/pcap_capture.py` | dumpcap → `.pcapng` + meta + เตือนถ้าได้ 0 packet | ✅ เก็บจริงได้ 30 packets / 6 วินาที |
| `host/run_zeek.py` | auto-detect backend (native/wsl/docker) → Zeek → CSV | ⚠️ ตรวจ backend + ข้อความ error ทดสอบแล้ว; **ยังไม่เคยรัน Zeek จริง** |
| `host/fuse_network.py` | join 4-tuple + วัด clock offset + rollup ระดับ process | ✅ ทดสอบด้วย Zeek CSV สังเคราะห์: offset ที่ฝัง +7.25 วัดได้ +7.290, match 90.1% ตรงตามที่ตั้งใจ |
| `host/dashboard.py` | เปิด/ปิด pcap คู่กับ collector อื่น | ✅ syntax + เส้นทาง error |

`pcap_capture` ที่เปิดไม่ได้ **ไม่ทำให้รอบเก็บข้อมูลล้ม** — Sysmon ยังเก็บได้ปกติ
แต่พิมพ์เตือนดังใน log ว่ารอบนั้นจะไม่มีข้อมูล Zeek (ตั้ง `PCAP=0` ถ้าตั้งใจ)
