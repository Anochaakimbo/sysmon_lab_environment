"""Add scenario rationale and endpoint observability to the retained v4 narrative."""
from standalone_content import (
    CONTENT as PREVIOUS_CONTENT, REFERENCE_ORDER, THAI_TITLE, ENGLISH_TITLE, FEATURES,
)

HOST_BASED = 'งานนี้วิเคราะห์พฤติกรรมแบบ host-based คือเก็บเหตุการณ์จาก Sysmon ที่ติดตั้งบนเครื่องเป้าหมาย แล้วเชื่อมกิจกรรมกับกระบวนการบนเครื่องนั้น EventID 1 ให้ข้อมูลการเริ่มกระบวนการและคำสั่ง EventID 11 และ 23 ให้ร่องรอยการสร้างหรือเขียนทับไฟล์และการลบไฟล์ ส่วน EventID 12 และ 13 ให้กิจกรรม registry บน Windows แม้ EventID 3 เป็นการเชื่อมต่อเครือข่าย ก็ยังเป็นข้อมูลจากโฮสต์ เพราะบันทึกกระบวนการต้นทางร่วมกับ IP และพอร์ต [1] จึงศึกษาการติดต่อเครือข่ายร่วมกับกิจกรรมของโปรแกรมบนเครื่องได้'

SCENARIO_PROSE = [
    'เลือกห้ากลุ่มเพื่อให้ชุดข้อมูลมีพฤติกรรมบนโฮสต์หลายด้านที่บันทึก Sysmon สังเกตได้ ได้แก่ ผลกระทบต่อไฟล์ การคงอยู่ในระบบ การสื่อสารกับผู้ควบคุม บริบทการใช้ทรัพยากร และการยกระดับสิทธิ์ อีกทั้งสามารถจัดกิจกรรมที่มีวัตถุประสงค์ใกล้กันบน Linux และ Windows โดยอิงเทคนิค MITRE ATT&CK [4] และชุดทดสอบ Atomic Red Team [5] การเลือกนี้กำหนดขอบเขตการทดลองเชิงพฤติกรรม ไม่ได้อ้างว่าห้ากลุ่มเป็นมัลแวร์ที่พบบ่อยที่สุดหรือครอบคลุมภัยคุกคามทั้งหมด',
    'Ransomware ใช้ศึกษากิจกรรมที่กระทบไฟล์จำนวนมาก สคริปต์สร้างไฟล์เป้าหมาย เรียกชุดทดสอบเข้ารหัส และสร้างหรือลบไฟล์ในพื้นที่ทดลอง ร่องรอยที่ศึกษาได้คือกระบวนการที่เรียกเครื่องมือ จำนวนไฟล์ที่เกี่ยวข้อง และสัดส่วน FileCreate กับ FileDelete สัญญาณเหล่านี้สะท้อนกิจกรรมไฟล์ แต่บันทึกดังกล่าวเพียงอย่างเดียวไม่ได้ยืนยันว่าเนื้อหาทุกไฟล์ถูกเข้ารหัส',
    'Trojan/backdoor ใช้ศึกษาการรันคำสั่งและการคงอยู่บนเครื่อง ฝั่ง Linux มีการวาง backdoor เรียก shell และตั้งค่า cron กับ systemd ส่วน Windows ใช้ชุดทดสอบ PowerShell, Registry Run Keys และ Scheduled Task จึงศึกษาการสร้างกระบวนการ ไฟล์ที่ถูกวาง และกิจกรรม registry ของ Windows ได้ กลุ่มนี้เน้นพฤติกรรมหลังเริ่มทำงาน โดยไม่ได้ทดสอบการหลอกให้ผู้ใช้เปิดโปรแกรมซึ่งเป็นอีกด้านหนึ่งของ Trojan',
    'Botnet ใช้ศึกษาการสื่อสารกับเซิร์ฟเวอร์ Command-and-Control ภายในแล็บ สคริปต์ติดต่อ HTTP/TCP ซ้ำและเตรียมข้อมูลสำหรับส่งออก EventID 3 เชื่อมการติดต่อกับกระบวนการต้นทาง จึงนำจำนวนและสัดส่วน NetworkConnect กับจำนวน IP และพอร์ตปลายทางที่ต่างกันมาศึกษาได้ การวิเคราะห์แบบ host-based ในกรณีนี้จึงอาศัยบริบทของโปรแกรมที่ติดต่อเครือข่าย ไม่ได้ยืนยันจากพอร์ตเพียงค่าเดียวว่าเป็น botnet',
    'Cryptominer ใช้ศึกษาบริบทการใช้เครื่องเพื่อประมวลผลงานขุด ฝั่ง Linux รัน XMRig กับ pool ภายในแล็บ ส่วน Windows สร้างงานคำนวณและเชื่อมต่อ pool จำลอง ร่องรอยที่คุณลักษณะปัจจุบันใช้ได้คือการเริ่มและจบกระบวนการ ช่วงเวลาที่สังเกต และการติดต่อปลายทาง ชุดข้อมูลและคุณลักษณะ 32 ตัวไม่ได้วัดเปอร์เซ็นต์ CPU หรือ GPU โดยตรง จึงยังไม่รองรับข้อสรุปว่าโมเดลตรวจการใช้ CPU สูงหรือยืนยันการขุดได้จาก Sysmon เพียงอย่างเดียว',
    'Exploitation ใช้ศึกษาการยกระดับสิทธิ์และกิจกรรมหลังความพยายามโจมตี ฝั่ง Linux มีชุดทดสอบช่องโหว่และการรันโปรแกรมหลังยกระดับสิทธิ์ ส่วน Windows ทดสอบ UAC bypass, token manipulation และ process injection ร่องรอยที่ศึกษาได้ประกอบด้วยการสร้างกระบวนการ คำสั่ง ไฟล์ และกิจกรรม registry ที่รองรับ อย่างไรก็ตาม การมีเหตุการณ์เหล่านี้ไม่ยืนยันว่าการยกระดับสิทธิ์สำเร็จ และขอบเขตข้อมูล CreateRemoteThread ยังจำกัดตามหัวข้อ 4.5 ชื่อ exploitation เป็นกลุ่มเทคนิคโจมตี ไม่ใช่ตระกูลมัลแวร์',
]

SCENARIOS = [
    ['สถานการณ์', 'ด้านที่ศึกษา', 'EventID ที่เกี่ยวข้อง'],
    ['Benign', 'กิจกรรมผู้ใช้ปกติ', '1, 3, 5, 11, 23'],
    ['Ransomware', 'ผลกระทบต่อไฟล์', '1, 11, 23'],
    ['Trojan/backdoor', 'รันคำสั่ง\nคงอยู่ในระบบ', '1, 3, 11, 23\n12, 13 (Windows)'],
    ['Botnet', 'การสื่อสาร C2', '1, 3, 11'],
    ['Cryptominer', 'บริบทงานขุด\nการติดต่อ pool', '1, 3, 5, 11'],
    ['Exploitation', 'สิทธิ์และรันโค้ด', '1, 11\n8, 12, 13 (Windows)'],
]

CONTENT = []
for item in PREVIOUS_CONTENT:
    role = item[0]
    value = item[1]
    if role == 'body' and value.startswith('บทความนี้นำเสนอ'):
        value = value.replace('การทดลองใช้ Atomic Red Team จำลองห้ากลุ่มสถานการณ์โจมตีร่วมกับพฤติกรรมปกติ', 'การทดลองใช้ Atomic Red Team ร่วมกับโปรแกรมทดลองสร้างห้ากลุ่มสถานการณ์โจมตีและพฤติกรรมปกติ')
    elif role == 'body_en' and value.startswith('This paper presents'):
        value = value.replace('Atomic Red Team emulates five attack scenario categories alongside benign activity.', 'Atomic Red Team and controlled executable workloads generate five attack scenario categories alongside benign activity.')
    elif role == 'body' and value.startswith('งานวิจัยนี้ตั้งโจทย์'):
        value = value.replace('และใช้ Atomic Red Team [5] ภายใต้แล็บ', 'และใช้ Atomic Red Team [5] ร่วมกับโปรแกรมทดลองภายใต้แล็บ')
    elif role == 'subheading' and value.startswith('3.2 '):
        value = '3.2 เหตุผลเลือกสถานการณ์และพฤติกรรมบนโฮสต์'
    elif role == 'body' and value.startswith('แต่ละแพลตฟอร์มมีพฤติกรรมปกติ'):
        CONTENT.append(('body', 'แต่ละแพลตฟอร์มมีพฤติกรรมปกติและห้ากลุ่มสถานการณ์โจมตี ได้แก่ ransomware, trojan/backdoor, botnet, cryptominer และ exploitation ฝั่ง Linux ใช้ทั้ง Atomic Red Team และโปรแกรมทดลอง ได้แก่ XMRig, backdoor และชุดทดสอบยกระดับสิทธิ์ ส่วน Windows ใช้ Atomic Red Team ร่วมกับกิจกรรมไฟล์ งานคำนวณ และการติดต่อเครือข่ายในแล็บ เซิร์ฟเวอร์ C2 และ pool อยู่ภายในสภาพแวดล้อมทดลอง ชื่อกลุ่มเหล่านี้ใช้จัดสถานการณ์และไม่ได้ระบุว่ามีตัวอย่างมัลแวร์จากธรรมชาติห้าตระกูล'))
        CONTENT.extend(('body', paragraph) for paragraph in SCENARIO_PROSE)
        continue
    elif role == 'table' and item[1] == 1:
        CONTENT.append(('table', 1, 'ตาราง 1 ด้านพฤติกรรมและเหตุการณ์บนโฮสต์ที่ใช้ศึกษาสถานการณ์'))
        CONTENT.append(('body', 'ตาราง 1 สรุปเหตุการณ์ที่เกี่ยวข้องตามชนิดที่รองรับและการตั้งค่าการเก็บบันทึก [1] พฤติกรรมแต่ละกลุ่มอาจซ้อนทับกัน เช่น Trojan และ Botnet อาจติดต่อ C2 หรือมีการคงอยู่ในระบบเช่นเดียวกัน กลุ่มทั้งห้าจึงเป็นบริบทการสร้างและประเมินข้อมูล ส่วนแบบจำลองหลักจำแนกสองป้ายกำกับ คือกิจกรรมปกติและกิจกรรมที่เชื่อมโยงกับสถานการณ์โจมตี การมี EventID ใดรายการหนึ่งยังไม่เพียงพอที่จะระบุประเภทมัลแวร์'))
        continue
    CONTENT.append((role, value) if role not in ('table', 'figure') else item)
    if role == 'body' and value.startswith('การตรวจจับมัลแวร์เชิงพฤติกรรม'):
        CONTENT.append(('body', HOST_BASED))

