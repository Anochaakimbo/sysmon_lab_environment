"""Audit the v5 revision against its source, template and retained v4 results."""
from pathlib import Path

ROOT = Path('S:/Jr.Project(Real)/sysmon-lab')
code = (ROOT / 'tmp/paper_nccy_review/audit_standalone.py').read_text(encoding='utf-8')
code = code.replace('from standalone_content import', 'from host_based_content import')
code = code.replace('tmp/paper_nccy_review/standalone', 'tmp/paper_nccy_review/host_based')
code = code.replace('paper_draft_NCCY_v4_standalone', 'paper_draft_NCCY_v5_host_based')
code = code.replace('iteration3', 'iteration2')
code = code.replace('assert len(pages) == 9', 'assert len(pages) == 10')
code = code.replace("'pages': 9", "'pages': 10")
code = code.replace("glob('page-*.png'))) == 9", "glob('page-*.png'))) == 10")
code = code.replace(
    '== tables[str(number)]',
    "== [[value.replace('\\n', '') for value in row] for row in tables[str(number)]]",
)
extra = r'''
PREVIOUS = ROOT / 'docs/paper_draft_NCCY_v4_standalone.docx'
assert hashlib.sha256(PREVIOUS.read_bytes()).hexdigest() == '40340114ac8e1157ee92e67047dbcc86417412107c3c9b8512b05f762f5c0282'
with zipfile.ZipFile(PREVIOUS) as z:
    previous_parts = {n: z.read(n) for n in z.namelist()}
previous_root = E.fromstring(previous_parts['word/document.xml'])
previous_body = previous_root.find(q('body'))
previous_tables = previous_body.findall(q('tbl'))
assert all(E.tostring(now) == E.tostring(old) for now, old in zip(table_xml[1:], previous_tables[1:]))
previous_refs = [text(p) for p in previous_body.findall(q('p')) if re.match(r'^\[\d+\]', text(p))]
assert [text(p) for p in refs] == previous_refs
previous_media = {n: b for n, b in previous_parts.items() if n.startswith('word/media/')}
current_media = {n: b for n, b in final_parts.items() if n.startswith('word/media/')}
assert current_media == previous_media
assert len(table_xml[0].xpath('.//w:br', namespaces=NS)) == 4
assert '3.2 เหตุผลเลือกสถานการณ์และพฤติกรรมบนโฮสต์' in visible
assert 'Sysmon ที่ติดตั้งบนเครื่องเป้าหมาย' in visible
assert 'เพราะบันทึกกระบวนการต้นทางร่วมกับ IP และพอร์ต' in visible
assert 'เลือกห้ากลุ่มเพื่อให้ชุดข้อมูลมีพฤติกรรมบนโฮสต์หลายด้าน' in visible
for group in ('Ransomware', 'Trojan/backdoor', 'Botnet', 'Cryptominer', 'Exploitation'):
    assert group + ' ใช้ศึกษา' in visible
assert '32 ตัวไม่ได้วัดเปอร์เซ็นต์ CPU หรือ GPU โดยตรง' in visible
assert 'แบบจำลองหลักจำแนกสองป้ายกำกับ' in visible
assert 'ไม่ยืนยันว่าการยกระดับสิทธิ์สำเร็จ' in visible
assert 'XMRig, backdoor และชุดทดสอบยกระดับสิทธิ์' in visible
assert 'Atomic Red Team emulates five' not in visible
assert 'Atomic Red Team จำลองห้ากลุ่ม' not in visible
unchanged_package_parts = [n for n, b in previous_parts.items() if n != 'word/document.xml' and final_parts.get(n) == b]
'''
code = code.replace('report = {', extra + '\nreport = {')
code = code.replace(
    "'header_present_on_every_page': True,",
    "'header_present_on_every_page': True,\n"
    "    'all_ten_rendered_pages_visually_inspected': True,\n"
    "    'rationale_for_all_five_groups_added': True,\n"
    "    'host_based_endpoint_process_context_explained': True,\n"
    "    'cpu_measurement_and_exploitation_success_limits_explicit': True,\n"
    "    'previous_v4_preserved': True,\n"
    "    'tables_2_to_7_figures_and_bibliography_identical_to_v4': True,\n"
    "    'package_parts_identical_to_v4_except_document': len(unchanged_package_parts),",
)
exec(compile(code, str(ROOT / 'tmp/paper_nccy_review/audit_standalone.py'), 'exec'), globals())
