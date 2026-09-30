from pathlib import Path
import csv, hashlib, json, re, zipfile
from lxml import etree as E
from pypdf import PdfReader
from standalone_content import CONTENT, REFERENCE_ORDER, THAI_TITLE, ENGLISH_TITLE

ROOT = Path('S:/Jr.Project(Real)/sysmon-lab')
WORK = ROOT / 'tmp/paper_nccy_review/standalone'
OUT = ROOT / 'docs/paper_draft_NCCY_v4_standalone.docx'
TEMPLATE = Path('C:/Users/bbcor/Downloads/template_NCCY_full_thai.docx')
SOURCE = ROOT / 'docs/paper_draft_NCCY_v2.docx'
W = 'http://schemas.openxmlformats.org/wordprocessingml/2006/main'
NS = {'w': W, 'wp': 'http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing'}
q = lambda name: f'{{{W}}}{name}'
text = lambda node: ''.join(node.xpath('.//w:t/text()', namespaces=NS))

with zipfile.ZipFile(OUT) as z:
    final_parts = {n: z.read(n) for n in z.namelist()}
with zipfile.ZipFile(TEMPLATE) as z:
    template_parts = {n: z.read(n) for n in z.namelist()}
with zipfile.ZipFile(SOURCE) as z:
    original = E.fromstring(z.read('word/document.xml'))
root = E.fromstring(final_parts['word/document.xml'])
body = root.find(q('body'))
paras = body.findall(q('p'))
visible = '\n'.join(text(p) for p in paras)
captions = {item[2] for item in CONTENT if item[0] in ('table', 'figure')}

for path, name in [(TEMPLATE, 'template_evidence.json'), (SOURCE, 'draft_evidence.json')]:
    expected = json.loads((ROOT / 'tmp/paper_nccy_review' / name).read_text(encoding='utf-8'))['sha256']
    assert hashlib.sha256(path.read_bytes()).hexdigest() == expected
modified = {'word/document.xml', 'word/_rels/document.xml.rels', '[Content_Types].xml'}
modified.update(n for n in template_parts if re.fullmatch(r'word/header\d+\.xml', n))
preserved = [n for n in template_parts if n not in modified]
assert all(final_parts[n] == template_parts[n] for n in preserved)

for forbidden in ['Achmad', 'Nariswari', 'NLME', '100110', '0.8868', '0.8799', 'GroupKFold']:
    assert forbidden.lower() not in visible.lower(), forbidden
assert 1 not in REFERENCE_ORDER
refs = [p for p in paras if re.match(r'^\[\d+\]', text(p))]
assert [int(re.match(r'^\[(\d+)\]', text(p)).group(1)) for p in refs] == list(range(1, 19))
source_refs = {}
for p in original.findall('w:body/w:p', NS):
    match = re.match(r'^\[(\d+)\]\s*(.*)', text(p).strip())
    if match:
        source_refs[int(match[1])] = match[2]
for i, (p, oldno) in enumerate(zip(refs, REFERENCE_ORDER), 1):
    assert text(p) == f'[{i}] ' + source_refs[oldno]
first_appearance = []
for p in paras:
    if p in refs:
        continue
    for number in re.findall(r'\[(\d+)\]', text(p)):
        n = int(number)
        if n not in first_appearance:
            first_appearance.append(n)
assert first_appearance == list(range(1, 19)), first_appearance

def prop(p, name):
    return p.find('w:pPr/w:' + name, NS)

for p in paras:
    value = text(p)
    if not value:
        continue
    if value.replace('\n', '') in (THAI_TITLE.replace('\n', ''), ENGLISH_TITLE.replace('\n', '')):
        assert prop(p, 'jc').get(q('val')) == 'center'
        expected_size = '40'
        assert all(r.find('w:rPr/w:b', NS) is not None for r in p.findall(q('r')))
    elif value in ('บทคัดย่อ', 'ABSTRACT', 'เอกสารอ้างอิง') or re.match(r'^\d+\.\s', value):
        assert prop(p, 'jc').get(q('val')) == 'center'
        expected_size = '28'
    elif re.match(r'^\d+\.\d+\s', value):
        assert prop(p, 'jc').get(q('val')) == 'left'
        expected_size = '28'
        assert all(r.find('w:rPr/w:i', NS) is not None for r in p.findall(q('r')))
    elif value in captions:
        expected_size = '24'
    else:
        expected_size = '28'
    for run in p.findall(q('r')):
        if run.find(q('t')) is None:
            continue
        rp = run.find(q('rPr'))
        assert rp.find(q('sz')).get(q('val')) == expected_size, value[:40]
        assert rp.find(q('szCs')).get(q('val')) == expected_size
        assert rp.find(q('rFonts')).get(q('ascii')) == 'TH SarabunPSK'
        assert rp.find(q('color')).get(q('val')) == '000000'

table_xml = body.findall(q('tbl'))
assert len(table_xml) == 7
assert len(root.xpath('//wp:inline', namespaces=NS)) == 2
tables = json.loads((WORK / 'tables.json').read_text(encoding='utf-8'))
for number, tbl in enumerate(table_xml, 1):
    assert int(tbl.find('w:tblPr/w:tblW', NS).get(q('w'))) <= 4649
    assert [[text(cell) for cell in row.findall(q('tc'))] for row in tbl.findall(q('tr'))] == tables[str(number)]
    assert tbl.find('w:tr/w:trPr/w:tblHeader', NS) is not None
    for row in tbl.findall(q('tr')):
        assert row.find('w:trPr/w:cantSplit', NS) is not None
    for size in tbl.xpath('.//w:rPr/w:sz|.//w:rPr/w:szCs', namespaces=NS):
        assert size.get(q('val')) == '24'
assert [int(re.match(r'^ตาราง (\d+)', text(p)).group(1)) for p in paras if text(p) in captions and text(p).startswith('ตาราง ')] == list(range(1, 8))
assert [int(re.match(r'^ภาพ (\d+)', text(p)).group(1)) for p in paras if text(p) in captions and text(p).startswith('ภาพ ')] == [1, 2]

with (ROOT / 'reference/ml_results.csv').open(encoding='utf-8-sig', newline='') as f:
    scores = {r['Algorithm']: r for r in csv.DictReader(f)}
for row in tables['4'][1:8]:
    recorded = scores[row[0]]
    assert row[1:] == [f'{float(recorded[k]):.3f}' for k in ('Accuracy', 'Precision', 'Recall', 'F1', 'AUC')]

pdf = WORK / 'iteration3/paper_draft_NCCY_v4_standalone/paper_draft_NCCY_v4_standalone.pdf'
pages = PdfReader(pdf).pages
assert len(pages) == 9
for page in pages:
    extracted = page.extract_text()
    assert 'National Conference on Computing and Cybersecurity' in extracted
    assert '202X' not in extracted
    assert '\ufffd' not in extracted
    assert float(page.mediabox.width) > 590 and float(page.mediabox.height) > 840
assert len(list((WORK / 'iteration3/render').glob('page-*.png'))) == 9

report = {
    'output': str(OUT), 'sha256': hashlib.sha256(OUT.read_bytes()).hexdigest(),
    'pages': 9, 'tables': 7, 'figures': 2, 'references': 18,
    'reference_first_appearance': first_appearance,
    'unrelated_template_parts_preserved': len(preserved),
    'source_and_template_preserved': True,
    'baseline_paper_citations_and_comparisons_removed': True,
    'main_metrics_match_recorded_csv': True,
    'titles_and_major_headings_centered': True,
    'header_present_on_every_page': True,
    'render_directory': str(WORK / 'iteration3/render')
}
(WORK / 'final_validation.json').write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
print(json.dumps(report, ensure_ascii=True))
