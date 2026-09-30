from pathlib import Path
from collections import Counter
from zipfile import ZipFile
from lxml import etree as E
import re, json, hashlib
from pypdf import PdfReader

ROOT=Path('S:/Jr.Project(Real)/sysmon-lab')
TMP=ROOT/'tmp/paper_nccy_review'
original=ROOT/'docs/paper_draft_NCCY_v2.docx'
final=ROOT/'docs/paper_draft_NCCY_v3_formatted.docx'
template=Path('C:/Users/bbcor/Downloads/template_NCCY_full_thai.docx')
review=ROOT/'docs/paper_draft_NCCY_v3_review_th.md'
NS={'w':'http://schemas.openxmlformats.org/wordprocessingml/2006/main',
    'a':'http://schemas.openxmlformats.org/drawingml/2006/main'}
W=NS['w']; q=lambda n:f'{{{W}}}{n}'
def plain(e):return ''.join(e.xpath('.//w:t/text()',namespaces=NS))
def normalized(e):return re.sub(r'\s+','',plain(e))
def tree(path):
    with ZipFile(path) as z:return E.fromstring(z.read('word/document.xml'))
old=tree(original); new=tree(final); ref=tree(template)
op=old.find(q('body')).findall(q('p')); np=new.find(q('body')).findall(q('p'))
assert ''.join(normalized(p) for p in op[:4])==''.join(normalized(p) for p in np[:2]),'titles changed'
assert Counter(normalized(p) for p in op[4:] if plain(p).strip())==Counter(normalized(p) for p in np[2:] if plain(p).strip()),'scientific body changed'
ot=old.xpath('//w:body/w:tbl',namespaces=NS); nt=new.xpath('//w:body/w:tbl',namespaces=NS)
assert len(ot)==len(nt)==8
for i,(a,b) in enumerate(zip(ot,nt),1):
    assert [normalized(c) for c in a.xpath('.//w:tc',namespaces=NS)]==[normalized(c) for c in b.xpath('.//w:tc',namespaces=NS)],f'table {i} values changed'
    assert b.find('w:tblPr/w:tblW',NS).get(q('w'))==str(sum(int(c.get(q('w'))) for c in b.find(q('tblGrid'))))
    assert sum(int(c.get(q('w'))) for c in b.find(q('tblGrid')))<=4649
    for row in b.findall(q('tr')):assert row.find('w:trPr/w:cantSplit',NS) is not None
    for rp in b.xpath('.//w:rPr',namespaces=NS):
        assert rp.find(q('sz')).get(q('val'))=='24'
        assert rp.find(q('szCs')).get(q('val'))=='24'
headings=[]; subheadings=[]; captions=[]
for i,p in enumerate(np):
    s=plain(p).strip()
    if not s:continue
    pp=p.find(q('pPr')); sizes=[r.get(q('val')) for r in p.xpath('.//w:rPr/w:sz',namespaces=NS)]
    if i<2:
        assert pp.find(q('jc')).get(q('val'))=='center' and set(sizes)=={'40'}
    elif s in ('บทคัดย่อ','ABSTRACT','เอกสารอ้างอิง') or re.match(r'^\d+\.\s',s):
        assert pp.find(q('jc')).get(q('val'))=='center' and set(sizes)=={'28'}
        headings.append(s)
    elif re.match(r'^\d+\.\d+\s',s):
        assert pp.find(q('jc')).get(q('val'))=='left' and set(sizes)=={'28'}
        assert all(r.find(q('b')) is not None and r.find(q('i')) is not None for r in p.xpath('.//w:rPr',namespaces=NS))
        subheadings.append(s)
    elif re.match(r'^(ตาราง|ภาพ) \d+ ',s) and len(s)<160:
        # Captions are determined by adjacency in the authoring script; short source labels verified here.
        assert set(sizes)=={'24'},s
        captions.append(s)
    else:
        assert set(sizes)=={'28'},'wrong body size: '+s[:80]
assert len(captions)==12
assert len(new.xpath('//a:blip',namespaces=NS))==4
with ZipFile(original) as o,ZipFile(final) as n:
    original_images=[o.read(k) for k in o.namelist() if k.startswith('word/media/')]
    retained_images=[n.read(k) for k in n.namelist() if k.startswith('word/media/nccy_source_')]
    assert Counter(hashlib.sha256(x).hexdigest() for x in original_images)==Counter(hashlib.sha256(x).hexdigest() for x in retained_images)
    page_fields=[]
    for part in n.namelist():
        if re.match(r'word/(header|footer)\d+\.xml',part):
            e=E.fromstring(n.read(part))
            page_fields+=e.xpath('//w:instrText[contains(text(),"PAGE")]',namespaces=NS)
    assert not page_fields
for path,evidence in [(original,'draft_evidence.json'),(template,'template_evidence.json')]:
    assert hashlib.sha256(path.read_bytes()).hexdigest()==json.loads((TMP/evidence).read_text(encoding='utf-8'))['sha256']
for s in new.xpath('//w:sectPr',namespaces=NS):
    assert s.find(q('pgSz')).get(q('w'))=='11907'
    assert s.find(q('pgSz')).get(q('h'))=='16840'
    margins=s.find(q('pgMar'))
    assert margins.get(q('left')) in ('1134','1797') and margins.get(q('right'))==margins.get(q('left'))
    assert margins.get(q('top'))=='1701' and margins.get(q('bottom'))=='1418'
pdf=PdfReader(TMP/'iteration7/paper_draft_NCCY_v3_formatted/paper_draft_NCCY_v3_formatted.pdf')
assert len(pdf.pages)==10
assert all('National Conference on Computing and Cybersecurity (NCCY)' in p.extract_text() for p in pdf.pages)
assert not any('\ufffd' in p.extract_text() for p in pdf.pages)
for target in re.findall(r'\]\(<([^>]+)>\)',review.read_text(encoding='utf-8')):
    path,sep,line=target.rpartition(':')
    if not line.isdigit():path=target;line=None
    assert Path(path).is_file(),target
    if line:assert int(line)<=len(Path(path).read_text(encoding='utf-8').splitlines()),target
result={'pages':10,'tables':8,'figures':4,'captions':len(captions),'headings':headings,
        'subheading_count':len(subheadings),'source_files_unchanged':True,
        'scientific_text_preserved':True,'table_values_preserved':True,'image_bytes_preserved':True,
        'template_geometry_verified':True,'fonts_and_alignment_verified':True,'review_local_links_valid':True}
(TMP/'final_validation.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
print(json.dumps({k:v for k,v in result.items() if k!='headings'},indent=2))
