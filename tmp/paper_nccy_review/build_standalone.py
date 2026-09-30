from pathlib import Path
import csv, math, json, re, zipfile, hashlib, subprocess
from copy import deepcopy
from lxml import etree as E
from reportlab.pdfgen import canvas
from reportlab.lib.colors import Color, black, white
from PIL import Image
from standalone_content import CONTENT, REFERENCE_ORDER, THAI_TITLE, ENGLISH_TITLE, SCENARIOS, FEATURES

ROOT=Path('S:/Jr.Project(Real)/sysmon-lab')
WORK=ROOT/'tmp/paper_nccy_review/standalone'
WORK.mkdir(exist_ok=True)
base=(ROOT/'tmp/paper_nccy_review/format_manuscript.py').read_text(encoding='utf-8')
# Reuse only the established template roles and table component, never execute v3 authoring.
exec(base[:base.index('srcbody=')],globals())
exec(base[base.index('table_widths='):base.index('fig_number=')],globals())
OUTPUT=ROOT/'docs/paper_draft_NCCY_v4_standalone.docx'
table_widths=[[26,10,46],[22,48,12],[18,16,16,16,16],[27,11,11,11,11,11],[31,16,16,19],[45,18.5,18.5],[8,41,19,14]]

with (ROOT/'reference/ml_results.csv').open(encoding='utf-8-sig',newline='') as f:
    scores=list(csv.DictReader(f))
with (ROOT/'reference/ml_loso.csv').open(encoding='utf-8-sig',newline='') as f:
    loso=list(csv.DictReader(f))
with (ROOT/'reference/bench_event.csv').open(encoding='utf-8-sig',newline='') as f:
    bench=list(csv.DictReader(f))
order=['Random Forest','Decision Tree','SVM','Naive Bayes','Local Outlier Factor','Isolation Forest','One-Class SVM']
score_map={row['Algorithm']:row for row in scores}

def render_figure(pdf,name):
    subprocess.run(['pdftoppm','-singlefile','-r','240','-png',str(pdf),str(WORK/name)],check=True,capture_output=True)
    return WORK/f'{name}.png'

def flow_chart():
    pdf=WORK/'flow.pdf';c=canvas.Canvas(str(pdf),pagesize=(480,284))
    lines=[
        ('Collect Sysmon logs','Linux and Windows; six scenarios per platform'),
        ('Parse, enrich and label','Process lineage in attack sessions'),
        ('Aggregate by ProcessGuid','23,971 vectors under the current grouping rules'),
        ('Split the main process holdout','Train 16,779; test 7,192; seed 0'),
        ('Prepare 32 retained features','Drop three features; fit StandardScaler on outer train'),
        ('Fit the seven models','Supervised models and benign-only anomaly detectors'),
        ('Evaluate held-out processes','Accuracy, Precision, Recall, F1 and ROC-AUC'),
    ]
    for i,(title,detail) in enumerate(lines):
        y=246-i*38
        c.setFillColor(Color(.97,.97,.97));c.setStrokeColor(black);c.setLineWidth(.7)
        c.roundRect(36,y,408,30,3,stroke=1,fill=1)
        c.setFillColor(black);c.setFont('Helvetica-Bold',10);c.drawCentredString(240,y+18,title)
        c.setFont('Helvetica',9);c.drawCentredString(240,y+6,detail)
        if i<6:
            c.line(240,y,240,y-8)
            p=c.beginPath();p.moveTo(237,y-5);p.lineTo(240,y-8);p.lineTo(243,y-5);c.drawPath(p,stroke=1)
    c.save();return render_figure(pdf,'flow')

def metric_chart():
    pdf=WORK/'metrics.pdf';c=canvas.Canvas(str(pdf),pagesize=(500,256))
    left,bottom,width,height=45,44,440,170
    c.setFillColor(black);c.setFont('Helvetica-Bold',11)
    c.drawCentredString(265,239,'Precision, Recall and F1 on the main process holdout')
    for tick in range(6):
        y=bottom+height*tick/5
        c.setStrokeColor(Color(.84,.84,.84));c.setLineWidth(.4);c.line(left,y,left+width,y)
        c.setFillColor(black);c.setFont('Helvetica',9);c.drawRightString(left-7,y-3,f'{tick/5:.1f}')
    shades=[Color(.15,.15,.15),Color(.48,.48,.48),Color(.76,.76,.76)]
    short=['RF','DT','SVM','NB','LOF','IF','OCSVM']
    metrics=['Precision','Recall','F1']
    group=width/7;bar=12
    for i,name in enumerate(order):
        start=left+i*group+12
        for j,key in enumerate(metrics):
            value=float(score_map[name][key]);c.setFillColor(shades[j]);c.setStrokeColor(black);c.setLineWidth(.25)
            c.rect(start+j*(bar+1),bottom,bar,height*value,fill=1,stroke=1)
        c.setFillColor(black);c.setFont('Helvetica',9);c.drawCentredString(left+(i+.5)*group,bottom-15,short[i])
    c.setStrokeColor(black);c.setLineWidth(.65);c.line(left,bottom,left,bottom+height);c.line(left,bottom,left+width,bottom)
    for j,key in enumerate(metrics):
        x=120+j*110;c.setFillColor(shades[j]);c.rect(x,10,10,8,stroke=0,fill=1)
        c.setFillColor(black);c.setFont('Helvetica',9);c.drawString(x+15,10,key)
    c.save();return render_figure(pdf,'metrics')

figures={1:flow_chart(),2:metric_chart()}
tables={1:SCENARIOS,2:FEATURES,
    3:[['แพลตฟอร์ม','ปกติ','อันตราย','รวม','%อันตราย'],['Linux','29,805','15,506','45,311','34.2%'],['Windows','24,027','11,993','36,020','33.3%'],['รวม','53,832','27,499','81,331','33.8%']]}
tables[4]=[['แบบจำลอง','Acc','Prec','Rec','F1','AUC']]
for name in order:
    row=score_map[name]
    tables[4].append([name]+[f'{float(row[key]):.3f}' for key in ('Accuracy','Precision','Recall','F1','AUC')])
row=next(r for r in scores if r['Algorithm'].startswith('[baseline]'))
tables[4].append(['แจ้งเตือนทุกแถว']+[f'{float(row[key]):.3f}' for key in ('Accuracy','Precision','Recall','F1')]+['-'])
tables[5]=[['แบบจำลอง','F1 เฉลี่ย','AUC เฉลี่ย','ชนะเส้นฐาน']]
base_by_group={r['HeldOut']:float(r['F1']) for r in loso if r['Algorithm'].startswith('[baseline]')}
for name in ('Random Forest','Local Outlier Factor','Decision Tree'):
    rows=[r for r in loso if r['Algorithm']==name]
    tables[5].append([name,f'{sum(float(r["F1"]) for r in rows)/len(rows):.3f}',f'{sum(float(r["AUC"]) for r in rows)/len(rows):.3f}',f'{sum(float(r["F1"])>base_by_group[r["HeldOut"]] for r in rows)}/{len(rows)}'])
tables[6]=[['การแบ่ง holdout','Accuracy','F1']]
for protocol,label in [('random','สุ่มรายเหตุการณ์'),('process','จัดกลุ่มตาม ProcessGuid'),('scenario','จัดกลุ่มแพลตฟอร์มและสถานการณ์')]:
    r=next(r for r in bench if r['model']=='Random Forest' and r['protocol']==protocol)
    tables[6].append([label,f'{float(r["acc"]):.3f}',f'{float(r["f1"]):.3f}'])
stats=json.loads((TMP/'results_evidence.json').read_text(encoding='utf-8'))
names={1:'ProcessCreate',2:'FileCreateTime',3:'NetworkConnect',4:'SysmonStateChange',5:'ProcessTerminate',8:'CreateRemoteThread',9:'RawAccessRead',11:'FileCreate',12:'RegistryCreateDelete',13:'RegistrySetValue',23:'FileDelete'}
tables[7]=[['ID','เหตุการณ์','จำนวน','%']]
for event,n in stats['events'].items():
    pct=n/stats['rows']*100
    tables[7].append([event,names[int(event)],f'{n:,}',f'{pct:.2f}' if pct>=.1 else f'{pct:.3f}'])

relationships=E.fromstring(template['word/_rels/document.xml.rels'])
REL=patch.PKG_REL_NS
added={}
for n,path in figures.items():
    name=f'nccy_standalone_figure{n}.png';added['word/media/'+name]=path.read_bytes()
    relationships.append(E.Element(f'{{{REL}}}Relationship',Id=f'rIdStandaloneFigure{n}',Type='http://schemas.openxmlformats.org/officeDocument/2006/relationships/image',Target='media/'+name))

def make_table(data,number):
    tbl=el('tbl');tbl.append(el('tblPr'))
    for row in data:
        tr=el('tr')
        for value in row:
            cell=el('tc');cell.append(el('tcPr'));cell.append(para(value));tr.append(cell)
        tbl.append(tr)
    return table_xml(tbl,number-1)

def add_figure(number,caption):
    boundary(section2)
    p=deepcopy(src.xpath('//w:p[.//wp:inline]',namespaces=NS)[0])
    oldpr=p.find(q('pPr'))
    if oldpr is not None:p.remove(oldpr)
    pp=ppr('caption');setchild(pp,'keepNext');p.insert(0,pp)
    for blip in p.xpath('.//a:blip',namespaces=NS):blip.set(f'{{{R}}}embed',f'rIdStandaloneFigure{number}')
    for crop in p.xpath('.//a:srcRect',namespaces=NS):crop.getparent().remove(crop)
    with Image.open(figures[number]) as im:ratio=im.height/im.width
    cx=round(145/25.4*914400);cy=round(cx*ratio)
    for ext in p.xpath('.//wp:extent|.//a:xfrm/a:ext',namespaces=NS):ext.set('cx',str(cx));ext.set('cy',str(cy))
    for dp in p.xpath('.//wp:docPr',namespaces=NS):
        dp.set('id',str(100+number));dp.set('name',f'Standalone Figure {number}');dp.set('descr',caption)
    body.append(p);body.append(para(caption,'caption'));boundary(wide_section())

body.append(para(THAI_TITLE,'title'));body.append(para(ENGLISH_TITLE,'title',english=True));boundary(section1)
for item in CONTENT:
    role=item[0]
    if role=='figure':add_figure(item[1],item[2]);continue
    if role=='table':
        p=para(item[2],'caption');setchild(p.find(q('pPr')),'jc',val='left');setchild(p.find(q('pPr')),'keepNext')
        body.append(p);body.append(make_table(tables[item[1]],item[1]));continue
    value=item[1]
    p=para(value,'body' if role=='body_en' else role,english=role=='body_en' or not bool(re.search('[\u0e00-\u0e7f]',value)))
    # Word Thai-distribution stretches Latin parameter tokens character by character.
    # Align this mixed technical paragraph left, retaining Thai language shaping.
    if value.startswith('กำหนดพารามิเตอร์คงที่สำหรับการทดลองหลัก'):
        setchild(p.find(q('pPr')),'jc',val='left')
    if role=='keyword':
        label,remainder=value.split(' -- ',1)
        for r in list(p.findall(q('r'))):p.remove(r)
        first=para(label+' -- ','keyword',english=label=='Keywords').find(q('r'))
        for key in ('b','bCs','i','iCs'):setchild(first.find(q('rPr')),key)
        p.append(first);p.append(para(remainder,'keyword',english=label=='Keywords').find(q('r')))
    body.append(p)

refs={}
for p in src.findall('w:body/w:p',NS):
    m=re.match(r'^\[(\d+)\]\s*(.*)',text(p).strip())
    if m:refs[int(m[1])]=m[2]
for newno,oldno in enumerate(REFERENCE_ORDER,1):
    p=para(f'[{newno}] '+refs[oldno],'reference',english=True)
    setchild(p.find(q('pPr')),'keepLines')
    body.append(p)
boundary(section2);body.append(deepcopy(section2))

patches={'word/document.xml':serialize(reference),'word/_rels/document.xml.rels':serialize(relationships)}
types=E.fromstring(template['[Content_Types].xml'])
if not any(c.get('Extension')=='png' for c in types):types.append(E.Element(f'{{{patch.CT_NS}}}Default',Extension='png',ContentType='image/png'))
patches['[Content_Types].xml']=serialize(types)
for name,data in template.items():
    if re.fullmatch(r'word/header\d+\.xml',name):
        header=E.fromstring(data)
        for p in header.xpath('//w:p',namespaces=NS):
            ts=p.xpath('.//w:t',namespaces=NS);combined=''.join(t.text or '' for t in ts)
            if '202X' in combined:
                ts[0].text=combined.replace('NCCY 202X','NCCY').replace('202X','')
                for t in ts[1:]:t.text=''
        patches[name]=serialize(header)

with zipfile.ZipFile(TEMPLATE) as origin,zipfile.ZipFile(OUTPUT,'w',compression=zipfile.ZIP_DEFLATED) as out:
    for entry in origin.infolist():out.writestr(entry,patches.get(entry.filename,template[entry.filename]))
    for name,data in added.items():out.writestr(name,data)
for path,evidence in [(TEMPLATE,'template_evidence.json'),(SOURCE,'draft_evidence.json')]:
    assert hashlib.sha256(path.read_bytes()).hexdigest()==json.loads((TMP/evidence).read_text(encoding='utf-8'))['sha256']
with zipfile.ZipFile(OUTPUT) as out:
    for name,data in template.items():
        if name not in patches:assert out.read(name)==data,name
    for name,data in added.items():assert out.read(name)==data
corpus='\n'.join(text(p) for p in body.findall(q('p')))
for term in ('Achmad','Nariswari','NLME','100110','0.8868','0.8799','GroupKFold','ตามแนวทางงานอ้างอิง'):
    assert term not in corpus,term
prose=[text(p) for p in body.findall(q('p')) if not re.match(r'^\[\d+\]',text(p))]
cited={int(n) for p in prose for n in re.findall(r'\[(\d+)\]',p)}
assert cited==set(range(1,len(REFERENCE_ORDER)+1)),cited
(WORK/'tables.json').write_text(json.dumps(tables,ensure_ascii=False,indent=2),encoding='utf-8')
(WORK/'standalone_text.txt').write_text('\n'.join(text(e) for e in body),encoding='utf-8')
(WORK/'reference_mapping.json').write_text(json.dumps(dict(enumerate(REFERENCE_ORDER,1)),indent=2),encoding='utf-8')
print('Saved',OUTPUT)
print('Tables',len(tables),'figures',len(figures),'references',len(REFERENCE_ORDER),'sections',len(reference.xpath('//w:sectPr',namespaces=NS)))
