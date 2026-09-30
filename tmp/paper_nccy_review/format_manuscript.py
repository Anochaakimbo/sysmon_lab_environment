from pathlib import Path
from copy import deepcopy
import sys, zipfile, re, json, hashlib
from lxml import etree as E

ROOT=Path('S:/Jr.Project(Real)/sysmon-lab')
TMP=ROOT/'tmp/paper_nccy_review'
TEMPLATE=Path('C:/Users/bbcor/Downloads/template_NCCY_full_thai.docx')
SOURCE=ROOT/'docs/paper_draft_NCCY_v2.docx'
OUTPUT=ROOT/'docs/paper_draft_NCCY_v3_formatted.docx'
helper=next(Path('C:/Users/bbcor/.codex/plugins/cache/openai-primary-runtime/documents').glob('*/skills/documents/scripts/docx_ooxml_patch.py'))
sys.path.insert(0,str(helper.parent))
import docx_ooxml_patch as patch
W=patch.W_NS
R=patch.NS['r']
NS={'w':W,'r':R,'a':'http://schemas.openxmlformats.org/drawingml/2006/main','wp':'http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing','pic':'http://schemas.openxmlformats.org/drawingml/2006/picture'}
q=lambda n:f'{{{W}}}{n}'
def el(n,**attrs):
    return E.Element(q(n),{q(k):str(v) for k,v in attrs.items()})
def setchild(parent,name,**attrs):
    old=parent.find(q(name))
    if old is not None: parent.remove(old)
    c=el(name,**attrs); parent.append(c); return c
def text(p): return ''.join(p.xpath('.//w:t[not(ancestor::w:txbxContent)]/text()',namespaces=NS))
def serialize(e): return E.tostring(e,encoding='UTF-8',xml_declaration=True,standalone=True)

with zipfile.ZipFile(TEMPLATE) as z: template={n:z.read(n) for n in z.namelist()}
with zipfile.ZipFile(SOURCE) as z: source={n:z.read(n) for n in z.namelist()}
reference=E.fromstring(template['word/document.xml'])
src=E.fromstring(source['word/document.xml'])
body=reference.find(q('body')); old=deepcopy(body)
def find(text_start):
    return next(p for p in old.findall(q('p')) if text(p).strip().startswith(text_start))
role_source={'title':find('ชื่อเรื่องภาษาไทย'),'heading':find('5. หัวข้อหลัก'),'subheading':find('5.1 หัวข้อย่อย'),
    'body':find('เอกสารนี้รวบรวมข้อมูล'),'reference':find('[2]'),'caption':find('ภาพ 1'),'keyword':find('คำสำคัญ')}
section1=deepcopy(old.xpath('.//w:sectPr',namespaces=NS)[0])
section2=deepcopy(old.xpath('.//w:sectPr',namespaces=NS)[1])
for c in list(body):body.remove(c)

def rpr(role):
    rp=deepcopy(role_source[role].find(q('pPr')).find(q('rPr')))
    if rp is None:rp=el('rPr')
    for n in ('color','sz','szCs','b','bCs','i','iCs','caps','cs'):
        for c in list(rp.findall(q(n))):rp.remove(c)
    setchild(rp,'rFonts',ascii='TH SarabunPSK',hAnsi='TH SarabunPSK',eastAsia='TH SarabunPSK',cs='TH SarabunPSK')
    size=40 if role=='title' else 24 if role=='caption' else 28
    setchild(rp,'sz',val=size);setchild(rp,'szCs',val=size);setchild(rp,'color',val='000000')
    if role in ('title','heading','subheading'):
        setchild(rp,'b');setchild(rp,'bCs')
    if role=='subheading':
        setchild(rp,'i');setchild(rp,'iCs')
    setchild(rp,'lang',val='th-TH',bidi='th-TH')
    setchild(rp,'cs')
    return rp
def ppr(role,english=False):
    pp=deepcopy(role_source[role].find(q('pPr')))
    for n in ('rPr','sectPr','pageBreakBefore','keepLines','keepNext','spacing','widowControl','ind','jc'):
        for c in list(pp.findall(q(n))):pp.remove(c)
    align='center' if role in ('title','heading','caption') else 'left' if role in ('subheading','keyword','reference') else 'both' if english else 'thaiDistribute'
    setchild(pp,'jc',val=align)
    setchild(pp,'spacing',before=280 if role in ('heading','subheading') else 0,after=0,line=240,lineRule='auto')
    if role=='body':setchild(pp,'ind',firstLine=270)
    elif role=='reference':setchild(pp,'ind',left=284,hanging=284)
    else:setchild(pp,'ind',left=0,right=0,firstLine=0)
    setchild(pp,'widowControl',val=1)
    if role in ('title','heading','subheading'):setchild(pp,'keepNext')
    if role in ('title','heading','subheading','caption'):setchild(pp,'keepLines')
    pp.append(rpr(role))
    return pp
def para(string,role='body',english=False):
    p=el('p');p.append(ppr(role,english))
    for i,line in enumerate(string.split('\n')):
        r=el('r');r.append(rpr(role))
        if english:
            rp=r.find(q('rPr'))
            cs=rp.find(q('cs'))
            if cs is not None:rp.remove(cs)
            setchild(rp,'lang',val='en-US',bidi='th-TH')
        if i:r.append(el('br'))
        t=el('t');t.text=line
        if line.startswith(' ') or line.endswith(' '):t.set('{http://www.w3.org/XML/1998/namespace}space','preserve')
        r.append(t);p.append(r)
    return p
def boundary(section):
    p=el('p');pp=el('pPr');pp.append(el('spacing',before=0,after=0,line=20,lineRule='exact'))
    pp.append(el('rPr'));setchild(pp[-1],'sz',val=2);setchild(pp[-1],'szCs',val=2)
    pp.append(deepcopy(section));p.append(pp);body.append(p)
def wide_section():
    s=deepcopy(section2);setchild(s,'type',val='continuous');setchild(s,'cols',num=1,space=340)
    return s

srcbody=src.find(q('body')); source_pars=srcbody.findall(q('p'))
body.append(para('การสร้างชุดข้อมูลข้ามแพลตฟอร์มสำหรับการตรวจจับมัลแวร์\nด้วยการเรียนรู้ของเครื่องจากบันทึกเหตุการณ์ Sysmon\nบนระบบปฏิบัติการ Linux และ Windows','title'))
body.append(para('A CROSS-PLATFORM SYSMON-BASED DATASET\nFOR MACHINE-LEARNING MALWARE DETECTION\nON LINUX AND WINDOWS','title',english=True))
boundary(section1)

# Add the original image bytes and remap only the imported drawing relationships.
relationships=E.fromstring(template['word/_rels/document.xml.rels'])
src_rels=E.fromstring(source['word/_rels/document.xml.rels'])
REL=patch.PKG_REL_NS
image_map={}; added={}
for item in src_rels:
    if item.get('Type','').endswith('/image'):
        target=item.get('Target'); name=f'nccy_source_{Path(target).name}'
        newid='rIdNccyImage'+str(len(image_map)+1)
        relationships.append(E.Element(f'{{{REL}}}Relationship',Id=newid,Type=item.get('Type'),Target='media/'+name))
        image_map[item.get('Id')]=newid;added['word/media/'+name]=source['word/'+target]

table_widths=[[25,13,44],[25,57],[18,16,16,16,16],[10,23,9.8,9.8,9.8,9.8,9.8],[31,16,16,19],[47,17.5,17.5],[40,10,16,16],[44,19,19]]
def table_xml(tbl,number):
    t=deepcopy(tbl);pr=t.find(q('tblPr'))
    if pr is None:pr=el('tblPr');t.insert(0,pr)
    widths=[round(mm/25.4*1440) for mm in table_widths[number]]
    # Distribute rounding residue so every table fits the 4649.5-twip body column.
    if sum(widths)>4649:widths[-1]-=sum(widths)-4649
    setchild(pr,'tblW',w=sum(widths),type='dxa');setchild(pr,'tblLayout',type='fixed');setchild(pr,'jc',val='center')
    setchild(pr,'tblInd',w=0,type='dxa')
    margins=setchild(pr,'tblCellMar')
    for n,value in [('top',35),('bottom',35),('left',25),('right',25)]:margins.append(el(n,w=value,type='dxa'))
    borders=setchild(pr,'tblBorders')
    for n in ('top','left','bottom','right','insideH','insideV'):borders.append(el(n,val='single',sz=4,color='000000'))
    grid=t.find(q('tblGrid'))
    if grid is not None:t.remove(grid)
    grid=el('tblGrid');[grid.append(el('gridCol',w=w)) for w in widths];t.insert(1,grid)
    for ri,row in enumerate(t.findall(q('tr'))):
        trpr=row.find(q('trPr'))
        if trpr is None:trpr=el('trPr');row.insert(0,trpr)
        for child in list(trpr.findall(q('trHeight'))):trpr.remove(child)
        setchild(trpr,'cantSplit')
        if ri==0:setchild(trpr,'tblHeader')
        for ci,cell in enumerate(row.findall(q('tc'))):
            tcpr=cell.find(q('tcPr'))
            if tcpr is None:tcpr=el('tcPr');cell.insert(0,tcpr)
            setchild(tcpr,'tcW',w=widths[ci],type='dxa');setchild(tcpr,'vAlign',val='center');setchild(tcpr,'shd',val='clear',fill='FFFFFF')
            value='\n'.join(text(p) for p in cell.findall(q('p')))
            for p in list(cell.findall(q('p'))):cell.remove(p)
            p=para(value,'body',english=True);pp=p.find(q('pPr'))
            setchild(pp,'ind',left=0,right=0,firstLine=0)
            numeric=bool(re.fullmatch(r'[0-9.,%/ -]+',value))
            setchild(pp,'jc',val='center' if ri==0 or numeric else 'left')
            setchild(pp,'spacing',before=0,after=0,line=240,lineRule='auto')
            setchild(pp,'keepLines')
            if ri<len(t.findall(q('tr')))-1:setchild(pp,'keepNext')
            for rp in p.findall('.//'+q('rPr')):
                setchild(rp,'sz',val=24);setchild(rp,'szCs',val=24)
                if ri==0:setchild(rp,'b');setchild(rp,'bCs')
            if numeric:setchild(tcpr,'noWrap')
            cell.append(p)
    return t

fig_number=0;table_number=0;deferred_figures=[]
children=list(srcbody)[4:]
skip_next=False
for i,node in enumerate(children):
    if skip_next:skip_next=False;continue
    if node.tag==q('sectPr'):continue
    if node.tag==q('tbl'):
        body.append(table_xml(node,table_number));table_number+=1
        if table_number==5 and deferred_figures:
            boundary(section2)
            for fi,(picture,caption) in enumerate(deferred_figures):
                if fi<len(deferred_figures)-1:setchild(caption.find(q('pPr')),'keepNext')
                body.append(picture);body.append(caption)
            boundary(wide_section())
        continue
    value=text(node).strip()
    if node.xpath('.//wp:inline',namespaces=NS):
        fig_number+=1
        picture=deepcopy(node)
        pp=picture.find(q('pPr'))
        if pp is not None:picture.remove(pp)
        pp=ppr('caption');setchild(pp,'keepNext');picture.insert(0,pp)
        for b in picture.xpath('.//a:blip',namespaces=NS):
            key=b.get(f'{{{R}}}embed');b.set(f'{{{R}}}embed',image_map[key])
        # Crop only excess white canvas via OOXML without touching source image bytes.
        crop_b={1:18000,2:24000,3:0,4:0}[fig_number]
        width_mm={1:130,2:115,3:145,4:145}[fig_number]
        inline=picture.xpath('.//wp:inline',namespaces=NS)[0]
        extent=inline.find(f'{{{NS["wp"]}}}extent');ratio=int(extent.get('cy'))/int(extent.get('cx'))
        cx=round(width_mm/25.4*914400);cy=round(cx*ratio*(1-crop_b/100000))
        extent.set('cx',str(cx));extent.set('cy',str(cy))
        for ext in picture.xpath('.//a:xfrm/a:ext',namespaces=NS):ext.set('cx',str(cx));ext.set('cy',str(cy))
        fill=picture.xpath('.//pic:blipFill',namespaces=NS)[0]
        crop=fill.find(f'{{{NS["a"]}}}srcRect')
        if crop is None:crop=E.Element(f'{{{NS["a"]}}}srcRect');fill.insert(1,crop)
        crop.set('b',str(crop_b));crop.set('t','0');crop.set('l','0');crop.set('r','0')
        caption=para(text(children[i+1]).strip(),'caption');skip_next=True
        if fig_number in (3,4):deferred_figures.append((picture,caption));continue
        boundary(section2);body.append(picture);body.append(caption);boundary(wide_section());continue
    if not value:continue
    if value in ('บทคัดย่อ','ABSTRACT','เอกสารอ้างอิง') or re.match(r'^\d+\.\s',value):role='heading'
    elif re.match(r'^\d+\.\d+\s',value):role='subheading'
    elif value.startswith('ตาราง ') and i+1<len(children) and children[i+1].tag==q('tbl'):role='caption'
    elif value.startswith(('คำสำคัญ','Keywords')):role='keyword'
    elif re.match(r'^\[\d+\]',value):role='reference'
    else:role='body'
    p=para(value,role,english=not bool(re.search('[\u0e00-\u0e7f]',value)))
    if role=='caption' and value.startswith('ตาราง '):
        setchild(p.find(q('pPr')),'jc',val='left');setchild(p.find(q('pPr')),'keepNext')
    if role=='keyword':
        label,remainder=value.split(' -- ',1)
        for r in list(p.findall(q('r'))):p.remove(r)
        first=para(label+' -- ','keyword').find(q('r'))
        for name in ('b','bCs','i','iCs'):setchild(first.find(q('rPr')),name)
        p.append(first)
        p.append(para(remainder,'keyword').find(q('r')))
    body.append(p)
# Balance the last reference columns with a zero-height continuous section.
boundary(section2)
body.append(deepcopy(section2))

patches={'word/document.xml':serialize(reference),'word/_rels/document.xml.rels':serialize(relationships)}
types=E.fromstring(template['[Content_Types].xml']);CT=patch.CT_NS
if not any(c.get('Extension')=='png' for c in types):types.append(E.Element(f'{{{CT}}}Default',Extension='png',ContentType='image/png'))
patches['[Content_Types].xml']=serialize(types)
for name,data in template.items():
    if re.fullmatch(r'word/header\d+\.xml',name):
        header=E.fromstring(data)
        for p in header.xpath('//w:p',namespaces=NS):
            ts=p.xpath('.//w:t',namespaces=NS)
            combined=''.join(t.text or '' for t in ts)
            if '202X' in combined:
                ts[0].text=combined.replace('NCCY 202X','NCCY').replace('202X','')
                for t in ts[1:]:t.text=''
        patches[name]=serialize(header)
with zipfile.ZipFile(TEMPLATE) as original,zipfile.ZipFile(OUTPUT,'w',compression=zipfile.ZIP_DEFLATED) as out:
    for entry in original.infolist():out.writestr(entry,patches.get(entry.filename,template[entry.filename]))
    for name,data in added.items():out.writestr(name,data)

# Exact preservation gate for unrelated package parts and retained source files.
baseline=json.loads((TMP/'template_evidence.json').read_text(encoding='utf-8'))
assert hashlib.sha256(TEMPLATE.read_bytes()).hexdigest()==baseline['sha256']
baseline_src=json.loads((TMP/'draft_evidence.json').read_text(encoding='utf-8'))
assert hashlib.sha256(SOURCE.read_bytes()).hexdigest()==baseline_src['sha256']
with zipfile.ZipFile(OUTPUT) as final:
    for name,data in template.items():
        if name not in patches:assert final.read(name)==data,name
    for name,data in added.items():assert final.read(name)==data,name
print('Saved',OUTPUT)
print('Tables',table_number,'images',fig_number,'sections',len(reference.xpath('//w:sectPr',namespaces=NS)))
print('All unrelated template package parts and original images preserved byte-for-byte')
