"""Reuse the accepted template components while preserving the v4 deliverable."""
from pathlib import Path
ROOT = Path('S:/Jr.Project(Real)/sysmon-lab')
code = (ROOT / 'tmp/paper_nccy_review/build_standalone.py').read_text(encoding='utf-8')
code = code.replace('from standalone_content import', 'from host_based_content import')
code = code.replace("WORK=ROOT/'tmp/paper_nccy_review/standalone'", "WORK=ROOT/'tmp/paper_nccy_review/host_based'")
code = code.replace('paper_draft_NCCY_v4_standalone.docx', 'paper_draft_NCCY_v5_host_based.docx')
code = code.replace('table_widths=[[26,10,46]', 'table_widths=[[25,24,33]')
code = code.replace(
    "cell=el('tc');cell.append(el('tcPr'));cell.append(para(value));tr.append(cell)",
    "cell=el('tc');cell.append(el('tcPr'))\n"
    "            for line in value.split('\\n'):cell.append(para(line))\n"
    "            tr.append(cell)",
)
code = code.replace(
    '    return table_xml(tbl,number-1)',
    "    formatted=table_xml(tbl,number-1)\n"
    "    if number==1:\n"
    "        for row in formatted.findall(q('tr')):\n"
    "            for ci,cell in enumerate(row.findall(q('tc'))):\n"
    "                for p in cell.findall(q('p')):\n"
    "                    if ci==2:setchild(p.find(q('pPr')),'jc',val='center')\n"
    "                    if re.search('[\\u0e00-\\u0e7f]',text(p)):\n"
    "                        for rp in p.findall('.//'+q('rPr')):\n"
    "                            setchild(rp,'lang',val='th-TH',bidi='th-TH');setchild(rp,'cs')\n"
    "    return formatted",
)
exec(compile(code, str(ROOT / 'tmp/paper_nccy_review/build_standalone.py'), 'exec'), globals())
