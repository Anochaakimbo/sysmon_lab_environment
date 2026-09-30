"""Use the packaged render_docx rasterizer with a read-only Microsoft Word PDF.
The packaged LibreOffice backend is unavailable on this Windows host.
"""
import argparse, importlib.util, shutil
from pathlib import Path

parser=argparse.ArgumentParser()
parser.add_argument('docx')
parser.add_argument('pdf')
parser.add_argument('--output_dir',required=True)
parser.add_argument('--dpi',type=int,default=180)
args=parser.parse_args()
skill=next(Path('C:/Users/bbcor/.codex/plugins/cache/openai-primary-runtime/documents').glob('*/skills/documents/render_docx.py')).parent
spec=importlib.util.spec_from_file_location('packaged_render_docx',skill/'render_docx.py')
renderer=importlib.util.module_from_spec(spec)
spec.loader.exec_module(renderer)
def word_pdf(input_path,user_profile,convert_tmp_dir,stem,verbose=False):
    destination=Path(convert_tmp_dir)/f'{stem}.pdf'
    shutil.copy2(args.pdf,destination)
    return str(destination),'PDF exported read-only by native Microsoft Word'
renderer.convert_to_pdf=word_pdf
pages=renderer.rasterize(args.docx,args.output_dir,args.dpi,verbose=False,emit_pdf=False)
print(f'Rendered {len(pages)} pages to {args.output_dir} with packaged render_docx.py')
