const $=id=>document.getElementById(id);
let selected=null,modelFile=null,modelId=null,modelInfo=null,result=null,busy=false,token='',page=0;
const pageSize=25,num=n=>Number(n).toLocaleString('en-US'),score=v=>v==null?'—':Number(v).toFixed(3);
function error(id,message){$(id).textContent=message;$(id).hidden=false;}
function sync(){
 $('load-model').disabled=busy||!modelFile||!$('trust-model').checked||!token;
 $('predict').disabled=busy||!selected||!modelId;
 for(const id of ['model-file','csv-file','features','input-mode','label-column','confirm-event-schema','trust-model']) $(id).disabled=busy;
 $('label-column').disabled=busy||$('input-mode').value==='events';
 $('use-threshold').disabled=busy||modelInfo?.score_kind!=='probability';
 $('threshold').disabled=busy||!$('use-threshold').checked||modelInfo?.score_kind!=='probability';
}
function clearResults(){result=null;$('results').hidden=true;$('process-panel').hidden=true;$('empty').hidden=false;$('result-tag').textContent='รอข้อมูล';}
function chooseModel(file){
 if(!file||busy)return;modelFile=null;modelId=null;modelInfo=null;clearResults();$('trust-model').checked=false;$('model-error').hidden=true;
 $('model-name').textContent='รอโหลดโมเดล';$('model-status').textContent='ยังไม่ได้โหลด';$('model-file-name').textContent='scikit-learn · pickle / joblib';$('feature-count').textContent='—';$('preprocessing').textContent='—';$('features').value='';$('features').readOnly=false;$('model-notes').replaceChildren();
 if(!/\.(pkl|pickle|joblib)$/i.test(file.name)||!file.size||file.size>100*1024*1024){error('model-error','เลือกไฟล์ .pkl / .pickle / .joblib ที่ไม่ว่างและไม่เกิน 100 MB');sync();return;}
 modelFile=file;$('model-selected').textContent=file.name;$('model-upload-status').textContent='ยืนยันแหล่งที่มา แล้วกดโหลดโมเดล';sync();
}
function chooseCSV(file){
 if(!file||busy)return;selected=null;clearResults();$('error').hidden=true;
 if(!/\.csv$/i.test(file.name)||!file.size||file.size>100*1024*1024){error('error','เลือกไฟล์ CSV ที่ไม่ว่างและไม่เกิน 100 MB');sync();return;}
 selected=file;$('file-name').textContent=file.name;$('file-detail').textContent=(file.size/1024/1024).toFixed(2)+' MB';
 $('request-status').textContent=modelId?'พร้อมทดสอบ':'โหลดโมเดลก่อนเริ่มทดสอบ';sync();
}
function drop(id,choose){
 for(const ev of ['dragenter','dragover']) $(id).addEventListener(ev,e=>{e.preventDefault();$(id).classList.add('drag');});
 for(const ev of ['dragleave','drop']) $(id).addEventListener(ev,e=>{e.preventDefault();$(id).classList.remove('drag');});
 $(id).addEventListener('drop',e=>choose(e.dataTransfer.files[0]));
}
drop('model-dropzone',chooseModel);drop('dropzone',chooseCSV);
$('model-file').addEventListener('change',e=>chooseModel(e.target.files[0]));
$('csv-file').addEventListener('change',e=>chooseCSV(e.target.files[0]));
$('trust-model').addEventListener('change',sync);
$('load-model').addEventListener('click',async()=>{
 if(busy||!modelFile||!$('trust-model').checked)return;
 busy=true;modelId=null;clearResults();sync();$('model-error').hidden=true;$('model-upload-status').textContent='กำลังโหลดโมเดล…';
 try{
  const q=new URLSearchParams({filename:modelFile.name,trusted:'1'});
  const r=await fetch('/api/upload-model?'+q,{method:'POST',headers:{'Content-Type':'application/octet-stream','X-Model-Token':token},body:modelFile});
  const d=await r.json();if(!r.ok)throw Error(d.error||'โหลดโมเดลไม่สำเร็จ');
  modelId=d.model_id;modelInfo=d.metadata;$('model-name').textContent=modelInfo.name;$('model-file-name').textContent=modelInfo.filename;
  $('model-status').textContent='● พร้อมใช้งาน';$('feature-count').textContent=modelInfo.feature_count??'ระบุเอง';$('preprocessing').textContent=modelInfo.preprocessing;
  $('features').value=modelInfo.columns.join(', ');$('features').readOnly=!!modelInfo.columns.length;$('use-threshold').checked=false;
  $('model-notes').replaceChildren(...modelInfo.notes.map(t=>{const li=document.createElement('li');li.textContent=t;return li;}));
  $('model-upload-status').textContent='โหลดโมเดลแล้ว · เลือก CSV ที่มีฟีเจอร์ตรงกัน';
 }catch(e){error('model-error',e.message);$('model-status').textContent='โหลดไม่สำเร็จ';$('model-upload-status').textContent='ตรวจไฟล์และลองใหม่';}
 finally{busy=false;sync();}
});
$('input-mode').addEventListener('change',()=>{const events=$('input-mode').value==='events';$('event-confirmation').hidden=!events;$('event-defaults').hidden=!events;clearResults();sync();});
$('use-threshold').addEventListener('change',()=>{clearResults();sync();});
$('threshold').addEventListener('input',()=>{$('threshold-value').textContent=Number($('threshold').value).toFixed(2);clearResults();});
$('predict').addEventListener('click',async()=>{
 if(!selected||!modelId||busy)return;busy=true;clearResults();sync();$('error').hidden=true;$('request-status').textContent='กำลังทำนายด้วยโมเดลที่อัปโหลด…';
 const q=new URLSearchParams({model_id:modelId,filename:selected.name,mode:$('input-mode').value,features:$('features').value,label_column:$('label-column').value,threshold:$('threshold').value,use_threshold:$('use-threshold').checked?'1':'0',confirm_event_schema:$('confirm-event-schema').checked?'1':'0',platform:$('platform-default').value,run_id:$('run-id').value});
 try{
  const r=await fetch('/api/predict?'+q,{method:'POST',headers:{'Content-Type':'text/csv; charset=utf-8','X-Model-Token':token},body:selected});
  const d=await r.json();if(!r.ok)throw Error(d.error||'ทดสอบไม่สำเร็จ');result=d;page=0;$('os-filter').value='all';$('search').value='';$('flagged-only').checked=false;
  $('empty').hidden=true;$('results').hidden=false;$('process-panel').hidden=false;$('download').href='/api/download?id='+d.download_id;
  $('result-file').textContent=d.filename+' · '+d.model_file;$('result-tag').textContent='เสร็จสมบูรณ์';
  $('request-status').textContent='ทำนาย '+num(d.processes)+' ตัวอย่างแล้ว';
  $('notes').replaceChildren(...d.notes.map(t=>{const li=document.createElement('li');li.textContent=t;return li;}));render();
 }catch(e){error('error',e.message);$('request-status').textContent='ทดสอบไม่สำเร็จ';}finally{busy=false;sync();}
});
function render(){
 if(!result)return;const os=$('os-filter').value,block=os==='all'?result:result.by_os[os],m=block?.metrics,n=block?.processes||0,flagged=block?.flagged||0;
 $('n-process').textContent=num(n);$('n-flagged').textContent=num(flagged);$('n-benign').textContent=num(n-flagged);
 $('event-note').textContent=(result.input_mode==='events'?num(result.events)+' Event · ตัดรหัสที่ใช้ไม่ได้ '+num(result.dropped_events)+' Event':num(result.processes)+' แถวฟีเจอร์')+' · '+(result.threshold==null?'ใช้ predict() ของโมเดล':'เกณฑ์ predict_proba '+result.threshold.toFixed(2));
 $('overlap').hidden=false;$('overlap').textContent='ยังยืนยันไม่ได้ว่าข้อมูลทดสอบแยกจากชุดฝึกของโมเดลนี้ กรุณาตรวจแหล่งข้อมูลก่อนอ้างอิงคะแนน';
 for(const [id,k] of [['f1','F1'],['precision','Precision'],['recall','Recall'],['auc','AUC'],['accuracy','Accuracy'],['fpr','FPR']]) $('metric-'+id).textContent=score(m?.[k]);
 $('baseline-note').textContent=m?'เทียบ baseline: ทายว่าปกติทุกตัวได้ Accuracy '+score(m.baseline_all_benign_accuracy)+' · ทายว่าโจมตีทุกตัวได้ F1 '+score(m.baseline_all_attack_f1)+' (Accuracy/F1 ของโมเดลต้องสูงกว่านี้จึงมีความหมาย)':'';
 const types=result.attack_types;$('attack-types').hidden=!types?.length;
 if(types?.length)$('attack-types').textContent='ประเภทหลัก: '+types[0].type+' ('+(types[0].share*100).toFixed(0)+'% ของตัวอย่างที่ถูกทำนายเป็นการโจมตี)'+(types.length>1?' · อื่นๆ: '+types.slice(1).map(t=>t.type+' '+(t.share*100).toFixed(0)+'%').join(', '):'');
 $('metric-note').textContent=m?'คะแนนจาก '+num(m.n_labeled)+' ตัวอย่างที่มี label'+(m.AUC==null?' · ROC-AUC ไม่มีคะแนนโมเดลหรือมี label เพียงคลาสเดียว':''):'ไม่มี label จริงสำหรับคำนวณคะแนน';
 for(const [id,a,b] of [['tn',0,0],['fp',0,1],['fn',1,0],['tp',1,1]]) $(id).textContent=m?num(m.confusion[a][b]):'—';
 renderTable();
}
function renderTable(){
 if(!result)return;const os=$('os-filter').value,q=$('search').value.toLowerCase();
 const rows=result.rows.filter(r=>(os==='all'||r.platform===os)&&(!$('flagged-only').checked||r.prediction===1)&&([r.Image,r.ProcessGuid,r.run,r.process_key].join(' ').toLowerCase().includes(q)));
 const pages=Math.max(1,Math.ceil(rows.length/pageSize));page=Math.max(0,Math.min(page,pages-1));const fragment=document.createDocumentFragment();
 for(const r of rows.slice(page*pageSize,(page+1)*pageSize)){
  const tr=document.createElement('tr');
  function cell(text,sub){const td=document.createElement('td'),main=document.createElement('strong');main.textContent=text;td.append(main);if(sub){const small=document.createElement('small');small.textContent=sub;td.append(small);}tr.append(td);return td;}
  const name=(r.Image||r.process_key).split(/[\\/]/).pop();cell(name,r.ProcessGuid).title=r.Image||'';
  cell(r.platform==='windows'?'Windows':r.platform==='linux'?'Linux':'ไม่ระบุ',r.run);cell(r.n_events==null?'—':num(r.n_events));cell(score(r.score));
  const td=document.createElement('td'),badge=document.createElement('span');badge.className='badge'+(r.prediction?' bad':'');badge.textContent=r.prediction?'การโจมตี / ผิดปกติ':'ปกติ';td.append(badge);tr.append(td);cell(r.attack_type||'—');
  cell(r.true_label==null?'ไม่มี':r.true_label===1?'1 · การโจมตี':'0 · ปกติ');fragment.append(tr);
 }
 if(!rows.length){const tr=document.createElement('tr'),td=document.createElement('td');td.colSpan=7;td.textContent='ไม่พบตัวอย่างตามเงื่อนไข';tr.append(td);fragment.append(tr);}
 $('process-rows').replaceChildren(fragment);$('row-count').textContent=num(rows.length)+' ตัวอย่าง';$('page-count').textContent='หน้า '+(page+1)+' / '+pages;$('prev').disabled=page===0;$('next').disabled=page>=pages-1;
}
$('os-filter').addEventListener('change',()=>{page=0;render();});
for(const id of ['search','flagged-only']) $(id).addEventListener('input',()=>{page=0;renderTable();});
$('prev').addEventListener('click',()=>{page--;renderTable();});$('next').addEventListener('click',()=>{page++;renderTable();});
(async()=>{try{const r=await fetch('/api/model');if(!r.ok)throw Error('เชื่อมต่อเซิร์ฟเวอร์ไม่ได้');const d=await r.json();token=d.token;$('schema-columns').textContent=d.required.join(', ');$('optional-columns').textContent=['platform','run_id','label','Image','User',...d.optional].join(', ');sync();}catch(e){error('model-error',e.message);}})();
