const $=id=>document.getElementById(id);
const api=async(path,opts={})=>{const r=await fetch(path,{cache:"no-store",...opts});const j=await r.json();if(!r.ok)throw Error(j.error||r.status);return j};
const post=(path,obj)=>api(path,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(obj)});
const esc=s=>String(s??"").replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
const statusClass=s=>String(s||"").toLowerCase();

const HUMAN_LABELS={
  root:"Repository root",branch:"Branch",commit:"Commit",remote:"Git remote",dirty:"Working tree changed",
  status:"Status",configured:"Configured",valid:"Integrity valid",records:"Records",head_hash:"Head checkpoint",
  policy_bundle:"Signed policy bundle",integrity_manifest:"Signed runtime manifest",microvm_configured:"MicroVM configuration",
  audit_ledger:"Audit ledger",remote_anchor:"Remote audit anchor",seccomp_profile:"Seccomp profile",
  cgroup_parent:"Delegated cgroup v2",snapshot_root:"Snapshot scratch",hardware_approval:"Hardware approval",
  assets_verified:"Guest assets verified",asset_manifest:"Guest asset manifest",asset_error:"Guest asset error",
  microvm_config:"MicroVM config",config_error:"Config error",software_emulation_fallback:"Software-emulation fallback",
  persistent_session:"Persistent VM session",guest_network_device:"Guest network device",control_channel:"Control channel",
  audit_channel:"Audit channel",returncode:"Return code",output_dir:"Evidence directory",command_label:"Operation",
  started:"Started",finished:"Finished",signals:"Signals",counts:"Signal counts",findings:"Findings"
};
function humanLabel(k){
  k=String(k||"");
  if(HUMAN_LABELS[k])return HUMAN_LABELS[k];
  return k.replace(/[_-]+/g," ").replace(/\b\w/g,m=>m.toUpperCase());
}
function humanScalar(key,v){
  if(v===null||v===undefined||v==="")return '<span class="human-muted">Not available</span>';
  if(typeof v==="boolean")return '<span class="human-badge '+(v?"yes":"no")+'">'+(v?"YES":"NO")+'</span>';
  if(typeof v==="number"){
    if(String(key).includes("time")||String(key).includes("started")||String(key).includes("finished")){
      if(v>1000000000)return '<span>'+esc(new Date(v*1000).toLocaleString())+'</span>';
    }
    return '<strong class="human-number">'+esc(v.toLocaleString())+'</strong>';
  }
  const s=String(v);
  const upper=s.toUpperCase();
  if(["PASS","FAIL","BLOCKED","RUNNING","READY","VALID","INVALID","ALLOW","SANDBOX","ESCALATE","DENY","IMPLEMENTED","EXTERNAL","CLEAN","SUSPICIOUS","AGENT"].includes(upper)){
    return '<span class="human-badge '+statusClass(upper)+'">'+esc(upper)+'</span>';
  }
  const codeLike=String(key).includes("path")||String(key).includes("hash")||String(key).includes("commit")||String(key).includes("url")||s.startsWith("/")||/^[a-f0-9]{32,}$/i.test(s);
  return codeLike?'<code class="human-code">'+esc(s)+'</code>':'<span class="human-text">'+esc(s)+'</span>';
}
function humanRender(v,key="",depth=0){
  if(depth>4)return '<span class="human-muted">Nested detail omitted</span>';
  if(Array.isArray(v)){
    if(!v.length)return '<span class="human-muted">None</span>';
    if(v.every(x=>x===null||["string","number","boolean"].includes(typeof x))){
      return '<div class="human-chips">'+v.map(x=>'<span class="human-chip">'+humanScalar(key,x)+'</span>').join("")+'</div>';
    }
    return '<div class="human-list">'+v.map((x,i)=>'<article class="human-card"><div class="human-card-title">'+esc(humanLabel(key||("Item "+(i+1))))+'</div>'+humanRender(x,key,depth+1)+'</article>').join("")+'</div>';
  }
  if(v&&typeof v==="object"){
    const entries=Object.entries(v);
    if(!entries.length)return '<span class="human-muted">No data</span>';
    return '<div class="human-grid">'+entries.map(([k,val])=>'<div class="human-row"><div class="human-label">'+esc(humanLabel(k))+'</div><div class="human-value">'+humanRender(val,k,depth+1)+'</div></div>').join("")+'</div>';
  }
  return humanScalar(key,v);
}
function showHuman(id,value){$(id).innerHTML=humanRender(value)}
function showMessage(id,message,tone="info"){$(id).innerHTML='<div class="human-message '+tone+'">'+esc(message)+'</div>'}

function openView(name){
  document.querySelectorAll(".view").forEach(x=>x.classList.toggle("active",x.id==="view-"+name));
  document.querySelectorAll("#nav button").forEach(x=>x.classList.toggle("active",x.dataset.view===name));
  if(name==="repo")loadRepo();
  if(name==="workspace")loadWorkspace();
  if(name==="visualization")loadArchitecture();
  if(name==="runtime")loadRuntime();
  if(name==="controls")loadAssurance();
  if(name==="logs")loadLogs();
  if(name==="agents")loadAgents();
  if(name==="settings")loadSettings();
}
document.querySelectorAll("#nav button").forEach(b=>b.onclick=()=>openView(b.dataset.view));
document.querySelectorAll("[data-open]").forEach(b=>b.onclick=()=>openView(b.dataset.open));
setInterval(()=>{$("clock").textContent=new Date().toLocaleString()},1000);

let lastSystem=null,lastScan={agent:0,swarm:0,botnet:0,endpoint:0};

function decisionBadge(v){
  v=String(v||"event").toUpperCase();
  return '<span class="decision '+v.toLowerCase()+'">'+esc(v)+'</span>';
}
function controlRow(c){
  return '<div class="control-row '+statusClass(c.status)+'"><b>'+esc(c.status)+'</b><span>'+esc(c.id||c.control_id||c.title)+'</span></div>';
}
function drawActivity(adversary){
  const box=$("activity-nodes");box.innerHTML="";
  const records=adversary.records||[];
  records.slice(0,30).forEach((r,i)=>{
    const n=document.createElement("div");
    n.className="activity-node "+(r.quarantined?"quarantine":r.swarm_id?"swarm":"");
    n.dataset.label=(r.swarm_id?r.swarm_id+" · ":"")+r.label.slice(0,28);
    n.style.left=(8+((i*37)%84))+"%";n.style.top=(12+((i*53)%72))+"%";
    box.appendChild(n);
  });
}
function renderMainLogs(events){
  const body=$("main-log");body.innerHTML="";
  if(!events.length){body.innerHTML='<tr><td colspan="4">No configured audit ledger events.</td></tr>';return}
  events.slice(-13).reverse().forEach(x=>{
    const tr=document.createElement("tr");
    tr.innerHTML='<td>'+esc((x.timestamp||"").slice(11,19))+'</td><td>'+decisionBadge(x.decision||x.record_type)+'</td><td>'+esc(x.actor||"runtime")+'</td><td>'+esc(x.operation||"—")+'</td>';
    body.appendChild(tr);
  });
}
async function refreshMain(){
  try{
    const [s,events,adv,files]=await Promise.all([api("/api/system"),api("/api/audit/events?limit=30"),api("/api/adversary"),api("/api/files?path=.")]);
    lastSystem=s;
    $("st-engine").textContent="ONLINE";
    $("st-policy").textContent=s.runtime.policy_bundle?"SIGNED":"DEV";
    $("st-vm").textContent=s.vm?.kvm?.status==="PASS"?(s.vm.assets_verified?"KVM READY":"KVM / NO ASSETS"):(s.vm?.kvm?.status||"BLOCKED");
    $("st-audit").textContent=s.audit.configured?(s.audit.valid?"VALID":"CHECK"):"UNSET";
    $("st-malware").textContent=s.malware.available?"ACTIVE":"UNAVAILABLE";
    $("st-agent").textContent=String(s.sentinel.verdict||"unknown").toUpperCase();
    $("protection").textContent=s.assurance.deployment_complete?"● DEPLOYMENT CONTROLS PASS":"● BULL DEVELOPMENT / PARTIAL DEPLOYMENT";
    $("repo-pill").textContent=s.repo.branch+" @ "+s.repo.commit+(s.repo.dirty?" · DIRTY":" · CLEAN");
    $("repo-summary").innerHTML="<b>"+esc(s.repo.remote)+"</b><br>Branch: "+esc(s.repo.branch)+"<br>Commit: "+esc(s.repo.commit)+"<br>Working tree: "+(s.repo.dirty?"CHANGED":"CLEAN");
    $("mini-files").innerHTML=files.items.slice(0,10).map(x=>'<div>'+(x.dir?"▣ ":"· ")+esc(x.path)+'</div>').join("");
    const controls=s.assurance.controls||[];$("main-controls").innerHTML=controls.slice(0,9).map(controlRow).join("");
    $("m-observed").textContent=adv.summary.total_attackers||0;
    $("m-swarms").textContent=Object.keys(adv.summary.swarms||{}).length;
    $("m-quarantine").textContent=adv.summary.quarantined||0;
    $("m-audit").textContent=s.audit.records||0;
    drawActivity(adv);renderMainLogs(events);
    $("recent-alerts").innerHTML=events.filter(x=>["DENY","ESCALATE"].includes(String(x.decision).toUpperCase())).slice(-6).reverse().map(x=>'<div class="alert">'+esc(x.decision)+" · "+esc(x.operation||"event")+"<br>"+esc(x.resource||"")+"</div>").join("")||'<div class="alert">No deny/escalate events in loaded audit window.</div>';
  }catch(e){$("protection").textContent="BULL DASHBOARD ERROR · "+e.message}
}
setInterval(refreshMain,5000);

let currentRepoPath=".";
async function browse(path="."){
  const x=await api("/api/files?path="+encodeURIComponent(path));currentRepoPath=x.path;$("repo-path").textContent=x.path;
  const render=el=>{
    el.innerHTML="";
    if(x.path!=="."){const up=document.createElement("button");up.className="dir";up.textContent="↰ ..";up.onclick=()=>browse(x.path.split("/").slice(0,-1).join("/")||".");el.appendChild(up)}
    x.items.forEach(it=>{const b=document.createElement("button");b.className=it.dir?"dir":"";b.textContent=(it.dir?"▣ ":"· ")+it.name;b.onclick=()=>it.dir?browse(it.path):previewFile(it.path);el.appendChild(b)});
  };
  render($("repo-browser"));
}
async function previewFile(path){try{const x=await api("/api/file?path="+encodeURIComponent(path));$("file-preview").textContent=x.content}catch(e){$("file-preview").textContent=e.message}}
async function loadRepo(){
  const s=await api("/api/repo");showHuman("repo-json",s);
  $("changed-files").innerHTML=s.status.length?s.status.map(x=>'<div>'+esc(x)+'</div>').join(""):"<div>Working tree clean.</div>";
  await browse(currentRepoPath);
}
$("repo-refresh").onclick=loadRepo;

async function loadWorkspace(){
  const x=await api("/api/files?path=.");
  $("workspace-tree").innerHTML=x.items.map(it=>'<button data-p="'+esc(it.path)+'" class="'+(it.dir?"dir":"")+'">'+(it.dir?"▣ ":"· ")+esc(it.path)+'</button>').join("");
  $("workspace-tree").querySelectorAll("button").forEach(b=>b.onclick=()=>{$("malware-path").value=b.dataset.p});
}
$("malware-scan").onclick=async()=>{try{showMessage("malware-result","Scanning with BULL's bounded malware admission path…");showHuman("malware-result",await post("/api/malware/scan",{path:$("malware-path").value}))}catch(e){showMessage("malware-result",e.message,"error")}};

let arch=null;
async function loadArchitecture(){
  arch=await api("/api/architecture");
  $("architecture-graph").innerHTML=arch.nodes.map(n=>'<div class="arch-node"><b>'+esc(n.label)+'</b><span>'+esc(n.group)+'</span></div>').join("");
  for(const id of ["p-capability","p-granted"]){const s=$(id);s.innerHTML=arch.capabilities.map(x=>'<option value="'+esc(x)+'">'+esc(x)+'</option>').join("")}
  $("p-provenance").innerHTML=arch.provenance.map(x=>'<option value="'+esc(x)+'">'+esc(x)+'</option>').join("");
  $("p-capability").value="fs.read.project";$("p-provenance").value="human";
  [...$("p-granted").options].forEach(o=>o.selected=o.value==="fs.read.project");
}
$("policy-evaluate").onclick=async()=>{
  const granted=[...$("p-granted").selectedOptions].map(o=>o.value);
  const payload={actor:$("p-actor").value,task:"BULL UI policy test",operation:$("p-operation").value,resource:$("p-resource").value,capability:$("p-capability").value,granted_capabilities:granted,provenance:[$("p-provenance").value]};
  try{showHuman("policy-result",await post("/api/policy/evaluate",payload))}catch(e){showMessage("policy-result",e.message,"error")}
};
$("trace-run").onclick=async()=>{
  const events=[{transition:"Evaluate",data:{decision:$("trace-decision").value}}];
  if($("trace-scan").checked)events.push({transition:"ScanClean",data:{}});
  if($("trace-execute").checked)events.push({transition:"Execute",data:{sandboxed:$("trace-sandbox").checked,seccomp:$("trace-seccomp").checked}});
  try{showHuman("trace-result",await post("/api/trace/simulate",{events}))}catch(e){showMessage("trace-result",e.message,"error")}
};


let selectedJob=null;
async function loadRuntime(){
  try{
    const v=await api("/api/vm");
    $("vm-kvm").textContent=v.kvm?.status||"UNKNOWN";
    $("vm-assets").textContent=v.assets_verified?"VERIFIED":v.asset_manifest?"INVALID":"UNSET";
    const missing=Object.entries(v.tools||{}).filter(([,x])=>!x).map(([k])=>k);
    $("vm-tools").textContent=missing.length?"MISSING "+missing.length:"READY";
    $("vm-mode").textContent=v.architecture?.mode||"—";
    showHuman("vm-state",v);
  }catch(e){
    showMessage("vm-state",e.message,"error");
  }
  await refreshJobs();
}
async function refreshJobs(){
  try{
    const jobs=await api("/api/jobs");
    $("job-list").innerHTML=jobs.length?jobs.map(j=>'<button class="job '+String(j.status).toLowerCase()+'" data-job="'+esc(j.id)+'"><b>'+esc(j.status)+'</b><span>'+esc(j.command_label)+'</span><small>'+esc(new Date((j.started||0)*1000).toLocaleString())+'</small></button>').join(""):'<div class="empty">No BULL runtime jobs launched from this dashboard session.</div>';
    $("job-list").querySelectorAll("[data-job]").forEach(b=>b.onclick=()=>selectJob(b.dataset.job));
    if(selectedJob) await selectJob(selectedJob,false);
  }catch(e){$("job-list").innerHTML='<div class="empty">'+esc(e.message)+'</div>'}
}
async function selectJob(id,remember=true){
  if(remember)selectedJob=id;
  try{
    const [j,l]=await Promise.all([api("/api/job?id="+encodeURIComponent(id)),api("/api/job/log?id="+encodeURIComponent(id))]);
    $("job-log").innerHTML='<div class="job-meta">'+humanRender(j)+'</div><div class="console-log"><div class="console-log-title">Captured runtime log</div><pre>'+esc(l.log||"No log output yet.")+'</pre></div>';
  }catch(e){showMessage("job-log",e.message,"error")}
}
$("vm-refresh").onclick=loadRuntime;
$("jobs-refresh").onclick=refreshJobs;
$("vm-install-assets").onclick=async()=>{try{const j=await post("/api/vm/install-assets",{});selectedJob=j.id;showHuman("job-log",{status:"RUNNING",operation:j.command_label,job:j.id,note:"Downloading and verifying the published BULL guest. The rootfs image is approximately 1.5 GiB."});await refreshJobs()}catch(e){showMessage("job-log",e.message,"error")}};
$("vm-plan").onclick=async()=>{try{showMessage("job-log","Validating configured BULL MicroVM launcher…");showHuman("job-log",await api("/api/microvm/plan"))}catch(e){showMessage("job-log",e.message,"error")}};
$("vm-run").onclick=async()=>{try{const j=await post("/api/vm/run",{case:$("vm-case").value});selectedJob=j.id;showHuman("job-log",{status:"RUNNING",operation:j.command_label,job:j.id});await refreshJobs()}catch(e){showMessage("job-log",e.message,"error")}};
$("deployment-run").onclick=async()=>{try{const j=await post("/api/deployment/run",{});selectedJob=j.id;showHuman("job-log",{status:"RUNNING",operation:"Full BULL deployment check",job:j.id});await refreshJobs()}catch(e){showMessage("job-log",e.message,"error")}};
setInterval(()=>{if(document.getElementById("view-runtime").classList.contains("active"))refreshJobs()},2500);


async function loadAssurance(){
  const a=await api("/api/assurance");
  $("a-source").textContent=String(a.source_complete).toUpperCase();
  $("a-deploy").textContent=String(a.deployment_complete).toUpperCase();
  $("a-release").textContent=a.release_complete===null?"NOT RUN":String(a.release_complete).toUpperCase();
  $("a-profile").textContent=a.profile||"—";
  $("assurance-controls").innerHTML=(a.controls||[]).map(c=>'<div class="control-detail"><div class="status '+statusClass(c.status)+'">'+esc(c.status)+'</div><div><b>'+esc(c.title||humanLabel(c.id))+'</b><small>'+esc(c.id)+'</small></div><div>'+esc(c.detail||"No additional deployment detail.")+'</div><div>'+esc(humanLabel(c.phase))+'</div></div>').join("");
}
$("assurance-refresh").onclick=loadAssurance;

async function loadLogs(){
  const [a,e]=await Promise.all([api("/api/audit"),api("/api/audit/events?limit=150")]);
  $("l-config").textContent=a.configured?"YES":"NO";$("l-valid").textContent=a.valid===true?"VALID":a.valid===false?"INVALID":"—";$("l-records").textContent=a.records||0;$("l-head").textContent=(a.head_hash||"—").slice(0,14);
  $("audit-events").innerHTML=e.length?e.reverse().map(x=>'<div class="audit-event"><span>'+esc(x.timestamp||"")+'</span><span>'+decisionBadge(x.decision||x.record_type)+'</span><span>'+esc(x.actor||"runtime")+'</span><span>'+esc((x.operation||"")+" "+(x.resource||""))+'</span><span class="hash">'+esc(x.record_hash||"")+'</span></div>').join(""):'<div class="audit-event">No audit events available.</div>';
}
$("log-refresh").onclick=loadLogs;

function registryHtml(a){
  const rows=a.records||[];return rows.length?rows.map(r=>'<div class="registry-row"><span>'+esc(r.attacker_id)+'</span><span>'+esc(r.label)+'</span><span>'+esc(r.swarm_id||"—")+'</span><span>'+esc(r.model_family)+'</span><button data-q="'+esc(r.attacker_id)+'">'+(r.quarantined?"QUARANTINED":"CLASSIFY QUARANTINE")+'</button></div>').join(""):'<div class="registry-row">No observed records yet.</div>';
}
async function refreshRegistry(){
  const a=await api("/api/adversary");$("adversary-registry").innerHTML=registryHtml(a);
  $("adversary-registry").querySelectorAll("[data-q]").forEach(b=>b.onclick=async()=>{if(b.textContent==="QUARANTINED")return;try{await post("/api/adversary/quarantine",{attacker_id:b.dataset.q});refreshRegistry();refreshMain()}catch(e){alert(e.message)}});
}
async function loadAgents(){
  const [s,a]=await Promise.all([api("/api/sentinel"),api("/api/adversary")]);
  $("sentinel-score").textContent=Number(s.score||0).toFixed(3);$("sentinel-verdict").textContent=String(s.verdict||"unknown").toUpperCase();showHuman("sentinel-signals",s.signals||{});
  $("adversary-registry").innerHTML=registryHtml(a);await refreshRegistry();
}
$("agent-refresh").onclick=refreshRegistry;
$("agent-scan").onclick=async()=>{
  const payload={};if($("agent-url").value.trim())payload.url=$("agent-url").value.trim();else payload.text=$("agent-text").value;
  try{const r=await post("/api/agent-scan",payload);showHuman("agent-scan-result",r);lastScan=r.counts||lastScan;$("t-agent").textContent=lastScan.agent||0;$("t-swarm").textContent=lastScan.swarm||0;$("t-botnet").textContent=lastScan.botnet||0;refreshRegistry();refreshMain()}catch(e){showMessage("agent-scan-result",e.message,"error")}
};

async function loadSettings(){
  const [s,b]=await Promise.all([api("/api/system"),api("/api/brand")]);
  showHuman("runtime-json",s.runtime);
  $("brand-meta").innerHTML="<b>Revision:</b> "+esc(b.revision)+"<br><b>Approved source:</b> "+esc(b.source?.file||"")+"<br><b>Source SHA-256:</b><br>"+esc(b.source?.sha256||"")+"<br><b>Note:</b> "+esc(b.source?.note||"");
  $("brand-assets").innerHTML=Object.keys(b.files||{}).map(name=>'<div class="brand-asset '+(name.includes("primary.svg")?"light":"")+'"><img src="/brand/'+encodeURIComponent(name)+'" alt="'+esc(name)+'"><span>'+esc(name)+'</span></div>').join("");
}
refreshMain();loadArchitecture();
