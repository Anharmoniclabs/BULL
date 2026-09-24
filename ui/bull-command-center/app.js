const $=id=>document.getElementById(id);
const api=async(path,opts={})=>{const r=await fetch(path,{cache:"no-store",...opts});const j=await r.json();if(!r.ok)throw Error(j.error||r.status);return j};
const post=(path,obj)=>api(path,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(obj)});
const esc=s=>String(s??"").replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
const statusClass=s=>String(s||"").toLowerCase();

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
  const s=await api("/api/repo");$("repo-json").textContent=JSON.stringify(s,null,2);
  $("changed-files").innerHTML=s.status.length?s.status.map(x=>'<div>'+esc(x)+'</div>').join(""):"<div>Working tree clean.</div>";
  await browse(currentRepoPath);
}
$("repo-refresh").onclick=loadRepo;

async function loadWorkspace(){
  const x=await api("/api/files?path=.");
  $("workspace-tree").innerHTML=x.items.map(it=>'<button data-p="'+esc(it.path)+'" class="'+(it.dir?"dir":"")+'">'+(it.dir?"▣ ":"· ")+esc(it.path)+'</button>').join("");
  $("workspace-tree").querySelectorAll("button").forEach(b=>b.onclick=()=>{$("malware-path").value=b.dataset.p});
}
$("malware-scan").onclick=async()=>{try{$("malware-result").textContent="Scanning…";$("malware-result").textContent=JSON.stringify(await post("/api/malware/scan",{path:$("malware-path").value}),null,2)}catch(e){$("malware-result").textContent=e.message}};

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
  try{$("policy-result").textContent=JSON.stringify(await post("/api/policy/evaluate",payload),null,2)}catch(e){$("policy-result").textContent=e.message}
};
$("trace-run").onclick=async()=>{try{$("trace-result").textContent=JSON.stringify(await post("/api/trace/simulate",{events:JSON.parse($("trace-events").value)}),null,2)}catch(e){$("trace-result").textContent=e.message}};


let selectedJob=null;
async function loadRuntime(){
  try{
    const v=await api("/api/vm");
    $("vm-kvm").textContent=v.kvm?.status||"UNKNOWN";
    $("vm-assets").textContent=v.assets_verified?"VERIFIED":v.asset_manifest?"INVALID":"UNSET";
    const missing=Object.entries(v.tools||{}).filter(([,x])=>!x).map(([k])=>k);
    $("vm-tools").textContent=missing.length?"MISSING "+missing.length:"READY";
    $("vm-mode").textContent=v.architecture?.mode||"—";
    $("vm-state").textContent=JSON.stringify(v,null,2);
  }catch(e){
    $("vm-state").textContent=e.message;
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
    $("job-log").textContent=JSON.stringify(j,null,2)+"\n\n"+(l.log||"");
  }catch(e){$("job-log").textContent=e.message}
}
$("vm-refresh").onclick=loadRuntime;
$("jobs-refresh").onclick=refreshJobs;
$("vm-install-assets").onclick=async()=>{try{const j=await post("/api/vm/install-assets",{});selectedJob=j.id;$("job-log").textContent="Downloading and verifying the published BULL guest into this Codespace...\nJob "+j.id+"\nThis includes the ~1.5 GiB rootfs.ext4 image.";await refreshJobs()}catch(e){$("job-log").textContent=e.message}};
$("vm-plan").onclick=async()=>{try{$("job-log").textContent="Validating configured BULL MicroVM launcher…";$("job-log").textContent=JSON.stringify(await api("/api/microvm/plan"),null,2)}catch(e){$("job-log").textContent=e.message}};
$("vm-run").onclick=async()=>{try{const j=await post("/api/vm/run",{case:$("vm-case").value});selectedJob=j.id;$("job-log").textContent="Started "+j.command_label+"\nJob "+j.id;await refreshJobs()}catch(e){$("job-log").textContent=e.message}};
$("deployment-run").onclick=async()=>{try{const j=await post("/api/deployment/run",{});selectedJob=j.id;$("job-log").textContent="Started full BULL deployment check\nJob "+j.id;await refreshJobs()}catch(e){$("job-log").textContent=e.message}};
setInterval(()=>{if(document.getElementById("view-runtime").classList.contains("active"))refreshJobs()},2500);


async function loadAssurance(){
  const a=await api("/api/assurance");
  $("a-source").textContent=String(a.source_complete).toUpperCase();
  $("a-deploy").textContent=String(a.deployment_complete).toUpperCase();
  $("a-release").textContent=a.release_complete===null?"NOT RUN":String(a.release_complete).toUpperCase();
  $("a-profile").textContent=a.profile||"—";
  $("assurance-controls").innerHTML=(a.controls||[]).map(c=>'<div class="control-detail"><div class="status '+statusClass(c.status)+'">'+esc(c.status)+'</div><div>'+esc(c.id)+'</div><div>'+esc(c.detail||c.title||"")+'</div><div>'+esc(c.phase)+'</div></div>').join("");
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
  $("sentinel-score").textContent=Number(s.score||0).toFixed(3);$("sentinel-verdict").textContent=String(s.verdict||"unknown").toUpperCase();$("sentinel-signals").textContent=JSON.stringify(s.signals||{},null,2);
  $("adversary-registry").innerHTML=registryHtml(a);await refreshRegistry();
}
$("agent-refresh").onclick=refreshRegistry;
$("agent-scan").onclick=async()=>{
  const payload={};if($("agent-url").value.trim())payload.url=$("agent-url").value.trim();else payload.text=$("agent-text").value;
  try{const r=await post("/api/agent-scan",payload);$("agent-scan-result").textContent=JSON.stringify(r,null,2);lastScan=r.counts||lastScan;$("t-agent").textContent=lastScan.agent||0;$("t-swarm").textContent=lastScan.swarm||0;$("t-botnet").textContent=lastScan.botnet||0;refreshRegistry();refreshMain()}catch(e){$("agent-scan-result").textContent=e.message}
};

async function loadSettings(){
  const [s,b]=await Promise.all([api("/api/system"),api("/api/brand")]);
  $("runtime-json").textContent=JSON.stringify(s.runtime,null,2);
  $("brand-meta").innerHTML="<b>Revision:</b> "+esc(b.revision)+"<br><b>Approved source:</b> "+esc(b.source?.file||"")+"<br><b>Source SHA-256:</b><br>"+esc(b.source?.sha256||"")+"<br><b>Note:</b> "+esc(b.source?.note||"");
  $("brand-assets").innerHTML=Object.keys(b.files||{}).map(name=>'<div class="brand-asset '+(name.includes("primary.svg")?"light":"")+'"><img src="/brand/'+encodeURIComponent(name)+'" alt="'+esc(name)+'"><span>'+esc(name)+'</span></div>').join("");
}
refreshMain();loadArchitecture();
