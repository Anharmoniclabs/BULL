const $=id=>document.getElementById(id);
const $$=q=>Array.from(document.querySelectorAll(q));

const api=async(path,opts={})=>{
  const response=await fetch(path,{cache:"no-store",...opts});
  const body=await response.json().catch(()=>({error:"Invalid server response"}));
  if(!response.ok) throw new Error(body.error||("HTTP "+response.status));
  return body;
};
const post=(path,body={})=>api(path,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)});
const esc=value=>String(value??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));

const pages={
  overview:["Overview",loadOverview],
  firewall:["Firewall",loadFirewall],
  policy:["Policy Lab",loadPolicy],
  signals:["Signals",loadSignals],
  files:["Files & Malware",loadFiles],
  runtime:["Runtime",loadRuntime],
  audit:["Audit",loadAudit],
  assurance:["Assurance",loadAssurance],
  system:["System",loadSystem],
};

let scenarioCatalog=null;
let selectedScenario=null;
let currentPath=".";
let selectedJob=null;
let presentation=false;

function tone(value){
  const v=String(value||"").toUpperCase();
  if(["READY","PASS","VALID","SIGNED","ONLINE","CLEAN","ALLOW","YES","ACTIVE","RECORDED","CHECKED","LOCAL"].includes(v)) return "pass";
  if(["FAIL","INVALID","ERROR","DENY"].includes(v)) return "fail";
  if(["BLOCKED","PARTIAL","UNAVAILABLE","NOT_INSTALLED","SIGNATURES_MISSING","SANDBOX","NOT READY","HOST LIMITED","NOT VERIFIED"].includes(v)) return "warn";
  return "info";
}
function toast(message,type=""){
  const node=$("toast");
  node.textContent=message;
  node.className="toast show "+type;
  clearTimeout(toast.timer);
  toast.timer=setTimeout(()=>node.className="toast",3200);
}
function statusPill(status){
  return '<span class="status-pill '+tone(status)+'">'+esc(status)+'</span>';
}
function decisionChip(value){
  const v=String(value||"EVENT").toUpperCase();
  return '<span class="decision-chip '+v.toLowerCase()+'">'+esc(v)+'</span>';
}
function typeChip(event){
  return event?.metadata?.simulation==="true"
    ? '<span class="type-chip">DEMO</span>'
    : '<span class="type-chip">LIVE / RUNTIME</span>';
}
function notice(title,detail,type="info"){
  const icon=type==="pass"?"✓":type==="warn"?"!":"i";
  return '<div class="notice '+type+'"><i>'+icon+'</i><div><strong>'+esc(title)+'</strong><p>'+esc(detail)+'</p></div></div>';
}
function layerCard(name,status,detail){
  return '<article class="layer-card"><div class="layer-top"><strong>'+esc(name)+'</strong>'+statusPill(status)+'</div><p>'+esc(detail)+'</p></article>';
}
function readRow(label,value){
  let display=value;
  if(Array.isArray(display)) display=display.join(", ");
  if(display&&typeof display==="object") display=Object.entries(display).map(([k,v])=>k+": "+v).join(" · ");
  return '<div class="read-row"><small>'+esc(String(label).replace(/_/g," "))+'</small><span>'+esc(display??"Not available")+'</span></div>';
}
function renderReadable(obj){
  if(!obj||typeof obj!=="object") return readRow("Value",obj);
  return Object.entries(obj).map(([k,v])=>readRow(k,v)).join("");
}

const routeAliases={activity:"signals",workspace:"files",controls:"assurance"};
function openView(name){
  const requested=routeAliases[name]||name;
  const page=pages[requested]?requested:"overview";
  $$(".view").forEach(view=>{
    const active=view.id==="view-"+page;
    view.hidden=!active;
    view.classList.toggle("active",active);
  });
  $$("#nav button").forEach(button=>button.classList.toggle("active",button.dataset.view===page));
  $("page-title").textContent=pages[page][0];
  if(location.hash!=="#"+page) history.replaceState(null,"","#"+page);
  window.scrollTo(0,0);
  Promise.resolve(pages[page][1]()).catch(error=>toast(error.message||String(error),"error"));
}
$$("#nav button").forEach(button=>button.addEventListener("click",()=>openView(button.dataset.view)));
$$("[data-open]").forEach(button=>button.addEventListener("click",()=>openView(button.dataset.open)));

$("presentation-toggle").addEventListener("click",()=>{
  presentation=!presentation;
  document.body.classList.toggle("presentation",presentation);
  $("presentation-toggle").textContent=presentation?"Exit presentation":"Presentation";
  window.scrollTo(0,0);
});

setInterval(()=>{$("clock").textContent=new Date().toLocaleTimeString([], {hour:"2-digit",minute:"2-digit"})},1000);

const search=$("global-search");
search.addEventListener("input",()=>{
  const q=search.value.trim().toLowerCase();
  const active=document.querySelector(".view.active");
  if(!active) return;
  active.querySelectorAll(".card,.layer-card,.scenario-button,.assurance-row,.dependency-row,.config-row,tr").forEach(node=>{
    node.classList.toggle("search-hidden",!!q&&!node.textContent.toLowerCase().includes(q));
  });
});
document.addEventListener("keydown",event=>{
  if(event.key==="/"&&!/INPUT|TEXTAREA|SELECT/.test(document.activeElement?.tagName||"")){
    event.preventDefault();
    search.focus();
  }
});

function controlStatus(system,id){
  return (system.assurance?.controls||[]).find(item=>item.id===id)?.status;
}
function kvmReason(vm){
  return vm?.kvm?.reason||vm?.kvm?.error||"This host does not expose usable KVM hardware virtualization.";
}

async function getScenarios(){
  if(!scenarioCatalog) scenarioCatalog=await api("/api/scenarios");
  return scenarioCatalog;
}
function enforcementText(decision){
  return {
    ALLOW:"BULL would let the authorized runtime path continue.",
    SANDBOX:"BULL would force constrained execution instead of direct host execution.",
    ESCALATE:"BULL would stop automatic execution and require operator review.",
    DENY:"BULL would block the action before the requested effect.",
  }[decision]||"Awaiting policy decision.";
}
function previewPipeline(scenario){
  const preview=scenario.preview||{};
  return [
    {title:"1 · Request",status:"OBSERVED",detail:scenario.request},
    {title:"2 · Provenance",status:"CHECKED",detail:(scenario.provenance||[]).join(", ")},
    {title:"3 · Capability",status:"CHECKED",detail:scenario.capability},
    {title:"4 · Policy",status:preview.decision||"PREVIEW",detail:(preview.reasons||[]).join("; ")},
    {title:"5 · Enforcement",status:preview.decision||"PREVIEW",detail:enforcementText(preview.decision)},
    {title:"6 · Evidence",status:"PREVIEW",detail:"Run the scenario to record this simulated policy decision."},
  ];
}
function renderPipeline(node,pipeline){
  node.innerHTML=(pipeline||[]).map(stage=>'<article class="stage '+tone(stage.status)+'"><small>'+esc(stage.title)+'</small><strong>'+esc(stage.status)+'</strong><p>'+esc(stage.detail||"")+'</p></article>').join("");
}
function renderScenarioResult(node,data,preview=false){
  const result=preview?data.preview:data;
  if(!result){
    node.className="result-box empty";
    node.textContent="No result.";
    return;
  }
  const decision=result.decision||"UNKNOWN";
  node.className="result-box";
  node.innerHTML='<div class="decision-hero"><b class="'+decision.toLowerCase()+'">'+esc(decision)+'</b><span>Risk '+Number(result.risk||0).toFixed(2)+(result.hard_block?" · hard block":"")+(preview?" · preview":"")+'</span></div><div class="reason-list">'+(result.reasons||[]).map(reason=>'<div>'+esc(reason)+'</div>').join("")+'</div>';
}
function scenarioButtons(node,selected,overview){
  node.innerHTML=(scenarioCatalog?.scenarios||[]).map(s=>'<button class="scenario-button '+(s.id===selected?"active":"")+'" data-scenario="'+esc(s.id)+'"><small>'+esc(s.category)+'</small><strong>'+esc(s.title)+'</strong><span>'+esc(s.summary)+'</span></button>').join("");
  node.querySelectorAll("[data-scenario]").forEach(button=>button.addEventListener("click",()=>selectScenario(button.dataset.scenario,overview)));
}
function selectScenario(id,overview=false){
  const scenario=(scenarioCatalog?.scenarios||[]).find(item=>item.id===id);
  if(!scenario) return;
  selectedScenario=id;
  if(overview){
    scenarioButtons($("overview-scenario-list"),id,true);
    $("overview-demo-title").textContent=scenario.title;
    $("overview-demo-request").textContent=scenario.request;
    renderPipeline($("overview-pipeline"),previewPipeline(scenario));
    renderScenarioResult($("overview-demo-result"),scenario,true);
  }else{
    scenarioButtons($("scenario-list"),id,false);
    $("firewall-category").textContent=scenario.category.toUpperCase();
    $("firewall-title").textContent=scenario.title;
    $("firewall-request").textContent=scenario.request;
    $("scenario-run").disabled=false;
    renderPipeline($("firewall-pipeline"),previewPipeline(scenario));
    renderScenarioResult($("firewall-result"),scenario,true);
  }
}
async function runSelectedScenario(){
  if(!selectedScenario) return;
  const button=$("scenario-run");
  button.disabled=true;
  button.textContent="Running…";
  try{
    const result=await post("/api/scenario/run",{id:selectedScenario});
    renderPipeline($("firewall-pipeline"),result.pipeline);
    renderScenarioResult($("firewall-result"),result,false);
    $("firewall-result").insertAdjacentHTML("beforeend",
      '<div class="scenario-proof">'+
      '<div><b>Enforcement</b><span>'+esc(result.enforcement)+'</span></div>'+
      '<div><b>Host effect executed</b><span>NO</span></div>'+
      '<div><b>Audit</b><span>'+(result.audit?.recorded?"Simulation decision recorded":"Not recorded")+'</span></div>'+
      '</div>');
    toast("BULL policy scenario complete","success");
    scenarioCatalog=null;
  }catch(error){
    toast(error.message,"error");
  }finally{
    button.disabled=false;
    button.textContent="Run through BULL";
  }
}
$("scenario-run").addEventListener("click",runSelectedScenario);

async function loadOverview(){
  const [system,events,adversary]=await Promise.all([
    api("/api/system"),
    api("/api/audit/events?limit=120"),
    api("/api/adversary"),
  ]);
  await getScenarios();

  const env=system.environment?.codespaces?"CODESPACES":"LOCAL HOST";
  $("env-badge").textContent=env;
  $("sidebar-host").textContent=env+" · "+(system.repo?.branch||"repo");

  const counts={ALLOW:0,SANDBOX:0,ESCALATE:0,DENY:0};
  events.forEach(event=>{
    const decision=String(event.decision||"").toUpperCase();
    if(decision in counts) counts[decision]++;
  });
  $("metric-records").textContent=Number(system.audit?.records||0).toLocaleString();
  $("metric-denied").textContent=counts.DENY;
  $("metric-review").textContent=counts.ESCALATE;
  $("metric-agents").textContent=Number(adversary.summary?.total_attackers||0).toLocaleString();

  const signed=!!system.runtime?.policy_bundle;
  const malware=!!system.malware?.ready;
  const auditValid=system.audit?.valid===true;
  const sentinel=String(system.sentinel?.verdict||"UNKNOWN").toUpperCase();
  const sentinelReady=sentinel==="CLEAN";
  const localReady=malware&&auditValid&&sentinelReady;
  const productionReady=system.assurance?.deployment_complete===true;

  const core=[
    ["Policy engine",signed?"SIGNED":"LOCAL",signed?"Signed deployment policy loaded.":"Deterministic policy engine is active in local mode."],
    ["Malware scanning",malware?"READY":"NOT READY",malware?"ClamAV and signed malware signatures are ready.":(system.malware?.error||"Scanner needs attention.")],
    ["Audit ledger",auditValid?"VALID":"NOT READY",auditValid?"Tamper-evident hash chain verifies.":(system.audit?.error||"Audit needs attention.")],
    ["Agent Sentinel",sentinel,"Current host behavior signal."],
  ];
  $("overview-layers").innerHTML=core.map(item=>layerCard(...item)).join("");
  const coreReady=core.filter(item=>["pass","info"].includes(tone(item[1]))&&item[1]!=="NOT READY").length;
  $("overview-core-score").textContent=coreReady+"/4";

  const sandboxPass=controlStatus(system,"SANDBOX.SECCOMP_STRICT")==="PASS"&&controlStatus(system,"SANDBOX.LANDLOCK")==="PASS";
  const kvmPass=system.vm?.kvm?.status==="PASS";
  $("overview-trust").innerHTML=[
    ["Audit integrity",auditValid?"VALID":"CHECK",auditValid?"Ledger chain verifies.":"Audit verification needs attention."],
    ["Malware admission",malware?"READY":"CHECK",malware?"ClamAV signatures loaded.":"Scanner is not fully ready."],
    ["Host sandbox",sandboxPass?"PASS":"NOT VERIFIED",sandboxPass?"Seccomp and Landlock checks pass.":"Production sandbox proof is separate from local UI readiness."],
    ["MicroVM",kvmPass?"READY":"HOST LIMITED",kvmPass?"KVM hardware access is available.":"KVM is unavailable on this host."],
  ].map(item=>layerCard(...item)).join("");

  const notices=[];
  if(localReady) notices.push(notice("Core local protection is ready","Policy evaluation, malware scanning, audit verification and Sentinel are available.","pass"));
  if(!signed) notices.push(notice("Production policy is not loaded","Local policy testing still works. A signed policy is only required for the production enforcement boundary.","info"));
  if(!kvmPass) notices.push(notice(
    system.environment?.codespaces?"MicroVM is not available in Codespaces":"MicroVM is not available on this host",
    system.environment?.codespaces
      ?"Codespaces does not provide usable KVM access here. Policy, malware, audit and Sentinel still work."
      :"Use a KVM-capable Linux host when you specifically want the hardened MicroVM layer.",
    "info"
  ));
  $("overview-notices").innerHTML=notices.join("");

  if(productionReady){
    $("overview-state").textContent="Production enforcement is ready";
    $("overview-detail").textContent="All required deployment controls pass.";
    $("top-protection").textContent="PRODUCTION READY";
    $("top-protection").className="status-badge pass";
    $("sidebar-state").textContent="PRODUCTION READY";
    $("sidebar-dot").className="pass";
  }else if(localReady){
    $("overview-state").textContent="BULL is ready for local protection";
    $("overview-detail").textContent="Core local services work. Production-only controls remain separate.";
    $("top-protection").textContent="LOCAL READY";
    $("top-protection").className="status-badge pass";
    $("sidebar-state").textContent="LOCAL READY";
    $("sidebar-dot").className="pass";
  }else{
    $("overview-state").textContent="BULL needs attention";
    $("overview-detail").textContent="One or more core local checks are not ready.";
    $("top-protection").textContent="ATTENTION";
    $("top-protection").className="status-badge warn";
    $("sidebar-state").textContent="ATTENTION";
    $("sidebar-dot").className="";
  }

  $("overview-events").innerHTML=events.length
    ? events.slice(-12).reverse().map(event=>'<tr><td>'+esc(event.timestamp?new Date(event.timestamp).toLocaleTimeString():"—")+'</td><td>'+decisionChip(event.decision||event.record_type)+'</td><td>'+esc(event.actor||"runtime")+'</td><td>'+esc(event.operation||"—")+'</td><td>'+esc(event.resource||"—")+'</td><td>'+typeChip(event)+'</td></tr>').join("")
    : '<tr><td colspan="6">No decisions recorded yet. Run a firewall scenario to see the path.</td></tr>';

  const first=selectedScenario||(scenarioCatalog.scenarios?.[0]?.id);
  scenarioButtons($("overview-scenario-list"),first,true);
  if(first) selectScenario(first,true);
}

async function loadFirewall(){
  await getScenarios();
  const first=selectedScenario||(scenarioCatalog.scenarios?.[0]?.id);
  scenarioButtons($("scenario-list"),first,false);
  $("scenario-cards").innerHTML=(scenarioCatalog.scenarios||[]).map(s=>
    '<article class="scenario-card"><small>'+esc(s.category)+'</small><h3>'+esc(s.title)+'</h3><p>'+esc(s.summary)+'</p><footer>'+decisionChip(s.preview?.decision)+'<button class="text-button" data-card-scenario="'+esc(s.id)+'">Open →</button></footer></article>'
  ).join("");
  $$("[data-card-scenario]").forEach(button=>button.addEventListener("click",()=>{
    selectScenario(button.dataset.cardScenario,false);
    window.scrollTo(0,0);
  }));
  if(first) selectScenario(first,false);
}

const actionMap={
  read:{operation:"read",cap:"fs.read.project"},
  write:{operation:"write",cap:"fs.write.project"},
  execute:{operation:"execute",cap:"process.exec"},
  fetch:{operation:"fetch",cap:"network.outbound"},
  post:{operation:"post",cap:"network.post"},
  "credential.read":{operation:"credential.read",cap:"credential.read"},
  spawn:{operation:"spawn",cap:"agent.spawn"},
  message:{operation:"message",cap:"agent.message"},
  security:{operation:"modify",cap:"security_control.write"},
};
function policyExample(type,root){
  return {
    read:root+"/README.md",
    write:root+"/tmp-output.txt",
    execute:"/usr/bin/python3",
    fetch:"https://example.com/",
    post:"https://example.com/api",
    "credential.read":"credential://example/service",
    spawn:"agent://child",
    message:"agent://peer",
    security:"/etc/security-control",
  }[type]||root;
}
async function loadPolicy(){
  const repo=await api("/api/repo");
  if(!$("policy-resource").value) $("policy-resource").value=policyExample($("policy-action").value,repo.root);
}
$("policy-action").addEventListener("change",async()=>{
  const repo=await api("/api/repo");
  $("policy-resource").value=policyExample($("policy-action").value,repo.root);
});
$("policy-evaluate").addEventListener("click",async()=>{
  try{
    const mapping=actionMap[$("policy-action").value];
    const granted=$("policy-authority").value==="granted"?[mapping.cap]:[];
    const result=await post("/api/policy/evaluate",{
      actor:$("policy-actor").value,
      task:"Command Center policy evaluation",
      operation:mapping.operation,
      resource:$("policy-resource").value,
      capability:mapping.cap,
      granted_capabilities:granted,
      provenance:[$("policy-provenance").value],
      external_side_effect:$("policy-side-effect").checked,
      irreversible:$("policy-irreversible").checked,
    });
    $("policy-result").className="policy-result";
    $("policy-result").innerHTML=
      '<div class="decision-hero"><b class="'+String(result.decision).toLowerCase()+'">'+esc(result.decision)+'</b><span>Risk '+Number(result.risk||0).toFixed(2)+(result.hard_block?" · hard block":"")+'</span></div>'+
      '<div class="risk-bar"><i style="width:'+Math.round(Number(result.risk||0)*100)+'%"></i></div>'+
      '<h3>Why BULL decided this</h3>'+
      '<div class="reason-list">'+(result.reasons||[]).map(reason=>'<div>'+esc(reason)+'</div>').join("")+'</div>'+
      '<div class="demo-note">Policy dry-run only. No host effect was executed.</div>';
  }catch(error){
    $("policy-result").className="policy-result human-message";
    $("policy-result").textContent=error.message;
  }
});

async function loadSignals(){
  const [sentinel,adversary]=await Promise.all([api("/api/sentinel"),api("/api/adversary")]);
  $("sentinel-score").textContent=Number(sentinel.score||0).toFixed(3);
  $("sentinel-verdict").textContent=String(sentinel.verdict||"UNKNOWN").toUpperCase();
  $("sentinel-signals").innerHTML=renderReadable(sentinel.signals||{});
  renderRegistry(adversary);
}
$("signals-refresh").addEventListener("click",loadSignals);
function renderRegistry(adversary){
  const rows=adversary.records||[];
  $("registry-rows").innerHTML=rows.length
    ? rows.map(row=>'<tr><td>'+esc(row.attacker_id)+'</td><td>'+esc(row.label)+'</td><td>'+esc(row.swarm_id||"—")+'</td><td>'+esc(row.model_family||"—")+'</td><td>'+(row.quarantined?statusPill("QUARANTINED"):'<button class="text-button" data-q="'+esc(row.attacker_id)+'">Classify quarantine</button>')+'</td></tr>').join("")
    : '<tr><td colspan="5">No observed records yet.</td></tr>';
  $$("[data-q]").forEach(button=>button.addEventListener("click",async()=>{
    try{
      await post("/api/adversary/quarantine",{attacker_id:button.dataset.q});
      toast("Record classified for quarantine","success");
      loadSignals();
    }catch(error){toast(error.message,"error")}
  }));
}
$("agent-scan").addEventListener("click",async()=>{
  try{
    const payload=$("agent-url").value.trim()?{url:$("agent-url").value.trim()}:{text:$("agent-text").value};
    const result=await post("/api/agent-scan",payload);
    const counts=result.counts||{};
    $("agent-scan-summary").className="scan-summary";
    $("agent-scan-summary").innerHTML=
      '<div class="signal-grid">'+["agent","swarm","botnet","endpoint"].map(key=>'<div><small>'+key.toUpperCase()+'</small><b>'+Number(counts[key]||0)+'</b></div>').join("")+'</div>'+
      '<div class="readable">'+readRow("Source",result.source)+readRow("Bytes inspected",result.bytes)+readRow("Meaning",result.note)+'</div>';
    loadSignals();
  }catch(error){
    $("agent-scan-summary").className="scan-summary human-message";
    $("agent-scan-summary").textContent=error.message;
  }
});

async function browse(path="."){
  $("repo-browser").innerHTML='<div class="empty-state">Loading files…</div>';
  const result=await api("/api/files?path="+encodeURIComponent(path));
  currentPath=result.path;
  $("browser-path").textContent=result.path;
  const browser=$("repo-browser");
  browser.innerHTML="";
  if(result.path!=="."){
    const up=document.createElement("button");
    up.className="file-button dir";
    up.textContent="↰ ..";
    up.addEventListener("click",()=>browse(result.path.split("/").slice(0,-1).join("/")||"."));
    browser.appendChild(up);
  }
  result.items.forEach(item=>{
    const button=document.createElement("button");
    button.className="file-button "+(item.dir?"dir":"");
    button.textContent=(item.dir?"▣ ":"· ")+item.name;
    button.addEventListener("click",()=>{
      $("scan-target").value=item.path;
      if(item.dir) browse(item.path); else previewFile(item.path);
    });
    browser.appendChild(button);
  });
}
async function previewFile(path){
  try{
    const result=await api("/api/file?path="+encodeURIComponent(path));
    $("preview-title").textContent=result.path;
    $("file-preview").textContent=result.content;
  }catch(error){
    $("file-preview").textContent=error.message;
  }
}
async function loadFiles(){
  const system=await api("/api/system");
  $("scanner-state").textContent=system.malware?.ready?"READY":(system.malware?.status||"UNAVAILABLE");
  $("scanner-detail").textContent=system.malware?.ready?"ClamAV + signed signatures ready":(system.malware?.error||"Scanner unavailable");
  await browse(currentPath);
}
$("files-refresh").addEventListener("click",loadFiles);
async function runScan(target){
  try{
    $("scan-result").className="scan-result";
    $("scan-result").textContent="Scanning "+target+"…";
    const result=await post("/api/malware/scan",{path:target,timeout:180});
    if(result.clean){
      $("scan-result").innerHTML='<div class="scan-good"><b>✓ CLEAN</b><span>'+Number(result.files_scanned||0).toLocaleString()+' file(s) scanned with '+esc(result.engine||"ClamAV")+'.</span></div>';
    }else{
      $("scan-result").innerHTML='<b style="color:var(--red)">DETECTIONS FOUND</b>'+(result.detections||[]).map(item=>'<div class="scan-detection"><strong>'+esc(item.signature)+'</strong><br>'+esc(item.path)+'</div>').join("");
    }
  }catch(error){
    $("scan-result").innerHTML='<div class="scan-detection">'+esc(error.message)+'</div>';
  }
}
$("scan-target-button").addEventListener("click",()=>runScan($("scan-target").value||"."));
$("scan-all-button").addEventListener("click",()=>{$("scan-target").value=".";runScan(".")});

function checklist(label,status,detail){
  return '<div class="check-row '+tone(status)+'"><i></i><div><b>'+esc(label)+'</b><small>'+esc(detail)+'</small></div><span>'+esc(status)+'</span></div>';
}
async function loadRuntime(){
  const vm=await api("/api/vm");
  const kvmReady=vm.kvm?.status==="PASS";
  const missingTools=Object.entries(vm.tools||{}).filter(([,value])=>!value).map(([key])=>key);
  $("runtime-summary").className="runtime-summary "+(kvmReady?"pass":"warn");
  $("runtime-summary").innerHTML=
    '<div class="runtime-icon">⬢</div><div><h2>'+(kvmReady?"MicroVM host is ready":"MicroVM is unavailable on this host")+'</h2><p>'+
    (kvmReady
      ?"KVM hardware access is available. Guest assets and launcher configuration determine whether a specific launch can proceed."
      :esc(kvmReason(vm))+" Policy, malware scanning, audit and Sentinel still work without the MicroVM layer.")+
    '</p></div>';
  $("runtime-checklist").innerHTML=
    checklist("KVM hardware access",kvmReady?"READY":"HOST LIMITED",kvmReady?"/dev/kvm is usable":kvmReason(vm))+
    checklist("QEMU",vm.tools?.["qemu-system-x86_64"]?"READY":"MISSING",vm.tools?.["qemu-system-x86_64"]||"qemu-system-x86_64 not installed")+
    checklist("Verified guest assets",vm.assets_verified?"READY":"NOT READY",vm.assets_verified?"Guest files verified":vm.asset_error||"Guest assets are not cached yet")+
    checklist("Launcher configuration",vm.microvm_config?"READY":"OPTIONAL",vm.microvm_config||"No private launcher config supplied");
  $("vm-run").disabled=!kvmReady||missingTools.length>0;
  $("runtime-advanced").innerHTML=renderReadable({
    mode:vm.architecture?.mode,
    control_channel:vm.architecture?.control_channel,
    audit_channel:vm.architecture?.audit_channel,
    software_emulation_fallback:vm.architecture?.software_emulation_fallback,
  });
  await refreshJobs();
}
$("runtime-refresh").addEventListener("click",loadRuntime);
async function refreshJobs(){
  try{
    const jobs=await api("/api/jobs");
    $("job-list").innerHTML=jobs.length
      ? jobs.map(job=>'<button class="job-item" data-job="'+esc(job.id)+'"><b class="'+String(job.status).toLowerCase()+'">'+esc(job.status)+'</b><span>'+esc(job.command_label)+'</span><small>'+esc(new Date((job.started||0)*1000).toLocaleString())+'</small></button>').join("")
      : '<div class="job-log empty">No runtime jobs launched in this session.</div>';
    $$("[data-job]").forEach(button=>button.addEventListener("click",()=>selectJob(button.dataset.job)));
    if(selectedJob) await selectJob(selectedJob,false);
  }catch(error){toast(error.message,"error")}
}
async function selectJob(id,remember=true){
  if(remember) selectedJob=id;
  try{
    const [job,log]=await Promise.all([
      api("/api/job?id="+encodeURIComponent(id)),
      api("/api/job/log?id="+encodeURIComponent(id)),
    ]);
    $("job-log").className="job-log";
    $("job-log").innerHTML=readRow("Status",job.status)+readRow("Operation",job.command_label)+readRow("Evidence directory",job.output_dir)+'<pre>'+esc(log.log||"No log output yet.")+'</pre>';
  }catch(error){$("job-log").textContent=error.message}
}
$("jobs-refresh").addEventListener("click",refreshJobs);
$("vm-install-assets").addEventListener("click",async()=>{try{const job=await post("/api/vm/install-assets");selectedJob=job.id;toast("Verified guest download started","success");refreshJobs()}catch(error){toast(error.message,"error")}});
$("vm-plan").addEventListener("click",async()=>{try{const result=await api("/api/microvm/plan");$("job-log").className="job-log";$("job-log").innerHTML=readRow("Validated",result.validated?"YES":"NO")+'<pre>'+esc(result.output||"No output")+'</pre>'}catch(error){toast(error.message,"error")}});
$("vm-run").addEventListener("click",async()=>{try{const job=await post("/api/vm/run",{case:$("vm-case").value});selectedJob=job.id;toast("MicroVM integration job started","success");refreshJobs()}catch(error){toast(error.message,"error")}});
$("deployment-run").addEventListener("click",async()=>{try{const job=await post("/api/deployment/run");selectedJob=job.id;toast("Deployment check started","success");refreshJobs()}catch(error){toast(error.message,"error")}});

async function loadAudit(){
  const [audit,events]=await Promise.all([api("/api/audit"),api("/api/audit/events?limit=200")]);
  $("audit-configured").textContent=audit.configured?"YES":"NO";
  $("audit-valid").textContent=audit.valid===true?"VALID":audit.valid===false?"INVALID":"—";
  $("audit-records").textContent=Number(audit.records||0).toLocaleString();
  $("audit-head").textContent=(audit.head_hash||"—").slice(0,12);
  $("audit-rows").innerHTML=events.length
    ? events.reverse().map(event=>'<tr><td>'+esc(event.timestamp?new Date(event.timestamp).toLocaleString():"—")+'</td><td>'+decisionChip(event.decision||event.record_type)+'</td><td>'+esc(event.actor||"runtime")+'</td><td>'+esc(event.operation||"—")+'</td><td>'+esc(event.capability||"—")+'</td><td>'+esc(event.resource||"—")+'</td><td>'+typeChip(event)+'</td><td>'+esc((event.reasons||[]).join("; ")||"—")+'</td></tr>').join("")
    : '<tr><td colspan="8">No audit events recorded.</td></tr>';
}
$("audit-refresh").addEventListener("click",loadAudit);

async function loadAssurance(){
  const report=await api("/api/assurance");
  const controls=report.controls||[];
  const phases=["source","deployment","release","external"];
  $("assurance-summary").innerHTML=phases.map(phase=>{
    const rows=controls.filter(item=>item.phase===phase);
    const passed=rows.filter(item=>["PASS","IMPLEMENTED"].includes(item.status)).length;
    return '<article><small>'+phase.toUpperCase()+'</small><strong>'+passed+'/'+rows.length+'</strong><span>controls passing</span></article>';
  }).join("");
  $("assurance-groups").innerHTML=phases.map(phase=>{
    const rows=controls.filter(item=>item.phase===phase);
    return '<section class="assurance-group"><header><h2>'+phase[0].toUpperCase()+phase.slice(1)+'</h2><span>'+rows.length+' controls</span></header>'+
      rows.map(item=>'<div class="assurance-row"><div>'+statusPill(item.status)+'</div><div><h3>'+esc(item.title||item.id)+'</h3><p>'+esc(item.detail||"No additional detail.")+'</p><code>'+esc(item.id)+'</code></div></div>').join("")+
      '</section>';
  }).join("");
}
$("assurance-refresh").addEventListener("click",loadAssurance);

const configLabels={
  policy_bundle:["Signed production policy","Required for the production authority ceiling."],
  integrity_manifest:["Signed runtime integrity","Verifies the trusted runtime files in production."],
  microvm_configured:["MicroVM configuration","Private launcher configuration for hardened KVM runs."],
  audit_ledger:["Audit ledger","Local tamper-evident decision history."],
  remote_anchor:["Remote audit anchor","External checkpoint destination for production evidence."],
  seccomp_profile:["Seccomp profile","System-call restriction profile used by the sandbox."],
  cgroup_parent:["Delegated cgroup","Resource-control boundary for sandboxed workloads."],
  snapshot_root:["Snapshot scratch","Private storage for bounded execution snapshots."],
  hardware_approval:["Hardware approval","Optional enrolled physical approval authority."],
};
function configStatus(key,value){
  if(key==="seccomp_profile") return value&&value!=="unset"?["READY",String(value)]:["NOT SET","No profile configured for this session."];
  return value?["READY","Configured"]:["NOT SET",configLabels[key]?.[1]||"Not configured"];
}
function renderDependencies(deps){
  $("dependency-grid").innerHTML=(deps.items||[]).map(item=>
    '<div class="dependency-row '+(item.installed?"pass":"")+'"><i></i><div><b>'+esc(item.label)+'</b><small>'+esc(item.command)+(item.id==="clamav"?" · signatures "+(item.database_ready?"ready":"missing"):"")+'</small></div><span>'+(item.installed?"READY":"MISSING")+'</span></div>'
  ).join("");
}
async function loadSystem(){
  const [system,deps,brand]=await Promise.all([api("/api/system"),api("/api/host/dependencies"),api("/api/brand")]);
  renderDependencies(deps);
  $("runtime-config").innerHTML=Object.entries(system.runtime||{}).map(([key,value])=>{
    const [state,detail]=configStatus(key,value);
    const label=configLabels[key]?.[0]||key.replace(/_/g," ");
    return '<div class="config-row"><div><strong>'+esc(label)+'</strong><p>'+esc(detail)+'</p></div>'+statusPill(state)+'</div>';
  }).join("");
  $("brand-meta").innerHTML=
    '<strong>'+esc(brand.revision||"Approved BULL identity")+'</strong><br>'+
    'Source: '+esc(brand.source?.file||"approved brand source")+' · '+esc(brand.source?.note||"");
}
$("system-install").addEventListener("click",async()=>{
  try{
    const job=await post("/api/host/install");
    selectedJob=job.id;
    toast("Host dependency repair started","success");
    openView("runtime");
  }catch(error){toast(error.message,"error")}
});

const initial=(location.hash||"#overview").slice(1);
openView(initial);
setInterval(()=>{if($("view-overview").classList.contains("active")&&!presentation)loadOverview().catch(()=>{})},6000);
