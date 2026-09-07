#include "web.h"

#include <cstdio>
#include <cstring>

#include <LittleFS.h>
#include <Preferences.h>
#include <uri/UriGlob.h>

namespace WebUI {

WebServer server(80);
DNSServer dnsServer;
Preferences preferences;

namespace {

bool english = false;

bool streamBufferResponse(const char* contentType, const char* filename, const uint8_t* data, size_t size) {
    if (!data || size == 0) {
        return false;
    }

    server.sendHeader("Access-Control-Allow-Origin", "*");
    server.sendHeader("Content-Disposition", String("attachment; filename=") + filename);
    server.setContentLength(size);
    server.send(200, contentType, "");

    WiFiClient client = server.client();
    const size_t chunkSize = 1024;
    size_t offset = 0;
    while (offset < size) {
        size_t toWrite = size - offset;
        if (toWrite > chunkSize) toWrite = chunkSize;
        size_t written = client.write(data + offset, toWrite);
        if (written != toWrite) {
            return false;
        }
        offset += written;
        delay(0);
    }
    return true;
}

bool streamFileResponse(const char* path, const char* contentType, const char* filename) {
    File file = LittleFS.open(path, FILE_READ);
    if (!file || file.size() == 0) {
        if (file) file.close();
        return false;
    }

    server.sendHeader("Access-Control-Allow-Origin", "*");
    server.sendHeader("Content-Disposition", String("attachment; filename=") + filename);
    server.setContentLength(file.size());
    server.send(200, contentType, "");

    WiFiClient client = server.client();
    uint8_t buffer[1024];
    while (file.available()) {
        size_t n = file.read(buffer, sizeof(buffer));
        if (n == 0) break;
        size_t written = client.write(buffer, n);
        if (written != n) {
            file.close();
            return false;
        }
        delay(0);
    }

    file.close();
    return true;
}

}  // namespace

const char MAIN_PAGE[] PROGMEM = R"rawliteral(
<!DOCTYPE html>
<html lang="zh-CN" id="page">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>ESP32-S3 WiFi Handshake Sniffer</title>
<style>
:root{--bg:#f5f7fb;--card:#fff;--accent:#0f766e;--accent2:#0ea5e9;--text:#172033;--muted:#63708a;--border:#d9e1ee;--ok:#15803d;--warn:#b45309;--shadow:0 12px 32px rgba(15,23,42,.08)}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI','PingFang SC','Microsoft YaHei',sans-serif;background:linear-gradient(180deg,#eef4ff 0,#f8fbff 180px,#f5f7fb 100%);color:var(--text);padding:18px}
.wrap{max-width:920px;margin:0 auto}
.hero{display:flex;justify-content:space-between;gap:16px;align-items:flex-start;margin-bottom:18px}
.hero h1{font-size:1.5rem}
.hero p{color:var(--muted);margin-top:6px}
.pill{padding:8px 12px;border-radius:999px;background:#e6fffb;color:#0f766e;font-size:.84rem;font-weight:700}
.card{background:var(--card);border:1px solid var(--border);border-radius:18px;box-shadow:var(--shadow);padding:20px;margin-bottom:16px}
.card h2{font-size:1.02rem;margin-bottom:14px}
.tip{font-size:.84rem;color:var(--muted);margin-top:-6px;margin-bottom:14px}
.row{display:flex;gap:12px;flex-wrap:wrap}
.col{flex:1;min-width:180px}
.check{display:flex;align-items:center;gap:8px;margin-top:14px;color:var(--muted);font-size:.84rem;font-weight:700}.check input{width:auto}
label{display:block;font-size:.82rem;color:var(--muted);margin-bottom:6px;font-weight:700}
input,select{width:100%;padding:10px 12px;border:1.5px solid var(--border);border-radius:12px;background:#fbfdff;font-size:.92rem}
button{border:none;border-radius:12px;padding:10px 16px;font-weight:700;cursor:pointer}
.primary{background:var(--accent);color:#fff}
.ghost{background:#ecfeff;color:#0f766e}
.danger{background:#fee2e2;color:#b91c1c}
.actions{display:flex;gap:10px;flex-wrap:wrap;margin-top:12px}
table{width:100%;border-collapse:collapse;font-size:.87rem}
th,td{padding:10px 8px;border-bottom:1px solid var(--border);text-align:left}
th{color:var(--muted);font-size:.76rem;text-transform:uppercase}
.mono{font-family:Consolas,monospace}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px}
.stat{background:#f7fafc;border:1px solid var(--border);border-radius:14px;padding:14px;text-align:center}
.stat strong{display:block;font-size:1.35rem;color:var(--accent2)}
.status{font-weight:700}
.hint{margin-top:10px;margin-bottom:10px;font-size:.82rem;color:var(--warn);line-height:1.45}
.hint + .tip{margin-top:0}
.fileRow{display:flex;align-items:center;justify-content:space-between;gap:10px;padding:8px 0;border-bottom:1px solid var(--border);font-size:.82rem}.fileRow:last-child{border-bottom:0}.fileRow span{overflow-wrap:anywhere}.fileRow button{padding:7px 10px;font-size:.78rem;flex:none}
.overlay{position:fixed;inset:0;background:rgba(15,23,42,.72);display:none;align-items:center;justify-content:center;padding:18px;z-index:20}
.overlay.show{display:flex}
.dialog{max-width:420px;width:100%;background:#fff;border-radius:20px;padding:24px;box-shadow:0 20px 50px rgba(15,23,42,.22);text-align:center}
.dialog h3{font-size:1.15rem;margin-bottom:10px}
.dialog p{color:var(--muted);line-height:1.6}
.count{font-size:2.4rem;font-weight:800;color:var(--accent2);margin:14px 0}
@media(max-width:640px){body{padding:10px}.hero{flex-direction:column}.card{padding:16px}.hero h1{font-size:1.25rem}.hero>.actions{width:100%;align-items:center}.hero>.actions .pill{margin-left:auto}.card table{table-layout:fixed;font-size:.72rem}.card th,.card td{padding:8px 4px;overflow:hidden}.card th:nth-child(1),.card td:nth-child(1){width:27%}.card th:nth-child(2),.card td:nth-child(2){width:39%}.card th:nth-child(4),.card td:nth-child(4){width:14%}.card th:nth-child(6),.card td:nth-child(6){width:20%}.card th:nth-child(3),.card td:nth-child(3),.card th:nth-child(5),.card td:nth-child(5){display:none}.mono{font-size:.62rem;word-break:break-all}.card td button{padding:8px 7px;font-size:.72rem}}
</style>
</head>
<body>
<div class="wrap">
  <div class="hero">
    <div>
      <h1>ESP32-S3 WiFi Handshake Sniffer</h1>
      <p id="intro">仅用于被动监听握手包 / PMKID。启动抓包后，管理热点会暂时断开，停止后恢复。</p>
    </div>
    <div class="actions" style="margin-top:0"><button class="ghost" id="languageToggle" onclick="toggleLanguage()">English</button><div class="pill" id="apState">管理热点在线</div></div>
  </div>

  <div class="card">
    <h2 id="scanTitle">WiFi 扫描</h2>
    <div class="actions">
      <button class="primary" id="scanBtn" onclick="scanNetworks()">扫描附近 AP</button>
      <span class="tip" id="scanStatus"></span>
    </div>
    <div style="overflow:auto;margin-top:12px">
      <table>
        <thead><tr><th>SSID</th><th>BSSID</th><th>RSSI</th><th id="channelHead">信道</th><th id="encryptionHead">加密</th><th></th></tr></thead>
        <tbody id="scanBody"><tr><td colspan="6" style="text-align:center;color:#94a3b8;padding:20px" id="scanEmpty">点击扫描加载周边网络</td></tr></tbody>
      </table>
    </div>
  </div>

  <div class="card">
    <h2 id="captureTitle">被动抓包</h2>
    <div class="tip" id="captureTip">建议先选择目标 AP，再固定目标信道监听。全信道模式会保存更多包，但噪声更高。</div>
    <div class="row">
      <div class="col">
        <label id="modeLabel">抓取模式</label>
        <select id="capMode" onchange="toggleMode();saveCaptureConfig()">
          <option value="target" id="targetMode">目标 BSSID 过滤</option>
          <option value="full" id="fullMode">整信道监听</option>
        </select>
      </div>
      <div class="col" id="bssidCol">
        <label id="bssidLabel">目标 AP（可多选）</label>
        <input id="capBssid" maxlength="17" placeholder="AA:BB:CC:DD:EE:FF" onchange="selectedTargets=[];renderSelectedTargets();saveCaptureConfig()">
        <div class="tip" id="targetSelectionHint">也可点击上方扫描结果中的“添加”来选择多个 AP。</div>
        <div id="selectedTargetsBox" class="mono" style="font-size:.76rem"></div>
      </div>
      <div class="col">
        <label id="channelLabel">监听信道</label>
        <input id="capChannel" type="number" min="1" max="14" value="1" onchange="saveCaptureConfig()">
      </div>
    </div>
    <div class="actions">
      <button class="primary" id="startBtn" onclick="captureStart()">开始监听</button>
      <button class="danger" id="stopBtn" onclick="captureStop()" disabled>停止监听</button>
      <button class="ghost" id="pcapBtn" onclick="downloadPcap()" disabled>下载 .pcap</button>
      <button class="ghost" id="pmkidBtn" onclick="downloadPmkid()" disabled>下载 .22000</button>
    </div>
    <div class="hint" id="captureHint">抓包开始后 Web 页面可能短暂断开；停止监听后重新连接 `esp32-s3-whs` 即可。</div>
    <div class="tip" id="latestHint">最近一次抓包会在停止监听后自动保存到设备 Flash。</div>
  </div>

  <div class="card">
    <h2 id="statusTitle">抓取状态</h2>
    <div class="stats">
      <div class="stat"><span id="statusLabel">状态</span><strong id="capStatus" class="status">空闲</strong></div>
      <div class="stat"><span id="targetFramesLabel">目标帧</span><strong id="capFrames">0</strong></div>
      <div class="stat"><span id="rawFramesLabel">信道原始帧</span><strong id="capRawFrames">0</strong></div>
      <div class="stat"><span>EAPOL</span><strong id="capEapol">0</strong></div>
      <div class="stat"><span>PMKID</span><strong id="capPmkid">0</strong></div>
      <div class="stat"><span id="summaryLabel">摘要</span><strong id="capSummary" style="font-size:.92rem">idle</strong></div>
    </div>
  </div>

  <div class="card">
    <h2 id="savedTitle">已保存抓包</h2>
    <div class="tip" id="savedTip">只有在停止监听后，当前会话才会保存到设备 Flash。这里显示的是最近一次已保存结果。</div>
    <div class="stats">
      <div class="stat"><span>PCAP</span><strong id="savedPcapSize">0 B</strong></div>
      <div class="stat"><span>22000</span><strong id="savedPmkidSize">0 B</strong></div>
      <div class="stat"><span id="reportLabel">报告</span><strong id="savedMetaSize">0 B</strong></div>
      <div class="stat"><span id="savedStateLabel">保存状态</span><strong id="savedState" style="font-size:.92rem">无</strong></div>
      <div class="stat"><span id="storageLabel">LittleFS 可用空间</span><strong id="storageFree">0 B</strong></div>
    </div>
    <div class="actions">
      <button class="ghost" id="savedPcapBtn" onclick="downloadSavedPcap()" disabled>下载已保存 .pcap</button>
      <button class="ghost" id="savedPmkidBtn" onclick="downloadSavedPmkid()" disabled>下载已保存 .22000</button>
      <button class="ghost" id="savedMetaBtn" onclick="downloadSavedMeta()" disabled>下载报告 .json</button>
      <button class="danger" id="clearSavedBtn" onclick="clearSaved()" disabled>清除已保存</button>
      <button class="danger" id="clearAllFilesBtn" onclick="clearAllFiles()">删除 LittleFS 全部文件</button>
    </div>
    <div class="tip" id="filesTitle" style="margin-top:16px">所有已保存会话</div>
    <div id="savedFiles"><span id="filesEmpty">暂无已保存文件</span></div>
  </div>
</div>
<div class="overlay" id="countdownOverlay">
  <div class="dialog">
    <h3 id="countdownTitle">即将进入监听模式</h3>
    <p id="countdownText">管理热点会暂时关闭，当前网页连接将中断。停止监听后，重新连接 <strong>esp32-s3-whs</strong> 查看结果。</p>
    <div class="count" id="countdownValue">3</div>
    <div class="actions" style="justify-content:center">
      <button class="danger" id="cancelBtn" type="button" onclick="cancelCountdown()">取消</button>
    </div>
  </div>
</div>
<script>
function $(id){return document.getElementById(id)}
function esc(s){var d=document.createElement('div');d.textContent=s;return d.innerHTML}
let english=false;
function encMap(v){var m=english?{0:'Open',1:'WEP',2:'WPA',3:'WPA2',4:'WPA/WPA2',5:'WPA2 Enterprise',6:'WPA3',7:'WPA2/3'}:{0:'开放',1:'WEP',2:'WPA',3:'WPA2',4:'WPA/WPA2',5:'WPA2-企业',6:'WPA3',7:'WPA2/3'};return m[v]||('#'+v)}
let countdownTimer=null;
let pendingCaptureBody=null;
let captureConfigLoaded=false;
let selectedTargets=[];
let scannedNetworks=[];

const text={
  zh:{intro:'仅用于被动监听握手包 / PMKID。启动抓包后，管理热点会暂时断开，停止后恢复。',scanTitle:'WiFi 扫描',scanBtn:'扫描附近 AP',channelHead:'信道',encryptionHead:'加密',scanEmpty:'点击扫描加载周边网络',captureTitle:'被动抓包',captureTip:'可选择多个目标 AP；同信道会同时过滤，不同信道每 10 分钟轮换一次。',modeLabel:'抓取模式',targetMode:'目标 BSSID 过滤',fullMode:'整信道监听',bssidLabel:'目标 AP（可多选）',targetSelectionHint:'点击上方扫描结果中的“添加”来选择多个 AP，也可手动输入一个 BSSID。',channelLabel:'监听信道',startBtn:'开始监听',stopBtn:'停止监听',pcapBtn:'下载 .pcap',pmkidBtn:'下载 .22000',captureHint:'抓包开始后 Web 页面可能短暂断开；停止监听后重新连接 `esp32-s3-whs` 即可。',latestHint:'最近一次抓包会在停止监听后自动保存到设备 Flash。',statusTitle:'抓取状态',statusLabel:'状态',targetFramesLabel:'目标帧',rawFramesLabel:'信道原始帧',summaryLabel:'摘要',savedTitle:'已保存抓包',savedTip:'只有在停止监听后，当前会话才会保存到设备 Flash。这里显示的是最近一次已保存结果。',reportLabel:'报告',savedStateLabel:'保存状态',storageLabel:'LittleFS 可用空间',filesTitle:'所有已保存会话',filesEmpty:'暂无已保存文件',savedPcapBtn:'下载已保存 .pcap',savedPmkidBtn:'下载已保存 .22000',savedMetaBtn:'下载报告 .json',clearSavedBtn:'清除已保存',autoStartLabel:'启动时自动开始上次配置',countdownTitle:'即将进入监听模式',countdownText:'管理热点会暂时关闭，当前网页连接将中断。停止监听后，重新连接 <strong>esp32-s3-whs</strong> 查看结果。',cancelBtn:'取消'},
  en:{intro:'For authorized passive handshake / PMKID monitoring only. The management AP disconnects during capture and returns afterward.',scanTitle:'WiFi scan',scanBtn:'Scan nearby APs',channelHead:'Channel',encryptionHead:'Security',scanEmpty:'Click scan to load nearby networks',captureTitle:'Passive capture',captureTip:'Select multiple target APs; same-channel targets are filtered together, and different channels rotate every 10 minutes.',modeLabel:'Capture mode',targetMode:'Target BSSID filter',fullMode:'Full-channel listen',bssidLabel:'Target APs (multiple)',targetSelectionHint:'Click “Add” in the scan results to select multiple APs, or enter one BSSID manually.',channelLabel:'Listen channel',startBtn:'Start listening',stopBtn:'Stop listening',pcapBtn:'Download .pcap',pmkidBtn:'Download .22000',captureHint:'The Web page may disconnect during capture; reconnect to `esp32-s3-whs` after stopping.',latestHint:'The latest capture will be saved to device flash after listening stops.',statusTitle:'Capture status',statusLabel:'Status',targetFramesLabel:'Target frames',rawFramesLabel:'Raw channel frames',summaryLabel:'Summary',savedTitle:'Saved captures',savedTip:'The current session is saved to device flash only after listening stops. The latest saved result is shown here.',reportLabel:'Report',savedStateLabel:'Save status',storageLabel:'LittleFS free space',filesTitle:'All saved sessions',filesEmpty:'No saved files',savedPcapBtn:'Download saved .pcap',savedPmkidBtn:'Download saved .22000',savedMetaBtn:'Download report .json',clearSavedBtn:'Clear saved',autoStartLabel:'Start the saved configuration at boot',countdownTitle:'Entering listening mode',countdownText:'The management AP will close temporarily and this page will disconnect. Reconnect to <strong>esp32-s3-whs</strong> after stopping to view results.',cancelBtn:'Cancel'}
};
function applyLanguage(){const d=text[english?'en':'zh'];Object.keys(d).forEach(id=>{const e=$(id);if(e)e.innerHTML=d[id]});$('page').lang=english?'en':'zh-CN';$('languageToggle').textContent=english?'中文':'English';$('apState').textContent=english?'Management AP online':'管理热点在线';$('capStatus').textContent=english?'Idle':'空闲';$('savedState').textContent=english?'None':'无';$('clearAllFilesBtn').textContent=english?'Delete all LittleFS files':'删除 LittleFS 全部文件'}
async function loadPreferences(){try{const r=await fetch('/api/preferences');const d=await r.json();english=d.language==='en';applyLanguage()}catch(e){}}
async function toggleLanguage(){english=!english;applyLanguage();try{await fetch('/api/preferences',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({language:english?'en':'zh'})})}catch(e){}}
function currentTargets(){
  if(selectedTargets.length)return selectedTargets.map(t=>({bssid:t.bssid,channel:Number(t.channel)||1,ssid:t.ssid||''}));
  const bssid=$('capBssid').value.trim(), channel=parseInt($('capChannel').value,10)||1;
  if(!/^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$/.test(bssid))return [];
  return [{bssid:bssid,channel:channel}];
}

async function saveCaptureConfig(){
  const mode=$('capMode').value, targets=currentTargets();
  if(mode!=='full'&&!targets.length)return;
  const first=targets[0]||{};
  try{await fetch('/api/capture/config',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({mode:mode,bssid:first.bssid||'',channel:first.channel||1,targets:targets})})}catch(e){}
}

window.addEventListener('DOMContentLoaded',()=>{toggleMode();loadPreferences();loadSavedFiles();pollStatus();setInterval(pollStatus,2000);setInterval(loadSavedFiles,10000)})

function toggleMode(){
  $('bssidCol').style.display=$('capMode').value==='full'?'none':'block'
}

function targetSelected(bssid){return selectedTargets.some(t=>t.bssid.toUpperCase()===bssid.toUpperCase())}
function renderSelectedTargets(){
  const box=$('selectedTargetsBox');if(!box)return;
  if(!selectedTargets.length){box.textContent=english?'No multiple targets selected':'尚未选择多个目标 AP';return}
  box.innerHTML=selectedTargets.map((t,i)=>'<div style="display:flex;align-items:center;gap:6px;margin-top:5px"><span>'+esc(t.ssid||'<hidden>')+' '+esc(t.bssid)+' / ch '+Number(t.channel)+'</span><button class="ghost" type="button" data-remove-target="'+i+'">'+(english?'Remove':'移除')+'</button></div>').join('')
}

async function scanNetworks(){
  $('scanBtn').disabled=true;$('scanStatus').textContent=english?'Scanning...':'扫描中...';
  try{
    const r=await fetch('/api/scan');const d=await r.json();scannedNetworks=d||[];renderTable(scannedNetworks);$('scanStatus').textContent=''
  }catch(e){$('scanStatus').textContent=english?'Scan failed':'扫描失败'}
  $('scanBtn').disabled=false
}

function renderTable(nets){
  if(nets&&nets.length)scannedNetworks=nets;
  const body=$('scanBody');
  if(!nets||!nets.length){body.innerHTML='<tr><td colspan="6" style="text-align:center;color:#94a3b8;padding:20px">'+(english?'No APs found':'未发现 AP')+'</td></tr>';return}
  let h='';
  nets.forEach(n=>{
    h+='<tr>';
    h+='<td>'+esc(n.ssid||'<hidden>')+'</td>';
    h+='<td class="mono">'+esc(n.bssid||'')+'</td>';
    h+='<td>'+(n.rssi??'')+'</td>';
    h+='<td>'+(n.channel??'')+'</td>';
    h+='<td>'+esc(encMap(n.encryption))+'</td>';
    h+='<td><button class="ghost" type="button" data-bssid="'+esc(n.bssid||'')+'" data-channel="'+(n.channel||1)+'" data-ssid="'+encodeURIComponent(n.ssid||'')+'">'+(targetSelected(n.bssid||'')?(english?'Remove':'移除'):(english?'Add':'添加'))+'</button></td>';
    h+='</tr>';
  });
  body.innerHTML=h
}

document.addEventListener('click',e=>{
  const remove=e.target.closest('button[data-remove-target]');
  if(remove){selectedTargets.splice(Number(remove.dataset.removeTarget),1);renderSelectedTargets();renderTable(scannedNetworks);saveCaptureConfig();return}
  const btn=e.target.closest('button[data-bssid]');
  if(!btn)return;
  const bssid=btn.dataset.bssid||'';
  const existing=selectedTargets.findIndex(t=>t.bssid.toUpperCase()===bssid.toUpperCase());
  if(existing>=0){selectedTargets.splice(existing,1)}else{
    if(selectedTargets.length>=8){alert(english?'You can select up to 8 APs':'最多只能选择 8 个 AP');return}
    selectedTargets.push({bssid:bssid,channel:Number(btn.dataset.channel)||1,ssid:decodeURIComponent(btn.dataset.ssid||'')});
  }
  $('capBssid').value=selectedTargets[0]?.bssid||'';
  $('capChannel').value=selectedTargets[0]?.channel||btn.dataset.channel||'1';
  $('capMode').value='target';
  toggleMode();
  renderSelectedTargets();
  saveCaptureConfig();
})

async function captureStart(){
  const mode=$('capMode').value;
  const targets=currentTargets();
  if(mode!=='full'&&!targets.length){alert(english?'Select or enter at least one target AP':'请选择或输入至少一个目标 AP');return}
  const first=targets[0]||{};
  pendingCaptureBody={mode:mode,bssid:first.bssid||'',channel:first.channel||1,targets:targets};
  beginCountdown()
}

function beginCountdown(){
  cancelCountdown(false);
  let remaining=3;
  $('countdownValue').textContent=String(remaining);
  $('countdownOverlay').classList.add('show');
  countdownTimer=setInterval(async()=>{
    remaining--;
    $('countdownValue').textContent=String(remaining);
    if(remaining<=0){
      cancelCountdown(false);
      await startCaptureRequest();
    }
  },1000)
}

function cancelCountdown(clearPending=true){
  if(countdownTimer){clearInterval(countdownTimer);countdownTimer=null}
  $('countdownOverlay').classList.remove('show');
  if(clearPending)pendingCaptureBody=null
}

async function startCaptureRequest(){
  if(!pendingCaptureBody)return;
  try{
    const r=await fetch('/api/capture/start',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(pendingCaptureBody)});
    const d=await r.json();
    if(d.status==='ok'){
      $('startBtn').disabled=true;$('stopBtn').disabled=false;$('capStatus').textContent=english?'Listening':'监听中'
    }else if(d.msg){alert(d.msg)}
  }catch(e){console.error(e)}
  pendingCaptureBody=null
}

async function captureStop(){
  try{
    const r=await fetch('/api/capture/stop',{method:'POST'});
    const d=await r.json();
    if(d.status==='ok'){
      $('startBtn').disabled=false;$('stopBtn').disabled=true;$('capStatus').textContent=english?'Stopped':'已停止'
      loadSavedFiles()
    }
  }catch(e){console.error(e)}
}

function downloadPcap(){window.open('/api/capture/download','_blank')}
function downloadPmkid(){window.open('/api/capture/pmkid','_blank')}
function downloadSavedPcap(){window.open('/api/capture/download?source=latest','_blank')}
function downloadSavedPmkid(){window.open('/api/capture/pmkid?source=latest','_blank')}
function downloadSavedMeta(){window.open('/api/capture/meta','_blank')}

async function clearSaved(){
  try{
    const r=await fetch('/api/capture/clear',{method:'POST'});
    const d=await r.json();
    if(d.status==='ok'){pollStatus();loadSavedFiles()}
  }catch(e){console.error(e)}
}

async function clearAllFiles(){
  const message=english?'Delete every file on LittleFS? This cannot be undone.':'删除 LittleFS 上的全部文件？此操作不可撤销。';
  if(!confirm(message))return;
  try{
    const r=await fetch('/api/capture/clear-all',{method:'POST'});
    const d=await r.json();
    if(d.status==='ok'){pollStatus();loadSavedFiles()}
    else if(d.msg)alert(d.msg);
  }catch(e){console.error(e)}
}

function fmtSize(n){
  n=Number(n||0);
  if(n<1024)return n+' B';
  if(n<1024*1024)return (n/1024).toFixed(1)+' KB';
  return (n/1024/1024).toFixed(2)+' MB';
}

async function loadSavedFiles(){
  try{
    const r=await fetch('/api/capture/files');
    if(!r.ok) throw new Error('HTTP '+r.status);
    const files=await r.json();const box=$('savedFiles');
    if(!files||!files.length){box.innerHTML='<span id="filesEmpty">'+(english?'No saved files':'暂无已保存文件')+'</span>';return}
    box.innerHTML=files.map(f=>'<div class="fileRow"><span>'+esc(f.name)+' ('+fmtSize(f.size)+')</span><button class="ghost" onclick="downloadFile(\''+encodeURIComponent(f.name)+'\')">'+(english?'Download':'下载')+'</button></div>').join('');
  }catch(e){
    console.warn('Unable to load saved files',e);
    const box=$('savedFiles');
    if(box) box.innerHTML='<span id="filesEmpty">'+(english?'Saved-file list unavailable':'已保存文件列表不可用')+'</span>';
  }
}
function downloadFile(name){window.open('/api/capture/file?name='+name,'_blank')}

async function pollStatus(){
  try{
    const r=await fetch('/api/capture/status');const d=await r.json();
    if(!captureConfigLoaded){
      if(d.savedConfig){
        $('capMode').value=d.savedFull?'full':'target';
        if(Array.isArray(d.savedTargets)&&d.savedTargets.length){
          selectedTargets=d.savedTargets.slice(0,8);
          $('capBssid').value=selectedTargets[0].bssid||'';
          $('capChannel').value=selectedTargets[0].channel||1;
        }else{
          selectedTargets=[];
          $('capChannel').value=d.savedChannel||1;
          $('capBssid').value=d.savedBssid||'';
        }
        toggleMode();renderSelectedTargets()
      }
      captureConfigLoaded=true;
    }
    $('capStatus').textContent=d.running?(english?'Listening':'监听中'):(english?'Idle':'空闲');
    $('capFrames').textContent=d.frames||0;
    $('capRawFrames').textContent=d.rawFrames||0;
    $('capEapol').textContent=d.eapol||0;
    $('capPmkid').textContent=d.pmkidCount||0;
    $('capSummary').textContent=d.summary||'idle';
    $('startBtn').disabled=!!d.running;
    $('stopBtn').disabled=!d.running;
    $('pcapBtn').disabled=!(!d.running && ((d.size||0)>24 || (d.latestPcapSize||0)>24));
    $('pmkidBtn').disabled=!((d.pmkidSize||0)>0 || (d.latestPmkidSize||0)>0);
    $('savedPcapSize').textContent=fmtSize(d.latestPcapSize||0);
    $('savedPmkidSize').textContent=fmtSize(d.latestPmkidSize||0);
    $('savedMetaSize').textContent=fmtSize(d.latestMetaSize||0);
    $('storageFree').textContent=fmtSize(d.fsFree||0)+' / '+fmtSize(d.fsTotal||0);
    $('savedState').textContent=(d.latestPcapSize||0)>24 || (d.latestPmkidSize||0)>0 || (d.latestMetaSize||0)>0 ? (english?'Saved results available':'有已保存结果') : (english?'None':'无');
    $('savedPcapBtn').disabled=!((d.latestPcapSize||0)>24);
    $('savedPmkidBtn').disabled=!((d.latestPmkidSize||0)>0);
    $('savedMetaBtn').disabled=!((d.latestMetaSize||0)>0);
    $('clearSavedBtn').disabled=!((d.latestPcapSize||0)>0 || (d.latestPmkidSize||0)>0 || (d.latestMetaSize||0)>0);
    $('clearAllFilesBtn').disabled=!!d.running;
    $('apState').textContent=d.apActive?(english?'Management AP online':'管理热点在线'):(english?'Capture mode':'监听模式中');
    if(!d.running&&(d.latestPcapSize||0)>24){$('latestHint').textContent=english?'The latest capture is saved in device flash and ready to download.':'最近一次抓包已保存在设备 Flash，可直接下载。'}
    else{$('latestHint').textContent=english?'The latest capture will be saved to device flash after listening stops.':'最近一次抓包会在停止监听后自动保存到设备 Flash。'}
  }catch(e){}
}
</script>
</body>
</html>
)rawliteral";

static int parseJsonInt(const String& body, const char* key, int defaultVal) {
    String search = "\"" + String(key) + "\":";
    int pos = body.indexOf(search);
    if (pos < 0) return defaultVal;
    pos += search.length();
    while (pos < (int)body.length() && (body[pos] == ' ' || body[pos] == '\t')) pos++;
    return body.substring(pos).toInt();
}

static String parseJsonString(const String& body, const char* key, const char* defaultVal) {
    String search = "\"" + String(key) + "\":\"";
    int pos = body.indexOf(search);
    if (pos < 0) return String(defaultVal);
    pos += search.length();
    String out;
    bool escaped = false;
    while (pos < (int)body.length()) {
        const char c = body[pos++];
        if (escaped) {
            switch (c) {
                case '"': out += '"'; break;
                case '\\': out += '\\'; break;
                case '/': out += '/'; break;
                case 'b': out += '\b'; break;
                case 'f': out += '\f'; break;
                case 'n': out += '\n'; break;
                case 'r': out += '\r'; break;
                case 't': out += '\t'; break;
                default: out += c; break;
            }
            escaped = false;
        } else if (c == '\\') {
            escaped = true;
        } else if (c == '"') {
            return out;
        } else {
            out += c;
        }
    }
    return String(defaultVal);
}

static bool parseMacString(const char* str, uint8_t out[6]);

static size_t parseJsonTargets(const String& body,
                               Capture::TargetNetwork* targets,
                               size_t maxTargets) {
    const String marker = "\"targets\":[";
    int pos = body.indexOf(marker);
    if (pos < 0 || !targets || maxTargets == 0) return 0;
    pos += marker.length();

    size_t count = 0;
    while (pos < (int)body.length() && count < maxTargets) {
        const int objectStart = body.indexOf('{', pos);
        if (objectStart < 0) break;
        const int objectEnd = body.indexOf('}', objectStart);
        if (objectEnd < 0) break;
        const String object = body.substring(objectStart, objectEnd + 1);
        const String bssid = parseJsonString(object, "bssid", "");
        const int channel = parseJsonInt(object, "channel", 0);
        uint8_t parsedBssid[6];
        if (channel >= 1 && channel <= 14 && parseMacString(bssid.c_str(), parsedBssid)) {
            Capture::TargetNetwork& target = targets[count++];
            memcpy(target.bssid, parsedBssid, sizeof(target.bssid));
            target.channel = (uint8_t)channel;
            const String ssid = parseJsonString(object, "ssid", "");
            ssid.toCharArray(target.ssid, sizeof(target.ssid));
        }
        pos = objectEnd + 1;
        if (pos >= (int)body.length() || body[pos] == ']') break;
    }
    return count;
}

static bool parseMacString(const char* str, uint8_t out[6]) {
    if (!str || strlen(str) != 17) return false;
    int values[6];
    int n = sscanf(str, "%2x:%2x:%2x:%2x:%2x:%2x",
                   &values[0], &values[1], &values[2],
                   &values[3], &values[4], &values[5]);
    if (n != 6) return false;
    for (int i = 0; i < 6; ++i) out[i] = (uint8_t)values[i];
    return true;
}

static String jsonEscape(const char* input) {
    String out;
    if (!input) return out;
    for (const char* p = input; *p; ++p) {
        switch (*p) {
            case '\"': out += F("\\\""); break;
            case '\\': out += F("\\\\"); break;
            case '\n': out += F("\\n"); break;
            case '\r': out += F("\\r"); break;
            case '\t': out += F("\\t"); break;
            default: out += *p; break;
        }
    }
    return out;
}

static void sendJson(int code, const String& body) {
    server.sendHeader("Access-Control-Allow-Origin", "*");
    server.send(code, "application/json", body);
}

static void handleRoot() {
    server.sendHeader("Access-Control-Allow-Origin", "*");
    server.send_P(200, "text/html", MAIN_PAGE);
}

static bool parseJsonBool(const String& body, const char* key, bool defaultVal) {
    String search = "\"" + String(key) + "\":";
    int pos = body.indexOf(search);
    if (pos < 0) return defaultVal;
    pos += search.length();
    while (pos < (int)body.length() && (body[pos] == ' ' || body[pos] == '\t')) pos++;
    if (body.startsWith("true", pos)) return true;
    if (body.startsWith("false", pos)) return false;
    return defaultVal;
}

static String parseJsonString(const String& body, const char* key, const char* defaultVal);
static void sendJson(int code, const String& body);
static bool parseMacString(const char* str, uint8_t out[6]);

static void handlePreferences() {
    if (server.method() == HTTP_POST) {
        String language = parseJsonString(server.hasArg("plain") ? server.arg("plain") : "", "language", "zh");
        english = language == "en";
        preferences.putBool("english", english);
        Serial.printf("[Web] Language changed to %s\n", english ? "English" : "Chinese");
    }
    sendJson(200, String("{\"language\":\"") + (english ? "en" : "zh") + "\"}");
}

static void handleScan() {
    Serial.println("[Web] Scan requested");
    sendJson(200, Scanner::scanToJson());
}

static void handleCaptureStart() {
    String mode = "target";
    String bssidStr = "";
    String ssid = "";
    int channel = 1;
    Capture::TargetNetwork targets[Capture::MAX_TARGETS];
    size_t targetCount = 0;

    if (server.hasArg("plain")) {
        String body = server.arg("plain");
        mode = parseJsonString(body, "mode", "target");
        bssidStr = parseJsonString(body, "bssid", "");
        ssid = parseJsonString(body, "ssid", "");
        channel = parseJsonInt(body, "channel", 1);
        targetCount = parseJsonTargets(body, targets, Capture::MAX_TARGETS);
    }

    if (channel < 1) channel = 1;
    if (channel > 14) channel = 14;

    Serial.printf("[Web] Capture start requested: mode=%s channel=%d bssid=%s targets=%u\n",
                  mode.c_str(), channel, bssidStr.length() ? bssidStr.c_str() : "<all>",
                  (unsigned)targetCount);

    uint8_t bssid[6];
    bool fullMode = (mode == "full");
    bool started = false;
    if (!fullMode && targetCount > 0) {
        started = Capture::startTargets(targets, targetCount);
    } else {
        if (!fullMode && !parseMacString(bssidStr.c_str(), bssid)) {
            sendJson(400, "{\"status\":\"error\",\"msg\":\"invalid bssid\"}");
            return;
        }
        Capture::start((uint8_t)channel, fullMode ? nullptr : bssid, fullMode, ssid.c_str());
        started = Capture::isRunning;
    }
    if (!started) {
        String msg = Capture::getLastError();
        if (!msg.length()) msg = "capture start failed";
        sendJson(400, String("{\"status\":\"error\",\"msg\":\"") + jsonEscape(msg.c_str()) + "\"}");
        return;
    }

    sendJson(200, "{\"status\":\"ok\"}");
}

static void handleCaptureConfig() {
    if (!server.hasArg("plain")) {
        sendJson(400, "{\"status\":\"error\",\"msg\":\"missing config\"}");
        return;
    }
    String body = server.arg("plain");
    String mode = parseJsonString(body, "mode", "target");
    String bssidText = parseJsonString(body, "bssid", "");
    String ssid = parseJsonString(body, "ssid", "");
    int channel = parseJsonInt(body, "channel", 1);
    Capture::TargetNetwork targets[Capture::MAX_TARGETS];
    const size_t targetCount = parseJsonTargets(body, targets, Capture::MAX_TARGETS);
    if (channel < 1 || channel > 14) {
        sendJson(400, "{\"status\":\"error\",\"msg\":\"invalid channel\"}");
        return;
    }

    const bool fullMode = mode == "full";
    bool saved = false;
    if (!fullMode && targetCount > 0) {
        saved = Capture::saveTargetConfiguration(targets, targetCount);
    } else {
        uint8_t bssid[6];
        if (!fullMode && !parseMacString(bssidText.c_str(), bssid)) {
            sendJson(400, "{\"status\":\"error\",\"msg\":\"invalid bssid\"}");
            return;
        }
        Capture::saveConfiguration((uint8_t)channel, fullMode ? nullptr : bssid, fullMode, ssid.c_str());
        saved = Capture::hasSavedConfig();
    }
    Serial.printf("[Web] Capture configuration saved: mode=%s channel=%d bssid=%s targets=%u\n",
                  fullMode ? "full" : "target", channel,
                  fullMode ? "<all>" : bssidText.c_str(), (unsigned)targetCount);
    sendJson(saved ? 200 : 400, saved ? "{\"status\":\"ok\"}" : "{\"status\":\"error\",\"msg\":\"could not save capture configuration\"}");
}

static void handleAutoStart() {
    if (server.method() == HTTP_POST) {
        bool enabled = false;
        if (server.hasArg("plain")) enabled = parseJsonBool(server.arg("plain"), "enabled", false);
        Capture::setAutoStartEnabled(enabled);
        Serial.printf("[Web] Auto-start %s\n", enabled ? "enabled" : "disabled");
    }
    sendJson(200, String("{\"enabled\":") + (Capture::isAutoStartEnabled() ? "true" : "false") + "}");
}

static void handleCaptureStop() {
    Serial.println("[Web] Capture stop requested");
    Capture::stop();
    sendJson(200, "{\"status\":\"ok\"}");
}

static String savedTargetsJson() {
    String out = "[";
    for (size_t i = 0; i < Capture::getSavedTargetCount(); ++i) {
        Capture::TargetNetwork target;
        if (!Capture::getSavedTarget(i, target)) continue;
        char bssid[18];
        snprintf(bssid, sizeof(bssid), "%02X:%02X:%02X:%02X:%02X:%02X",
                 target.bssid[0], target.bssid[1], target.bssid[2],
                 target.bssid[3], target.bssid[4], target.bssid[5]);
        if (i > 0) out += ',';
        out += "{\"bssid\":\"";
        out += bssid;
        out += "\",\"channel\":";
        out += String(target.channel);
        out += ",\"ssid\":\"";
        out += jsonEscape(target.ssid);
        out += "\"}";
    }
    out += ']';
    return out;
}

static void handleCaptureStatus() {
    const String savedTargets = savedTargetsJson();
    char buf[1800];
    snprintf(buf, sizeof(buf),
             "{\"running\":%s,\"handshake\":%s,\"pmkid\":%s,\"frames\":%lu,"
             "\"rawFrames\":%lu,\"eapol\":%lu,\"pmkidCount\":%lu,\"channel\":%u,\"fullMode\":%s,"
             "\"summary\":\"%s\",\"size\":%u,\"pmkidSize\":%u,\"apActive\":%s,"
             "\"latestPcapSize\":%u,\"latestPmkidSize\":%u,\"latestMetaSize\":%u,"
             "\"fsTotal\":%u,\"fsUsed\":%u,\"fsFree\":%u,"
             "\"savedConfig\":%s,\"savedChannel\":%u,\"savedFull\":%s,\"savedBssid\":\"%s\","
             "\"savedTargets\":%s,\"autoStart\":%s}",
             Capture::isRunning ? "true" : "false",
             Capture::handshakeFound ? "true" : "false",
             Capture::pmkidFound ? "true" : "false",
             (unsigned long)Capture::frameCount,
             (unsigned long)Capture::getRawChannelFrames(),
             (unsigned long)Capture::eapolCount,
             (unsigned long)Capture::pmkidCount,
             Capture::captureChannel,
             Capture::usesFullChannel() ? "true" : "false",
             Capture::getCaptureSummary(),
             (unsigned)Capture::getPcapSize(),
             (unsigned)Capture::getPmkidSize(),
             Capture::managementApActive() ? "true" : "false",
             (unsigned)Capture::getLatestPcapSize(),
             (unsigned)Capture::getLatestPmkidSize(),
             (unsigned)Capture::getLatestMetaSize(),
             (unsigned)Capture::getFilesystemTotalBytes(),
             (unsigned)Capture::getFilesystemUsedBytes(),
             (unsigned)Capture::getFilesystemFreeBytes(),
             Capture::hasSavedConfig() ? "true" : "false",
             Capture::getSavedChannel(),
             Capture::usesSavedFullChannel() ? "true" : "false",
             Capture::getSavedBssid(),
             savedTargets.c_str(),
             Capture::isAutoStartEnabled() ? "true" : "false");
    sendJson(200, String(buf));
}

static void handleCaptureDownload() {
    Serial.printf("[Web] PCAP download requested: source=%s\n",
                  (server.hasArg("source") && server.arg("source") == "latest") ? "latest" : "current");
    if (Capture::isRunning) {
        sendJson(409, "{\"status\":\"error\",\"msg\":\"stop capture before downloading\"}");
        return;
    }

    if (Capture::getLatestPcapSize() <= 24) {
        sendJson(404, "{\"status\":\"error\",\"msg\":\"no data\"}");
        return;
    }
    if (!streamFileResponse("/latest_capture.pcap", "application/vnd.tcpdump.pcap", "latest_capture.pcap")) {
        sendJson(500, "{\"status\":\"error\",\"msg\":\"saved pcap stream failed\"}");
    }
}

static void handlePmkidDownload() {
    bool latestOnly = server.hasArg("source") && server.arg("source") == "latest";
    Serial.printf("[Web] 22000 download requested: source=%s\n", latestOnly ? "latest" : "current");
    size_t size = Capture::getPmkidSize();
    if (!latestOnly && size > 0) {
        server.sendHeader("Access-Control-Allow-Origin", "*");
        server.sendHeader("Content-Disposition", "attachment; filename=pmkid.22000");
        server.send(200, "text/plain", Capture::getPmkidData());
        return;
    }
    String latest;
    if (!Capture::loadLatestPmkid(latest) || latest.length() == 0) {
        sendJson(404, "{\"status\":\"error\",\"msg\":\"no pmkid\"}");
        return;
    }
    server.sendHeader("Access-Control-Allow-Origin", "*");
    server.sendHeader("Content-Disposition", "attachment; filename=latest_capture.22000");
    server.send(200, "text/plain", latest);
}

static void handleMetaDownload() {
    Serial.println("[Web] JSON report download requested");
    String latest;
    if (!Capture::loadLatestMeta(latest) || latest.length() == 0) {
        sendJson(404, "{\"status\":\"error\",\"msg\":\"no saved report\"}");
        return;
    }
    server.sendHeader("Access-Control-Allow-Origin", "*");
    server.sendHeader("Content-Disposition", "attachment; filename=latest_capture.json");
    server.send(200, "application/json", latest);
}

static void handleClearSaved() {
    Serial.println("[Web] Clear saved captures requested");
    bool ok = Capture::clearLatestSaved();
    sendJson(ok ? 200 : 500, ok ? "{\"status\":\"ok\"}" : "{\"status\":\"error\",\"msg\":\"clear failed\"}");
}

static void handleClearAllFiles() {
    Serial.println("[Web] Clear all LittleFS files requested");
    bool ok = Capture::clearAllFiles();
    sendJson(ok ? 200 : 409, ok ? "{\"status\":\"ok\"}" : "{\"status\":\"error\",\"msg\":\"stop capture first or clear failed\"}");
}

static bool isSavedCaptureFile(const String& name) {
    if (name.indexOf("..") >= 0) return false;
    String path = name;
    if (!path.startsWith("/")) path = "/" + path;
    if (!(path.startsWith("/latest_") || path.startsWith("/session_"))) return false;
    return path.endsWith(".pcap") || path.endsWith(".22000") || path.endsWith(".json");
}

static void handleCaptureFiles() {
    String json = "[";
    File root = LittleFS.open("/");
    bool first = true;
    if (root) {
        File file = root.openNextFile();
        while (file) {
            String name = file.name();
            if (!name.startsWith("/")) name = "/" + name;
            if (isSavedCaptureFile(name)) {
                if (!first) json += ',';
                json += "{\"name\":\"";
                json += jsonEscape(name.c_str());
                json += "\",\"size\":";
                json += String((unsigned)file.size());
                json += '}';
                first = false;
            }
            file.close();
            file = root.openNextFile();
        }
        root.close();
    }
    json += ']';
    sendJson(200, json);
}

static void handleCaptureFile() {
    String name = server.arg("name");
    if (!name.startsWith("/")) name = "/" + name;
    if (!isSavedCaptureFile(name)) {
        sendJson(400, "{\"status\":\"error\",\"msg\":\"invalid file\"}");
        return;
    }
    String filename = name.substring(name.lastIndexOf('/') + 1);
    const char* contentType = name.endsWith(".pcap") ? "application/vnd.tcpdump.pcap" :
                              (name.endsWith(".json") ? "application/json" : "text/plain");
    Serial.printf("[Web] Saved file download requested: %s\n", name.c_str());
    if (!streamFileResponse(name.c_str(), contentType, filename.c_str())) {
        sendJson(404, "{\"status\":\"error\",\"msg\":\"file not found\"}");
    }
}

static void handleCors() {
    server.sendHeader("Access-Control-Allow-Origin", "*");
    server.sendHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
    server.sendHeader("Access-Control-Allow-Headers", "Content-Type");
    server.send(204);
}

static void handleNoContent() {
    server.send(204);
}

void setup() {
    preferences.begin("webui", false);
    english = preferences.getBool("english", false);
    dnsServer.start(53, "*", WiFi.softAPIP());

    server.on("/", HTTP_GET, handleRoot);
    server.on("/api/preferences", HTTP_GET, handlePreferences);
    server.on("/api/preferences", HTTP_POST, handlePreferences);
    server.on("/api/scan", HTTP_GET, handleScan);
    server.on("/api/capture/start", HTTP_POST, handleCaptureStart);
    server.on("/api/capture/config", HTTP_POST, handleCaptureConfig);
    server.on("/api/capture/stop", HTTP_POST, handleCaptureStop);
    server.on("/api/capture/status", HTTP_GET, handleCaptureStatus);
    server.on("/api/capture/download", HTTP_GET, handleCaptureDownload);
    server.on("/api/capture/pmkid", HTTP_GET, handlePmkidDownload);
    server.on("/api/capture/meta", HTTP_GET, handleMetaDownload);
    server.on("/api/capture/clear", HTTP_POST, handleClearSaved);
    server.on("/api/capture/clear-all", HTTP_POST, handleClearAllFiles);
    server.on("/api/capture/autostart", HTTP_GET, handleAutoStart);
    server.on("/api/capture/autostart", HTTP_POST, handleAutoStart);
    server.on("/api/capture/files", HTTP_GET, handleCaptureFiles);
    server.on("/api/capture/file", HTTP_GET, handleCaptureFile);

    server.on("/api/capture/start", HTTP_OPTIONS, handleCors);
    server.on("/api/capture/config", HTTP_OPTIONS, handleCors);
    server.on("/api/capture/stop", HTTP_OPTIONS, handleCors);
    server.on("/api/capture/clear", HTTP_OPTIONS, handleCors);
    server.on("/api/capture/clear-all", HTTP_OPTIONS, handleCors);
    server.on("/api/capture/autostart", HTTP_OPTIONS, handleCors);
    server.on("/api/preferences", HTTP_OPTIONS, handleCors);

    // Phones and captive-portal helpers periodically probe extra paths.
    // Handle those quietly instead of logging a handler-not-found error.
    server.on(UriGlob("*"), HTTP_GET, handleNoContent);
    server.on(UriGlob("*"), HTTP_OPTIONS, handleCors);

    server.on("/generate_204", HTTP_GET, handleRoot);
    server.on("/hotspot-detect.html", HTTP_GET, handleRoot);
    server.on("/canonical.html", HTTP_GET, handleRoot);
    server.on("/ncsi.txt", HTTP_GET, handleRoot);
    server.on("/success.txt", HTTP_GET, handleRoot);
    server.on("/redirect", HTTP_GET, handleRoot);
    server.on("/fwlink", HTTP_GET, handleRoot);
    server.on("/favicon.ico", HTTP_GET, handleNoContent);
    server.on("/apple-touch-icon.png", HTTP_GET, handleNoContent);
    server.on("/apple-touch-icon-precomposed.png", HTTP_GET, handleNoContent);
    server.on("/connecttest.txt", HTTP_GET, handleRoot);
    server.on("/library/test/success.html", HTTP_GET, handleRoot);
    server.on("/hotspotdetect.html", HTTP_GET, handleRoot);
    server.on("/", HTTP_HEAD, handleNoContent);
    server.onNotFound(handleNoContent);

    server.begin();
}

void loop() {
    dnsServer.processNextRequest();
    server.handleClient();
}

}  // namespace WebUI
