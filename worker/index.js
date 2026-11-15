const enc = new TextEncoder();
const b64 = (b) => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
const json = (x, s = 200) => new Response(JSON.stringify(x), {
  status: s,
  headers: {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
  },
});

function parseJson(raw, label) {
  if (!raw) return null;
  if (typeof raw === 'object') return raw;
  try {
    return JSON.parse(raw);
  } catch {
    throw Error(`${label} 格式无效`);
  }
}

function buildNode(id, idx, defaults, meta, saRaw, vpnRaw) {
  const sa = saRaw ? parseJson(saRaw, `${id} GCP 密钥`) : null;
  const vpn = vpnRaw ? parseJson(vpnRaw, `${id} 客户端配置`) : null;
  const project = meta?.project || vpn?.project || sa?.project_id || defaults.project || '';
  const zone = meta?.zone || vpn?.zone || defaults.zone || 'us-west1-b';
  const vm = meta?.vm || vpn?.vm || defaults.vm || `vps-ai-node-${idx}`;
  const region = meta?.region || vpn?.region || defaults.region || 'Google Cloud · 俄勒冈';
  const name = meta?.name || vpn?.name || defaults.name || `节点 ${idx}${project ? ` · ${project}` : ''}`;
  const tag = meta?.tag || vpn?.tag || defaults.tag || `GCP-US-West-AI-Node-${idx}`;
  const limitGiB = Number(meta?.limitGiB || vpn?.limitGiB || defaults.limitGiB || 550);
  return {
    id,
    name,
    project,
    zone,
    vm,
    region,
    tag,
    limitGiB,
    sa,
    vpn,
  };
}

function resolveNodes(env) {
  const nodes = [];
  const seen = new Set();
  const pushNode = (node) => {
    if (!node || !node.id || seen.has(node.id)) return;
    seen.add(node.id);
    nodes.push(node);
  };

  pushNode(buildNode(
    'node1',
    1,
    {
      name: '节点 1 · tongshe',
      project: 'tongshe',
      zone: 'us-west1-b',
      vm: 'vps-ai-node',
      region: 'Google Cloud · 俄勒冈',
      tag: 'GCP-US-West-AI-Node',
      limitGiB: 550,
    },
    parseJson(env.GCP_NODE_1_META, 'node1 元数据'),
    env.GCP_SERVICE_ACCOUNT_JSON,
    env.VPN_CLIENT_CONFIG,
  ));

  for (let i = 2; i <= 8; i++) {
    const metaRaw = env[`GCP_NODE_${i}_META`];
    const saRaw = env[`GCP_SERVICE_ACCOUNT_JSON_${i}`];
    const vpnRaw = env[`VPN_CLIENT_CONFIG_${i}`];
    if (!metaRaw && !saRaw && !vpnRaw) continue;
    const meta = parseJson(metaRaw, `node${i} 元数据`);
    const id = meta?.id || `node${i}`;
    pushNode(buildNode(
      id,
      i,
      {
        region: 'Google Cloud · 俄勒冈',
        limitGiB: 550,
      },
      meta,
      saRaw,
      vpnRaw,
    ));
  }

  if (env.GCP_NODES_JSON) {
    const list = parseJson(env.GCP_NODES_JSON, 'GCP_NODES_JSON');
    if (!Array.isArray(list)) throw Error('GCP_NODES_JSON 必须是数组');
    list.forEach((item, idx) => {
      if (!item || typeof item !== 'object') return;
      const n = nodes.length + 1;
      const id = item.id || `node${n}`;
      pushNode(buildNode(
        id,
        idx + 1,
        {
          name: item.name,
          project: item.project,
          zone: item.zone || 'us-west1-b',
          vm: item.vm || `vps-ai-node-${n}`,
          region: item.region || 'Google Cloud · 俄勒冈',
          tag: item.tag || `GCP-Node-${n}`,
          limitGiB: item.limitGiB || 550,
        },
        item,
        item.serviceAccount || item.gcpServiceAccountJson,
        item.vpnConfig || item.vpnClientConfig,
      ));
    });
  }

  return nodes;
}

async function token(sa) {
  const now = Math.floor(Date.now() / 1000);
  const head = b64(enc.encode(JSON.stringify({ alg: 'RS256', typ: 'JWT' })));
  const body = b64(enc.encode(JSON.stringify({
    iss: sa.client_email,
    scope: 'https://www.googleapis.com/auth/cloud-platform',
    aud: 'https://oauth2.googleapis.com/token',
    iat: now,
    exp: now + 300,
  })));
  const key = Uint8Array.from(atob(sa.private_key.replace(/-----[^-]+-----/g, '').replace(/\s/g, '')), (x) => x.charCodeAt(0));
  const priv = await crypto.subtle.importKey('pkcs8', key, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['sign']);
  const assertion = `${head}.${body}.${b64(await crypto.subtle.sign('RSASSA-PKCS1-v1_5', priv, enc.encode(`${head}.${body}`)))}`;
  const r = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer', assertion }),
  });
  if (!r.ok) throw Error('Google 身份验证失败');
  return (await r.json()).access_token;
}

async function api(t, url, options = {}) {
  const r = await fetch(url, { ...options, headers: { authorization: `Bearer ${t}`, ...options.headers } });
  if (!r.ok) throw Error(`Google Cloud 返回 ${r.status}`);
  return r.json();
}

function instanceBase(node) {
  return `https://compute.googleapis.com/compute/v1/projects/${encodeURIComponent(node.project)}/zones/${encodeURIComponent(node.zone)}/instances/${encodeURIComponent(node.vm)}`;
}

async function usage(t, project, id) {
  const now = new Date();
  const p = new Intl.DateTimeFormat('en-US', { timeZone: 'America/Los_Angeles', year: 'numeric', month: '2-digit' }).formatToParts(now);
  const n = Object.fromEntries(p.map((x) => [x.type, x.value]));
  // Start early enough to cover Pacific midnight; trim points at the correct zoned boundary below.
  const first = new Date(`${n.year}-${n.month}-01T08:00:00Z`);
  if (['00', '24'].includes(new Date(`${n.year}-${n.month}-01T07:00:00Z`).toLocaleString('en-US', { timeZone: 'America/Los_Angeles', hour: '2-digit', hour12: false }))) {
    first.setUTCHours(7);
  }
  const q = new URLSearchParams({
    filter: `metric.type="compute.googleapis.com/instance/network/sent_bytes_count" AND resource.type="gce_instance" AND resource.label.instance_id="${id}"`,
    'interval.startTime': first.toISOString(),
    'interval.endTime': now.toISOString(),
    'aggregation.alignmentPeriod': '3600s',
    'aggregation.perSeriesAligner': 'ALIGN_SUM',
    view: 'FULL',
  });
  let sum = 0;
  let next;
  do {
    if (next) q.set('pageToken', next);
    const d = await api(t, `https://monitoring.googleapis.com/v3/projects/${encodeURIComponent(project)}/timeSeries?${q}`);
    for (const ts of d.timeSeries || []) {
      for (const point of ts.points || []) {
        sum += Number(point.value.int64Value ?? point.value.doubleValue ?? 0);
      }
    }
    next = d.nextPageToken;
  } while (next);
  return { bytes: sum, source: 'Cloud Monitoring', note: '统计有延迟，仅供参考；停机由服务器本地计数器独立执行。' };
}

function share(c, ip, node) {
  const port = Number(c.port || 8443);
  const tag = c.tag || node.tag || 'GCP-US-West-AI-Node';
  return `vless://${c.uuid}@${ip}:${port}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${encodeURIComponent(c.sni)}&fp=chrome&pbk=${encodeURIComponent(c.public_key)}&sid=${encodeURIComponent(c.short_id)}&type=tcp#${encodeURIComponent(tag)}`;
}

function publicMeta(node) {
  return {
    id: node.id,
    name: node.name,
    project: node.project,
    zone: node.zone,
    vm: node.vm,
    region: node.region,
    limitGiB: node.limitGiB,
    configured: Boolean(node.sa && node.project && node.vm),
    hasVpnConfig: Boolean(node.vpn),
  };
}

async function nodeStatus(node) {
  const meta = publicMeta(node);
  if (!node.sa) return { ...meta, error: '尚未连接 Google Cloud' };
  if (!node.project || !node.vm) return { ...meta, error: '缺少项目 ID 或实例名称' };
  const t = await token(node.sa);
  const v = await api(t, instanceBase(node));
  let traffic = null;
  let trafficError = null;
  try {
    traffic = await usage(t, node.project, v.id);
  } catch {
    trafficError = '用量暂不可用';
  }
  const ip = v.networkInterfaces?.[0]?.accessConfigs?.[0]?.natIP || null;
  return {
    ...meta,
    status: v.status,
    ip,
    machine: v.machineType?.split('/').pop() || null,
    traffic,
    trafficError,
  };
}

function pickNode(nodes, id) {
  if (!id) return nodes[0] || null;
  return nodes.find((n) => n.id === id) || null;
}

async function handle(req, env) {
  if (!req.headers.get('oai-authenticated-user-id')) return json({ error: '请先登录控制台' }, 401);
  const u = new URL(req.url);
  if (u.pathname === '/' && req.method === 'GET') {
    return new Response(PAGE, {
      headers: {
        'content-type': 'text/html; charset=utf-8',
        'cache-control': 'no-store',
        'content-security-policy': "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'",
        'x-content-type-options': 'nosniff',
        'referrer-policy': 'no-referrer',
      },
    });
  }

  if (req.method === 'POST' && (req.headers.get('origin') !== u.origin || req.headers.get('content-type') !== 'application/json')) {
    return json({ error: '请求来源无效' }, 403);
  }

  const nodes = resolveNodes(env);
  if (u.pathname === '/api/nodes' && req.method === 'GET') {
    return json({ nodes: nodes.map(publicMeta) });
  }

  if (u.pathname === '/api/status' && req.method === 'GET') {
    const id = u.searchParams.get('node');
    if (id) {
      const node = pickNode(nodes, id);
      if (!node) return json({ error: '未找到指定节点' }, 404);
      if (!node.sa) return json({ error: '尚未连接 Google Cloud' }, 503);
      return json(await nodeStatus(node));
    }
    const results = await Promise.all(nodes.map(async (node) => {
      try {
        return await nodeStatus(node);
      } catch (e) {
        return { ...publicMeta(node), error: e.message || '读取失败' };
      }
    }));
    const first = results[0] || {};
    return json({ ...first, nodes: results });
  }

  if (u.pathname === '/api/config' && req.method === 'GET') {
    const node = pickNode(nodes, u.searchParams.get('node'));
    if (!node) return json({ error: '未找到指定节点' }, 404);
    if (!node.sa) return json({ error: '尚未连接 Google Cloud' }, 503);
    if (!node.vpn) return json({ error: '客户端配置尚未连接' }, 503);
    const t = await token(node.sa);
    const v = await api(t, instanceBase(node));
    const ip = v.networkInterfaces?.[0]?.accessConfigs?.[0]?.natIP;
    if (!ip) return json({ error: '实例没有公网 IP，请先启动' }, 409);
    return json({ id: node.id, link: share(node.vpn, ip, node), ip });
  }

  if (u.pathname === '/api/action' && req.method === 'POST') {
    const d = await req.json();
    const node = pickNode(nodes, d.node);
    if (!node) return json({ error: '未找到指定节点' }, 404);
    if (!node.sa) return json({ error: '尚未连接 Google Cloud' }, 503);
    if (!['start', 'stop'].includes(d.action)) return json({ error: '不支持的操作' }, 400);
    const t = await token(node.sa);
    const v = await api(t, instanceBase(node));
    if ((d.action === 'stop' && v.status !== 'RUNNING') || (d.action === 'start' && v.status !== 'TERMINATED')) {
      return json({ error: `节点当前状态不允许此操作：${v.status}` }, 409);
    }
    const op = await api(t, `${instanceBase(node)}/${d.action}`, { method: 'POST' });
    return json({ id: node.id, operation: op.name, message: '操作已提交，状态更新可能需要一些时间。' });
  }

  return json({ error: '未找到' }, 404);
}

export default {
  async fetch(req, env) {
    try {
      return await handle(req, env);
    } catch (e) {
      return json({ error: e.message || '请求失败' }, 500);
    }
  },
};

const PAGE = `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>节点控制台</title><style>
:root{font-family:Inter,system-ui,-apple-system,'Segoe UI',sans-serif;color:#17251f;background:#f5f7f2}*{box-sizing:border-box}body{margin:0}header{background:#133d2e;color:#fff;padding:24px max(24px,calc((100vw - 1180px)/2)) 52px}.top{display:flex;justify-content:space-between;align-items:center;gap:12px;font-size:14px}.logo{font-weight:750;letter-spacing:.03em}.top-right{display:flex;align-items:center;gap:10px}.tag{color:#c1dfc7}.ghost{background:rgba(255,255,255,.14);color:#fff;padding:8px 14px;border-radius:9px;font-size:13px}.ghost:hover{background:rgba(255,255,255,.22)}h1{font-size:32px;margin:38px 0 8px}header p{margin:0;color:#c8ddcf}.wrap{max-width:1180px;margin:-24px auto 44px;padding:0 20px}.nodes-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(350px,1fr));gap:18px;align-items:start}.card{background:#fff;border:1px solid #e1e9e1;border-radius:16px;padding:22px;box-shadow:0 4px 18px #1d412509}.node-head{display:flex;justify-content:space-between;align-items:flex-start;gap:12px;margin-bottom:16px}.node-title{font-size:19px;font-weight:750;margin:0 0 4px}.node-sub{font-size:13px;color:#687b6e}.node-actions-top{display:flex;align-items:center;gap:8px;flex-shrink:0}.pill{display:inline-flex;align-items:center;gap:6px;padding:5px 10px;border-radius:999px;font-size:12px;font-weight:650;background:#eef3ee;color:#4a5e51}.pill.ok{background:#e3f4ea;color:#16653d}.pill.warn{background:#fef3db;color:#9a5b13}.pill.err{background:#fdecea;color:#b23d2d}.metrics{display:grid;grid-template-columns:1fr 1fr;gap:10px}.metric{background:#f7faf7;border:1px solid #e8efe8;border-radius:12px;padding:13px 14px}.label{font-size:12px;color:#687b6e}.value{font-size:18px;font-weight:700;margin:6px 0 4px;word-break:break-all}.small{font-size:12px;color:#748478;line-height:1.5}.traffic-box{margin-top:14px;padding:14px;border:1px solid #e8efe8;border-radius:12px;background:#fcfefc}.head{display:flex;justify-content:space-between;align-items:center;gap:10px}.head h2{font-size:15px;margin:0}.bar{height:9px;background:#eaf0e9;border-radius:10px;overflow:hidden;margin:12px 0 8px}.bar span{display:block;height:100%;background:#44a674;width:0;transition:width .25s ease}.bar span.warn{background:#d9822b}.bar span.danger{background:#c94a38}.controls{display:flex;gap:8px;flex-wrap:wrap;margin-top:16px}button{border:0;border-radius:10px;padding:10px 14px;font:inherit;font-size:13px;font-weight:650;cursor:pointer;background:#eaf2eb;color:#245640}button.mini{padding:6px 11px;font-size:12px;border-radius:8px}button.primary{background:#196841;color:#fff}button.danger{background:#fff0ec;color:#b23d2d}button:disabled{opacity:.48;cursor:not-allowed}.msg{min-height:18px;margin-top:12px;font-size:13px;color:#96612d}.result{white-space:pre-wrap;overflow-wrap:anywhere;background:#f4f7f3;padding:12px;border-radius:10px;font-size:12px;line-height:1.5;margin:10px 0 8px}.notice{margin-top:16px;padding:14px 18px;background:#fff;border:1px solid #e1e9e1;border-radius:14px;color:#667c6b;font-size:13px;line-height:1.6}footer{font-size:12px;color:#88978a;text-align:center;margin-top:20px}@media(max-width:720px){.nodes-grid{grid-template-columns:1fr}.metrics{grid-template-columns:1fr}header{padding-bottom:44px}h1{margin-top:26px;font-size:26px}.card{padding:18px}}
</style></head><body><header><div class="top"><span class="logo">● NODE / CONTROL</span><div class="top-right"><span class="tag" id="summary">多节点控制台</span><button class="ghost" id="refreshAll">全部刷新</button></div></div><h1>你的节点，一目了然。</h1><p>同屏查看所有节点的运行状态、出站流量与获取最新连接配置。</p></header><main class="wrap"><div id="nodes" class="nodes-grid"></div><div class="notice">Cloud Monitoring 数据可能延迟，实际停机依据各服务器每分钟记录的主网卡流量；更换 IP 需要先停止再启动，新 IP 不保证可用，达到流量上限后节点会再次自动停机。</div><footer>流量及预算提醒为辅助保护，无法保证费用不超出赠金。</footer></main><script>
const $=id=>document.getElementById(id);
const STATUS_MAP={RUNNING:'运行中',TERMINATED:'已停止',STOPPING:'正在停止',PROVISIONING:'正在启动',STAGING:'正在启动',SUSPENDED:'已暂停'};
const cards=new Map();
async function call(path,options){const r=await fetch(path,{cache:'no-store',...options});const j=await r.json();if(!r.ok)throw Error(j.error||'操作失败');return j}
function el(tag,cls,text){const e=document.createElement(tag);if(cls)e.className=cls;if(text!==undefined)e.textContent=text;return e}
function createCard(n){
  const card=el('article','card node-card');
  const head=el('div','node-head');
  const info=el('div');
  const title=el('h2','node-title',n.name||n.id);
  const sub=el('div','node-sub',\`\${n.vm||'—'} · \${n.zone||'—'}\`);
  info.append(title,sub);
  const topAct=el('div','node-actions-top');
  const pill=el('span','pill','读取中…');
  const btnRefresh=el('button','mini','刷新');
  topAct.append(pill,btnRefresh);
  head.append(info,topAct);

  const metrics=el('div','metrics');
  const mIp=el('div','metric');
  const ipVal=el('div','value','—');
  mIp.append(el('div','label','当前公网 IP'),ipVal,el('div','small','临时地址，停止后可能变更'));
  const mSpec=el('div','metric');
  const machVal=el('div','value','—');
  const projVal=el('div','small',\`\${n.region||'Google Cloud'} · 项目 \${n.project||'未配置'}\`);
  mSpec.append(el('div','label','机器规格'),machVal,projVal);
  metrics.append(mIp,mSpec);

  const tBox=el('div','traffic-box');
  const tHead=el('div','head');
  const limitLabel=el('span','small',\`安全阈值 \${n.limitGiB||550} GiB\`);
  tHead.append(el('h2','','本月出站流量'),limitLabel);
  const bar=el('div','bar');const barFill=el('span');bar.append(barFill);
  const trafficText=el('div','small','读取中…');
  tBox.append(tHead,bar,trafficText);

  const controls=el('div','controls');
  const btnStop=el('button','danger','停止节点');btnStop.disabled=true;
  const btnStart=el('button','primary','启动节点');btnStart.disabled=true;
  const btnConfig=el('button','','获取最新连接');btnConfig.disabled=true;
  controls.append(btnStop,btnStart,btnConfig);

  const msg=el('div','msg');msg.setAttribute('role','status');
  const pre=el('pre','result');pre.hidden=true;
  const btnCopy=el('button','mini','复制连接');btnCopy.hidden=true;

  card.append(head,metrics,tBox,controls,msg,pre,btnCopy);
  const ref={id:n.id,card,title,sub,pill,ipVal,machVal,projVal,limitLabel,barFill,trafficText,btnRefresh,btnStop,btnStart,btnConfig,msg,pre,btnCopy};

  btnRefresh.onclick=()=>refreshNode(n.id);
  for(const act of ['stop','start']){
    (act==='stop'?btnStop:btnStart).onclick=async()=>{
      const tip=act==='stop'?'停止该节点？当前连接会中断，临时 IP 可能释放。':'启动该节点？可能产生费用；超出流量阈值会自动停机。';
      if(!confirm(tip))return;
      try{
        btnStop.disabled=true;btnStart.disabled=true;
        const d=await call('/api/action',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({node:n.id,action:act})});
        msg.textContent=d.message;
        setTimeout(()=>refreshNode(n.id),7000);
      }catch(e){msg.textContent=e.message;refreshNode(n.id)}
    };
  }
  btnConfig.onclick=async()=>{
    try{
      const d=await call('/api/config?node='+encodeURIComponent(n.id));
      pre.textContent=d.link;pre.hidden=false;btnCopy.hidden=false;msg.textContent='';
    }catch(e){msg.textContent=e.message}
  };
  btnCopy.onclick=()=>navigator.clipboard.writeText(pre.textContent).then(()=>{msg.textContent='已复制连接'}).catch(()=>{msg.textContent='请手动复制连接'});
  cards.set(n.id,ref);
  return card;
}

function renderStatus(ref,d){
  if(d.error){
    ref.pill.className='pill err';ref.pill.textContent='未就绪';
    ref.ipVal.textContent='—';ref.machVal.textContent='—';
    ref.trafficText.textContent=d.error;
    ref.barFill.style.width='0%';ref.barFill.className='';
    ref.btnStop.disabled=true;ref.btnStart.disabled=true;ref.btnConfig.disabled=true;
    ref.msg.textContent=d.error;
    return;
  }
  const st=d.status||'';
  ref.pill.textContent=STATUS_MAP[st]||st||'未知';
  ref.pill.className='pill '+(st==='RUNNING'?'ok':st==='TERMINATED'?'':'warn');
  ref.ipVal.textContent=d.ip||'暂无';
  ref.machVal.textContent=d.machine||'—';
  ref.sub.textContent=\`\${d.vm||'—'} · \${d.zone||'—'}\`;
  ref.projVal.textContent=\`\${d.region||'Google Cloud'} · 项目 \${d.project||'—'}\`;
  const lim=Number(d.limitGiB||550);
  ref.limitLabel.textContent=\`安全阈值 \${lim} GiB\`;
  ref.btnStop.disabled=st!=='RUNNING';
  ref.btnStart.disabled=st!=='TERMINATED';
  ref.btnConfig.disabled=!d.ip||!d.hasVpnConfig;
  if(d.traffic){
    const n=d.traffic.bytes/1073741824;
    const pct=Math.min(100,n/lim*100);
    ref.trafficText.textContent=n.toFixed(2)+' GiB / '+lim+' GiB · 统计可能延迟';
    ref.barFill.style.width=pct+'%';
    ref.barFill.className=pct>=95?'danger':pct>=80?'warn':'';
  }else{
    ref.trafficText.textContent=d.trafficError||'暂无数据';
    ref.barFill.style.width='0%';ref.barFill.className='';
  }
  ref.msg.textContent='';
}

async function refreshNode(id){
  const ref=cards.get(id);if(!ref)return;
  try{
    ref.btnRefresh.disabled=true;
    const d=await call('/api/status?node='+encodeURIComponent(id));
    renderStatus(ref,d);
  }catch(e){
    ref.pill.className='pill err';ref.pill.textContent='异常';
    ref.msg.textContent=e.message;
  }finally{ref.btnRefresh.disabled=false}
}

async function init(){
  try{
    const {nodes}=await call('/api/nodes');
    $('summary').textContent=\`共 \${nodes.length} 个节点\`;
    const box=$('nodes');box.textContent='';cards.clear();
    for(const n of nodes)box.append(createCard(n));
    await Promise.all(nodes.map(n=>refreshNode(n.id)));
  }catch(e){
    $('summary').textContent=e.message||'加载失败';
  }
}
$('refreshAll').onclick=()=>Promise.all([...cards.keys()].map(refreshNode));
init();
</script></body></html>`;
