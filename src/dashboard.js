/**
 * Local web dashboard — browse assessments and runs, view prioritized reports,
 * diff two runs, and drive an assessment (start → run → report) from the browser.
 *
 * Built on Node's `http` (no new dependency). Binds to 127.0.0.1 by default — it
 * can trigger active scans, so it is a localhost tool for the operator, not a
 * service to expose. Reuses the same assessment engine the CLI and MCP server do.
 */

import http from 'http';
import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';
import { loadCatalog } from './extensions/loader.js';
import {
  createAssessment, runStep, saveAssessment, loadAssessment, listAssessments, preflightTarget,
} from './assessment.js';
import { suggest } from './pivots.js';
import { synthesize } from './assessment-report.js';
import { diffFiles } from './diff.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const RUNS_DIR = path.join(__dirname, '..', 'runs');

const json = (res, code, body) => {
  res.writeHead(code, { 'content-type': 'application/json' });
  res.end(JSON.stringify(body));
};
const readBody = (req) => new Promise((resolve) => {
  let b = ''; req.on('data', (d) => { b += d; if (b.length > 1_000_000) req.destroy(); });
  req.on('end', () => { try { resolve(b ? JSON.parse(b) : {}); } catch { resolve({}); } });
});

async function listRunFiles() {
  try {
    const files = await fs.readdir(RUNS_DIR);
    const out = [];
    for (const f of files.filter(n => n.endsWith('.json'))) {
      try {
        const st = await fs.stat(path.join(RUNS_DIR, f));
        const r = JSON.parse(await fs.readFile(path.join(RUNS_DIR, f), 'utf8'));
        out.push({ file: f, target: r.target || r.vars?.target || '?', title: r.title || r.playbook || '?', at: st.mtime.toISOString(), steps: (r.outputs || r.steps || []).length });
      } catch { /* skip */ }
    }
    return out.sort((a, b) => b.at.localeCompare(a.at));
  } catch { return []; }
}

export async function startDashboard({ port = 7878, host = '127.0.0.1' } = {}) {
  const catalog = await loadCatalog();

  // DNS-rebinding + CSRF guard. Binding to loopback is not enough: a malicious
  // page can rebind a hostname to 127.0.0.1 or POST cross-site to drive scans.
  // Browsers cannot forge Host/Origin, so we accept only requests that name this
  // exact loopback server.
  const allowedHosts = new Set([`${host}:${port}`, `127.0.0.1:${port}`, `localhost:${port}`, `[::1]:${port}`]);
  const allowedOrigins = new Set([...allowedHosts].map(h => `http://${h}`));

  const server = http.createServer(async (req, res) => {
    try {
      if (!allowedHosts.has(req.headers.host || '')) { res.writeHead(403); return res.end('forbidden host'); }
      const origin = req.headers.origin;
      if (origin && !allowedOrigins.has(origin)) { res.writeHead(403); return res.end('forbidden origin'); }

      const u = new URL(req.url, `http://${host}:${port}`);
      const p = u.pathname;

      if (p === '/' || p === '/index.html') {
        res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
        return res.end(HTML);
      }

      // ── API ────────────────────────────────────────────────────────────────
      if (p === '/api/assessments') return json(res, 200, await listAssessments());
      if (p === '/api/runs') return json(res, 200, await listRunFiles());
      if (p === '/api/capabilities') return json(res, 200, {
        executors: catalog.executors.length, extensions: catalog.descriptors.length,
        byPhase: Object.fromEntries(Object.entries(catalog.byPhase).map(([k, v]) => [k, v.length])),
      });

      let m;
      if ((m = p.match(/^\/api\/assessment\/([^/]+)\/report$/))) {
        const s = await loadAssessment(m[1]); if (!s) return json(res, 404, { error: 'not found' });
        return json(res, 200, synthesize(s).json);
      }
      if ((m = p.match(/^\/api\/assessment\/([^/]+)\/next$/))) {
        const s = await loadAssessment(m[1]); if (!s) return json(res, 404, { error: 'not found' });
        return json(res, 200, suggest(s, catalog, { posture: s.posture, limit: 12 }));
      }
      if ((m = p.match(/^\/api\/assessment\/([^/]+)\/run$/)) && req.method === 'POST') {
        const s = await loadAssessment(m[1]); if (!s) return json(res, 404, { error: 'not found' });
        const { top = 5 } = await readBody(req);
        const toRun = suggest(s, catalog, { posture: s.posture, limit: top });
        for (const step of toRun) await runStep(s, step, catalog);
        await saveAssessment(s);
        return json(res, 200, { ran: toRun.length, totals: { steps: s.steps.length, findings: s.findings.length, entities: s.entities.length } });
      }
      if (p === '/api/assessment/start' && req.method === 'POST') {
        const { target, passive } = await readBody(req);
        if (!target) return json(res, 400, { error: 'target required' });
        const s = createAssessment({ target, posture: passive ? 'passive' : undefined });
        const reachability = await preflightTarget(s); await saveAssessment(s);
        return json(res, 200, { id: s.id, reachability, suggestions: suggest(s, catalog, { posture: s.posture, limit: 12 }) });
      }
      if ((m = p.match(/^\/api\/assessment\/([^/]+)$/))) {
        const s = await loadAssessment(m[1]); if (!s) return json(res, 404, { error: 'not found' });
        return json(res, 200, s);
      }
      if ((m = p.match(/^\/api\/run\/(.+)$/))) {
        const file = path.basename(decodeURIComponent(m[1]));   // prevent traversal
        try { return json(res, 200, JSON.parse(await fs.readFile(path.join(RUNS_DIR, file), 'utf8'))); }
        catch { return json(res, 404, { error: 'not found' }); }
      }
      if (p === '/api/diff') {
        const a = path.basename(u.searchParams.get('a') || ''), b = path.basename(u.searchParams.get('b') || '');
        try { return json(res, 200, await diffFiles(path.join(RUNS_DIR, a), path.join(RUNS_DIR, b))); }
        catch (e) { return json(res, 400, { error: e.message }); }
      }

      json(res, 404, { error: 'not found' });
    } catch (e) {
      json(res, 500, { error: e.message });
    }
  });

  await new Promise((resolve) => server.listen(port, host, resolve));
  return { server, url: `http://${host}:${port}` };
}

// ── The single-file SPA ─────────────────────────────────────────────────────
const HTML = `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CyberAgentToolSet — Dashboard</title>
<style>
  :root{--bg:#0d1117;--panel:#161b22;--border:#30363d;--fg:#c9d1d9;--mut:#8b949e;--acc:#58a6ff;
    --crit:#f85149;--high:#ff7b72;--med:#d29922;--low:#3fb950;--info:#8b949e}
  *{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif}
  header{padding:14px 20px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:12px}
  header h1{font-size:16px;margin:0}header .stat{color:var(--mut);font-size:12px}
  .tabs{display:flex;gap:4px;padding:10px 20px 0}.tabs button{background:none;border:none;color:var(--mut);padding:8px 14px;cursor:pointer;border-radius:6px 6px 0 0}
  .tabs button.on{color:var(--fg);background:var(--panel);border:1px solid var(--border);border-bottom:none}
  main{display:grid;grid-template-columns:320px 1fr;gap:16px;padding:16px 20px}
  .panel{background:var(--panel);border:1px solid var(--border);border-radius:8px;padding:14px;overflow:auto;max-height:calc(100vh - 150px)}
  .item{padding:8px 10px;border:1px solid var(--border);border-radius:6px;margin-bottom:8px;cursor:pointer}
  .item:hover{border-color:var(--acc)}.item .t{font-weight:600}.item .s{color:var(--mut);font-size:12px}
  input,select,button.go{background:var(--bg);border:1px solid var(--border);color:var(--fg);padding:8px;border-radius:6px;width:100%}
  button.go{cursor:pointer;background:var(--acc);color:#04122b;border:none;font-weight:600;width:auto;padding:8px 14px}
  label{display:flex;gap:6px;align-items:center;color:var(--mut);font-size:13px;margin:8px 0}
  h2{font-size:14px;margin:0 0 10px}.row{display:flex;gap:8px;margin-bottom:10px;flex-wrap:wrap}
  pre{white-space:pre-wrap;word-break:break-word;background:var(--bg);border:1px solid var(--border);border-radius:6px;padding:12px;font-size:12.5px}
  .pill{display:inline-block;padding:1px 7px;border-radius:10px;font-size:11px;margin-right:4px}
  .crit{background:var(--crit);color:#fff}.high{background:var(--high);color:#1b0000}.med{background:var(--med);color:#1b1400}.low{background:var(--low);color:#04210d}.info{background:#21262d;color:var(--mut)}
  .warn{color:var(--med);border:1px solid var(--med);padding:8px;border-radius:6px;margin:8px 0}
  .muted{color:var(--mut)} a{color:var(--acc)}
</style></head><body>
<header><h1>⚡ CyberAgentToolSet</h1><span class="stat" id="stat">loading…</span></header>
<div class="tabs"><button id="tA" class="on" onclick="tab('A')">Assessments</button><button id="tR" onclick="tab('R')">Runs</button></div>
<main>
  <div class="panel" id="left"></div>
  <div class="panel" id="right"><p class="muted">Select or start an assessment.</p></div>
</main>
<script>
const $=s=>document.querySelector(s), L=$('#left'), R=$('#right');
let view='A';
const sev=s=>'<span class="pill '+s+'">'+s+'</span>';
async function api(p,opt){const r=await fetch(p,opt);return r.json();}
async function boot(){const c=await api('/api/capabilities');$('#stat').textContent=c.executors+' executors · '+c.extensions+' extensions';render();}
function tab(t){view=t;$('#tA').className=t==='A'?'on':'';$('#tR').className=t==='R'?'on':'';render();}
async function render(){view==='A'?renderAssessments():renderRuns();}

async function renderAssessments(){
  const list=await api('/api/assessments');
  L.innerHTML='<h2>New assessment</h2><div class="row"><input id="tgt" placeholder="example.com"></div>'
    +'<label><input type="checkbox" id="pv" checked> passive only</label>'
    +'<div class="row"><button class="go" onclick="startA()">Start</button></div><h2>Saved</h2>'
    +(list.length?list.map(a=>'<div class="item" onclick="openA(\\''+a.id+'\\')"><div class="t">'+esc(a.target)+'</div>'
      +'<div class="s">'+a.id+' · '+a.steps+' steps · '+a.findings+' findings</div></div>').join(''):'<p class="muted">none yet</p>');
}
async function startA(){
  const target=$('#tgt').value.trim();if(!target)return;
  const r=await api('/api/assessment/start',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({target,passive:$('#pv').checked})});
  if(r.error){R.innerHTML='<p class="warn">'+esc(r.error)+'</p>';return;}
  await renderAssessments();openA(r.id);
}
async function openA(id){
  const rep=await api('/api/assessment/'+id+'/report');
  const sc=rep.severityCounts||{};
  let h='<div class="row"><h2 style="flex:1">'+esc(rep.target)+' <span class="muted">'+id+'</span></h2>'
    +'<button class="go" onclick="runA(\\''+id+'\\')">Run top 5</button> <button class="go" onclick="openA(\\''+id+'\\')">Refresh</button></div>';
  if(rep.reachability&&!rep.reachability.resolves)h+='<div class="warn">⚠ Target does not resolve ('+esc(rep.reachability.reason)+') — likely a typo or nonexistent.</div>';
  if(rep.diagnostics&&rep.diagnostics.length)h+=rep.diagnostics.map(d=>'<div class="warn">⚠ '+esc(d)+'</div>').join('');
  h+='<p>'+sev('critical')+sc.critical+' '+sev('high')+sc.high+' '+sev('medium')+sc.medium+' '+sev('low')+sc.low+' '+sev('info')+sc.info+'</p>';
  if(rep.topRisks&&rep.topRisks.length){h+='<h2>Top risks</h2>'+rep.topRisks.map(r=>'<div>'+sev(r.severity)+esc(r.message)+'</div>').join('');}
  h+='<h2>Entities</h2>'+(Object.keys(rep.entities||{}).length?Object.entries(rep.entities).map(([t,v])=>'<div><b>'+t+'</b> ('+v.length+'): <span class="muted">'+esc(v.slice(0,25).join(', '))+'</span></div>').join(''):'<p class="muted">none</p>');
  h+='<h2>Coverage</h2><p class="muted">'+rep.coverage.stepsRun+' steps · '+rep.coverage.executorsUsed+' executors</p>';
  R.innerHTML=h;
}
async function runA(id){R.innerHTML='<p class="muted">running…</p>';await api('/api/assessment/'+id+'/run',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({top:5})});await renderAssessments();openA(id);}

let diffSel=[];
async function renderRuns(){
  const list=await api('/api/runs');diffSel=[];
  L.innerHTML='<h2>Run reports</h2>'+(list.length?list.map(r=>'<div class="item"><div class="t" onclick="openRun(\\''+esc(r.file)+'\\')">'+esc(r.target)+'</div>'
    +'<div class="s">'+esc(r.title)+' · '+r.steps+' steps · '+r.at.slice(0,16).replace("T"," ")+'</div>'
    +'<label><input type="checkbox" onchange="pickDiff(\\''+esc(r.file)+'\\',this.checked)"> diff</label></div>').join(''):'<p class="muted">no runs yet</p>')
    +'<div class="row"><button class="go" onclick="doDiff()">Diff selected (2)</button></div>';
}
function pickDiff(f,on){if(on){diffSel.push(f);if(diffSel.length>2)diffSel.shift();}else diffSel=diffSel.filter(x=>x!==f);}
async function openRun(f){const r=await api('/api/run/'+encodeURIComponent(f));R.innerHTML='<h2>'+esc(r.target||f)+'</h2><pre>'+esc(JSON.stringify(r.summary||r,null,2).slice(0,8000))+'</pre>';}
async function doDiff(){if(diffSel.length!==2){R.innerHTML='<p class="warn">Select exactly 2 runs.</p>';return;}
  const d=await api('/api/diff?a='+encodeURIComponent(diffSel[0])+'&b='+encodeURIComponent(diffSel[1]));
  R.innerHTML='<h2>Diff</h2><pre>'+esc(JSON.stringify(d,null,2).slice(0,8000))+'</pre>';}
function esc(s){return String(s==null?'':s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));}
boot();
</script></body></html>`;
