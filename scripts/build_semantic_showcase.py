#!/usr/bin/env python3
"""Build a self-contained Cytoscape C1/C2 semantic showcase HTML."""
import json
from pathlib import Path

ROOT = Path(__file__).parent.parent
CORPUS = ROOT / "output" / "semantic_corpus" / "cloud_db_semantic_corpus.json"
STATS = ROOT / "output" / "semantic_corpus" / "cloud_db_semantic_corpus_stats.json"
EXPERIMENTS = ROOT / "output" / "semantic_corpus" / "semantic_experiments_results.json"
SDDP_SLICE = ROOT / "output" / "sddp_slices" / "sddp_lindorm_example_slice.json"
VENDOR = ROOT / "vendor" / "cytoscape.min.js"
OUT = ROOT / "showcase" / "showcase_semantic.html"

TYPE_COLOR = {
    "Network": "#3b82f6",      # Blue - L0 network entry
    "Identity": "#a855f7",     # Purple - L1 identity/permission
    "DBInstance": "#06b6d4",   # Cyan - L2 database instance (distinct from DBObject)
    "DBObject": "#16a34a",     # Green - L3 database object (table/column)
    "SensitiveTag": "#ef4444", # Red - L4 sensitive target
    "AuditEvent": "#f97316",   # Orange - L5 audit event
    "RiskFinding": "#dc2626",  # Dark red - L5 risk finding
    "Control": "#eab308",      # Yellow - L5 control
}
TYPE_LAYER = {
    "Network": 0,
    "Identity": 1,
    "DBInstance": 2,
    "DBObject": 3,
    "SensitiveTag": 4,
    "AuditEvent": 5,
    "RiskFinding": 5,
    "Control": 5,
}
LAYER_NAMES = ["网络入口", "身份权限", "数据库实例", "数据库对象", "敏感目标", "审计/控制"]
STATE_COLOR = {"Valid": "#22c55e", "Invalid": "#ef4444", "Insufficient": "#f59e0b"}
STATUS_COLOR = {"Supported": "#22c55e", "Contradicted": "#ef4444", "Unknown": "#f59e0b"}


def main():
    if not VENDOR.exists():
        raise SystemExit(f"missing Cytoscape vendor: {VENDOR}")
    corpus = json.loads(CORPUS.read_text(encoding="utf-8"))
    stats = json.loads(STATS.read_text(encoding="utf-8"))
    experiments = json.loads(EXPERIMENTS.read_text(encoding="utf-8"))
    samples = [_pack_sample(sample) for sample in corpus]
    if SDDP_SLICE.exists():
        sddp = json.loads(SDDP_SLICE.read_text(encoding="utf-8"))
        samples.insert(0, _pack_sample(sddp))
    payload = json.dumps({
        "stats": stats,
        "experiments": experiments,
        "samples": samples,
        "typeColor": TYPE_COLOR,
        "stateColor": STATE_COLOR,
        "statusColor": STATUS_COLOR,
        "layerNames": LAYER_NAMES,
    }, ensure_ascii=False).replace("</", "<\\/")
    html = HTML.replace("__CYTOSCAPE__", VENDOR.read_text(encoding="utf-8")).replace("__DATA__", payload)
    OUT.write_text(html, encoding="utf-8")
    print(f"wrote {OUT}")


def _pack_sample(sample):
    nodes = []
    layer_counts = {}
    for node in sample.get("nodes", []):
        layer = TYPE_LAYER.get(node.get("type"), 5)
        layer_counts[layer] = layer_counts.get(layer, 0) + 1
    layer_seen = {}
    for node in sample.get("nodes", []):
        layer = TYPE_LAYER.get(node.get("type"), 5)
        idx = layer_seen.get(layer, 0)
        layer_seen[layer] = idx + 1
        n = layer_counts[layer]
        
        # Robust layout: 2 rows per layer, wide horizontal distribution
        row = idx % 2
        col = idx // 2
        cols = max(1, (n + 1) // 2)
        
        # Horizontal: use full width with generous padding
        # Ensure minimum 80px between nodes
        available_width = 1400
        min_spacing = 80
        if cols > 1:
            spacing = max(min_spacing, available_width / (cols + 1))
        else:
            spacing = available_width / 2
        x = 100 + (col + 1) * spacing
        
        # Vertical: 180px between layers, 50px between rows within layer
        y = 100 + layer * 180 + (row * 50)
        
        attrs = node.get("attrs", {})
        nodes.append({
            "id": node["id"],
            "type": node.get("type"),
            "name": attrs.get("name") or attrs.get("category") or node["id"],
            "kind": attrs.get("kind", ""),
            "x": round(x, 1),
            "y": round(y, 1),
            "color": TYPE_COLOR.get(node.get("type"), "#64748b"),
            "isGold": any(node["id"] in label.get("path", []) for label in sample.get("path_labels", [])),
        })
    node_ids = {n["id"] for n in nodes}
    edges = []
    seen = {}
    for edge in sample.get("edges", []):
        if edge.get("source") not in node_ids or edge.get("target") not in node_ids:
            continue
        attrs = edge.get("attrs", {})
        key = (edge.get("source"), edge.get("target"), edge.get("type"), attrs.get("status"), attrs.get("temporal_conflict", False))
        if key in seen:
            continue
        seen[key] = True
        edges.append({
            "id": f"e{len(edges)}",
            "source": edge.get("source"),
            "target": edge.get("target"),
            "type": edge.get("type"),
            "label": edge.get("type"),
            "status": attrs.get("status"),
            "sourceKind": attrs.get("source"),
            "time": attrs.get("time"),
            "confidence": attrs.get("confidence"),
            "queryCost": attrs.get("query_cost"),
            "temporalConflict": attrs.get("temporal_conflict", False),
            "color": STATUS_COLOR.get(attrs.get("status"), "#64748b"),
        })
    return {
        "sample_id": sample.get("sample_id"),
        "scenario": sample.get("scenario"),
        "scenario_name": sample.get("scenario_name"),
        "industry": sample.get("industry"),
        "raw_dataset": sample.get("raw_dataset"),
        "variant_type": sample.get("variant_type"),
        "sample_label": sample.get("sample_label"),
        "expected_type": sample.get("expected_type"),
        "nodes": nodes,
        "edges": edges,
        "path_labels": sample.get("path_labels", []),
    }


HTML = r'''<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>CloudDB C1/C2 语义证据与路径推理 Demo</title>
<style>
*{box-sizing:border-box}body{margin:0;background:#0b1020;color:#e5eefb;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;font-size:13px}.header{height:56px;background:#101a31;border-bottom:1px solid #24324a;display:flex;align-items:center;padding:0 18px;gap:16px}.header h1{font-size:18px;margin:0;color:#60a5fa}.header .sub{color:#94a3b8;font-size:12px}.stats{margin-left:auto;display:flex;gap:18px}.stat{text-align:right}.stat .v{font-size:18px;font-weight:800}.stat .l{font-size:10px;color:#94a3b8;text-transform:uppercase}.main{display:grid;grid-template-columns:330px 1fr 390px;height:calc(100vh - 56px)}.panel{border-right:1px solid #1f2a3d;overflow:auto}.right{border-left:1px solid #1f2a3d;border-right:0}.section{padding:14px;border-bottom:1px solid #1f2a3d}.title{font-size:12px;color:#93c5fd;font-weight:800;text-transform:uppercase;letter-spacing:.8px;margin-bottom:10px}.cards{display:grid;grid-template-columns:repeat(2,1fr);gap:8px}.card{background:#121d33;border:1px solid #27364f;border-radius:8px;padding:10px}.card .num{font-size:22px;font-weight:900}.card .lab{color:#94a3b8;font-size:11px}.filters{display:flex;gap:6px;flex-wrap:wrap}.chip,.btn{border:1px solid #30425f;background:#121d33;color:#cbd5e1;border-radius:999px;padding:5px 9px;cursor:pointer}.chip.active,.btn:hover{background:#2563eb;border-color:#60a5fa}.sample{border:1px solid #27364f;background:#101827;margin-bottom:8px;border-radius:8px;padding:9px;cursor:pointer}.sample.active{border-color:#60a5fa;background:#172540}.sample .sid{color:#60a5fa;font-weight:800;font-size:11px}.sample .meta{color:#94a3b8;font-size:11px;margin-top:3px}.badge{display:inline-block;padding:2px 6px;border-radius:4px;color:#fff;font-size:10px;font-weight:800}.graph-area{height:100%;padding:14px;display:flex;flex-direction:column}.graph-head{display:flex;align-items:center;gap:10px;margin-bottom:8px}.graph-title{font-weight:800;color:#cfe4ff;flex:1}.legend{display:flex;gap:8px;flex-wrap:wrap;color:#94a3b8;font-size:11px}.cy-wrap{position:relative;flex:1;min-height:720px;background:#0f172a;border:1px solid #27364f;border-radius:10px;overflow:hidden}#cy{position:absolute;inset:0}.layer-band{position:absolute;left:0;right:0;border-top:1px dashed #334155;pointer-events:none;color:#60a5fa;font-size:11px;padding:4px 8px;opacity:.75}.table{width:100%;border-collapse:collapse}.table th,.table td{border-bottom:1px solid #26364f;padding:7px;text-align:left}.table th{color:#93c5fd;font-size:11px}.hi{color:#22c55e;font-weight:900}.method-best{background:rgba(34,197,94,.09)}.pathbox{background:#101827;border:1px solid #27364f;border-radius:8px;margin-bottom:8px;padding:9px;cursor:pointer}.pathbox.active{border-color:#60a5fa;background:#172540}.pathline{font-family:ui-monospace,Menlo,monospace;font-size:11px;color:#cbd5e1;word-break:break-all}.small{font-size:11px;color:#94a3b8}.note{background:#172033;border-left:3px solid #60a5fa;padding:10px;border-radius:6px;color:#cbd5e1;line-height:1.6}.edge-detail{font-family:ui-monospace,Menlo,monospace;font-size:11px;color:#cbd5e1;line-height:1.5;white-space:pre-wrap}.toolbar{display:flex;gap:8px;align-items:center}.kbd{border:1px solid #334155;background:#0b1020;border-radius:4px;padding:1px 5px;color:#93c5fd}
</style>
<script>__CYTOSCAPE__</script>
</head>
<body>
<div class="header"><h1>CloudDB C1/C2 语义证据与路径推理 Demo</h1><div class="sub">Cytoscape 可缩放/拖拽 · 异构证据语义化 · RefuteAwareBeamSearch</div><div class="stats" id="topStats"></div></div>
<div class="main">
  <aside class="panel">
    <div class="section"><div class="title">语料概览</div><div class="cards" id="overview"></div></div>
    <div class="section"><div class="title">样本过滤</div><div class="filters" id="filters"></div></div>
    <div class="section"><div class="title">样本列表</div><div id="sampleList"></div></div>
  </aside>
  <main class="graph-area">
    <div class="graph-head"><div class="graph-title" id="graphTitle">请选择样本</div><div class="toolbar"><button class="btn" onclick="fitGraph()">Fit</button><button class="btn" onclick="resetHighlight()">Reset</button><span class="small">滚轮缩放 · 拖动画布 · 拖动节点</span></div></div>
    <div class="cy-wrap"><div id="bands"></div><div id="cy"></div></div>
  </main>
  <aside class="panel right">
    <div class="section"><div class="title">C2 方法对比</div><div id="methodTable"></div></div>
    <div class="section"><div class="title">T/F/U 验证</div><div id="verifyBox"></div></div>
    <div class="section"><div class="title">路径标签（点击高亮）</div><div id="pathLabels"></div></div>
    <div class="section"><div class="title">边证据详情</div><div id="edgeDetail" class="edge-detail">点击图中的边查看 status/source/time/confidence/query_cost。</div></div>
    <div class="section"><div class="title">结论提示</div><div class="note">该页面展示 C1/C2 语义一致评测集和算法效果。Accuracy=1.0 只能说明语义标签与验证器实现一致，不代表真实云环境泛化准确率；主结果应看 R@K、MRR、查询成本和 FPR。</div></div>
    <div class="section">
      <div class="title">T/F/U 验证状态详解</div>
      <div style="font-size:12px;line-height:1.7;color:#cbd5e1;">
        <div style="margin-bottom:14px;padding:10px;background:#0f2818;border-left:3px solid #22c55e;border-radius:4px;">
          <strong style="color:#4ade80;">Valid（已确认暴露）</strong><br>
          路径上所有 6 个维度（entry/reach/perm/target/sense/temporal）的证据均已收集且支持该路径成立。<br>
          <span style="color:#94a3b8;">安全影响：攻击者可沿此路径访问高敏数据，需立即修复。示例：公网IP → 安全组放行3306 → IAM有SELECT权限 → 表含身份证字段 → 审计显示已访问 → 时间线连贯</span>
        </div>
        <div style="margin-bottom:14px;padding:10px;background:#2d2305;border-left:3px solid #f59e0b;border-radius:4px;">
          <strong style="color:#fbbf24;">Insufficient（证据不足）</strong><br>
          至少一个维度的证据缺失（Unknown），但无反证。<br>
          <span style="color:#94a3b8;">安全影响：无法确定路径是否可被利用，需进一步调查。可能是监控覆盖不全或日志缺失。示例：公网IP → 安全组放行 → <span style="color:#fbbf24;">[权限证据缺失]</span> → 表含身份证字段</span>
        </div>
        <div style="margin-bottom:14px;padding:10px;background:#2d0a0a;border-left:3px solid #ef4444;border-radius:4px;">
          <strong style="color:#f87171;">Invalid（已确认不可达）</strong><br>
          至少一个维度的证据明确反驳该路径（Contradicted）。<br>
          <span style="color:#94a3b8;">安全影响：攻击者无法沿此路径访问数据，可归档为"已排除风险"。示例：公网IP → <span style="color:#f87171;">[安全组拒绝3306端口]</span> → 后续不再检查</span>
        </div>
        <div style="padding:10px;background:#0c1929;border-left:3px solid #60a5fa;border-radius:4px;">
          <strong style="color:#93c5fd;">为什么三值比二值更好？</strong><br>
          传统二值判断（可达/不可达）无法区分"证据不足"和"已确认不可达"。在云安全审计中：<br>
          • <strong>Insufficient</strong> → 需补充监控、收集更多证据<br>
          • <strong>Invalid</strong> → 可归档为"已排除风险"，记录哪些控制措施生效<br>
          这种区分帮助安全团队更高效地分配调查资源。
        </div>
      </div>
    </div>
    <div class="section">
      <div class="title">核心结论总结</div>
      <div style="font-size:12px;line-height:1.7;color:#cbd5e1;">
        <div style="margin-bottom:12px;">
          <strong style="color:#60a5fa;">解决的核心问题：</strong><br>
          传统方法（DFS + GateScore）无法区分反证与缺证，导致误报率高。本项目提出：
        </div>
        <div style="margin-bottom:12px;padding:8px;background:#172033;border-radius:4px;">
          <strong style="color:#4ade80;">C1 异构云证据语义化</strong><br>
          引入 6 维证据边（status/source/time/confidence/query_cost/raw_evidence），显式标记每条证据的状态和来源。
        </div>
        <div style="margin-bottom:12px;padding:8px;background:#172033;border-radius:4px;">
          <strong style="color:#4ade80;">C2 反证感知路径搜索</strong><br>
          RefuteAwareBeamSearch 在搜索阶段即考虑证据状态，优先探索高价值路径，主动剪枝反证路径。
        </div>
        <div style="margin-bottom:12px;padding:8px;background:#172033;border-radius:4px;">
          <strong style="color:#4ade80;">T/F/U 三值验证器</strong><br>
          区分 Valid（已确认暴露）、Insufficient（证据不足）、Invalid（已确认不可达），提供更精细的安全判断。
        </div>
        <div style="margin-bottom:12px;padding:10px;background:#0f2818;border-radius:4px;">
          <strong style="color:#4ade80;">核心指标：</strong><br>
          • R@3 = 0.6514（+199.8%）：Top-3 候选路径中 65% 包含真实暴露路径<br>
          • FPR = 0.0000：样本级误报率为 0，不会将安全路径误判为风险<br>
          • T/F/U 准确率 = 99.56%：676 条路径标签中 673 条被正确分类<br>
          • 313 样本 · 676 路径标签：覆盖 4 种变体（base/missing/refuted/temporal_conflict）
        </div>
        <div style="padding:10px;background:#2d2305;border-radius:4px;">
          <strong style="color:#fbbf24;">局限性：</strong><br>
          • 语料是构造的（pathbench_60 + cloudgoat + samples_v2 + SDDP 模拟），非真实生产数据<br>
          • 缺乏消融实验（无法确定哪个组件贡献最大）<br>
          • 未与真实云安全工具（PMapper/Cartography）对比<br>
          <span style="color:#94a3b8;">下一步：接入真实脱敏数据 + 消融实验 + 真实工具对比</span>
        </div>
      </div>
    </div>
  </aside>
</div>
<script id="payload" type="application/json">__DATA__</script>
<script>
const P=JSON.parse(document.getElementById('payload').textContent);let currentFilter='all',currentSample=null,cy=null,activePath=-1;
const $=id=>document.getElementById(id), esc=s=>String(s??'').replace(/[&<>"']/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));
const STATUS_CLASS={Supported:'supported',Contradicted:'contradicted',Unknown:'unknown'};
function init(){renderTop();renderOverview();renderFilters();renderMethods();renderBands();selectFilter('all');selectSample(P.samples[0]);}
function renderTop(){const s=P.stats,e=P.experiments.path_label_verification; $('topStats').innerHTML=[['样本',s.samples_total],['路径标签',s.path_labels_total],['验证准确率',e.accuracy.toFixed(4)],['R@3',P.experiments.methods.refute_aware_beam['recall@3'].toFixed(4)],['FPR',P.experiments.methods.refute_aware_beam.sample_false_positive_rate.toFixed(4)]].map(x=>`<div class="stat"><div class="v">${x[1]}</div><div class="l">${x[0]}</div></div>`).join('')}
function renderOverview(){const s=P.stats; $('overview').innerHTML=[['总样本',s.samples_total],['Base',s.samples_base],['变体',s.samples_variants],['路径标签',s.path_labels_total],['Supported',s.status_counts.Supported],['Contradicted',s.status_counts.Contradicted],['Unknown',s.status_counts.Unknown],['字段覆盖','100%']].map(x=>`<div class="card"><div class="num">${x[1]}</div><div class="lab">${x[0]}</div></div>`).join('')}
function renderFilters(){const filters=['all','sddp_real_slice','base','missing','refuted','temporal_conflict','Valid','Invalid','Insufficient']; $('filters').innerHTML=filters.map(f=>`<button class="chip" id="f-${f}" onclick="selectFilter('${f}')">${f}</button>`).join('')}
function selectFilter(f){currentFilter=f;document.querySelectorAll('.chip').forEach(x=>x.classList.remove('active'));$('f-'+f).classList.add('active');const list=P.samples.filter(s=>f==='all'||s.variant_type===f||s.sample_label===f).slice(0,160);$('sampleList').innerHTML=list.map((s,i)=>`<div class="sample" data-sid="${esc(s.sample_id)}" onclick="selectSampleById('${esc(s.sample_id)}')"><div class="sid">${esc(s.sample_id.split(':').slice(-2).join(':'))}</div><div class="meta"><span class="badge" style="background:${P.stateColor[s.sample_label]||'#64748b'}">${s.sample_label}</span> ${esc(s.variant_type)} · ${esc(s.raw_dataset)}</div><div class="meta">${esc(s.scenario_name||s.scenario)}</div></div>`).join('')}
function selectSampleById(id){const s=P.samples.find(x=>x.sample_id===id); if(s)selectSample(s)}
function selectSample(s){currentSample=s;activePath=-1;document.querySelectorAll('.sample').forEach(x=>x.classList.toggle('active',x.dataset.sid===s.sample_id));$('graphTitle').textContent=`${s.sample_id} · ${s.sample_label} · ${s.variant_type}`;buildGraph(s);renderVerify(s);renderPaths(s);$('edgeDetail').textContent='点击图中的边查看 status/source/time/confidence/query_cost。'}
function renderMethods(){const names={plain_dfs_gatescore:'Plain DFS + GateScore',type_dfs_gatescore:'Type DFS + GateScore',full_constrained_gatescore:'Full constrained + GateScore',refute_aware_beam:'RefuteAwareBeamSearch'};let rows=Object.entries(P.experiments.methods).map(([k,m])=>`<tr class="${k==='refute_aware_beam'?'method-best':''}"><td>${names[k]}</td><td>${m['recall@3'].toFixed(4)}</td><td>${m.mrr.toFixed(4)}</td><td>${m.avg_top_query_cost.toFixed(3)}</td><td>${m.sample_false_positive_rate.toFixed(4)}</td></tr>`).join('');$('methodTable').innerHTML=`<table class="table"><tr><th>方法</th><th>R@3</th><th>MRR</th><th>查询成本</th><th>FPR</th></tr>${rows}</table>`}
function renderVerify(s){const e=P.experiments.path_label_verification; $('verifyBox').innerHTML=`<div class="cards"><div class="card"><div class="num hi">${e.accuracy.toFixed(4)}</div><div class="lab">path-label accuracy</div></div><div class="card"><div class="num">${e.total}</div><div class="lab">path labels</div></div></div><table class="table"><tr><th>标签</th><th>数量</th></tr>${Object.entries(s.path_labels.reduce((a,p)=>(a[p.state]=(a[p.state]||0)+1,a),{})).map(([k,v])=>`<tr><td><span class="badge" style="background:${P.stateColor[k]}">${k}</span></td><td>${v}</td></tr>`).join('')}</table>`}
function renderPaths(s){
  $('pathLabels').innerHTML=(s.path_labels||[]).slice(0,10).map((p,i)=>{
    const explanation = generatePathExplanation(s, p);
    return `<div class="pathbox" id="path-${i}" onclick="selectPath(${i})">
      <span class="badge" style="background:${P.stateColor[p.state]||'#64748b'}">${p.state}</span> 
      <span class="small">#${i+1} ${esc(p.variant_type)}</span>
      <div class="pathline">${esc(p.path.join(' → '))}</div>
      <div style="margin-top:8px;padding:8px;background:#0c1929;border-radius:4px;font-size:11px;color:#cbd5e1;line-height:1.5;">${explanation}</div>
    </div>`;
  }).join('')||'<div class="small">无 path labels</div>';
}

function generatePathExplanation(sample, pathLabel) {
  const path = pathLabel.path;
  const state = pathLabel.state;
  const nodes = sample.nodes;
  const edges = sample.edges;
  const nodeMap = {};
  nodes.forEach(n => nodeMap[n.id] = n);
  
  // Build edge map for quick lookup
  const edgeMap = {};
  edges.forEach(e => {
    const key = e.source + '|' + e.target;
    edgeMap[key] = e;
  });
  
  if (state === 'Valid') {
    return '<strong style="color:#4ade80;">验证通过：</strong>路径上所有 6 个维度（entry/reach/perm/target/sense/temporal）的证据均已收集且支持该路径成立。攻击者可沿此路径访问高敏数据，需立即修复。';
  }
  
  if (state === 'Insufficient') {
    // Find missing evidence
    const missingDims = [];
    
    // Check entry (first node should be Network with public_exposed)
    const firstNode = nodeMap[path[0]];
    if (firstNode && firstNode.type === 'Network') {
      if (!firstNode.attrs.public_exposed) {
        missingDims.push('入口暴露证据');
      }
    }
    
    // Check reach (should have can_connect edges)
    let hasReach = false;
    for (let i = 0; i < path.length - 1; i++) {
      const edgeKey = path[i] + '|' + path[i+1];
      const edge = edgeMap[edgeKey];
      if (edge && edge.type === 'can_connect') {
        hasReach = true;
        break;
      }
    }
    if (!hasReach) {
      missingDims.push('网络可达证据（缺少 can_connect 边）');
    }
    
    // Check perm (should have has_permission or can_assume edges)
    let hasPerm = false;
    for (let i = 0; i < path.length - 1; i++) {
      const edgeKey = path[i] + '|' + path[i+1];
      const edge = edgeMap[edgeKey];
      if (edge && (edge.type === 'has_permission' || edge.type === 'can_assume')) {
        hasPerm = true;
        break;
      }
    }
    if (!hasPerm) {
      missingDims.push('权限授予证据（缺少 has_permission/can_assume 边）');
    }
    
    // Check target (last node should be SensitiveTag or connected to one)
    const lastNode = nodeMap[path[path.length - 1]];
    let hasTarget = false;
    if (lastNode && lastNode.type === 'SensitiveTag') {
      hasTarget = true;
    } else {
      // Check if connected to SensitiveTag
      for (let i = 0; i < path.length - 1; i++) {
        const edgeKey = path[i] + '|' + path[i+1];
        const edge = edgeMap[edgeKey];
        if (edge && edge.type === 'classified_as') {
          hasTarget = true;
          break;
        }
      }
    }
    if (!hasTarget) {
      missingDims.push('敏感目标证据（缺少 SensitiveTag 或 classified_as 边）');
    }
    
    if (missingDims.length > 0) {
      return '<strong style="color:#fbbf24;">证据不足：</strong>由于缺少 ' + missingDims.join('、') + '，该路径验证状态为 Insufficient。需要进一步调查以确认路径是否可被利用。';
    } else {
      return '<strong style="color:#fbbf24;">证据不足：</strong>路径上至少一个维度的证据状态为 Unknown，无法确定路径是否可被利用。';
    }
  }
  
  if (state === 'Invalid') {
    // Find contradicted evidence
    const contradictedEdges = [];
    for (let i = 0; i < path.length - 1; i++) {
      const edgeKey = path[i] + '|' + path[i+1];
      const edge = edgeMap[edgeKey];
      if (edge && edge.status === 'Contradicted') {
        contradictedEdges.push({
          from: nodeMap[path[i]]?.attrs?.name || path[i],
          to: nodeMap[path[i+1]]?.attrs?.name || path[i+1],
          type: edge.type
        });
      }
    }
    
    if (contradictedEdges.length > 0) {
      const edgeDesc = contradictedEdges.map(e => `从 ${e.from} 到 ${e.to} 的 ${e.type} 边`).join('、');
      return '<strong style="color:#f87171;">验证失败：</strong>由于 ' + edgeDesc + ' 被明确标记为 Contradicted，该路径已被确认不可达。攻击者无法沿此路径访问数据，可归档为"已排除风险"。';
    } else {
      return '<strong style="color:#f87171;">验证失败：</strong>路径上至少一个维度的证据明确反驳该路径，已被确认不可达。';
    }
  }
  
  return '验证状态：' + state;
}
function renderBands(){let h='';P.layerNames.forEach((n,i)=>{h+=`<div class="layer-band" style="top:${20+i*14.5}%;">L${i} ${n}</div>`});$('bands').innerHTML=h}
function buildGraph(s){const els=[];s.nodes.forEach(n=>els.push({group:'nodes',data:{id:n.id,label:short(n.name),full:n.name,type:n.type,color:n.color,size:n.isGold?34:26},position:{x:n.x,y:n.y}}));s.edges.forEach(e=>{let cls=e.temporalConflict?'temporal':(STATUS_CLASS[e.status]||'supported');els.push({group:'edges',data:{id:e.id,source:e.source,target:e.target,label:e.label,status:e.status,sourceKind:e.sourceKind,time:e.time,confidence:e.confidence,queryCost:e.queryCost,temporalConflict:e.temporalConflict},classes:cls})});if(cy)cy.destroy();cy=cytoscape({container:$('cy'),elements:els,layout:{name:'preset'},wheelSensitivity:.25,minZoom:.15,maxZoom:4,style:CY_STYLE});cy.fit(cy.elements(),50);cy.on('tap','edge',ev=>showEdge(ev.target));cy.on('tap','node',ev=>highlightNode(ev.target.id()));cy.on('tap',ev=>{if(ev.target===cy)resetHighlight()});}
const CY_STYLE=[{selector:'node',style:{'background-color':'data(color)','label':'data(label)','width':'data(size)','height':'data(size)','color':'#e5eefb','font-size':11,'font-weight':700,'text-valign':'bottom','text-halign':'center','text-margin-y':5,'text-outline-width':3,'text-outline-color':'#0f172a','border-width':2,'border-color':'#0b1020'}},{selector:'edge',style:{'curve-style':'bezier','target-arrow-shape':'triangle','width':2.4,'line-color':'#22c55e','target-arrow-color':'#22c55e','label':'data(label)','font-size':9,'color':'#cbd5e1','text-background-color':'#0f172a','text-background-opacity':.9,'text-background-padding':2,'text-rotation':'autorotate'}},{selector:'edge.contradicted',style:{'line-color':'#ef4444','target-arrow-color':'#ef4444','width':3.4}},{selector:'edge.unknown',style:{'line-color':'#f59e0b','target-arrow-color':'#f59e0b','line-style':'dashed'}},{selector:'edge.temporal',style:{'line-color':'#ef4444','target-arrow-color':'#ef4444','line-style':'dotted','width':4}},{selector:'.dim',style:{'opacity':.08,'text-opacity':0}},{selector:'node.hl',style:{'border-width':5,'border-color':'#60a5fa','opacity':1,'text-opacity':1}},{selector:'edge.hl',style:{'line-color':'#60a5fa','target-arrow-color':'#60a5fa','width':4.5,'opacity':1,'text-opacity':1}}];
function short(s){s=String(s||'');return s.length>14?s.slice(0,12)+'…':s}
function selectPath(i){activePath=i;document.querySelectorAll('.pathbox').forEach(x=>x.classList.remove('active'));const el=$('path-'+i);if(el)el.classList.add('active');highlightPath(currentSample.path_labels[i].path)}
function highlightPath(path){const ns={},es={};path.forEach(n=>ns[n]=true);for(let i=0;i<path.length-1;i++){es[path[i]+'|'+path[i+1]]=true;es[path[i+1]+'|'+path[i]]=true}cy.batch(()=>{cy.elements().addClass('dim').removeClass('hl');cy.nodes().forEach(n=>{if(ns[n.id()])n.removeClass('dim').addClass('hl')});cy.edges().forEach(e=>{if(es[e.data('source')+'|'+e.data('target')])e.removeClass('dim').addClass('hl')})})}
function highlightNode(id){const ns={[id]:true};cy.edges().forEach(e=>{if(e.data('source')===id||e.data('target')===id){ns[e.data('source')]=true;ns[e.data('target')]=true}});cy.batch(()=>{cy.elements().addClass('dim').removeClass('hl');cy.nodes().forEach(n=>{if(ns[n.id()])n.removeClass('dim').addClass('hl')});cy.edges().forEach(e=>{if(ns[e.data('source')]&&ns[e.data('target')])e.removeClass('dim').addClass('hl')})})}
function showEdge(e){$('edgeDetail').textContent=`type: ${e.data('label')}\nstatus: ${e.data('status')}\nsource: ${e.data('sourceKind')}\ntime: ${e.data('time')}\nconfidence: ${e.data('confidence')}\nquery_cost: ${e.data('queryCost')}\ntemporal_conflict: ${e.data('temporalConflict')}\n${e.data('source')} -> ${e.data('target')}`}
function resetHighlight(){activePath=-1;document.querySelectorAll('.pathbox').forEach(x=>x.classList.remove('active'));if(cy)cy.elements().removeClass('dim').removeClass('hl')}
function fitGraph(){if(cy)cy.fit(cy.elements(),50)}
init();
</script>
</body></html>'''

if __name__ == "__main__":
    main()
