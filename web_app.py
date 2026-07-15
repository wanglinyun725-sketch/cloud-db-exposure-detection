#!/usr/bin/env python3
"""EIC-Agent 暴露路径侦测系统 — Web 可视化看板"""

import json
import os

from flask import Flask, Response

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RESULTS_FILE = os.path.join(BASE_DIR, "output", "web_results_v2.json")
SAMPLES_FILE = os.path.join(BASE_DIR, "data", "verification_set", "samples_v2.json")

LAYER_Y = {0: 60, 1: 220, 2: 380, 3: 540, 4: 700}

TYPE_LAYER = {
    "Network": 0, "Identity": 1,
    "DBInstance": 2, "DBObject": 2,
    "SensitiveTag": 3,
    "AuditEvent": 4, "Control": 4, "RiskFinding": 4,
}
TYPE_COLOR = {
    "Network": "#3b82f6", "Identity": "#a855f7",
    "DBInstance": "#22c55e", "DBObject": "#16a34a",
    "SensitiveTag": "#ef4444",
    "Control": "#eab308", "AuditEvent": "#f97316", "RiskFinding": "#dc2626",
}


def _layer_of(node):
    return TYPE_LAYER.get(node.get("type", ""), 4)


def _is_noise(node):
    nid = node.get("id", "")
    return nid.startswith("noise_") or node.get("attrs", {}).get("_is_noise", False)


def _assign_xy(nodes):
    groups = {}
    for n in nodes:
        groups.setdefault(_layer_of(n), []).append(n)
    pos = {}
    for lyr, items in groups.items():
        m = len(items)
        if m == 0:
            continue
        if m == 1:
            pos[items[0]["id"]] = (500, LAYER_Y[lyr])
        else:
            step = 900.0 / (m + 1)
            for i, nd in enumerate(items):
                pos[nd["id"]] = (round(step * (i + 1), 1), LAYER_Y[lyr])
    return pos


def _dedup_edges(edges):
    """按 (source, target, type) 去重，避免图谱出现重复的平行边"""
    seen = set()
    result = []
    for e in edges:
        key = (e.get("source"), e.get("target"), e.get("type"))
        if key in seen:
            continue
        seen.add(key)
        result.append(e)
    return result


def _load_data():
    with open(RESULTS_FILE, "r", encoding="utf-8") as f:
        results = json.load(f)
    with open(SAMPLES_FILE, "r", encoding="utf-8") as f:
        samples = json.load(f)

    sample_map = {s["sample_id"]: s for s in samples}
    merged = {}

    for case_id, case_data in results.items():
        samp = sample_map.get(case_id, {})
        raw_nodes = samp.get("nodes", [])
        edges = _dedup_edges(samp.get("edges", []))
        gold_paths = samp.get("gold_paths", [])
        positions = _assign_xy(raw_nodes)

        nodes_out = []
        for n in raw_nodes:
            nid = n["id"]
            x, y = positions.get(nid, (500, 300))
            nodes_out.append({
                "id": nid, "type": n["type"],
                "attrs": n.get("attrs", {}),
                "layer": _layer_of(n), "x": x, "y": y,
                "is_noise": _is_noise(n),
            })

        merged[case_id] = {
            "scenario": case_data.get("scenario", ""),
            "scenario_name": case_data.get("scenario_name", ""),
            "industry": case_data.get("industry", ""),
            "expected": case_data.get("expected", ""),
            "entries": case_data.get("entries", []),
            "targets": case_data.get("targets", []),
            "node_count": case_data.get("node_count", 0),
            "edge_count": case_data.get("edge_count", 0),
            "results": case_data.get("results", []),
            "nodes": nodes_out, "edges": edges, "gold_paths": gold_paths,
        }
    return merged


@app.route("/")
def index():
    data = _load_data()
    stats = {
        "cases": len(data),
        "paths": sum(len(c["results"]) for c in data.values()),
        "passed": sum(1 for c in data.values() for r in c["results"] if r.get("gate_result", {}).get("gate") == 1),
        "blocked": sum(1 for c in data.values() for r in c["results"] if r.get("gate_result", {}).get("gate") == 0),
        "max_score": round(max((r.get("gate_result", {}).get("score", 0) for c in data.values() for r in c["results"]), default=0), 4),
    }
    data_json = json.dumps(data, ensure_ascii=False).replace("</", "<\\/")
    stats_json = json.dumps(stats, ensure_ascii=False).replace("</", "<\\/")
    html = _HTML.replace("__DATA_JSON__", data_json).replace("__STATS_JSON__", stats_json)
    return Response(html, mimetype="text/html; charset=utf-8")

_HTML = r'''<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>EIC-Agent 暴露路径侦测系统</title>
<script src="https://unpkg.com/cytoscape@3.34.0/dist/cytoscape.min.js"></script>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0f1419;color:#e2e8f0;font-family:'Segoe UI',system-ui,-apple-system,sans-serif;font-size:14px;min-height:100vh}
.header{background:linear-gradient(135deg,#0c1929 0%,#142244 100%);border-bottom:1px solid #1e3a5f;padding:14px 24px;display:flex;align-items:center;gap:12px}
.header h1{font-size:20px;font-weight:700;color:#60a5fa;letter-spacing:1px}
.header .subtitle{color:#64748b;font-size:12px;margin-left:8px}
.header .badge{margin-left:auto;background:rgba(59,130,246,.15);color:#60a5fa;padding:4px 12px;border-radius:4px;font-size:12px;border:1px solid rgba(59,130,246,.3)}
.stats-row{display:flex;gap:12px;padding:16px 24px;background:#111827;border-bottom:1px solid #1e293b}
.stat-card{flex:1;background:linear-gradient(135deg,#1a2332 0%,#1e293b 100%);border:1px solid #2a3a4a;border-radius:8px;padding:14px 16px;display:flex;align-items:center;gap:12px;transition:border-color .2s}
.stat-card:hover{border-color:#3b82f6}
.stat-card .stat-icon{font-size:24px;width:40px;height:40px;display:flex;align-items:center;justify-content:center;border-radius:8px}
.stat-card .stat-info{flex:1}
.stat-card .stat-label{font-size:11px;color:#64748b;text-transform:uppercase;letter-spacing:.5px}
.stat-card .stat-value{font-size:22px;font-weight:700;color:#e2e8f0;margin-top:2px}
.main{display:flex;height:calc(100vh - 140px)}
.sidebar{width:280px;min-width:280px;background:#111827;border-right:1px solid #1e293b;overflow-y:auto;padding:12px}
.sidebar-title{font-size:12px;color:#64748b;text-transform:uppercase;letter-spacing:1px;padding:8px 4px 12px;border-bottom:1px solid #1e293b;margin-bottom:8px}
.case-card{background:#1a2332;border:1px solid #2a3a4a;border-radius:8px;padding:12px;margin-bottom:8px;cursor:pointer;transition:all .2s}
.case-card:hover{border-color:#3b82f6;background:#1e293b}
.case-card.active{border-color:#3b82f6;background:rgba(59,130,246,.08);box-shadow:0 0 0 1px rgba(59,130,246,.3)}
.case-card .case-id{font-size:11px;color:#60a5fa;font-weight:600;letter-spacing:.5px}
.case-card .case-name{font-size:13px;color:#e2e8f0;margin-top:4px;line-height:1.4}
.case-card .case-meta{display:flex;gap:8px;margin-top:6px;align-items:center}
.case-card .meta-chip{font-size:10px;padding:2px 6px;border-radius:3px;background:rgba(100,116,139,.2);color:#94a3b8}
.case-card .meta-score{font-size:11px;color:#fbbf24;font-weight:600}
.right-panel{flex:1;overflow-y:auto;padding:16px 24px}
.section{margin-bottom:20px}
.section-title{font-size:13px;color:#94a3b8;text-transform:uppercase;letter-spacing:1px;margin-bottom:8px;display:flex;align-items:center;gap:6px}
.guide-card{background:#1a2332;border:1px solid #2a3a4a;border-radius:8px;padding:12px 16px}
.guide-card .guide-row{display:flex;align-items:center;gap:8px;margin:4px 0;font-size:12px;color:#94a3b8}
.guide-card .color-dot{width:12px;height:12px;border-radius:3px;flex-shrink:0}
.guide-card .guide-layer{display:flex;gap:16px;flex-wrap:wrap;margin-top:8px;padding-top:8px;border-top:1px solid #2a3a4a}
.guide-card .layer-tag{font-size:11px;padding:3px 8px;border-radius:4px}
.narrative-card{background:linear-gradient(135deg,#1a2332 0%,#1e293b 100%);border:1px solid #2a3a4a;border-radius:8px;padding:14px 18px}
.narrative-card .narr-title{font-size:15px;font-weight:600;color:#60a5fa;margin-bottom:8px}
.narrative-card .narr-row{display:flex;gap:8px;margin:4px 0;font-size:13px}
.narrative-card .narr-label{color:#64748b;min-width:80px;flex-shrink:0}
.narrative-card .narr-val{color:#e2e8f0}
.narrative-card .narr-desc{margin-top:10px;padding:10px 12px;background:rgba(239,68,68,.08);border-left:3px solid #ef4444;border-radius:4px;font-size:13px;color:#fca5a5;line-height:1.6}
.graph-wrapper{position:relative;width:100%;height:800px;background:#0d1117;border:1px solid #1e293b;border-radius:8px;overflow:hidden}
#bands-container{position:absolute;top:0;left:0;right:0;bottom:0;z-index:0;pointer-events:none}
.layer-band{position:absolute;left:0;right:0;border-radius:4px}
.band-label{position:absolute;left:10px;top:50%;transform:translateY(-50%);font-size:11px;color:rgba(148,163,184,.5);writing-mode:vertical-rl;text-orientation:mixed;letter-spacing:2px}
#cy{position:absolute;top:0;left:0;right:0;bottom:0;z-index:1;background:transparent}
.legend{display:flex;flex-wrap:wrap;gap:8px;padding:10px 14px;background:#1a2332;border:1px solid #2a3a4a;border-radius:8px}
.legend-item{display:flex;align-items:center;gap:6px;font-size:12px;color:#94a3b8}
.legend-dot{width:14px;height:14px;border-radius:3px;flex-shrink:0}
.legend-gold{border:2px solid #fbbf24}
.legend-noise{opacity:.3}
.path-list{display:flex;flex-direction:column;gap:10px}
.path-item{background:#1a2332;border:1px solid #2a3a4a;border-radius:8px;padding:14px 16px;transition:border-color .2s}
.path-item.path-highlight{border-color:#60a5fa;box-shadow:0 0 0 1px rgba(96,165,250,.3)}
.path-header{display:flex;align-items:center;gap:10px;margin-bottom:10px;flex-wrap:wrap}
.path-num{font-size:12px;font-weight:700;color:#64748b;background:rgba(100,116,139,.2);padding:2px 8px;border-radius:4px}
.path-type-badge{font-size:11px;padding:3px 8px;border-radius:4px;font-weight:600;color:#fff}
.path-score{font-size:12px;color:#fbbf24;font-family:monospace}
.path-gate{font-size:11px;padding:3px 8px;border-radius:4px;font-weight:600}
.gate-pass{background:rgba(34,197,94,.15);color:#4ade80;border:1px solid rgba(34,197,94,.3)}
.gate-block{background:rgba(239,68,68,.15);color:#f87171;border:1px solid rgba(239,68,68,.3)}
.path-steps{display:flex;flex-wrap:wrap;align-items:center;gap:4px;margin-bottom:10px;padding:8px 10px;background:#0d1117;border-radius:6px}
.step-chip{display:inline-flex;align-items:center;gap:4px;border:1px solid #2a3a4a;border-radius:4px;padding:2px 6px}
.step-type{font-size:9px;padding:1px 4px;border-radius:2px;color:#fff;font-weight:600}
.step-name{font-size:11px;color:#cbd5e1;font-family:monospace}
.step-arrow{color:#475569;font-size:12px}
.evidence-grid{display:grid;grid-template-columns:repeat(5,1fr);gap:8px;margin-bottom:10px}
.ev-item{display:flex;flex-direction:column;align-items:center;gap:3px}
.ev-label{font-size:10px;color:#94a3b8;text-transform:uppercase;letter-spacing:.5px}
.ev-bar{width:100%;height:6px;background:rgba(100,116,139,.15);border-radius:3px;overflow:hidden}
.ev-fill{height:100%;border-radius:3px;transition:width .3s}
.ev-val{font-size:10px;color:#64748b;font-family:monospace}
.detail-section{margin-top:8px;padding-top:8px;border-top:1px solid #2a3a4a}
.detail-label{font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.5px;margin-bottom:4px;display:inline-block;padding:2px 6px;border-radius:3px}
.detail-label.attr{background:rgba(168,85,247,.15);color:#c084fc}
.detail-label.remed{background:rgba(34,197,94,.15);color:#4ade80}
.detail-text{font-size:13px;color:#cbd5e1;line-height:1.7}
::-webkit-scrollbar{width:8px;height:8px}
::-webkit-scrollbar-track{background:#0d1117}
::-webkit-scrollbar-thumb{background:#2a3a4a;border-radius:4px}
::-webkit-scrollbar-thumb:hover{background:#3b82f6}
.loading{text-align:center;padding:40px;color:#64748b}
</style>
</head>
<body>

<div class="header">
  <h1>EIC-Agent 暴露路径侦测系统</h1>
  <span class="subtitle">CloudDB-PathBench 可视化看板</span>
  <span class="badge">DeepSeek LLM 真实结果</span>
</div>

<div class="stats-row" id="stats-row"></div>

<div class="main">
  <div class="sidebar">
    <div class="sidebar-title">案例列表</div>
    <div id="case-list"></div>
  </div>
  <div class="right-panel" id="right-panel">
    <div class="loading">加载中…</div>
  </div>
</div>

<script id="embedded-data" type="application/json">__DATA_JSON__</script>
<script id="embedded-stats" type="application/json">__STATS_JSON__</script>

<script>
const EDGE_LABELS = {'can_connect':'网络可达','has_permission':'授予权限','can_assume':'可扮演角色','contains':'包含','classified_as':'分类标记','accessed':'访问','triggered':'触发','has_risk':'存在风险','protected_by':'受控于','owns':'拥有','stores_data':'存储数据','exposes_port':'暴露端口','trusts_identity':'信任身份','NetworkReach':'网络可达','HasRole':'拥有角色','CanAssume':'可扮演','HasPermission':'授予权限','StoresData':'存储数据','ContainsSensitive':'含敏感数据','LogsTo':'记录至','ExposesPort':'暴露端口','TrustsIdentity':'信任身份','AccessesData':'访问数据'};

(function(){
  'use strict';

  var DATA  = JSON.parse(document.getElementById('embedded-data').textContent);
  var STATS = JSON.parse(document.getElementById('embedded-stats').textContent);

  var LAYER_Y     = [50, 170, 290, 410, 530];
  var LAYER_NAMES = ['网络入口层', '身份权限层', '数据库层', '敏感数据层', '审计 / 噪声层'];
  var LAYER_BG    = ['rgba(59,130,246,0.08)','rgba(168,85,247,0.08)','rgba(34,197,94,0.08)','rgba(239,68,68,0.08)','rgba(234,179,8,0.08)'];
  var LAYER_BORDER= ['rgba(59,130,246,0.18)','rgba(168,85,247,0.18)','rgba(34,197,94,0.18)','rgba(239,68,68,0.18)','rgba(234,179,8,0.18)'];

  var TYPE_COLOR = {'Network':'#3b82f6','Identity':'#a855f7','DBInstance':'#22c55e','DBObject':'#16a34a','SensitiveTag':'#ef4444','Control':'#eab308','AuditEvent':'#f97316','RiskFinding':'#dc2626'};
  var TYPE_LABEL = {'Network':'网络','Identity':'身份','DBInstance':'数据库实例','DBObject':'数据库对象','SensitiveTag':'敏感标签','Control':'控制','AuditEvent':'审计','RiskFinding':'风险'};
  var EV_INFO = [{key:'entry',label:'入口',color:'#3b82f6'},{key:'reach',label:'可达',color:'#06b6d4'},{key:'perm',label:'权限',color:'#a855f7'},{key:'target',label:'目标',color:'#ef4444'},{key:'sense',label:'感知',color:'#f59e0b'}];
  var PATH_TYPE_COLOR = {'Low_Risk':'#22c55e','Medium_Risk':'#eab308','High_Risk':'#f97316','Critical_Risk':'#ef4444','Observed_Risk':'#3b82f6'};

  var CY_STYLE = [
    {selector:'node', style:{'label':'data(label)','text-valign':'bottom','text-halign':'center','text-margin-y':3,'font-size':'11px','color':'#94a3b8','background-color':'data(bgColor)','width':26,'height':26,'border-width':0}},
    {selector:'node.gold', style:{'border-width':3,'border-color':'#fbbf24','width':32,'height':32}},
    {selector:'node.entry', style:{'border-width':2,'border-color':'#60a5fa','border-style':'dashed'}},
    {selector:'node.noise', style:{'opacity':0.2,'width':18,'height':18}},
    {selector:'node.focused', style:{'border-width':3,'border-color':'#60a5fa'}},
    {selector:'node.dimmed', style:{'opacity':0.12}},
    {selector:'edge', style:{'width':2,'line-color':'#475569','target-arrow-color':'#475569','target-arrow-shape':'triangle','curve-style':'bezier','font-size':'12px','color':'#58a6ff','font-weight':'bold','text-background-color':'#1a2332','text-background-padding':'3px','text-background-opacity':'0.9','text-border-width':'1px','text-border-color':'#30363d','text-border-opacity':'0.8','text-rotation':'autorotate','text-rotation':'autorotate','label':'data(label)','text-background-color':'#0d1117','text-background-padding':1,'text-background-opacity':0.85}},
    {selector:'edge.gold-edge', style:{'width':2.5,'line-color':'#fbbf24','target-arrow-color':'#fbbf24','z-index':10}},
    {selector:'edge.dimmed', style:{'opacity':0.08}},
    {selector:'edge.focused', style:{'width':2.5,'line-color':'#60a5fa','target-arrow-color':'#60a5fa'}}
  ];

  var currentCase = null;
  var cy = null;
  var highlightNode = null;

  function renderStats(){
    var cards = [
      {icon:'📁',label:'案例数',value:STATS.cases,bg:'rgba(59,130,246,.12)'},
      {icon:'🔀',label:'路径总数',value:STATS.paths,bg:'rgba(168,85,247,.12)'},
      {icon:'✅',label:'Gate 通过',value:STATS.passed,bg:'rgba(34,197,94,.12)'},
      {icon:'🚫',label:'Gate 拦截',value:STATS.blocked,bg:'rgba(239,68,68,.12)'},
      {icon:'📊',label:'最高 Score',value:STATS.max_score,bg:'rgba(234,179,8,.12)'}
    ];
    var html = '';
    cards.forEach(function(c){
      html += '<div class="stat-card"><div class="stat-icon" style="background:'+c.bg+'">'+c.icon+'</div><div class="stat-info"><div class="stat-label">'+c.label+'</div><div class="stat-value">'+c.value+'</div></div></div>';
    });
    document.getElementById('stats-row').innerHTML = html;
  }

  function renderCaseList(){
    var html = '';
    Object.keys(DATA).forEach(function(cid){
      var c = DATA[cid];
      var maxScore = 0;
      c.results.forEach(function(r){ var s = r.gate_result.score; if(s>maxScore) maxScore=s; });
      html += '<div class="case-card" id="card-'+cid+'" onclick="selectCase(\''+cid+'\')">';
      html += '<div class="case-id">'+cid+'</div>';
      html += '<div class="case-name">'+escapeHtml(c.scenario_name)+'</div>';
      html += '<div class="case-meta"><span class="meta-chip">'+escapeHtml(c.industry)+'</span>';
      html += '<span class="meta-chip">'+c.results.length+' 条路径</span>';
      html += '<span class="meta-score">'+maxScore.toFixed(4)+'</span></div></div>';
    });
    document.getElementById('case-list').innerHTML = html;
  }

  window.selectCase = function(cid){
    currentCase = DATA[cid];
    document.querySelectorAll('.case-card').forEach(function(el){el.classList.remove('active');});
    var card = document.getElementById('card-'+cid);
    if(card) card.classList.add('active');
    var rp = document.getElementById('right-panel');
    rp.innerHTML = '<div class="section"><div class="section-title">📖 读图指南</div>'+renderGuide()+'</div>'
      + '<div class="section"><div class="section-title">⚠ 风险叙事</div>'+renderNarrative(currentCase)+'</div>'
      + '<div class="section"><div class="section-title">分层图谱</div><div class="graph-wrapper" id="graph-wrapper"><div id="bands-container"></div><div id="cy"></div></div></div>'
      + '<div class="section"><div class="section-title">图例</div>'+renderLegend()+'</div>'
      + '<div class="section"><div class="section-title">路径列表 ('+currentCase.results.length+' 条)</div><div class="path-list" id="path-list"></div></div>';
    initGraph(currentCase);
    renderPaths(currentCase);
  };

  function renderGuide(){
    var html = '<div class="guide-card">';
    html += '<div class="guide-row"><span class="color-dot" style="background:#fbbf24;border:2px solid #fbbf24"></span>金色边框 = Gold Path（标准答案路径）</div>';
    html += '<div class="guide-row"><span class="color-dot" style="background:#60a5fa;border:2px dashed #60a5fa"></span>蓝色虚线边框 = 攻击入口节点</div>';
    html += '<div class="guide-row"><span class="color-dot" style="background:#475569;opacity:.2"></span>半透明 = 噪声/干扰节点（非真实攻击路径）</div>';
    html += '<div class="guide-row">👆 点击节点 → 高亮经过该节点的所有路径</div>';
    html += '<div class="guide-layer">';
    LAYER_NAMES.forEach(function(name, i){
      html += '<span class="layer-tag" style="background:'+LAYER_BG[i]+';border:1px solid '+LAYER_BORDER[i]+';color:#94a3b8">L'+i+' '+name+'</span>';
    });
    html += '</div></div>';
    return html;
  }

  function renderNarrative(c){
    var realTargets = (c.targets||[]).filter(function(t){return t.indexOf('noise_')!==0;});
    var maxR = c.results[0];
    c.results.forEach(function(r){ if(r.gate_result.score > maxR.gate_result.score) maxR = r; });
    var html = '<div class="narrative-card">';
    html += '<div class="narr-title">'+escapeHtml(c.scenario_name)+'</div>';
    html += '<div class="narr-row"><span class="narr-label">行业</span><span class="narr-val">'+escapeHtml(c.industry)+'</span></div>';
    html += '<div class="narr-row"><span class="narr-label">攻击入口</span><span class="narr-val">'+escapeHtml((c.entries||[]).join(', '))+'</span></div>';
    html += '<div class="narr-row"><span class="narr-label">敏感目标</span><span class="narr-val">'+escapeHtml(realTargets.join(', '))+'</span></div>';
    html += '<div class="narr-row"><span class="narr-label">预期类型</span><span class="narr-val">'+escapeHtml(c.expected)+'</span></div>';
    html += '<div class="narr-row"><span class="narr-label">最高评分</span><span class="narr-val" style="color:#fbbf24;font-weight:600">'+maxR.gate_result.score.toFixed(4)+' ('+maxR.gate_result.path_type+')</span></div>';
    html += '<div class="narr-desc">攻击者从 <strong>'+escapeHtml((c.entries||[]).join(' / '))+'</strong> 入手，经由 IAM 权限传递链逐步获取数据库访问权限，最终触及敏感数据 <strong>'+escapeHtml(realTargets.join(' / '))+'</strong>。最高风险路径：'+escapeHtml(maxR.path.join(' → '))+'。</div>';
    html += '</div>';
    return html;
  }

  function renderLegend(){
    var html = '<div class="legend">';
    Object.keys(TYPE_COLOR).forEach(function(t){
      html += '<div class="legend-item"><span class="legend-dot" style="background:'+TYPE_COLOR[t]+'"></span>'+TYPE_LABEL[t]+'</div>';
    });
    html += '<div class="legend-item"><span class="legend-dot legend-gold" style="background:#1a2332"></span>Gold Path</div>';
    html += '<div class="legend-item"><span class="legend-dot legend-noise" style="background:#475569"></span>噪声节点</div>';
    html += '</div>';
    return html;
  }

  function initGraph(c){
    if(typeof cytoscape === 'undefined'){
      document.getElementById('cy').innerHTML = '<div style="padding:20px;color:#ef4444">Cytoscape.js 加载失败</div>';
      return;
    }
    var goldNodeIds = {};
    var goldEdgeKeys = {};
    (c.gold_paths||[]).forEach(function(path){
      path.forEach(function(nid){goldNodeIds[nid]=true;});
      for(var i=0;i<path.length-1;i++){
        goldEdgeKeys[path[i]+'|'+path[i+1]]=true;
        goldEdgeKeys[path[i+1]+'|'+path[i]]=true;
      }
    });
    var entries = c.entries||[];

    var nodes = c.nodes.map(function(n){
      var classes = [];
      if(goldNodeIds[n.id]) classes.push('gold');
      if(n.is_noise) classes.push('noise');
      if(entries.indexOf(n.id)>=0) classes.push('entry');
      return {data:{id:n.id,label:n.attrs.name||n.id,type:n.type,bgColor:TYPE_COLOR[n.type]||'#64748b'},position:{x:n.x,y:n.y},classes:classes.join(' ')};
    });

    var edges = (c.edges||[]).map(function(e,i){
      var key = e.source+'|'+e.target;
      return {data:{id:'e'+i,source:e.source,target:e.target,label:EDGE_LABELS[e.type]||e.type},classes:goldEdgeKeys[key]?'gold-edge':''};
    });

    var bandsHtml = '';
    for(var i=0;i<5;i++){
      bandsHtml += '<div class="layer-band" id="band-'+i+'" style="background:'+LAYER_BG[i]+';border-top:1px dashed '+LAYER_BORDER[i]+';border-bottom:1px dashed '+LAYER_BORDER[i]+'"><div class="band-label">L'+i+' '+LAYER_NAMES[i]+'</div></div>';
    }
    document.getElementById('bands-container').innerHTML = bandsHtml;

    if(cy){cy.destroy();cy=null;}
    cy = cytoscape({container:document.getElementById('cy'),elements:{nodes:nodes,edges:edges},style:CY_STYLE,layout:{name:'preset',padding:30},wheelSensitivity:0.3,minZoom:0.3,maxZoom:3});
    cy.fit(undefined, 40);
    updateLayerBands();
    cy.on('pan zoom resize', updateLayerBands);
    cy.on('tap','node', function(evt){ onNodeTap(evt.target.id()); });
    cy.on('tap', function(evt){ if(evt.target === cy){ resetHighlight(); } });
  }

  function updateLayerBands(){
    if(!cy) return;
    var pan = cy.pan();
    var zoom = cy.zoom();
    for(var i=0;i<5;i++){
      var band = document.getElementById('band-'+i);
      if(!band) continue;
      var y = LAYER_Y[i];
      var topY = (y - 60) * zoom + pan.y;
      var h = 120 * zoom;
      band.style.top = topY + 'px';
      band.style.height = h + 'px';
      var label = band.querySelector('.band-label');
      if(label) label.style.fontSize = Math.max(8, 11*zoom) + 'px';
    }
  }

  function onNodeTap(nodeId){
    if(highlightNode === nodeId){resetHighlight();return;}
    highlightNode = nodeId;
    cy.nodes().addClass('dimmed').removeClass('focused');
    cy.edges().addClass('dimmed').removeClass('focused');
    var pathNodeIds = {};
    pathNodeIds[nodeId] = true;
    var caseResults = currentCase.results;
    for(var i=0;i<caseResults.length;i++){
      var path = caseResults[i].path;
      if(path.indexOf(nodeId)>=0){
        for(var j=0;j<path.length;j++) pathNodeIds[path[j]]=true;
        var item = document.getElementById('path-item-'+i);
        if(item) item.classList.add('path-highlight');
      } else {
        var item2 = document.getElementById('path-item-'+i);
        if(item2) item2.classList.remove('path-highlight');
      }
    }
    Object.keys(pathNodeIds).forEach(function(nid){
      var n = cy.getElementById(nid);
      if(n && n.length>0){n.removeClass('dimmed').addClass('focused');}
    });
    cy.edges().forEach(function(e){
      if(pathNodeIds[e.source().id()] && pathNodeIds[e.target().id()]){
        e.removeClass('dimmed').addClass('focused');
      }
    });
  }

  function resetHighlight(){
    highlightNode = null;
    if(!cy) return;
    cy.nodes().removeClass('dimmed').removeClass('focused');
    cy.edges().removeClass('dimmed').removeClass('focused');
    document.querySelectorAll('.path-item').forEach(function(el){el.classList.remove('path-highlight');});
  }

  window.highlightPathByIndex = function(idx){
    if(!cy || !currentCase || !currentCase.results[idx]) return;
    if(highlightNode === 'path-'+idx){ resetHighlight(); return; }
    highlightNode = 'path-'+idx;
    var path = currentCase.results[idx].path || [];
    var nodeSet = {}, edgeKeys = {};
    path.forEach(function(nid){ nodeSet[nid]=true; });
    for(var i=0;i<path.length-1;i++){
      edgeKeys[path[i]+'|'+path[i+1]]=true;
      edgeKeys[path[i+1]+'|'+path[i]]=true;
    }
    cy.nodes().addClass('dimmed').removeClass('focused');
    cy.edges().addClass('dimmed').removeClass('focused');
    cy.nodes().forEach(function(n){ if(nodeSet[n.id()]){ n.removeClass('dimmed').addClass('focused'); } });
    cy.edges().forEach(function(e){ if(edgeKeys[e.source().id()+'|'+e.target().id()]){ e.removeClass('dimmed').addClass('focused'); } });
    document.querySelectorAll('.path-item').forEach(function(el){el.classList.remove('path-highlight');});
    var item = document.getElementById('path-item-'+idx);
    if(item){ item.classList.add('path-highlight'); }
  };

  function renderPaths(c){
    var container = document.getElementById('path-list');
    if(!container) return;
    var nodeMap = {};
    c.nodes.forEach(function(n){nodeMap[n.id]=n;});
    var html = '';
    c.results.forEach(function(r, idx){
      var gr = r.gate_result;
      var ev = r.evidence_vector || {};
      var ptc = PATH_TYPE_COLOR[gr.path_type] || '#6b7280';
      var gateClass = gr.gate===1 ? 'gate-pass' : 'gate-block';
      var gateText  = gr.gate===1 ? '通过' : '拦截';
      html += '<div class="path-item" id="path-item-'+idx+'" onclick="highlightPathByIndex('+idx+')" style="cursor:pointer">';
      html += '<div class="path-header">';
      html += '<span class="path-num">#'+(idx+1)+'</span>';
      html += '<span class="path-type-badge" style="background:'+ptc+'">'+escapeHtml(gr.path_type)+'</span>';
      html += '<span class="path-score">Score: '+gr.score.toFixed(4)+'</span>';
      html += '<span class="path-gate '+gateClass+'">'+gateText+'</span>';
      if(gr.blocked_by && gr.blocked_by.length>0){
        html += '<span class="path-gate gate-block">'+escapeHtml(gr.blocked_by.join(', '))+'</span>';
      }
      html += '</div>';
      html += '<div class="path-steps">';
      r.path.forEach(function(nid, si){
        var node = nodeMap[nid] || {};
        var type = node.type || 'Unknown';
        var color = TYPE_COLOR[type] || '#6b7280';
        var label = TYPE_LABEL[type] || type;
        var name = (node.attrs && node.attrs.name) ? node.attrs.name : nid;
        if(si>0) html += '<span class="step-arrow">→</span>';
        html += '<span class="step-chip" style="border-color:'+color+'">';
        html += '<span class="step-type" style="background:'+color+'">'+label+'</span>';
        html += '<span class="step-name">'+escapeHtml(name)+'</span></span>';
      });
      html += '</div>';
      html += '<div class="evidence-grid">';
      EV_INFO.forEach(function(info){
        var val = ev[info.key] || 0;
        var pct = Math.round(val*100);
        html += '<div class="ev-item">';
        html += '<span class="ev-label" style="color:'+info.color+'">'+info.label+'</span>';
        html += '<div class="ev-bar"><div class="ev-fill" style="width:'+pct+'%;background:'+info.color+'"></div></div>';
        html += '<span class="ev-val">'+val.toFixed(2)+'</span></div>';
      });
      html += '</div>';
      html += '<div class="detail-section"><span class="detail-label attr">归因分析</span>';
      html += '<div class="detail-text">'+renderMarkdown(r.attribution)+'</div></div>';
      html += '<div class="detail-section"><span class="detail-label remed">处置建议</span>';
      html += '<div class="detail-text">'+renderMarkdown(r.remediation)+'</div></div>';
      html += '</div>';
    });
    container.innerHTML = html;
  }

  function escapeHtml(text){
    if(!text) return '';
    return String(text).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  }

  function renderMarkdown(text){
    if(!text) return '';
    var html = String(text);
    html = html.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
    html = html.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
    html = html.replace(/\n/g, '<br>');
    return html;
  }

  renderStats();
  renderCaseList();
  var firstId = Object.keys(DATA)[0];
  if(firstId){ selectCase(firstId); }
})();
</script>
</body>
</html>'''


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5050, debug=True)
