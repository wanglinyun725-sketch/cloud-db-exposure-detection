#!/usr/bin/env python3
"""
build_showcase.py — 生成自包含 showcase.html（内联 Cytoscape 专业图谱）

读取 projects 下的真实数据（web_results_v2.json + samples_v2.json），
在 Python 端完成数据 join 与分层归类，前端用 Cytoscape.js 渲染分层力导向图谱。
Cytoscape 库从 vendor/cytoscape.min.js 内联进 HTML —— 单文件、离线、无 CDN，
open 双击即可查看（绕开 CDN file:// 白屏问题）。

运行:  python3 scripts/build_showcase.py
输出:  cloud_db_pathbench/showcase.html
"""
import json
from pathlib import Path

ROOT = Path(__file__).parent.parent
RESULTS_FILE = ROOT / "output" / "web_results_v2.json"
SAMPLES_FILE = ROOT / "data" / "verification_set" / "samples_v2.json"
VENDOR_FILE = ROOT / "vendor" / "cytoscape.min.js"
OUT_FILE = ROOT / "showcase.html"

# ── 五层图谱定义 ──────────────────────────────────────────────
# 网络入口 → 身份权限 → 数据库 → 敏感目标 → 审计/噪声
TYPE_LAYER = {
    "Network": 0, "Identity": 1,
    "DBInstance": 2, "DBObject": 2,
    "SensitiveTag": 3,
    "Control": 4, "AuditEvent": 4, "RiskFinding": 4,
}
LAYER_NAMES = ["网络入口层", "身份权限层", "数据库层", "敏感目标层", "审计/风控层"]
LAYER_COUNT = 5
TYPE_COLOR = {
    "Network": "#3b82f6", "Identity": "#a855f7",
    "DBInstance": "#22c55e", "DBObject": "#16a34a",
    "SensitiveTag": "#ef4444",
    "Control": "#eab308", "AuditEvent": "#f97316", "RiskFinding": "#dc2626",
}
TYPE_LABEL = {
    "Network": "网络", "Identity": "身份", "DBInstance": "库实例",
    "DBObject": "库对象", "SensitiveTag": "敏感", "Control": "控制",
    "AuditEvent": "审计", "RiskFinding": "风险",
}
EDGE_LABELS = {
    "can_connect": "网络可达", "has_permission": "授予权限", "can_assume": "可扮演角色",
    "contains": "包含", "classified_as": "分类标记", "accessed": "访问",
    "triggered": "触发", "has_risk": "存在风险", "protected_by": "受控于",
    "owns": "拥有", "stores_data": "存储数据", "exposes_port": "暴露端口",
    "trusts_identity": "信任身份",
}


def layer_of(node_type):
    return TYPE_LAYER.get(node_type, 4)


def build_case_graph(case_data, sample):
    """输出完整图谱：全部节点 + 全部边，带分层/噪声/孤立/路径标记，坐标交给 Cytoscape。"""
    raw_nodes = sample.get("nodes", [])
    raw_edges = sample.get("edges", [])
    nmap = {n["id"]: n for n in raw_nodes}

    # 路径相关标记集合
    path_node_ids = set()
    path_edge_keys = set()
    for r in case_data.get("results", []):
        p = r.get("path", [])
        path_node_ids.update(p)
        for i in range(len(p) - 1):
            path_edge_keys.add((p[i], p[i + 1]))
            path_edge_keys.add((p[i + 1], p[i]))

    gold_node_ids = set()
    for gp in sample.get("gold_paths", []):
        gold_node_ids.update(gp)

    entries = set(case_data.get("entries", []))

    # 有边相连的节点集合（用于判定孤立节点）
    connected = set()
    for e in raw_edges:
        connected.add(e.get("source"))
        connected.add(e.get("target"))

    nodes_out = []
    for n in raw_nodes:
        nid = n["id"]
        nodes_out.append({
            "id": nid,
            "type": n.get("type", "Network"),
            "name": n.get("attrs", {}).get("name", nid),
            "layer": layer_of(n.get("type", "Network")),
            "is_noise": nid.startswith("noise_"),
            "is_isolated": nid not in connected,
            "on_path": nid in path_node_ids,
            "is_entry": nid in entries,
            "is_gold": nid in gold_node_ids,
        })

    # 全部边去重，并标记是否位于某条候选路径上
    edges_out = []
    eseen = set()
    for e in raw_edges:
        s, t, typ = e.get("source"), e.get("target"), e.get("type")
        if s not in nmap or t not in nmap:
            continue
        key = (s, t, typ)
        if key in eseen:
            continue
        eseen.add(key)
        edges_out.append({
            "source": s, "target": t, "type": typ,
            "label": EDGE_LABELS.get(typ, typ),
            "on_path": (s, t) in path_edge_keys,
        })

    return nodes_out, edges_out


def build_data():
    results = json.loads(RESULTS_FILE.read_text(encoding="utf-8"))
    samples = {s["sample_id"]: s for s in json.loads(SAMPLES_FILE.read_text(encoding="utf-8"))}

    out = {}
    for cid, case_data in results.items():
        sample = samples.get(cid, {})
        nodes, edges = build_case_graph(case_data, sample)

        # 路径按 score 降序
        res = sorted(
            case_data.get("results", []),
            key=lambda r: r.get("gate_result", {}).get("score", 0),
            reverse=True,
        )

        out[cid] = {
            "case_id": cid,
            "scenario": case_data.get("scenario", ""),
            "scenario_name": case_data.get("scenario_name", ""),
            "industry": case_data.get("industry", ""),
            "expected": case_data.get("expected", ""),
            "initial_signal": sample.get("initial_signal", {}),
            "entries": case_data.get("entries", []),
            "targets": [t for t in case_data.get("targets", []) if not t.startswith("noise_")],
            "node_count": case_data.get("node_count", 0),
            "edge_count": case_data.get("edge_count", 0),
            "results": res,
            "nodes": nodes,
            "edges": edges,
        }
    return out


def build_stats(data):
    cases = len(data)
    paths = sum(len(c["results"]) for c in data.values())
    passed = sum(1 for c in data.values() for r in c["results"]
                 if r.get("gate_result", {}).get("gate") == 1)
    observed = sum(1 for c in data.values() for r in c["results"]
                   if r.get("gate_result", {}).get("path_type") == "Observed_Risk")
    max_score = max((r.get("gate_result", {}).get("score", 0)
                     for c in data.values() for r in c["results"]), default=0)
    return {
        "cases": cases, "paths": paths, "passed": passed,
        "observed": observed, "max_score": round(max_score, 4),
    }


def main():
    if not VENDOR_FILE.exists() or VENDOR_FILE.stat().st_size < 1000:
        raise SystemExit(
            f"缺少 Cytoscape 库: {VENDOR_FILE}\n"
            f"请先下载: curl -sSL -o {VENDOR_FILE} "
            f"https://unpkg.com/cytoscape@3.30.2/dist/cytoscape.min.js"
        )

    data = build_data()
    stats = build_stats(data)
    cyto_lib = VENDOR_FILE.read_text(encoding="utf-8")

    data_json = json.dumps(data, ensure_ascii=False).replace("</", "<\\/")
    stats_json = json.dumps(stats, ensure_ascii=False).replace("</", "<\\/")

    html = (HTML_TEMPLATE
            .replace("__CYTOSCAPE_LIB__", cyto_lib)
            .replace("__DATA__", data_json)
            .replace("__STATS__", stats_json))
    OUT_FILE.write_text(html, encoding="utf-8")

    print(f"✅ 已生成: {OUT_FILE}  ({OUT_FILE.stat().st_size // 1024} KB, 内联 Cytoscape)")
    print(f"   案例 {stats['cases']} | 路径 {stats['paths']} | Gate通过 {stats['passed']} | 最高Score {stats['max_score']}")
    for cid, c in data.items():
        onp = sum(1 for n in c["nodes"] if n["on_path"])
        print(f"   {cid} [{c['scenario']}] 全图 {len(c['nodes'])} 节点 / {len(c['edges'])} 边（路径相关 {onp}）| 路径 {len(c['results'])}")
    print(f"\n打开: open {OUT_FILE}")


# ─────────────────────────────────────────────────────────────
# 前端模板：三栏工作台 + 内联 Cytoscape 分层力导向图谱
# __CYTOSCAPE_LIB__ / __DATA__ / __STATS__ 由 Python 注入
# ─────────────────────────────────────────────────────────────
HTML_TEMPLATE = r'''<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>EIC-Agent 暴露路径侦测工作台</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
html,body{height:100%}
body{background:#0f1419;color:#e2e8f0;font-family:'Segoe UI',system-ui,-apple-system,sans-serif;font-size:13px;display:flex;flex-direction:column;overflow:hidden}
.header{background:linear-gradient(135deg,#0c1929 0%,#142244 100%);border-bottom:1px solid #1e3a5f;padding:10px 20px;display:flex;align-items:center;gap:12px;flex-shrink:0}
.header h1{font-size:17px;font-weight:700;color:#60a5fa;letter-spacing:.5px}
.header .subtitle{color:#64748b;font-size:12px}
.header .stats{margin-left:auto;display:flex;gap:16px}
.header .stat{display:flex;flex-direction:column;align-items:flex-end}
.header .stat .v{font-size:16px;font-weight:700;color:#e2e8f0}
.header .stat .l{font-size:10px;color:#64748b;text-transform:uppercase;letter-spacing:.5px}
.main{flex:1;display:flex;min-height:0}
/* ── 左栏 ── */
.col-left{width:300px;min-width:300px;background:#111827;border-right:1px solid #1e293b;display:flex;flex-direction:column;min-height:0}
.col-title{font-size:11px;color:#64748b;text-transform:uppercase;letter-spacing:1px;padding:12px 14px 8px;flex-shrink:0}
.case-tabs{display:flex;gap:6px;padding:0 12px 10px;flex-wrap:wrap;flex-shrink:0;border-bottom:1px solid #1e293b}
.case-tab{flex:1;min-width:64px;background:#1a2332;border:1px solid #2a3a4a;border-radius:6px;padding:8px 6px;cursor:pointer;text-align:center;transition:all .15s}
.case-tab:hover{border-color:#3b82f6}
.case-tab.active{border-color:#3b82f6;background:rgba(59,130,246,.12)}
.case-tab .ct-id{font-size:11px;font-weight:700;color:#60a5fa}
.case-tab .ct-ind{font-size:10px;color:#94a3b8;margin-top:2px}
.env-box{padding:12px 14px;border-bottom:1px solid #1e293b;flex-shrink:0}
.env-box .env-name{font-size:13px;font-weight:600;color:#e2e8f0;margin-bottom:8px;line-height:1.4}
.env-row{display:flex;gap:8px;margin:3px 0;font-size:12px}
.env-row .k{color:#64748b;min-width:56px;flex-shrink:0}
.env-row .v{color:#cbd5e1}
.env-row .v.sig{color:#fbbf24;font-family:monospace;font-size:11px}
.path-scroll{flex:1;overflow-y:auto;padding:10px 12px}
.path-scroll .ps-title{font-size:11px;color:#64748b;text-transform:uppercase;letter-spacing:1px;margin-bottom:8px}
.plist-item{background:#1a2332;border:1px solid #2a3a4a;border-radius:6px;padding:9px 11px;margin-bottom:7px;cursor:pointer;transition:all .15s}
.plist-item:hover{border-color:#3b82f6}
.plist-item.active{border-color:#60a5fa;background:rgba(96,165,250,.1);box-shadow:0 0 0 1px rgba(96,165,250,.3)}
.pli-head{display:flex;align-items:center;gap:6px;margin-bottom:6px}
.pli-num{font-size:10px;font-weight:700;color:#64748b;background:rgba(100,116,139,.2);padding:1px 6px;border-radius:3px}
.pli-badge{font-size:10px;padding:2px 7px;border-radius:3px;font-weight:600;color:#fff}
.pli-score{margin-left:auto;font-size:12px;color:#fbbf24;font-family:monospace;font-weight:600}
.pli-chain{font-size:11px;color:#94a3b8;font-family:monospace;line-height:1.5;word-break:break-all}
/* ── 中栏 ── */
.col-mid{flex:1;display:flex;flex-direction:column;min-width:0;background:#0d1117}
.graph-head{display:flex;align-items:center;gap:12px;padding:10px 16px;flex-shrink:0}
.graph-head .gh-title{font-size:12px;color:#94a3b8;text-transform:uppercase;letter-spacing:1px}
.graph-head .gh-hint{font-size:11px;color:#64748b;margin-left:auto}
.legend{display:flex;flex-wrap:wrap;gap:10px;padding:0 16px 8px;flex-shrink:0}
.legend-item{display:flex;align-items:center;gap:5px;font-size:11px;color:#94a3b8}
.legend-dot{width:11px;height:11px;border-radius:3px;flex-shrink:0}
.legend-dot.noise{opacity:.28}
.graph-box{flex:1;position:relative;min-height:0;margin:0 12px 12px;border:1px solid #1e293b;border-radius:8px;background:radial-gradient(circle at 50% 30%,#0f1a2b 0%,#0b0f16 100%);overflow:hidden}
#cy{position:absolute;top:0;left:30px;right:0;bottom:0}
.layer-rail{position:absolute;left:0;top:0;bottom:0;width:30px;z-index:5;display:flex;flex-direction:column;pointer-events:none;border-right:1px solid rgba(148,163,184,.1)}
.layer-rail .lr-bands{flex:0 0 78%;display:flex;flex-direction:column}
.layer-rail .lr-item{flex:1;display:flex;align-items:center;justify-content:center;border-bottom:1px dashed rgba(148,163,184,.1)}
.layer-rail .lr-item span{writing-mode:vertical-rl;font-size:10px;letter-spacing:2px;white-space:nowrap}
.layer-rail .lr-pool{flex:1;display:flex;align-items:center;justify-content:center;border-top:1px solid rgba(148,163,184,.18);background:rgba(100,116,139,.05)}
.layer-rail .lr-pool span{writing-mode:vertical-rl;font-size:10px;letter-spacing:2px;color:#64748b;opacity:.7}
/* ── 右栏 ── */
.col-right{width:380px;min-width:380px;background:#111827;border-left:1px solid #1e293b;display:flex;flex-direction:column;min-height:0}
.chain-scroll{flex:1;overflow-y:auto;padding:12px 14px}
.chain-empty{color:#64748b;text-align:center;padding:40px 20px;font-size:12px;line-height:1.8}
.step{position:relative;padding-left:30px;padding-bottom:16px;border-left:2px solid #2a3a4a;margin-left:8px}
.step:last-child{border-left-color:transparent;padding-bottom:0}
.step-dot{position:absolute;left:-9px;top:0;width:16px;height:16px;border-radius:50%;background:#1a2332;border:2px solid #3b82f6;display:flex;align-items:center;justify-content:center;font-size:9px;font-weight:700;color:#60a5fa}
.step-title{font-size:12px;font-weight:600;color:#e2e8f0;margin-bottom:6px}
.step-title .tag{font-size:9px;color:#64748b;font-weight:400;margin-left:6px}
.step-body{font-size:12px;color:#cbd5e1;line-height:1.6}
.step-body .mono{font-family:monospace;font-size:11px;color:#94a3b8;word-break:break-all}
.ev-grid{display:grid;grid-template-columns:repeat(5,1fr);gap:6px;margin:4px 0}
.ev-cell{display:flex;flex-direction:column;align-items:center;gap:2px}
.ev-lab{font-size:9px;text-transform:uppercase;letter-spacing:.5px}
.ev-bar{width:100%;height:5px;background:rgba(100,116,139,.15);border-radius:3px;overflow:hidden}
.ev-fill{height:100%;border-radius:3px}
.ev-num{font-size:9px;color:#64748b;font-family:monospace}
.gate-row{display:flex;align-items:center;gap:8px;margin:4px 0}
.gate-pill{font-size:11px;padding:3px 10px;border-radius:4px;font-weight:600}
.gate-ok{background:rgba(34,197,94,.15);color:#4ade80;border:1px solid rgba(34,197,94,.3)}
.gate-no{background:rgba(239,68,68,.15);color:#f87171;border:1px solid rgba(239,68,68,.3)}
.score-big{font-size:22px;font-weight:700;font-family:monospace}
.type-badge{font-size:11px;padding:3px 9px;border-radius:4px;font-weight:600;color:#fff}
.llm-box{background:#0d1117;border-radius:6px;padding:9px 11px;margin-top:4px;font-size:12px;line-height:1.65;color:#cbd5e1}
.llm-tag{font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:.5px;padding:2px 7px;border-radius:3px;display:inline-block;margin-bottom:5px}
.llm-tag.attr{background:rgba(168,85,247,.15);color:#c084fc}
.llm-tag.remed{background:rgba(34,197,94,.15);color:#4ade80}
::-webkit-scrollbar{width:7px;height:7px}
::-webkit-scrollbar-track{background:#0d1117}
::-webkit-scrollbar-thumb{background:#2a3a4a;border-radius:4px}
::-webkit-scrollbar-thumb:hover{background:#3b82f6}
</style>
</head>
<body>

<div class="header">
  <h1>EIC-Agent 暴露路径侦测工作台</h1>
  <span class="subtitle">CloudDB-PathBench · 表达—判定分离 · DeepSeek 真实结果</span>
  <div class="stats" id="hstats"></div>
</div>

<div class="main">
  <div class="col-left">
    <div class="col-title">案例</div>
    <div class="case-tabs" id="case-tabs"></div>
    <div class="env-box" id="env-box"></div>
    <div class="path-scroll">
      <div class="ps-title" id="ps-title">暴露路径</div>
      <div id="plist"></div>
    </div>
  </div>

  <div class="col-mid">
    <div class="graph-head">
      <span class="gh-title" id="gh-title">CDB-RG 五层暴露图谱</span>
      <span class="gh-hint">点击路径 / 节点 → 高亮攻击链 · 滚轮缩放 · 拖拽平移 · 点空白复位</span>
    </div>
    <div class="legend" id="legend"></div>
    <div class="graph-box">
      <div class="layer-rail" id="layer-rail"></div>
      <div id="cy"></div>
    </div>
  </div>

  <div class="col-right">
    <div class="col-title">EIC-Agent 推理链路</div>
    <div class="chain-scroll" id="chain"></div>
  </div>
</div>

<script>__CYTOSCAPE_LIB__</script>
<script id="data" type="application/json">__DATA__</script>
<script id="stats" type="application/json">__STATS__</script>
<script>
(function(){
  'use strict';
  var DATA  = JSON.parse(document.getElementById('data').textContent);
  var STATS = JSON.parse(document.getElementById('stats').textContent);

  var LAYER_NAMES = ['网络入口层','身份权限层','数据库层','敏感目标层','审计/风控层'];
  var LAYER_TINT  = ['#3b82f6','#a855f7','#22c55e','#ef4444','#eab308'];
  var TYPE_COLOR = {'Network':'#3b82f6','Identity':'#a855f7','DBInstance':'#22c55e','DBObject':'#16a34a','SensitiveTag':'#ef4444','Control':'#eab308','AuditEvent':'#f97316','RiskFinding':'#dc2626'};
  var TYPE_LABEL = {'Network':'网络','Identity':'身份','DBInstance':'库实例','DBObject':'库对象','SensitiveTag':'敏感','Control':'控制','AuditEvent':'审计','RiskFinding':'风险'};
  var EV_INFO = [{k:'entry',l:'入口',c:'#3b82f6'},{k:'reach',l:'可达',c:'#06b6d4'},{k:'perm',l:'权限',c:'#a855f7'},{k:'target',l:'目标',c:'#ef4444'},{k:'sense',l:'感知',c:'#f59e0b'}];
  var PTYPE_COLOR = {'Observed_Risk':'#ef4444','Potential_Exposure':'#f97316','Low_Risk':'#22c55e','Insufficient_Evidence':'#64748b'};
  var SIGNAL_LABEL = {'iam_over_permission':'IAM权限过宽','user_data_leak':'用户数据泄露','web_rce_to_db':'Web RCE到数据库','public_db_exposure':'RDS公网暴露'};

  var currentCase = null, currentCid = null, activePath = -1, cy = null;

  function esc(t){ return t==null?'':String(t).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
  function el(id){ return document.getElementById(id); }
  function shortName(s){ s=String(s); return s.length>16?s.slice(0,15)+'…':s; }
  function nodeMap(c){ if(!c._nmap){ c._nmap={}; c.nodes.forEach(function(n){c._nmap[n.id]=n;}); } return c._nmap; }

  function renderHeaderStats(){
    var items=[['案例',STATS.cases],['路径',STATS.paths],['Gate通过',STATS.passed],['已观测暴露',STATS.observed],['最高Score',STATS.max_score]];
    el('hstats').innerHTML = items.map(function(it){
      return '<div class="stat"><span class="v">'+it[1]+'</span><span class="l">'+it[0]+'</span></div>';
    }).join('');
  }

  function renderLegend(){
    var order=['Network','Identity','DBInstance','DBObject','SensitiveTag','Control','AuditEvent'];
    el('legend').innerHTML = order.map(function(t){
      return '<div class="legend-item"><span class="legend-dot" style="background:'+TYPE_COLOR[t]+'"></span>'+TYPE_LABEL[t]+'</div>';
    }).join('')
      + '<div class="legend-item"><span class="legend-dot" style="background:#60a5fa"></span>高亮攻击链</div>'
      + '<div class="legend-item"><span class="legend-dot" style="background:#93c5fd;box-shadow:0 0 0 1px #93c5fd inset"></span>攻击入口(虚框)</div>'
      + '<div class="legend-item"><span class="legend-dot noise" style="background:#94a3b8"></span>噪声干扰池(底部)</div>';
  }

  function renderLayerRail(){
    var bands = LAYER_NAMES.map(function(name,i){
      return '<div class="lr-item"><span style="color:'+LAYER_TINT[i]+';opacity:.75">L'+i+' '+name+'</span></div>';
    }).join('');
    el('layer-rail').innerHTML =
      '<div class="lr-bands">'+bands+'</div>'
      + '<div class="lr-pool"><span>噪声池</span></div>';
  }

  function renderTabs(){
    el('case-tabs').innerHTML = Object.keys(DATA).map(function(cid){
      var c=DATA[cid];
      return '<div class="case-tab" id="tab-'+cid+'" data-cid="'+cid+'">'
        + '<div class="ct-id">'+esc(c.scenario)+'</div>'
        + '<div class="ct-ind">'+esc(c.industry)+'</div></div>';
    }).join('');
    Object.keys(DATA).forEach(function(cid){
      el('tab-'+cid).addEventListener('click',function(){ selectCase(cid); });
    });
  }

  function renderEnv(c){
    var sig = c.initial_signal||{};
    var sigTxt = (SIGNAL_LABEL[sig.type]||sig.type||'-') + (sig.entity?(' @ '+sig.entity):'');
    el('env-box').innerHTML =
      '<div class="env-name">'+esc(c.scenario_name)+'</div>'
      + '<div class="env-row"><span class="k">行业</span><span class="v">'+esc(c.industry)+'</span></div>'
      + '<div class="env-row"><span class="k">初始信号</span><span class="v sig">'+esc(sigTxt)+'</span></div>'
      + '<div class="env-row"><span class="k">敏感目标</span><span class="v">'+esc((c.targets||[]).join(', ')||'-')+'</span></div>'
      + '<div class="env-row"><span class="k">图规模</span><span class="v">'+c.node_count+' 节点 / '+c.edge_count+' 边</span></div>'
      + '<div class="env-row"><span class="k">预期</span><span class="v">'+esc(c.expected)+'</span></div>';
  }

  function renderPathList(c){
    el('ps-title').textContent = '暴露路径 ('+c.results.length+' 条，按 Score 降序)';
    var nmap=nodeMap(c);
    el('plist').innerHTML = c.results.map(function(r,idx){
      var gr=r.gate_result, ptc=PTYPE_COLOR[gr.path_type]||'#64748b';
      var chain=r.path.map(function(nid){ var n=nmap[nid]; return n?n.name:nid; }).join(' → ');
      return '<div class="plist-item" id="pli-'+idx+'" data-idx="'+idx+'">'
        + '<div class="pli-head"><span class="pli-num">#'+(idx+1)+'</span>'
        + '<span class="pli-badge" style="background:'+ptc+'">'+esc(gr.path_type)+'</span>'
        + '<span class="pli-score">'+gr.score.toFixed(4)+'</span></div>'
        + '<div class="pli-chain">'+esc(chain)+'</div></div>';
    }).join('');
    c.results.forEach(function(r,idx){
      el('pli-'+idx).addEventListener('click',function(){ selectPath(idx); });
    });
  }

  // ── Cytoscape 图谱 ────────────────────────────────────────
  var CY_STYLE = [
    {selector:'node', style:{
      'background-color':'data(color)','label':'data(label)','width':'data(size)','height':'data(size)',
      'font-size':13,'font-weight':600,'color':'#e2e8f0','text-valign':'bottom','text-halign':'center','text-margin-y':5,
      'text-outline-width':3,'text-outline-color':'#0b0f16','border-width':0,
      'transition-property':'opacity,border-width','transition-duration':'0.15s'
    }},
    {selector:'node.noise', style:{'opacity':0.35,'font-size':9,'color':'#94a3b8','text-outline-width':2}},
    {selector:'node.entry', style:{'border-width':3,'border-color':'#93c5fd','border-style':'dashed'}},
    {selector:'node.gold', style:{'border-width':3,'border-color':'#fbbf24'}},
    {selector:'edge', style:{
      'width':2,'line-color':'#3f4d63','curve-style':'bezier',
      'target-arrow-shape':'triangle','target-arrow-color':'#3f4d63','arrow-scale':1,
      'label':'data(label)','font-size':10,'color':'#9fb4d4','text-opacity':0.85,
      'text-background-color':'#0b0f16','text-background-opacity':0.9,'text-background-padding':3,'text-background-shape':'roundrectangle',
      'text-rotation':'autorotate','transition-property':'opacity,line-color,width','transition-duration':'0.15s'
    }},
    {selector:'edge.onpath', style:{'line-color':'#5b7590','target-arrow-color':'#5b7590','width':2.4}},
    {selector:'.dim', style:{'opacity':0.06,'text-opacity':0}},
    {selector:'node.hl', style:{'border-width':4,'border-color':'#60a5fa','opacity':1,'text-opacity':1,'z-index':30,'font-size':14}},
    {selector:'edge.hl', style:{'line-color':'#60a5fa','target-arrow-color':'#60a5fa','width':3.4,'color':'#bfdbfe','text-opacity':1,'z-index':30,'opacity':1}}
  ];

  // 确定性微抖动，避免同层节点标签完全对齐产生呆板感（同一 id 每次相同）
  function jitter(id){
    var s=0; for(var i=0;i<id.length;i++){ s=(s*31+id.charCodeAt(i))%100000; }
    return { x:((s%13)-6), y:(((s>>3)%9)-4) };
  }

  // 重心排序：按相邻真实节点的平均横坐标给每层重新排序，减少层间连线交叉
  function barycenterOrder(byLayer, adj){
    var order={};
    for(var l=0;l<5;l++){ order[l]=(byLayer[l]||[]).map(function(n){return n.id;}); }
    var idx={};
    function reindex(){ for(var l=0;l<5;l++){ order[l].forEach(function(id,i){ idx[id]=i; }); } }
    reindex();
    for(var pass=0; pass<4; pass++){
      for(var l=0;l<5;l++){
        var arr=order[l];
        var bary=arr.map(function(id){
          var nb=adj[id]||[]; if(nb.length===0) return idx[id];
          var s=0,cnt=0; nb.forEach(function(m){ if(idx[m]!=null){ s+=idx[m]; cnt++; } });
          return cnt?s/cnt:idx[id];
        });
        var paired=arr.map(function(id,i){ return {id:id,b:bary[i]}; });
        paired.sort(function(a,b){ return a.b-b.b; });
        order[l]=paired.map(function(p){ return p.id; });
        reindex();
      }
    }
    return order;
  }

  // 分层布局：真实节点入 5 分层带并对齐 L0-L4；noise 节点归入底部干扰池
  function computePositions(c){
    var W=1500, top=90, bandH=220, poolTop=90+5*220+40;
    var real=[], noise=[];
    c.nodes.forEach(function(n){ (n.is_noise?noise:real).push(n); });

    var byLayer={0:[],1:[],2:[],3:[],4:[]};
    real.forEach(function(n){ byLayer[n.layer].push(n); });

    // 构建真实节点邻接（仅真实节点间的边）用于重心排序
    var realIds={}; real.forEach(function(n){ realIds[n.id]=true; });
    var adj={};
    c.edges.forEach(function(e){
      if(realIds[e.source] && realIds[e.target]){
        (adj[e.source]=adj[e.source]||[]).push(e.target);
        (adj[e.target]=adj[e.target]||[]).push(e.source);
      }
    });
    var order=barycenterOrder(byLayer, adj);

    var pos={};
    for(var l=0;l<5;l++){
      var ids=order[l], m=ids.length, yc=top+l*bandH;
      for(var i=0;i<m;i++){
        var x=W/(m+1)*(i+1), j=jitter(ids[i]);
        pos[ids[i]]={x:x+j.x, y:yc+j.y};
      }
    }
    // 底部干扰池：紧凑网格
    var perRow=Math.ceil(Math.sqrt(noise.length*2.2))||1;
    noise.forEach(function(n,i){
      var row=Math.floor(i/perRow), col=i%perRow;
      var rowN=Math.min(perRow, noise.length-row*perRow);
      pos[n.id]={ x:W/(rowN+1)*(col+1), y:poolTop+row*46 };
    });
    return { pos:pos, poolTop:poolTop, W:W, realIds:realIds };
  }

  function buildGraph(c){
    var layout=computePositions(c);
    var pos=layout.pos, realIds=layout.realIds;
    var els=[];
    c.nodes.forEach(function(n){
      var cls=[];
      if(n.is_noise) cls.push('noise');
      if(n.is_entry) cls.push('entry');
      if(n.is_gold)  cls.push('gold');
      var size = n.on_path?44:(n.is_noise?16:32);
      els.push({group:'nodes',data:{id:n.id,label:n.is_noise?'':shortName(n.name),color:TYPE_COLOR[n.type]||'#64748b',size:size},position:pos[n.id],classes:cls.join(' ')});
    });
    // 只画真实节点之间的边（隐藏牵扯 noise 的杂边，避免重叠）
    c.edges.forEach(function(e,i){
      if(!(realIds[e.source] && realIds[e.target])) return;
      els.push({group:'edges',data:{id:'ed'+i,source:e.source,target:e.target,label:e.label},classes:e.on_path?'onpath':''});
    });

    if(cy){ cy.destroy(); cy=null; }
    cy=cytoscape({container:el('cy'),elements:els,style:CY_STYLE,layout:{name:'preset'},
      wheelSensitivity:0.25,minZoom:0.2,maxZoom:3,pixelRatio:2});
    cy.fit(cy.elements(),45);
    cy.on('tap','node',function(evt){ onNodeClick(evt.target.id()); });
    cy.on('tap',function(evt){ if(evt.target===cy) resetHighlight(); });
  }

  function highlightPath(path){
    if(!cy) return;
    var ns={}, es={};
    path.forEach(function(n){ ns[n]=true; });
    for(var i=0;i<path.length-1;i++){ es[path[i]+'|'+path[i+1]]=true; es[path[i+1]+'|'+path[i]]=true; }
    cy.batch(function(){
      cy.elements().addClass('dim').removeClass('hl');
      cy.nodes().forEach(function(n){ if(ns[n.id()]){ n.removeClass('dim').addClass('hl'); } });
      cy.edges().forEach(function(e){ if(es[e.data('source')+'|'+e.data('target')]){ e.removeClass('dim').addClass('hl'); } });
    });
  }

  function resetHighlight(){
    activePath=-1;
    if(cy){ cy.batch(function(){ cy.elements().removeClass('dim').removeClass('hl'); }); }
    document.querySelectorAll('.plist-item').forEach(function(x){ x.classList.remove('active'); });
    renderChainEmpty();
  }

  // 点节点 → 高亮经过它的路径中 score 最高的一条
  function onNodeClick(nid){
    var best=-1, bestScore=-1;
    currentCase.results.forEach(function(r,idx){
      if(r.path.indexOf(nid)>=0 && r.gate_result.score>bestScore){ bestScore=r.gate_result.score; best=idx; }
    });
    if(best>=0){ selectPath(best); }
  }

  function selectPath(idx){
    if(activePath===idx){ resetHighlight(); return; }
    activePath=idx;
    document.querySelectorAll('.plist-item').forEach(function(x){ x.classList.remove('active'); });
    var item=el('pli-'+idx); if(item) item.classList.add('active');
    highlightPath(currentCase.results[idx].path);
    renderChain(currentCase, idx);
  }

  // ── 右栏 7 环节推理链路 ──────────────────────────────────
  function renderChainEmpty(){
    el('chain').innerHTML='<div class="chain-empty">← 从左侧选择一条暴露路径<br>查看 EIC-Agent 的七环节推理过程<br><br>'
      +'①初始信号 ②候选路径 ③证据采集<br>④五维证据向量 ⑤Gate 硬门判定<br>⑥Score 风险量化 ⑦LLM 归因与处置</div>';
  }

  function step(num, title, tag, body){
    return '<div class="step"><div class="step-dot">'+num+'</div>'
      + '<div class="step-title">'+title+(tag?'<span class="tag">'+tag+'</span>':'')+'</div>'
      + '<div class="step-body">'+body+'</div></div>';
  }

  function mdToHtml(t){
    return esc(t).replace(/\*\*(.+?)\*\*/g,'<strong>$1</strong>').replace(/\n/g,'<br>');
  }

  function renderChain(c, idx){
    var r=c.results[idx], gr=r.gate_result, ev=r.evidence_vector||{};
    var nmap=nodeMap(c);
    var sig=c.initial_signal||{};
    var sigTxt=(SIGNAL_LABEL[sig.type]||sig.type||'-')+(sig.entity?(' @ '+sig.entity):'');
    var chain=r.path.map(function(nid){ var n=nmap[nid]; return n?n.name:nid; }).join(' → ');
    var ptc=PTYPE_COLOR[gr.path_type]||'#64748b';

    var evHtml='<div class="ev-grid">'+EV_INFO.map(function(info){
      var v=ev[info.k]||0, pct=Math.round(v*100);
      return '<div class="ev-cell"><span class="ev-lab" style="color:'+info.c+'">'+info.l+'</span>'
        +'<div class="ev-bar"><div class="ev-fill" style="width:'+pct+'%;background:'+info.c+'"></div></div>'
        +'<span class="ev-num">'+v.toFixed(2)+'</span></div>';
    }).join('')+'</div>';

    var gateHtml, blocked=gr.blocked_by&&gr.blocked_by.length>0;
    if(gr.gate===1){
      gateHtml='<div class="gate-row"><span class="gate-pill gate-ok">✓ Gate 通过</span>'
        +'<span style="font-size:11px;color:#64748b">五维硬约束全部满足</span></div>';
    } else {
      gateHtml='<div class="gate-row"><span class="gate-pill gate-no">✗ Gate 拦截</span></div>'
        +(blocked?'<div class="step-body" style="margin-top:4px"><span class="mono">'+esc(gr.blocked_by.join(', '))+'</span></div>':'');
    }

    var scoreHtml='<div class="gate-row"><span class="score-big" style="color:'+ptc+'">'+gr.score.toFixed(4)+'</span>'
      +'<span class="type-badge" style="background:'+ptc+'">'+esc(gr.path_type)+'</span></div>';

    var html='';
    html+=step('①','初始信号','DIE · Discover','侦测到告警信号 <span class="mono">'+esc(sigTxt)+'</span>，触发暴露路径调查。');
    html+=step('②','候选路径','约束 DFS','在 CDB-RG 图上枚举得到候选暴露链：<div class="step-body" style="margin-top:4px"><span class="mono">'+esc(chain)+'</span></div>');
    html+=step('③','证据采集','7 类工具','沿路径调用 NetworkCheck / PermissionCheck / SensitiveDataQuery / AuditLogQuery 等工具收集证据。');
    html+=step('④','五维证据向量','ε','LLM 将证据表达为可判定向量：'+evHtml);
    html+=step('⑤','Gate 硬门判定','确定性算子',gateHtml);
    html+=step('⑥','Score 风险量化','加权几何均值',scoreHtml);
    html+=step('⑦','LLM 归因与处置','表达层',
      '<div class="llm-box"><span class="llm-tag attr">归因分析</span><br>'+mdToHtml(r.attribution)+'</div>'
      +'<div class="llm-box" style="margin-top:6px"><span class="llm-tag remed">处置建议</span><br>'+mdToHtml(r.remediation)+'</div>');

    el('chain').innerHTML=html;
  }

  // ── 案例切换 ──────────────────────────────────────────────
  function selectCase(cid){
    currentCid=cid; currentCase=DATA[cid]; activePath=-1;
    document.querySelectorAll('.case-tab').forEach(function(x){ x.classList.remove('active'); });
    el('tab-'+cid).classList.add('active');
    el('gh-title').textContent='CDB-RG 五层暴露图谱（'+currentCase.node_count+' 节点 / '+currentCase.edge_count+' 边）';
    renderEnv(currentCase);
    renderPathList(currentCase);
    buildGraph(currentCase);
    if(currentCase.results && currentCase.results.length>0){ selectPath(0); }
    else { renderChainEmpty(); }
  }

  if(typeof cytoscape==='undefined'){
    el('cy').innerHTML='<div style="padding:24px;color:#ef4444">Cytoscape 库未加载</div>';
  }
  renderHeaderStats();
  renderLegend();
  renderLayerRail();
  renderTabs();
  var first=Object.keys(DATA)[0];
  if(first) selectCase(first);
})();
</script>
</body>
</html>'''


if __name__ == "__main__":
    main()
