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
            "kind": n.get("attrs", {}).get("kind", ""),
            "parent_vpc": n.get("attrs", {}).get("parent_vpc"),
            "layer": layer_of(n.get("type", "Network")),
            "is_noise": nid.startswith("noise_"),
            "is_isolated": nid not in connected,
            "is_infra": n.get("attrs", {}).get("is_infra", False),
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
            "no_path_reason": case_data.get("no_path_reason", ""),
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
.pli-prune{font-size:10px;padding:2px 7px;border-radius:3px;font-weight:600;color:#fb923c;background:rgba(251,146,60,.15);border:1px solid rgba(251,146,60,.4)}
.plist-item.pli-pruned{border-left:3px dashed #fb923c;opacity:.85}
.no-path-box{background:rgba(251,146,60,.08);border:1px solid rgba(251,146,60,.35);border-radius:6px;padding:16px 14px;margin-top:8px}
.no-path-title{font-size:14px;font-weight:700;color:#fb923c;margin-bottom:8px}
.no-path-reason{font-size:12px;color:#cbd5e1;line-height:1.6}
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
#cy{position:absolute;top:0;left:0;right:0;bottom:0;z-index:2}
#bands{position:absolute;top:0;left:0;width:100%;height:100%;z-index:1;pointer-events:none}
.band-fill{transition:none}
.band-text{font-size:12px;letter-spacing:3px;font-weight:600}
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
      <span class="gh-hint">点击节点/路径 → 高亮攻击链(噪声→诱饵链) · 悬停边/噪声看标签 · 滚轮缩放 · 点空白复位</span>
    </div>
    <div class="legend" id="legend"></div>
    <div class="graph-box">
      <svg id="bands"></svg>
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

  // ── 布局与尺寸集中配置（每层可独立调整）──────────────────
  var CANVAS_W = 1900;                       // 虚拟画布宽度
  var LAYER_Y  = [400, 900, 1400, 1900, 2400]; // L0-L4 各层纵向中心（等距 500px，各层 band 高度均衡）
  var NODE_SIZE = { core: 88, path: 72, real: 52, noise: 32 }; // 四类节点直径（core=核心网络骨架）
  var CORE_KINDS = {vpc:1};  // 仅 VPC 是"万物之源"核心节点（igw/subnet/route_table/subnet_group 是儿子，保持普通大小）
  var FONT = { base: 22, hl: 25, noise: 16 };        // 节点标签字号
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
      + '<div class="legend-item"><span class="legend-dot noise" style="background:#94a3b8"></span>噪声/诱饵(半透明·点击查看)</div>';
  }

  // 绘制分层背景带，随 cy 的 pan/zoom 同步，使每层节点始终落在其色带内
  function updateBands(){
    var svg=el('bands'); if(!svg) return;
    while(svg.firstChild) svg.removeChild(svg.firstChild);
    if(!cy) return;
    var pan=cy.pan(), zoom=cy.zoom();
    var W=svg.clientWidth, H=svg.clientHeight;
    var SVGNS='http://www.w3.org/2000/svg';

    // 每层带的模型坐标上下界（相邻层中点）
    // L0 特例：四行树（VPC/entry_sg/infra/sg）跨 yc±262.5，上下沿各留余量。
    function bandBounds(l){
      var yc=LAYER_Y[l];
      if(l===0){
        var up   = yc - 320;                       // 80 - VPC(y=137.5) 顶部(y=93.5) 以下留余量
        var down = yc + 262 + 78;                  // 740 - sg(y=662.5) 底部(y=688.5) + 余量
        return [up, down];
      }
      var up   = (l===1) ? Math.max((LAYER_Y[0]+yc)/2, LAYER_Y[0]+262+78)
                         : (LAYER_Y[l-1]+yc)/2;
      var down = (l===4) ? yc+(LAYER_Y[4]-LAYER_Y[3])/2 : (yc+LAYER_Y[l+1])/2;
      return [up, down];
    }
    function y2s(y){ return y*zoom+pan.y; }

    function drawBand(top, bottom, fill, lineColor, label, labelColor){
      var yTop=y2s(top), yBot=y2s(bottom), h=yBot-yTop;
      if(yBot<0 || yTop>H) return; // 不在可视区跳过
      var rect=document.createElementNS(SVGNS,'rect');
      rect.setAttribute('x',0); rect.setAttribute('y',yTop);
      rect.setAttribute('width',W); rect.setAttribute('height',Math.max(0,h));
      rect.setAttribute('fill',fill); rect.setAttribute('class','band-fill');
      svg.appendChild(rect);
      var line=document.createElementNS(SVGNS,'line');
      line.setAttribute('x1',0); line.setAttribute('y1',yTop);
      line.setAttribute('x2',W); line.setAttribute('y2',yTop);
      line.setAttribute('stroke',lineColor); line.setAttribute('stroke-width',1);
      line.setAttribute('stroke-dasharray','5 5'); svg.appendChild(line);
      var txt=document.createElementNS(SVGNS,'text');
      txt.setAttribute('x',12); txt.setAttribute('y',yTop+18);
      txt.setAttribute('fill',labelColor); txt.setAttribute('class','band-text');
      txt.setAttribute('opacity','0.85'); txt.textContent=label;
      svg.appendChild(txt);
    }

    for(var l=0;l<5;l++){
      var b=bandBounds(l);
      drawBand(b[0], b[1], hexA(LAYER_TINT[l],0.07), hexA(LAYER_TINT[l],0.30),
               'L'+l+' '+LAYER_NAMES[l], LAYER_TINT[l]);
    }
  }

  // hex + alpha → rgba()
  function hexA(hex,a){
    var h=hex.replace('#',''); if(h.length===3){h=h[0]+h[0]+h[1]+h[1]+h[2]+h[2];}
    var r=parseInt(h.slice(0,2),16),g=parseInt(h.slice(2,4),16),b=parseInt(h.slice(4,6),16);
    return 'rgba('+r+','+g+','+b+','+a+')';
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
    // 空结果：显示断链/无路径诊断，而非空白
    if(!c.results || c.results.length===0){
      el('ps-title').textContent = '暴露路径 (0 条)';
      var reason = c.no_path_reason || '约束搜索未找到满足条件的候选路径';
      el('plist').innerHTML = '<div class="no-path-box">'
        + '<div class="no-path-title">⚠ 未发现候选暴露路径</div>'
        + '<div class="no-path-reason">'+esc(reason)+'</div></div>';
      return;
    }
    el('ps-title').textContent = '暴露路径 ('+c.results.length+' 条，按 Score 降序)';
    var nmap=nodeMap(c);
    el('plist').innerHTML = c.results.map(function(r,idx){
      var gr=r.gate_result, ptc=PTYPE_COLOR[gr.path_type]||'#64748b';
      var chain=r.path.map(function(nid){ var n=nmap[nid]; return n?n.name:nid; }).join(' → ');
      var pruned = gr.early_terminated === true;
      var pruneBadge = pruned
        ? '<span class="pli-prune" title="硬证据一票否决，提前终止：跳过后续工具调用与 LLM 归因">⚡ 提前剪枝</span>'
        : '';
      return '<div class="plist-item'+(pruned?' pli-pruned':'')+'" id="pli-'+idx+'" data-idx="'+idx+'">'
        + '<div class="pli-head"><span class="pli-num">#'+(idx+1)+'</span>'
        + '<span class="pli-badge" style="background:'+ptc+'">'+esc(gr.path_type)+'</span>'
        + pruneBadge
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
      'font-size':FONT.base,'font-weight':600,'color':'#e2e8f0','text-valign':'bottom','text-halign':'center','text-margin-y':5,
      'text-outline-width':3,'text-outline-color':'#0b0f16','border-width':2,'border-color':'#0b0f16','z-index':10,
      'transition-property':'opacity,border-width','transition-duration':'0.15s'
    }},
    {selector:'node.core', style:{'border-width':3,'border-color':'#60a5fa','font-size':24,'font-weight':700,'z-index':12}},
    {selector:'node.noise', style:{'opacity':0.26,'font-size':FONT.noise,'color':'#94a3b8','text-outline-width':2,'text-opacity':0,'border-width':0}},
    {selector:'node.noise.hover', style:{'opacity':0.95,'text-opacity':1,'z-index':35}},
    {selector:'node.hover', style:{'border-width':4,'border-color':'#22d3ee','opacity':1,'text-opacity':1,'z-index':36}},
    {selector:'node.entry', style:{'border-width':3,'border-color':'#93c5fd','border-style':'dashed'}},
    {selector:'node.gold', style:{'border-width':3,'border-color':'#fbbf24'}},
    {selector:'edge', style:{
      'width':2.6,'line-color':'#3f4d63','curve-style':'bezier',
      'target-arrow-shape':'triangle','target-arrow-color':'#3f4d63','arrow-scale':1,
      'label':'data(label)','font-size':18,'color':'#cfe0f5','text-opacity':0.92,'z-index':1,
      'text-background-color':'#0b0f16','text-background-opacity':1,'text-background-padding':4,'text-background-shape':'roundrectangle',
      'text-border-width':1,'text-border-color':'#334155','text-border-opacity':1,
      'text-rotation':'autorotate','transition-property':'opacity,line-color,width','transition-duration':'0.15s'
    }},
    {selector:'edge.noiseedge', style:{'line-color':'#4a5568','target-arrow-color':'#4a5568','width':1.6,'opacity':0.85,'text-opacity':0}},
    {selector:'edge.onpath', style:{'line-color':'#5b7590','target-arrow-color':'#5b7590','width':3,'color':'#dbeafe','z-index':2}},
    {selector:'edge.hover', style:{'line-color':'#60a5fa','target-arrow-color':'#60a5fa','width':3.4,'text-opacity':1,'z-index':40,'opacity':1}},
    {selector:'.dim', style:{'opacity':0.06,'text-opacity':0}},
    {selector:'node.hl', style:{'border-width':4,'border-color':'#60a5fa','opacity':1,'text-opacity':1,'z-index':45,'font-size':FONT.hl}},
    {selector:'edge.hl', style:{'line-color':'#60a5fa','target-arrow-color':'#60a5fa','width':4.2,'color':'#eaf2ff','text-opacity':1,'text-background-opacity':1,'z-index':40,'opacity':1}}
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

  // 分层布局：真实节点居中成主轴，噪声节点在其上下环绕散布（万军丛中取敌将首级）
  function computePositions(c){
    var real=[], noise=[];
    c.nodes.forEach(function(n){ (n.is_noise?noise:real).push(n); });

    var byLayerReal={0:[],1:[],2:[],3:[],4:[]};
    real.forEach(function(n){ byLayerReal[n.layer].push(n); });
    var byLayerNoise={0:[],1:[],2:[],3:[],4:[]};
    noise.forEach(function(n){ byLayerNoise[n.layer].push(n); });

    // 仅真实节点邻接用于重心排序（真实攻击链尽量少交叉）
    var realIds={}; real.forEach(function(n){ realIds[n.id]=true; });
    var adj={};
    c.edges.forEach(function(e){
      if(realIds[e.source] && realIds[e.target]){
        (adj[e.source]=adj[e.source]||[]).push(e.target);
        (adj[e.target]=adj[e.target]||[]).push(e.source);
      }
    });
    var order=barycenterOrder(byLayerReal, adj);

    var pos={};
    var W=CANVAS_W;
    var bandHalfL0=320;   // L0 四行树：噪声填满 VPC/entry_sg/infra/sg 的间隙
    var bandHalfOther=140; // L1-L4：较窄，避免跨层重叠
    var centerGuard=48; // 中心保护带：噪声不进入 ±48 内，避免压盖真实主轴

    // L0 网络层：VPC 为根的纵向树。kind/parent 映射
    var kindMap={}, parentMap={};
    c.nodes.forEach(function(n){ kindMap[n.id]=n.kind||''; parentMap[n.id]=n.parent_vpc||null; });
    function roleRow(k, isEntry){
      if(k==='vpc') return 0;                                       // 顶：VPC 根
      if(k==='igw'||k==='route_table'||k==='subnet_group'||k==='subnet') return 1; // 骨架/子网
      if(k==='sg' && !isEntry) return 2;                             // 普通安全组（上移一行，距 VPC 近）
      if(k==='sg' && isEntry) return 3;                              // 入口 SG（下沉到底行，距 VPC 远 → 边长、斜角明显）
      return 1;
    }

    for(var l=0;l<5;l++){
      var yc=LAYER_Y[l];
      var rids=order[l], rn=rids.length;

      if(l===0 && rn>0){
        // ── L0 树状布局 ──
        // VPC 为根在顶部，骨架(infra)在中行，安全组(sg)在底部。
        // 三行等距垂直排列，每行内节点水平等距铺开，避免同心圆弧的越界问题。
        var branches={}, border=[];
        rids.forEach(function(id){
          var key = parentMap[id] || (kindMap[id]==='vpc'? id : '__novpc__');
          if(!branches[key]){ branches[key]=[]; border.push(key); }
          branches[key].push(id);
        });
        var nb=border.length;
        var rowH=175;  // 4 行间距（VPC→entry_sg→infra→sg），总高度 525px
        border.forEach(function(bkey, bi){
          var segL=W*0.06 + (W*0.88)/nb*bi;    // 左右留 6% padding，避免最外节点贴画布边
          var segR=W*0.06 + (W*0.88)/nb*(bi+1);
          var segC=(segL+segR)/2;
          var segW=segR-segL;
          var sub={0:[],1:[],2:[],3:[]};
          var nmap=nodeMap(c);
          branches[bkey].forEach(function(id){
            sub[roleRow(kindMap[id], nmap[id] && nmap[id].is_entry)].push(id);
          });

          for(var sr=0;sr<4;sr++){
            var row=sub[sr], m=row.length;
            if(m===0) continue;
            var baseY = yc - 1.5*rowH + sr*rowH;   // 4 行：yc-1.5h / yc-0.5h / yc+0.5h / yc+1.5h
            // 每行不同的横向铺幅，让不同行的节点横向位置错开，避免 VPC 出发的边重叠
            var spreadFrac = [0.90, 0.80, 0.96, 1.00][sr];
            var effW = segW * spreadFrac;
            var offL = segC - effW/2;
            for(var r=0;r<m;r++){
              // 水平等距铺开：节点中心间距 = effW/(m+1)
              var x = offL + (r+1)*effW/(m+1);
              var jj=jitter(row[r]);
              pos[row[r]]={ x:x + jj.x*0.2, y:baseY + jj.y*0.08 };
            }
          }
        });
      } else {
        // L1-L4：多行网格布局（节点多时自动分行，避免单行挤成一条线）
        var nRows = (rn <= 12) ? 1 : (rn <= 18) ? 2 : 3;
        var rowH_L = 160;    // L1-L4 的行间距
        for(var i=0;i<rn;i++){
          var sr = Math.floor(i * nRows / rn);        // 节点 i 属于哪一行
          var rowStart = Math.floor(sr * rn / nRows);
          var rowEnd   = Math.floor((sr+1) * rn / nRows);
          var rowLen   = rowEnd - rowStart;
          var inRow    = i - rowStart;
          var baseY    = yc - (nRows-1)*rowH_L/2 + sr*rowH_L;
          var rx = W*0.08 + (W*0.84)/(rowLen+1)*(inRow+1);
          var jx = jitter(rids[i]).x * 0.3;
          var jy = jitter(rids[i]).y * 0.08;
          pos[rids[i]] = { x:rx+jx, y:baseY+jy };
        }
      }

      // 噪声节点：在中心线上下两侧散布，避开中心保护带
      var nids=byLayerNoise[l].map(function(n){return n.id;}).sort();
      for(var k=0;k<nids.length;k++){
        var jt=jitter(nids[k]);
        var sign=(k%2===0)?-1:1;
        var bh = (l===0) ? bandHalfL0 : bandHalfOther;
        var mag=centerGuard+18+((jt.y+4)/8)*(bh-centerGuard-18);
        var ny=yc+sign*mag;
        var frac=(k+0.5)/Math.max(1,nids.length);
        var nx=W*0.06+W*0.88*frac + jt.x*1.2;
        if(nx<W*0.03) nx=W*0.03; if(nx>W*0.97) nx=W*0.97;
        pos[nids[k]]={ x:nx, y:ny };
      }
    }

    // ── 边重叠消除（L0 VPC 扇出边）──
    // 问题：VPC 到多个子节点的箭头如果角度接近，会近乎重叠。
    // 算法：对每个 L0 父节点的出边，按 atan2 角度排序，若相邻边角度差 < minSep
    // 就横向推开子节点，确保扇出角度均匀分散。
    (function(){
      var MIN_SEP_DEG = 10;
      var ITERS = 3;
      var minSepRad = MIN_SEP_DEG * Math.PI / 180;
      // 找出 L0 中可能是父节点的 id（vpc 或作为 can_connect 源的网络节点）
      var parentIds = {};
      c.nodes.forEach(function(n){
        if(n.layer===0 && (n.kind==='vpc' || n.kind==='subnet' || n.kind==='subnet_group')) parentIds[n.id]=true;
      });
      // 按 source 归组出边
      var outE = {};
      c.edges.forEach(function(e){
        if(parentIds[e.source] && pos[e.source] && pos[e.target]){
          if(!outE[e.source]) outE[e.source]=[];
          outE[e.source].push(e);
        }
      });
      var keys = Object.keys(outE);
      for(var it=0; it<ITERS; it++){
        for(var k=0; k<keys.length; k++){
          var p = keys[k], pp = pos[p];
          var edges = outE[p];
          if(edges.length < 2) continue;
          // 计算每条边的角度并排序
          var list = edges.map(function(e){
            var tp = pos[e.target];
            return { e:e, ang:Math.atan2(tp.y-pp.y, tp.x-pp.x) };
          });
          list.sort(function(a,b){ return a.ang - b.ang; });
          // 相邻边若角度 < minSep，把更外侧的 target 往外推
          for(var i=0; i<list.length-1; i++){
            var a = list[i], b = list[i+1];
            var gap = b.ang - a.ang;
            if(gap > 0 && gap < minSepRad){
              var atp = pos[a.e.target], btp = pos[b.e.target];
              // 目标角度：对称扩展
              var mid = (a.ang + b.ang) / 2;
              var aTarget = mid - minSepRad/2;
              var bTarget = mid + minSepRad/2;
              var ady = atp.y - pp.y, bdy = btp.y - pp.y;
              if(Math.abs(ady) > 10){
                var axNew = pp.x + ady / Math.tan(aTarget);
                var dax = axNew - atp.x;
                if(Math.abs(dax) < 200) atp.x += dax * 0.6;
              }
              if(Math.abs(bdy) > 10){
                var bxNew = pp.x + bdy / Math.tan(bTarget);
                var dbx = bxNew - btp.x;
                if(Math.abs(dbx) < 200) btp.x += dbx * 0.6;
              }
            }
          }
        }
      }
      // 边界约束：不超出画布
      var idsAll = Object.keys(pos);
      for(var q=0; q<idsAll.length; q++){
        var p=pos[idsAll[q]];
        if(p.x<W*0.03) p.x=W*0.03; if(p.x>W*0.97) p.x=W*0.97;
      }
    })();

    // ── 普适碰撞消解：迭代推开重叠节点，且约束每个节点不越出所在层带 ──
    var meta={};
    c.nodes.forEach(function(n){
      var isCore = (n.layer===0) && CORE_KINDS[n.kind||''];
      var size = isCore ? NODE_SIZE.core
                : (n.on_path ? NODE_SIZE.path
                : (n.is_noise ? NODE_SIZE.noise : NODE_SIZE.real));
      meta[n.id]={ size:size, yc:LAYER_Y[n.layer], noise:n.is_noise, layer:n.layer, core:isCore };
    });
    var idsAll=Object.keys(pos);
    var PAD=14, ITERS=120;
    for(var it=0; it<ITERS; it++){
      for(var a=0;a<idsAll.length;a++){
        for(var b=a+1;b<idsAll.length;b++){
          var ia=idsAll[a], ib=idsAll[b];
          var pa=pos[ia], pb=pos[ib], ma=meta[ia], mb=meta[ib];
          if(!pa||!pb||!ma||!mb) continue;
          var dx=pb.x-pa.x, dy=pb.y-pa.y;
          var dist=Math.sqrt(dx*dx+dy*dy);
          var minD=(ma.size+mb.size)/2 + PAD;
          if(dist<minD){
            if(dist<0.01){ var jn=jitter(ia+ib); dx=(jn.x||1); dy=(jn.y||1); dist=Math.sqrt(dx*dx+dy*dy)||1; }
            var overlap=(minD-dist);
            var ux=dx/dist, uy=dy/dist;
            var fa=ma.noise?1.0:0.3, fb=mb.noise?1.0:0.3;   // 真实节点少动，保持主轴稳定
            var tot=fa+fb;
            pa.x-=ux*overlap*(fa/tot); pa.y-=uy*overlap*(fa/tot);
            pb.x+=ux*overlap*(fb/tot); pb.y+=uy*overlap*(fb/tot);
          }
        }
      }
      // 约束回各自层带
      for(var q=0;q<idsAll.length;q++){
        var id=idsAll[q], p=pos[id], mt=meta[id];
        if(!p||!mt) continue;
        if(p.x<W*0.03) p.x=W*0.03; if(p.x>W*0.97) p.x=W*0.97;
        if(mt.noise){
          var band = (mt.layer===0) ? bandHalfL0 : bandHalfOther;
          if(p.y>mt.yc+band) p.y=mt.yc+band;
          if(p.y<mt.yc-band) p.y=mt.yc-band;
          // 保持在中心保护带之外，不压真实主轴
          if(Math.abs(p.y-mt.yc)<centerGuard){ p.y = mt.yc + (p.y>=mt.yc?centerGuard:-centerGuard); }
        } else {
          var rband = (mt.layer===0) ? 360 : 26;   // L0 四行树：VPC/entry_sg/infra/sg 距中心各 262.5px，加半径余量
          if(p.y>mt.yc+rband) p.y=mt.yc+rband;
          if(p.y<mt.yc-rband) p.y=mt.yc-rband;
        }
      }
    }
    return { pos:pos, W:CANVAS_W, realIds:realIds };
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
      var isCore = (n.layer===0) && CORE_KINDS[n.kind||''];
      if(isCore) cls.push('core');
      var size = isCore ? NODE_SIZE.core
                : (n.on_path ? NODE_SIZE.path
                : (n.is_noise ? NODE_SIZE.noise : NODE_SIZE.real));
      els.push({group:'nodes',data:{id:n.id,label:shortName(n.name),color:TYPE_COLOR[n.type]||'#64748b',size:size},position:pos[n.id],classes:cls.join(' ')});
    });
    // 画出全部边；牵涉噪声节点的边标 noiseedge 予以弱化，路径边标 onpath
    c.edges.forEach(function(e,i){
      var cls=[];
      if(e.on_path) cls.push('onpath');
      if(!(realIds[e.source] && realIds[e.target])) cls.push('noiseedge');
      els.push({group:'edges',data:{id:'ed'+i,source:e.source,target:e.target,label:e.label},classes:cls.join(' ')});
    });

    if(cy){ cy.destroy(); cy=null; }
    cy=cytoscape({container:el('cy'),elements:els,style:CY_STYLE,layout:{name:'preset'},
      wheelSensitivity:0.25,minZoom:0.2,maxZoom:3,pixelRatio:2});
    cy.fit(cy.elements(),45);
    cy.on('tap','node',function(evt){ onNodeClick(evt.target.id()); });
    cy.on('tap',function(evt){ if(evt.target===cy) resetHighlight(); });

    // hover：基于经过该节点的暴露路径高亮（图整体连通，用路径而非连通分量）
    function hoverByNode(nid){
      var ns={}, es={};
      var hit=false;
      (currentCase.results||[]).forEach(function(r){
        var p=r.path||[];
        if(p.indexOf(nid)<0) return;
        hit=true;
        p.forEach(function(x){ ns[x]=true; });
        for(var i=0;i<p.length-1;i++){ es[p[i]+'|'+p[i+1]]=true; es[p[i+1]+'|'+p[i]]=true; }
      });
      if(!hit){
        // 不在任何暴露路径上：只亮自身 + 直接相邻边（1 跳）
        ns[nid]=true;
        (currentCase.edges||[]).forEach(function(e){
          if(e.source===nid||e.target===nid){ ns[e.source]=true; ns[e.target]=true; es[e.source+'|'+e.target]=true; es[e.target+'|'+e.source]=true; }
        });
      }
      cy.batch(function(){
        cy.nodes().forEach(function(n){ if(ns[n.id()]) n.addClass('hover'); });
        cy.edges().forEach(function(e){ if(es[e.data('source')+'|'+e.data('target')]) e.addClass('hover'); });
      });
    }
    cy.on('mouseover','node',function(evt){ hoverByNode(evt.target.id()); });
    cy.on('mouseover','edge',function(evt){ hoverByNode(evt.target.data('source')); });
    cy.on('mouseout','node',function(){ cy.elements().removeClass('hover'); });
    cy.on('mouseout','edge',function(){ cy.elements().removeClass('hover'); });
    cy.on('pan zoom render',updateBands);
    updateBands();
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

  // 高亮任意节点集合，及其内部相连的边
  function highlightNodeSet(nsMap){
    if(!cy) return;
    cy.batch(function(){
      cy.elements().addClass('dim').removeClass('hl');
      cy.nodes().forEach(function(n){ if(nsMap[n.id()]){ n.removeClass('dim').addClass('hl'); } });
      cy.edges().forEach(function(e){
        if(nsMap[e.data('source')] && nsMap[e.data('target')]){ e.removeClass('dim').addClass('hl'); }
      });
    });
  }

  function resetHighlight(){
    activePath=-1;
    if(cy){ cy.batch(function(){ cy.elements().removeClass('dim').removeClass('hl'); }); }
    document.querySelectorAll('.plist-item').forEach(function(x){ x.classList.remove('active'); });
    renderChainEmpty();
  }

  // 计算 nid 所在的连通分量（无向），返回 {nodeId:true,...}
  function componentOf(nid){
    var comp={}; comp[nid]=true;
    var queue=[nid];
    while(queue.length){
      var cur=queue.shift();
      currentCase.edges.forEach(function(e){
        var nb=null;
        if(e.source===cur) nb=e.target; else if(e.target===cur) nb=e.source;
        if(nb && !comp[nb]){ comp[nb]=true; queue.push(nb); }
      });
    }
    return comp;
  }

  // 点节点 → 真实节点高亮其最高分攻击链；噪声节点高亮其所在诱饵连通分量
  function onNodeClick(nid){
    var best=-1, bestScore=-1;
    currentCase.results.forEach(function(r,idx){
      if(r.path.indexOf(nid)>=0 && r.gate_result.score>bestScore){ bestScore=r.gate_result.score; best=idx; }
    });
    if(best>=0){ selectPath(best); return; }

    // 噪声/非路径节点：连通分量，高亮诱饵链
    var comp=componentOf(nid);
    activePath=-2;
    document.querySelectorAll('.plist-item').forEach(function(x){ x.classList.remove('active'); });
    highlightNodeSet(comp);
    renderDecoyExplain(nid, Object.keys(comp).length);
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

  function renderDecoyExplain(nid, compSize){
    var nmap=nodeMap(currentCase);
    var n=nmap[nid]||{};
    var name=n.name||nid;
    var html='';
    html+='<div class="step"><div class="step-dot" style="border-color:#64748b;color:#94a3b8">!</div>'
      + '<div class="step-title">良性干扰资源 <span class="tag">噪声 / 诱饵链</span></div>'
      + '<div class="step-body">已选中 <span class="mono">'+esc(name)+'</span>。该节点<strong>不在任何真实暴露路径上</strong>，属于基准注入的良性干扰资源。</div></div>';
    html+='<div class="step"><div class="step-dot" style="border-color:#64748b;color:#94a3b8">✓</div>'
      + '<div class="step-title">EIC 判定 <span class="tag">证据约束算子</span></div>'
      + '<div class="step-body"><div class="llm-box">该诱饵连通分量约 <strong>'+compSize+'</strong> 个节点。EIC 证据校验中其硬约束维度（reach / perm / target）无法同时满足，Gate 未通过，判定为 <span class="type-badge" style="background:#64748b">Insufficient_Evidence</span>（非暴露路径）。</div></div></div>';
    html+='<div class="step"><div class="step-dot" style="border-color:#64748b;color:#94a3b8">i</div>'
      + '<div class="step-title">设计意图 <span class="tag">抗干扰评测</span></div>'
      + '<div class="step-body">基准注入约 30% 噪声/诱饵节点，用于考验 EIC-Agent 在真实与虚假攻击链混杂时的抗干扰与精确判定能力。</div></div>';
    el('chain').innerHTML=html;
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
  renderTabs();
  window.addEventListener('resize', updateBands);
  var first=Object.keys(DATA)[0];
  if(first) selectCase(first);
})();
</script>
</body>
</html>'''


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="生成 EIC-Agent 暴露路径看板")
    ap.add_argument("--dataset", choices=["v2", "cloudgoat"], default="v2",
                    help="数据源：v2=原验证集，cloudgoat=真实靶场种子数据集")
    _args = ap.parse_args()
    if _args.dataset == "cloudgoat":
        RESULTS_FILE = ROOT / "output" / "web_results_cloudgoat.json"
        SAMPLES_FILE = ROOT / "data" / "verification_set" / "samples_cloudgoat.json"
        OUT_FILE = ROOT / "showcase_cloudgoat.html"
    main()
