#!/usr/bin/env python3
"""Generate a scientific knowledge graph visualization of the complex SDDP slice."""
import json
from pathlib import Path

ROOT = Path(__file__).parent.parent
SLICE_PATH = ROOT / 'output' / 'sddp_slices' / 'sddp_complex_real_slice.json'
OUTPUT_PATH = ROOT / 'showcase' / 'showcase_complex_sddp.html'
VENDOR_PATH = ROOT / 'vendor'

def main():
    slice_data = json.loads(SLICE_PATH.read_text(encoding='utf-8'))
    
    # Build Cytoscape elements
    nodes = []
    edges = []
    
    type_colors = {
        'Network': '#3b82f6',
        'Identity': '#a855f7',
        'DBInstance': '#22c55e',
        'DBObject': '#16a34a',
        'SensitiveTag': '#ef4444',
        'AuditEvent': '#f59e0b',
        'Control': '#eab308',
    }
    
    for n in slice_data['nodes']:
        node_type = n['type']
        color = type_colors.get(node_type, '#6b7280')
        size = 30 if n.get('id') == 'internet_attacker' else 20
        if node_type == 'SensitiveTag':
            size = 25
        
        nodes.append({
            'data': {
                'id': n['id'],
                'label': n['attrs'].get('name', n['id']),
                'type': node_type,
                'color': color,
                'size': size,
            }
        })
    
    for e in slice_data['edges']:
        status = e['attrs'].get('status', 'Supported')
        edge_color = '#10b981' if status == 'Supported' else '#f59e0b' if status == 'Unknown' else '#ef4444'
        edge_width = 2 if status == 'Supported' else 3
        
        edges.append({
            'data': {
                'source': e['source'],
                'target': e['target'],
                'label': e['type'],
                'status': status,
                'color': edge_color,
                'width': edge_width,
            }
        })
    
    # Highlight paths
    path_edges = set()
    path_nodes = set()
    for pl in slice_data.get('path_labels', []):
        path = pl['path']
        path_nodes.update(path)
        for i in range(len(path) - 1):
            path_edges.add((path[i], path[i+1]))
    
    for e in edges:
        src = e['data']['source']
        tgt = e['data']['target']
        if (src, tgt) in path_edges or (tgt, src) in path_edges:
            e['data']['color'] = '#ef4444'
            e['data']['width'] = 4
    
    for n in nodes:
        if n['data']['id'] in path_nodes:
            n['data']['size'] = max(n['data']['size'], 35)
            n['data']['border-width'] = 3
            n['data']['border-color'] = '#fbbf24'
    
    # Read local vendor files
    cytoscape_js = (VENDOR_PATH / 'cytoscape.min.js').read_text(encoding='utf-8')
    
    # Generate HTML with inlined scripts
    html = f'''<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Complex SDDP Evidence Graph - Scientific Visualization</title>
<script>{cytoscape_js}</script>
<style>
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{ 
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    background: #0f172a;
    color: #e2e8f0;
    overflow: hidden;
}}
#cy {{
    width: 100vw;
    height: 100vh;
    position: absolute;
    top: 0;
    left: 0;
}}
.header {{
    position: absolute;
    top: 20px;
    left: 20px;
    z-index: 10;
    background: rgba(15, 23, 42, 0.9);
    padding: 15px 20px;
    border-radius: 8px;
    border: 1px solid #334155;
    max-width: 400px;
}}
.header h1 {{
    font-size: 18px;
    color: #60a5fa;
    margin-bottom: 8px;
}}
.header p {{
    font-size: 13px;
    color: #94a3b8;
    line-height: 1.5;
}}
.legend {{
    position: absolute;
    bottom: 20px;
    right: 20px;
    z-index: 10;
    background: rgba(15, 23, 42, 0.9);
    padding: 15px;
    border-radius: 8px;
    border: 1px solid #334155;
}}
.legend h3 {{
    font-size: 14px;
    color: #60a5fa;
    margin-bottom: 10px;
}}
.legend-item {{
    display: flex;
    align-items: center;
    gap: 8px;
    margin-bottom: 6px;
    font-size: 12px;
}}
.legend-color {{
    width: 16px;
    height: 16px;
    border-radius: 50%;
}}
.stats {{
    position: absolute;
    top: 20px;
    right: 20px;
    z-index: 10;
    background: rgba(15, 23, 42, 0.9);
    padding: 15px;
    border-radius: 8px;
    border: 1px solid #334155;
}}
.stats h3 {{
    font-size: 14px;
    color: #60a5fa;
    margin-bottom: 10px;
}}
.stat-item {{
    font-size: 12px;
    margin-bottom: 4px;
}}
.stat-value {{
    color: #22c55e;
    font-weight: 600;
}}
</style>
</head>
<body>
<div class="header">
    <h1>Complex SDDP Evidence Graph</h1>
    <p>SDDP 真实生产环境复杂证据图谱（非入侵轨迹）<br>
    152 nodes · 195 edges · 5 exposure paths<br>
    <strong>滚轮缩放 · 拖动画布 · 拖动节点</strong></p>
</div>
<div class="stats">
    <h3>Graph Statistics</h3>
    <div class="stat-item">Nodes: <span class="stat-value">{len(nodes)}</span></div>
    <div class="stat-item">Edges: <span class="stat-value">{len(edges)}</span></div>
    <div class="stat-item">Paths: <span class="stat-value">{len(slice_data.get('path_labels', []))}</span></div>
    <div class="stat-item">Sample Label: <span class="stat-value">{slice_data.get('sample_label', 'N/A')}</span></div>
</div>
<div class="legend">
    <h3>Node Types</h3>
    <div class="legend-item"><div class="legend-color" style="background: #3b82f6"></div>Network</div>
    <div class="legend-item"><div class="legend-color" style="background: #a855f7"></div>Identity</div>
    <div class="legend-item"><div class="legend-color" style="background: #22c55e"></div>DBInstance</div>
    <div class="legend-item"><div class="legend-color" style="background: #16a34a"></div>DBObject</div>
    <div class="legend-item"><div class="legend-color" style="background: #ef4444"></div>SensitiveTag</div>
    <div class="legend-item"><div class="legend-color" style="background: #f59e0b"></div>AuditEvent</div>
    <h3 style="margin-top: 12px">Edge Status</h3>
    <div class="legend-item"><div class="legend-color" style="background: #10b981"></div>Supported</div>
    <div class="legend-item"><div class="legend-color" style="background: #f59e0b"></div>Unknown</div>
    <div class="legend-item"><div class="legend-color" style="background: #ef4444"></div>Contradicted</div>
</div>
<div id="cy"></div>
<script>
const cy = cytoscape({{
    container: document.getElementById('cy'),
    elements: {json.dumps(nodes + edges)},
    style: [
        {{
            selector: 'node',
            style: {{
                'background-color': 'data(color)',
                'label': 'data(label)',
                'width': 'data(size)',
                'height': 'data(size)',
                'font-size': '10px',
                'color': '#e2e8f0',
                'text-valign': 'bottom',
                'text-halign': 'center',
                'text-margin-y': 8,
                'border-width': 'data(border-width)',
                'border-color': 'data(border-color)',
                'text-outline-width': 2,
                'text-outline-color': '#0f172a',
            }}
        }},
        {{
            selector: 'edge',
            style: {{
                'width': 'data(width)',
                'line-color': 'data(color)',
                'target-arrow-color': 'data(color)',
                'target-arrow-shape': 'triangle',
                'curve-style': 'bezier',
                'label': 'data(label)',
                'font-size': '8px',
                'color': '#94a3b8',
                'text-rotation': 'autorotate',
                'text-outline-width': 1,
                'text-outline-color': '#0f172a',
            }}
        }}
    ],
    layout: {{
        name: 'cose',
        animate: true,
        randomize: false,
        maxSimulationTime: 4000,
        fit: true,
        padding: 50,
        nodeRepulsion: 400000,
        edgeElasticity: 100,
    }},
    wheelSensitivity: 0.3,
}});
</script>
</body>
</html>'''
    
    OUTPUT_PATH.write_text(html, encoding='utf-8')
    print(f'Generated scientific visualization: {OUTPUT_PATH}')
    print(f'Nodes: {len(nodes)}, Edges: {len(edges)}')

if __name__ == '__main__':
    main()
