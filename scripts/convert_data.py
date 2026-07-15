#!/usr/bin/env python3
"""
数据格式转换脚本
将新版 case_XXX.json (Agent循环架构) 转换为 demo 期望的旧版 samples 格式
"""
import json
import glob
import os
from pathlib import Path

NEW_DATA_DIR = Path('/Users/yunyun/Desktop/云数据库高敏数据暴露路径侦测/experiments/data_gen/output')
OUTPUT_DIR = Path(__file__).parent.parent / 'data' / 'verification_set'

SIGNAL_SCENARIO_NAME = {
    'iam_over_permission': 'IAM权限过宽',
    'user_data_leak': '用户数据泄露',
    'web_rce_to_db': 'Web RCE到数据库',
    'public_db_exposure': 'RDS公网暴露',
}

SEED_MAP = {
    'codebuild_secrets': ('CB', 'devops'),
    'data_secrets': ('DS', 'ecommerce'),
    'rce_web_app': ('RCE', 'tech'),
    'rds_snapshot': ('RDS', 'finance'),
}


def convert_level(val):
    if isinstance(val, int):
        return val
    if isinstance(val, str):
        s = val.strip().upper().replace('L', '')
        try:
            return int(s)
        except ValueError:
            return 0
    return 0


def convert_node(node):
    attrs = dict(node.get('config', {}))
    if 'level' in attrs:
        attrs['level'] = convert_level(attrs['level'])
    return {'id': node['id'], 'type': node['type'], 'attrs': attrs}


def convert_edge(edge):
    attrs = dict(edge.get('config', {}))
    return {'source': edge['source'], 'target': edge['target'], 'type': edge['type'], 'attrs': attrs}


def convert_gold_paths(gold_paths):
    result = []
    for path in gold_paths:
        if isinstance(path, list):
            node_ids = []
            for step in path:
                if isinstance(step, dict):
                    node_ids.append(step['node_id'])
                elif isinstance(step, str):
                    node_ids.append(step)
            result.append(node_ids)
        elif isinstance(path, str):
            result.append([path])
    return result


def convert_case(case_data):
    case_id = case_data['case_id']
    seed_source = case_data.get('seed_source', 'unknown')
    initial_signal = case_data.get('initial_signal', {})
    signal_type = initial_signal.get('type', 'unknown')

    scenario_code, industry = SEED_MAP.get(seed_source, ('X', 'unknown'))
    scenario_name = SIGNAL_SCENARIO_NAME.get(signal_type, signal_type)

    world = case_data.get('world_snapshot', {})
    nodes = [convert_node(n) for n in world.get('nodes', [])]
    edges = [convert_edge(e) for e in world.get('edges', [])]

    gold = case_data.get('gold', {})
    gold_paths = convert_gold_paths(gold.get('gold_paths', []))
    expected_type = gold.get('label', 'Observed_Risk')

    case_num = int(case_id.replace('case_', ''))
    scenario = f'{scenario_code}-{case_num:02d}'

    return {
        'sample_id': case_id,
        'scenario': scenario,
        'scenario_name': f'[{seed_source}] {scenario_name}',
        'industry': industry,
        'initial_signal': initial_signal,
        'variant_dims': case_data.get('variant_dims', []),
        'seed_source': seed_source,
        'nodes': nodes,
        'edges': edges,
        'gold_paths': gold_paths,
        'expected_type': expected_type,
    }


def main():
    output_file = OUTPUT_DIR / 'samples_v2.json'
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    case_files = sorted(glob.glob(str(NEW_DATA_DIR / 'case_*.json')))
    print(f'找到 {len(case_files)} 个案例文件')

    samples = []
    for cf in case_files:
        with open(cf, 'r', encoding='utf-8') as f:
            case_data = json.load(f)
        sample = convert_case(case_data)
        samples.append(sample)
        print(f'  ✓ {sample["sample_id"]}: {sample["scenario"]} | '
              f'{sample["scenario_name"]} | '
              f'{len(sample["nodes"])}节点 {len(sample["edges"])}边 | '
              f'{len(sample["gold_paths"])}条gold路径')

    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(samples, f, ensure_ascii=False, indent=2)

    print(f"\n✅ 转换完成: {output_file}")
    print(f'   共 {len(samples)} 个样本')

    s = samples[0]
    print(f"\n📋 第一个样本验证:")
    print(f'   sample_id: {s["sample_id"]}')
    print(f'   scenario: {s["scenario"]}')
    print(f'   scenario_name: {s["scenario_name"]}')
    print(f'   industry: {s["industry"]}')
    print(f'   expected_type: {s["expected_type"]}')
    print(f'   initial_signal: {s["initial_signal"]}')
    print(f'   nodes[0]: {s["nodes"][0]}')
    print(f'   edges[0]: {s["edges"][0]}')
    if s['gold_paths']:
        print(f'   gold_paths[0]: {s["gold_paths"][0]}')

    for n in s['nodes']:
        if n['type'] == 'SensitiveTag':
            lvl = n['attrs'].get('level')
            print(f'   SensitiveTag level: {lvl} (type={type(lvl).__name__})')
            break


if __name__ == '__main__':
    main()
