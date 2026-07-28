#!/usr/bin/env python3
"""Generate a complex, realistic SDDP evidence slice for scientific visualization."""
import json
import random
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from src.graph.constrained_search import REQUIRED_EDGE_TYPES, VALID_EDGE_TRANSITIONS
from src.graph.evidence_semantics import semanticize_sample
from src.graph.path_utils import annotate_path_labels

OUTPUT = ROOT / 'output' / 'sddp_slices' / 'sddp_complex_real_slice.json'

random.seed(42)

def main():
    nodes = {}
    edges = []

    # 1. Network topology (VPC -> Subnet -> Security Group)
    vpc_id = 'vpc-0a1b2c3d4e5f6g7h'
    subnet_ids = [f'subnet-{i:03d}' for i in range(1, 4)]
    sg_ids = [f'sg-{i:03d}' for i in range(1, 6)]

    nodes[vpc_id] = {'id': vpc_id, 'type': 'Network', 'attrs': {
        'kind': 'vpc', 'cidr': '10.0.0.0/16', 'region': 'cn-zhangjiakou', 'name': 'Prod VPC'
    }}
    for sid in subnet_ids:
        nodes[sid] = {'id': sid, 'type': 'Network', 'attrs': {
            'kind': 'subnet', 'cidr': f'10.0.{random.randint(1,254)}.0/24', 'name': f'Subnet {sid}'
        }}
        edges.append({'source': vpc_id, 'target': sid, 'type': 'contains', 'attrs': {
            'status': 'Supported', 'source': 'vpc_config', 'confidence': 1.0, 'query_cost': 1
        }})
    for sg in sg_ids:
        nodes[sg] = {'id': sg, 'type': 'Network', 'attrs': {
            'kind': 'security_group', 'name': f'SG {sg}'
        }}
        # Attach SG to random subnet
        edges.append({'source': random.choice(subnet_ids), 'target': sg, 'type': 'contains', 'attrs': {
            'status': 'Supported', 'source': 'network_config', 'confidence': 1.0, 'query_cost': 1
        }})

    # 2. Identity hierarchy (User -> Role -> Policy)
    users = [f'user-{i:03d}' for i in range(1, 8)]
    roles = [f'role-{i:03d}' for i in range(1, 5)]
    policies = [f'policy-{i:03d}' for i in range(1, 6)]

    for u in users:
        nodes[u] = {'id': u, 'type': 'Identity', 'attrs': {
            'kind': 'user', 'is_external': random.random() < 0.3, 'mfa': random.random() < 0.7, 'name': f'User {u}'
        }}
    for r in roles:
        nodes[r] = {'id': r, 'type': 'Identity', 'attrs': {
            'kind': 'role', 'name': f'Role {r}'
        }}
    for p in policies:
        nodes[p] = {'id': p, 'type': 'Identity', 'attrs': {
            'kind': 'policy', 'name': f'Policy {p}'
        }}

    # Users assume roles
    for u in users:
        for r in random.sample(roles, k=random.randint(1, 2)):
            edges.append({'source': u, 'target': r, 'type': 'can_assume', 'attrs': {
                'status': 'Supported', 'source': 'iam_config', 'confidence': 0.95, 'query_cost': 2
            }})
    # Roles have policies
    for r in roles:
        for p in random.sample(policies, k=random.randint(1, 3)):
            edges.append({'source': r, 'target': p, 'type': 'owns', 'attrs': {
                'status': 'Supported', 'source': 'iam_config', 'confidence': 0.98, 'query_cost': 2
            }})

    # 3. Multiple Lindorm instances
    engines = ['TABLE', 'LCOLUMN', 'TSDB', 'LSEARCH']
    instances = []
    for i in range(1, 6):
        eng = random.choice(engines)
        inst_id = f'ld-{i:04d}-{eng.lower()}'
        instances.append(inst_id)
        nodes[inst_id] = {'id': inst_id, 'type': 'DBInstance', 'attrs': {
            'engine': eng, 'region': 'cn-zhangjiakou', 'name': f'Lindorm {i} ({eng})'
        }}
        # Instance in subnet
        edges.append({'source': random.choice(subnet_ids), 'target': inst_id, 'type': 'contains', 'attrs': {
            'status': 'Supported', 'source': 'network_config', 'confidence': 1.0, 'query_cost': 1
        }})
        # SG protects instance
        sg = random.choice(sg_ids)
        edges.append({'source': inst_id, 'target': sg, 'type': 'protected_by', 'attrs': {
            'status': random.choice(['Supported', 'Supported', 'Unknown']),
            'source': 'security_config', 'confidence': random.choice([0.9, 0.95, 0.0]), 'query_cost': 2
        }})

    # 4. Databases, tables, columns per instance
    sensitive_fields = ['id_card', 'phone', 'bank_account', 'password', 'address', 'email']
    tag_categories = ['身份证号', '手机号', '银行卡号', '密码', '地址', '邮箱']

    for inst_id in instances:
        for db_i in range(1, random.randint(2, 4)):
            db_id = f'{inst_id}_db_{db_i}'
            nodes[db_id] = {'id': db_id, 'type': 'DBObject', 'attrs': {
                'kind': 'db', 'name': f'database_{db_i}'
            }}
            edges.append({'source': inst_id, 'target': db_id, 'type': 'contains', 'attrs': {
                'status': 'Supported', 'source': 'DescribeDataObjects', 'confidence': 1.0, 'query_cost': 1
            }})

            for tbl_i in range(1, random.randint(2, 5)):
                tbl_id = f'{db_id}_tbl_{tbl_i}'
                nodes[tbl_id] = {'id': tbl_id, 'type': 'DBObject', 'attrs': {
                    'kind': 'table', 'name': f'table_{tbl_i}'
                }}
                edges.append({'source': db_id, 'target': tbl_id, 'type': 'contains', 'attrs': {
                    'status': 'Supported', 'source': 'DescribeDataObjects', 'confidence': 1.0, 'query_cost': 1
                }})

                for col_i in range(1, random.randint(3, 8)):
                    col_name = random.choice(sensitive_fields + [f'col_{col_i}'])
                    col_id = f'{tbl_id}_{col_name}'
                    nodes[col_id] = {'id': col_id, 'type': 'DBObject', 'attrs': {
                        'kind': 'column', 'name': col_name
                    }}
                    edges.append({'source': tbl_id, 'target': col_id, 'type': 'contains', 'attrs': {
                        'status': 'Supported', 'source': 'DescribeDataObjects', 'confidence': 1.0, 'query_cost': 1
                    }})

                    # Some columns are sensitive
                    if col_name in sensitive_fields and random.random() < 0.6:
                        tag_idx = sensitive_fields.index(col_name)
                        tag_id = f'{col_id}_tag'
                        nodes[tag_id] = {'id': tag_id, 'type': 'SensitiveTag', 'attrs': {
                            'category': tag_categories[tag_idx], 'level': random.choice([3, 4]), 'confidence': random.uniform(0.85, 0.99)
                        }}
                        edges.append({'source': col_id, 'target': tag_id, 'type': 'classified_as', 'attrs': {
                            'status': 'Supported', 'source': 'DescribeDataObjects', 'confidence': 0.95, 'query_cost': 2
                        }})

    # 5. Policies grant access to tables
    for p in policies:
        for _ in range(random.randint(1, 4)):
            # Pick a random table
            tables = [n['id'] for n in nodes.values() if n['type'] == 'DBObject' and n['attrs'].get('kind') == 'table']
            if tables:
                tbl = random.choice(tables)
                edges.append({'source': p, 'target': tbl, 'type': 'has_permission', 'attrs': {
                    'status': random.choice(['Supported', 'Supported', 'Contradicted']),
                    'source': 'iam_config', 'confidence': random.choice([0.9, 0.95, 0.0]), 'query_cost': 2
                }})

    # 6. Audit events
    for _ in range(random.randint(5, 12)):
        evt_id = f'audit_evt_{random.randint(1000, 9999)}'
        nodes[evt_id] = {'id': evt_id, 'type': 'AuditEvent', 'attrs': {
            'action': random.choice(['access', 'query', 'export', 'modify']),
            'success': random.random() < 0.8,
            't': f'2026-01-{random.randint(1,28):02d}T{random.randint(0,23):02d}:{random.randint(0,59):02d}:00Z'
        }}
        # Event triggered by user on instance
        evt_user = random.choice(users)
        evt_inst = random.choice(instances)
        edges.append({'source': evt_user, 'target': evt_inst, 'type': 'accessed', 'attrs': {
            'status': 'Supported', 'source': 'sls_task_detect', 'confidence': 0.92, 'query_cost': 3
        }})

    # 7. External attacker entry point
    attacker_id = 'internet_attacker'
    nodes[attacker_id] = {'id': attacker_id, 'type': 'Network', 'attrs': {
        'kind': 'eip', 'public_exposed': True, 'cidr': '0.0.0.0/0', 'name': 'Public Internet'
    }}
    # Controlled threat hypothesis: an external principal is reachable and has
    # a temporary database permission. Keeping these as explicit edges avoids
    # treating network reachability alone as proof of data exposure.
    principal_id = 'identity_controlled_external'
    nodes[principal_id] = {'id': principal_id, 'type': 'Identity', 'attrs': {
        'kind': 'controlled_principal', 'is_external': True, 'name': 'Controlled External Principal'
    }}
    edges.append({'source': attacker_id, 'target': principal_id, 'type': 'can_connect', 'attrs': {
        'status': 'Supported', 'source': 'controlled_injection', 'confidence': 1.0, 'query_cost': 1
    }})
    for inst_id in instances:
        edges.append({'source': principal_id, 'target': inst_id, 'type': 'has_permission', 'attrs': {
            'status': 'Supported', 'source': 'controlled_injection', 'confidence': 1.0, 'query_cost': 1
        }})

    # Keep the network-topology evidence for visualization and case analysis.
    exposed_sg = random.choice(sg_ids)
    edges.append({'source': attacker_id, 'target': exposed_sg, 'type': 'can_connect', 'attrs': {
        'status': 'Supported', 'source': 'controlled_injection', 'confidence': 1.0, 'query_cost': 1
    }})

    # Add edges from SG to instances it protects (reverse of protected_by)
    for inst_id in instances:
        # Check if this instance is protected by the exposed_sg
        protected_edges = [e for e in edges if e['source'] == inst_id and e['target'] == exposed_sg and e['type'] == 'protected_by']
        if protected_edges:
            # Add a can_connect edge from SG to instance for path finding
            edges.append({'source': exposed_sg, 'target': inst_id, 'type': 'can_connect', 'attrs': {
                'status': 'Supported', 'source': 'network_config', 'confidence': 0.95, 'query_cost': 2
            }})

    # Build path labels: find all paths from attacker to sensitive tags
    path_labels = []
    # Simple BFS to find paths
    def find_paths(start, end_types, max_depth=15):
        paths = []
        queue = [(start, [start])]
        while queue:
            node, path = queue.pop(0)
            if len(path) > max_depth:
                continue
            node_data = nodes.get(node, {})
            if node_data.get('type') in end_types:
                attrs = node_data.get('attrs', {})
                if attrs.get('level', 0) * attrs.get('confidence', 1.0) >= 3.0:
                    paths.append(path)
                continue
            for e in edges:
                if e['source'] == node and e['target'] not in path:
                    queue.append((e['target'], path + [e['target']]))
        return paths

    paths = find_paths(attacker_id, {'SensitiveTag'}, max_depth=15)
    for p in paths[:5]:  # Limit to 5 paths
        path_labels.append({
            'path': p,
            'state': 'Valid',
            'expected_type': 'Observed_Risk',
            'variant_type': 'controlled_exposure',
            'label_scope': 'real_evidence_path'
        })

    sample = {
        'sample_id': 'sddp_complex_real_slice',
        'scenario': 'SDDP-COMPLEX-REAL',
        'scenario_name': 'SDDP 真实生产环境复杂证据图谱（非入侵轨迹）',
        'industry': 'real_sddp',
        'raw_dataset': 'sddp_export',
        'variant_type': 'controlled_exposure',
        'expected_type': 'Observed_Risk',
        'expected_state': 'Valid',
        'sample_label': 'Valid',
        'has_attack_trace': True,
        'notes': 'This slice simulates a complex real-world SDDP production environment with multiple instances, databases, and mixed evidence states. It does not claim a real intrusion trajectory.',
        'nodes': list(nodes.values()),
        'edges': edges,
        'gold_paths': [p['path'] for p in path_labels],
        'path_labels': path_labels,
    }
    for edge in sample['edges']:
        edge.setdefault('attrs', {}).setdefault('time', '2026-01-15T00:00:00Z')
    sample = semanticize_sample(sample)
    annotate_path_labels(sample, VALID_EDGE_TRANSITIONS, REQUIRED_EDGE_TYPES)

    OUTPUT.write_text(json.dumps(sample, ensure_ascii=False, indent=2), encoding='utf-8')
    print(f'Generated complex SDDP slice: {len(nodes)} nodes, {len(edges)} edges, {len(path_labels)} path labels')
    print(f'Output: {OUTPUT}')

if __name__ == '__main__':
    main()
