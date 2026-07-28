#!/usr/bin/env python3
"""Case study analysis for C2 experiments."""
import json
from pathlib import Path
from collections import defaultdict

ROOT = Path(__file__).parent.parent.parent
CORPUS_FILE = ROOT / "output" / "semantic_corpus" / "cloud_db_semantic_corpus.json"
RESULTS_FILE = ROOT / "output" / "semantic_corpus" / "semantic_experiments_results.json"
OUT_FILE = ROOT / "output" / "semantic_corpus" / "case_study_analysis.json"


def load_corpus():
    """Load the semantic corpus."""
    with open(CORPUS_FILE, 'r', encoding='utf-8') as f:
        return json.load(f)


def load_results():
    """Load experiment results."""
    with open(RESULTS_FILE, 'r', encoding='utf-8') as f:
        return json.load(f)


def analyze_case_studies():
    """Analyze case studies to identify success and failure patterns."""
    corpus = load_corpus()
    results = load_results()
    
    # Extract per-sample results
    # Note: The current results file doesn't have per-sample breakdown
    # We need to simulate this based on aggregate results
    
    print("Analyzing case studies...")
    print(f"Total samples in corpus: {len(corpus)}")
    
    # Categorize samples by variant type
    variant_counts = defaultdict(int)
    for sample in corpus:
        variant_type = sample.get('variant_type', 'unknown')
        variant_counts[variant_type] += 1
    
    print("\nSample distribution by variant type:")
    for variant, count in sorted(variant_counts.items(), key=lambda x: -x[1]):
        print(f"  {variant}: {count} ({count/len(corpus)*100:.1f}%)")
    
    # Categorize by expected state
    state_counts = defaultdict(int)
    for sample in corpus:
        expected_state = sample.get('expected_state', 'unknown')
        state_counts[expected_state] += 1
    
    print("\nSample distribution by expected state:")
    for state, count in sorted(state_counts.items(), key=lambda x: -x[1]):
        print(f"  {state}: {count} ({count/len(corpus)*100:.1f}%)")
    
    # Analyze path complexity
    path_lengths = []
    edge_counts = []
    for sample in corpus:
        nodes = sample.get('nodes', [])
        edges = sample.get('edges', [])
        path_labels = sample.get('path_labels', [])
        
        edge_counts.append(len(edges))
        if path_labels:
            for pl in path_labels:
                path = pl.get('path', [])
                path_lengths.append(len(path))
    
    print(f"\nPath complexity statistics:")
    print(f"  Average path length: {sum(path_lengths)/len(path_lengths):.2f}")
    print(f"  Min path length: {min(path_lengths)}")
    print(f"  Max path length: {max(path_lengths)}")
    print(f"  Average edges per sample: {sum(edge_counts)/len(edge_counts):.2f}")
    print(f"  Min edges per sample: {min(edge_counts)}")
    print(f"  Max edges per sample: {max(edge_counts)}")
    
    # Identify interesting cases based on characteristics
    print("\n" + "="*70)
    print("IDENTIFYING INTERESTING CASES")
    print("="*70)
    
    # Case 1: Complex paths (long paths with many edges)
    complex_cases = []
    for i, sample in enumerate(corpus):
        edges = sample.get('edges', [])
        path_labels = sample.get('path_labels', [])
        
        if len(edges) > 50 and path_labels:
            max_path_len = max(len(pl.get('path', [])) for pl in path_labels)
            if max_path_len > 6:
                complex_cases.append({
                    'index': i,
                    'sample_id': sample.get('sample_id', f'sample_{i}'),
                    'variant_type': sample.get('variant_type', 'unknown'),
                    'expected_state': sample.get('expected_state', 'unknown'),
                    'num_edges': len(edges),
                    'max_path_length': max_path_len,
                    'scenario_name': sample.get('scenario_name', 'N/A'),
                })
    
    complex_cases.sort(key=lambda x: -x['num_edges'])
    print(f"\nTop 5 complex cases (many edges + long paths):")
    for i, case in enumerate(complex_cases[:5], 1):
        print(f"  {i}. {case['sample_id']}")
        print(f"     Variant: {case['variant_type']}, State: {case['expected_state']}")
        print(f"     Edges: {case['num_edges']}, Max path length: {case['max_path_length']}")
        print(f"     Scenario: {case['scenario_name']}")
    
    # Case 2: Temporal conflict cases
    temporal_cases = []
    for i, sample in enumerate(corpus):
        if 'temporal' in sample.get('variant_type', ''):
            edges = sample.get('edges', [])
            temporal_edges = sum(1 for e in edges if e.get('attrs', {}).get('temporal_conflict', False))
            temporal_cases.append({
                'index': i,
                'sample_id': sample.get('sample_id', f'sample_{i}'),
                'variant_type': sample.get('variant_type', 'unknown'),
                'expected_state': sample.get('expected_state', 'unknown'),
                'temporal_edges': temporal_edges,
                'total_edges': len(edges),
                'scenario_name': sample.get('scenario_name', 'N/A'),
            })
    
    temporal_cases.sort(key=lambda x: -x['temporal_edges'])
    print(f"\nTop 5 temporal conflict cases:")
    for i, case in enumerate(temporal_cases[:5], 1):
        print(f"  {i}. {case['sample_id']}")
        print(f"     Variant: {case['variant_type']}, State: {case['expected_state']}")
        print(f"     Temporal edges: {case['temporal_edges']}/{case['total_edges']}")
        print(f"     Scenario: {case['scenario_name']}")
    
    # Case 3: Contradicted evidence cases
    contradicted_cases = []
    for i, sample in enumerate(corpus):
        edges = sample.get('edges', [])
        contradicted_edges = sum(1 for e in edges if e.get('attrs', {}).get('status') == 'Contradicted')
        if contradicted_edges > 5:
            contradicted_cases.append({
                'index': i,
                'sample_id': sample.get('sample_id', f'sample_{i}'),
                'variant_type': sample.get('variant_type', 'unknown'),
                'expected_state': sample.get('expected_state', 'unknown'),
                'contradicted_edges': contradicted_edges,
                'total_edges': len(edges),
                'scenario_name': sample.get('scenario_name', 'N/A'),
            })
    
    contradicted_cases.sort(key=lambda x: -x['contradicted_edges'])
    print(f"\nTop 5 contradicted evidence cases:")
    for i, case in enumerate(contradicted_cases[:5], 1):
        print(f"  {i}. {case['sample_id']}")
        print(f"     Variant: {case['variant_type']}, State: {case['expected_state']}")
        print(f"     Contradicted edges: {case['contradicted_edges']}/{case['total_edges']}")
        print(f"     Scenario: {case['scenario_name']}")
    
    # Case 4: Unknown evidence cases (insufficient evidence)
    unknown_cases = []
    for i, sample in enumerate(corpus):
        if sample.get('expected_state') == 'Insufficient':
            edges = sample.get('edges', [])
            unknown_edges = sum(1 for e in edges if e.get('attrs', {}).get('status') == 'Unknown')
            unknown_cases.append({
                'index': i,
                'sample_id': sample.get('sample_id', f'sample_{i}'),
                'variant_type': sample.get('variant_type', 'unknown'),
                'unknown_edges': unknown_edges,
                'total_edges': len(edges),
                'scenario_name': sample.get('scenario_name', 'N/A'),
            })
    
    unknown_cases.sort(key=lambda x: -x['unknown_edges'])
    print(f"\nTop 5 insufficient evidence cases:")
    for i, case in enumerate(unknown_cases[:5], 1):
        print(f"  {i}. {case['sample_id']}")
        print(f"     Variant: {case['variant_type']}")
        print(f"     Unknown edges: {case['unknown_edges']}/{case['total_edges']}")
        print(f"     Scenario: {case['scenario_name']}")
    
    # Generate detailed case study report
    print("\n" + "="*70)
    print("DETAILED CASE STUDY REPORT")
    print("="*70)
    
    # Select representative cases for detailed analysis
    selected_cases = []
    
    # Add 2 complex cases
    for case in complex_cases[:2]:
        sample = corpus[case['index']]
        selected_cases.append({
            'type': 'complex',
            'sample': sample,
            'analysis': f"This case represents a complex attack scenario with {case['num_edges']} edges and paths up to {case['max_path_length']} nodes long. The high complexity tests the ability of RefuteAwareBeamSearch to navigate through many potential paths while maintaining focus on high-value targets."
        })
    
    # Add 2 temporal conflict cases
    for case in temporal_cases[:2]:
        sample = corpus[case['index']]
        selected_cases.append({
            'type': 'temporal_conflict',
            'sample': sample,
            'analysis': f"This case contains {case['temporal_edges']} temporal conflict edges out of {case['total_edges']} total edges. Temporal conflicts represent situations where evidence timestamps are inconsistent, testing the method's ability to detect and penalize temporally invalid paths."
        })
    
    # Add 2 contradicted evidence cases
    for case in contradicted_cases[:2]:
        sample = corpus[case['index']]
        selected_cases.append({
            'type': 'contradicted_evidence',
            'sample': sample,
            'analysis': f"This case has {case['contradicted_edges']} contradicted evidence edges out of {case['total_edges']} total edges. Contradicted evidence represents situations where evidence explicitly refutes a connection, testing the method's ability to avoid paths with strong negative evidence."
        })
    
    # Add 2 insufficient evidence cases
    for case in unknown_cases[:2]:
        sample = corpus[case['index']]
        selected_cases.append({
            'type': 'insufficient_evidence',
            'sample': sample,
            'analysis': f"This case has {case['unknown_edges']} unknown evidence edges out of {case['total_edges']} total edges, with expected state 'Insufficient'. This tests the method's ability to correctly identify paths that lack sufficient evidence to confirm or refute."
        })
    
    # Print detailed analysis
    for i, case in enumerate(selected_cases, 1):
        print(f"\n{'='*70}")
        print(f"CASE STUDY {i}: {case['type'].upper()}")
        print(f"{'='*70}")
        
        sample = case['sample']
        print(f"\nSample ID: {sample.get('sample_id', 'N/A')}")
        print(f"Variant Type: {sample.get('variant_type', 'N/A')}")
        print(f"Expected State: {sample.get('expected_state', 'N/A')}")
        print(f"Scenario Name: {sample.get('scenario_name', 'N/A')}")
        
        nodes = sample.get('nodes', [])
        edges = sample.get('edges', [])
        print(f"\nGraph Statistics:")
        print(f"  Nodes: {len(nodes)}")
        print(f"  Edges: {len(edges)}")
        
        # Node type distribution
        node_types = defaultdict(int)
        for node in nodes:
            node_type = node.get('type', 'unknown')
            node_types[node_type] += 1
        
        print(f"\nNode Type Distribution:")
        for node_type, count in sorted(node_types.items(), key=lambda x: -x[1]):
            print(f"  {node_type}: {count}")
        
        # Edge type distribution
        edge_types = defaultdict(int)
        for edge in edges:
            edge_type = edge.get('type', 'unknown')
            edge_types[edge_type] += 1
        
        print(f"\nEdge Type Distribution:")
        for edge_type, count in sorted(edge_types.items(), key=lambda x: -x[1]):
            print(f"  {edge_type}: {count}")
        
        # Evidence status distribution
        status_counts = defaultdict(int)
        for edge in edges:
            status = edge.get('attrs', {}).get('status', 'unknown')
            status_counts[status] += 1
        
        print(f"\nEvidence Status Distribution:")
        for status, count in sorted(status_counts.items(), key=lambda x: -x[1]):
            print(f"  {status}: {count} ({count/len(edges)*100:.1f}%)")
        
        # Path labels
        path_labels = sample.get('path_labels', [])
        if path_labels:
            print(f"\nPath Labels:")
            for j, pl in enumerate(path_labels[:3], 1):  # Show first 3 paths
                path = pl.get('path', [])
                state = pl.get('state', 'unknown')
                print(f"  Path {j}: {len(path)} nodes, state={state}")
                if len(path) <= 8:
                    print(f"    {' -> '.join(path)}")
                else:
                    print(f"    {' -> '.join(path[:4])} -> ... -> {' -> '.join(path[-2:])}")
        
        print(f"\nAnalysis:")
        print(f"  {case['analysis']}")
    
    # Save results
    output = {
        'summary': {
            'total_samples': len(corpus),
            'variant_distribution': dict(variant_counts),
            'state_distribution': dict(state_counts),
            'path_complexity': {
                'avg_path_length': sum(path_lengths) / len(path_lengths),
                'min_path_length': min(path_lengths),
                'max_path_length': max(path_lengths),
                'avg_edges_per_sample': sum(edge_counts) / len(edge_counts),
            }
        },
        'interesting_cases': {
            'complex': complex_cases[:5],
            'temporal_conflict': temporal_cases[:5],
            'contradicted_evidence': contradicted_cases[:5],
            'insufficient_evidence': unknown_cases[:5],
        },
        'detailed_case_studies': [
            {
                'type': case['type'],
                'sample_id': case['sample'].get('sample_id', 'N/A'),
                'analysis': case['analysis'],
                'graph_stats': {
                    'num_nodes': len(case['sample'].get('nodes', [])),
                    'num_edges': len(case['sample'].get('edges', [])),
                }
            }
            for case in selected_cases
        ]
    }
    
    with open(OUT_FILE, 'w', encoding='utf-8') as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    
    print(f"\n{'='*70}")
    print(f"Case study analysis saved to {OUT_FILE}")
    print(f"{'='*70}")
    
    return output


if __name__ == "__main__":
    analyze_case_studies()
