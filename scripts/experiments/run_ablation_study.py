#!/usr/bin/env python3
"""Ablation study for RefuteAwareBeamSearch components."""
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(ROOT))

from src.graph.graph_builder import build_graph
from src.graph.gate_score import verify_path
from src.graph.refute_aware_search import refute_aware_beam_search
from src.graph.path_utils import path_from_label, path_query_cost
from src.eval.metrics import path_recall_at_k, mrr

CORPUS = ROOT / "output" / "semantic_corpus" / "cloud_db_semantic_corpus.json"
OUT = ROOT / "output" / "semantic_corpus" / "ablation_study_results.json"


def load_corpus():
    return json.loads(CORPUS.read_text(encoding="utf-8"))


def run_ablation_variant(samples, variant_name, beam_width=4, use_temporal=True, use_query_cost=True, use_refute_scoring=True):
    """Run a single ablation variant and collect metrics."""
    results = {
        "variant": variant_name,
        "gold_definition": "path_labels where state == Valid",
        "beam_width": beam_width,
        "use_temporal": use_temporal,
        "use_query_cost": use_query_cost,
        "use_refute_scoring": use_refute_scoring,
        "n_samples": 0,
        "recall_at_1": 0.0,
        "recall_at_3": 0.0,
        "recall_at_5": 0.0,
        "mrr": 0.0,
        "avg_expanded_edges": 0.0,
        "avg_generated_paths": 0.0,
        "avg_completed_paths": 0.0,
        "avg_top_query_cost": 0.0,
        "time_s": 0.0,
        "valid_count": 0,
        "insufficient_count": 0,
        "invalid_count": 0,
    }
    
    total_expanded = 0
    total_generated = 0
    total_completed = 0
    total_query_cost = 0
    n_eval = 0
    recall_1_sum = 0
    recall_3_sum = 0
    recall_5_sum = 0
    mrr_sum = 0
    
    start_time = time.time()
    
    for sample in samples:
        gold_paths = [
            path_from_label(pl)
            for pl in sample.get("path_labels", [])
            if pl.get("state") == "Valid" and pl.get("path")
        ]
        if not gold_paths:
            continue
        G = build_graph(sample)
        entries = [n["id"] for n in sample["nodes"] if n.get("attrs", {}).get("public_exposed") or n.get("attrs", {}).get("is_external")]
        targets = [n["id"] for n in sample["nodes"] if n["type"] == "SensitiveTag"]
        
        if not entries or not targets:
            continue
        n_eval += 1
        
        # Run search with variant configuration
        search_results = refute_aware_beam_search(
            G, entries, targets,
            beam_width=beam_width,
            use_temporal=use_temporal,
            use_query_cost=use_query_cost,
            use_refute_scoring=use_refute_scoring
        )
        
        paths = search_results.get("paths", [])
        total_expanded += search_results.get("expanded_edges", 0)
        total_generated += search_results.get("generated_paths", 0)
        total_completed += search_results.get("completed_paths", 0)
        
        # Calculate metrics
        if paths:
            recall_1_sum += path_recall_at_k(paths, gold_paths, k=1)
            recall_3_sum += path_recall_at_k(paths, gold_paths, k=3)
            recall_5_sum += path_recall_at_k(paths, gold_paths, k=5)
            mrr_sum += mrr(paths, gold_paths)
            
            # Query cost for top path
            if paths:
                top_path = paths[0]
                total_query_cost += path_query_cost(G, top_path)
            
            # Count verification states
            for path in paths[:5]:
                verification = verify_path(G, path)
                state = verification.get("state")
                if state == "Valid":
                    results["valid_count"] += 1
                elif state == "Insufficient":
                    results["insufficient_count"] += 1
                elif state == "Invalid":
                    results["invalid_count"] += 1
    
    elapsed = time.time() - start_time
    
    if n_eval > 0:
        results["n_samples"] = n_eval
        results["recall_at_1"] = round(recall_1_sum / n_eval, 4)
        results["recall_at_3"] = round(recall_3_sum / n_eval, 4)
        results["recall_at_5"] = round(recall_5_sum / n_eval, 4)
        results["mrr"] = round(mrr_sum / n_eval, 4)
        results["avg_expanded_edges"] = round(total_expanded / n_eval, 3)
        results["avg_generated_paths"] = round(total_generated / n_eval, 3)
        results["avg_completed_paths"] = round(total_completed / n_eval, 3)
        results["avg_top_query_cost"] = round(total_query_cost / n_eval, 3)
        results["time_s"] = round(elapsed, 3)
    
    return results


def main():
    print("Loading corpus...")
    samples = load_corpus()
    print(f"Loaded {len(samples)} samples")
    
    ablation_variants = [
        # Baseline: full RefuteAwareBeamSearch
        ("full_refute_aware_beam", 4, True, True, True),
        
        # Beam width ablation
        ("beam_width_2", 2, True, True, True),
        ("beam_width_8", 8, True, True, True),
        ("beam_width_16", 16, True, True, True),
        
        # Component ablation
        ("no_temporal", 4, False, True, True),
        ("no_query_cost", 4, True, False, True),
        ("no_refute_scoring", 4, True, True, False),
        ("no_temporal_no_query_cost", 4, False, False, True),
    ]
    
    results = []
    for variant_name, beam_width, use_temporal, use_query_cost, use_refute_scoring in ablation_variants:
        print(f"\nRunning ablation: {variant_name}")
        print(f"  beam_width={beam_width}, temporal={use_temporal}, query_cost={use_query_cost}, refute_scoring={use_refute_scoring}")
        
        result = run_ablation_variant(
            samples, variant_name,
            beam_width=beam_width,
            use_temporal=use_temporal,
            use_query_cost=use_query_cost,
            use_refute_scoring=use_refute_scoring
        )
        results.append(result)
        
        print(f"  R@1={result['recall_at_1']}, R@3={result['recall_at_3']}, R@5={result['recall_at_5']}, MRR={result['mrr']}")
        print(f"  Expanded: {result['avg_expanded_edges']}, Generated: {result['avg_generated_paths']}, Completed: {result['avg_completed_paths']}")
        print(f"  Time: {result['time_s']}s")
    
    output = {
        "dataset": CORPUS.relative_to(ROOT).as_posix(),
        "n_samples": len(samples),
        "ablation_variants": results
    }
    
    OUT.write_text(json.dumps(output, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\nWrote ablation results to {OUT}")
    
    # Print summary table
    print("\n" + "="*100)
    print("ABLATION STUDY SUMMARY")
    print("="*100)
    print(f"{'Variant':<30} {'R@1':>6} {'R@3':>6} {'R@5':>6} {'MRR':>6} {'Expanded':>10} {'Time(s)':>8}")
    print("-"*100)
    for r in results:
        print(f"{r['variant']:<30} {r['recall_at_1']:>6.4f} {r['recall_at_3']:>6.4f} {r['recall_at_5']:>6.4f} {r['mrr']:>6.4f} {r['avg_expanded_edges']:>10.3f} {r['time_s']:>8.3f}")
    print("="*100)


if __name__ == "__main__":
    main()
