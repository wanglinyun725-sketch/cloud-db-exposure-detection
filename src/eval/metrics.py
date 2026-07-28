"""Path-level retrieval metrics for exposure path experiments."""
from __future__ import annotations


def path_recall_at_k(predicted_paths: list[list[str]], gold_paths: list[list[str]], k: int) -> float:
    strict = _uses_edge_references(gold_paths)
    gold = {_path_key(path, strict) for path in gold_paths if path}
    if not gold:
        return 0.0
    pred = {_path_key(path, strict) for path in predicted_paths[:k] if path}
    return len(gold & pred) / len(gold)


def path_precision_at_k(predicted_paths: list[list[str]], gold_paths: list[list[str]], k: int) -> float:
    if k <= 0:
        return 0.0
    strict = _uses_edge_references(gold_paths)
    gold = {_path_key(path, strict) for path in gold_paths if path}
    pred = [_path_key(path, strict) for path in predicted_paths[:k] if path]
    if not pred:
        return 0.0
    return sum(1 for path in pred if path in gold) / min(k, len(predicted_paths))


def exact_match(predicted_paths: list[list[str]], gold_paths: list[list[str]]) -> float:
    return path_recall_at_k(predicted_paths, gold_paths, len(predicted_paths))


def mrr(predicted_paths: list[list[str]], gold_paths: list[list[str]]) -> float:
    strict = _uses_edge_references(gold_paths)
    gold = {_path_key(path, strict) for path in gold_paths if path}
    if not gold:
        return 0.0
    for idx, path in enumerate(predicted_paths, start=1):
        if _path_key(path, strict) in gold:
            return 1 / idx
    return 0.0


def target_recall_at_k(predicted_paths: list[list[str]], gold_paths: list[list[str]], k: int) -> float:
    gold_targets = {path[-1] for path in gold_paths if path}
    if not gold_targets:
        return 0.0
    pred_targets = {path[-1] for path in predicted_paths[:k] if path}
    return len(gold_targets & pred_targets) / len(gold_targets)


def summarize_path_ranking(predicted_paths: list[list[str]], gold_paths: list[list[str]], ks=(1, 3, 5)) -> dict:
    out = {
        "mrr": round(mrr(predicted_paths, gold_paths), 4),
        "exact_match": round(exact_match(predicted_paths, gold_paths), 4),
    }
    for k in ks:
        out[f"recall@{k}"] = round(path_recall_at_k(predicted_paths, gold_paths, k), 4)
        out[f"precision@{k}"] = round(path_precision_at_k(predicted_paths, gold_paths, k), 4)
        out[f"target_recall@{k}"] = round(target_recall_at_k(predicted_paths, gold_paths, k), 4)
    return out


def _uses_edge_references(paths) -> bool:
    return any(
        getattr(path, "edge_ids", None) or getattr(path, "edge_types", None)
        for path in paths
        if path
    )


def _path_key(path: list[str], strict: bool = False) -> tuple:
    nodes = tuple(path)
    if strict:
        edge_ids = tuple(getattr(path, "edge_ids", ()) or ())
        edge_types = tuple(getattr(path, "edge_types", ()) or ())
        if edge_ids:
            return ("edges", nodes, edge_ids)
        if edge_types:
            return ("types", nodes, edge_types)
        # A node-only prediction cannot equal an edge-annotated gold path.
        return ("legacy", nodes)
    return ("nodes", nodes)
