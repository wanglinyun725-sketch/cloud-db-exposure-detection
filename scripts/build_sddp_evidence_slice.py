#!/usr/bin/env python3
"""Build CloudDB semantic evidence slices from exported SDDP/DSC evidence.

Inputs are local JSON exports, not live credentials:
- data_instance_source.json
- sys_data_limit.json
- dsc_identify_task_asset.json (optional)
- data_objects.json from DescribeDataObjects or normalized Items
- sls_results.json (optional)
"""
import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))
CONTROLLED_TIME = "2026-01-01T00:00:00Z"

from src.graph.evidence_semantics import evidence_field_stats, semanticize_sample
from src.graph.constrained_search import REQUIRED_EDGE_TYPES, VALID_EDGE_TRANSITIONS
from src.graph.path_utils import annotate_path_labels


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-dir", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--slice-id", default="sddp_real_slice_001")
    parser.add_argument("--variant", choices=["controlled_exposure", "controlled_missing", "controlled_refuted", "base"], default="base")
    parser.add_argument("--write-example", action="store_true")
    args = parser.parse_args()

    input_dir = Path(args.input_dir)
    if args.write_example:
        _write_example(input_dir)

    sample = build_slice(input_dir, args.slice_id, args.variant)
    sample = semanticize_sample(sample)
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output).write_text(json.dumps(sample, ensure_ascii=False, indent=2), encoding="utf-8")
    stats_path = str(Path(args.output).with_suffix("")) + "_stats.json"
    Path(stats_path).write_text(json.dumps(evidence_field_stats([sample]), ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"wrote {args.output}")
    print(f"wrote {stats_path}")
    print(json.dumps({
        "sample_id": sample["sample_id"],
        "nodes": len(sample["nodes"]),
        "edges": len(sample["edges"]),
        "expected_type": sample["expected_type"],
        "sample_label": sample["sample_label"],
        "path_labels": len(sample.get("path_labels", [])),
    }, ensure_ascii=False, indent=2))


def build_slice(input_dir: Path, slice_id: str, variant: str = "base") -> dict:
    instances = _load_list(input_dir / "data_instance_source.json")
    limits = _load_list(input_dir / "sys_data_limit.json")
    tasks = _load_list(input_dir / "dsc_identify_task_asset.json", optional=True)
    objects = _load_items(input_dir / "data_objects.json")
    sls = _load_list(input_dir / "sls_results.json", optional=True)

    nodes = {}
    edges = []
    scanner = "identity_sddp_scanner"
    nodes[scanner] = _node(scanner, "Identity", {"kind": "scanner", "is_external": True, "name": "SDDP Scanner / Connector"})

    instance_by_key = {}
    for inst in instances:
        iid = str(inst.get("instance_id") or inst.get("InstanceId") or inst.get("name") or inst.get("Name"))
        if not iid or iid == "None":
            continue
        engine = str(inst.get("engine") or inst.get("Engine") or inst.get("engine_type") or inst.get("EngineType") or "unknown")
        node_id = _safe_id(f"dbinst_{iid}_{engine}")
        instance_by_key[iid] = node_id
        nodes[node_id] = _node(node_id, "DBInstance", {
            "name": iid,
            "engine": engine,
            "region": inst.get("region") or inst.get("RegionId") or inst.get("service_region_id"),
            "resource_name": inst.get("resource_name") or inst.get("ResourceName"),
            "auth_status": inst.get("auth_status") or inst.get("AuthStatus"),
        })
        edges.append(_edge(scanner, node_id, "owns", "Supported", "data_instance_source", 1.0, 1, f"data_instance_source:{iid}"))

    for limit in limits:
        iid = _extract_instance_id(limit)
        if not iid or iid not in instance_by_key:
            continue
        inst_node = instance_by_key[iid]
        status = _connect_status(limit.get("check_status", limit.get("CheckStatus")))
        strength = 1.0 if status == "Supported" else 0.0
        edges.append(_edge(scanner, inst_node, "can_connect", status, "sys_data_limit", strength, 1, f"sys_data_limit:{limit.get('id', limit.get('Id', iid))}"))
        parent = limit.get("parent_id") or limit.get("ParentId")
        if parent:
            nodes[inst_node]["attrs"]["parent_id"] = parent

    for task in tasks:
        did = str(task.get("sys_data_limit_id") or task.get("SysDataLimitId") or task.get("data_limit_id") or "")
        task_id = str(task.get("dsc_task_id") or task.get("DscTaskId") or task.get("task_id") or "")
        if task_id:
            audit_id = _safe_id(f"audit_task_{task_id}")
            nodes[audit_id] = _node(audit_id, "AuditEvent", {"action": "identify_task_bound", "success": True, "t": task.get("gmt_modified") or task.get("GmtModified")})
            for inst_node in instance_by_key.values():
                edges.append(_edge(audit_id, inst_node, "triggered", "Supported", "dsc_identify_task_asset", 0.8, 2, f"task:{task_id}:limit:{did}"))
                break

    object_paths = []
    for obj in objects:
        inst_key = str(obj.get("InstanceId") or obj.get("instance_id") or obj.get("InstanceName") or obj.get("instance_name") or "")
        inst_node = _find_instance_node(instance_by_key, inst_key) or next(iter(instance_by_key.values()), None)
        if not inst_node:
            continue
        db = str(obj.get("DbName") or obj.get("data_base_name") or obj.get("DatabaseName") or "default")
        table = str(obj.get("TableName") or obj.get("table_name") or obj.get("ObjectName") or "table")
        column = str(obj.get("ColumnName") or obj.get("column_name") or obj.get("Name") or "column")
        db_node = _safe_id(f"db_{inst_node}_{db}")
        tbl_node = _safe_id(f"tbl_{inst_node}_{db}_{table}")
        col_node = _safe_id(f"col_{inst_node}_{db}_{table}_{column}")
        nodes.setdefault(db_node, _node(db_node, "DBObject", {"kind": "db", "name": db}))
        nodes.setdefault(tbl_node, _node(tbl_node, "DBObject", {"kind": "table", "name": table, "parent": db_node}))
        nodes.setdefault(col_node, _node(col_node, "DBObject", {"kind": "field", "name": column, "parent": tbl_node}))
        object_time = (
            obj.get("LastScanTime")
            or obj.get("last_scan_time")
            or obj.get("GmtModified")
            or obj.get("gmt_modified")
        )
        edges.extend([
            _edge(inst_node, db_node, "contains", "Supported", "DescribeDataObjects", 1.0, 1, f"db:{db}", object_time),
            _edge(db_node, tbl_node, "contains", "Supported", "DescribeDataObjects", 1.0, 1, f"table:{table}", object_time),
            _edge(tbl_node, col_node, "contains", "Supported", "DescribeDataObjects", 1.0, 1, f"column:{column}", object_time),
        ])
        rule_names = _rule_names(obj)
        if rule_names:
            tag_node = _safe_id(f"tag_{rule_names[0]}_{column}")
            nodes.setdefault(tag_node, _node(tag_node, "SensitiveTag", {"category": rule_names[0], "level": _level(obj), "confidence": 0.95}))
            edges.append(_edge(
                col_node,
                tag_node,
                "classified_as",
                "Supported",
                "DescribeDataObjects",
                0.95,
                1,
                f"rule:{','.join(rule_names)}",
                object_time,
            ))
            object_paths.append([scanner, inst_node, db_node, tbl_node, col_node, tag_node])

    for idx, row in enumerate(sls):
        audit_id = _safe_id(f"audit_sls_{idx}_{row.get('scan_time', row.get('time', 't'))}")
        nodes[audit_id] = _node(audit_id, "AuditEvent", {"action": "sensitive_detect", "success": True, "t": row.get("scan_time") or row.get("time")})

    path_labels = [{"path": path, "state": "Valid", "expected_type": "Potential_Exposure", "variant_type": "sddp_real_slice", "label_scope": "controlled_evidence_path"} for path in object_paths]

    # Apply variant-specific controlled threat injection
    if variant != "base" and path_labels:
        inst_node = path_labels[0]["path"][1]  # DBInstance node
        internet_id = "internet_attacker"
        principal_id = "identity_controlled_external"
        nodes[internet_id] = _node(internet_id, "Network", {
            "kind": "eip",
            "public_exposed": True,
            "cidr": "0.0.0.0/0",
            "name": "Controlled Public Internet",
        })
        nodes[principal_id] = _node(principal_id, "Identity", {
            "kind": "controlled_principal",
            "is_external": True,
            "name": "Controlled External Principal",
        })
        edges.insert(0, _edge(
            principal_id,
            inst_node,
            "has_permission",
            "Supported",
            "controlled_injection",
            1.0,
            1,
            "controlled:temporary_db_permission",
            CONTROLLED_TIME,
        ))
        edges.insert(0, _edge(
            internet_id,
            principal_id,
            "can_connect",
            "Supported",
            "controlled_injection",
            1.0,
            1,
            "controlled:public_connectivity",
            CONTROLLED_TIME,
        ))
        for pl in path_labels:
            pl["path"] = [internet_id, principal_id, *pl["path"][1:]]

        if variant == "controlled_exposure":
            for pl in path_labels:
                pl["variant_type"] = "controlled_exposure"
                pl["expected_type"] = "Observed_Risk"
            sample_label = "Valid"
            expected_state = "Valid"
            expected_type = "Observed_Risk"
            has_attack_trace = True
        elif variant == "controlled_missing":
            for e in edges:
                if e["source"] == internet_id and e["type"] == "can_connect":
                    e["attrs"]["status"] = "Unknown"
                    e["attrs"]["strength"] = 0.0
                    e["attrs"]["source"] = "controlled_injection"
                    e["attrs"]["evidence_ref"] = "controlled:missing_connectivity"
            for pl in path_labels:
                pl["state"] = "Insufficient"
                pl["variant_type"] = "controlled_missing"
                pl["expected_type"] = "Insufficient_Evidence"
            sample_label = "Insufficient"
            expected_state = "Insufficient"
            expected_type = "Insufficient_Evidence"
            has_attack_trace = False
        elif variant == "controlled_refuted":
            for e in edges:
                if e["source"] == internet_id and e["type"] == "can_connect":
                    e["attrs"]["status"] = "Contradicted"
                    e["attrs"]["strength"] = 0.0
                    e["attrs"]["source"] = "controlled_injection"
                    e["attrs"]["evidence_ref"] = "controlled:refuted_connectivity"
            for pl in path_labels:
                pl["state"] = "Invalid"
                pl["variant_type"] = "controlled_refuted"
                pl["expected_type"] = "Refuted"
            sample_label = "Invalid"
            expected_state = "Invalid"
            expected_type = "Refuted"
            has_attack_trace = False
        else:
            sample_label = "Valid" if path_labels else "Insufficient"
            expected_state = "Valid" if path_labels else "Insufficient"
            expected_type = "Potential_Exposure" if path_labels else "Insufficient_Evidence"
            has_attack_trace = False
    else:
        # Connector ownership/scanning is ingestion evidence, not an exposure.
        path_labels = []
        sample_label = "Insufficient"
        expected_state = "Insufficient"
        expected_type = "Insufficient_Evidence"
        has_attack_trace = False

    sample = {
        "sample_id": slice_id,
        "scenario": "SDDP-REAL-SLICE",
        "scenario_name": f"SDDP真实资产与敏感识别证据切片（{variant}）",
        "industry": "real_sddp",
        "raw_dataset": "sddp_export",
        "variant_type": variant,
        "expected_type": expected_type,
        "expected_state": expected_state,
        "sample_label": sample_label,
        "has_attack_trace": has_attack_trace,
        "notes": "This slice uses real SDDP/DSC evidence semantics with controlled threat injection. It does not claim a real intrusion trajectory.",
        "nodes": list(nodes.values()),
        "edges": edges,
        "gold_paths": [p["path"] for p in path_labels],
        "path_labels": path_labels,
    }
    return annotate_path_labels(
        sample,
        VALID_EDGE_TRANSITIONS,
        REQUIRED_EDGE_TYPES,
    )


def _write_example(input_dir: Path):
    input_dir.mkdir(parents=True, exist_ok=True)
    (input_dir / "data_instance_source.json").write_text(json.dumps([
        {"instance_id": "ld-demo-001", "engine": "LCOLUMN", "region": "cn-zhangjiakou", "resource_name": "demo_lindorm", "auth_status": "authorized"}
    ], ensure_ascii=False, indent=2), encoding="utf-8")
    (input_dir / "sys_data_limit.json").write_text(json.dumps([
        {"id": 1001, "parent_id": "ld-demo-001.LCOLUMN.default", "engine_type": "LCOLUMN", "check_status": 3}
    ], ensure_ascii=False, indent=2), encoding="utf-8")
    (input_dir / "dsc_identify_task_asset.json").write_text(json.dumps([
        {"sys_data_limit_id": 1001, "dsc_task_id": 741610, "scan_type": "manual", "gmt_modified": "2026-01-01T00:00:00Z"}
    ], ensure_ascii=False, indent=2), encoding="utf-8")
    (input_dir / "data_objects.json").write_text(json.dumps({"Items": [
        {"InstanceId": "ld-demo-001", "EngineType": "LCOLUMN", "DbName": "default", "TableName": "customer_profile", "ColumnName": "id_card", "RuleList": [{"Name": "身份证号", "RiskLevel": 4}], "LastScanTime": "2026-01-01T00:10:00Z"}
    ]}, ensure_ascii=False, indent=2), encoding="utf-8")
    (input_dir / "sls_results.json").write_text(json.dumps([
        {"instance_type": "Lindorm", "engine_type": "LCOLUMN", "data_base_name": "default", "table_name": "customer_profile", "column_name": "id_card", "rule_name": "身份证号", "is_sensitive": True, "scan_time": "2026-01-01T00:10:00Z"}
    ], ensure_ascii=False, indent=2), encoding="utf-8")


def _load_list(path: Path, optional=False):
    if not path.exists():
        if optional:
            return []
        raise SystemExit(f"missing input file: {path}")
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        return data.get("Items") or data.get("items") or data.get("data") or [data]
    return []


def _load_items(path: Path):
    data = _load_list(path)
    if len(data) == 1 and isinstance(data[0], dict) and isinstance(data[0].get("Items"), list):
        return data[0]["Items"]
    return data


def _node(node_id, node_type, attrs):
    return {"id": node_id, "type": node_type, "attrs": {k: v for k, v in attrs.items() if v is not None}}


def _edge(
    source,
    target,
    edge_type,
    status,
    source_kind,
    confidence,
    query_cost,
    evidence_ref,
    observed_at=None,
):
    return {"source": source, "target": target, "type": edge_type, "attrs": {
        "status": status,
        "source": source_kind,
        "strength": confidence,
        "confidence": confidence,
        "query_cost": query_cost,
        "evidence_ref": evidence_ref,
        "raw_evidence": evidence_ref,
        "time": observed_at,
    }}


def _connect_status(value):
    value = str(value)
    if value == "3":
        return "Supported"
    if value == "4":
        return "Contradicted"
    return "Unknown"


def _extract_instance_id(limit):
    parent = str(limit.get("parent_id") or limit.get("ParentId") or "")
    if parent:
        return parent.split(".")[0]
    return str(limit.get("instance_id") or limit.get("InstanceId") or "")


def _find_instance_node(instance_by_key, inst_key):
    if inst_key in instance_by_key:
        return instance_by_key[inst_key]
    for key, node in instance_by_key.items():
        if key and key in inst_key:
            return node
    return None


def _rule_names(obj):
    rules = obj.get("RuleList") or obj.get("rule_list") or obj.get("Rules") or []
    if isinstance(rules, str):
        return [rules]
    names = []
    for rule in rules:
        if isinstance(rule, dict):
            name = rule.get("Name") or rule.get("RuleName") or rule.get("name")
            if name:
                names.append(str(name))
    if obj.get("rule_name"):
        names.append(str(obj["rule_name"]))
    return names


def _level(obj):
    for key in ["RiskLevel", "risk_level", "Level", "level"]:
        if obj.get(key) is not None:
            try:
                return max(1, min(4, int(obj[key])))
            except ValueError:
                pass
    return 4


def _safe_id(value):
    return "".join(ch if ch.isalnum() or ch in "_-" else "_" for ch in str(value))[:180]


if __name__ == "__main__":
    main()
