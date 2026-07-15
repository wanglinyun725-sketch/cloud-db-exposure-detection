"""
CloudDB-PathBench 数据生成器
─────────────────────────────
从 schema_pool 采样，基于 6 类场景模板生成 CDB-RG 图样本。
每个样本自动计算 gold_paths 和 expected_type。

使用: python -m src.data_gen.generator --count 60 --output data/pathbench_60.json
"""
import json
import random
import copy
import argparse
from pathlib import Path
from typing import List, Dict, Tuple

ROOT = Path(__file__).parent.parent.parent
SCHEMA_PATH = ROOT / "data" / "schema_pool" / "schema_pool.json"

# ─── 加载 schema pool ───
with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
    SCHEMA_POOL = json.load(f)

INDUSTRIES = list(SCHEMA_POOL.keys())  # ["finance", "medical", "ecommerce"]
ENGINES = [
    {"engine": "MySQL", "port": 3306},
    {"engine": "PostgreSQL", "port": 5432},
    {"engine": "SQLServer", "port": 1433},
]
REGIONS = ["cn-hangzhou", "cn-shanghai", "cn-beijing", "cn-shenzhen", "cn-chengdu"]


def _pick_table(industry: str) -> dict:
    """从 schema_pool 中随机选一张表"""
    tables = SCHEMA_POOL[industry]
    return random.choice(tables)


def _pick_sensitive_fields(table: dict, min_level: int = 4) -> list:
    """选取高敏字段 (level >= min_level)，确保 level*confidence >= 3.0"""
    return [f for f in table["fields"] if int(f["level"].replace("L", "")) >= min_level]


def _level_to_int(level_str: str) -> int:
    return int(level_str.replace("L", ""))


def _gen_id(prefix: str, idx: int) -> str:
    return f"{prefix}_{idx:03d}"


# ════════════════════════════════════════════════
# 6 类场景模板
# ════════════════════════════════════════════════

def tpl_public_exposure(idx: int, industry: str, is_negative: bool = False) -> dict:
    """S1: 公网暴露 + 高敏数据未保护"""
    table = _pick_table(industry)
    sensitive = _pick_sensitive_fields(table)
    if not sensitive:
        sensitive = [{"name": "id_card", "type": "VARCHAR", "level": "L4"}]
    field = random.choice(sensitive)
    eng = random.choice(ENGINES)
    sid = _gen_id(f"S1_{industry}", idx)

    # 网络强度: 正例高，负例低于gate阈值
    sg_strength = random.uniform(0.85, 1.0) if not is_negative else random.uniform(0.05, 0.15)
    net_strength = random.uniform(0.8, 0.99)
    perm_strength = random.uniform(0.7, 0.95)
    field_level = _level_to_int(field["level"])
    confidence = round(random.uniform(0.85, 0.99), 2)

    nodes = [
        {"id": "internet", "type": "Network", "attrs": {"kind": "eip", "public_exposed": True, "cidr": "0.0.0.0/0"}},
        {"id": f"sg_{sid}", "type": "Network", "attrs": {"kind": "sg", "public_exposed": not is_negative, "cidr": "0.0.0.0/0", "port": eng["port"]}},
        {"id": f"rds_{sid}", "type": "DBInstance", "attrs": {"engine": eng["engine"], "version": "8.0", "port": eng["port"], "encrypted": is_negative, "audit_on": is_negative, "region": random.choice(REGIONS)}},
        {"id": f"db_{sid}", "type": "DBObject", "attrs": {"kind": "db", "name": table["table"]}},
        {"id": f"tbl_{sid}", "type": "DBObject", "attrs": {"kind": "table", "name": table["table"], "parent": f"db_{sid}"}},
        {"id": f"fld_{sid}", "type": "DBObject", "attrs": {"kind": "field", "name": field["name"], "parent": f"tbl_{sid}"}},
        {"id": f"tag_{sid}", "type": "SensitiveTag", "attrs": {"category": field["name"], "level": field_level, "confidence": confidence}},
        {"id": f"user_{sid}", "type": "Identity", "attrs": {"kind": "user", "is_external": False, "mfa": False, "name": f"user_{sid}"}},
        {"id": f"ctrl_tde_{sid}", "type": "Control", "attrs": {"kind": "TDE", "enabled": is_negative, "scope": f"rds_{sid}"}},
        {"id": f"ctrl_audit_{sid}", "type": "Control", "attrs": {"kind": "Audit", "enabled": is_negative, "scope": f"rds_{sid}"}},
    ]
    edges = [
        {"source": "internet", "target": f"sg_{sid}", "type": "can_connect", "attrs": {"strength": round(sg_strength, 2), "evidence_ref": f"ev_sg_{sid}"}},
        {"source": f"sg_{sid}", "target": f"rds_{sid}", "type": "can_connect", "attrs": {"strength": round(net_strength, 2), "evidence_ref": f"ev_net_{sid}"}},
        {"source": f"rds_{sid}", "target": f"user_{sid}", "type": "owns", "attrs": {"strength": 1.0, "evidence_ref": f"ev_owns_{sid}"}},
        {"source": f"user_{sid}", "target": f"tbl_{sid}", "type": "has_permission", "attrs": {"strength": round(perm_strength, 2), "evidence_ref": f"ev_perm_{sid}", "privilege": "SELECT"}},
        {"source": f"rds_{sid}", "target": f"db_{sid}", "type": "contains", "attrs": {"strength": 1.0, "evidence_ref": f"ev_c1_{sid}"}},
        {"source": f"db_{sid}", "target": f"tbl_{sid}", "type": "contains", "attrs": {"strength": 1.0, "evidence_ref": f"ev_c2_{sid}"}},
        {"source": f"tbl_{sid}", "target": f"fld_{sid}", "type": "contains", "attrs": {"strength": 1.0, "evidence_ref": f"ev_c3_{sid}"}},
        {"source": f"fld_{sid}", "target": f"tag_{sid}", "type": "classified_as", "attrs": {"strength": confidence, "evidence_ref": f"ev_dlp_{sid}"}},
        {"source": f"rds_{sid}", "target": f"ctrl_tde_{sid}", "type": "protected_by", "attrs": {"strength": 1.0, "evidence_ref": f"ev_ctrl1_{sid}"}},
        {"source": f"rds_{sid}", "target": f"ctrl_audit_{sid}", "type": "protected_by", "attrs": {"strength": 1.0, "evidence_ref": f"ev_ctrl2_{sid}"}},
    ]
    gold = ["internet", f"sg_{sid}", f"rds_{sid}", f"db_{sid}", f"tbl_{sid}", f"fld_{sid}", f"tag_{sid}"]
    expected = "Insufficient_Evidence" if is_negative else "Observed_Risk"
    return _make_sample(sid, "S1", "公网暴露+高敏数据未保护", industry, nodes, edges, [gold], expected)


def tpl_excess_privilege(idx: int, industry: str, is_negative: bool = False) -> dict:
    """S2: 低权限账号权限过宽"""
    table = _pick_table(industry)
    sensitive = _pick_sensitive_fields(table)
    if not sensitive:
        sensitive = [{"name": "bank_card", "type": "VARCHAR", "level": "L4"}]
    field = random.choice(sensitive)
    eng = random.choice(ENGINES)
    sid = _gen_id(f"S2_{industry}", idx)

    sg_strength = random.uniform(0.55, 0.75)
    net_strength = random.uniform(0.72, 0.88)
    assume_strength = random.uniform(0.8, 0.95)
    perm_strength = random.uniform(0.65, 0.85) if not is_negative else random.uniform(0.1, 0.3)
    field_level = _level_to_int(field["level"])
    confidence = round(random.uniform(0.85, 0.99), 2)

    nodes = [
        {"id": "internet", "type": "Network", "attrs": {"kind": "eip", "public_exposed": True, "cidr": "0.0.0.0/0"}},
        {"id": f"sg_{sid}", "type": "Network", "attrs": {"kind": "sg", "public_exposed": False, "cidr": "10.0.0.0/8", "port": eng["port"]}},
        {"id": f"user_{sid}", "type": "Identity", "attrs": {"kind": "user", "is_external": False, "mfa": False, "name": f"intern_{sid}"}},
        {"id": f"role_{sid}", "type": "Identity", "attrs": {"kind": "role", "is_external": False, "name": f"analyst_{sid}"}},
        {"id": f"rds_{sid}", "type": "DBInstance", "attrs": {"engine": eng["engine"], "version": "8.0", "port": eng["port"], "encrypted": True, "audit_on": True, "region": random.choice(REGIONS)}},
        {"id": f"db_{sid}", "type": "DBObject", "attrs": {"kind": "db", "name": table["table"]}},
        {"id": f"tbl_{sid}", "type": "DBObject", "attrs": {"kind": "table", "name": table["table"], "parent": f"db_{sid}"}},
        {"id": f"fld_{sid}", "type": "DBObject", "attrs": {"kind": "field", "name": field["name"], "parent": f"tbl_{sid}"}},
        {"id": f"tag_{sid}", "type": "SensitiveTag", "attrs": {"category": field["name"], "level": field_level, "confidence": confidence}},
        {"id": f"ctrl_tde_{sid}", "type": "Control", "attrs": {"kind": "TDE", "enabled": True, "scope": f"rds_{sid}"}},
    ]
    edges = [
        {"source": "internet", "target": f"sg_{sid}", "type": "can_connect", "attrs": {"strength": round(sg_strength, 2), "evidence_ref": f"ev_sg_{sid}"}},
        {"source": f"sg_{sid}", "target": f"rds_{sid}", "type": "can_connect", "attrs": {"strength": round(net_strength, 2), "evidence_ref": f"ev_net_{sid}"}},
        {"source": f"rds_{sid}", "target": f"user_{sid}", "type": "owns", "attrs": {"strength": 1.0, "evidence_ref": f"ev_owns_{sid}"}},
        {"source": f"user_{sid}", "target": f"role_{sid}", "type": "can_assume", "attrs": {"strength": round(assume_strength, 2), "evidence_ref": f"ev_assume_{sid}"}},
        {"source": f"role_{sid}", "target": f"tbl_{sid}", "type": "has_permission", "attrs": {"strength": round(perm_strength, 2), "evidence_ref": f"ev_perm_{sid}", "privilege": "SELECT *.*"}},
        {"source": f"rds_{sid}", "target": f"db_{sid}", "type": "contains", "attrs": {"strength": 1.0, "evidence_ref": f"ev_c1_{sid}"}},
        {"source": f"db_{sid}", "target": f"tbl_{sid}", "type": "contains", "attrs": {"strength": 1.0, "evidence_ref": f"ev_c2_{sid}"}},
        {"source": f"tbl_{sid}", "target": f"fld_{sid}", "type": "contains", "attrs": {"strength": 1.0, "evidence_ref": f"ev_c3_{sid}"}},
        {"source": f"fld_{sid}", "target": f"tag_{sid}", "type": "classified_as", "attrs": {"strength": confidence, "evidence_ref": f"ev_dlp_{sid}"}},
        {"source": f"rds_{sid}", "target": f"ctrl_tde_{sid}", "type": "protected_by", "attrs": {"strength": 1.0, "evidence_ref": f"ev_ctrl_{sid}"}},
    ]
    gold = ["internet", f"sg_{sid}", f"rds_{sid}", f"user_{sid}", f"role_{sid}", f"tbl_{sid}", f"fld_{sid}", f"tag_{sid}"]
    expected = "Insufficient_Evidence" if is_negative else "Potential_Exposure"
    return _make_sample(sid, "S2", "低权限账号权限过宽", industry, nodes, edges, [gold], expected)


def tpl_abnormal_access(idx: int, industry: str, is_negative: bool = False) -> dict:
    """S3: 异常IP/夜间访问+批量查询"""
    table = _pick_table(industry)
    sensitive = _pick_sensitive_fields(table)
    if not sensitive:
        sensitive = [{"name": "id_card", "type": "VARCHAR", "level": "L4"}]
    field = random.choice(sensitive)
    eng = random.choice(ENGINES)
    sid = _gen_id(f"S3_{industry}", idx)
    field_level = _level_to_int(field["level"])
    confidence = round(random.uniform(0.85, 0.99), 2)
    anomaly = round(random.uniform(0.75, 0.98), 2) if not is_negative else round(random.uniform(0.1, 0.4), 2)

    nodes = [
        {"id": "internet", "type": "Network", "attrs": {"kind": "eip", "public_exposed": True, "cidr": "0.0.0.0/0"}},
        {"id": f"sg_{sid}", "type": "Network", "attrs": {"kind": "sg", "public_exposed": True, "cidr": "0.0.0.0/0", "port": eng["port"]}},
        {"id": f"rds_{sid}", "type": "DBInstance", "attrs": {"engine": eng["engine"], "version": "14", "port": eng["port"], "encrypted": False, "audit_on": True, "region": random.choice(REGIONS)}},
        {"id": f"db_{sid}", "type": "DBObject", "attrs": {"kind": "db", "name": table["table"]}},
        {"id": f"tbl_{sid}", "type": "DBObject", "attrs": {"kind": "table", "name": table["table"], "parent": f"db_{sid}"}},
        {"id": f"fld_{sid}", "type": "DBObject", "attrs": {"kind": "field", "name": field["name"], "parent": f"tbl_{sid}"}},
        {"id": f"tag_{sid}", "type": "SensitiveTag", "attrs": {"category": field["name"], "level": field_level, "confidence": confidence}},
        {"id": f"user_{sid}", "type": "Identity", "attrs": {"kind": "user", "is_external": False, "mfa": False, "name": f"nurse_{sid}"}},
        {"id": f"audit_{sid}", "type": "AuditEvent", "attrs": {"action": f"SELECT * FROM {table['table']} LIMIT 50000", "success": True, "src_ip": f"198.51.{random.randint(1,255)}.{random.randint(1,255)}", "anomaly_score": anomaly, "t": "2025-02-10T03:15:00"}},
        {"id": f"risk_{sid}", "type": "RiskFinding", "attrs": {"rule": "night_bulk_export", "severity": "critical" if not is_negative else "low", "observed_at": "2025-02-10T03:16:00"}},
    ]
    edges = [
        {"source": "internet", "target": f"sg_{sid}", "type": "can_connect", "attrs": {"strength": 1.0, "evidence_ref": f"ev_sg_{sid}"}},
        {"source": f"sg_{sid}", "target": f"rds_{sid}", "type": "can_connect", "attrs": {"strength": 0.95, "evidence_ref": f"ev_net_{sid}"}},
        {"source": f"rds_{sid}", "target": f"user_{sid}", "type": "owns", "attrs": {"strength": 1.0, "evidence_ref": f"ev_owns_{sid}"}},
        {"source": f"user_{sid}", "target": f"tbl_{sid}", "type": "has_permission", "attrs": {"strength": round(random.uniform(0.6, 0.85), 2), "evidence_ref": f"ev_perm_{sid}", "privilege": "SELECT"}},
        {"source": f"rds_{sid}", "target": f"db_{sid}", "type": "contains", "attrs": {"strength": 1.0, "evidence_ref": f"ev_c1_{sid}"}},
        {"source": f"db_{sid}", "target": f"tbl_{sid}", "type": "contains", "attrs": {"strength": 1.0, "evidence_ref": f"ev_c2_{sid}"}},
        {"source": f"tbl_{sid}", "target": f"fld_{sid}", "type": "contains", "attrs": {"strength": 1.0, "evidence_ref": f"ev_c3_{sid}"}},
        {"source": f"fld_{sid}", "target": f"tag_{sid}", "type": "classified_as", "attrs": {"strength": confidence, "evidence_ref": f"ev_dlp_{sid}"}},
        {"source": f"user_{sid}", "target": f"tbl_{sid}", "type": "accessed", "attrs": {"strength": anomaly, "evidence_ref": f"ev_audit_{sid}", "via": f"audit_{sid}"}},
        {"source": f"audit_{sid}", "target": f"risk_{sid}", "type": "triggered", "attrs": {"strength": 0.9, "evidence_ref": f"ev_risk_{sid}"}},
    ]
    gold = ["internet", f"sg_{sid}", f"rds_{sid}", f"db_{sid}", f"tbl_{sid}", f"fld_{sid}", f"tag_{sid}"]
    expected = "Observed_Risk" if not is_negative else "Observed_Risk"  # 路径结构本身仍可达
    return _make_sample(sid, "S3", "异常IP/夜间访问+批量查询", industry, nodes, edges, [gold], expected)


def tpl_external_entity(idx: int, industry: str, is_negative: bool = False) -> dict:
    """S4: 外部主体+白名单过宽"""
    table = _pick_table(industry)
    sensitive = _pick_sensitive_fields(table)
    if not sensitive:
        sensitive = [{"name": "id_card", "type": "VARCHAR", "level": "L4"}]
    field = random.choice(sensitive)
    eng = random.choice(ENGINES)
    sid = _gen_id(f"S4_{industry}", idx)
    field_level = _level_to_int(field["level"])
    confidence = round(random.uniform(0.85, 0.99), 2)
    sg_strength = round(random.uniform(0.5, 0.7), 2)
    net_strength = round(random.uniform(0.45, 0.6), 2) if not is_negative else round(random.uniform(0.1, 0.3), 2)

    nodes = [
        {"id": "internet", "type": "Network", "attrs": {"kind": "eip", "public_exposed": True, "cidr": "0.0.0.0/0"}},
        {"id": f"sg_{sid}", "type": "Network", "attrs": {"kind": "sg", "public_exposed": True, "cidr": "0.0.0.0/0", "port": eng["port"]}},
        {"id": f"vendor_{sid}", "type": "Identity", "attrs": {"kind": "user", "is_external": True, "mfa": False, "name": f"vendor_{sid}"}},
        {"id": f"role_{sid}", "type": "Identity", "attrs": {"kind": "role", "is_external": False, "name": f"export_role_{sid}"}},
        {"id": f"rds_{sid}", "type": "DBInstance", "attrs": {"engine": eng["engine"], "version": "8.0", "port": eng["port"], "encrypted": True, "audit_on": False, "region": random.choice(REGIONS)}},
        {"id": f"db_{sid}", "type": "DBObject", "attrs": {"kind": "db", "name": table["table"]}},
        {"id": f"tbl_{sid}", "type": "DBObject", "attrs": {"kind": "table", "name": table["table"], "parent": f"db_{sid}"}},
        {"id": f"fld_{sid}", "type": "DBObject", "attrs": {"kind": "field", "name": field["name"], "parent": f"tbl_{sid}"}},
        {"id": f"tag_{sid}", "type": "SensitiveTag", "attrs": {"category": field["name"], "level": field_level, "confidence": confidence}},
    ]
    edges = [
        {"source": "internet", "target": f"sg_{sid}", "type": "can_connect", "attrs": {"strength": sg_strength, "evidence_ref": f"ev_sg_{sid}"}},
        {"source": f"sg_{sid}", "target": f"rds_{sid}", "type": "can_connect", "attrs": {"strength": net_strength, "evidence_ref": f"ev_net_{sid}"}},
        {"source": f"rds_{sid}", "target": f"vendor_{sid}", "type": "owns", "attrs": {"strength": 1.0, "evidence_ref": f"ev_owns_{sid}"}},
        {"source": f"vendor_{sid}", "target": f"role_{sid}", "type": "can_assume", "attrs": {"strength": round(random.uniform(0.75, 0.9), 2), "evidence_ref": f"ev_assume_{sid}"}},
        {"source": f"role_{sid}", "target": f"tbl_{sid}", "type": "has_permission", "attrs": {"strength": round(random.uniform(0.6, 0.8), 2), "evidence_ref": f"ev_perm_{sid}", "privilege": "SELECT"}},
        {"source": f"rds_{sid}", "target": f"db_{sid}", "type": "contains", "attrs": {"strength": 1.0, "evidence_ref": f"ev_c1_{sid}"}},
        {"source": f"db_{sid}", "target": f"tbl_{sid}", "type": "contains", "attrs": {"strength": 1.0, "evidence_ref": f"ev_c2_{sid}"}},
        {"source": f"tbl_{sid}", "target": f"fld_{sid}", "type": "contains", "attrs": {"strength": 1.0, "evidence_ref": f"ev_c3_{sid}"}},
        {"source": f"fld_{sid}", "target": f"tag_{sid}", "type": "classified_as", "attrs": {"strength": confidence, "evidence_ref": f"ev_dlp_{sid}"}},
    ]
    gold = ["internet", f"sg_{sid}", f"rds_{sid}", f"vendor_{sid}", f"role_{sid}", f"tbl_{sid}", f"fld_{sid}", f"tag_{sid}"]
    expected = "Insufficient_Evidence" if is_negative else "Potential_Exposure"
    return _make_sample(sid, "S4", "外部主体+白名单过宽", industry, nodes, edges, [gold], expected)


def tpl_no_protection(idx: int, industry: str, is_negative: bool = False) -> dict:
    """S5: 未开启审计/保护+高敏资产"""
    table = _pick_table(industry)
    sensitive = _pick_sensitive_fields(table)
    if not sensitive:
        sensitive = [{"name": "policyholder_id_card", "type": "VARCHAR", "level": "L4"}]
    field = random.choice(sensitive)
    eng = random.choice(ENGINES)
    sid = _gen_id(f"S5_{industry}", idx)
    field_level = _level_to_int(field["level"])
    confidence = round(random.uniform(0.85, 0.99), 2)

    nodes = [
        {"id": "internet", "type": "Network", "attrs": {"kind": "eip", "public_exposed": True, "cidr": "0.0.0.0/0"}},
        {"id": f"sg_{sid}", "type": "Network", "attrs": {"kind": "sg", "public_exposed": True, "cidr": "0.0.0.0/0", "port": eng["port"]}},
        {"id": f"rds_{sid}", "type": "DBInstance", "attrs": {"engine": eng["engine"], "version": "2019", "port": eng["port"], "encrypted": False, "audit_on": False, "region": random.choice(REGIONS)}},
        {"id": f"db_{sid}", "type": "DBObject", "attrs": {"kind": "db", "name": table["table"]}},
        {"id": f"tbl_{sid}", "type": "DBObject", "attrs": {"kind": "table", "name": table["table"], "parent": f"db_{sid}"}},
        {"id": f"fld_{sid}", "type": "DBObject", "attrs": {"kind": "field", "name": field["name"], "parent": f"tbl_{sid}"}},
        {"id": f"tag_{sid}", "type": "SensitiveTag", "attrs": {"category": field["name"], "level": field_level, "confidence": confidence}},
        {"id": f"user_{sid}", "type": "Identity", "attrs": {"kind": "user", "is_external": False, "mfa": False, "name": f"admin_{sid}"}},
        {"id": f"ctrl_tde_{sid}", "type": "Control", "attrs": {"kind": "TDE", "enabled": is_negative, "scope": f"rds_{sid}"}},
        {"id": f"ctrl_audit_{sid}", "type": "Control", "attrs": {"kind": "Audit", "enabled": is_negative, "scope": f"rds_{sid}"}},
        {"id": f"ctrl_backup_{sid}", "type": "Control", "attrs": {"kind": "Backup", "enabled": is_negative, "scope": f"rds_{sid}"}},
    ]
    edges = [
        {"source": "internet", "target": f"sg_{sid}", "type": "can_connect", "attrs": {"strength": 1.0, "evidence_ref": f"ev_sg_{sid}"}},
        {"source": f"sg_{sid}", "target": f"rds_{sid}", "type": "can_connect", "attrs": {"strength": 0.95, "evidence_ref": f"ev_net_{sid}"}},
        {"source": f"rds_{sid}", "target": f"user_{sid}", "type": "owns", "attrs": {"strength": 1.0, "evidence_ref": f"ev_owns_{sid}"}},
        {"source": f"user_{sid}", "target": f"tbl_{sid}", "type": "has_permission", "attrs": {"strength": round(random.uniform(0.85, 0.99), 2), "evidence_ref": f"ev_perm_{sid}", "privilege": "ALL"}},
        {"source": f"rds_{sid}", "target": f"db_{sid}", "type": "contains", "attrs": {"strength": 1.0, "evidence_ref": f"ev_c1_{sid}"}},
        {"source": f"db_{sid}", "target": f"tbl_{sid}", "type": "contains", "attrs": {"strength": 1.0, "evidence_ref": f"ev_c2_{sid}"}},
        {"source": f"tbl_{sid}", "target": f"fld_{sid}", "type": "contains", "attrs": {"strength": 1.0, "evidence_ref": f"ev_c3_{sid}"}},
        {"source": f"fld_{sid}", "target": f"tag_{sid}", "type": "classified_as", "attrs": {"strength": confidence, "evidence_ref": f"ev_dlp_{sid}"}},
        {"source": f"rds_{sid}", "target": f"ctrl_tde_{sid}", "type": "protected_by", "attrs": {"strength": 1.0, "evidence_ref": f"ev_ctrl1_{sid}"}},
        {"source": f"rds_{sid}", "target": f"ctrl_audit_{sid}", "type": "protected_by", "attrs": {"strength": 1.0, "evidence_ref": f"ev_ctrl2_{sid}"}},
        {"source": f"rds_{sid}", "target": f"ctrl_backup_{sid}", "type": "protected_by", "attrs": {"strength": 1.0, "evidence_ref": f"ev_ctrl3_{sid}"}},
    ]
    gold = ["internet", f"sg_{sid}", f"rds_{sid}", f"db_{sid}", f"tbl_{sid}", f"fld_{sid}", f"tag_{sid}"]
    expected = "Observed_Risk"
    return _make_sample(sid, "S5", "未开启审计/保护+高敏资产", industry, nodes, edges, [gold], expected)


def tpl_evidence_conflict(idx: int, industry: str, is_negative: bool = False) -> dict:
    """S6: 证据冲突 — 权限有但网络不通，或审计有但权限无"""
    table = _pick_table(industry)
    sensitive = _pick_sensitive_fields(table)
    if not sensitive:
        sensitive = [{"name": "id_card", "type": "VARCHAR", "level": "L4"}]
    field = random.choice(sensitive)
    eng = random.choice(ENGINES)
    sid = _gen_id(f"S6_{industry}", idx)
    field_level = _level_to_int(field["level"])
    confidence = round(random.uniform(0.85, 0.99), 2)

    # 冲突设计: 权限高但网络弱(reach < gate阈值)
    net_strength = round(random.uniform(0.1, 0.35), 2)  # reach 会 < 0.5 gate
    perm_strength = round(random.uniform(0.85, 0.99), 2)  # 权限很高

    nodes = [
        {"id": "internet", "type": "Network", "attrs": {"kind": "eip", "public_exposed": True, "cidr": "0.0.0.0/0"}},
        {"id": f"sg_{sid}", "type": "Network", "attrs": {"kind": "sg", "public_exposed": True, "cidr": "10.0.0.0/8", "port": eng["port"]}},
        {"id": f"rds_{sid}", "type": "DBInstance", "attrs": {"engine": eng["engine"], "version": "8.0", "port": eng["port"], "encrypted": True, "audit_on": True, "region": random.choice(REGIONS)}},
        {"id": f"db_{sid}", "type": "DBObject", "attrs": {"kind": "db", "name": table["table"]}},
        {"id": f"tbl_{sid}", "type": "DBObject", "attrs": {"kind": "table", "name": table["table"], "parent": f"db_{sid}"}},
        {"id": f"fld_{sid}", "type": "DBObject", "attrs": {"kind": "field", "name": field["name"], "parent": f"tbl_{sid}"}},
        {"id": f"tag_{sid}", "type": "SensitiveTag", "attrs": {"category": field["name"], "level": field_level, "confidence": confidence}},
        {"id": f"user_{sid}", "type": "Identity", "attrs": {"kind": "user", "is_external": False, "mfa": True, "name": f"dba_{sid}"}},
        {"id": f"audit_{sid}", "type": "AuditEvent", "attrs": {"action": f"SELECT * FROM {table['table']}", "success": True, "src_ip": f"203.0.{random.randint(1,255)}.{random.randint(1,255)}", "anomaly_score": round(random.uniform(0.6, 0.9), 2), "t": "2025-03-01T14:30:00"}},
    ]
    edges = [
        {"source": "internet", "target": f"sg_{sid}", "type": "can_connect", "attrs": {"strength": net_strength, "evidence_ref": f"ev_sg_{sid}"}},
        {"source": f"sg_{sid}", "target": f"rds_{sid}", "type": "can_connect", "attrs": {"strength": round(random.uniform(0.3, 0.5), 2), "evidence_ref": f"ev_net_{sid}"}},
        {"source": f"rds_{sid}", "target": f"user_{sid}", "type": "owns", "attrs": {"strength": 1.0, "evidence_ref": f"ev_owns_{sid}"}},
        {"source": f"user_{sid}", "target": f"tbl_{sid}", "type": "has_permission", "attrs": {"strength": perm_strength, "evidence_ref": f"ev_perm_{sid}", "privilege": "ALL"}},
        {"source": f"rds_{sid}", "target": f"db_{sid}", "type": "contains", "attrs": {"strength": 1.0, "evidence_ref": f"ev_c1_{sid}"}},
        {"source": f"db_{sid}", "target": f"tbl_{sid}", "type": "contains", "attrs": {"strength": 1.0, "evidence_ref": f"ev_c2_{sid}"}},
        {"source": f"tbl_{sid}", "target": f"fld_{sid}", "type": "contains", "attrs": {"strength": 1.0, "evidence_ref": f"ev_c3_{sid}"}},
        {"source": f"fld_{sid}", "target": f"tag_{sid}", "type": "classified_as", "attrs": {"strength": confidence, "evidence_ref": f"ev_dlp_{sid}"}},
        {"source": f"user_{sid}", "target": f"tbl_{sid}", "type": "accessed", "attrs": {"strength": 0.8, "evidence_ref": f"ev_audit_{sid}", "via": f"audit_{sid}"}},
    ]
    gold = ["internet", f"sg_{sid}", f"rds_{sid}", f"db_{sid}", f"tbl_{sid}", f"fld_{sid}", f"tag_{sid}"]
    expected = "Insufficient_Evidence"  # Gate 拦截（reach < 0.5）
    return _make_sample(sid, "S6", "证据冲突(权限高但网络不通)", industry, nodes, edges, [gold], expected)


# ════════════════════════════════════════════════
# 辅助函数
# ════════════════════════════════════════════════

def _make_sample(sid, scenario, name, industry, nodes, edges, gold_paths, expected):
    return {
        "sample_id": sid,
        "scenario": scenario,
        "scenario_name": name,
        "industry": industry,
        "nodes": nodes,
        "edges": edges,
        "gold_paths": gold_paths,
        "expected_type": expected,
    }


SCENARIO_TEMPLATES = {
    "S1": tpl_public_exposure,
    "S2": tpl_excess_privilege,
    "S3": tpl_abnormal_access,
    "S4": tpl_external_entity,
    "S5": tpl_no_protection,
    "S6": tpl_evidence_conflict,
}


def generate_dataset(
    count: int = 60,
    positive_ratio: float = 0.8,
    seed: int = 42,
) -> List[dict]:
    """生成完整数据集
    
    Args:
        count: 总样本数
        positive_ratio: 正例比例
        seed: 随机种子
    """
    random.seed(seed)
    scenarios = list(SCENARIO_TEMPLATES.keys())
    per_scenario = count // len(scenarios)
    pos_per = int(per_scenario * positive_ratio)
    neg_per = per_scenario - pos_per
    
    samples = []
    for sc in scenarios:
        tpl_fn = SCENARIO_TEMPLATES[sc]
        for i in range(pos_per):
            industry = INDUSTRIES[i % len(INDUSTRIES)]
            samples.append(tpl_fn(i, industry, is_negative=False))
        for i in range(neg_per):
            industry = INDUSTRIES[i % len(INDUSTRIES)]
            samples.append(tpl_fn(pos_per + i, industry, is_negative=True))
    
    random.shuffle(samples)
    return samples


def _attach_sensitive_target(nodes, edges, db_instance_id, industry, sid):
    """给种子图的 DBInstance 挂上真实敏感字段目标（来自 schema_pool），
    构造 DBInstance→db→table→field→SensitiveTag 的完整证据路径。"""
    table = _pick_table(industry)
    sensitive = _pick_sensitive_fields(table)
    if not sensitive:
        sensitive = [{"name": "id_card", "type": "VARCHAR", "level": "L4"}]
    field = random.choice(sensitive)
    field_level = _level_to_int(field["level"])
    confidence = round(random.uniform(0.85, 0.99), 2)

    db_id = f"db_{sid}"
    tbl_id = f"tbl_{sid}"
    fld_id = f"fld_{sid}"
    tag_id = f"tag_{sid}"

    nodes.extend([
        {"id": db_id, "type": "DBObject", "attrs": {"kind": "db", "name": table["table"]}},
        {"id": tbl_id, "type": "DBObject", "attrs": {"kind": "table", "name": table["table"], "parent": db_id}},
        {"id": fld_id, "type": "DBObject", "attrs": {"kind": "field", "name": field["name"], "parent": tbl_id}},
        {"id": tag_id, "type": "SensitiveTag", "attrs": {"category": field["name"], "level": field_level, "confidence": confidence}},
    ])
    edges.extend([
        {"source": db_instance_id, "target": db_id, "type": "contains", "attrs": {"strength": 1.0, "evidence_ref": f"ev_c1_{sid}"}},
        {"source": db_id, "target": tbl_id, "type": "contains", "attrs": {"strength": 1.0, "evidence_ref": f"ev_c2_{sid}"}},
        {"source": tbl_id, "target": fld_id, "type": "contains", "attrs": {"strength": 1.0, "evidence_ref": f"ev_c3_{sid}"}},
        {"source": fld_id, "target": tag_id, "type": "classified_as", "attrs": {"strength": confidence, "evidence_ref": f"ev_dlp_{sid}"}},
        # 权限传导：持有该实例权限即可访问其中的表（使网络链→权限→数据 首尾相接）
        {"source": db_instance_id, "target": tbl_id, "type": "has_permission",
         "attrs": {"strength": round(random.uniform(0.85, 0.95), 2), "privilege": "SELECT", "evidence_ref": f"ev_perm_{sid}", "source": "iam_transduced"}},
    ])
    return tbl_id


def build_from_seed(seed_name: str, idx: int = 0, industry: str = "finance", is_negative: bool = False) -> dict:
    """从 CloudGoat 真实种子图构建完整样本：真实拓扑 + 真实敏感字段目标。

    Args:
        seed_name: 种子文件名（data/seeds/<seed_name>_seed.json）
        industry: 用于采样敏感字段的行业
        is_negative: True 时压低网络可达强度，构造 Gate 拦截负例
    """
    seed_path = ROOT / "data" / "seeds" / f"{seed_name}_seed.json"
    if not seed_path.exists():
        raise FileNotFoundError(f"种子图不存在: {seed_path}，请先运行 scripts/ingest_cloudgoat.py")
    seed = json.loads(seed_path.read_text(encoding="utf-8"))

    nodes = copy.deepcopy(seed["nodes"])
    edges = copy.deepcopy(seed["edges"])
    sid = _gen_id(f"CG_{seed_name}", idx)

    # 找到数据存储节点作为敏感目标挂载点：优先“从入口有向可达”的 store，避免挂到走不到的孤立存储
    import networkx as _nx
    _tg = _nx.DiGraph()
    for _e in edges:
        _tg.add_edge(_e["source"], _e["target"])
    _entries = [n["id"] for n in nodes if n["type"] == "Network" and n["attrs"].get("public_exposed")]
    if not _entries:
        _entries = [n["id"] for n in nodes if n["type"] == "Network"]
    _reach = set(_entries)
    for _en in _entries:
        if _en in _tg:
            _reach |= _nx.descendants(_tg, _en)

    def _pick(pred):
        return next((n for n in nodes if pred(n)), None)

    store_node = (_pick(lambda n: n["type"] == "DBInstance" and n["id"] in _reach)
                  or _pick(lambda n: n["type"] == "DBObject" and n["id"] in _reach)
                  or _pick(lambda n: n["type"] == "DBInstance")
                  or _pick(lambda n: n["type"] == "DBObject"))
    if store_node is None:
        raise ValueError(f"种子 {seed_name} 无数据存储节点(DBInstance/DBObject)，无法挂载敏感目标")

    # 让至少一个 Network 节点成为公网入口（真实靶场 sg 若开放则已标记）
    has_entry = any(n["type"] == "Network" and n["attrs"].get("public_exposed") for n in nodes)
    if not has_entry:
        # 靶场默认 publicly_accessible=false，注入一个真实常见的公网入口（对应 Checkov CKV_AWS_17）
        nodes.append({"id": f"internet_{sid}", "type": "Network",
                      "attrs": {"kind": "eip", "public_exposed": True, "cidr": "0.0.0.0/0", "name": "internet"}})
        # 连到第一个安全组/子网
        net_tgt = next((n["id"] for n in nodes if n["type"] == "Network" and n["attrs"].get("kind") == "sg"), None)
        if net_tgt:
            reach = round(random.uniform(0.05, 0.15), 2) if is_negative else round(random.uniform(0.85, 0.99), 2)
            edges.append({"source": f"internet_{sid}", "target": net_tgt, "type": "can_connect",
                          "attrs": {"strength": reach, "evidence_ref": f"ev_entry_{sid}", "source": "injected_public_exposure"}})

    # 挂真实敏感字段目标
    _attach_sensitive_target(nodes, edges, store_node["id"], industry, sid)

    # 负例：把全部网络可达边强度压到 gate 阈值以下（模拟“任何入口都无法在网络上触达数据存储”）
    # 多入口场景存在旁路，仅压单条边会被绕过，故对所有 can_connect 统一压制，确保 reach 硬约束失败
    if is_negative:
        for e in edges:
            if e["type"] == "can_connect":
                e["attrs"]["strength"] = round(random.uniform(0.05, 0.2), 2)

    expected = "Insufficient_Evidence" if is_negative else "Observed_Risk"
    sample = _make_sample(sid, f"CG-{seed_name}", f"[CloudGoat] {seed_name}", industry, nodes, edges, [], expected)
    sample["seed_source"] = seed.get("source", "CloudGoat")
    return sample


# ════════════════════════════════════════════════
# CLI 入口
# ════════════════════════════════════════════════
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CloudDB-PathBench 数据生成器")
    parser.add_argument("--count", type=int, default=60, help="总样本数")
    parser.add_argument("--seed", type=int, default=42, help="随机种子")
    parser.add_argument("--output", type=str, default="data/pathbench_60.json", help="输出文件路径")
    parser.add_argument("--from-seeds", nargs="*", default=None,
                        help="从 CloudGoat 种子图生成样本（如 --from-seeds rds_snapshot），正例+负例各一")
    args = parser.parse_args()

    if args.from_seeds is not None:
        seed_names = args.from_seeds or ["rds_snapshot", "cloud_breach_s3", "data_secrets",
                                         "ec2_ssrf", "rce_web_app", "secrets_in_the_cloud",
                                         "vpc_peering_overexposed"]
        random.seed(args.seed)
        samples = []
        for si, sn in enumerate(seed_names):
            for ind in INDUSTRIES:
                samples.append(build_from_seed(sn, idx=len(samples), industry=ind, is_negative=False))
            samples.append(build_from_seed(sn, idx=len(samples), industry="finance", is_negative=True))
        output_path = ROOT / (args.output if args.output != "data/pathbench_60.json" else "data/pathbench_cloudgoat.json")
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(samples, f, ensure_ascii=False, indent=2)
        from collections import Counter
        print(f"✅ 从 CloudGoat 种子生成 {len(samples)} 个样本 → {output_path}")
        print(f"   种子: {seed_names}")
        print(f"   类型分布: {dict(Counter(s['expected_type'] for s in samples))}")
        import sys
        sys.exit(0)
    
    output_path = ROOT / args.output
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    samples = generate_dataset(count=args.count, seed=args.seed)
    
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(samples, f, ensure_ascii=False, indent=2)
    
    # 统计
    from collections import Counter
    sc_count = Counter(s["scenario"] for s in samples)
    type_count = Counter(s["expected_type"] for s in samples)
    ind_count = Counter(s["industry"] for s in samples)
    
    print(f"✅ 生成 {len(samples)} 个样本 → {output_path}")
    print(f"   场景分布: {dict(sc_count)}")
    print(f"   类型分布: {dict(type_count)}")
    print(f"   行业分布: {dict(ind_count)}")
