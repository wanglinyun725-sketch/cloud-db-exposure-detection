#!/usr/bin/env python3
"""
ingest_cloudgoat.py — 从 CloudGoat 真实 Terraform 提取 CDB-RG 种子图

将开源云安全靶场 CloudGoat 的场景 IaC（.tf 文件）静态解析为 CDB-RG 种子图，
作为 generator.py 合成数据集的“真实种子”来源（对标论文：靶场种子 + 合成）。

不部署到云、不产生费用，纯静态解析 .tf 文本。
用正则解析 HCL（避免引入 python-hcl2 依赖），提取：
  - resource "aws_xxx" "name" 块  → CDB-RG 节点
  - 块内对其他资源的引用 aws_yyy.zzz  → 边
  - IAM policy 的 Action（rds:* / s3:* 等）  → has_permission 边的权限标注

运行:  python3 scripts/ingest_cloudgoat.py --scenario rds_snapshot
输出:  data/seeds/<scenario>_seed.json
"""
import json
import re
import argparse
from pathlib import Path

ROOT = Path(__file__).parent.parent
RAW_DIR = ROOT / "data" / "cloudgoat_raw"
OUT_DIR = ROOT / "data" / "seeds"

# ─── AWS 资源类型 → CDB-RG 节点类型 ───
RESOURCE_NODE_TYPE = {
    "aws_vpc": "Network",
    "aws_subnet": "Network",
    "aws_security_group": "Network",
    "aws_internet_gateway": "Network",
    "aws_route_table": "Network",
    "aws_db_subnet_group": "Network",
    "aws_iam_user": "Identity",
    "aws_iam_role": "Identity",
    "aws_iam_instance_profile": "Identity",
    "aws_instance": "Identity",          # EC2 作为可被扮演/持凭证的计算主体
    "aws_lambda_function": "Identity",    # Lambda 计算主体，可经环境变量泄露凭证
    "aws_db_instance": "DBInstance",
    "aws_rds_cluster": "DBInstance",
    "aws_dynamodb_table": "DBInstance",        # NoSQL 数据存储
    "aws_secretsmanager_secret": "DBInstance",  # 密钥/敏感数据存储
    "aws_efs_file_system": "DBInstance",
    "aws_db_snapshot": "DBObject",
    "aws_s3_bucket": "DBObject",
    "aws_s3_object": "DBObject",
}

# IAM policy / access_key 等辅助资源不直接建节点，转化为边或属性
POLICY_RESOURCES = {"aws_iam_user_policy", "aws_iam_role_policy", "aws_iam_policy", "aws_iam_role_policy_attachment"}

# 资源块正则：resource "TYPE" "NAME" {  ... }
RESOURCE_RE = re.compile(r'resource\s+"([a-z0-9_]+)"\s+"([A-Za-z0-9_\-]+)"\s*\{', re.M)
# 引用正则：aws_xxx.name（属性引用）
REF_RE = re.compile(r'\b(aws_[a-z0-9_]+)\.([A-Za-z0-9_\-]+)')
# policy Action 正则
ACTION_RE = re.compile(r'"([a-z0-9]+:[A-Za-z0-9*]+)"')


def _read_scenario(scenario: str) -> str:
    """读取场景目录下所有 .tf 拼成一个文本"""
    d = RAW_DIR / scenario
    if not d.exists():
        raise SystemExit(f"未找到场景目录: {d}\n请先用 GitHub API 抓取 .tf 到该目录。")
    text = []
    for tf in sorted(d.glob("*.tf")):
        text.append(f"# ==== {tf.name} ====\n" + tf.read_text(encoding="utf-8"))
    return "\n".join(text)


def _extract_blocks(text: str):
    """提取每个 resource 块的 (type, name, body) —— 用花括号配平找块体"""
    blocks = []
    for m in RESOURCE_RE.finditer(text):
        rtype, rname = m.group(1), m.group(2)
        start = m.end()  # 指向 { 之后
        depth = 1
        i = start
        while i < len(text) and depth > 0:
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
            i += 1
        body = text[start:i-1]
        blocks.append((rtype, rname, body))
    return blocks


def _sg_public_exposed(body: str) -> bool:
    """安全组是否对公网开放：ingress 含 0.0.0.0/0"""
    return "0.0.0.0/0" in body


def _policy_actions(body: str) -> list:
    """从 policy 块体提取 Action 列表"""
    return sorted(set(ACTION_RE.findall(body)))


def ingest(scenario: str) -> dict:
    text = _read_scenario(scenario)
    blocks = _extract_blocks(text)

    # 资源全名 -> (rtype, rname, body)
    by_key = {}
    for rtype, rname, body in blocks:
        by_key[f"{rtype}.{rname}"] = (rtype, rname, body)

    # 1) 建节点
    nodes = []
    node_ids = {}   # "rtype.rname" -> node_id
    _used_ids = set()
    _GENERIC = {"this", "that", "main", "default"}
    for key, (rtype, rname, body) in by_key.items():
        ntype = RESOURCE_NODE_TYPE.get(rtype)
        if not ntype:
            continue  # policy 等非节点资源跳过
        short = rtype[4:] if rtype.startswith("aws_") else rtype  # aws_vpc -> vpc
        # 唯一 id：通用名或冲突时加类型前缀，再冲突加数字后缀
        if rname.lower() in _GENERIC or rname in _used_ids:
            nid = f"{short}_{rname}"
        else:
            nid = rname
        if nid in _used_ids:
            _k = 2
            while f"{nid}_{_k}" in _used_ids:
                _k += 1
            nid = f"{nid}_{_k}"
        _used_ids.add(nid)
        node_ids[key] = nid
        disp = f"{short}:{rname}" if rname.lower() in _GENERIC else rname
        attrs = {"name": disp, "tf_type": rtype, "source": "cloudgoat:" + scenario}

        if ntype == "Network":
            if rtype == "aws_security_group":
                attrs["kind"] = "sg"
            elif rtype == "aws_internet_gateway":
                attrs["kind"] = "igw"
            elif rtype == "aws_route_table":
                attrs["kind"] = "route_table"
            elif rtype == "aws_db_subnet_group":
                attrs["kind"] = "subnet_group"
            elif "subnet" in rtype:
                attrs["kind"] = "subnet"
            elif "vpc" in rtype:
                attrs["kind"] = "vpc"
            else:
                attrs["kind"] = "net"
            # 纯 VPC 骨架节点标为辅助（不属于暴露主干链），前端弱化展示
            attrs["is_infra"] = attrs["kind"] in ("vpc", "igw", "route_table", "subnet_group")
            attrs["public_exposed"] = _sg_public_exposed(body) if rtype == "aws_security_group" else False
            if "0.0.0.0/0" in body:
                attrs["cidr"] = "0.0.0.0/0"
        elif ntype == "Identity":
            attrs["kind"] = "role" if "role" in rtype else ("user" if "user" in rtype else "compute")
            attrs["is_external"] = False
            attrs["mfa"] = False
        elif ntype == "DBInstance":
            m_eng = re.search(r'engine\s*=\s*"([^"]+)"', body)
            attrs["engine"] = m_eng.group(1) if m_eng else "mysql"
            attrs["publicly_accessible"] = "publicly_accessible = true" in body.replace(" ", " ")
            attrs["encrypted"] = "storage_encrypted = true" in body or "storage_encrypted=true" in body
            attrs["audit_on"] = False
        elif ntype == "DBObject":
            attrs["kind"] = "snapshot" if "snapshot" in rtype else ("bucket" if "bucket" in rtype else "object")

        nodes.append({"id": nid, "type": ntype, "attrs": attrs})

    # 2) 建边：扫描每个节点资源块体内对其他资源的引用
    edges = []
    eseen = set()

    def add_edge(s, t, etype, **eattrs):
        if s == t:
            return
        key = (s, t, etype)
        if key in eseen:
            return
        eseen.add(key)
        e = {"source": s, "target": t, "type": etype, "attrs": {"strength": 1.0, "source": "cloudgoat_ref"}}
        e["attrs"].update(eattrs)
        edges.append(e)

    for key, (rtype, rname, body) in by_key.items():
        if key not in node_ids:
            continue
        src = node_ids[key]
        for ref_type, ref_name in REF_RE.findall(body):
            ref_key = f"{ref_type}.{ref_name}"
            if ref_key == key or ref_key not in node_ids:
                continue
            tgt = node_ids[ref_key]
            etype = _infer_edge_type(rtype, ref_type)
            # 边方向：从“被引用的基础设施”指向“引用者”更符合攻击可达方向，按类型定
            _wire(add_edge, src, tgt, rtype, ref_type, etype)

    # 3) IAM policy 资源 → has_permission 边（user/role → 其可操作的资源）
    for key, (rtype, rname, body) in by_key.items():
        if rtype not in POLICY_RESOURCES:
            continue
        actions = _policy_actions(body)
        # policy 绑定的主体
        subj = None
        m_user = re.search(r'user\s*=\s*aws_iam_user\.([A-Za-z0-9_\-]+)', body)
        m_role = re.search(r'role\s*=\s*aws_iam_role\.([A-Za-z0-9_\-]+)', body)
        if m_user and f"aws_iam_user.{m_user.group(1)}" in node_ids:
            subj = node_ids[f"aws_iam_user.{m_user.group(1)}"]
        elif m_role and f"aws_iam_role.{m_role.group(1)}" in node_ids:
            subj = node_ids[f"aws_iam_role.{m_role.group(1)}"]
        if not subj or not actions:
            continue
        # 按 action 前缀确定可达的数据存储节点
        prefixes = set(a.split(":")[0] for a in actions)

        def _matched_stores():
            hits = []
            for n in nodes:
                nt = n["type"]
                kind = n["attrs"].get("kind")
                if nt == "DBInstance" and ({"rds", "secretsmanager", "dynamodb"} & prefixes):
                    hits.append(n)
                elif nt == "DBObject" and kind in ("bucket", "object") and "s3" in prefixes:
                    hits.append(n)
            return hits

        data_prefixes = {"rds", "s3", "secretsmanager", "dynamodb"}
        priv = ",".join(a for a in actions if a.split(":")[0] in data_prefixes)
        stores = _matched_stores()
        for n in stores:
            add_edge(subj, n["id"], "has_permission", privilege=priv,
                     strength=0.9, source="cloudgoat_iam_policy")

        # 凭证横移：若主体是 role，把权限传导给通过 instance_profile 持有该 role 的 EC2
        if m_role and stores:
            role_name = m_role.group(1)
            # 找引用该 role 的 instance_profile
            profiles = [pn for pk, (pt, pn, pbody) in by_key.items()
                        if pt == "aws_iam_instance_profile" and f"aws_iam_role.{role_name}" in pbody]
            for prof in profiles:
                for ik, (it, iname, ibody) in by_key.items():
                    if it == "aws_instance" and f"aws_iam_instance_profile.{prof}" in ibody and ik in node_ids:
                        ec2_id = node_ids[ik]
                        for n in stores:
                            add_edge(ec2_id, n["id"], "has_permission", privilege=priv,
                                     strength=0.85, source="cloudgoat_cred_lateral")

    # 4) Lambda 环境变量凭证泄露（真实漏洞：凭证明文存于 env）
    #    lambda 被攻陷 → 泄露某 user 的 access_key → 该 user 持数据权限
    for key, (rtype, rname, body) in by_key.items():
        if rtype != "aws_lambda_function" or key not in node_ids:
            continue
        lambda_id = node_ids[key]
        # 环境变量里引用的 access_key → owner user
        for ak_name in set(re.findall(r'aws_iam_access_key\.([A-Za-z0-9_\-]+)', body)):
            ak_key = f"aws_iam_access_key.{ak_name}"
            if ak_key not in by_key:
                continue
            ak_body = by_key[ak_key][2]
            m_owner = re.search(r'user\s*=\s*aws_iam_user\.([A-Za-z0-9_\-]+)', ak_body)
            if m_owner and f"aws_iam_user.{m_owner.group(1)}" in node_ids:
                user_id = node_ids[f"aws_iam_user.{m_owner.group(1)}"]
                add_edge(lambda_id, user_id, "can_assume", strength=0.9, source="cloudgoat_env_cred_leak")
        # 把 lambda 接入入口区：EC2 可触及/调用 lambda
        for ik, (it, iname, ibody) in by_key.items():
            if it == "aws_instance" and ik in node_ids:
                add_edge(node_ids[ik], lambda_id, "can_connect", strength=0.8, source="cloudgoat_ec2_to_lambda")

    # 回填 parent_vpc：每个非 VPC 网络节点归属到指向它的 VPC（VPC 直接 can_connect 其子节点）
    vpc_ids = {n["id"] for n in nodes if n["type"] == "Network" and n["attrs"].get("kind") == "vpc"}
    child_to_vpc = {}
    for e in edges:
        if e.get("type") == "can_connect" and e.get("source") in vpc_ids:
            child_to_vpc.setdefault(e["target"], e["source"])
    for n in nodes:
        if n["type"] == "Network":
            n["attrs"]["parent_vpc"] = None if n["id"] in vpc_ids else child_to_vpc.get(n["id"])

    seed = {
        "seed_id": scenario,
        "source": "CloudGoat (RhinoSecurityLabs, BSD-3-Clause)",
        "scenario_ref": scenario,
        "nodes": nodes,
        "edges": edges,
    }
    return seed


def _infer_edge_type(rtype: str, ref_type: str) -> str:
    return "generic"


def _wire(add_edge, src, tgt, rtype, ref_type, _etype):
    """根据资源类型对，决定边类型与方向（贴合攻击可达语义）"""
    # 网络：subnet/sg/vpc 之间及与 db/ec2 的关系 → can_connect
    net = {"aws_vpc", "aws_subnet", "aws_security_group", "aws_db_subnet_group", "aws_internet_gateway", "aws_route_table"}
    if ref_type in net or rtype in net:
        # 基础设施 → 使用者：可达方向
        add_edge(tgt, src, "can_connect", source="cloudgoat_ref")
        return
    # EC2 instance profile / role 关系 → can_assume
    if rtype == "aws_iam_instance_profile" and ref_type == "aws_iam_role":
        add_edge(src, tgt, "can_assume")
        return
    if rtype == "aws_instance" and ref_type == "aws_iam_instance_profile":
        add_edge(src, tgt, "can_assume")
        return
    # 快照 → 源实例 contains/派生
    if rtype == "aws_db_snapshot" and ref_type == "aws_db_instance":
        add_edge(tgt, src, "contains", source="cloudgoat_ref")
        return
    # s3 object → bucket contains
    if rtype == "aws_s3_object" and ref_type == "aws_s3_bucket":
        add_edge(tgt, src, "contains")
        return
    if rtype == "aws_s3_object" and ref_type == "aws_iam_access_key":
        return  # 凭证内容，不建结构边
    # 兜底：弱可达
    add_edge(src, tgt, "can_connect", strength=0.6, source="cloudgoat_ref")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenario", default="rds_snapshot", help="CloudGoat 场景名（对应 data/cloudgoat_raw/<scenario>/）")
    args = ap.parse_args()

    seed = ingest(args.scenario)
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out = OUT_DIR / f"{args.scenario}_seed.json"
    out.write_text(json.dumps(seed, ensure_ascii=False, indent=2), encoding="utf-8")

    from collections import Counter
    ntypes = Counter(n["type"] for n in seed["nodes"])
    etypes = Counter(e["type"] for e in seed["edges"])
    print(f"✅ 种子图已生成: {out}")
    print(f"   节点 {len(seed['nodes'])} | 边 {len(seed['edges'])}")
    print(f"   节点类型: {dict(ntypes)}")
    print(f"   边类型: {dict(etypes)}")
    print(f"   节点: {[n['id'] for n in seed['nodes']]}")


if __name__ == "__main__":
    main()
