#!/usr/bin/env python3
"""数据规模实测探针：生成器到底能产出多少『结构可区分』样本，会在哪里饱和。

- 对参数化生成器按递增 count 生成，用结构指纹去重（忽略连续强度/索引ID等种子噪声）。
- 对 CloudGoat 种子按 种子×行业×正负例 枚举，统计真实来源锚点数。
- 对去重后的唯一样本跑 SHACL 校验，报告『有效唯一』产出。
复现: python scripts/experiments/data_scale_probe.py
"""
import sys, os, json

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)

from src.data_gen.generator import (
    generate_dataset, build_from_seed, SCENARIO_TEMPLATES, INDUSTRIES, ENGINES,
)
try:
    from src.data_gen.validator import validate_sample
except Exception:
    validate_sample = None


def structural_fingerprint(s):
    """忽略种子噪声（连续强度、索引ID、region），保留决定样本『结构不同』的要素。"""
    table = field = engine = ""
    ntypes, etypes = {}, {}
    for n in s["nodes"]:
        t = n["type"]; ntypes[t] = ntypes.get(t, 0) + 1
        a = n.get("attrs", {})
        if t == "DBObject" and a.get("kind") == "table":
            table = a.get("name", "")
        if t == "DBObject" and a.get("kind") == "field":
            field = a.get("name", "")
        if t == "DBInstance":
            engine = a.get("engine", "")
    for e in s["edges"]:
        et = e["type"]; etypes[et] = etypes.get(et, 0) + 1
    nsig = tuple(sorted(ntypes.items()))
    esig = tuple(sorted(etypes.items()))
    return (s.get("scenario", ""), s.get("industry", ""), s.get("expected_type", ""),
            table, field, engine, nsig, esig)


def probe_generator():
    print("═" * 60)
    print("A. 参数化生成器：结构可区分样本 vs 生成量（饱和曲线）")
    print("═" * 60)
    print(f"池: {len(SCENARIO_TEMPLATES)} 场景 × {len(INDUSTRIES)} 行业 × {len(ENGINES)} 引擎 × 正负例")
    print(f"{'生成量':>8}{'唯一结构':>10}{'唯一率':>9}")
    curve = {}
    for count in [60, 300, 1000, 3000, 6000, 12000, 24000]:
        samples = generate_dataset(count=count, seed=42)
        fps = {structural_fingerprint(s) for s in samples}
        curve[count] = len(fps)
        print(f"{count:>8}{len(fps):>10}{len(fps)/count*100:>8.1f}%")
    return curve


def probe_cloudgoat():
    print("\n" + "═" * 60)
    print("B. CloudGoat 真实靶场：种子 × 行业 × 正负例")
    print("═" * 60)
    seeds_dir = os.path.join(ROOT, "data", "seeds")
    seed_names = [f.replace("_seed.json", "") for f in os.listdir(seeds_dir) if f.endswith("_seed.json")]
    print(f"可用种子 {len(seed_names)} 个: {', '.join(seed_names)}")
    fps = set()
    ok = 0
    for sn in seed_names:
        for ind in INDUSTRIES:
            for neg in (False, True):
                for idx in range(3):  # 每组合多试几个 idx（换表/字段）
                    try:
                        s = build_from_seed(sn, idx=len(fps) + idx, industry=ind, is_negative=neg)
                        fps.add(structural_fingerprint(s)); ok += 1
                    except Exception:
                        pass
    print(f"枚举组合产出: {ok} 次调用 → 唯一结构 {len(fps)} 条")
    return len(fps)


def probe_valid_yield():
    print("\n" + "═" * 60)
    print("C. 去重后唯一样本的 SHACL 有效产出")
    print("═" * 60)
    if validate_sample is None:
        print("  (validator 不可用，跳过)")
        return None
    # 生成大批，去重，再校验
    samples = generate_dataset(count=12000, seed=7)
    uniq = {}
    for s in samples:
        fp = structural_fingerprint(s)
        if fp not in uniq:
            uniq[fp] = s
    valid = 0
    for i, s in enumerate(uniq.values()):
        try:
            violations = validate_sample(s, i)
            if isinstance(violations, list) and len(violations) == 0:
                valid += 1
        except Exception:
            pass
    print(f"唯一结构 {len(uniq)} 条 → SHACL 通过 {valid} 条 ({valid/max(len(uniq),1)*100:.1f}%)")
    return len(uniq), valid


if __name__ == "__main__":
    c = probe_generator()
    cg = probe_cloudgoat()
    vy = probe_valid_yield()
    print("\n" + "═" * 60)
    print("小结")
    print("═" * 60)
    ceiling = max(c.values())
    print(f"• 生成器结构可区分上限（当前池）≈ {ceiling} 条（生成量再大也基本饱和）")
    print(f"• CloudGoat 真实锚点 ≈ {cg} 条唯一结构")
    if vy:
        print(f"• 有效（SHACL 通过）唯一样本 ≈ {vy[1]} 条")
