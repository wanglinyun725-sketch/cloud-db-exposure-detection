"""Gate·Score 快速验证 demo - 验证判定逻辑是否正确"""
import math
from pathlib import Path
import yaml

CONFIG_PATH = Path(__file__).parent.parent / "configs" / "thresholds.yaml"

def load_config():
    with open(CONFIG_PATH) as f:
        return yaml.safe_load(f)

def gate_score(evidence_vector: list, config: dict) -> dict:
    eps_entry, eps_reach, eps_perm, eps_target, eps_sense = evidence_vector
    tau = config["gate_thresholds"]
    
    # Gate: 硬约束一票否决
    blocked_by = []
    if eps_entry < tau["entry"]:
        blocked_by.append(f"entry({eps_entry:.2f}<{tau['entry']})")
    if eps_reach < tau["reach"]:
        blocked_by.append(f"reach({eps_reach:.2f}<{tau['reach']})")
    if eps_perm < tau["perm"]:
        blocked_by.append(f"perm({eps_perm:.2f}<{tau['perm']})")
    
    gate = 1 if not blocked_by else 0
    
    if gate == 0:
        return {
            "gate": 0, "score": 0.0,
            "type": "Insufficient_Evidence",
            "blocked_by": blocked_by
        }
    
    # Score: 加权几何均值
    weights = config["score_weights"]
    w = [weights["entry"], weights["reach"], weights["perm"], weights["target"], weights["sense"]]
    score = math.prod(e ** wi for e, wi in zip(evidence_vector, w))
    
    # 分类
    levels = config["risk_levels"]
    if score >= levels["high"]:
        path_type = "Observed_Risk"
    elif score >= levels["medium"]:
        path_type = "Potential_Exposure"
    else:
        path_type = "Low_Risk"
    
    return {"gate": 1, "score": round(score, 4), "type": path_type}


if __name__ == "__main__":
    config = load_config()
    
    print("=" * 60)
    print("  EIC Gate·Score 判定演示")
    print("  证据向量: [ε_entry, ε_reach, ε_perm, ε_target, ε_sense]")
    print("=" * 60)
    
    # 测试用例
    cases = [
        ("S1 公网暴露+高敏字段", [0.90, 0.95, 0.85, 0.97, 0.97]),
        ("S2 权限过宽+高敏字段", [0.70, 0.80, 0.90, 0.88, 0.92]),
        ("S4 网络不可达（反例）", [0.90, 0.10, 0.85, 0.97, 0.97]),
        ("S5 权限缺失（反例）",   [0.80, 0.90, 0.20, 0.95, 0.90]),
        ("S5 证据全缺（反例）",   [0.10, 0.05, 0.10, 0.30, 0.20]),
    ]
    
    for name, vec in cases:
        result = gate_score(vec, config)
        print(f"\n{'─' * 50}")
        print(f"场景: {name}")
        print(f"证据: {vec}")
        if result["gate"] == 1:
            print(f"Gate:  ✅ PASS")
            print(f"Score: {result['score']}")
            print(f"Type:  {result['type']}")
        else:
            print(f"Gate:  ❌ BLOCK")
            print(f"原因:  {result['blocked_by']}")
            print(f"Type:  {result['type']}")
    
    print(f"\n{'═' * 60}")
    print("  判定逻辑验证完成")
    print(f"{'═' * 60}")
