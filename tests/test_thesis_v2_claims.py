from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
THESIS = ROOT / "docs" / "thesis_v2"


def _corpus():
    return "\n".join(
        path.read_text(encoding="utf-8")
        for path in sorted(THESIS.glob("*.md"))
    )


def test_v2_thesis_does_not_reintroduce_unsubstantiated_legacy_results():
    corpus = _corpus()
    banned = [
        "Mitigation Validity 93.5%",
        "幻觉率从 18.4% 降至 5.3%",
        "端到端耗时下降一个数量级",
        "500–800 个参数化合成样本",
        "GV-FA/SFT+DPO 已完成并构成创新点",
    ]

    for claim in banned:
        assert claim not in corpus.replace(
            f"- “{claim}”；",
            "",
        )


def test_v2_thesis_discloses_current_human_gold_and_result_boundaries():
    corpus = _corpus()

    assert "双人 gold 谱系 | 0" in corpus
    assert "在此之前不宣称方法有效" in corpus
    assert "CP-Cert 当前已有" in corpus
    assert "条件性第三创新" in corpus
    assert "LangGraph 本身不构成研究创新" in corpus


def test_v2_thesis_contains_required_method_and_statistics_contracts():
    corpus = _corpus()

    for term in (
        "四值证据记忆",
        "作用域守卫",
        "Pareto",
        "硬预算",
        "vanilla ReAct",
        "full-query",
        "certified_fine_edge_f1_at_5",
        "cluster bootstrap",
        "Holm",
        "unsafe false-Reachable",
    ):
        assert term in corpus
