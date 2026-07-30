"""Local-only human annotation UI over hash-frozen task bundles.

The application never calls an LLM or an external API.  It only lets a named
human edit protocol fields, while source context and assignment identity stay
immutable and hash checked.
"""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from hashlib import sha256
import hmac
import json
import os
from pathlib import Path
import secrets
from typing import Any
from uuid import uuid4

from flask import (
    Flask,
    abort,
    redirect,
    render_template_string,
    request,
    url_for,
)

from src.annotation.workflow import validate_submission
from src.graph.path_ontology import load_path_ontology


EDITABLE_ARRAY_FIELDS = (
    "nodes",
    "edges",
    "path_labels",
    "tool_tasks",
    "instance_labels",
)
SCREEN_BOOLEAN_FIELDS = (
    "external_or_low_privilege_entry_defined",
    "multi_step_path_present",
    "cloud_data_target_present",
    "critical_edges_have_raw_evidence",
    "not_a_near_duplicate",
)
DECISIONS = {"accept", "needs_execution", "reject"}


def _stable_hash(value: Any) -> str:
    return sha256(json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")).hexdigest()


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} root must be an object")
    return value


def _write_json_atomic(path: Path, value: dict[str, Any]) -> None:
    temporary = path.with_name(f".{path.name}.{uuid4().hex}.tmp")
    try:
        temporary.write_text(
            json.dumps(value, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def _verify_source_context(
    case: dict[str, Any],
    expected_digest: str | None,
) -> None:
    fields = case.get("source_context_fields")
    if (
        not isinstance(fields, list)
        or not fields
        or any(field not in case for field in fields)
    ):
        raise ValueError("case source context fields are missing")
    digest = _stable_hash({field: case[field] for field in fields})
    if digest != case.get("source_context_sha256"):
        raise ValueError("case source context hash mismatch")
    if expected_digest is not None and digest != expected_digest:
        raise ValueError("case differs from assignment manifest source hash")


def _parse_bool(value: str | None) -> bool | None:
    if value in {None, ""}:
        return None
    if value == "true":
        return True
    if value == "false":
        return False
    raise ValueError("boolean fields must be true, false or blank")


def _parse_array(value: str, field: str) -> list[Any]:
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"{field} is invalid JSON at line {exc.lineno}, "
            f"column {exc.colno}: {exc.msg}"
        ) from exc
    if not isinstance(parsed, list):
        raise ValueError(f"{field} must be a JSON array")
    return parsed


def _apply_form(
    source_case: dict[str, Any],
    form: Any,
    *,
    complete: bool,
) -> dict[str, Any]:
    case = deepcopy(source_case)
    screen = dict(case.get("admission_screen") or {})
    for field in SCREEN_BOOLEAN_FIELDS:
        screen[field] = _parse_bool(form.get(field))
    decision = str(form.get("decision") or "").strip()
    screen["decision"] = decision or None
    screen["rationale"] = str(form.get("rationale") or "")
    case["admission_screen"] = screen
    for field in EDITABLE_ARRAY_FIELDS:
        case[field] = _parse_array(form.get(field, "[]"), field)
    if complete:
        case["human_attestation"] = True
        case["completed_at"] = datetime.now(timezone.utc).isoformat()
    else:
        case["human_attestation"] = False
        case["completed_at"] = None
    return case


def _case_state(case: dict[str, Any]) -> tuple[str, str | None]:
    if case.get("human_attestation") is True:
        try:
            validate_submission(case)
        except (KeyError, TypeError, ValueError) as exc:
            return "invalid", str(exc)
        return "complete", None
    decision = (case.get("admission_screen") or {}).get("decision")
    has_content = (
        decision is not None
        or bool((case.get("admission_screen") or {}).get("rationale"))
        or any(case.get(field) for field in EDITABLE_ARRAY_FIELDS)
    )
    return ("draft" if has_content else "blank"), None


def create_local_review_app(task_dir: str | Path) -> Flask:
    """Create a local review application bound to one blind task bundle."""
    task_dir = Path(task_dir).resolve()
    manifest_path = task_dir / "assignment_manifest.json"
    if not manifest_path.is_file():
        raise ValueError(f"assignment manifest is missing: {manifest_path}")
    manifest = _read_json(manifest_path)
    entries = manifest.get("entries")
    if not isinstance(entries, list) or not entries:
        raise ValueError("assignment manifest entries are missing")
    filenames = [entry.get("file") for entry in entries]
    if (
        any(not isinstance(name, str) or Path(name).name != name for name in filenames)
        or len(filenames) != len(set(filenames))
    ):
        raise ValueError("assignment manifest has invalid task filenames")
    entry_by_file = {
        entry["file"]: deepcopy(entry) for entry in entries
    }
    for entry in entries:
        case_path = task_dir / entry["file"]
        if not case_path.is_file():
            raise ValueError(f"task file is missing: {case_path}")
        case = _read_json(case_path)
        if case.get(entry["identity_field"]) != entry["item_id"]:
            raise ValueError(f"task identity mismatch: {case_path}")
        _verify_source_context(
            case, entry.get("source_context_sha256")
        )

    ontology = load_path_ontology()
    nonce = secrets.token_urlsafe(32)
    app = Flask(__name__)
    app.config.update(
        MAX_CONTENT_LENGTH=8 * 1024 * 1024,
        ANNOTATION_TASK_DIR=str(task_dir),
        ANNOTATION_NONCE=nonce,
    )

    def load_case(filename: str) -> tuple[dict[str, Any], dict[str, Any]]:
        entry = entry_by_file.get(filename)
        if entry is None:
            abort(404)
        case = _read_json(task_dir / filename)
        if case.get(entry["identity_field"]) != entry["item_id"]:
            raise ValueError("task identity changed")
        _verify_source_context(
            case, entry.get("source_context_sha256")
        )
        return case, entry

    def render_case(
        filename: str,
        case: dict[str, Any],
        *,
        error: str | None = None,
        status_code: int = 200,
    ):
        position = filenames.index(filename)
        state, validation_error = _case_state(case)
        return (
            render_template_string(
                CASE_TEMPLATE,
                case=case,
                filename=filename,
                state=state,
                error=error or validation_error,
                nonce=nonce,
                node_types=ontology["node_types"],
                edge_types=ontology["edge_types"],
                editable_json={
                    field: json.dumps(
                        case.get(field) or [],
                        ensure_ascii=False,
                        indent=2,
                    )
                    for field in EDITABLE_ARRAY_FIELDS
                },
                previous=filenames[position - 1] if position else None,
                next=(
                    filenames[position + 1]
                    if position + 1 < len(filenames)
                    else None
                ),
                ordinal=position + 1,
                total=len(filenames),
                saved=request.args.get("saved"),
            ),
            status_code,
        )

    @app.get("/")
    def index():
        rows = []
        counts = {"blank": 0, "draft": 0, "complete": 0, "invalid": 0}
        for entry in entries:
            case, _ = load_case(entry["file"])
            state, error = _case_state(case)
            counts[state] += 1
            rows.append({
                "ordinal": entry["ordinal"],
                "filename": entry["file"],
                "case_id": case.get("case_id"),
                "source_id": (case.get("source") or {}).get("source_id"),
                "state": state,
                "error": error,
            })
        return render_template_string(
            INDEX_TEMPLATE,
            manifest=manifest,
            rows=rows,
            counts=counts,
        )

    @app.get("/case/<filename>")
    def case_page(filename: str):
        case, _ = load_case(filename)
        return render_case(filename, case)

    @app.post("/case/<filename>")
    def save_case(filename: str):
        case, entry = load_case(filename)
        if case.get("human_attestation") is True:
            return render_case(
                filename,
                case,
                error=(
                    "This task is already completed and immutable. "
                    "Use the adjudication workflow for a later decision."
                ),
                status_code=409,
            )
        submitted_nonce = str(request.form.get("_nonce") or "")
        if not hmac.compare_digest(submitted_nonce, nonce):
            abort(403)
        action = request.form.get("action")
        if action not in {"draft", "complete"}:
            abort(400)
        try:
            candidate = _apply_form(
                case,
                request.form,
                complete=action == "complete",
            )
            _verify_source_context(
                candidate, entry.get("source_context_sha256")
            )
            if action == "complete":
                validate_submission(candidate)
        except (
            KeyError,
            TypeError,
            ValueError,
        ) as exc:
            return render_case(
                filename,
                (
                    candidate
                    if "candidate" in locals()
                    else case
                ),
                error=str(exc),
                status_code=400,
            )
        _write_json_atomic(task_dir / filename, candidate)
        return redirect(url_for(
            "case_page",
            filename=filename,
            saved=action,
        ))

    return app


BASE_STYLE = """
<style>
:root{color-scheme:light;--ink:#16202a;--muted:#64748b;--line:#d7dee8;
--accent:#0b6bcb;--ok:#137333;--warn:#a15c00;--bad:#b42318;--panel:#f7f9fc}
*{box-sizing:border-box}body{margin:0;font:14px/1.5 Inter,Segoe UI,sans-serif;
color:var(--ink);background:#eef2f7}header{background:#102a43;color:white;
padding:18px 28px}header h1{margin:0;font-size:22px}header p{margin:4px 0 0;
color:#cbd8e6}.wrap{max-width:1440px;margin:20px auto;padding:0 20px}
.card{background:white;border:1px solid var(--line);border-radius:10px;
padding:18px;margin-bottom:16px;box-shadow:0 2px 8px #18324a0d}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));
gap:12px}.metric{background:var(--panel);padding:12px;border-radius:8px}
.metric b{display:block;font-size:22px}.muted{color:var(--muted)}
table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:9px;
border-bottom:1px solid var(--line);vertical-align:top}th{background:var(--panel)}
a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}
.badge{display:inline-block;padding:2px 8px;border-radius:999px;background:#e8eef5}
.complete{color:var(--ok)}.draft{color:var(--warn)}.invalid{color:var(--bad)}
label{font-weight:600;display:block;margin:10px 0 5px}select,input,textarea{
width:100%;padding:8px;border:1px solid #aebdca;border-radius:6px;background:white}
textarea{min-height:150px;font:12px/1.45 Consolas,monospace;tab-size:2}
.rationale{min-height:90px;font:14px/1.5 Inter,Segoe UI,sans-serif}
.actions{position:sticky;bottom:0;background:#fffffff2;border-top:1px solid var(--line);
padding:12px;display:flex;gap:10px;justify-content:flex-end;backdrop-filter:blur(8px)}
button{border:0;border-radius:6px;padding:9px 15px;font-weight:600;cursor:pointer}
.primary{background:var(--accent);color:white}.secondary{background:#e6edf5}
.error{border-left:4px solid var(--bad);background:#fff1f0;padding:12px}
.success{border-left:4px solid var(--ok);background:#edf8ef;padding:12px}
details{border:1px solid var(--line);border-radius:7px;padding:9px;margin:8px 0}
summary{cursor:pointer;font-weight:600}pre{white-space:pre-wrap;overflow-wrap:anywhere;
font:12px/1.45 Consolas,monospace;background:#f5f7fa;padding:10px;border-radius:6px}
.two{display:grid;grid-template-columns:1fr 1fr;gap:16px}
@media(max-width:900px){.two{grid-template-columns:1fr}.wrap{padding:0 10px}}
</style>
"""


INDEX_TEMPLATE = (
    BASE_STYLE
    + """
<header><h1>RealPathBench-CD 本地人工标注</h1>
<p>仅人工填写；不调用 LLM 或外部 API。来源上下文受 SHA-256 保护。</p></header>
<main class="wrap">
<section class="card">
  <div class="grid">
    <div class="metric"><span>角色</span><b>{{ manifest.role }}</b></div>
    <div class="metric"><span>匿名标注者</span><b>{{ manifest.annotator_id }}</b></div>
    <div class="metric"><span>空白</span><b>{{ counts.blank }}</b></div>
    <div class="metric"><span>草稿</span><b>{{ counts.draft }}</b></div>
    <div class="metric"><span>已完成</span><b>{{ counts.complete }}</b></div>
    <div class="metric"><span>无效</span><b>{{ counts.invalid }}</b></div>
  </div>
</section>
<section class="card">
<table><thead><tr><th>#</th><th>案例</th><th>来源</th><th>状态</th></tr></thead>
<tbody>{% for row in rows %}<tr>
<td>{{ row.ordinal }}</td>
<td><a href="{{ url_for('case_page', filename=row.filename) }}">{{ row.case_id }}</a>
{% if row.error %}<div class="invalid">{{ row.error }}</div>{% endif %}</td>
<td>{{ row.source_id }}</td>
<td class="{{ row.state }}"><span class="badge">{{ row.state }}</span></td>
</tr>{% endfor %}</tbody></table>
</section></main>
"""
)


CASE_TEMPLATE = (
    BASE_STYLE
    + """
<header><h1>案例 {{ ordinal }}/{{ total }}</h1>
<p>{{ case.case_id }} · {{ case.role }} · {{ case.annotator_id }} ·
状态 {{ state }}</p></header>
<main class="wrap">
<div class="card">
{% if previous %}<a href="{{ url_for('case_page', filename=previous) }}">← 上一例</a>{% endif %}
{% if next %}<a style="float:right" href="{{ url_for('case_page', filename=next) }}">下一例 →</a>{% endif %}
</div>
{% if error %}<div class="card error"><b>不能完成：</b>{{ error }}</div>{% endif %}
{% if saved %}<div class="card success">已保存 {{ saved }}。</div>{% endif %}
<section class="card">
<h2>冻结的来源上下文</h2>
<div class="grid">
<div><b>来源</b><br>{{ case.source.source_id }}</div>
<div><b>证据等级</b><br>{{ case.source.provenance_level }}</div>
<div><b>独立谱系</b><br>{{ case.candidate_metadata.independence_group }}</div>
<div><b>运行实例</b><br>{{ case.runtime_instances|length }}</div>
</div>
<p>{{ case.candidate_metadata.description }}</p>
<details><summary>来源与候选元数据</summary><pre>{{ {
  "source": case.source,
  "candidate_metadata": case.candidate_metadata
}|tojson(indent=2) }}</pre></details>
{% if case.source_materials %}<details><summary>静态来源材料</summary>
<pre>{{ case.source_materials|tojson(indent=2) }}</pre></details>{% endif %}
{% for instance in case.runtime_instances %}
<details><summary>实例 {{ instance.instance_id }} · {{ instance.platform }} ·
{{ instance.observation_count }} observations</summary>
<pre>{{ instance|tojson(indent=2) }}</pre></details>
{% endfor %}
</section>
<form method="post">
<input type="hidden" name="_nonce" value="{{ nonce }}">
<section class="card">
<h2>1. 人工准入判断</h2>
<p class="muted">五个问题必须由当前标注者独立判断。缺少决定性证据时不要猜测：
使用 needs_execution，并在理由中写清需要哪种 provider-native 分析或主动探针。
“没有看到”不等于反证。</p>
{% for field, label_text in [
("external_or_low_privilege_entry_defined","存在外部或低权限入口"),
("multi_step_path_present","存在多步路径"),
("cloud_data_target_present","存在云数据目标"),
("critical_edges_have_raw_evidence","关键边有原始证据"),
("not_a_near_duplicate","不是近重复")
] %}
<label>{{ label_text }}</label>
<select name="{{ field }}">
<option value="" {% if case.admission_screen[field] is none %}selected{% endif %}>尚未判断</option>
<option value="true" {% if case.admission_screen[field] is sameas true %}selected{% endif %}>是</option>
<option value="false" {% if case.admission_screen[field] is sameas false %}selected{% endif %}>否</option>
</select>
{% endfor %}
<label>最终准入决定</label>
<select name="decision">
<option value="">尚未判断</option>
{% for value, text in [("accept","accept：五项条件均有证据，可进入人工 gold 流程"),
("needs_execution","needs_execution：关键边需要云原生工具或隔离探针"),
("reject","reject：明确不满足路径准入条件")] %}
<option value="{{ value }}" {% if case.admission_screen.decision == value %}selected{% endif %}>{{ text }}</option>
{% endfor %}
</select>
<label>人工理由</label>
<textarea class="rationale" name="rationale">{{ case.admission_screen.rationale or "" }}</textarea>
</section>
<section class="card">
<h2>2. 路径结构与实例标签</h2>
<div class="two">
<details open><summary>允许的节点类型</summary>
<table>{% for item in node_types %}<tr><td><code>{{ item.id }}</code></td>
<td>{{ item.definition }}</td></tr>{% endfor %}</table></details>
<details open><summary>允许的边类型</summary>
<table>{% for item in edge_types %}<tr><td><code>{{ item.id }}</code></td>
<td>{{ item.definition }}</td></tr>{% endfor %}</table></details>
</div>
{% for field in ["nodes","edges","path_labels","tool_tasks","instance_labels"] %}
<label>{{ field }}（JSON array）</label>
<textarea name="{{ field }}" spellcheck="false">{{ editable_json[field] }}</textarea>
{% endfor %}
</section>
<section class="card">
<h2>3. 真人声明</h2>
<p>“严格校验并完成”表示这些判断由页面顶部显示的标注者本人独立完成。完成后
文件不可在此界面修改；分歧通过 reviewer/adjudicator 工作流处理。</p>
</section>
<div class="actions">
<button class="secondary" type="submit" name="action" value="draft">保存草稿</button>
<button class="primary" type="submit" name="action" value="complete">严格校验并完成</button>
</div>
</form></main>
"""
)
