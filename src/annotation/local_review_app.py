"""Local-only human annotation UI over hash-frozen task bundles.

The application never calls an LLM or an external API.  It only lets a named
human edit protocol fields, while source context and assignment identity stay
immutable and hash checked.
"""
from __future__ import annotations

from collections import Counter
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

from src.annotation.negative_control_workflow import (
    validate_negative_assignment,
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
NEGATIVE_SCREEN_BOOLEAN_FIELDS = (
    "cloud_data_relevant",
    "non_attack_confirmed",
    "usable_as_negative_control",
)

FIELD_EXAMPLES = {
    "nodes": [
        {
            "id": "REPLACE_node_id",
            "type": "identity",
            "raw_refs": ["REPLACE_observation_or_archive_ref"],
        }
    ],
    "edges": [
        {
            "edge_id": "REPLACE_edge_id",
            "source": "REPLACE_source_node_id",
            "target": "REPLACE_target_node_id",
            "type": "invoke",
            "evidence_state": "Supported",
            "evidence_items": [
                {
                    "evidence_id": "REPLACE_observation_id",
                    "polarity": "support",
                    "raw_ref": "REPLACE_raw_ref",
                    "query_cost": 0,
                    "source": "REPLACE_source_id",
                }
            ],
            "raw_refs": ["REPLACE_raw_ref"],
            "annotator_rationale": "REPLACE_human_reason",
        }
    ],
    "path_labels": [
        {
            "path_id": "REPLACE_path_id",
            "node_ids": ["REPLACE_node_1", "REPLACE_node_2"],
            "edge_ids": ["REPLACE_edge_1"],
            "state": "Valid",
            "certificate_raw_refs": ["REPLACE_raw_ref"],
        }
    ],
    "tool_tasks": [
        {
            "tool_name": "REPLACE_tool_name",
            "query_scope": {},
            "observable_raw_refs": ["REPLACE_raw_ref"],
            "query_cost": 0,
        }
    ],
    "instance_labels": [
        {
            "instance_id": "REPLACE_runtime_instance_id",
            "overall_state": "Valid",
            "path_states": [
                {
                    "path_id": "REPLACE_path_id",
                    "state": "Valid",
                }
            ],
            "evidence_raw_refs": ["REPLACE_raw_ref"],
            "annotator_rationale": "REPLACE_human_reason",
        }
    ],
}


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


def _apply_negative_form(
    source_case: dict[str, Any],
    form: Any,
    *,
    complete: bool,
) -> dict[str, Any]:
    case = deepcopy(source_case)
    screening = dict(case.get("screening") or {})
    for field in NEGATIVE_SCREEN_BOOLEAN_FIELDS:
        screening[field] = _parse_bool(form.get(field))
    screening["rationale"] = str(form.get("rationale") or "")
    case["screening"] = screening
    if complete:
        case["human_attestation"] = True
        case["completed_at"] = datetime.now(timezone.utc).isoformat()
    else:
        case["human_attestation"] = False
        case["completed_at"] = None
    return case


def _negative_single_assignment(
    assignment_header: dict[str, Any],
    case: dict[str, Any],
) -> dict[str, Any]:
    assignment = deepcopy(assignment_header)
    assignment["cases"] = [deepcopy(case)]
    return assignment


def _case_state(
    case: dict[str, Any],
    *,
    workflow_kind: str = "path",
    assignment_header: dict[str, Any] | None = None,
) -> tuple[str, str | None]:
    if workflow_kind == "negative":
        if case.get("human_attestation") is True:
            try:
                validate_negative_assignment(_negative_single_assignment(
                    assignment_header or {},
                    case,
                ))
            except (KeyError, TypeError, ValueError) as exc:
                return "invalid", str(exc)
            return "complete", None
        screening = case.get("screening") or {}
        has_content = any(
            screening.get(field) is not None
            for field in NEGATIVE_SCREEN_BOOLEAN_FIELDS
        ) or bool(screening.get("rationale"))
        return ("draft" if has_content else "blank"), None
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


def _runtime_instance_summary(instance: dict[str, Any]) -> dict[str, Any]:
    """Build a neutral observation index without inferring any label."""
    observations = instance.get("observations") or []
    operations: Counter[str] = Counter()
    statuses: Counter[str] = Counter()
    actors: set[tuple[str, str]] = set()
    timestamps = []
    event_rows = []
    raw_ref_count = 0
    for observation in observations:
        operation = str(observation.get("operation") or "unknown")
        service = str(observation.get("service") or "unknown")
        status = str(observation.get("event_status") or "unknown")
        actor_type = str(observation.get("actor_type") or "unknown")
        actor_id = str(observation.get("actor_id") or "unknown")
        timestamp = str(observation.get("timestamp") or "")
        operations[operation] += 1
        statuses[status] += 1
        actors.add((actor_type, actor_id))
        if timestamp:
            timestamps.append(timestamp)
        raw_ref = observation.get("raw_ref")
        if raw_ref:
            raw_ref_count += 1
        event_rows.append({
            "observation_id": observation.get("observation_id"),
            "timestamp": timestamp or None,
            "service": service,
            "operation": operation,
            "actor_type": actor_type,
            "actor_id": actor_id,
            "status": status,
            "raw_ref": raw_ref,
        })
    return {
        "instance_id": instance.get("instance_id"),
        "platform": instance.get("platform"),
        "runtime_source_id": instance.get("runtime_source_id"),
        "observation_count": len(observations),
        "time_start": min(timestamps) if timestamps else None,
        "time_end": max(timestamps) if timestamps else None,
        "operations": sorted(
            operations.items(),
            key=lambda item: (-item[1], item[0]),
        ),
        "statuses": sorted(statuses.items()),
        "actors": [
            {"type": actor_type, "id": actor_id}
            for actor_type, actor_id in sorted(actors)
        ],
        "raw_ref_count": raw_ref_count,
        "event_rows": event_rows,
    }


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
    workflow_kinds = set()
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
        if "screening" in case and "candidate_id" in case:
            workflow_kinds.add("negative")
        elif "admission_screen" in case and "case_id" in case:
            workflow_kinds.add("path")
        else:
            raise ValueError(f"unsupported annotation task schema: {case_path}")
    if len(workflow_kinds) != 1:
        raise ValueError("task bundle mixes incompatible annotation schemas")
    workflow_kind = workflow_kinds.pop()
    assignment_header = manifest.get("assignment_header")
    if not isinstance(assignment_header, dict):
        raise ValueError("assignment manifest header is missing")

    ontology = load_path_ontology()
    nonce = secrets.token_urlsafe(32)
    app = Flask(__name__)
    app.config.update(
        MAX_CONTENT_LENGTH=8 * 1024 * 1024,
        ANNOTATION_TASK_DIR=str(task_dir),
        ANNOTATION_NONCE=nonce,
        ANNOTATION_WORKFLOW_KIND=workflow_kind,
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
        checked: str | None = None,
    ):
        position = filenames.index(filename)
        state, validation_error = _case_state(
            case,
            workflow_kind=workflow_kind,
            assignment_header=assignment_header,
        )
        if workflow_kind == "negative":
            template = NEGATIVE_CASE_TEMPLATE
        else:
            template = CASE_TEMPLATE
        return (
            render_template_string(
                template,
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
                field_examples={
                    field: json.dumps(
                        FIELD_EXAMPLES[field],
                        ensure_ascii=False,
                        indent=2,
                    )
                    for field in EDITABLE_ARRAY_FIELDS
                },
                instance_summaries=[
                    _runtime_instance_summary(instance)
                    for instance in case.get("runtime_instances") or []
                ],
                previous=filenames[position - 1] if position else None,
                next=(
                    filenames[position + 1]
                    if position + 1 < len(filenames)
                    else None
                ),
                ordinal=position + 1,
                total=len(filenames),
                saved=request.args.get("saved"),
                checked=checked or request.args.get("checked"),
            ),
            status_code,
        )

    @app.get("/")
    def index():
        rows = []
        counts = {"blank": 0, "draft": 0, "complete": 0, "invalid": 0}
        group_case_states: dict[str, list[str]] = {}
        for entry in entries:
            case, _ = load_case(entry["file"])
            state, error = _case_state(
                case,
                workflow_kind=workflow_kind,
                assignment_header=assignment_header,
            )
            counts[state] += 1
            group_id = str(
                (case.get("candidate_metadata") or {}).get(
                    "independence_group"
                )
                or case.get("independence_group")
                or case.get("case_id")
                or case.get("candidate_id")
            )
            group_case_states.setdefault(group_id, []).append(state)
            rows.append({
                "ordinal": entry["ordinal"],
                "filename": entry["file"],
                "case_id": case.get("case_id") or case.get("candidate_id"),
                "source_id": (case.get("source") or {}).get("source_id"),
                "group_id": group_id,
                "state": state,
                "error": error,
            })
        group_counts = {
            "total": len(group_case_states),
            "blank": 0,
            "draft": 0,
            "complete": 0,
            "invalid": 0,
        }
        for states in group_case_states.values():
            if any(state == "invalid" for state in states):
                group_counts["invalid"] += 1
            elif all(state == "complete" for state in states):
                group_counts["complete"] += 1
            elif any(state != "blank" for state in states):
                group_counts["draft"] += 1
            else:
                group_counts["blank"] += 1
        return render_template_string(
            INDEX_TEMPLATE,
            manifest=manifest,
            rows=rows,
            counts=counts,
            group_counts=group_counts,
            workflow_kind=workflow_kind,
        )

    @app.get("/guide")
    def guide_page():
        if workflow_kind == "negative":
            return render_template_string(NEGATIVE_GUIDE_TEMPLATE)
        return render_template_string(
            GUIDE_TEMPLATE,
            node_types=ontology["node_types"],
            edge_types=ontology["edge_types"],
            field_examples={
                field: json.dumps(
                    FIELD_EXAMPLES[field],
                    ensure_ascii=False,
                    indent=2,
                )
                for field in EDITABLE_ARRAY_FIELDS
            },
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
        if action not in {"draft", "check", "complete"}:
            abort(400)
        try:
            if workflow_kind == "negative":
                candidate = _apply_negative_form(
                    case,
                    request.form,
                    complete=action in {"check", "complete"},
                )
            else:
                candidate = _apply_form(
                    case,
                    request.form,
                    complete=action in {"check", "complete"},
                )
            _verify_source_context(
                candidate, entry.get("source_context_sha256")
            )
            if action in {"check", "complete"}:
                if workflow_kind == "negative":
                    validate_negative_assignment(
                        _negative_single_assignment(
                            assignment_header,
                            candidate,
                        )
                    )
                else:
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
        if action == "check":
            candidate["human_attestation"] = False
            candidate["completed_at"] = None
            return render_case(
                filename,
                candidate,
                checked="pass",
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
.guide{border-left:4px solid var(--accent);background:#eef7ff;padding:12px}
.chips{display:flex;gap:6px;flex-wrap:wrap}.chip{background:#edf2f7;
border-radius:999px;padding:3px 8px}.compact td,.compact th{padding:6px;font-size:12px}
.example{min-height:110px;background:#f7fafc}
@media(max-width:900px){.two{grid-template-columns:1fr}.wrap{padding:0 10px}}
</style>
"""


INDEX_TEMPLATE = (
    BASE_STYLE
    + """
<header><h1>RealPathBench-CD
{% if workflow_kind == "negative" %}负对照筛选{% else %}路径标注{% endif %}</h1>
<p>仅人工填写；不调用 LLM 或外部 API。来源上下文受 SHA-256 保护。</p></header>
<main class="wrap">
<section class="card guide"><b>第一次标注？</b>
先阅读 <a href="{{ url_for('guide_page') }}">
{% if workflow_kind == "negative" %}真实负对照筛选手册
{% else %}证据判定与 JSON 填写手册{% endif %}</a>。
手册只解释规则，不推荐本案例标签。</section>
<section class="card">
  <div class="grid">
    <div class="metric"><span>角色</span><b>{{ manifest.role }}</b></div>
    <div class="metric"><span>匿名标注者</span><b>{{ manifest.annotator_id }}</b></div>
    <div class="metric"><span>空白</span><b>{{ counts.blank }}</b></div>
    <div class="metric"><span>草稿</span><b>{{ counts.draft }}</b></div>
    <div class="metric"><span>已完成</span><b>{{ counts.complete }}</b></div>
    <div class="metric"><span>无效</span><b>{{ counts.invalid }}</b></div>
    <div class="metric"><span>已完成{% if workflow_kind == "negative" %}独立记录
    {% else %}谱系{% endif %}</span>
    <b>{{ group_counts.complete }}/{{ group_counts.total }}</b></div>
    <div class="metric"><span>进行中{% if workflow_kind == "negative" %}独立记录
    {% else %}谱系{% endif %}</span><b>{{ group_counts.draft }}</b></div>
  </div>
</section>
<section class="card">
<table><thead><tr><th>#</th><th>案例</th>
<th>{% if workflow_kind == "negative" %}独立来源记录{% else %}独立谱系{% endif %}</th>
<th>来源</th><th>状态</th></tr></thead>
<tbody>{% for row in rows %}<tr>
<td>{{ row.ordinal }}</td>
<td><a href="{{ url_for('case_page', filename=row.filename) }}">{{ row.case_id }}</a>
{% if row.error %}<div class="invalid">{{ row.error }}</div>{% endif %}</td>
<td><code>{{ row.group_id }}</code></td>
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
{% if checked %}<div class="card success">完整性预检通过；任务文件尚未改动。
确认内容确由你本人独立判断后，才能点击“严格校验并完成”。</div>{% endif %}
<section class="card guide">
<b>先判证据，不猜攻击故事。</b>
<a href="{{ url_for('guide_page') }}" target="_blank">打开判定手册</a>。
“未看到”不是反证；作用域不足时选择 <code>needs_execution</code>。
</section>
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
{% for summary in instance_summaries %}
<details open><summary>实例 {{ summary.instance_id }} · {{ summary.platform }} ·
{{ summary.observation_count }} observations</summary>
<div class="grid">
<div><b>运行来源</b><br>{{ summary.runtime_source_id }}</div>
<div><b>时间范围</b><br>{{ summary.time_start }}<br>→ {{ summary.time_end }}</div>
<div><b>原始引用</b><br>{{ summary.raw_ref_count }}/{{ summary.observation_count }}</div>
</div>
<p><b>操作频次</b></p><div class="chips">
{% for name, count in summary.operations %}<span class="chip">{{ name }} × {{ count }}</span>{% endfor %}
</div>
<p><b>主体</b></p><div class="chips">
{% for actor in summary.actors %}<span class="chip">{{ actor.type }} · {{ actor.id }}</span>{% endfor %}
</div>
<details><summary>逐条观测索引（中立字段，不含推荐标签）</summary>
<table class="compact"><thead><tr><th>时间</th><th>主体</th><th>服务/操作</th>
<th>状态</th><th>observation ID</th><th>raw ref</th></tr></thead><tbody>
{% for row in summary.event_rows %}<tr>
<td>{{ row.timestamp }}</td><td>{{ row.actor_type }}<br>{{ row.actor_id }}</td>
<td>{{ row.service }}<br><b>{{ row.operation }}</b></td><td>{{ row.status }}</td>
<td><code>{{ row.observation_id }}</code></td>
<td><details><summary>查看</summary><pre>{{ row.raw_ref|tojson(indent=2) }}</pre></details></td>
</tr>{% endfor %}</tbody></table></details>
</details>
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
<details><summary>查看 {{ field }} 结构示例（必须替换全部 REPLACE 值）</summary>
<pre class="example">{{ field_examples[field] }}</pre></details>
{% endfor %}
</section>
<section class="card">
<h2>3. 真人声明</h2>
<p>“严格校验并完成”表示这些判断由页面顶部显示的标注者本人独立完成。完成后
文件不可在此界面修改；分歧通过 reviewer/adjudicator 工作流处理。</p>
</section>
<div class="actions">
<button class="secondary" type="submit" name="action" value="draft">保存草稿</button>
<button class="secondary" type="submit" name="action" value="check">只做完整性预检</button>
<button class="primary" type="submit" name="action" value="complete">严格校验并完成</button>
</div>
</form></main>
"""
)


NEGATIVE_CASE_TEMPLATE = (
    BASE_STYLE
    + """
<header><h1>{{ ordinal }}/{{ total }} · {{ case.candidate_id }}</h1>
<p>{{ case.role }} · {{ case.annotator_id }} · <span class="{{ state }}">{{ state }}</span></p>
</header>
<main class="wrap">
<div class="card"><a href="{{ url_for('index') }}">← 任务列表</a>
{% if previous %} · <a href="{{ url_for('case_page', filename=previous) }}">上一条</a>{% endif %}
{% if next %} · <a href="{{ url_for('case_page', filename=next) }}">下一条</a>{% endif %}
</div>
{% if error %}<div class="card error"><b>不能完成：</b>{{ error }}</div>{% endif %}
{% if saved %}<div class="card success">已保存 {{ saved }}。</div>{% endif %}
{% if checked %}<div class="card success">完整性预检通过；任务文件尚未改动。
确认内容确由你本人独立判断后，才能点击“严格校验并完成”。</div>{% endif %}
<section class="card guide"><b>这是外部负对照筛选，不是攻击路径标注。</b>
<a href="{{ url_for('guide_page') }}" target="_blank">打开筛选手册</a>。
只有“云数据相关”“确认为非攻击”“适合作为负对照”三个问题分别有证据时，
才可将三项都选为“是”；不确定不能当作“是”。</section>
<section class="card">
<h2>冻结的真实来源记录</h2>
<div class="grid">
<div><b>云厂商</b><br>{{ case.vendor }}</div>
<div><b>服务</b><br>{{ case.service_hint }}</div>
<div><b>年份</b><br>{{ case.year }}</div>
<div><b>独立记录</b><br><code>{{ case.independence_group }}</code></div>
</div>
<h3>原始报告文本</h3>
<div class="guide">{{ case.report_text }}</div>
<p><b>数据相关线索字段</b></p>
<div class="chips">{% for facet in case.data_relevance_facets %}
<span class="chip">{{ facet }}</span>{% endfor %}
{% if not case.data_relevance_facets %}<span class="muted">无预筛字段</span>{% endif %}</div>
<p><b>安全术语命中（仅是检索线索，不是标签）</b></p>
<div class="chips">{% for hit in case.security_term_hits %}
<span class="chip">{{ hit }}</span>{% endfor %}
{% if not case.security_term_hits %}<span class="muted">无</span>{% endif %}</div>
<details><summary>来源、DOI 与原始引用</summary><pre>{{ {
"source": case.source,
"raw_ref": case.raw_ref,
"source_context_sha256": case.source_context_sha256,
"packet_sha256": case.packet_sha256
}|tojson(indent=2) }}</pre></details>
{% if case.dispute_context %}<details><summary>仅仲裁员可见的双人分歧</summary>
<pre>{{ case.dispute_context|tojson(indent=2) }}</pre></details>{% endif %}
</section>
<form method="post">
<input type="hidden" name="_nonce" value="{{ nonce }}">
<section class="card">
<h2>三项独立判断</h2>
<div class="two">
<div><label>1. 与云数据资产/服务相关</label>
<select name="cloud_data_relevant">
<option value="" {% if case.screening.cloud_data_relevant is none %}selected{% endif %}>未判断</option>
<option value="true" {% if case.screening.cloud_data_relevant is sameas true %}selected{% endif %}>是</option>
<option value="false" {% if case.screening.cloud_data_relevant is sameas false %}selected{% endif %}>否</option>
</select><p class="muted">报告涉及数据库、对象存储、备份、密钥、数据处理或其
明确的数据可用性；只出现“云”字样不够。</p></div>
<div><label>2. 当前记录可确认为非攻击事件</label>
<select name="non_attack_confirmed">
<option value="" {% if case.screening.non_attack_confirmed is none %}selected{% endif %}>未判断</option>
<option value="true" {% if case.screening.non_attack_confirmed is sameas true %}selected{% endif %}>是</option>
<option value="false" {% if case.screening.non_attack_confirmed is sameas false %}selected{% endif %}>否</option>
</select><p class="muted">报告内容支持故障、容量、配置、维护等可靠性解释，且没有
未授权访问或攻击证据；“没写攻击”本身不等于确认为非攻击。</p></div>
</div>
<label>3. 适合作为主实验外部负对照</label>
<select name="usable_as_negative_control">
<option value="" {% if case.screening.usable_as_negative_control is none %}selected{% endif %}>未判断</option>
<option value="true" {% if case.screening.usable_as_negative_control is sameas true %}selected{% endif %}>是</option>
<option value="false" {% if case.screening.usable_as_negative_control is sameas false %}selected{% endif %}>否</option>
</select>
<p class="muted">选择“是”要求前两项均为“是”，并且记录足够明确、独立且可追溯；
前两项为“是”仍可因语义过少等理由在此选“否”。</p>
<label>人工理由（必须说明依据文本；不要只写“是/否”）</label>
<textarea class="rationale" name="rationale">{{ case.screening.rationale or "" }}</textarea>
</section>
<section class="card">
<label><input style="width:auto" type="checkbox" required>
我确认以上筛选由我本人独立完成，没有查看另一位标注者的答案，也没有使用
LLM 生成标签。</label>
</section>
<div class="actions">
<button class="secondary" type="submit" name="action" value="draft">保存草稿</button>
<button class="secondary" type="submit" name="action" value="check">只做完整性预检</button>
<button class="primary" type="submit" name="action" value="complete">严格校验并完成</button>
</div>
</form></main>
"""
)


NEGATIVE_GUIDE_TEMPLATE = (
    BASE_STYLE
    + """
<header><h1>真实外部负对照筛选手册</h1>
<p>只解释冻结协议，不分析当前记录、不调用模型、不推荐答案。</p></header>
<main class="wrap">
<section class="card"><a href="{{ url_for('index') }}">← 返回任务列表</a></section>
<section class="card">
<h2>为什么需要负对照</h2>
<p>负对照用于检验方法是否会把真实云服务故障、维护或容量问题误报成攻击路径。
这些记录必须来自可追溯的外部来源，并由两位真人独立筛选。</p>
</section>
<section class="card">
<h2>三个问题必须分开判断</h2>
<table><thead><tr><th>问题</th><th>“是”的最低条件</th><th>不能据此判“是”</th></tr></thead><tbody>
<tr><td>云数据相关</td><td>明确涉及数据库、对象存储、备份、密钥、数据处理，
或这些资产的数据可用性。</td><td>只看到云厂商品牌或通用计算服务。</td></tr>
<tr><td>确认为非攻击</td><td>文本支持故障、容量、配置、维护或其他可靠性解释，
且不存在未授权访问/攻击证据。</td><td>报告没有出现 attack/security 单词。</td></tr>
<tr><td>可用作负对照</td><td>前两项均为“是”，记录仍有足够语义、独立谱系和
可追溯引用，可用于评估误报。</td><td>仅因它来自“incident”数据集。</td></tr>
</tbody></table>
<p>“可用作负对照=是”时，前两项必须均为“是”；系统会在完成时严格检查。
如果文本不足以确认非攻击，应选择“否”，并在理由中写明缺失证据。</p>
</section>
<section class="card">
<h2>如何写理由</h2>
<p>指出报告中的具体事实，例如受影响的服务、事件类型、时间和恢复说明；
再解释这些事实分别如何支持三个判断。不要复制数据集名称，也不要猜测未记载的
根因。</p>
</section>
<section class="card">
<h2>独立性与完成</h2>
<p>primary 与 reviewer 不得互看答案或共用笔记。可以先保存草稿，再做不写文件的
完整性预检。两人不一致时，只有第三位真人能查看双方答案并仲裁。</p>
</section>
</main>
"""
)


GUIDE_TEMPLATE = (
    BASE_STYLE
    + """
<header><h1>人工标注判定手册</h1>
<p>只解释协议，不分析当前案例、不调用模型、不推荐标签。</p></header>
<main class="wrap">
<section class="card"><a href="{{ url_for('index') }}">← 返回任务列表</a></section>
<section class="card">
<h2>一、先判断五项准入条件</h2>
<table><thead><tr><th>问题</th><th>“是”的最低证据</th><th>常见误判</th></tr></thead><tbody>
<tr><td>外部或低权限入口</td><td>日志或固定配置明确出现匿名/外部主体、低权限
IAM/用户、被盗凭据或可从低权限到达的入口。</td><td>Root/Owner 自己执行操作不自动
等于外部入口；仅有攻击脚本说明也不是运行证据。</td></tr>
<tr><td>多步路径</td><td>至少两个语义不同且有因果或资源关联的步骤，能够组成有向
链。</td><td>同一 API 重复多次、只按时间相邻的无关事件不算路径。</td></tr>
<tr><td>云数据目标</td><td>路径终点或明确目标是数据库、对象存储、备份、密钥、
数据对象或分析数据。</td><td>只创建空桶、枚举控制面资源，不自动证明数据窃取。</td></tr>
<tr><td>关键边有原始证据</td><td>每条关键边可绑定 observation ID 与 raw ref，
且字段足以支持该边语义。</td><td>README/场景名可作上下文，不能替代缺失的运行边。</td></tr>
<tr><td>不是近重复</td><td>谱系、拓扑或事件序列具有独立信息，未被另一个案例
完整覆盖。</td><td>仅时间戳或哈希不同但序列相同，仍可能是近重复。</td></tr>
</tbody></table>
</section>
<section class="card">
<h2>二、选择最终决定</h2>
<ul>
<li><b>accept</b>：五项均有当前证据支持，并能完整填写节点、边、路径和工具任务。</li>
<li><b>needs_execution</b>：存在合理候选，但至少一条关键边需要 provider-native
oracle 或隔离探针。理由必须写明缺什么证据和所需作用域。</li>
<li><b>reject</b>：至少一个必要条件有明确反证或明确不成立。不能只因“没看到”
而 reject。</li>
</ul>
</section>
<section class="card">
<h2>三、四值证据与路径状态</h2>
<table><thead><tr><th>边状态</th><th>含义</th><th>evidence_items</th></tr></thead><tbody>
<tr><td>Supported</td><td>仅有作用域充分的支持</td><td>至少一条 support，无 refute</td></tr>
<tr><td>Contradicted</td><td>仅有决定性反证</td><td>至少一条 refute，无 support</td></tr>
<tr><td>Unknown</td><td>证据不足</td><td>必须为空</td></tr>
<tr><td>Conflict</td><td>支持与反证并存</td><td>support 和 refute 均至少一条</td></tr>
</tbody></table>
<p>路径为 Valid 仅当所有硬前提 Supported；出现 Conflict 则路径 Conflict；
无 Conflict 且至少一条 Contradicted 时为 Invalid；其余为 Insufficient。</p>
</section>
<section class="card">
<h2>四、作用域检查</h2>
<p>判断 Reachable/NotReachable 前，逐项确认账号或项目、区域、资源、目标时刻和
查询覆盖范围。控制面配置只能说明“可能”，不能自动证明当时网络或权限实际成立。
作用域不完整时使用 Unknown/needs_execution。</p>
</section>
<section class="card">
<h2>五、JSON 字段结构</h2>
<p>以下仅为语法示例，<b>不是标签建议</b>。所有 <code>REPLACE_</code> 值必须
由真人根据当前页面证据替换；完成校验会拒绝占位符。</p>
{% for field, example in field_examples.items() %}
<details><summary>{{ field }}</summary><pre>{{ example }}</pre></details>
{% endfor %}
</section>
<section class="card">
<h2>六、独立性与完成</h2>
<p>primary 与 reviewer 不得互看页面、文件或笔记。先保存草稿，再用“只做完整性
预检”；预检不写文件。只有确认标签由本人独立完成后才可严格完成，完成后页面
不可修改，分歧交由第三位真人仲裁。</p>
</section>
</main>
"""
)
