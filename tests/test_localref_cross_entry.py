"""跨入口 ``$ref`` 指针解析一致性回归测试。

兼容性分析（app.compat）、引用依赖诊断（app.refgraph）与实例脱敏
（app.redact）共用 app.localref 的本地 ``$ref`` 解析组件。这里验证：

* 同一条引用（百分号编码 / ``~0`` / ``~1`` / 数组下标 / 非法转义 /
  名称片段 / 外部引用 / 目标缺失）在三个入口定位到**同一节点**或得到
  **同一失败原因**；
* 各入口沿用各自的既有降级方式：兼容性分析把不可解析的本地引用按
  无约束处理（外部引用原样保留）、诊断产出 invalid_refs 条目、脱敏
  抛异常并由接口层返回 422；
* 旧版 / 新版 Draft 的 ``$ref`` 同级规则语义在三个入口保持一致。
"""
import copy

import pytest

from app import compat, redact, refgraph
from app.localref import (
    REASON_EXTERNAL,
    REASON_MALFORMED_POINTER,
    REASON_NAME_FRAGMENT,
    REASON_NON_STRING,
    REASON_TARGET_NOT_FOUND,
    ResolvedRef,
    node_at_pointer,
    resolve_local_ref,
)


def _diag_invalid(schema):
    """{引用声明位置: 失败原因} 映射。"""
    result = refgraph.analyze_references(schema)
    return {item["source"]: item["reason"] for item in result["invalid_refs"]}


def _diag_targets(schema):
    """{引用声明位置: 规范化目标指针} 映射（仅可解析边）。"""
    result = refgraph.analyze_references(schema)
    return {edge["source"]: edge["target"] for edge in result["edges"]}


# ---------------------------------------------------------------------------
# 共用组件本身
# ---------------------------------------------------------------------------


class TestSharedResolver:
    def test_percent_slash_and_tilde_normalize_to_same_target(self):
        root = {"$defs": {"a/b": 1, "c~d": 2}}
        for ref in ("#/$defs/a%2Fb", "#/$defs/a~1b", "#/$defs/a%2fb"):
            result = resolve_local_ref(root, ref)
            assert isinstance(result, ResolvedRef), ref
            assert result.target == "#/$defs/a~1b"
            assert result.node == 1
        result = resolve_local_ref(root, "#/$defs/c~0d")
        assert result.target == "#/$defs/c~0d"
        assert result.node == 2

    def test_division_happens_before_percent_decoding(self):
        # %2F 是键名中的字面斜杠，不作为路径分隔符
        root = {"$defs": {"a/b": {"type": "integer"}}}
        result = resolve_local_ref(root, "#/$defs/a%2Fb/type")
        assert isinstance(result, ResolvedRef)
        assert result.target == "#/$defs/a~1b/type"
        assert result.node == "integer"

    def test_strict_array_indices(self):
        root = {"items": [{"type": "string"}]}
        ok = resolve_local_ref(root, "#/items/0")
        assert isinstance(ok, ResolvedRef) and ok.target == "#/items/0"
        for ref in ("#/items/01", "#/items/-", "#/items/3", "#/items/x"):
            result = resolve_local_ref(root, ref)
            assert not isinstance(result, ResolvedRef), ref
            assert result.reason == REASON_TARGET_NOT_FOUND

    def test_malformed_tilde_escape(self):
        result = resolve_local_ref({}, "#/a/~2")
        assert not isinstance(result, ResolvedRef)
        assert result.reason == REASON_MALFORMED_POINTER

    def test_name_fragment_rejected(self):
        result = resolve_local_ref({}, "#myAnchor")
        assert not isinstance(result, ResolvedRef)
        assert result.reason == REASON_NAME_FRAGMENT

    def test_external_references_rejected(self):
        for ref in ("http://e.com/s.json#/$defs/A", "other.json#/$defs/A",
                    "urn:isbn:123", "plain-name"):
            result = resolve_local_ref({}, ref)
            assert not isinstance(result, ResolvedRef), ref
            assert result.reason == REASON_EXTERNAL

    def test_non_string_ref(self):
        result = resolve_local_ref({}, 123)
        assert not isinstance(result, ResolvedRef)
        assert result.reason == REASON_NON_STRING
        assert result.ref is None

    def test_root_pointer(self):
        root = {"$ref": "#"}
        result = resolve_local_ref(root, "#")
        assert isinstance(result, ResolvedRef)
        assert result.target == "#"
        assert result.node is root

    def test_node_at_pointer_round_trips_normalized_target(self):
        root = {"$defs": {"a/b": {"properties": {"n": {"type": "integer"}}}}}
        result = resolve_local_ref(root, "#/$defs/a%2Fb/properties/n/type")
        assert isinstance(result, ResolvedRef)
        assert node_at_pointer(root, result.target) == "integer"


# ---------------------------------------------------------------------------
# 同一引用在三个入口定位到同一节点 / 得到同一失败原因
# ---------------------------------------------------------------------------


class TestSameRefResolvesSameNodeAcrossEntries:
    def test_percent_encoded_slash(self):
        schema = {
            "type": "object",
            "properties": {
                "pct": {"$ref": "#/$defs/a%2Fb"},
                "tilde": {"$ref": "#/$defs/a~1b"},
            },
            "$defs": {"a/b": {"type": "string", "x-sensitive": True}},
        }
        # 引用诊断：两种写法归一到同一规范化目标
        targets = _diag_targets(schema)
        assert targets["#/properties/pct"] == "#/$defs/a~1b"
        assert targets["#/properties/tilde"] == "#/$defs/a~1b"

        # 兼容性分析：$ref 预展开后两个属性都按 string 定义参与比较
        resolved = compat.resolve_refs(schema)
        assert resolved["properties"]["pct"] == {"type": "string",
                                                "x-sensitive": True}
        assert resolved["properties"]["tilde"] == {"type": "string",
                                                   "x-sensitive": True}

        # 实例脱敏：两个属性都定位到带 x-sensitive 的同一目标节点
        result = redact.redact_documents(
            schema, [{"pct": "x", "tilde": "y"}])["results"][0]
        assert result["redacted"] == {"pct": "***", "tilde": "***"}
        schema_ptrs = {r["schema_pointer"] for r in result["replacements"]}
        assert schema_ptrs == {"#/$defs/a~1b"}

    def test_tilde_in_definition_name(self):
        schema = {
            "properties": {"v": {"$ref": "#/$defs/m~0n"}},
            "$defs": {"m~n": {"x-sensitive": True}},
        }
        assert _diag_targets(schema) == {"#/properties/v": "#/$defs/m~0n"}
        resolved = compat.resolve_refs(schema)
        assert resolved["properties"]["v"] == {"x-sensitive": True}
        result = redact.redact_documents(schema, [{"v": 1}])["results"][0]
        assert result["redacted"] == {"v": "***"}
        assert result["replacements"][0]["schema_pointer"] == "#/$defs/m~0n"

    def test_valid_array_index(self):
        schema = {
            "allOf": [{}, {"$ref": "#/$defs/A"}],
            "$defs": {"A": {"type": "integer"}},
        }
        assert _diag_targets(schema)["#/allOf/1"] == "#/$defs/A"
        # 兼容性分析沿 #/allOf/1 定位到 A（allOf 浅合并后为 integer 约束）
        resolved = compat.effective(compat.resolve_refs(schema))
        assert resolved.get("type") == "integer"

    def test_shared_resolver_node_identity_used_by_compat_and_diagnostics(self):
        schema = {
            "properties": {"a": {"$ref": "#/$defs/A"}},
            "$defs": {"A": {"type": "integer"}},
        }
        result = resolve_local_ref(schema, "#/$defs/A")
        assert isinstance(result, ResolvedRef)
        # 诊断边的规范化目标与共用组件一致
        assert _diag_targets(schema)["#/properties/a"] == result.target
        # 兼容性展开得到的就是该目标节点的深拷贝（结构一致）
        resolved = compat.resolve_refs(schema)
        assert resolved["properties"]["a"] == copy.deepcopy(result.node)
        # 脱敏沿同一指针取回的节点与共用组件是同一对象
        assert node_at_pointer(schema, result.target) is result.node


class TestSameFailureReasonAcrossEntries:
    @pytest.mark.parametrize(
        "ref,reason",
        [
            ("#/$defs/Missing", REASON_TARGET_NOT_FOUND),
            ("#/items/01", REASON_TARGET_NOT_FOUND),
            ("#/items/-", REASON_TARGET_NOT_FOUND),
            ("#/$defs/~2", REASON_MALFORMED_POINTER),
            ("#anchor", REASON_NAME_FRAGMENT),
            ("https://e.com/s.json#/a", REASON_EXTERNAL),
            ("other.json#/a", REASON_EXTERNAL),
        ],
    )
    def test_failure_classification_is_shared(self, ref, reason):
        # 共用组件与诊断引擎对同一条非法引用给出同一 reason
        result = resolve_local_ref({"items": []}, ref)
        assert not isinstance(result, ResolvedRef)
        assert result.reason == reason

    def test_missing_target_diagnostics_entry(self):
        schema = {"properties": {"a": {"$ref": "#/$defs/Missing"}}}
        assert _diag_invalid(schema) == {
            "#/properties/a": REASON_TARGET_NOT_FOUND}

    def test_missing_target_redact_raises_422_payload(self):
        schema = {"properties": {"a": {"$ref": "#/$defs/Missing"}}}
        with pytest.raises(redact.UnresolvableReference) as exc:
            redact.redact_documents(schema, [{"a": 1}])
        assert exc.value.reason == REASON_TARGET_NOT_FOUND
        assert exc.value.schema_pointer == "#/properties/a"
        assert exc.value.instance_pointer == "#/a"

    def test_missing_target_compat_degrades_to_unconstrained(self):
        # 兼容性分析的降级：不可解析的本地引用视为无约束（true），
        # 不影响结构比较，也不抛异常
        schema = {
            "properties": {"a": {"$ref": "#/$defs/Missing"}},
        }
        resolved = compat.resolve_refs(schema)
        assert resolved["properties"]["a"] is True
        # 无约束差异时两个方向都兼容（旧版完全无约束）
        report = compat.analyze({}, schema)
        assert report["backward_compatible"] is True
        assert report["forward_compatible"] is True

    def test_malformed_pointer_all_three_entries(self):
        schema = {"properties": {"a": {"$ref": "#/$defs/~2"}}}
        assert _diag_invalid(schema) == {
            "#/properties/a": REASON_MALFORMED_POINTER}
        with pytest.raises(redact.UnresolvableReference) as exc:
            redact.redact_documents(schema, [{"a": 1}])
        assert exc.value.reason == REASON_MALFORMED_POINTER
        # 兼容性分析同样降级为无约束
        assert compat.resolve_refs(schema)["properties"]["a"] is True

    def test_name_fragment_all_three_entries(self):
        schema = {
            "properties": {"a": {"$ref": "#myAnchor"}},
        }
        assert _diag_invalid(schema) == {
            "#/properties/a": REASON_NAME_FRAGMENT}
        with pytest.raises(redact.UnresolvableReference) as exc:
            redact.redact_documents(schema, [{"a": 1}])
        assert exc.value.reason == REASON_NAME_FRAGMENT
        assert compat.resolve_refs(schema)["properties"]["a"] is True

    def test_external_ref_compat_keeps_ref_but_diagnostics_and_redact_reject(self):
        schema = {
            "properties": {"a": {"$ref": "https://e.com/s.json#/X"}},
        }
        # 诊断：external_reference 条目
        assert _diag_invalid(schema) == {
            "#/properties/a": REASON_EXTERNAL}
        # 脱敏：外部引用同样无法解析 -> 422
        with pytest.raises(redact.UnresolvableReference) as exc:
            redact.redact_documents(schema, [{"a": 1}])
        assert exc.value.reason == REASON_EXTERNAL
        # 兼容性分析：外部引用原样保留（结构比较当无约束，最终由原始
        # schema 校验器把关），不做内联也不替换为 true
        resolved = compat.resolve_refs(schema)
        assert resolved["properties"]["a"] == {"$ref": "https://e.com/s.json#/X"}

    def test_leading_zero_index_all_three_entries(self):
        # 严格数组下标：01 在三个入口都按目标不存在处理
        schema = {
            "items": [{"type": "string"}],
            "properties": {"a": {"$ref": "#/items/01"}},
        }
        assert _diag_invalid(schema) == {
            "#/properties/a": REASON_TARGET_NOT_FOUND}
        with pytest.raises(redact.UnresolvableReference) as exc:
            redact.redact_documents(schema, [{"a": 1}])
        assert exc.value.reason == REASON_TARGET_NOT_FOUND
        assert compat.resolve_refs(schema)["properties"]["a"] is True


# ---------------------------------------------------------------------------
# 旧版 / 新版 Draft 的 $ref 同级规则语义跨入口保持一致
# ---------------------------------------------------------------------------


MODERN_DIALECTS = (
    "https://json-schema.org/draft/2020-12/schema",
    "https://json-schema.org/draft/2019-09/schema",
)
DRAFT07 = "http://json-schema.org/draft-07/schema#"


class TestRefSiblingDialectSemanticsAcrossEntries:
    def _schema(self, dialect):
        # data 经 $ref 指向整数定义；同级 minimum 仅在新方言下与引用合取
        return {
            "$schema": dialect,
            "type": "object",
            "properties": {"data": {
                "$ref": "#/$defs/Base",
                "minimum": 5,
            }},
            "$defs": {"Base": {"type": "integer"}},
        }

    @pytest.mark.parametrize("dialect", MODERN_DIALECTS)
    def test_modern_siblings_apply_in_all_three_entries(self, dialect):
        schema = self._schema(dialect)

        # 诊断只看引用边，与方言无关：引用可解析到 $defs/Base
        assert _diag_targets(schema)["#/properties/data"] == "#/$defs/Base"

        # 兼容性分析（新方言）：$ref 目标与同级 minimum 合取。
        # 旧版（同级 minimum 生效）整数 2 被拒；新版去掉 minimum 后接受
        old = schema
        new = copy.deepcopy(schema)
        del new["properties"]["data"]["minimum"]
        report = compat.analyze(old, new)
        forward_errors = [i for i in report["issues"]
                          if i["direction"] == "forward"
                          and i["severity"] == "error"]
        assert forward_errors, "新方言下同级 minimum 应生效，构成向前不兼容"

        # 脱敏（新方言）：引用目标为整数标量，无可脱敏位置，
        # 且同一引用在两个入口解析到同一目标（不抛无法解析异常）
        result = redact.redact_documents(schema, [{"data": 9}])["results"][0]
        assert result["redacted"] == {"data": 9}
        assert result["replacements"] == []

    @pytest.mark.parametrize("dialect", MODERN_DIALECTS)
    def test_modern_object_sibling_properties_redacted(self, dialect):
        # 对象场景：新方言下与 $ref 同级的 properties 参与脱敏遍历
        schema = {
            "$schema": dialect,
            "type": "object",
            "properties": {"data": {
                "$ref": "#/$defs/Base",
                "properties": {"extra": {"x-sensitive": True}},
            }},
            "$defs": {"Base": {
                "type": "object",
                "properties": {"name": {"type": "string"}}}},
        }
        assert _diag_targets(schema)["#/properties/data"] == "#/$defs/Base"
        result = redact.redact_documents(
            schema, [{"data": {"name": "a", "extra": "shh"}}])["results"][0]
        assert result["redacted"] == {"data": {"name": "a", "extra": "***"}}
        assert result["replacements"][0]["schema_pointer"] == \
            "#/properties/data/properties/extra"

    def test_draft07_siblings_ignored_in_all_three_entries(self):
        schema = self._schema(DRAFT07)

        assert _diag_targets(schema)["#/properties/data"] == "#/$defs/Base"

        # 兼容性分析（旧方言）：$ref 是纯跳转，同级 minimum 被忽略 ——
        # 删除它不产生任何 issue
        old = schema
        new = copy.deepcopy(schema)
        del new["properties"]["data"]["minimum"]
        report = compat.analyze(old, new)
        assert report["backward_compatible"] is True
        assert report["forward_compatible"] is True

        # 脱敏（旧方言）：标量引用目标本身无 x-sensitive，遍历安全终止
        result = redact.redact_documents(schema, [{"data": 2}])["results"][0]
        assert result["redacted"] == {"data": 2}
        assert result["replacements"] == []

    def test_draft07_object_sibling_properties_ignored(self):
        schema = {
            "$schema": DRAFT07,
            "type": "object",
            "properties": {"data": {
                "$ref": "#/$defs/Base",
                "properties": {"extra": {"x-sensitive": True}},
            }},
            "$defs": {"Base": {
                "type": "object",
                "properties": {"name": {"type": "string"}}}},
        }
        result = redact.redact_documents(
            schema, [{"data": {"name": "a", "extra": "shh"}}])["results"][0]
        assert result["redacted"] == {"data": {"name": "a", "extra": "shh"}}
        assert result["replacements"] == []

    def test_undeclared_schema_defaults_to_modern_everywhere(self):
        # 未声明 $schema 且无旧形态标记 -> 现代方言（两入口判定一致）
        modern_schema = self._schema(MODERN_DIALECTS[0])
        del modern_schema["$schema"]
        assert compat._is_modern_ref_dialect(modern_schema) is True
        walker = redact._RedactionWalker(modern_schema)
        assert walker.modern_refs is True

    def test_legacy_tuple_form_forces_legacy_dialect_everywhere(self):
        # 无 $schema 但出现 draft-04/06/07 元组写法 -> 旧方言
        schema = {
            "properties": {"data": {
                "$ref": "#/$defs/Base",
                "properties": {"extra": {"x-sensitive": True}}}},
            "$defs": {"Base": {"items": [{}]}},
        }
        assert compat._is_modern_ref_dialect(schema) is False
        result = redact.redact_documents(schema, [{"data": {"extra": 1}}])
        assert result["results"][0]["redacted"] == {"data": {"extra": 1}}


# ---------------------------------------------------------------------------
# 诊断入口与脱敏入口的降级方式不串味
# ---------------------------------------------------------------------------


class TestEntrySpecificDegradation:
    def test_diagnostics_never_raises_on_invalid_refs(self):
        schema = {
            "properties": {
                "a": {"$ref": "#/$defs/Missing"},
                "b": {"$ref": "http://e.com/x#/1"},
                "c": {"$ref": "#anchor"},
                "d": {"$ref": "#/items/01"},
                "e": {"$ref": "#/~9"},
            },
            "items": [],
        }
        result = refgraph.analyze_references(schema)
        reasons = {item["source"]: item["reason"]
                   for item in result["invalid_refs"]}
        assert reasons == {
            "#/properties/a": REASON_TARGET_NOT_FOUND,
            "#/properties/b": REASON_EXTERNAL,
            "#/properties/c": REASON_NAME_FRAGMENT,
            "#/properties/d": REASON_TARGET_NOT_FOUND,
            "#/properties/e": REASON_MALFORMED_POINTER,
        }
        assert result["edges"] == []

    def test_redact_reports_first_unresolvable_ref_with_both_pointers(self):
        # 脱敏在遍历中按实际到达顺序遇到无法解析的引用时终止，
        # 异常同时携带 schema 指针与实例指针
        schema = {"properties": {
            "ok": {"type": "string"},
            "bad": {"$ref": "#/$defs/NoSuch"}}}
        with pytest.raises(redact.UnresolvableReference) as exc:
            redact.redact_documents(schema, [{"ok": "v", "bad": 1}])
        err = exc.value
        assert err.schema_pointer == "#/properties/bad"
        assert err.instance_pointer == "#/bad"
        assert err.ref == "#/$defs/NoSuch"

    def test_compat_invalid_local_ref_does_not_block_other_refs(self):
        schema = {
            "properties": {
                "good": {"$ref": "#/$defs/Good"},
                "bad": {"$ref": "#/$defs/Missing"},
            },
            "$defs": {"Good": {"type": "string", "x-sensitive": True}},
        }
        resolved = compat.resolve_refs(schema)
        assert resolved["properties"]["good"] == {"type": "string",
                                                  "x-sensitive": True}
        assert resolved["properties"]["bad"] is True
        # 同一 schema 下脱敏入口仍把坏引用判为 422，好引用不受影响
        with pytest.raises(redact.UnresolvableReference):
            redact.redact_documents(schema, [{"good": "a", "bad": 1}])
        diag = refgraph.analyze_references(schema)
        assert len(diag["edges"]) == 1
        assert len(diag["invalid_refs"]) == 1
