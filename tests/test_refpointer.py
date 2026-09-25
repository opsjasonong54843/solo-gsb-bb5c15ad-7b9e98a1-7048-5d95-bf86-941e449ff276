"""本地 $ref 指针解析共用组件（app.refpointer）单元测试 + 跨入口边界回归。

三个入口——兼容性分析（app.compat）、引用依赖诊断（app.refgraph）、
实例脱敏（app.redact）——对同一引用必须定位到**同一节点**；引用不可
解析时各入口沿用既有降级策略：

* 兼容性分析：不可解析的本地引用按无约束（``true``）降级，外部引用
  与非字符串 ``$ref`` 保持原样；
* 引用依赖诊断：记入 ``invalid_refs`` 诊断条目（带原因代码）；
* 实例脱敏：抛出 :class:`redact.UnresolvableReference`，接口层转 422。
"""
import jsonschema.exceptions
import pytest

from app import compat, redact, refgraph, refpointer
from app.refpointer import (
    REASON_EXTERNAL,
    REASON_MALFORMED_POINTER,
    REASON_NAME_FRAGMENT,
    REASON_NON_STRING,
    REASON_TARGET_NOT_FOUND,
    build_pointer,
    classify_ref,
    decode_pointer_fragment,
    node_at_pointer,
    pointer_segments,
    resolve_tokens,
)


# ---------------------------------------------------------------------------
# 共用组件：URI 片段分段与解码
# ---------------------------------------------------------------------------


class TestDecodePointerFragment:
    def test_plain_segments(self):
        assert decode_pointer_fragment("$defs/Name") == ["$defs", "Name"]

    def test_raw_slash_splits_before_percent_decoding(self):
        # %2F 是键名中的字面斜杠，不是分隔符：先按原始 / 分段再解码
        assert decode_pointer_fragment("$defs/a%2Fb") == ["$defs", "a/b"]
        assert decode_pointer_fragment("a%2Fb/c") == ["a/b", "c"]

    def test_tilde_escapes(self):
        assert decode_pointer_fragment("a~1b") == ["a/b"]
        assert decode_pointer_fragment("c~0d") == ["c~d"]
        assert decode_pointer_fragment("~0~1") == ["~/"]

    def test_percent_decoded_tilde_then_unescaped(self):
        # 百分号解码先于 ~ 转义还原：%7E0 -> ~0 -> ~
        assert decode_pointer_fragment("%7E0") == ["~"]
        assert decode_pointer_fragment("%7E1") == ["/"]

    def test_percent_decoding_is_single_pass(self):
        # %25 -> %：%252F 解码一次后是字面量 "%2F"，不再二次解码为 /
        assert decode_pointer_fragment("%252F") == ["%2F"]

    def test_malformed_tilde_returns_none(self):
        assert decode_pointer_fragment("~2") is None
        assert decode_pointer_fragment("~") is None
        assert decode_pointer_fragment("a~") is None
        assert decode_pointer_fragment("a~x") is None

    def test_empty_segment_preserved(self):
        # 空段是合法路径段（对应空字符串键名）
        assert decode_pointer_fragment("") == [""]
        assert decode_pointer_fragment("a//b") == ["a", "", "b"]


class TestResolveTokens:
    def test_dict_traversal(self):
        root = {"a": {"b": 1}}
        ok, node, failed = resolve_tokens(root, ["a", "b"])
        assert (ok, node, failed) == (True, 1, "")

    def test_missing_key(self):
        ok, node, failed = resolve_tokens({"a": 1}, ["b"])
        assert not ok and failed == "b"

    def test_empty_tokens_resolves_root(self):
        root = {"a": 1}
        ok, node, failed = resolve_tokens(root, [])
        assert (ok, node) == (True, root)

    @pytest.mark.parametrize("token", ["01", "-", "x", "1 "])
    def test_strict_array_index_rejected(self, token):
        ok, _node, failed = resolve_tokens({"items": [10, 20]}, ["items", token])
        assert not ok and failed == token

    def test_array_index_forms(self):
        root = {"items": [10, 20]}
        assert resolve_tokens(root, ["items", "0"])[1] == 10
        assert resolve_tokens(root, ["items", "1"])[1] == 20
        # 越界
        ok, _node, failed = resolve_tokens(root, ["items", "2"])
        assert not ok and failed == "2"

    def test_scalar_blocks_further_descent(self):
        ok, _node, failed = resolve_tokens({"a": 1}, ["a", "b"])
        assert not ok and failed == "b"


class TestPointerRoundTrip:
    @pytest.mark.parametrize("tokens", [
        [],
        ["$defs", "Name"],
        ["$defs", "a/b"],
        ["$defs", "c~d"],
        ["items", "0"],
        [""],
    ])
    def test_build_then_split_round_trip(self, tokens):
        assert pointer_segments(build_pointer(tokens)) == tokens

    def test_root_pointer(self):
        assert build_pointer([]) == "#"
        assert pointer_segments("#") == []


class TestClassifyRef:
    ROOT = {
        "$defs": {"Name": {"type": "string"}, "a/b": {"type": "integer"}},
        "items": [{"type": "null"}],
    }

    @pytest.mark.parametrize("ref,expected", [
        ("#", "#"),
        ("#/$defs/Name", "#/$defs/Name"),
        # %2F 与 ~1 归一到同一规范化目标
        ("#/$defs/a~1b", "#/$defs/a~1b"),
        ("#/$defs/a%2Fb", "#/$defs/a~1b"),
        ("#/items/0", "#/items/0"),
    ])
    def test_valid_refs_normalize(self, ref, expected):
        target, invalid = classify_ref(self.ROOT, ref)
        assert invalid is None
        assert target == expected

    @pytest.mark.parametrize("ref,reason", [
        ("http://example.com/x#/$defs/Name", REASON_EXTERNAL),
        ("other.json#/a", REASON_EXTERNAL),
        ("defs.json", REASON_EXTERNAL),
        ("#anchor", REASON_NAME_FRAGMENT),
        ("#/$defs/Missing", REASON_TARGET_NOT_FOUND),
        ("#/items/01", REASON_TARGET_NOT_FOUND),
        ("#/items/-", REASON_TARGET_NOT_FOUND),
        ("#/items/9", REASON_TARGET_NOT_FOUND),
        ("#/$defs/~2", REASON_MALFORMED_POINTER),
    ])
    def test_invalid_refs_carry_reason(self, ref, reason):
        target, invalid = classify_ref(self.ROOT, ref)
        assert target is None
        assert invalid["reason"] == reason
        assert invalid["ref"] == ref

    def test_non_string_ref(self):
        target, invalid = classify_ref(self.ROOT, 123)
        assert target is None
        assert invalid["reason"] == REASON_NON_STRING
        assert invalid["ref"] is None


# ---------------------------------------------------------------------------
# 跨入口边界回归：同一引用在三个入口定位到同一节点
# ---------------------------------------------------------------------------

# 各定义都带 x-sensitive，脱敏入口可直接观察引用展开到的 schema 节点
DEFS = {
    "Name": {"type": "string", "x-sensitive": True},
    "a/b": {"type": "integer", "x-sensitive": True},
    "c~d": {"type": "null", "x-sensitive": True},
}


def _schema_with_ref(ref):
    return {"properties": {"p": {"$ref": ref}}, "$defs": DEFS}


def _refgraph_observation(schema):
    """引用依赖诊断视角：(规范化目标指针 或 None, 失败原因 或 None)。"""
    result = refgraph.analyze_references(schema)
    assert len(result["edges"]) + len(result["invalid_refs"]) == 1
    if result["edges"]:
        return result["edges"][0]["target"], None
    return None, result["invalid_refs"][0]["reason"]


def _redact_observation(schema, document):
    """实例脱敏视角：命中位置的 schema 指针，或 422 异常的原因代码。"""
    try:
        result = redact.redact_documents(schema, [document])
    except redact.UnresolvableReference as exc:
        return None, exc.reason
    replacements = result["results"][0]["replacements"]
    assert len(replacements) == 1
    return replacements[0]["schema_pointer"], None


def _compat_observation(schema):
    """兼容性分析视角：$ref 预展开后该属性位置的结构。

    可解析 -> 内联后的目标内容；不可解析的本地引用 -> True（无约束降级）；
    外部引用 / 非字符串 -> 节点保持原样。
    """
    return compat.resolve_refs(schema)["properties"]["p"]


VALID_REF_CASES = [
    # (引用, 规范化目标指针)
    ("#/$defs/Name", "#/$defs/Name"),
    ("#/$defs/a~1b", "#/$defs/a~1b"),
    ("#/$defs/a%2Fb", "#/$defs/a~1b"),  # 百分号解码与 ~1 归一到同一节点
    ("#/$defs/c~0d", "#/$defs/c~0d"),
]


@pytest.mark.parametrize("ref,expected_pointer", VALID_REF_CASES)
def test_valid_ref_locates_same_node_across_entries(ref, expected_pointer):
    schema = _schema_with_ref(ref)

    # 引用依赖诊断：边目标为规范化指针
    target, reason = _refgraph_observation(schema)
    assert (target, reason) == (expected_pointer, None)

    # 实例脱敏：命中位置的 schema_pointer 是同一规范化指针
    target, reason = _redact_observation(schema, {"p": "secret"})
    assert (target, reason) == (expected_pointer, None)

    # 兼容性分析：内联结果正是共用组件定位到的同一节点内容
    resolved = _compat_observation(schema)
    assert resolved == node_at_pointer(schema, expected_pointer)


def test_root_ref_locates_root_across_entries():
    schema = {
        "properties": {"p": {"$ref": "#"}},
        "x-sensitive": True,
    }
    target, reason = _refgraph_observation(schema)
    assert (target, reason) == ("#", None)
    # 根节点 x-sensitive：脱敏在根位置命中（引用展开到根）
    target, reason = _redact_observation(schema, {"p": 1})
    assert (target, reason) == ("#", None)
    # 兼容性分析：根自指展开后仍保留全部根级结构（properties 在）
    resolved = compat.resolve_refs(schema)
    assert "properties" in resolved


def test_array_index_ref_locates_same_node_across_entries():
    # 元组写法 items（draft-04/06/07 形态）：严格下标解析在三个入口一致
    schema = {
        "properties": {"p": {"$ref": "#/items/0"}},
        "items": [{"type": "string", "x-sensitive": True}],
    }
    target, reason = _refgraph_observation(schema)
    assert (target, reason) == ("#/items/0", None)
    target, reason = _redact_observation(schema, {"p": "secret"})
    assert (target, reason) == ("#/items/0", None)
    assert _compat_observation(schema) == {"type": "string", "x-sensitive": True}


# (引用, 失败原因)：三个入口对同一不可解析引用给出同一原因
INVALID_REF_CASES = [
    ("#/$defs/Missing", REASON_TARGET_NOT_FOUND),
    ("#/$defs/a%2Fb/c", REASON_TARGET_NOT_FOUND),  # 解码后键存在、再下钻失败
    ("#/$defs/~2", REASON_MALFORMED_POINTER),
    ("#anchor", REASON_NAME_FRAGMENT),
    ("https://example.com/s.json#/$defs/Name", REASON_EXTERNAL),
    ("other.json#/a", REASON_EXTERNAL),
]


@pytest.mark.parametrize("ref,reason", INVALID_REF_CASES)
def test_invalid_ref_consistent_reason_across_entries(ref, reason):
    schema = _schema_with_ref(ref)

    # 引用依赖诊断：invalid_refs 诊断条目
    target, observed = _refgraph_observation(schema)
    assert (target, observed) == (None, reason)

    # 实例脱敏：UnresolvableReference（接口层 422）携带同一原因
    target, observed = _redact_observation(schema, {"p": "secret"})
    assert (target, observed) == (None, reason)

    # 兼容性分析：按既有策略降级，不抛异常
    resolved = _compat_observation(schema)
    if reason == REASON_EXTERNAL:
        # 外部引用保持原样（结构比较按无约束处理，最终校验把关）
        assert resolved == {"$ref": ref}
    else:
        # 不可解析的本地引用降级为无约束
        assert resolved is True


def test_invalid_array_index_ref_consistent_across_entries():
    # 严格数组下标：前导零 / `-` / 越界在三个入口同为 target_not_found
    for ref in ("#/items/01", "#/items/-", "#/items/5"):
        schema = {
            "properties": {"p": {"$ref": ref}},
            "items": [{"type": "string"}],
        }
        assert _refgraph_observation(schema) == (None, REASON_TARGET_NOT_FOUND)
        assert _redact_observation(schema, {"p": 1}) == (None, REASON_TARGET_NOT_FOUND)
        assert _compat_observation(schema) is True


def test_non_string_ref_consistent_across_entries():
    schema = {"properties": {"p": {"$ref": 123}}}
    # 引用依赖诊断：non_string_ref 诊断条目（引擎层面稳健处理）
    assert _refgraph_observation(schema) == (None, REASON_NON_STRING)
    # 兼容性分析：非字符串 $ref 不是引用，节点原样保留
    assert _compat_observation(schema) == {"$ref": 123}
    # 实例脱敏：遍历前构造校验器即拒绝非法 schema（接口层在创建分析时
    # 已以 400 拦截，引擎不会走到引用分类）
    with pytest.raises(jsonschema.exceptions.SchemaError):
        redact.redact_documents(schema, [{"p": 1}])


def test_mixed_spelling_cycle_terminates_across_entries():
    # 同一节点的两种写法（%2F / ~1）构成的自引用环：
    # 规范化目标指针判环，三个入口都安全终止
    schema = {
        "properties": {"p": {"$ref": "#/$defs/a%2Fb"}},
        "$defs": {"a/b": {"$ref": "#/$defs/a~1b", "type": "integer"}},
    }
    # 引用依赖诊断：两条边归一到同一目标，自环被检出
    result = refgraph.analyze_references(schema)
    assert {(e["source"], e["target"]) for e in result["edges"]} == {
        ("#/properties/p", "#/$defs/a~1b"),
        ("#/$defs/a~1b", "#/$defs/a~1b"),
    }
    assert result["cycles"] == [{"chain": ["#/$defs/a~1b", "#/$defs/a~1b"]}]
    # 兼容性分析：现代方言下环终止，同级 type 保留
    resolved = compat.resolve_refs(schema)
    assert resolved["properties"]["p"] == {"type": "integer"}
    # 实例脱敏：重复展开被跳过，遍历安全终止
    redacted = redact.redact_documents(schema, [{"p": 1}])
    assert redacted["results"][0]["redacted"] == {"p": 1}


@pytest.mark.parametrize("declared,modern", [
    ("https://json-schema.org/draft/2020-12/schema", True),
    ("https://json-schema.org/draft/2019-09/schema", True),
    ("http://json-schema.org/draft-07/schema#", False),
])
def test_ref_sibling_rules_follow_dialect_across_entries(declared, modern):
    # 同一引用 + 同级子规则：新方言同级生效、旧方言忽略，
    # 兼容性分析与实例脱敏沿用同一方言判定
    schema = {
        "$schema": declared,
        "type": "object",
        "properties": {
            "p": {
                "$ref": "#/$defs/Base",
                "properties": {"s": {"x-sensitive": True}},
            },
        },
        "$defs": {"Base": {"type": "object"}},
    }
    # 兼容性分析：新方言展开后同级 properties 保留（合取），旧方言被丢弃
    resolved = compat.resolve_refs(schema)["properties"]["p"]
    assert ("properties" in resolved) is modern
    # 实例脱敏：新方言遍历同级 properties 并命中，旧方言只展开引用目标
    result = redact.redact_documents(schema, [{"p": {"s": "secret"}}])
    expected = {"p": {"s": "***"}} if modern else {"p": {"s": "secret"}}
    assert result["results"][0]["redacted"] == expected
