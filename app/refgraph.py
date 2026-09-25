"""单份 JSON Schema 的 ``$ref`` 引用依赖诊断（纯只读，不访问网络 / 外部文件）。

输入一份 JSON Schema，遍历文档内部全部 ``$ref``，仅接受**片段形式的本地
引用**（``#`` 与 ``#/...`` JSON Pointer），按 RFC 6901 在本文档内解析
目标节点，输出：

* ``edges``：可解析的引用边（源节点指针 -> 规范化目标指针）；
* ``invalid_refs``：不可用引用的精确定位与原因（非本地引用 / 名称片段 /
  指针目标不存在 / 非法指针转义 / ``$ref`` 非字符串）；
* ``unreachable_defs``：从根侧（``$defs`` 之外）沿引用链不可达的
  ``$defs`` 节点（含定义内部嵌套 ``$defs`` 中的死定义）；
* ``cycles``：引用图中的循环链（含自环），以首尾相接的指针链表示。

图模型
======
图节点是各层 ``$defs`` 容器中的命名定义（顶层 ``$defs`` 的直接子节点，
以及定义内部嵌套 ``$defs`` 的子节点，嵌套定义与包裹它的顶层定义是
**不同节点**）。一条引用边按其源位置归属：源在某节点子树内（定义自身
或其 properties / items / 组合分支等）即为该节点发出的边；源在所有
$defs 节点之外（根侧结构）时，其已解析目标（**含定义内部的子 schema**，
如 ``#/$defs/User/properties/name``）所属的最近定义节点是可达性 BFS
的种子。

* **可达性**：每条边按**已解析目标所属的最近定义节点**折叠——根侧引用
  或已到达节点的引用，只要目标落在某定义子树内（不必精确命中定义根），
  该定义即被标记可达，再沿其内部发出的全部引用边继续传播；直接引用
  嵌套内层定义只标记该内层节点，不顺带标记包裹它的外层定义。未被任何
  根侧引用链指向的 $defs 节点即"死定义"；
* **循环**：每个节点取源路径最浅的出边作为代表边（定义对象自身的
  ``$ref`` 优先于子树内引用），沿代表边追踪至多落入一个环，按
  "环上最小指针旋转到链首"规范化去重；根侧节点引用文档根（``#``）
  形成的自环单独报告。

遍历边界
========
引用与定义的收集共用同一套 schema 树遍历，**只沿 JSON Schema 的子
schema 关键字递归**：

* 定义容器：``$defs`` / ``definitions``（draft-04/06/07），其每个命名
  成员是子 schema，成员内部继续递归（故嵌套 ``$defs`` 仍被识别）；
* 对象规则：``properties`` / ``patternProperties`` /
  ``dependentSchemas``（按命名映射的子 schema）、
  ``additionalProperties`` / ``unevaluatedProperties`` / ``propertyNames``；
* 数组规则：``items``（schema 或 draft-04 元组数组两种形态）、
  ``additionalItems`` / ``unevaluatedItems`` / ``contains``；
* 组合与条件分支：``allOf`` / ``anyOf`` / ``oneOf``（子 schema 数组）、
  ``not``、``if`` / ``then`` / ``else``；
* draft-04/06/07 的 ``dependencies``：成员为数组时是属性名依赖（数据），
  成员为对象时才是子 schema。

除此之外的关键字值一律视为**实例数据 / 注解 / 未知扩展**，不下钻：
``const`` / ``enum`` / ``default`` / ``examples``、``type`` /
``required`` / ``title`` 等普通注解，以及 ``x-`` 开头的任意扩展——
其内部同名字段（``$ref``、``$defs`` 等）都只是数据。整个过程只在入参
文档内存结构内解析，绝不发起网络或文件系统访问。
"""
from __future__ import annotations

from collections import deque
from typing import Any
from urllib.parse import unquote

# 定义容器关键字：值为「名称 -> 子 schema」映射
_DEFINITION_KEYWORDS = frozenset({"$defs", "definitions"})

# 值本身就是一个子 schema 的关键字
_SINGLE_SUBSCHEMA_KEYWORDS = frozenset({
    "additionalProperties",
    "unevaluatedProperties",
    "propertyNames",
    "additionalItems",
    "unevaluatedItems",
    "contains",
    "not",
    "if",
    "then",
    "else",
})

# 值为「名称 -> 子 schema」映射的关键字
_SUBSCHEMA_MAP_KEYWORDS = frozenset({
    "properties",
    "patternProperties",
    "dependentSchemas",
})

# 值为子 schema 数组的关键字
_SUBSCHEMA_ARRAY_KEYWORDS = frozenset({"allOf", "anyOf", "oneOf", "prefixItems"})

# 不可用引用的原因代码
REASON_EXTERNAL = "external_reference"
REASON_NAME_FRAGMENT = "name_fragment_unsupported"
REASON_TARGET_NOT_FOUND = "target_not_found"
REASON_MALFORMED_POINTER = "malformed_pointer"
REASON_NON_STRING = "non_string_ref"


# ---------------------------------------------------------------------------
# JSON Pointer 工具
# ---------------------------------------------------------------------------


def _escape_token(token: str) -> str:
    """JSON Pointer 段编码：``~`` -> ``~0``、``/`` -> ``~1``。"""
    return token.replace("~", "~0").replace("/", "~1")


def _build_pointer(tokens: list[str]) -> str:
    """由解码后的路径段构造规范化 JSON Pointer 字符串（根为 ``#``）。"""
    if not tokens:
        return "#"
    return "#/" + "/".join(_escape_token(token) for token in tokens)


def _pointer_segments(pointer: str) -> list[str]:
    """拆分已规范化的指针字符串为解码后的路径段（根 ``#`` 为空列表）。"""
    if pointer == "#":
        return []
    return [
        seg.replace("~1", "/").replace("~0", "~")
        for seg in pointer[2:].split("/")
    ]


def _decode_pointer_fragment(fragment: str) -> list[str] | None:
    """解码 URI fragment 中的 JSON Pointer（fragment 不含前导 ``#/``）。

    先按 ``/`` 切段（``%2F`` 是键名中的字面斜杠，不做分隔符），再逐段
    百分号解码并还原 ``~1`` / ``~0`` 转义。非法 ``~`` 转义返回 ``None``。
    """
    tokens: list[str] = []
    for raw in fragment.split("/"):
        token = unquote(raw)
        decoded = ""
        i = 0
        while i < len(token):
            ch = token[i]
            if ch == "~":
                if i + 1 >= len(token) or token[i + 1] not in ("0", "1"):
                    return None
                decoded += "~" if token[i + 1] == "0" else "/"
                i += 2
            else:
                decoded += ch
                i += 1
        tokens.append(decoded)
    return tokens


def _resolve_pointer(root: Any, tokens: list[str]) -> tuple[bool, str]:
    """按 JSON Pointer 在文档内解析目标。

    返回 ``(是否成功, 失败段)``：成功时失败段为空；失败时给出首个无法
    解析的路径段（已解码原文）。数组下标遵循 RFC 6901（``0`` 合法、
    带前导零非法、``-`` 指向不存在的末位后成员）。
    """
    node = root
    for token in tokens:
        if isinstance(node, dict):
            if token in node:
                node = node[token]
            else:
                return False, token
        elif isinstance(node, list):
            if token == "-" or not token.isdigit() or (
                len(token) > 1 and token.startswith("0")
            ):
                return False, token
            index = int(token)
            if index >= len(node):
                return False, token
            node = node[index]
        else:
            return False, token
    return True, ""


def _classify_ref(root: Any, ref: Any) -> tuple[str | None, dict | None]:
    """分类单个 ``$ref`` 取值，返回 ``(target_pointer, invalid_entry)``。

    二者恰有一个非 None：可解析的本地 Pointer 引用返回目标指针；其余
    情况返回不含 source 的不可用条目（由调用方补上 source）。
    """
    if not isinstance(ref, str):
        return None, {
            "ref": None,
            "reason": REASON_NON_STRING,
            "message": f"$ref 必须是字符串，实际类型为 {type(ref).__name__}",
        }

    before, separator, fragment = ref.partition("#")
    if before or not separator:
        # 非片段形式（http(s)://、相对文件路径、裸名称等）：一律不访问
        return None, {
            "ref": ref,
            "reason": REASON_EXTERNAL,
            "message": "仅接受片段形式的本地引用（# 或 #/...），不访问网络或外部文件",
        }

    if fragment == "":
        # "#"：指向文档根
        return "#", None

    if not fragment.startswith("/"):
        # "#anchor" 之类的名称片段（draft 2019-09 锚点）：不做解析
        return None, {
            "ref": ref,
            "reason": REASON_NAME_FRAGMENT,
            "message": "仅支持 JSON Pointer 片段（#/...），不支持锚点名称片段",
        }

    tokens = _decode_pointer_fragment(fragment[1:])
    if tokens is None:
        return None, {
            "ref": ref,
            "reason": REASON_MALFORMED_POINTER,
            "message": "非法 JSON Pointer：~ 后只能为 0 或 1",
        }

    ok, failed_segment = _resolve_pointer(root, tokens)
    if not ok:
        return None, {
            "ref": ref,
            "reason": REASON_TARGET_NOT_FOUND,
            "message": (
                f"引用目标 {_build_pointer(tokens)} 在路径段 "
                f"{_escape_token(failed_segment)!r} 处不存在"
            ),
        }

    return _build_pointer(tokens), None


# ---------------------------------------------------------------------------
# Schema 树遍历：只沿子 schema 关键字递归，收集 $defs 节点、引用边与无效引用
# ---------------------------------------------------------------------------


def _join(pointer: str, *tokens: str) -> str:
    """把已解码路径段依次拼到父指针之后（根指针为 ``#``）。"""
    suffix = "/".join(_escape_token(token) for token in tokens)
    return f"#/{suffix}" if pointer == "#" else f"{pointer}/{suffix}"


def _collect_definitions(
    schema: Any,
    pointer: str,
    top_level: bool,
    def_nodes: list[dict],
) -> None:
    """登记 ``schema`` **本层**定义容器（``$defs`` / ``definitions``）的成员。

    只登记直接命名成员；成员内部嵌套的容器在该成员被递归遍历时自行登记，
    以保证每个定义节点恰好登记一次。``top_level`` 仅对文档根直接下属的
    容器成员为 True。
    """
    if not isinstance(schema, dict):
        return
    for container in _DEFINITION_KEYWORDS:
        defs = schema.get(container)
        if not isinstance(defs, dict):
            continue
        for name in defs:
            def_nodes.append(
                {
                    "pointer": _join(pointer, container, name),
                    "name": name,
                    "top_level": top_level,
                }
            )


def _walk_schema(
    schema: Any,
    pointer: str,
    root: Any,
    def_nodes: list[dict],
    edges: list[dict],
    invalid_refs: list[dict],
) -> None:
    """沿 JSON Schema 子 schema 关键字递归，统一收集定义节点与引用。

    只递归白名单内的子 schema 关键字；``const`` / ``enum`` / ``default``
    / ``examples`` 等实例数据及 ``x-`` 等未知扩展值整体视为数据，不下钻
    ——其中同名字段（``$ref``、``$defs`` 等）不会产生伪引用或伪定义。
    布尔 schema（``true`` / ``false``）是叶子，无子结构。
    """
    if not isinstance(schema, dict):
        return

    # 先登记本层定义容器（容器本身不是引用位置，其成员仍是子 schema）
    _collect_definitions(schema, pointer, pointer == "#", def_nodes)

    for key, value in schema.items():
        child_pointer = _join(pointer, key)

        if key == "$ref":
            target, invalid = _classify_ref(root, value)
            if invalid is not None:
                invalid_refs.append({"source": pointer, **invalid})
            else:
                edges.append({"source": pointer, "ref": value, "target": target})
            # $ref 的取值本身（字符串）不是 schema 节点，不再下钻
            continue

        if key in _DEFINITION_KEYWORDS:
            # 命名成员已在 _collect_definitions 中登记；继续递归成员子树
            if isinstance(value, dict):
                for name, member in value.items():
                    _walk_schema(
                        member,
                        _join(pointer, key, name),
                        root,
                        def_nodes,
                        edges,
                        invalid_refs,
                    )
            continue

        if key in _SINGLE_SUBSCHEMA_KEYWORDS:
            _walk_schema(value, child_pointer, root, def_nodes, edges, invalid_refs)
            continue

        if key in _SUBSCHEMA_MAP_KEYWORDS:
            if isinstance(value, dict):
                for name, member in value.items():
                    _walk_schema(
                        member,
                        _join(pointer, key, name),
                        root,
                        def_nodes,
                        edges,
                        invalid_refs,
                    )
            continue

        if key in _SUBSCHEMA_ARRAY_KEYWORDS:
            if isinstance(value, list):
                for index, member in enumerate(value):
                    _walk_schema(
                        member,
                        f"{child_pointer}/{index}",
                        root,
                        def_nodes,
                        edges,
                        invalid_refs,
                    )
            continue

        if key == "items":
            # schema 形态（draft 2020-12 / 单元素 items）与
            # draft-04/06/07 元组形态（子 schema 数组）都要递归
            if isinstance(value, list):
                for index, member in enumerate(value):
                    _walk_schema(
                        member,
                        f"{child_pointer}/{index}",
                        root,
                        def_nodes,
                        edges,
                        invalid_refs,
                    )
            else:
                _walk_schema(
                    value, child_pointer, root, def_nodes, edges, invalid_refs
                )
            continue

        if key == "dependencies":
            # draft-04/06/07：成员为数组 = 属性名依赖（数据，跳过）；
            # 成员为 schema（对象或布尔）= schema 依赖（子 schema）
            if isinstance(value, dict):
                for name, member in value.items():
                    if isinstance(member, (dict, bool)):
                        _walk_schema(
                            member,
                            _join(pointer, "dependencies", name),
                            root,
                            def_nodes,
                            edges,
                            invalid_refs,
                        )
            continue

        # 其余关键字（const / enum / default / examples、普通注解、
        # type / required 及 x- 未知扩展等）的值都是数据，不下钻。


# ---------------------------------------------------------------------------
# $defs 节点粒度的引用图：可达性与循环
# ---------------------------------------------------------------------------


def _nearest_def(segments: list[str], def_pointers: set[str]) -> str | None:
    """路径段所属的最近 ``$defs`` 节点指针；不在任何定义子树返回 None。"""
    for end in range(len(segments), 0, -1):
        prefix = _build_pointer(segments[:end])
        if prefix in def_pointers:
            return prefix
    return None


def _def_graph(
    edges: list[dict], def_pointers: set[str]
) -> tuple[dict[str, str], dict[str, int]]:
    """把引用边折叠到 ``$defs`` 节点粒度（含顶层与嵌套定义）的有向图。

    仅供循环检测使用：源在某 $defs 节点子树内、且目标**恰好**是某 $defs
    节点根的边才构成图的出边（指向定义内部子 schema 的边不产生定义间的
    环）；一个节点有多条出边时记录源路径最浅者（定义对象**自身**的
    ``$ref``）为代表边。

    可达性的种子与传播按"已解析目标所属的最近定义节点"处理，见
    :func:`_reachable_defs`，不使用本函数。

    返回 ``(节点代表出边, 代表边的源相对深度)``。
    """
    def_out: dict[str, str] = {}
    source_depth: dict[str, int] = {}
    for edge in edges:
        source_segments = _pointer_segments(edge["source"])
        source_def = _nearest_def(source_segments, def_pointers)
        target_def = edge["target"] if edge["target"] in def_pointers else None
        if source_def is None or target_def is None:
            continue
        depth = len(source_segments) - len(_pointer_segments(source_def))
        if source_def not in source_depth or depth < source_depth[source_def]:
            source_depth[source_def] = depth
            def_out[source_def] = target_def
    return def_out, source_depth


def _reachable_defs(edges: list[dict], def_pointers: set[str]) -> set[str]:
    """在 $defs 节点粒度上做 BFS，返回从根侧可达的节点指针集合。

    每条引用边对可达性的贡献按**所属最近定义节点**折叠：

    * **种子**：源在所有 $defs 节点之外（根侧结构）的边，其已解析目标
      落在哪个定义子树内（目标本身是定义根，或定义内部的子 schema，如
      ``#/$defs/User/properties/name``），该目标所属的最近定义即为种子；
    * **传播**：从已到达的定义节点**自身子树内**（不含其嵌套 $defs 子
      节点的子树）发出的边，把已解析目标所属的最近定义标记为可达；
    * 直接引用嵌套定义内层节点（如
      ``#/$defs/outer/$defs/Inner/properties/x``）只标记 Inner，**不顺带**
      标记包裹它的外层定义。
    """
    # 预折叠：(源所属定义 or None, 目标所属定义 or None)；None 源 = 根侧
    folded: list[tuple[str | None, str | None]] = []
    for edge in edges:
        source_def = _nearest_def(_pointer_segments(edge["source"]), def_pointers)
        target_def = _nearest_def(_pointer_segments(edge["target"]), def_pointers)
        folded.append((source_def, target_def))

    reached: set[str] = set()
    queue: deque[str] = deque()

    def mark(node: str | None) -> None:
        if node is not None and node not in reached:
            reached.add(node)
            queue.append(node)

    # 根侧边：目标落入任何定义子树即为可达种子
    for source_def, target_def in folded:
        if source_def is None:
            mark(target_def)

    while queue:
        owner = queue.popleft()
        for source_def, target_def in folded:
            if source_def == owner:
                mark(target_def)
    return reached


def _find_cycles(edges: list[dict], def_pointers: set[str]) -> list[dict]:
    """找出全部引用循环链（确定性、去重）。

    循环分两类：

    * **定义节点之间的环**：沿每个节点的代表出边（自身 ``$ref`` 优先）
      追踪，自环（树节点内部引用自身定义）与多节点互引均检出；
    * **根侧自指**：$defs 之外的节点引用文档根 ``#`` 形成的自环。

    每个节点至多一条代表出边，沿出边追踪至多落入一个环；以"环上最小
    指针旋转到链首"规范化，使同一环只报一次且与遍历起点无关。
    """
    def_out, _ = _def_graph(edges, def_pointers)
    root_self_sources = sorted(
        edge["source"]
        for edge in edges
        if _nearest_def(_pointer_segments(edge["source"]), def_pointers) is None
        and edge["target"] == "#"
    )

    cycles: dict[tuple[str, ...], list[str]] = {}

    for start in sorted(def_out):
        order: list[str] = []
        positions: dict[str, int] = {}
        current = start
        while current in def_out and current not in positions:
            positions[current] = len(order)
            order.append(current)
            current = def_out[current]
        if current in positions:
            cycle = order[positions[current]:]
            pivot = min(range(len(cycle)), key=cycle.__getitem__)
            canonical = tuple(cycle[pivot:] + cycle[:pivot])
            cycles.setdefault(canonical, list(canonical) + [canonical[0]])

    for source in root_self_sources:
        chain = [source, "#"]
        cycles.setdefault(tuple(chain), chain)

    return [{"chain": chain} for chain in sorted(cycles.values())]


# ---------------------------------------------------------------------------
# 对外入口
# ---------------------------------------------------------------------------


def analyze_references(schema: dict[str, Any]) -> dict:
    """诊断单份 JSON Schema 的内部 ``$ref`` 依赖（纯函数，不修改入参）。"""
    edges: list[dict] = []
    invalid_refs: list[dict] = []
    def_nodes: list[dict] = []

    _walk_schema(schema, "#", schema, def_nodes, edges, invalid_refs)

    edges.sort(key=lambda edge: (edge["source"], edge["target"]))
    invalid_refs.sort(key=lambda item: (item["source"], str(item.get("ref") or "")))

    def_pointers = {node["pointer"] for node in def_nodes}
    reached = _reachable_defs(edges, def_pointers)

    unreachable: list[dict] = sorted(
        (
            {"pointer": node["pointer"], "name": node["name"]}
            for node in def_nodes
            if node["pointer"] not in reached
        ),
        key=lambda node: node["pointer"],
    )

    cycles = _find_cycles(edges, def_pointers)

    return {
        "counts": {
            "refs": len(edges) + len(invalid_refs),
            "edges": len(edges),
            "invalid_refs": len(invalid_refs),
            "unreachable_defs": len(unreachable),
            "cycles": len(cycles),
        },
        "edges": edges,
        "invalid_refs": invalid_refs,
        "unreachable_defs": unreachable,
        "cycles": cycles,
    }
