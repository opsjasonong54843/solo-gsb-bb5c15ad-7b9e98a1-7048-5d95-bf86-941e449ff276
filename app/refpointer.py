"""本地 ``$ref`` 指针解析共用组件（纯函数，不访问网络 / 外部文件）。

兼容性分析（:mod:`app.compat`）、引用依赖诊断（:mod:`app.refgraph`）与
实例脱敏（:mod:`app.redact`）三个入口共用同一份文档内 ``$ref`` 解析
逻辑，保证**同一引用在三个入口定位到同一节点**：

* 只接受**片段形式的本地引用**（``#`` 与 ``#/...`` JSON Pointer，
  RFC 6901），``http(s)://…``、相对文件路径、裸名称一律视为外部引用，
  绝不尝试解析；
* 片段先按**原始斜杠**分段（``%2F`` 是键名中的字面斜杠，不做分隔符），
  再逐段**百分号解码**、还原 ``~1`` / ``~0`` 转义（``~`` 后只能是
  ``0`` 或 ``1``，其余为非法指针）；
* **数组下标严格遵循 RFC 6901**：``0`` 合法、带前导零（``01``）非法、
  ``-`` 指向不存在的末位后成员（视为解析失败）；
* 成功时返回**规范化目标指针**（``~0`` / ``~1`` 归一、根为 ``#``），
  失败时返回明确的原因代码与首个无法解析的路径段。

各入口在同一份解析结果上沿用各自的降级策略：兼容性分析把不可解析的
本地引用按无约束（``true``）降级，引用依赖诊断输出 ``invalid_refs``
诊断条目，实例脱敏抛出异常由接口层转为 ``422``。``$ref`` 与同级关键字
的 Draft 方言语义（2019-09/2020-12 合取 vs Draft-07 及更早纯跳转）不
属于本组件，由 :mod:`app.compat` 的方言判定统一决定。
"""
from __future__ import annotations

from typing import Any
from urllib.parse import unquote

# 不可用引用的原因代码
REASON_EXTERNAL = "external_reference"
REASON_NAME_FRAGMENT = "name_fragment_unsupported"
REASON_TARGET_NOT_FOUND = "target_not_found"
REASON_MALFORMED_POINTER = "malformed_pointer"
REASON_NON_STRING = "non_string_ref"


# ---------------------------------------------------------------------------
# JSON Pointer 段编解码
# ---------------------------------------------------------------------------


def escape_token(token: str) -> str:
    """JSON Pointer 段编码：``~`` -> ``~0``、``/`` -> ``~1``。"""
    return token.replace("~", "~0").replace("/", "~1")


def build_pointer(tokens: list[str]) -> str:
    """由解码后的路径段构造规范化 JSON Pointer 字符串（根为 ``#``）。"""
    if not tokens:
        return "#"
    return "#/" + "/".join(escape_token(token) for token in tokens)


def pointer_segments(pointer: str) -> list[str]:
    """拆分已规范化的指针字符串为解码后的路径段（根 ``#`` 为空列表）。"""
    if pointer == "#":
        return []
    return [
        seg.replace("~1", "/").replace("~0", "~")
        for seg in pointer[2:].split("/")
    ]


def decode_pointer_fragment(fragment: str) -> list[str] | None:
    """解码 URI fragment 中的 JSON Pointer（fragment 不含前导 ``#/``）。

    先按**原始 ``/``** 切段（``%2F`` 是键名中的字面斜杠，不做分隔符），
    再逐段百分号解码并还原 ``~1`` / ``~0`` 转义。非法 ``~`` 转义
    （``~`` 后不是 ``0`` / ``1``）返回 ``None``。
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


# ---------------------------------------------------------------------------
# 文档内解析
# ---------------------------------------------------------------------------


def resolve_tokens(root: Any, tokens: list[str]) -> tuple[bool, Any, str]:
    """按解码后的路径段在文档内解析目标。

    返回 ``(是否成功, 目标节点, 失败段)``：成功时失败段为空字符串；
    失败时给出首个无法解析的路径段（已解码原文）。数组下标遵循 RFC 6901
    （``0`` 合法、带前导零非法、``-`` 指向不存在的末位后成员）。
    """
    node = root
    for token in tokens:
        if isinstance(node, dict):
            if token in node:
                node = node[token]
            else:
                return False, None, token
        elif isinstance(node, list):
            if token == "-" or not token.isdigit() or (
                len(token) > 1 and token.startswith("0")
            ):
                return False, None, token
            index = int(token)
            if index >= len(node):
                return False, None, token
            node = node[index]
        else:
            # 标量 / null 上继续取成员：无法解析
            return False, None, token
    return True, node, ""


def node_at_pointer(root: Any, pointer: str) -> Any:
    """按规范化后的本地指针取节点（``#`` 为根；调用方保证指针可解析）。

    指针通常来自 :func:`classify_ref` 成功返回的规范化目标。
    """
    node = root
    for segment in pointer_segments(pointer):
        node = node[segment] if isinstance(node, dict) else node[int(segment)]
    return node


def classify_ref(root: Any, ref: Any) -> tuple[str | None, dict | None]:
    """分类单个 ``$ref`` 取值，返回 ``(规范化目标指针, 无效条目)``。

    二者恰有一个非 None：可解析的本地 Pointer 引用返回规范化目标指针；
    其余情况返回不含 source 的不可用条目（由调用方补上 source）。
    解析规则见模块 docstring（原始斜杠分段、百分号 / ``~0`` / ``~1``
    解码、严格数组下标）。
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

    tokens = decode_pointer_fragment(fragment[1:])
    if tokens is None:
        return None, {
            "ref": ref,
            "reason": REASON_MALFORMED_POINTER,
            "message": "非法 JSON Pointer：~ 后只能为 0 或 1",
        }

    ok, _node, failed_segment = resolve_tokens(root, tokens)
    if not ok:
        return None, {
            "ref": ref,
            "reason": REASON_TARGET_NOT_FOUND,
            "message": (
                f"引用目标 {build_pointer(tokens)} 在路径段 "
                f"{escape_token(failed_segment)!r} 处不存在"
            ),
        }

    return build_pointer(tokens), None
