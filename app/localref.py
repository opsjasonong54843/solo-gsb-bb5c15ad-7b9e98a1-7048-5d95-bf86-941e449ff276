"""本地 ``$ref`` 指针解析的共用组件。

兼容性分析（:mod:`app.compat`）、引用依赖诊断（:mod:`app.refgraph`）与
实例脱敏（:mod:`app.redact`）三个入口共用同一套解析逻辑，保证同一条
``$ref`` 在三处定位到**同一个节点**，且对非法引用的判定一致。

只接受**片段形式的本地引用**（``#`` 与 ``#/...``），绝不访问网络或外部
文件：

* ``#`` —— 指向文档根；
* ``#/<JSON Pointer>`` —— 按 RFC 6901 在本文档内解析。

解析顺序（RFC 3986 fragment + RFC 6901）：

1. **先按 URI 片段中的原始斜杠切段**（``%2F`` 是键名中的字面斜杠，
   不做分隔符）；
2. 再对每段做百分号解码（``%2F`` → ``/``）并还原 JSON Pointer 转义
   （``~1`` → ``/``、``~0`` → ``~``）；
3. 严格解析数组下标：``0`` 合法、带前导零（``01``）非法、``-`` 指向
   末位后的不存在成员、越界非法。

成功时返回**规范化目标指针**（解码后的键名按 ``~0`` / ``~1`` 重新转义，
故 ``#/$defs/a%2Fb`` 与 ``#/$defs/a~1b`` 归一为同一指针）；失败时返回
结构化的失败原因（:class:`ReferenceError`），由各入口自行降级：

* 兼容性分析 —— 无法解析的本地引用按无约束节点处理（外部引用原样保留，
  最终由原始 schema 校验器把关）；
* 引用依赖诊断 —— 记录一条 ``invalid_refs`` 诊断条目；
* 实例脱敏 —— 抛出异常，由接口层转为 ``422``。
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import unquote

# 不可用引用的原因代码（三个入口共用同一套词汇）
REASON_EXTERNAL = "external_reference"
REASON_NAME_FRAGMENT = "name_fragment_unsupported"
REASON_TARGET_NOT_FOUND = "target_not_found"
REASON_MALFORMED_POINTER = "malformed_pointer"
REASON_NON_STRING = "non_string_ref"

# RFC 6901 合法数组下标：纯 ASCII 数字且不允许前导零（"0" 除外）
_ARRAY_INDEX = re.compile(r"^(0|[1-9][0-9]*)$")


# ---------------------------------------------------------------------------
# JSON Pointer 基础工具
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


def locate(root: Any, tokens: list[str]) -> tuple[Any, str | None]:
    """按解码后的 JSON Pointer 段在文档内定位目标节点。

    返回 ``(节点, 失败段)``：成功时失败段为 ``None``；目标不存在时给出
    首个无法解析的路径段（已解码原文）。数组下标遵循 RFC 6901：``0``
    合法、带前导零非法、``-`` 指向末位后的不存在成员、越界非法。
    """
    node = root
    for token in tokens:
        if isinstance(node, dict):
            if token in node:
                node = node[token]
            else:
                return None, token
        elif isinstance(node, list):
            if not _ARRAY_INDEX.match(token):
                # "-"、前导零与非数字都不是可定位的数组成员
                return None, token
            index = int(token)
            if index >= len(node):
                return None, token
            node = node[index]
        else:
            return None, token
    return node, None


def resolve_pointer(root: Any, tokens: list[str]) -> tuple[bool, str]:
    """``locate`` 的布尔形态：返回 ``(是否成功, 失败段)``（失败段成功时为空串）。"""
    _, failed = locate(root, tokens)
    return failed is None, (failed or "")


def node_at_pointer(root: Any, pointer: str) -> Any:
    """按**规范化后的**本地指针取节点（``#`` 为根）。

    调用方须保证指针来自 :func:`resolve_local_ref` 的成功结果，因此不做
    失败处理。
    """
    node = root
    for token in pointer_segments(pointer):
        if isinstance(node, dict):
            node = node[token]
        else:
            node = node[int(token)]
    return node


# ---------------------------------------------------------------------------
# 本地 $ref 分类
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ResolvedRef:
    """解析成功的本地引用。"""

    target: str          # 规范化目标指针（``#`` / ``#/...``）
    node: Any            # 目标节点（文档内存中的同一对象）


@dataclass(frozen=True)
class ReferenceError:
    """无法解析为本地 JSON Pointer 目标的引用。"""

    ref: str | None
    reason: str
    message: str


def _invalid(ref: str | None, reason: str, message: str) -> ReferenceError:
    return ReferenceError(ref=ref, reason=reason, message=message)


def resolve_local_ref(root: Any, ref: Any) -> ResolvedRef | ReferenceError:
    """分类单个 ``$ref`` 取值：解析为文档内目标，或给出明确失败原因。

    成功返回 :class:`ResolvedRef`（含规范化目标指针与目标节点）；其余
    情况返回 :class:`ReferenceError`（非字符串 / 外部引用 / 名称片段 /
    非法指针转义 / 目标不存在）。
    """
    if not isinstance(ref, str):
        return _invalid(
            None,
            REASON_NON_STRING,
            f"$ref 必须是字符串，实际类型为 {type(ref).__name__}",
        )

    before, separator, fragment = ref.partition("#")
    if before or not separator:
        # 非片段形式（http(s)://、相对文件路径、裸名称等）：一律不访问
        return _invalid(
            ref,
            REASON_EXTERNAL,
            "仅接受片段形式的本地引用（# 或 #/...），不访问网络或外部文件",
        )

    if fragment == "":
        # "#"：指向文档根
        return ResolvedRef(target="#", node=root)

    if not fragment.startswith("/"):
        # "#anchor" 之类的名称片段（draft 2019-09 锚点）：不做解析
        return _invalid(
            ref,
            REASON_NAME_FRAGMENT,
            "仅支持 JSON Pointer 片段（#/...），不支持锚点名称片段",
        )

    tokens = decode_pointer_fragment(fragment[1:])
    if tokens is None:
        return _invalid(
            ref,
            REASON_MALFORMED_POINTER,
            "非法 JSON Pointer：~ 后只能为 0 或 1",
        )

    node, failed_segment = locate(root, tokens)
    if failed_segment is not None:
        return _invalid(
            ref,
            REASON_TARGET_NOT_FOUND,
            f"引用目标 {build_pointer(tokens)} 在路径段 "
            f"{escape_token(failed_segment)!r} 处不存在",
        )

    return ResolvedRef(target=build_pointer(tokens), node=node)
