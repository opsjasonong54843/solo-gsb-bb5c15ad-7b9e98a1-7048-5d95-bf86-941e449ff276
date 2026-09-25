"""基线对比引擎（app.compare）单元测试。"""
import itertools

from app import compare


def make_issue(direction="backward", path="#", code="required_added",
               severity="error", message="m", reason="r"):
    return {
        "direction": direction, "path": path, "code": code,
        "severity": severity, "message": message, "reason": reason,
        "counterexample": None, "counterexample_path": None,
    }


def make_report(issues, backward_compatible=True, forward_compatible=True):
    def summarize(direction):
        subset = [i for i in issues if i["direction"] == direction]
        return {
            "errors": sum(1 for i in subset if i["severity"] == "error"),
            "warnings": sum(1 for i in subset if i["severity"] == "warning"),
            "total": len(subset),
        }

    return {
        "backward_compatible": backward_compatible,
        "forward_compatible": forward_compatible,
        "summary": {
            "backward": summarize("backward"),
            "forward": summarize("forward"),
            "total": len(issues),
            "errors": sum(1 for i in issues if i["severity"] == "error"),
            "warnings": sum(1 for i in issues if i["severity"] == "warning"),
        },
        "issues": issues,
    }


class TestNormalizeReason:
    def test_collapses_whitespace(self):
        assert compare.normalize_reason("  枚举值 \n 已移除\t") == "枚举值 已移除"

    def test_none_becomes_empty(self):
        assert compare.normalize_reason(None) == ""

    def test_strips_heuristic_suffix(self):
        from app.compat import HEURISTIC_SUFFIX
        base = "旧版未限制为整数，小数值在新版会被拒绝"
        assert compare.normalize_reason(base + HEURISTIC_SUFFIX) == compare.normalize_reason(base)


class TestIssueFingerprint:
    def test_stable_for_same_issue(self):
        issue = make_issue()
        assert compare.issue_fingerprint(issue) == compare.issue_fingerprint(dict(issue))

    def test_ignores_whitespace_jitter_in_reason(self):
        a = make_issue(reason="旧版允许类型 integer")
        b = make_issue(reason="  旧版允许类型\ninteger  ")
        assert compare.issue_fingerprint(a) == compare.issue_fingerprint(b)

    def test_ignores_heuristic_suffix(self):
        from app.compat import HEURISTIC_SUFFIX
        a = make_issue(reason="旧版未限制为整数，小数值在新版会被拒绝")
        b = make_issue(reason="旧版未限制为整数，小数值在新版会被拒绝" + HEURISTIC_SUFFIX)
        assert compare.issue_fingerprint(a) == compare.issue_fingerprint(b)

    def test_ignores_severity(self):
        a = make_issue(severity="error")
        b = make_issue(severity="warning")
        assert compare.issue_fingerprint(a) == compare.issue_fingerprint(b)

    def test_sensitive_to_direction_path_code_reason(self):
        base = make_issue()
        base_fp = compare.issue_fingerprint(base)
        assert compare.issue_fingerprint(make_issue(direction="forward")) != base_fp
        assert compare.issue_fingerprint(make_issue(path="#/properties/a")) != base_fp
        assert compare.issue_fingerprint(make_issue(code="type_removed")) != base_fp
        assert compare.issue_fingerprint(make_issue(reason="其他原因")) != base_fp

    def test_hex_prefix_format(self):
        fp = compare.issue_fingerprint(make_issue())
        assert len(fp) == 16
        int(fp, 16)  # 合法十六进制


class TestCompareReports:
    def test_classifies_all_four_categories(self):
        shared = make_issue(path="#/properties/a", code="min_length_increased",
                            reason="minLength 从 0 提高到 2")
        fixed_issue = make_issue(path="#", code="required_added",
                                 reason="旧版中 'b' 可以缺省")
        added_issue = make_issue(path="#", code="required_added",
                                 reason="旧版中 'c' 可以缺省")
        sev_base = make_issue(path="#", code="integer_required", severity="error",
                              reason="旧版未限制为整数")
        sev_cur = make_issue(path="#", code="integer_required", severity="warning",
                             reason="旧版未限制为整数")

        baseline = make_report([shared, fixed_issue, sev_base],
                               backward_compatible=False)
        current = make_report([shared, added_issue, sev_cur],
                              backward_compatible=False)

        result = compare.compare_reports(baseline, current)

        assert result["counts"] == {"added": 1, "fixed": 1, "persisting": 1,
                                    "severity_changed": 1}
        assert result["issues"]["added"][0]["reason"] == "旧版中 'c' 可以缺省"
        assert result["issues"]["fixed"][0]["reason"] == "旧版中 'b' 可以缺省"
        assert result["issues"]["persisting"][0]["code"] == "min_length_increased"
        changed = result["issues"]["severity_changed"][0]
        assert changed["baseline_severity"] == "error"
        assert changed["current_severity"] == "warning"
        assert changed["fingerprint"] == compare.issue_fingerprint(sev_base)

    def test_multiset_matching_by_occurrence(self):
        issue = make_issue()
        baseline = make_report([dict(issue), dict(issue)])  # 同指纹出现两次
        current = make_report([dict(issue)])
        result = compare.compare_reports(baseline, current)
        assert result["counts"]["persisting"] == 1
        assert result["counts"]["fixed"] == 1

    def test_interleaved_severities_pair_as_persisting(self):
        # 同一指纹：基线 error, warning；当前 warning, error（顺序交错）。
        # 严重级别多重集相同，必须全部配为 persisting，不能按出现顺序
        # 误报两条 severity_changed（即使错误 / 警告总数均未变化）。
        same = dict(path="#/properties/x", code="required_added", reason="r")
        baseline = make_report([
            make_issue(severity="error", **same),
            make_issue(severity="warning", **same),
        ])
        current = make_report([
            make_issue(severity="warning", **same),
            make_issue(severity="error", **same),
        ])

        result = compare.compare_reports(baseline, current)

        assert result["counts"] == {"added": 0, "fixed": 0, "persisting": 2,
                                    "severity_changed": 0}
        assert result["issues"]["severity_changed"] == []
        assert {i["severity"] for i in result["issues"]["persisting"]} == {
            "error", "warning"}
        # 总数不变 -> errors / warnings / total 的 delta 均为 0
        assert result["summary_diff"]["errors"]["delta"] == 0
        assert result["summary_diff"]["warnings"]["delta"] == 0
        assert result["summary_diff"]["total"]["delta"] == 0

    def test_interleaved_severities_with_real_change_and_extra(self):
        # 同一指纹的交错多重集，且夹带真实变化与数量差：
        # 基线 error×2, warning；当前 error, warning×2（先配同级别：
        # 1 error + 1 warning persisting，剩余 1 error↔1 warning 变化），
        # 当前还多出 1 warning -> added。
        same = dict(path="#/properties/y", code="type_removed", reason="r")
        baseline = make_report([
            make_issue(severity="error", **same),
            make_issue(severity="error", **same),
            make_issue(severity="warning", **same),
        ])
        current = make_report([
            make_issue(severity="warning", **same),
            make_issue(severity="error", **same),
            make_issue(severity="warning", **same),
            make_issue(severity="warning", **same),
        ])

        result = compare.compare_reports(baseline, current)

        assert result["counts"] == {"added": 1, "fixed": 0, "persisting": 2,
                                    "severity_changed": 1}
        changed = result["issues"]["severity_changed"]
        assert len(changed) == 1
        assert changed[0]["baseline_severity"] == "error"
        assert changed[0]["current_severity"] == "warning"
        assert result["issues"]["added"][0]["severity"] == "warning"
        assert result["summary_diff"]["errors"]["delta"] == -1
        assert result["summary_diff"]["warnings"]["delta"] == 2

    def test_interleaved_severities_extra_baseline_is_fixed(self):
        # 基线 error, warning；当前仅 warning：同级别 warning persisting，
        # 基线多出的 error 归 fixed（不应算作 severity_changed）。
        same = dict(path="#/properties/z", reason="r")
        baseline = make_report([
            make_issue(severity="error", **same),
            make_issue(severity="warning", **same),
        ])
        current = make_report([make_issue(severity="warning", **same)])

        result = compare.compare_reports(baseline, current)

        assert result["counts"] == {"added": 0, "fixed": 1, "persisting": 1,
                                    "severity_changed": 0}
        assert result["issues"]["fixed"][0]["severity"] == "error"

    def test_identical_reports_all_persisting(self):
        report = make_report([make_issue(), make_issue(code="enum_value_removed")])
        result = compare.compare_reports(report, report)
        assert result["counts"]["persisting"] == 2
        assert result["counts"]["added"] == 0
        assert result["counts"]["fixed"] == 0
        assert result["counts"]["severity_changed"] == 0

    def test_compatibility_and_summary_diff(self):
        baseline = make_report(
            [make_issue(severity="error"), make_issue(code="x", severity="warning")],
            backward_compatible=False, forward_compatible=True)
        current = make_report([], backward_compatible=True, forward_compatible=True)
        result = compare.compare_reports(baseline, current)

        compat = result["compatibility"]
        assert compat["backward"] == {"baseline": False, "current": True, "changed": True}
        assert compat["forward"] == {"baseline": True, "current": True, "changed": False}

        diff = result["summary_diff"]
        assert diff["errors"] == {"baseline": 1, "current": 0, "delta": -1}
        assert diff["warnings"] == {"baseline": 1, "current": 0, "delta": -1}
        assert diff["total"] == {"baseline": 2, "current": 0, "delta": -2}
        assert diff["backward"]["errors"]["delta"] == -1
        assert diff["forward"]["errors"] == {"baseline": 0, "current": 0, "delta": 0}

    def test_does_not_mutate_reports(self):
        baseline = make_report([make_issue()])
        current = make_report([make_issue(code="other")])
        baseline_snapshot = repr(baseline)
        current_snapshot = repr(current)
        compare.compare_reports(baseline, current)
        assert repr(baseline) == baseline_snapshot
        assert repr(current) == current_snapshot

    def test_empty_reports(self):
        result = compare.compare_reports(make_report([]), make_report([]))
        assert result["counts"] == {"added": 0, "fixed": 0, "persisting": 0,
                                    "severity_changed": 0}
        assert result["summary_diff"]["total"]["delta"] == 0


class TestConditionalIssues:
    """条件分支 issue 的指纹与分类。"""

    def test_conditional_path_participates_in_fingerprint(self):
        base = make_issue(path="#/then", code="required_added")
        assert compare.issue_fingerprint(base) != compare.issue_fingerprint(
            make_issue(path="#/else", code="required_added"))
        assert compare.issue_fingerprint(base) != compare.issue_fingerprint(
            make_issue(path="#", code="required_added"))

    def test_conditional_severity_change_classified(self):
        from app.compat import HEURISTIC_SUFFIX
        reason = "旧版中 'y' 可以缺省，新版 required 包含该字段"
        baseline = make_report([make_issue(
            path="#/then", code="required_added", severity="warning",
            reason=reason + HEURISTIC_SUFFIX)])
        current = make_report([make_issue(
            path="#/then", code="required_added", severity="error", reason=reason)])
        result = compare.compare_reports(baseline, current)
        assert result["counts"]["severity_changed"] == 1
        changed = result["issues"]["severity_changed"][0]
        assert changed["path"] == "#/then"
        assert changed["baseline_severity"] == "warning"
        assert changed["current_severity"] == "error"


class TestCanonicalOrdering:
    """重复 issue 的规范次序：配对与输出均与报告内出现顺序无关。"""

    def test_duplicate_same_severity_pairs_canonically(self):
        # 同一指纹 + 同一级别、仅 message 不同的重复记录（含完全重复项）：
        # 桶内按规范次序 FIFO 配对，数量持平部分全部 persisting（重复条目
        # 分别保留、不被合并），多出的记录按规范次序靠后者归入 fixed / added
        baseline_issues = [
            make_issue(message="m3"), make_issue(message="m1"),
            make_issue(message="m2"), make_issue(message="m2"),
        ]
        current_issues = [
            make_issue(message="m2"), make_issue(message="m1"),
            make_issue(message="m2"),
        ]
        result = compare.compare_reports(
            make_report(baseline_issues), make_report(current_issues))

        assert result["counts"] == {"added": 0, "fixed": 1, "persisting": 3,
                                    "severity_changed": 0}
        assert [i["message"] for i in result["issues"]["persisting"]] == [
            "m1", "m2", "m2"]
        assert [i["message"] for i in result["issues"]["fixed"]] == ["m3"]

        # 镜像：交换基线 / 当前，同一批多出的记录归入 added
        result = compare.compare_reports(
            make_report(current_issues), make_report(baseline_issues))
        assert result["counts"] == {"added": 1, "fixed": 0, "persisting": 3,
                                    "severity_changed": 0}
        assert [i["message"] for i in result["issues"]["persisting"]] == [
            "m1", "m2", "m2"]
        assert [i["message"] for i in result["issues"]["added"]] == ["m3"]

    def test_duplicates_output_independent_of_input_order(self):
        # 任意交换两份报告内重复记录的顺序，四类数组（内容与顺序）必须
        # 完全一致——这是本次修复的核心稳定性保证
        baseline_issues = [
            make_issue(severity="error", message="x1"),
            make_issue(severity="error", message="x2"),
            make_issue(severity="warning", message="x3"),
            make_issue(code="other", severity="error", message="y1"),
        ]
        current_issues = [
            make_issue(severity="warning", message="x5"),
            make_issue(severity="error", message="x2"),
            make_issue(severity="warning", message="x4"),
            make_issue(code="third", severity="warning", message="z1"),
        ]
        baseline = make_report(baseline_issues)
        current = make_report(current_issues)
        expected = compare.compare_reports(baseline, current)

        # 基线 error[x1,x2] + warning[x3]；当前 error[x2] + warning[x4,x5]
        assert expected["counts"] == {"added": 1, "fixed": 1,
                                      "persisting": 2, "severity_changed": 1}
        persisting = expected["issues"]["persisting"]
        assert [i["message"] for i in persisting] == ["x2", "x4"]
        changed = expected["issues"]["severity_changed"]
        assert [(i["baseline_severity"], i["current_severity"], i["message"])
                for i in changed] == [("error", "warning", "x5")]
        assert [i["message"] for i in expected["issues"]["fixed"]] == ["y1"]
        assert [i["message"] for i in expected["issues"]["added"]] == ["z1"]

        for b_perm in itertools.permutations(baseline_issues):
            for c_perm in itertools.permutations(current_issues):
                result = compare.compare_reports(
                    make_report(list(b_perm)), make_report(list(c_perm)))
                assert result == expected

    def test_cross_severity_duplicates_pair_canonically(self):
        # 基线 error×2、当前 warning×2，message 各不同：跨级别配对按
        # 规范次序逐条对应，与报告内顺序无关，两条变化均保留
        baseline_issues = [
            make_issue(severity="error", message="m2"),
            make_issue(severity="error", message="m1"),
        ]
        current_issues = [
            make_issue(severity="warning", message="m4"),
            make_issue(severity="warning", message="m3"),
        ]
        result = compare.compare_reports(
            make_report(baseline_issues), make_report(current_issues))

        assert result["counts"] == {"added": 0, "fixed": 0, "persisting": 0,
                                    "severity_changed": 2}
        changed = result["issues"]["severity_changed"]
        assert [i["message"] for i in changed] == ["m3", "m4"]
        assert [(i["baseline_severity"], i["current_severity"]) for i in changed] == [
            ("error", "warning"), ("error", "warning")]

        for b_perm in itertools.permutations(baseline_issues):
            for c_perm in itertools.permutations(current_issues):
                again = compare.compare_reports(
                    make_report(list(b_perm)), make_report(list(c_perm)))
                assert again == result

    def test_severity_changed_sorted_by_severity_combination(self):
        # 同一指纹剩余的跨级别记录按（基线级别, 当前级别）组合确定性排序：
        # error->info 排在 warning->notice 之前，不受出现顺序影响
        baseline_issues = [
            make_issue(severity="warning", message="b2"),
            make_issue(severity="error", message="b1"),
        ]
        current_issues = [
            make_issue(severity="notice", message="c2"),
            make_issue(severity="info", message="c1"),
        ]
        result = compare.compare_reports(
            make_report(baseline_issues), make_report(current_issues))

        changed = result["issues"]["severity_changed"]
        assert [(i["baseline_severity"], i["current_severity"], i["message"])
                for i in changed] == [
                    ("error", "info", "c1"),
                    ("warning", "notice", "c2"),
                ]

        for b_perm in itertools.permutations(baseline_issues):
            for c_perm in itertools.permutations(current_issues):
                again = compare.compare_reports(
                    make_report(list(b_perm)), make_report(list(c_perm)))
                assert again == result

    def test_raw_reason_breaks_ties_within_bucket(self):
        # 指纹相同（规范化 reason 一致）、级别相同，但原始 reason 不同的
        # 重复记录：按原始 reason 的规范次序配对，与报告内顺序无关
        r_tab = "\t原因一\t"      # 规范化后与 "原因一" 相同 -> 同一指纹
        r_pad = "  原因一  "      # 同上；原始文本排序：\t < 空格 < 原
        r_bare = "原因一"
        baseline_issues = [
            make_issue(reason=r_bare),
            make_issue(reason=r_tab),
            make_issue(reason=r_pad),
        ]
        current_issues = [
            make_issue(reason=r_pad),
            make_issue(reason=r_tab),
        ]
        expected = compare.compare_reports(
            make_report(baseline_issues), make_report(current_issues))
        assert [i["reason"] for i in expected["issues"]["persisting"]] == [
            r_tab, r_pad]
        assert [i["reason"] for i in expected["issues"]["fixed"]] == [r_bare]

        # 镜像：交换基线 / 当前，多出的记录归入 added
        mirror = compare.compare_reports(
            make_report(current_issues), make_report(baseline_issues))
        assert [i["reason"] for i in mirror["issues"]["added"]] == [r_bare]

        for b_perm in itertools.permutations(baseline_issues):
            for c_perm in itertools.permutations(current_issues):
                result = compare.compare_reports(
                    make_report(list(b_perm)), make_report(list(c_perm)))
                assert result == expected

    def test_self_compare_stable_for_shuffled_duplicates(self):
        # 报告与自身比较：打乱顺序后 persisting 条目集合（多重集）不变，
        # 全部配为 persisting 且重复条目完整保留
        issues = [
            make_issue(message="m2"),
            make_issue(message="m1"),
            make_issue(message="m2"),
        ]
        direct = compare.compare_reports(make_report(issues), make_report(issues))
        for perm in itertools.permutations(issues):
            shuffled = make_report(list(perm))
            result = compare.compare_reports(shuffled, shuffled)
            assert result["counts"] == direct["counts"]
            assert [i["message"] for i in result["issues"]["persisting"]] == [
                "m1", "m2", "m2"]
            assert result["issues"]["added"] == []
            assert result["issues"]["fixed"] == []
            assert result["issues"]["severity_changed"] == []
