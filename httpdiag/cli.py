#!/usr/bin/env python3
"""HTTP 请求诊断工具 - 模拟 HTTP 请求全过程并输出详细诊断信息
"""
import argparse
import sys
import os
import json

from .diagnostics import HttpDiagnostics
from .redirect import RedirectTracker
from .compare import CompareMode
from .logger import RequestLogger
from .batch import BatchTester
from .har import HarExporter
from .profiles import ProfileManager
from .history import HistoryManager
from .collection import CollectionRunner
from .utils import load_headers_from_file, format_duration


def print_result(result, show_body=True):
    if result.error:
        print(f"\n  [错误] {result.error}")
        return

    print(f"\n  URL:         {result.url}")
    print(f"  方法:         {result.method}")
    print(f"  IP地址:       {result.ip_address}")
    print(f"  HTTPS:        {'是' if result.is_https else '否'}")
    print(f"  状态码:       {result.status_code} {result.status_text}")
    print(f"  内容类型:     {result.response_content_type or '(unknown)'}")
    print(f"  响应体大小:   {result.response_body_raw_size} 字节 (原始)")
    if result.response_is_binary:
        print(f"  二进制内容:   是")
    if result.response_body_truncated:
        print(f"  内容截断:     是")
    print()
    print("  时间分解:")
    print(f"    DNS解析:      {format_duration(result.timing.dns_lookup)}")
    print(f"    TCP连接:      {format_duration(result.timing.tcp_connect)}")
    if result.is_https:
        print(f"    TLS握手:      {format_duration(result.timing.tls_handshake)}")
    print(f"    请求发送:     {format_duration(result.timing.request_send)}")
    print(f"    首字节时间:   {format_duration(result.timing.time_to_first_byte)}")
    print(f"    内容下载:     {format_duration(result.timing.content_download)}")
    print(f"    总耗时:       {format_duration(result.timing.total)}")
    print()
    print(f"  请求头 (已发送):")
    for key, value in list(result.request_headers.items()):
        print(f"    {key}: {value}")
    print()
    if result.request_body:
        print(f"  请求体 ({result.request_body_size} 字节):")
        body_preview = result.request_body[:200]
        print(f"    {repr(body_preview)}")
        if len(result.request_body) > 200:
            print(f"    (总长度 {len(result.request_body)} 字节，显示截断)")
        print()
    print(f"  响应头:")
    for key, value in list(result.response_headers.items())[:15]:
        print(f"    {key}: {value}")
    if len(result.response_headers) > 15:
        print(f"    ... 还有 {len(result.response_headers) - 15} 个响应头")
    print()
    if show_body:
        print(f"  响应体预览:")
        print(f"    {repr(result.response_body_preview)}")


def print_redirect_chain(chain):
    print(f"\n  重定向次数: {chain.total_redirects} / {chain.max_redirects}")
    print(f"  总耗时:     {format_duration(chain.total_time)}")
    if chain.max_redirects_exceeded:
        print(f"  警告: 超过最大重定向次数限制 ({chain.max_redirects})，已停住，下面是完整链路")
    print()

    for i, step in enumerate(chain.steps, 1):
        print(f"  [{i}/{chain.max_redirects}] {step.status_code}  {step.from_url}")
        print(f"               ↓  {format_duration(step.result.timing.total)}")
        print(f"               →  {step.to_url}")
        print()

    if chain.final_result:
        print("  最终响应:")
        print_result(chain.final_result, show_body=True)


def main():
    parser = argparse.ArgumentParser(
        description="HTTP 请求诊断工具 - 模拟 HTTP 请求全过程并输出详细诊断信息",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
常用示例:
  %(prog)s https://www.example.com
  %(prog)s -X POST -d '{\"key\":\"value\"}' https://api.example.com/data
  %(prog)s -H 'X-Custom: value' https://www.example.com
  %(prog)s --headers-file headers.txt https://www.example.com
  %(prog)s --json https://www.example.com
  %(prog)s --log request.log --har request.har https://www.example.com
  %(prog)s --compare https://site1.com https://site2.com
  %(prog)s --batch -n 100 https://www.example.com
  %(prog)s --no-redirect --max-redirects 3 http://example.com
  %(prog)s https://example.com  (位置参数URL)
  %(prog)s --url https://example.com  (--url参数)

Profile 管理:
  %(prog)s --profile-save myapi -X POST -H 'Content-Type: application/json' -d '{}' https://api.example.com
  %(prog)s --profile-list
  %(prog)s --profile-use myapi
  %(prog)s --profile-use myapi -X PUT -t 60  (命令行参数优先)
  %(prog)s --profile-export profiles.json --mask-sensitive
  %(prog)s --profile-import profiles.json --overwrite
  %(prog)s --profile-delete myapi

环境管理:
  %(prog)s --env-save dev --base-url http://127.0.0.1:8765 -H 'X-Env: dev' -t 30
  %(prog)s --env-use dev
  %(prog)s --env-list
  %(prog)s --env-delete staging

基线管理:
  %(prog)s --baseline-set --url https://example.com -n 30
  %(prog)s --baseline-set --profile myapi
  %(prog)s --baseline-list
  %(prog)s --baseline-clear --url https://example.com

历史记录与趋势:
  %(prog)s --history-list
  %(prog)s --history-trend https://example.com
  %(prog)s --history-trend --url https://example.com
  %(prog)s --history-trend --profile myapi

请求集合:
  %(prog)s --collection login_flow.json
  %(prog)s --collection login_flow.yaml --json
""",
    )

    parser.add_argument("url", nargs="?", help="请求的 URL 地址 (位置参数)")
    parser.add_argument("url2", nargs="?", help="第二个 URL（对比模式下使用）")

    parser.add_argument(
        "--url",
        dest="url_opt",
        help="请求的 URL 地址 (--url 参数，与位置参数二选一)",
    )

    parser.add_argument(
        "-X",
        "--method",
        default=None,
        choices=["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"],
        help="HTTP 请求方法 (默认: GET)",
    )

    parser.add_argument(
        "-d",
        "--data",
        dest="body",
        help="请求体数据 (POST/PUT 请求使用)",
    )

    parser.add_argument(
        "--headers-file",
        help="从文件读取自定义请求头，每行一个 'Key: Value' 格式",
    )

    parser.add_argument(
        "-H",
        "--header",
        action="append",
        dest="headers_list",
        help="自定义请求头，可以多次使用，格式: 'Key: Value'",
    )

    parser.add_argument(
        "-t",
        "--timeout",
        type=int,
        default=None,
        help="请求超时时间（秒），默认 30 秒",
    )

    parser.add_argument(
        "--no-redirect",
        action="store_true",
        help="不自动跟随重定向",
    )

    parser.add_argument(
        "--max-redirects",
        type=int,
        default=10,
        help="最大重定向次数，默认 10 次",
    )

    parser.add_argument(
        "--log",
        dest="log_file",
        help="将完整请求和响应保存到日志文件",
    )

    parser.add_argument(
        "--log-dir",
        default="./logs",
        help="日志文件目录（使用自动生成文件名时使用），默认 ./logs",
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help="输出 JSON 格式结果，仅输出 JSON，不输出表格",
    )

    parser.add_argument(
        "--har",
        dest="har_file",
        help="导出 HAR 格式文件，可导入 Chrome DevTools 等工具分析",
    )

    parser.add_argument(
        "--compare",
        action="store_true",
        help="对比模式：依次请求两个 URL，输出性能差异表格",
    )

    parser.add_argument(
        "--name1",
        default="URL 1",
        help="对比模式下第一个 URL 的显示名称",
    )

    parser.add_argument(
        "--name2",
        default="URL 2",
        help="对比模式下第二个 URL 的显示名称",
    )

    parser.add_argument(
        "--batch",
        action="store_true",
        help="批量压测模式：重复请求指定 URL 多次并输出统计结果",
    )

    parser.add_argument(
        "-n",
        "--count",
        type=int,
        default=10,
        help="批量模式/基线设置下请求次数，默认 10 次",
    )

    parser.add_argument(
        "--delay",
        type=float,
        default=0.0,
        help="批量模式下每次请求间隔时间（秒），默认 0",
    )

    parser.add_argument(
        "--no-body",
        action="store_true",
        help="不显示响应体预览",
    )

    parser.add_argument(
        "--no-history",
        action="store_true",
        help="不保存本次请求到历史记录",
    )

    profile_group = parser.add_argument_group("Profile 预设管理")
    profile_group.add_argument(
        "--profile-save",
        metavar="NAME",
        help="保存当前请求配置（method/headers/body/timeout/URL）为 profile",
    )
    profile_group.add_argument(
        "--profile-use",
        metavar="NAME",
        help="使用已保存的 profile，命令行参数会覆盖 profile 的设置",
    )
    profile_group.add_argument(
        "--profile-list",
        action="store_true",
        help="列出所有已保存的 profile",
    )
    profile_group.add_argument(
        "--profile-delete",
        metavar="NAME",
        help="删除指定的 profile",
    )
    profile_group.add_argument(
        "--profile-export",
        metavar="FILE",
        help="导出 profiles 到 JSON 文件",
    )
    profile_group.add_argument(
        "--profile-import",
        metavar="FILE",
        help="从 JSON 文件导入 profiles",
    )
    profile_group.add_argument(
        "--mask-sensitive",
        action="store_true",
        help="导出时隐藏敏感值（Authorization、token 等）",
    )
    profile_group.add_argument(
        "--overwrite",
        action="store_true",
        help="保存 profile/env 时允许覆盖已存在的同名配置",
    )

    env_group = parser.add_argument_group("环境管理")
    env_group.add_argument(
        "--env-save",
        metavar="NAME",
        help="保存环境配置",
    )
    env_group.add_argument(
        "--env-use",
        metavar="NAME",
        help="切换当前使用的环境",
    )
    env_group.add_argument(
        "--env-list",
        action="store_true",
        help="列出所有环境配置",
    )
    env_group.add_argument(
        "--env-delete",
        metavar="NAME",
        help="删除指定的环境配置",
    )
    env_group.add_argument(
        "--base-url",
        metavar="URL",
        help="环境的基础 URL，保存环境时使用",
    )

    baseline_group = parser.add_argument_group("基线管理")
    baseline_group.add_argument(
        "--baseline-set",
        action="store_true",
        help="设置基线，配合 --url 或 --profile 使用",
    )
    baseline_group.add_argument(
        "--baseline-list",
        action="store_true",
        help="列出所有基线",
    )
    baseline_group.add_argument(
        "--baseline-clear",
        action="store_true",
        help="清除指定的基线，配合 --url 或 --profile 使用",
    )
    baseline_group.add_argument(
        "--baseline-clear-all",
        action="store_true",
        help="清除所有基线",
    )

    history_group = parser.add_argument_group("历史记录与趋势")
    history_group.add_argument(
        "--history-list",
        action="store_true",
        help="列出最近的请求历史",
    )
    history_group.add_argument(
        "--history-trend",
        nargs="?",
        const="__HISTORY_TREND__",
        metavar="URL",
        help="查看请求趋势统计，可直接跟 URL 或配合 --url/--profile 使用",
    )
    history_group.add_argument(
        "--profile",
        dest="history_profile",
        metavar="NAME",
        help="按 profile 查询历史趋势",
    )
    history_group.add_argument(
        "--history-limit",
        type=int,
        default=30,
        help="趋势分析/历史列表的记录条数，默认 30",
    )
    history_group.add_argument(
        "--history-clear",
        action="store_true",
        help="清空所有历史记录",
    )

    collection_group = parser.add_argument_group("请求集合")
    collection_group.add_argument(
        "--collection",
        metavar="FILE",
        help="运行请求集合文件（JSON 或 YAML 格式）",
    )

    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version="httpdiag 1.3.0",
    )

    args = parser.parse_args()

    profile_manager = ProfileManager()
    history_manager = HistoryManager()

    try:
        if args.url_opt and not args.url:
            args.url = args.url_opt

        if args.env_list:
            envs = profile_manager.list_envs()
            current_env = profile_manager.get_current_env()
            print(f"  已配置 {len(envs)} 个环境:\n")
            for env_name in envs:
                env = profile_manager.get_env(env_name)
                marker = " [当前]" if env_name == current_env else ""
                print(f"  [{env_name}]{marker}")
                if env and env.base_url:
                    print(f"    Base URL: {env.base_url}")
                if env and env.headers:
                    print(f"    Headers:  {len(env.headers)} 个")
                if env and env.timeout != 30:
                    print(f"    Timeout:  {env.timeout}s")
                print()
            return

        if args.env_save:
            base_headers = {}
            if args.headers_list:
                for h in args.headers_list:
                    if ":" in h:
                        key, value = h.split(":", 1)
                        base_headers[key.strip()] = value.strip()
            if args.headers_file:
                base_headers.update(load_headers_from_file(args.headers_file))

            env = profile_manager.save_env(
                env_name=args.env_save,
                base_url=args.base_url or "",
                headers=base_headers,
                body=args.body or "",
                timeout=args.timeout or 30,
                overwrite=args.overwrite,
            )
            print(f"  已保存环境: {env.name}")
            if env.base_url:
                print(f"    Base URL: {env.base_url}")
            if env.headers:
                print(f"    Headers:  {len(env.headers)} 个")
            return

        if args.env_use:
            ok = profile_manager.set_current_env(args.env_use)
            if ok:
                print(f"  已切换到环境: {args.env_use}")
            else:
                print(f"错误: 未找到环境 '{args.env_use}'", file=sys.stderr)
                sys.exit(1)
            has_request_params = (args.url or args.url_opt or args.profile_use or
                                  args.collection or args.compare or args.batch or
                                  args.profile_save)
            if not has_request_params:
                return

        if args.env_delete:
            try:
                ok = profile_manager.delete_env(args.env_delete)
                if ok:
                    print(f"  已删除环境: {args.env_delete}")
                else:
                    print(f"错误: 未找到环境 '{args.env_delete}'", file=sys.stderr)
                    sys.exit(1)
            except ValueError as e:
                print(f"错误: {e}", file=sys.stderr)
                sys.exit(1)
            return

        if args.profile_list:
            profiles = profile_manager.list()
            if not profiles:
                print("  没有保存的 profile")
            else:
                print(f"  已保存 {len(profiles)} 个 profile:\n")
                for p in profiles:
                    print(f"  [{p.name}]")
                    print(f"    URL:      {p.url}")
                    print(f"    方法:     {p.method}")
                    print(f"    环境:     {p.env}")
                    print(f"    超时:     {p.timeout}s")
                    print(f"    Headers:  {len(p.headers)} 个")
                    print(f"    Body:     {len(p.body)} 字节" if p.body else "    Body:     (无)")
                    print(f"    更新:     {p.updated_at}")
                    print()
            return

        if args.profile_delete:
            ok = profile_manager.delete(args.profile_delete)
            if ok:
                print(f"  已删除 profile: {args.profile_delete}")
            else:
                print(f"错误: 未找到 profile '{args.profile_delete}'", file=sys.stderr)
                sys.exit(1)
            return

        if args.profile_export:
            count = profile_manager.export(
                filepath=args.profile_export,
                mask_sensitive=args.mask_sensitive,
            )
            mask_note = " (敏感值已隐藏)" if args.mask_sensitive else ""
            print(f"  已导出 {count} 个 profile 到: {args.profile_export}{mask_note}")
            return

        if args.profile_import:
            result = profile_manager.import_file(
                filepath=args.profile_import,
                overwrite=args.overwrite,
            )
            print(f"  导入完成:")
            print(f"    Profiles: 导入 {result['imported_profiles']} 个，跳过 {result['skipped_profiles']} 个")
            if result.get("imported_envs") or result.get("skipped_envs"):
                print(f"    环境:     导入 {result.get('imported_envs', 0)} 个，跳过 {result.get('skipped_envs', 0)} 个")
            return

        if args.baseline_list:
            baselines = history_manager.list_baselines()
            if not baselines:
                print("  没有设置的基线")
            else:
                print(f"  已设置 {len(baselines)} 个基线:\n")
                for b in baselines:
                    print(f"  [{b.key_type}] {b.key}")
                    print(f"    平均耗时:   {b.avg_total_ms:.2f}ms")
                    print(f"    P95 耗时:   {b.p95_total_ms:.2f}ms")
                    print(f"    样本数:     {b.sample_count}")
                    print(f"    失败率:     {b.failure_rate:.1f}%")
                    print(f"    阈值: 慢>{b.threshold_time_slow_pct:.0f}% 失败率>{b.threshold_failure_rate_pct:.0f}%")
                    print(f"    创建时间:   {b.created_at}")
                    print()
            return

        if args.baseline_set:
            key = None
            key_type = None
            if args.history_profile:
                key = args.history_profile
                key_type = "profile"
            elif args.url:
                key = args.url
                key_type = "url"
            else:
                print("错误: 设置基线需要提供 --url 或 --profile", file=sys.stderr)
                sys.exit(1)

            baseline = history_manager.set_baseline(key=key, key_type=key_type, limit=args.count)
            if baseline:
                print(f"  已设置 {key_type} 基线: {key}")
                print(f"    平均耗时:   {baseline.avg_total_ms:.2f}ms (样本数: {baseline.sample_count})")
                print(f"    P95 耗时:   {baseline.p95_total_ms:.2f}ms")
                print(f"    失败率:     {baseline.failure_rate:.1f}%")
            else:
                print(f"错误: 没有找到足够的历史记录来设置基线", file=sys.stderr)
                sys.exit(1)
            return

        if args.baseline_clear:
            key_type = "profile" if args.history_profile else "url"
            key = args.history_profile if args.history_profile else args.url
            if not key:
                print("错误: --baseline-clear 必须配合 --url 或 --profile 使用", file=sys.stderr)
                sys.exit(1)
            ok = history_manager.clear_baseline(key=key, key_type=key_type)
            if ok:
                print(f"  已清除 {key_type} 基线: {key}")
            else:
                print(f"错误: 未找到基线 '{key}'", file=sys.stderr)
                sys.exit(1)
            return

        if args.baseline_clear_all:
            count = history_manager.clear_all_baselines()
            print(f"  已清除 {count} 个基线")
            return

        if args.history_clear:
            count = history_manager.clear()
            print(f"  已清空 {count} 条历史记录")
            return

        if args.history_list:
            entries = history_manager.query(limit=args.history_limit)
            if not entries:
                print("  没有历史记录")
                return
            print(f"  最近 {len(entries)} 条历史:\n")
            for i, e in enumerate(entries, 1):
                status = f"{e.status_code}" if not e.error else "ERR"
                profile_str = f"  [{e.profile_name}]" if e.profile_name else ""
                print(
                    f"  [{i:>3}] {e.timestamp}  {e.method:<6} "
                    f"{e.total_time_ms:>8.2f}ms  {status:<5} "
                    f"{profile_str} {e.url[:60]}"
                )
            return

        if args.history_trend:
            trend_url = None
            trend_profile = None

            if args.history_trend != "__HISTORY_TREND__":
                trend_url = args.history_trend
            elif args.url:
                trend_url = args.url
            elif args.history_profile:
                trend_profile = args.history_profile
            elif args.profile_use:
                trend_profile = args.profile_use

            if not trend_url and not trend_profile:
                print("错误: 查看趋势需要提供 URL 或 --profile", file=sys.stderr)
                sys.exit(1)

            trend = history_manager.get_trend(
                url=trend_url,
                profile_name=trend_profile,
                limit=args.history_limit,
            )
            if args.json:
                data = {
                    "url": trend.url,
                    "count": trend.count,
                    "success_count": trend.success_count,
                    "failure_count": trend.failure_count,
                    "failure_rate_pct": round(trend.failure_rate, 2),
                    "avg_total_ms": round(trend.avg_total_ms, 3),
                    "avg_ttfb_ms": round(trend.avg_ttfb_ms, 3),
                    "min_total_ms": round(trend.min_total_ms, 3),
                    "max_total_ms": round(trend.max_total_ms, 3),
                    "status_codes": trend.status_codes,
                    "timeline": trend.timeline,
                }
                if trend.baseline:
                    data["baseline"] = trend.baseline.to_dict()
                    data["baseline_diff_pct"] = round(trend.baseline_diff_pct, 2) if trend.baseline_diff_pct is not None else None
                if trend.anomalies:
                    data["anomalies"] = [a.to_dict() for a in trend.anomalies]
                print(json.dumps(data, ensure_ascii=False, indent=2))
            else:
                if trend.count == 0:
                    print("  没有找到匹配的历史记录")
                else:
                    print(f"\n  ========================================")
                    print(f"  趋势分析: {trend.url}")
                    print(f"  ========================================")
                    print(trend.format_table())
                    print()
            return

        applied_profile = None
        if args.profile_use:
            try:
                applied_profile = profile_manager.apply(args.profile_use)
            except ValueError as e:
                print(f"错误: {e}", file=sys.stderr)
                sys.exit(1)

        method = "GET"
        timeout = 30
        body = None
        headers = {}

        if applied_profile:
            method = applied_profile.method
            timeout = applied_profile.timeout
            body = applied_profile.body if applied_profile.body else None
            headers.update(applied_profile.headers)
            if not args.url and applied_profile.url:
                args.url = applied_profile.url

        if args.method:
            method = args.method
        if args.timeout is not None:
            timeout = args.timeout
        if args.body is not None:
            body = args.body

        if args.headers_file:
            try:
                headers.update(load_headers_from_file(args.headers_file))
            except Exception as e:
                print(f"错误: 无法读取请求头文件: {e}", file=sys.stderr)
                sys.exit(1)
        if args.headers_list:
            for h in args.headers_list:
                if ":" in h:
                    key, value = h.split(":", 1)
                    headers[key.strip()] = value.strip()

        if not headers:
            headers["User-Agent"] = "httpdiag/1.3"
            headers["Accept"] = "*/*"

        method = method.upper()

        if args.profile_save:
            if not args.url:
                print("错误: 保存 profile 需要 URL", file=sys.stderr)
                sys.exit(1)
            try:
                profile = profile_manager.save(
                    name=args.profile_save,
                    method=method,
                    url=args.url,
                    headers=headers,
                    body=body or "",
                    timeout=timeout,
                    overwrite=args.overwrite,
                )
                print(f"  已保存 profile: {profile.name}")
                print(f"    方法: {profile.method}")
                print(f"    URL:  {args.url}")
                print(f"    Headers: {len(profile.headers)} 个")
                if profile.body:
                    print(f"    Body: {len(profile.body)} 字节")
            except ValueError as e:
                print(f"错误: {e}", file=sys.stderr)
                sys.exit(1)
            return

        if args.collection:
            if not args.json:
                print(f"\n  ========================================")
                print(f"  请求集合模式: {args.collection}")
                print(f"  ========================================")

            runner = CollectionRunner(timeout=timeout, max_redirects=args.max_redirects)
            env_config = profile_manager.get_env()
            initial_vars = {}
            if env_config and env_config.variables:
                initial_vars.update(env_config.variables)

            collection_result = runner.run_from_file(
                args.collection,
                base_headers=headers,
                initial_variables=initial_vars,
            )

            if not args.no_history:
                try:
                    for sr in collection_result.steps:
                        if sr.result:
                            history_manager.add_from_result(
                                sr.result,
                                profile_name=args.profile_use,
                                mode="collection",
                                extra={"collection": collection_result.name, "step": sr.step.name},
                            )
                except Exception:
                    pass

            if args.json:
                print(collection_result.to_json())
            else:
                print()
                print(collection_result.format_table())
                print()

            if args.log_file:
                filepath = logger.save_collection(collection_result, filename=args.log_file)
                if not args.json:
                    print(f"\n  日志已保存到: {filepath}")

            if not collection_result.success:
                sys.exit(1)
            return

        logger = RequestLogger(log_dir=args.log_dir)

        def _save_history(result, mode="single"):
            if args.no_history:
                return
            try:
                history_manager.add_from_result(
                    result,
                    profile_name=args.profile_use,
                    mode=mode,
                )
            except Exception:
                pass

        if not args.url and not args.compare:
            parser.print_help()
            sys.exit(1)

        if args.batch:
            if not args.url:
                print("错误: 批量模式需要提供 URL", file=sys.stderr)
                sys.exit(1)

            if not args.json:
                print(f"\n  ========================================")
                print(f"  批量压测模式: {args.url}")
                print(f"  请求次数: {args.count}")
                if args.delay > 0:
                    print(f"  间隔时间: {args.delay}s")
                print(f"  ========================================")

            tester = BatchTester(timeout=timeout)
            progress_cb = None
            if not args.json:
                def _progress(current, total, result):
                    status = f"{result.status_code}" if not result.error else "ERR"
                    print(f"    [{current:>3}/{total}] {result.timing.total*1000:>8.2f}ms  {status}")
                progress_cb = _progress

            batch_result = tester.run(
                url=args.url,
                count=args.count,
                method=method,
                headers=headers,
                body=body,
                delay=args.delay,
                follow_redirects=not args.no_redirect,
                on_progress=progress_cb,
            )

            if not args.no_history:
                try:
                    for r in batch_result.results:
                        history_manager.add_from_result(r, profile_name=args.profile_use, mode="batch")
                except Exception:
                    pass

            if args.json:
                print(batch_result.to_json())
            else:
                print()
                print(batch_result.format_table(show_details=False))

            if args.log_file:
                filepath = logger.save_batch(batch_result, filename=args.log_file)
                if not args.json:
                    print(f"\n  日志已保存到: {filepath}")

            if args.har_file:
                har_content = HarExporter.from_batch_result(batch_result)
                with open(args.har_file, "w", encoding="utf-8") as f:
                    f.write(har_content)
                if not args.json:
                    print(f"  HAR 文件已保存到: {args.har_file}")

            return

        if args.compare:
            if not args.url or not args.url2:
                print("错误: 对比模式需要提供两个 URL", file=sys.stderr)
                sys.exit(1)

            if not args.json:
                print(f"\n  ========================================")
                print(f"  对比模式: {args.name1} vs {args.name2}")
                print(f"  ========================================")

            comparer = CompareMode(timeout=timeout)
            compare_result = comparer.compare_urls(
                urls=[args.url, args.url2],
                names=[args.name1, args.name2],
                method=method,
                headers=headers,
                body=body,
            )

            _save_history(compare_result.items[0].result, mode="compare")
            _save_history(compare_result.items[1].result, mode="compare")

            if args.json:
                print(compare_result.to_json())
            else:
                print()
                print(compare_result.format_table())
                print()

            if args.log_file:
                filepath = logger.save_compare(compare_result, filename=args.log_file)
                if not args.json:
                    print(f"  日志已保存到: {filepath}")

            if args.har_file:
                har_content = HarExporter.from_compare_result(compare_result)
                with open(args.har_file, "w", encoding="utf-8") as f:
                    f.write(har_content)
                if not args.json:
                    print(f"  HAR 文件已保存到: {args.har_file}")

            return

        if args.no_redirect:
            if not args.json:
                print(f"\n  ========================================")
                print(f"  HTTP 请求诊断")
                print(f"  ========================================")

            diag = HttpDiagnostics(timeout=timeout)
            result = diag.request(
                args.url,
                method=method,
                headers=headers,
                body=body,
            )

            _save_history(result, mode="single")

            if args.json:
                print(result.to_json())
            else:
                print_result(result, show_body=not args.no_body)
                print()

            if args.log_file:
                filepath = logger.save_single_request(result, filename=args.log_file)
                if not args.json:
                    print(f"  日志已保存到: {filepath}")

            if args.har_file:
                har_content = HarExporter.from_single_result(result)
                with open(args.har_file, "w", encoding="utf-8") as f:
                    f.write(har_content)
                if not args.json:
                    print(f"  HAR 文件已保存到: {args.har_file}")
        else:
            if not args.json:
                print(f"\n  ========================================")
                print(f"  HTTP 请求诊断 (跟随重定向)")
                print(f"  ========================================")

            tracker = RedirectTracker(max_redirects=args.max_redirects, timeout=timeout)
            chain = tracker.follow(
                args.url,
                method=method,
                headers=headers,
                body=body,
            )

            if chain.final_result:
                _save_history(chain.final_result, mode="redirect")

            if args.json:
                print(chain.to_json())
            else:
                print_redirect_chain(chain)

            if args.log_file:
                filepath = logger.save_redirect_chain(chain, filename=args.log_file)
                if not args.json:
                    print(f"  日志已保存到: {filepath}")

            if args.har_file:
                har_content = HarExporter.from_redirect_chain(chain)
                with open(args.har_file, "w", encoding="utf-8") as f:
                    f.write(har_content)
                if not args.json:
                    print(f"  HAR 文件已保存到: {args.har_file}")

    except ValueError as e:
        print(f"错误: {e}", file=sys.stderr)
        sys.exit(1)
    except FileNotFoundError as e:
        print(f"错误: {e}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n操作已取消", file=sys.stderr)
        sys.exit(130)
    except Exception as e:
        print(f"错误: {e}", file=sys.stderr)
        sys.exit(1)

    if not args.json:
        print()


if __name__ == "__main__":
    main()
