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
        print(f"  请求体:")
        body_preview = result.request_body[:200]
        print(f"    {repr(body_preview)}")
        if len(result.request_body) > 200:
            print(f"    (总长度 {len(result.request_body)} 字节，已截断)")
        print()
    print(f"  响应头:")
    for key, value in list(result.response_headers.items())[:15]:
        print(f"    {key}: {value}")
    if len(result.response_headers) > 15:
        print(f"    ... 还有 {len(result.response_headers) - 15} 个响应头")
    print()
    if show_body:
        print(f"  响应体 (前200字符):")
        print(f"    {repr(result.response_body_preview)}")
        print(f"  响应体总长度: {result.response_body_size} 字节")


def print_redirect_chain(chain):
    print(f"\n  重定向次数: {chain.total_redirects}")
    print(f"  总耗时:     {format_duration(chain.total_time)}")
    if chain.max_redirects_exceeded:
        print(f"  警告: 超过最大重定向次数限制，已走过的完整链路已列出")
    print()

    for i, step in enumerate(chain.steps, 1):
        print(f"  [{i}] {step.status_code}  {step.from_url}")
        print(f"       ↓  {format_duration(step.result.timing.total)}")
        print(f"       →  {step.to_url}")
        print()

    if chain.final_result:
        print("  最终响应:")
        print_result(chain.final_result, show_body=True)


def main():
    parser = argparse.ArgumentParser(
        description="HTTP 请求诊断工具 - 模拟 HTTP 请求全过程并输出详细诊断信息",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  %(prog)s https://www.example.com
  %(prog)s -X POST -d '{"key":"value"}' https://api.example.com/data
  %(prog)s -H headers.txt https://www.example.com
  %(prog)s --json https://www.example.com
  %(prog)s --log request.log https://www.example.com
  %(prog)s --har request.har https://www.example.com
  %(prog)s --compare https://site1.com https://site2.com
  %(prog)s --batch -n 10 https://www.example.com
  %(prog)s --no-redirect https://www.example.com
        """,
    )

    parser.add_argument("url", nargs="?", help="请求的 URL 地址")
    parser.add_argument("url2", nargs="?", help="第二个 URL（对比模式下使用）")

    parser.add_argument(
        "-X",
        "--method",
        default="GET",
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
        "-H",
        "--headers-file",
        help="从文件读取自定义请求头，每行一个 'Key: Value' 格式",
    )

    parser.add_argument(
        "--header",
        action="append",
        dest="headers_list",
        help="自定义请求头，可以多次使用，格式: 'Key: Value'",
    )

    parser.add_argument(
        "-t",
        "--timeout",
        type=int,
        default=30,
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
        help="批量模式下请求次数，默认 10 次",
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
        "-v",
        "--version",
        action="version",
        version="httpdiag 1.1.0",
    )

    args = parser.parse_args()

    if not args.url and not args.compare:
        parser.print_help()
        sys.exit(1)

    headers = {}
    if args.headers_file:
        try:
            headers = load_headers_from_file(args.headers_file)
        except Exception as e:
            print(f"错误: 无法读取请求头文件: {e}", file=sys.stderr)
            sys.exit(1)

    if args.headers_list:
        for h in args.headers_list:
            if ":" in h:
                key, value = h.split(":", 1)
                headers[key.strip()] = value.strip()

    if not headers:
        headers["User-Agent"] = "httpdiag/1.1"
        headers["Accept"] = "*/*"

    if args.method:
        args.method = args.method.upper()

    logger = RequestLogger(log_dir=args.log_dir)

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

        tester = BatchTester(timeout=args.timeout)
        progress_cb = None
        if not args.json:
            def _progress(current, total, result):
                status = f"{result.status_code}" if not result.error else "ERR"
                print(f"    [{current:>3}/{total}] {result.timing.total*1000:>8.2f}ms  {status}")
            progress_cb = _progress

        batch_result = tester.run(
            url=args.url,
            count=args.count,
            method=args.method,
            headers=headers,
            body=args.body,
            delay=args.delay,
            follow_redirects=not args.no_redirect,
            on_progress=progress_cb,
        )

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

        comparer = CompareMode(timeout=args.timeout)
        compare_result = comparer.compare_urls(
            urls=[args.url, args.url2],
            names=[args.name1, args.name2],
            method=args.method,
            headers=headers,
            body=args.body,
        )

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

        diag = HttpDiagnostics(timeout=args.timeout)
        result = diag.request(
            args.url,
            method=args.method,
            headers=headers,
            body=args.body,
        )

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

        tracker = RedirectTracker(max_redirects=args.max_redirects, timeout=args.timeout)
        chain = tracker.follow(
            args.url,
            method=args.method,
            headers=headers,
            body=args.body,
        )

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

    if not args.json:
        print()


if __name__ == "__main__":
    main()
