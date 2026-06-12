#!/usr/bin/env python3
"""HTTP 请求诊断工具入口脚本
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from httpdiag.cli import main

if __name__ == "__main__":
    main()
