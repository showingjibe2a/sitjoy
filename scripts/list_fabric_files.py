#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
列出资源目录下的『面料』文件，并输出前端可用的 base64 id（相对于 resources 根）。
用法: 在能够访问 NAS 的机器上运行：
    python scripts/list_fabric_files.py

脚本不会修改数据库或文件，仅用于检查和恢复计划。
"""
import os
import base64
from pathlib import Path

# 配置：根据 app.py 中的设置调整
RESOURCES_PARENT = '/volume1/公共文件SITJOY'
# 下面的 CHILD_B64 是 app.py 中的 _RESOURCES_CHILD_B64
RESOURCES_CHILD_B64 = '44CO5LiK5p626LWE5rqQ44CP'

try:
    child_bytes = base64.b64decode(RESOURCES_CHILD_B64)
    child = child_bytes.decode('utf-8', errors='surrogatepass')
except Exception:
    child = '『上架资源』'

RESOURCES_PATH = os.path.join(RESOURCES_PARENT, child)
FABRIC_SUB = '『面料』'
FABRIC_PATH = os.path.join(RESOURCES_PATH, FABRIC_SUB)

def main():
    import sys
    try:
        print(f'Running scripts/list_fabric_files.py with Python {sys.version.split()[0]}')
        print('Resources root:', RESOURCES_PATH)
        print('Fabric folder:', FABRIC_PATH)
        print('\nScanning...')

        if not os.path.exists(FABRIC_PATH):
            print('警告：面料目录不存在，检查挂载和权限。')
            return 2

        rows = []
        for entry in os.listdir(FABRIC_PATH):
            p = os.path.join(FABRIC_PATH, entry)
            if os.path.isfile(p):
                # compute relative path bytes from resources root
                rel = os.path.join(FABRIC_SUB, entry)
                try:
                    rel_bytes = rel.encode('utf-8')
                except Exception:
                    rel_bytes = rel.encode('utf-8', errors='surrogatepass')
                b64 = base64.b64encode(rel_bytes).decode('ascii')
                rows.append((entry, p, rel, b64))

        print(f'Found {len(rows)} files in {FABRIC_PATH}')
        print('\nSample output: filename | absolute_path | rel_path | preview_b64')
        for fn, ap, rel, b64 in rows[:200]:
            print(f"{fn} | {ap} | {rel} | {b64}")

        print('\nDone. You can use the printed base64 ids in /api/image-preview?id=<b64> to verify previews.')
        return 0
    except Exception as e:
        import traceback
        print('脚本执行时发生异常:', e)
        traceback.print_exc()
        return 3


if __name__ == '__main__':
    import sys
    code = main()
    # ensure exit code propagates when run from CLI
    sys.exit(code)
