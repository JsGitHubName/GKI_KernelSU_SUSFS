#!/bin/bash
# hide_patch.sh — 编译前注入三项隐藏补丁
#
# 由 build.yml 在「配置内核选项」之前调用，此时所有上游补丁已应用。
# 三项改动：
#   1. add_taint() 直接 return          → /proc/sys/kernel/tainted 恒为 0
#   2. linux_banner 硬编码原厂串        → /proc/version 与原厂一致
#   3. m_show() 跳过指定模块            → /proc/modules 不出现 kernelsu/paradise
set -u

KROOT="${KERNEL_ROOT:-$GITHUB_WORKSPACE}/common"
[ -d "$KROOT" ] || KROOT="${KERNEL_ROOT:-$GITHUB_WORKSPACE}"
echo "[hide] kernel root = $KROOT"

if [ ! -d "$KROOT/kernel" ]; then
    echo "[hide] ERROR: 找不到内核源码（$KROOT/kernel 不存在）"
    exit 1
fi

python3 - "$KROOT" <<'PYEOF'
import os
import re
import sys

root = sys.argv[1]
results = []


def patch(rel, fn, tag):
    p = os.path.join(root, rel)
    if not os.path.exists(p):
        results.append((tag, rel, 'MISS'))
        return
    try:
        s = open(p, encoding='utf-8', errors='replace').read()
    except Exception as e:
        results.append((tag, rel, f'ERR {e}'))
        return
    try:
        n = fn(s)
    except Exception as e:
        results.append((tag, rel, f'ERR {e}'))
        return
    if n is None:
        results.append((tag, rel, 'ALREADY'))
        return
    if n == s:
        results.append((tag, rel, 'PATTERN-NOT-FOUND'))
        return
    open(p, 'w', encoding='utf-8').write(n)
    results.append((tag, rel, 'PATCHED'))


# ---------- 1) add_taint() 空操作 ----------
def f_taint(s):
    if 'hide: taint suppressed' in s:
        return None
    pat = re.compile(r'(void\s+add_taint\s*\(\s*unsigned\s+flag\s*,\s*enum\s+lockdep_ok\s+lockdep_ok\s*\)\s*\{)')
    return pat.sub(r'\1\n\treturn;  /* hide: taint suppressed */', s, count=1)


# ---------- 2) linux_banner 原厂串 ----------
ORIG_BANNER = (
    'Linux version 6.6.89-android15-8-g7e1f3c083cc6-abogki467167594-4k '
    '(kleaf@build-host) (Android (12481755, +pgo, +bolt, +lto, +mlgo, based on r522817) '
    'clang version 18.0.1) #1 SMP PREEMPT Mon Dec  8 04:00:43 UTC 2025\\n'
)


def f_banner(s):
    if 'g7e1f3c083cc6' in s:
        return None
    pat = re.compile(r'const\s+char\s+linux_banner\s*\[\s*\]\s*=\s*(?:"(?:[^"\\]|\\.)*"\s*)+;', re.S)
    repl = 'const char linux_banner[] = "%s";' % ORIG_BANNER
    return pat.sub(repl, s, count=1)


# ---------- 3) /proc/modules 过滤 ----------
HIDE_MODS = ('kernelsu', 'paradise', 'ksuhide', 'ksu_hide')


def f_mshow(s):
    if 'hide: skipped module' in s:
        return None
    # 定位 m_show 里取到 mod 的那一行，紧跟其后插入过滤
    pat = re.compile(
        r'(static\s+int\s+m_show\s*\(\s*struct\s+seq_file\s*\*\s*\w+\s*,\s*void\s*\*\s*\w+\s*\)\s*\{'
        r'.*?struct\s+module\s*\*\s*(\w+)\s*=\s*[^;]+;)',
        re.S)
    m = pat.search(s)
    if not m:
        return s
    var = m.group(2)
    inject = ('\n\t/* hide: skipped module */\n'
              '\tif (!strcmp(%s->name, "kernelsu") || !strcmp(%s->name, "paradise"))\n'
              '\t\treturn 0;' % (var, var))
    return s[:m.end()] + inject + s[m.end():]


patch('kernel/panic.c', f_taint, 'taint')
patch('init/version-timestamp.c', f_banner, 'banner')
patch('kernel/module/procfs.c', f_mshow, 'modules-filter')

print('\n[hide] ===== 结果 =====')
for tag, rel, st in results:
    print(f'[hide] {tag:<16} {st:<20} {rel}')

bad = [r for r in results if r[2] in ('MISS', 'PATTERN-NOT-FOUND') or r[2].startswith('ERR')]
if bad:
    print('[hide] WARN 有项目未成功应用（不中断编译，仅提示）')
    for tag, rel, st in bad:
        print(f'[hide]   {tag}: {st}')
else:
    print('[hide] 全部应用成功')
PYEOF

echo "[hide] done"
exit 0
