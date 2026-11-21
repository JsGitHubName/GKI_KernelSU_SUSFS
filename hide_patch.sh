#!/bin/bash
# hide_patch.sh v3 — 编译前注入隐藏补丁
#
#   1. add_taint() 直接 return          → tainted 恒为 0
#   2. linux_banner / linux_proc_banner  → /proc/version 与原厂一致
#      + fs/proc/version.c 改用 seq_puts
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

# 原厂 /proc/version 内容。
# 用 raw string，保证 C 代码里得到的是字面 \n 而不是真实换行。
ORIG_LINE = (
    r'Linux version 6.6.89-android15-8-g7e1f3c083cc6-abogki467167594-4k '
    r'(kleaf@build-host) (Android (12481755, +pgo, +bolt, +lto, +mlgo, based on r522817) '
    r'clang version 18.0.1) #1 SMP PREEMPT Mon Dec  8 04:00:43 UTC 2025\n'
)

# C 源里要写的完整定义（\n 和 \t 是真的换行/缩进，只有结尾那个 \n 是字面量）
C_DEF = 'const char %s[] =\n\t"%s";\n'


def patch(rel, fn, tag):
    p = os.path.join(root, rel)
    if not os.path.exists(p):
        results.append((tag, rel, 'MISS'))
        return
    try:
        s = open(p, encoding='utf-8', errors='replace').read()
        n = fn(s)
    except Exception as e:
        results.append((tag, rel, 'ERR %s' % e))
        return
    if n is None:
        results.append((tag, rel, 'ALREADY'))
    elif n == s:
        results.append((tag, rel, 'PATTERN-NOT-FOUND'))
    else:
        open(p, 'w', encoding='utf-8').write(n)
        results.append((tag, rel, 'PATCHED'))


# ---------- 1) add_taint() 空操作 ----------
def f_taint(s):
    if 'hide: taint suppressed' in s:
        return None
    pat = re.compile(r'(void\s+add_taint\s*\(\s*unsigned\s+flag\s*,\s*enum\s+lockdep_ok\s+lockdep_ok\s*\)\s*\{)')
    return pat.sub(r'\1\n\treturn;  /* hide: taint suppressed */', s, count=1)


# ---------- 2) banner 两个变量 ----------
def f_banner(s):
    if 'g7e1f3c083cc6' in s:
        return None
    changed = False

    # linux_banner：dmesg 横幅。6.6 里用宏拼接，所以贪婪到分号
    pat1 = re.compile(r'const\s+char\s+linux_banner\s*\[\s*\]\s*=\s*.*?;\n', re.S)
    s2, n1 = pat1.subn(C_DEF % ('linux_banner', ORIG_LINE), s, count=1)
    if n1:
        s, changed = s2, True

    # linux_proc_banner：/proc/version 用
    pat2 = re.compile(r'const\s+char\s+linux_proc_banner\s*\[\s*\]\s*=\s*.*?;\n', re.S)
    s3, n2 = pat2.subn(C_DEF % ('linux_proc_banner', ORIG_LINE), s, count=1)
    if n2:
        s, changed = s3, True

    return s if changed else None


# ---------- 2b) fs/proc/version.c 改 seq_puts ----------
def f_procver(s):
    if 'hide: seq_puts' in s:
        return None
    # 用 [^;]* 跨越 utsname() 这类内部括号，一直吃到分号
    pat = re.compile(r'seq_printf\s*\(\s*m\s*,\s*linux_proc_banner\s*,[^;]*;', re.S)
    repl = 'seq_puts(m, linux_proc_banner);  /* hide: seq_puts */'
    return pat.sub(repl, s, count=1)


# ---------- 3) /proc/modules 过滤 ----------
def f_mshow(s):
    if 'hide: skipped module' in s:
        return None
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
patch('fs/proc/version.c', f_procver, 'proc-version')
patch('kernel/module/procfs.c', f_mshow, 'modules-filter')

print('\n[hide] ===== 结果 =====')
for tag, rel, st in results:
    print('[hide] %-14s %-20s %s' % (tag, st, rel))

# 打印实际写入的 banner 片段，方便核对
p = os.path.join(root, 'init/version-timestamp.c')
if os.path.exists(p):
    txt = open(p, encoding='utf-8', errors='replace').read()
    i = txt.find('linux_proc_banner')
    if i >= 0:
        print('[hide] --- 写入内容 ---')
        print(txt[max(0, i - 60):i + 320])

bad = [r for r in results if r[2] in ('MISS', 'PATTERN-NOT-FOUND') or r[2].startswith('ERR')]
if bad:
    print('[hide] WARN 有项目未成功应用（不中断编译）')
    for tag, rel, st in bad:
        print('[hide]   %s: %s (%s)' % (tag, st, rel))
else:
    print('[hide] 全部应用成功')
PYEOF

echo "[hide] done"
exit 0
