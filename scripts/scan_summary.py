"""Summarize scanner results; missing or failed checks never verify a plugin."""
import json
import re
import sys
from pathlib import Path


def build_summary(results_dir):
    root = Path(results_dir)

    def text(name):
        try:
            return (root / name).read_text(encoding='utf-8')
        except (OSError, UnicodeError):
            return ''

    def exit_code(name):
        try:
            return int(text(name + '.exit').strip())
        except ValueError:
            return None

    def result(status, detail):
        return {'status': status, 'detail': detail}

    collection = result('pass', '所有待扫描文件下载完成') if exit_code('collect') == 0 else result('error', '文件收集失败或没有待扫描文件')
    clam_log = text('clamav.log')
    scanned = re.search(r'^Scanned files:\s*(\d+)\s*$', clam_log, re.MULTILINE)
    if exit_code('clamav') == 1:
        clam = result('fail', '检测到威胁')
    elif exit_code('clamav') == 0 and scanned and int(scanned[1]) > 0:
        clam = result('pass', f'完成 {scanned[1]} 个文件扫描，未发现威胁')
    else:
        clam = result('error', '扫描器失败、结果缺失或未扫描到文件')

    yara_hits = len([line for line in text('yara.txt').splitlines() if line.strip()])
    if exit_code('yara') != 0:
        yara = result('error', '规则扫描失败或结果缺失')
    elif yara_hits:
        yara = result('warn', f'{yara_hits} 条规则匹配')
    else:
        yara = result('pass', '规则扫描完成，无匹配')

    try:
        vt_data = json.loads(text('virustotal.json'))
    except (ValueError, TypeError):
        vt_data = None
    vt = result('error', '查询失败或结果缺失')
    if isinstance(vt_data, dict):
        status = vt_data.get('status')
        files = vt_data.get('files')
        if status == 'skip' and exit_code('virustotal') == 0:
            vt = result('skip', '未配置，未执行此项查询')
        elif status == 'fail':
            vt = result('fail', '查询发现报毒结果')
        elif status in ('warn', 'unknown'):
            vt = result('warn', '存在可疑、未收录或未检查的文件')
        elif status == 'pass' and exit_code('virustotal') == 0 and isinstance(files, list) and files:
            if all(isinstance(f, dict) and f.get('status') == 'pass'
                   and f.get('positives') == 0 and isinstance(f.get('total'), int)
                   and f['total'] > 0 for f in files):
                vt = result('pass', '所有文件均有有效的无报毒查询结果')

    checks = {'文件收集': collection, 'ClamAV': clam, 'YARA': yara, 'VirusTotal': vt}
    statuses = [item['status'] for item in checks.values()]
    overall = 'fail' if 'fail' in statuses else ('review' if any(s in ('error', 'warn') for s in statuses) else 'pass')
    label = {'pass': 'verified', 'review': 'needs-review', 'fail': 'malware-detected'}[overall]
    icons = {'pass': '✅', 'fail': '❌', 'warn': '⚠️', 'error': '⚠️', 'skip': '⏭️'}
    report = ['## 🔍 病毒扫描报告', '', '| 检查项 | 状态 | 结果 |', '| --- | --- | --- |']
    for name, check in checks.items():
        report.append(f'| {name} | {icons[check["status"]]} | {check["detail"]} |')
    conclusion = {
        'pass': '已完成已配置的扫描，未发现威胁；仍需维护者人工审核。',
        'review': '检查不完整或存在可疑结果，禁止据此判定扫描通过。',
        'fail': '检测到报毒结果，请勿合并，需人工复核。',
    }[overall]
    report.extend(['', f'**结论**：{conclusion}', '', '*此报告由 TubaBot 自动生成。*'])
    return {'overall': overall, 'label': label, 'checks': checks, 'report': '\n'.join(report)}


if __name__ == '__main__':
    print(json.dumps(build_summary(sys.argv[1]), ensure_ascii=False, indent=2))
