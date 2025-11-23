"""
OSINT 데이터베이스 웹 인터페이스
FastAPI를 사용하여 수집된 OSINT 정보를 시각화하고 관리합니다.
"""

import os
from typing import Optional, List
from datetime import datetime
from fastapi import FastAPI, Query, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

from db_manager import OSINTDatabase
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
import asyncio
import json

# 경고 메시지 제어
import warnings
warnings.filterwarnings("ignore", category=UserWarning, module="langchain_core._api.deprecation")

# LangChain 및 Agent 관련 라이브러리
try:
    from langchain_ollama import ChatOllama
    from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
    from langchain_core.output_parsers import StrOutputParser
    from langchain_core.tools import tool
    from langchain_core.messages import HumanMessage, AIMessage, SystemMessage, ToolMessage
    HAS_LLM = True
except ImportError as e:
    HAS_LLM = False
    print(f"⚠️ LangChain/Ollama 라이브러리 로드 실패: {e}")
    import traceback
    traceback.print_exc()
    print("⚠️ 챗봇 기능이 제한됩니다.")

from dotenv import load_dotenv

# .env 파일 로드
current_dir = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(current_dir, ".env"))

# API 키 로드
INTELX_API_KEY = os.getenv("INTELX_API_KEY", "")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "")

# OSINT 도구 클래스 직접 구현 (server_stdio.py 의존성 제거)
HAS_TOOLS = True

class SherlockClient:
    """Sherlock 래퍼 (간소화 버전)"""
    def __init__(self):
        # sherlock 라이브러리 임포트 시도하지 않음 (CLI 사용 권장)
        pass

    async def search(self, username: str, sites: List[str] = None):
        # subprocess로 sherlock 실행 (가장 확실한 방법)
        try:
            # 주요 사이트만 빠르게 검색
            # sherlock 명령어가 PATH에 있는지 확인 필요하지만, 
            # venv 내부라면 'sherlock' 또는 'python -m sherlock' 시도
            
            cmd = ["sherlock", username, "--timeout", "5", "--print-found"]
            if sites:
                for site in sites:
                    cmd.extend(["--site", site])
            
            # 1차 시도: sherlock 명령어 직접 실행
            try:
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
            except FileNotFoundError:
                # 2차 시도: python -m sherlock 실행
                cmd = ["python3", "-m", "sherlock", username, "--timeout", "5", "--print-found"]
                if sites:
                    for site in sites:
                        cmd.extend(["--site", site])
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )

            stdout, stderr = await process.communicate()
            
            # Sherlock이 생성한 txt 파일 삭제 (파일명은 username.txt)
            txt_file = f"{username}.txt"
            if os.path.exists(txt_file):
                try:
                    os.remove(txt_file)
                except Exception:
                    pass

            output = stdout.decode()
            found_sites = []
            for line in output.splitlines():
                # Sherlock 출력 파싱 개선
                if "[+]" in line:
                    parts = line.split(": ")
                    if len(parts) >= 2:
                        found_sites.append({"site": parts[0].replace("[+]", "").strip(), "url": parts[1].strip()})
                # 일반적인 URL 형식 파싱 (https://...)
                elif "https://" in line and username in line:
                     found_sites.append({"site": "Unknown", "url": line.strip()})
            
            if not found_sites and "Error" in output:
                 return {"error": f"Sherlock 실행 오류: {output}"}

            return {"found": found_sites, "count": len(found_sites)}
            
        except Exception as e:
            return {"error": f"Sherlock 실행 실패: {str(e)}"}

class VirusTotalClient:
    """VirusTotal API 클라이언트"""
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {"x-apikey": api_key}

    async def get_domain_report(self, domain: str):
        if not self.api_key:
            return {"error": "VirusTotal API 키가 설정되지 않았습니다."}
        
        import aiohttp
        async with aiohttp.ClientSession() as session:
            url = f"{self.base_url}/domains/{domain}"
            async with session.get(url, headers=self.headers) as response:
                if response.status == 200:
                    data = await response.json()
                    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                    return {"domain": domain, "stats": stats}
                return {"error": f"API Error: {response.status}"}

    async def get_ip_report(self, ip: str):
        if not self.api_key:
            return {"error": "VirusTotal API 키가 설정되지 않았습니다."}
            
        import aiohttp
        async with aiohttp.ClientSession() as session:
            url = f"{self.base_url}/ip_addresses/{ip}"
            async with session.get(url, headers=self.headers) as response:
                if response.status == 200:
                    data = await response.json()
                    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                    return {"ip": ip, "stats": stats}
                return {"error": f"API Error: {response.status}"}

class PlaywrightClient:
    """Playwright 웹 분석 클라이언트"""
    async def analyze_url(self, url: str):
        from playwright.async_api import async_playwright
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                page = await browser.new_page()
                await page.goto(url, wait_until="networkidle", timeout=30000)
                title = await page.title()
                content = await page.content()
                
                # 텍스트 추출 (간단히)
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(content, "html.parser")
                text = soup.get_text(separator=" ", strip=True)[:1000] # 앞부분 1000자만
                
                await browser.close()
                return {"url": url, "title": title, "text_summary": text + "..."}
        except Exception as e:
            return {"error": f"Playwright 분석 실패: {str(e)}"}

class ChatRequest(BaseModel):
    message: str


# ============================================================================
# LangChain 도구 정의
# ============================================================================

@tool
async def search_username(username: str) -> str:
    """
    Sherlock을 사용하여 여러 소셜 미디어 사이트에서 사용자명(username)을 검색합니다.
    특정 인물의 SNS 계정을 찾을 때 사용합니다.
    """
    if not HAS_TOOLS:
        return "도구 모듈을 로드할 수 없어 실행할 수 없습니다."
    
    client = SherlockClient()
    # 시간 관계상 주요 사이트만 검색
    sites = ["github", "twitter", "instagram", "facebook", "linkedin", "tinder"]
    result = await client.search(username, sites=sites)
    return json.dumps(result, ensure_ascii=False)

@tool
async def check_domain_reputation(domain: str) -> str:
    """
    VirusTotal을 사용하여 도메인의 보안 평판(악성 여부)을 확인합니다.
    웹사이트가 안전한지, 피싱 사이트인지 확인할 때 사용합니다.
    """
    if not HAS_TOOLS:
        return "도구 모듈을 로드할 수 없어 실행할 수 없습니다."

    client = VirusTotalClient(VIRUSTOTAL_API_KEY)
    result = await client.get_domain_report(domain)
    return json.dumps(result, ensure_ascii=False)

@tool
async def check_ip_reputation(ip: str) -> str:
    """
    VirusTotal을 사용하여 IP 주소의 보안 평판을 확인합니다.
    서버 위치, 악성 활동 연관성 등을 확인할 때 사용합니다.
    """
    if not HAS_TOOLS:
        return "도구 모듈을 로드할 수 없어 실행할 수 없습니다."

    client = VirusTotalClient(VIRUSTOTAL_API_KEY)
    result = await client.get_ip_report(ip)
    return json.dumps(result, ensure_ascii=False)

@tool
async def analyze_webpage(url: str) -> str:
    """
    Playwright를 사용하여 웹페이지에 직접 접속해 텍스트와 정보를 추출합니다.
    웹사이트의 내용을 자세히 파악하거나 요약할 때 사용합니다.
    """
    if not HAS_TOOLS:
        return "도구 모듈을 로드할 수 없어 실행할 수 없습니다."

    client = PlaywrightClient()
    result = await client.analyze_url(url)
    return json.dumps(result, ensure_ascii=False)

@tool
async def search_leaks(term: str) -> str:
    """
    Intelligence X를 사용하여 이메일, 도메인 등의 유출 정보를 검색합니다.
    다크웹이나 해킹된 데이터베이스에 정보가 있는지 확인할 때 사용합니다.
    """
    if not HAS_TOOLS:
        return "도구 모듈을 로드할 수 없어 실행할 수 없습니다."
    
    # Intelligence X는 구현이 복잡하므로 여기서는 Mock 또는 간단한 메시지 반환
    # 실제 구현 필요 시 별도 라이브러리 사용
    return json.dumps({"message": "Intelligence X 기능은 현재 API 키 설정이 필요합니다."}, ensure_ascii=False)

@tool
async def search_local_db(query: str) -> str:
    """
    로컬 데이터베이스(db.csv)에 저장된 과거 수집 기록을 검색합니다.
    이미 조사한 적이 있는 타겟인지, 과거 기록이 있는지 확인할 때 사용합니다.
    """
    records = db.get_all_records()
    results = []
    query = query.lower()
    
    for r in records:
        # 타겟, URL, 요약 내용에서 검색
        if (query in r['target'].lower() or 
            query in r['url'].lower() or 
            query in r['summary'].lower()):
            results.append({
                "timestamp": r['timestamp'],
                "target": r['target'],
                "method": r['collection_method'],
                "summary": r['summary'],
                "threat": r['threat_level']
            })
    
    if not results:
        return "데이터베이스에서 관련 기록을 찾을 수 없습니다."
        
    return json.dumps(results, ensure_ascii=False, indent=2)

@tool
async def save_to_db(target: str, summary: str, method: str, threat_level: str = "unknown") -> str:
    """
    조사 결과(정보)를 데이터베이스에 저장합니다.
    새로운 유의미한 정보를 발견했을 때 반드시 이 도구를 사용하여 기록을 남겨야 합니다.
    
    Args:
        target: 조사 대상 (예: username, domain, IP)
        summary: 발견된 정보 요약 (한글로 작성)
        method: 사용한 도구 이름 (예: search_username, check_domain_reputation)
        threat_level: 위협 수준 (safe, suspicious, malicious, unknown 중 하나)
    """
    try:
        success = db.add_record(
            target=target,
            summary=summary,
            collection_method=method,
            threat_level=threat_level,
            metadata={"source": "AI Chatbot Agent"}
        )
        if success:
            return "데이터베이스에 성공적으로 저장되었습니다."
        else:
            return "저장에 실패했습니다."
    except Exception as e:
        return f"저장 중 오류 발생: {str(e)}"

# 사용 가능한 도구 목록
tools = [search_username, check_domain_reputation, check_ip_reputation, analyze_webpage, search_leaks, search_local_db, save_to_db]



# FastAPI 앱 생성
app = FastAPI(
    title="OSINT Dashboard",
    description="OSINT 수집 정보 대시보드",
    version="1.0.0"
)

# CORS 설정 (개발 환경)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 데이터베이스 인스턴스
db = OSINTDatabase("db.csv")


@app.get("/", response_class=HTMLResponse)
async def root():
    """메인 대시보드 페이지"""
    return """
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OSINT Dashboard</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
        }

        .header {
            background: white;
            padding: 30px;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
            margin-bottom: 30px;
        }

        .header h1 {
            color: #333;
            margin-bottom: 10px;
            font-size: 2.5em;
        }

        .header p {
            color: #666;
            font-size: 1.1em;
        }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }

        .stat-card {
            background: white;
            padding: 25px;
            border-radius: 15px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
            transition: transform 0.3s ease;
        }

        .stat-card:hover {
            transform: translateY(-5px);
        }

        .stat-card h3 {
            color: #888;
            font-size: 0.9em;
            text-transform: uppercase;
            margin-bottom: 10px;
            font-weight: 600;
        }

        .stat-card .value {
            color: #667eea;
            font-size: 2.5em;
            font-weight: bold;
        }

        .filters {
            background: white;
            padding: 25px;
            border-radius: 15px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
            margin-bottom: 30px;
        }

        .filters h2 {
            margin-bottom: 20px;
            color: #333;
        }

        .filter-group {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }

        .filter-group input,
        .filter-group select {
            padding: 12px;
            border: 2px solid #e0e0e0;
            border-radius: 8px;
            font-size: 1em;
            transition: border-color 0.3s;
        }

        .filter-group input:focus,
        .filter-group select:focus {
            outline: none;
            border-color: #667eea;
        }

        .btn {
            padding: 12px 30px;
            border: none;
            border-radius: 8px;
            font-size: 1em;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s;
        }

        .btn-primary {
            background: #667eea;
            color: white;
        }

        .btn-primary:hover {
            background: #5568d3;
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(102, 126, 234, 0.4);
        }

        .btn-secondary {
            background: #e0e0e0;
            color: #333;
            margin-left: 10px;
        }

        .btn-secondary:hover {
            background: #d0d0d0;
        }

        .records {
            background: white;
            padding: 25px;
            border-radius: 15px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }

        .records h2 {
            margin-bottom: 20px;
            color: #333;
        }

        .records-table {
            width: 100%;
            border-collapse: collapse;
        }

        .records-table thead {
            background: #f8f9fa;
        }

        .records-table th {
            padding: 15px;
            text-align: left;
            font-weight: 600;
            color: #555;
            border-bottom: 2px solid #e0e0e0;
        }

        .records-table td {
            padding: 15px;
            border-bottom: 1px solid #f0f0f0;
        }

        .records-table tbody tr {
            transition: background 0.2s;
        }

        .records-table tbody tr:hover {
            background: #f8f9fa;
        }

        .threat-badge {
            display: inline-block;
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: 600;
        }

        .threat-safe {
            background: #d4edda;
            color: #155724;
        }

        .threat-suspicious {
            background: #fff3cd;
            color: #856404;
        }

        .threat-malicious {
            background: #f8d7da;
            color: #721c24;
        }

        .threat-unknown {
            background: #e2e3e5;
            color: #383d41;
        }

        .loading {
            text-align: center;
            padding: 40px;
            color: #666;
        }

        .no-records {
            text-align: center;
            padding: 40px;
            color: #999;
        }

        .action-btns {
            display: flex;
            gap: 10px;
        }

        .btn-small {
            padding: 5px 15px;
            font-size: 0.85em;
            border-radius: 5px;
            border: none;
            cursor: pointer;
            transition: all 0.2s;
        }

        .btn-view {
            background: #667eea;
            color: white;
        }

        .btn-view:hover {
            background: #5568d3;
        }

        .btn-pdf {
            background: #28a745;
            color: white;
        }

        .btn-pdf:hover {
            background: #218838;
        }

        .btn-delete {
            background: #dc3545;
            color: white;
        }

        .btn-delete:hover {
            background: #c82333;
        }

        .modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.5);
            z-index: 1000;
            overflow-y: auto;
        }

        .modal-content {
            background: white;
            max-width: 800px;
            margin: 50px auto;
            padding: 30px;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.3);
        }

        .modal-close {
            float: right;
            font-size: 28px;
            font-weight: bold;
            cursor: pointer;
            color: #aaa;
        }

        .modal-close:hover {
            color: #000;
        }

        .detail-section {
            margin-bottom: 20px;
        }

        .detail-section h3 {
            color: #667eea;
            margin-bottom: 10px;
            border-bottom: 2px solid #667eea;
            padding-bottom: 5px;
        }

        .detail-section pre {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 8px;
            overflow-x: auto;
            font-size: 0.9em;
        }

        @media (max-width: 768px) {
            .header h1 {
                font-size: 1.8em;
            }

            .stats-grid {
                grid-template-columns: 1fr;
            }

            .filter-group {
                grid-template-columns: 1fr;
            }

            .records-table {
                font-size: 0.85em;
            }

            .records-table th,
            .records-table td {
                padding: 10px;
            }
        }

        /* 챗봇 위젯 스타일 */
        .chat-widget-btn {
            position: fixed;
            bottom: 30px;
            right: 30px;
            width: 60px;
            height: 60px;
            background: #667eea;
            border-radius: 50%;
            box-shadow: 0 5px 20px rgba(0,0,0,0.2);
            display: flex;
            align-items: center;
            justify-content: center;
            cursor: pointer;
            transition: transform 0.3s;
            z-index: 1000;
        }

        .chat-widget-btn:hover {
            transform: scale(1.1);
        }

        .chat-icon {
            font-size: 30px;
            color: white;
        }

        .chat-window {
            position: fixed;
            bottom: 100px;
            right: 30px;
            width: 380px;
            height: 500px;
            background: white;
            border-radius: 20px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
            display: none;
            flex-direction: column;
            z-index: 1000;
            overflow: hidden;
        }

        .chat-header {
            background: #667eea;
            color: white;
            padding: 15px 20px;
            font-weight: bold;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .chat-messages {
            flex: 1;
            padding: 20px;
            overflow-y: auto;
            background: #f8f9fa;
        }

        .message {
            margin-bottom: 15px;
            max-width: 80%;
            padding: 10px 15px;
            border-radius: 15px;
            font-size: 0.9em;
            line-height: 1.4;
        }

        .message.user {
            background: #667eea;
            color: white;
            margin-left: auto;
            border-bottom-right-radius: 2px;
        }

        .message.ai {
            background: white;
            color: #333;
            border: 1px solid #e0e0e0;
            margin-right: auto;
            border-bottom-left-radius: 2px;
        }

        .chat-input-area {
            padding: 15px;
            background: white;
            border-top: 1px solid #e0e0e0;
            display: flex;
            gap: 10px;
        }

        .chat-input-area input {
            flex: 1;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 20px;
            outline: none;
        }

        .chat-input-area button {
            background: #667eea;
            color: white;
            border: none;
            width: 40px;
            height: 40px;
            border-radius: 50%;
            cursor: pointer;
        }

        .tool-status {
            font-size: 0.8em;
            color: #666;
            margin: 5px 0;
            padding: 5px 10px;
            background: #f0f0f0;
            border-radius: 10px;
            border-left: 3px solid #667eea;
            animation: fadeIn 0.5s;
        }

        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(5px); }
            to { opacity: 1; transform: translateY(0); }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 OSINT Dashboard</h1>
            <p>AI 기반 인텔리전스 위협 탐지 자동화 시스템</p>
        </div>

        <div class="stats-grid" id="stats">
            <div class="stat-card">
                <h3>총 레코드</h3>
                <div class="value" id="total-records">-</div>
            </div>
            <div class="stat-card">
                <h3>안전</h3>
                <div class="value" style="color: #28a745;" id="safe-count">-</div>
            </div>
            <div class="stat-card">
                <h3>의심스러움</h3>
                <div class="value" style="color: #ffc107;" id="suspicious-count">-</div>
            </div>
            <div class="stat-card">
                <h3>악성</h3>
                <div class="value" style="color: #dc3545;" id="malicious-count">-</div>
            </div>
        </div>

        <div class="filters">
            <h2>🔎 검색 & 필터</h2>
            <div class="filter-group">
                <input type="text" id="search-target" placeholder="타겟 검색...">
                <select id="filter-method">
                    <option value="">모든 수집 방법</option>
                    <option value="analyze_url_playwright">URL 분석</option>
                    <option value="crawl_and_analyze_url">URL 크롤링</option>
                    <option value="check_virustotal_domain">VirusTotal 도메인</option>
                    <option value="check_virustotal_ip">VirusTotal IP</option>
                    <option value="search_intelligence_x">Intelligence X</option>
                    <option value="search_username_sherlock">Sherlock</option>
                </select>
                <select id="filter-threat">
                    <option value="">모든 위협 수준</option>
                    <option value="safe">안전</option>
                    <option value="suspicious">의심스러움</option>
                    <option value="malicious">악성</option>
                    <option value="unknown">알 수 없음</option>
                </select>
            </div>
            <button class="btn btn-primary" onclick="applyFilters()">검색</button>
            <button class="btn btn-secondary" onclick="resetFilters()">초기화</button>
        </div>

        <div class="records">
            <h2>📋 수집된 정보</h2>
            <div id="records-container">
                <div class="loading">로딩 중...</div>
            </div>
        </div>
    </div>

    <div id="detail-modal" class="modal">
        <div class="modal-content">
            <span class="modal-close" onclick="closeModal()">&times;</span>
            <div id="detail-content"></div>
        </div>
    </div>

    <!-- 챗봇 위젯 -->
    <div class="chat-widget-btn" onclick="toggleChat()">
        <span class="chat-icon">🤖</span>
    </div>

    <div class="chat-window" id="chat-window">
        <div class="chat-header">
            <span>OSINT AI Assistant</span>
            <span style="cursor:pointer" onclick="toggleChat()">✕</span>
        </div>
        <div class="chat-messages" id="chat-messages">
            <div class="message ai">
                안녕하세요! 수집된 데이터를 바탕으로 무엇이든 물어보세요.
            </div>
        </div>
        <div class="chat-input-area">
            <input type="text" id="chat-input" placeholder="질문을 입력하세요..." onkeypress="handleKeyPress(event)">
            <button onclick="sendMessage()">➤</button>
        </div>
    </div>

    <script>
        let allRecords = [];

        async function loadStats() {
            try {
                const response = await fetch('/api/statistics');
                const stats = await response.json();

                document.getElementById('total-records').textContent = stats.total_records;
                document.getElementById('safe-count').textContent = stats.threat_levels.safe || 0;
                document.getElementById('suspicious-count').textContent = stats.threat_levels.suspicious || 0;
                document.getElementById('malicious-count').textContent = stats.threat_levels.malicious || 0;
            } catch (error) {
                console.error('통계 로딩 실패:', error);
            }
        }

        async function loadRecords() {
            try {
                const response = await fetch('/api/records');
                allRecords = await response.json();
                displayRecords(allRecords);
            } catch (error) {
                console.error('레코드 로딩 실패:', error);
                document.getElementById('records-container').innerHTML =
                    '<div class="no-records">데이터를 불러올 수 없습니다.</div>';
            }
        }

        function displayRecords(records) {
            const container = document.getElementById('records-container');

            if (records.length === 0) {
                container.innerHTML = '<div class="no-records">수집된 데이터가 없습니다.</div>';
                return;
            }

            let html = `
                <table class="records-table">
                    <thead>
                        <tr>
                            <th>시간</th>
                            <th>타겟</th>
                            <th>수집 방법</th>
                            <th>위협 수준</th>
                            <th>액션</th>
                        </tr>
                    </thead>
                    <tbody>
            `;

            records.forEach(record => {
                const time = new Date(record.timestamp).toLocaleString('ko-KR');
                const threatClass = 'threat-' + record.threat_level;
                const hasPdf = record.pdf_path ? true : false;

                html += `
                    <tr>
                        <td>${time}</td>
                        <td title="${record.target}">${truncate(record.target, 40)}</td>
                        <td>${record.collection_method}</td>
                        <td><span class="threat-badge ${threatClass}">${record.threat_level}</span></td>
                        <td class="action-btns">
                            <button class="btn-small btn-view" onclick='viewDetail(${JSON.stringify(record).replace(/'/g, "&apos;")})'>상세</button>
                            ${hasPdf ? `<button class="btn-small btn-pdf" onclick="downloadPdf('${record.pdf_path}')">PDF</button>` : ''}
                            <button class="btn-small btn-delete" onclick="deleteRecord('${record.timestamp}')">삭제</button>
                        </td>
                    </tr>
                `;
            });

            html += '</tbody></table>';
            container.innerHTML = html;
        }

        function truncate(str, length) {
            return str.length > length ? str.substring(0, length) + '...' : str;
        }

        function applyFilters() {
            const target = document.getElementById('search-target').value.toLowerCase();
            const method = document.getElementById('filter-method').value;
            const threat = document.getElementById('filter-threat').value;

            const filtered = allRecords.filter(record => {
                const matchTarget = !target || record.target.toLowerCase().includes(target);
                const matchMethod = !method || record.collection_method === method;
                const matchThreat = !threat || record.threat_level === threat;
                return matchTarget && matchMethod && matchThreat;
            });

            displayRecords(filtered);
        }

        function resetFilters() {
            document.getElementById('search-target').value = '';
            document.getElementById('filter-method').value = '';
            document.getElementById('filter-threat').value = '';
            displayRecords(allRecords);
        }

        function viewDetail(record) {
            const modal = document.getElementById('detail-modal');
            const content = document.getElementById('detail-content');

            let html = `
                <h2>상세 정보</h2>

                <div class="detail-section">
                    <h3>기본 정보</h3>
                    <p><strong>시간:</strong> ${new Date(record.timestamp).toLocaleString('ko-KR')}</p>
                    <p><strong>타겟:</strong> ${record.target}</p>
                    <p><strong>URL:</strong> ${record.url}</p>
                    <p><strong>수집 방법:</strong> ${record.collection_method}</p>
                    <p><strong>위협 수준:</strong> <span class="threat-badge threat-${record.threat_level}">${record.threat_level}</span></p>
                </div>

                <div class="detail-section">
                    <h3>요약</h3>
                    <p>${record.summary}</p>
                </div>
            `;

            if (Object.keys(record.sensitive_info).length > 0) {
                html += `
                    <div class="detail-section">
                        <h3>중요 정보</h3>
                        <pre>${JSON.stringify(record.sensitive_info, null, 2)}</pre>
                    </div>
                `;
            }

            if (Object.keys(record.metadata).length > 0) {
                html += `
                    <div class="detail-section">
                        <h3>메타데이터</h3>
                        <pre>${JSON.stringify(record.metadata, null, 2)}</pre>
                    </div>
                `;
            }

            content.innerHTML = html;
            modal.style.display = 'block';
        }

        function closeModal() {
            document.getElementById('detail-modal').style.display = 'none';
        }

        async function deleteRecord(timestamp) {
            if (!confirm('정말로 이 레코드를 삭제하시겠습니까?')) {
                return;
            }

            try {
                const response = await fetch(`/api/records/${encodeURIComponent(timestamp)}`, {
                    method: 'DELETE'
                });

                if (response.ok) {
                    alert('삭제되었습니다.');
                    loadRecords();
                    loadStats();
                } else {
                    alert('삭제에 실패했습니다.');
                }
            } catch (error) {
                console.error('삭제 실패:', error);
                alert('삭제 중 오류가 발생했습니다.');
            }
        }

        function downloadPdf(pdfPath) {
            window.open(`/api/pdf?path=${encodeURIComponent(pdfPath)}`, '_blank');
        }

        // 모달 외부 클릭 시 닫기
        window.onclick = function(event) {
            const modal = document.getElementById('detail-modal');
            if (event.target === modal) {
                closeModal();
            }
        }

        // 초기 로딩
        loadStats();
        loadRecords();

        // 30초마다 자동 새로고침
        setInterval(() => {
            loadStats();
            loadRecords();
        }, 30000);

        // 챗봇 관련 스크립트 (WebSocket 적용)
        let ws = null;
        let currentAiMessageId = null;

        function toggleChat() {
            const chatWindow = document.getElementById('chat-window');
            if (chatWindow.style.display === 'none' || chatWindow.style.display === '') {
                chatWindow.style.display = 'flex';
                connectWebSocket(); // 채팅창 열 때 연결
            } else {
                chatWindow.style.display = 'none';
            }
        }

        function connectWebSocket() {
            if (ws && ws.readyState === WebSocket.OPEN) return;

            const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
            const wsUrl = `${protocol}//${window.location.host}/ws/chat`;
            
            ws = new WebSocket(wsUrl);
            
            ws.onmessage = function(event) {
                const data = JSON.parse(event.data);
                handleWsMessage(data);
            };

            ws.onclose = function() {
                // 연결 끊기면 잠시 후 재연결 시도
                setTimeout(connectWebSocket, 3000);
            };
        }

        function handleWsMessage(data) {
            const container = document.getElementById('chat-messages');
            
            if (data.type === 'start') {
                // AI 응답 시작 (메시지 박스 미리 생성)
                currentAiMessageId = addMessage('', 'ai', true);
            } else if (data.type === 'answer') {
                // AI 답변 텍스트 추가
                const el = document.getElementById(currentAiMessageId);
                if (el) {
                    // 로딩 텍스트 제거 및 내용 채우기
                    if (el.textContent === '분석 중...') el.textContent = '';
                    
                    // 텍스트 노드 추가 (기존 도구 로그 유지)
                    const textNode = document.createTextNode(data.content);
                    el.appendChild(textNode);
                    el.id = ''; // 로딩 상태 해제
                    currentAiMessageId = null;
                } else {
                    addMessage(data.content, 'ai');
                }
            } else if (data.type === 'tool_start') {
                // 도구 실행 알림을 현재 AI 메시지 박스 *내부* 상단에 추가하거나,
                // 혹은 별도 박스지만 AI 답변 *전에* 배치
                
                // 여기서는 별도의 tool-status div를 만들되, 답변보다 먼저 보이게 처리
                // 만약 답변 박스(currentAiMessageId)가 이미 있다면 그 *앞*에 삽입해야 함.
                // 하지만 구조상 답변 박스가 먼저 만들어져 있으므로, 답변 박스 *안*의 맨 앞에 넣거나
                // 답변 박스를 잠시 숨기고 도구 박스를 넣는 식이어야 함.
                
                // 가장 쉬운 방법: 도구 상태를 별도 메시지로 취급하되, 시각적으로 구별
                const div = document.createElement('div');
                div.className = 'tool-status';
                div.innerHTML = `🛠️ <strong>${data.tool}</strong> 실행 중...<br><small>${data.args}</small>`;
                
                const aiMsg = document.getElementById(currentAiMessageId);
                if (aiMsg) {
                    // 답변 박스 바로 위에 삽입
                    container.insertBefore(div, aiMsg);
                } else {
                    container.appendChild(div);
                }
                container.scrollTop = container.scrollHeight;
                
            } else if (data.type === 'tool_end') {
                // 도구 실행 완료
                const div = document.createElement('div');
                div.className = 'tool-status';
                div.style.borderLeftColor = '#28a745';
                div.innerHTML = `✅ <strong>${data.tool}</strong> 완료<br><small>${data.result}</small>`;
                
                const aiMsg = document.getElementById(currentAiMessageId);
                if (aiMsg) {
                    container.insertBefore(div, aiMsg);
                } else {
                    container.appendChild(div);
                }
                container.scrollTop = container.scrollHeight;
                
            } else if (data.type === 'error') {
                addMessage(`❌ 오류: ${data.content}`, 'ai');
            } else if (data.type === 'done') {
                currentAiMessageId = null;
            }
        }

        function handleKeyPress(e) {
            if (e.key === 'Enter') sendMessage();
        }

        function sendMessage() {
            const input = document.getElementById('chat-input');
            const message = input.value.trim();
            if (!message) return;

            if (!ws || ws.readyState !== WebSocket.OPEN) {
                alert('서버와 연결되지 않았습니다. 잠시 후 다시 시도해주세요.');
                connectWebSocket();
                return;
            }

            // 사용자 메시지 표시
            addMessage(message, 'user');
            input.value = '';

            // 서버로 전송
            ws.send(JSON.stringify({ message: message }));
        }

        function addMessage(text, type, isLoading = false) {
            const container = document.getElementById('chat-messages');
            const div = document.createElement('div');
            div.className = `message ${type}`;
            if (isLoading) {
                div.id = 'ai-msg-' + Date.now();
                div.textContent = '분석 중...';
            } else {
                div.textContent = text;
            }
            container.appendChild(div);
            container.scrollTop = container.scrollHeight;
            return div.id;
        }

        function removeMessage(id) {
            if(id) {
                const el = document.getElementById(id);
                if(el) el.remove();
            }
        }
    </script>
</body>
</html>
    """


@app.get("/api/statistics")
async def get_statistics():
    """데이터베이스 통계 정보 반환"""
    return db.get_statistics()


@app.get("/api/records")
async def get_records(
    target: Optional[str] = None,
    collection_method: Optional[str] = None,
    threat_level: Optional[str] = None
):
    """모든 레코드 또는 필터링된 레코드 반환"""
    if target or collection_method or threat_level:
        return db.search_records(
            target=target,
            collection_method=collection_method,
            threat_level=threat_level
        )
    return db.get_all_records()


@app.delete("/api/records/{timestamp}")
async def delete_record(timestamp: str):
    """특정 레코드 삭제"""
    success = db.delete_record(timestamp)
    if not success:
        raise HTTPException(status_code=404, detail="레코드를 찾을 수 없습니다.")
    return {"message": "삭제되었습니다."}


@app.get("/api/pdf")
async def get_pdf(path: str):
    """PDF 파일 다운로드"""
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="PDF 파일을 찾을 수 없습니다.")
    return FileResponse(
        path,
        media_type="application/pdf",
        filename=os.path.basename(path)
    )


@app.get("/api/export")
async def export_database():
    """데이터베이스를 JSON으로 내보내기"""
    output_path = "db_export.json"
    success = db.export_to_json(output_path)
    if not success:
        raise HTTPException(status_code=500, detail="내보내기에 실패했습니다.")
    return FileResponse(
        output_path,
        media_type="application/json",
        filename=output_path
    )


# ============================================================================
# WebSocket 채팅 엔드포인트 (Streaming + Memory)
# ============================================================================

# 간단한 인메모리 세션 저장소 (실제 프로덕션에서는 Redis 등을 권장)
chat_sessions: Dict[int, List[Any]] = {}

@app.websocket("/ws/chat")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    
    # 세션 ID 생성 (간단히 메모리 주소 사용하거나 UUID 사용 가능)
    session_id = id(websocket)
    chat_sessions[session_id] = []
    
    if not HAS_LLM:
        await websocket.send_json({"type": "error", "content": "서버에 LLM 라이브러리가 설치되어 있지 않습니다."})
        await websocket.close()
        return

    try:
        # 시스템 프롬프트 (최초 1회 설정)
        system_prompt = SystemMessage(content="""너는 OSINT(공개출처정보) 분석 전문가 AI Agent야.

[핵심 지침]
1. **불필요한 도구 사용 금지**: 인사('안녕'), 일반적인 대화, 배경 지식 질문에는 절대 도구를 호출하지 말고 바로 답변해.
2. **명확한 요청 시 도구 사용**: 사용자가 특정 타겟(IP, 도메인, ID)에 대한 조사, 검색, 분석을 '명시적으로' 요청했을 때만 도구를 사용해.
3. **데이터 우선 확인**: 조사 요청이 오면 먼저 'search_local_db'를 사용해 수집된 데이터를 확인해.
4. **결과 자동 저장**: 조사 도구(Sherlock 등)를 사용하여 유의미한 새로운 정보를 발견하면, 반드시 'save_to_db'를 사용하여 DB에 기록해.
5. **한국어 답변**: 항상 친절하고 전문적인 한국어로 답변해.
""")
        chat_sessions[session_id].append(system_prompt)

        while True:
            # 메시지 수신
            data = await websocket.receive_json()
            user_message = data.get("message", "")
            
            if not user_message:
                continue

            # 1. 모델 설정
            # 사용자가 요청한 Qwen3 모델 사용
            llm = ChatOllama(model="qwen3:14b", temperature=0)
            
            # 2. 도구 준비
            tool_map = {t.name: t for t in tools}
            llm_with_tools = llm.bind_tools(tools)

            # 3. 메시지 히스토리 업데이트
            # 사용자 메시지 추가
            chat_sessions[session_id].append(HumanMessage(content=user_message))
            
            # 문맥 제한 (너무 길어지면 앞부분 자르기 - 시스템 메시지는 유지)
            if len(chat_sessions[session_id]) > 20:
                chat_sessions[session_id] = [chat_sessions[session_id][0]] + chat_sessions[session_id][-15:]

            # 4. 실행 루프 (Streaming)
            await websocket.send_json({"type": "start", "content": "분석을 시작합니다..."})
            
            # 현재 턴에서 사용할 메시지 복사본 (도구 실행 결과 등은 이 턴에서만 유효할 수도 있지만, 히스토리에 남김)
            current_messages = chat_sessions[session_id].copy()
            
            final_response = ""
            for i in range(5): # 최대 5단계
                # LLM 호출
                ai_msg = await llm_with_tools.ainvoke(current_messages)
                current_messages.append(ai_msg) # 대화 흐름에 AI 응답 추가
                
                # 도구 호출이 없는 경우 (최종 답변)
                if not ai_msg.tool_calls:
                    final_response = ai_msg.content
                    # 최종 답변을 세션 히스토리에 저장
                    chat_sessions[session_id].append(ai_msg)
                    
                    # 답변 전송 (도구 실행 내역이 먼저 출력된 후 마지막에 출력됨)
                    await websocket.send_json({"type": "answer", "content": final_response})
                    break
                
                # 도구 호출 감지 및 실행
                for tool_call in ai_msg.tool_calls:
                    tool_name = tool_call["name"]
                    tool_args = tool_call["args"]
                    
                    # UI에 알림 (도구 실행 시작)
                    await websocket.send_json({
                        "type": "tool_start", 
                        "tool": tool_name, 
                        "args": str(tool_args)
                    })
                    
                    # 도구 실행
                    if tool_name in tool_map:
                        tool_func = tool_map[tool_name]
                        try:
                            tool_result = await tool_func.ainvoke(tool_args)
                        except Exception as e:
                            tool_result = f"Error executing {tool_name}: {str(e)}"
                    else:
                        tool_result = f"Error: Tool {tool_name} not found"
                    
                    # 결과 메시지 추가
                    tool_msg = ToolMessage(content=str(tool_result), tool_call_id=tool_call["id"])
                    current_messages.append(tool_msg)
                    
                    # UI에 결과 알림 (도구 실행 완료)
                    preview = str(tool_result)[:300] + "..." if len(str(tool_result)) > 300 else str(tool_result)
                    await websocket.send_json({
                        "type": "tool_end", 
                        "tool": tool_name, 
                        "result": preview
                    })
            
            # 도구 실행 과정을 포함한 전체 대화를 히스토리에 반영
            chat_sessions[session_id] = current_messages

            await websocket.send_json({"type": "done"})

    except WebSocketDisconnect:
        print("WebSocket disconnected")
        if session_id in chat_sessions:
            del chat_sessions[session_id] # 연결 끊기면 세션 삭제
    except Exception as e:
        import traceback
        traceback.print_exc()
        await websocket.send_json({"type": "error", "content": f"오류 발생: {str(e)}"})


@app.post("/api/chat")
async def chat_endpoint(request: ChatRequest):
    """기존 HTTP 엔드포인트 (하위 호환성 유지)"""
    if not HAS_LLM:
        return {"response": "서버에 LLM 라이브러리가 설치되어 있지 않습니다."}

    try:
        # 1. 모델 설정
        llm = ChatOllama(model="qwen3:14b", temperature=0)
        
        # 2. DB 컨텍스트 구성
        records = db.get_all_records()
        recent_records = records[-5:] if len(records) > 5 else records
        db_context = "최근 수집된 데이터:\n"
        for r in recent_records:
            db_context += f"- [{r['timestamp']}] {r['target']} ({r['collection_method']}): {r['threat_level']}\n"
        if not recent_records:
            db_context = "최근 수집된 데이터가 없습니다."

        # 3. 직접 구현한 Agent 실행 루프 (LangChain AgentExecutor 대체)
        
        # 도구 이름과 설명 매핑
        tool_map = {t.name: t for t in tools}
        
        messages = [
            SystemMessage(content=f"""너는 OSINT(공개출처정보) 분석 전문가 AI Agent야.

[핵심 지침]
1. **불필요한 도구 사용 금지**: 인사('안녕'), 일반적인 대화, 배경 지식 질문에는 절대 도구를 호출하지 말고 바로 답변해.
2. **명확한 요청 시 도구 사용**: 사용자가 특정 타겟(IP, 도메인, ID)에 대한 조사, 검색, 분석을 '명시적으로' 요청했을 때만 도구를 사용해.
3. **데이터 우선 확인**: 조사 요청이 오면 먼저 아래 [수집된 데이터]에 정보가 있는지 확인해.
4. **한국어 답변**: 항상 친절하고 전문적인 한국어로 답변해.

[수집된 데이터]
{db_context}
"""),
            HumanMessage(content=request.message)
        ]

        # 모델에 도구 바인딩
        llm_with_tools = llm.bind_tools(tools)
        
        # 실행 루프 (최대 5회)
        final_response = ""
        for _ in range(5):
            # LLM 호출
            ai_msg = await llm_with_tools.ainvoke(messages)
            messages.append(ai_msg)
            
            # 도구 호출이 없는 경우 (최종 답변)
            if not ai_msg.tool_calls:
                final_response = ai_msg.content
                break
                
            # 도구 호출 실행
            for tool_call in ai_msg.tool_calls:
                tool_name = tool_call["name"]
                tool_args = tool_call["args"]
                
                # 도구 실행
                if tool_name in tool_map:
                    tool_func = tool_map[tool_name]
                    try:
                        # 비동기 도구 실행
                        tool_result = await tool_func.ainvoke(tool_args)
                    except Exception as e:
                        tool_result = f"Error executing {tool_name}: {str(e)}"
                else:
                    tool_result = f"Error: Tool {tool_name} not found"
                
                # 결과 메시지 추가
                messages.append(ToolMessage(content=str(tool_result), tool_call_id=tool_call["id"]))
        
        return {"response": final_response}
        
    except Exception as e:
        print(f"Chat Error: {e}")
        # 에러 발생 시 단순 RAG로 폴백하거나 에러 메시지 반환
        return {"response": f"처리 중 오류가 발생했습니다 (도구 호출 실패 등). 다시 시도해주세요. ({str(e)})"}


if __name__ == "__main__":
    print("=" * 70)
    print("🌐 OSINT Dashboard 시작")
    print("=" * 70)
    print("📊 대시보드: http://localhost:8000")
    print("📖 API 문서: http://localhost:8000/docs")
    print("=" * 70)

    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        log_level="info"
    )
