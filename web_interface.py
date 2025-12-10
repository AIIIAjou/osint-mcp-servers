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
GOOGLE_SAFE_BROWSING_API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "")
URLSCAN_API_KEY = os.getenv("URLSCAN_API_KEY", "")

# OSINT 도구 클래스 직접 구현 (server_stdio.py 의존성 제거)
HAS_TOOLS = True

# 추가 패키지 설치 확인
try:
    import whois
    HAS_WHOIS = True
except ImportError:
    HAS_WHOIS = False
    print("⚠️ whois 패키지가 설치되지 않았습니다. 도메인 분석 기능이 제한됩니다.")
    print("   설치 명령어: pip install python-whois")

class SherlockClient:
    """Sherlock 래퍼 (간소화 버전)"""
    def __init__(self):
        pass

    async def search(self, username: str, sites: List[str] = None):
        try:
            cmd = ["sherlock", username, "--timeout", "5", "--print-found"]
            if sites:
                for site in sites:
                    cmd.extend(["--site", site])

            try:
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
            except FileNotFoundError:
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

            txt_file = f"{username}.txt"
            if os.path.exists(txt_file):
                try:
                    os.remove(txt_file)
                except Exception:
                    pass

            output = stdout.decode()
            found_sites = []
            for line in output.splitlines():
                if "[+]" in line:
                    parts = line.split(": ")
                    if len(parts) >= 2:
                        found_sites.append({"site": parts[0].replace("[+]", "").strip(), "url": parts[1].strip()})
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


class GoogleSafeBrowsingClient:
    """Google Safe Browsing API 클라이언트"""

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

    async def check_url_threat(self, url: str) -> dict:
        """URL의 안전성을 Google Safe Browsing으로 확인"""
        if not self.api_key:
            return {"error": "Google Safe Browsing API 키가 설정되지 않았습니다."}

        import aiohttp
        payload = {
            "client": {
                "clientId": "osint-dashboard",
                "clientVersion": "1.0.0"
            },
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }

        async with aiohttp.ClientSession() as session:
            try:
                params = {"key": self.api_key}
                async with session.post(self.base_url, params=params, json=payload) as response:
                    if response.status == 200:
                        data = await response.json()
                        return self._parse_safe_browsing_response(data, url)
                    else:
                        return {"error": f"Google Safe Browsing API 오류: {response.status}"}
            except Exception as e:
                return {"error": f"Safe Browsing 조회 실패: {str(e)}"}

    def _parse_safe_browsing_response(self, data: dict, url: str) -> dict:
        """Safe Browsing 응답 파싱"""
        if "matches" in data and data["matches"]:
            threats = []
            for match in data["matches"]:
                threats.append({
                    "threat_type": match.get("threatType", "UNKNOWN"),
                    "platform_type": match.get("platformType", "UNKNOWN"),
                    "cache_duration": match.get("cacheDuration", "")
                })

            return {
                "url": url,
                "threat_level": "malicious",
                "threat_detected": True,
                "threats": threats,
                "recommendation": "🚨 악성 사이트로 판정됨! 접근하지 마세요."
            }
        else:
            return {
                "url": url,
                "threat_level": "safe",
                "threat_detected": False,
                "threats": [],
                "recommendation": "✅ Google Safe Browsing에서 안전한 사이트로 확인됨."
            }


class SSLClient:
    """SSL 인증서 분석 클라이언트"""

    async def analyze_ssl_certificate(self, domain: str) -> dict:
        """도메인의 SSL 인증서 분석"""
        try:
            import ssl
            import socket
            from datetime import datetime

            # SSL 연결 시도
            context = ssl.create_default_context()
            conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=domain)

            conn.settimeout(10)
            conn.connect((domain, 443))

            # 인증서 정보 가져오기
            cert = conn.getpeercert()
            conn.close()

            # 인증서 유효성 검증
            cert_valid = self._validate_certificate(cert, domain)

            return {
                "domain": domain,
                "ssl_valid": cert_valid["valid"],
                "issuer": cert.get("issuer", []),
                "subject": cert.get("subject", []),
                "valid_from": cert.get("notBefore", ""),
                "valid_until": cert.get("notAfter", ""),
                "serial_number": cert.get("serialNumber", ""),
                "warnings": cert_valid["warnings"]
            }

        except ssl.SSLError as e:
            return {
                "domain": domain,
                "ssl_valid": False,
                "error": f"SSL 오류: {str(e)}",
                "warnings": ["SSL 연결 실패 - 피싱 사이트 가능성 높음"]
            }
        except Exception as e:
            return {
                "domain": domain,
                "ssl_valid": False,
                "error": f"SSL 분석 실패: {str(e)}",
                "warnings": ["SSL 인증서 확인 불가"]
            }

    def _validate_certificate(self, cert: dict, domain: str) -> dict:
        """인증서 유효성 검증"""
        warnings = []
        from datetime import datetime

        try:
            # 유효 기간 확인
            not_before = datetime.strptime(cert.get("notBefore", ""), "%b %d %H:%M:%S %Y %Z")
            not_after = datetime.strptime(cert.get("notAfter", ""), "%b %d %H:%M:%S %Y %Z")
            now = datetime.now()

            if now < not_before:
                warnings.append("인증서가 아직 유효하지 않음")
            if now > not_after:
                warnings.append("인증서가 만료됨")

            # 도메인 일치 확인
            subject_alt_names = []
            for field in cert.get("subjectAltName", []):
                if field[0] == "DNS":
                    subject_alt_names.append(field[1])

            if domain not in subject_alt_names:
                common_name = ""
                for item in cert.get("subject", []):
                    if item[0][0] == "commonName":
                        common_name = item[0][1]
                        break

                if domain != common_name:
                    warnings.append("도메인이 인증서와 일치하지 않음")

            # 발급자 확인
            issuer_org = ""
            for item in cert.get("issuer", []):
                if item[0][0] == "organizationName":
                    issuer_org = item[0][1]
                    break

            if not issuer_org:
                warnings.append("인증서 발급자 정보 불명확")

        except Exception as e:
            warnings.append(f"인증서 검증 오류: {str(e)}")

        return {
            "valid": len(warnings) == 0,
            "warnings": warnings
        }


class DomainAnalysisClient:
    """도메인 분석 클라이언트"""

    async def analyze_domain_age(self, domain: str) -> dict:
        """도메인의 등록 일자 및 수명 분석"""
        try:
            import whois
            from datetime import datetime, timedelta

            # WHOIS 조회
            w = whois.whois(domain)

            result = {
                "domain": domain,
                "creation_date": None,
                "expiration_date": None,
                "registrar": w.registrar if hasattr(w, 'registrar') else None,
                "domain_age_days": None,
                "suspicious_indicators": []
            }

            # 생성일 분석
            if hasattr(w, 'creation_date') and w.creation_date:
                if isinstance(w.creation_date, list):
                    creation_date = w.creation_date[0]
                else:
                    creation_date = w.creation_date

                result["creation_date"] = creation_date.isoformat() if hasattr(creation_date, 'isoformat') else str(creation_date)

                # 도메인 수명 계산
                now = datetime.now()
                if hasattr(creation_date, 'replace'):  # datetime 객체인 경우
                    age = now - creation_date.replace(tzinfo=None)
                    result["domain_age_days"] = age.days

                    # 의심스러운 징후들
                    if age.days < 30:
                        result["suspicious_indicators"].append("매우 최근에 등록된 도메인 (< 30일)")
                    elif age.days < 90:
                        result["suspicious_indicators"].append("최근에 등록된 도메인 (< 90일)")

            # 만료일 분석
            if hasattr(w, 'expiration_date') and w.expiration_date:
                if isinstance(w.expiration_date, list):
                    expiration_date = w.expiration_date[0]
                else:
                    expiration_date = w.expiration_date

                result["expiration_date"] = expiration_date.isoformat() if hasattr(expiration_date, 'isoformat') else str(expiration_date)

                # 곧 만료되는 도메인
                if hasattr(expiration_date, 'replace'):
                    now = datetime.now()
                    time_to_expiry = expiration_date.replace(tzinfo=None) - now
                    if time_to_expiry.days < 30:
                        result["suspicious_indicators"].append("곧 만료되는 도메인 (< 30일)")

            return result

        except Exception as e:
            return {
                "domain": domain,
                "error": f"WHOIS 조회 실패: {str(e)}",
                "suspicious_indicators": ["WHOIS 정보 조회 불가 - 의심스러운 도메인"]
            }


class PlaywrightClient:
    """Playwright 웹 분석 클라이언트 (강화 버전)"""
    async def analyze_url(self, url: str, generate_pdf: bool = True):
        from playwright.async_api import async_playwright
        from bs4 import BeautifulSoup
        import re

        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                page = await browser.new_page()
                await page.goto(url, wait_until="networkidle", timeout=30000)

                title = await page.title()
                content = await page.content()

                soup = BeautifulSoup(content, "html.parser")
                text = soup.get_text(separator=" ", strip=True)[:2000]

                emails = list(set(re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', content)))
                phones = list(set(re.findall(r'(\+?\d{1,3}[-.\s]?)?\(?\d{2,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4}', content)))
                links = [a.get('href') for a in soup.find_all('a', href=True)][:50]

                social_media = []
                social_patterns = {
                    'twitter': r'https?://(?:www\.)?twitter\.com/[\w]+',
                    'facebook': r'https?://(?:www\.)?facebook\.com/[\w.]+',
                    'linkedin': r'https?://(?:www\.)?linkedin\.com/[\w/]+',
                    'instagram': r'https?://(?:www\.)?instagram\.com/[\w.]+',
                    'github': r'https?://(?:www\.)?github\.com/[\w-]+'
                }
                for platform, pattern in social_patterns.items():
                    matches = re.findall(pattern, content)
                    if matches:
                        social_media.extend([{"platform": platform, "url": m} for m in matches[:5]])

                meta_description = soup.find('meta', attrs={'name': 'description'})
                meta_keywords = soup.find('meta', attrs={'name': 'keywords'})

                metadata = {
                    "description": meta_description.get('content') if meta_description else "",
                    "keywords": meta_keywords.get('content') if meta_keywords else "",
                    "link_count": len(links)
                }

                pdf_path = ""
                if generate_pdf:
                    try:
                        from pdf_generator import PDFGenerator
                        pdf_gen = PDFGenerator()
                        pdf_path = await pdf_gen.url_to_pdf(url)
                    except Exception as pdf_error:
                        print(f"⚠️ PDF 생성 실패: {pdf_error}")

                await browser.close()

                return {
                    "url": url,
                    "title": title,
                    "text_summary": text,
                    "emails": emails,
                    "phones": phones,
                    "links": links,
                    "social_media": social_media,
                    "metadata": metadata,
                    "pdf_path": pdf_path
                }
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
    Playwright를 사용하여 웹페이지에 직접 접속해 상세 정보를 추출합니다.

    추출 정보:
    - 페이지 제목 및 메타데이터
    - 본문 텍스트 요약
    - 이메일 주소, 전화번호
    - 모든 링크 및 소셜 미디어 링크
    - PDF 스냅샷 자동 생성

    웹사이트의 내용을 자세히 파악하거나 요약할 때 사용합니다.
    """
    if not HAS_TOOLS:
        return "도구 모듈을 로드할 수 없어 실행할 수 없습니다."

    client = PlaywrightClient()
    result = await client.analyze_url(url, generate_pdf=True)
    return json.dumps(result, ensure_ascii=False)

@tool
async def search_leaks(term: str) -> str:
    """
    Intelligence X를 사용하여 이메일, 도메인 등의 유출 정보를 검색합니다.
    다크웹이나 해킹된 데이터베이스에 정보가 있는지 확인할 때 사용합니다.
    """
    if not HAS_TOOLS:
        return "도구 모듈을 로드할 수 없어 실행할 수 없습니다."

    return json.dumps({"message": "Intelligence X 기능은 현재 API 키 설정이 필요합니다."}, ensure_ascii=False)

@tool
async def check_google_safe_browsing(url: str) -> str:
    """
    Google Safe Browsing API를 사용하여 URL이 악성 사이트인지 확인합니다.
    피싱, 멀웨어, 원치 않는 소프트웨어 등을 탐지할 때 사용합니다.
    """
    if not HAS_TOOLS:
        return "도구 모듈을 로드할 수 없어 실행할 수 없습니다."

    client = GoogleSafeBrowsingClient(GOOGLE_SAFE_BROWSING_API_KEY)
    result = await client.check_url_threat(url)
    return json.dumps(result, ensure_ascii=False)

@tool
async def analyze_ssl_certificate(domain: str) -> str:
    """
    도메인의 SSL 인증서 유효성을 분석합니다.
    유효하지 않은 SSL 인증서는 피싱 사이트의 징후일 수 있습니다.
    """
    if not HAS_TOOLS:
        return "도구 모듈을 로드할 수 없어 실행할 수 없습니다."

    client = SSLClient()
    result = await client.analyze_ssl_certificate(domain)
    return json.dumps(result, ensure_ascii=False)

@tool
async def analyze_domain_age(domain: str) -> str:
    """
    도메인의 등록 일자, 만료일, 등록 기관 등을 분석합니다.
    최근 등록된 도메인이나 이상한 등록 정보는 의심스러운 징후입니다.
    """
    if not HAS_TOOLS:
        return "도구 모듈을 로드할 수 없어 실행할 수 없습니다."

    client = DomainAnalysisClient()
    result = await client.analyze_domain_age(domain)
    return json.dumps(result, ensure_ascii=False)

@tool
async def comprehensive_security_check(url: str) -> str:
    """
    URL에 대한 종합 보안 검사를 수행합니다.
    VirusTotal, Google Safe Browsing, SSL 분석, 도메인 수명 분석을 모두 실행합니다.
    """
    if not HAS_TOOLS:
        return "도구 모듈을 로드할 수 없어 실행할 수 없습니다."

    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        domain = parsed.netloc
        if not domain:
            domain = url.replace("https://", "").replace("http://", "").split("/")[0]

        results = {}

        # 1. VirusTotal 도메인 검사
        vt_client = VirusTotalClient(VIRUSTOTAL_API_KEY)
        vt_result = await vt_client.get_domain_report(domain)
        results["virustotal"] = vt_result

        # 2. Google Safe Browsing
        gsb_client = GoogleSafeBrowsingClient(GOOGLE_SAFE_BROWSING_API_KEY)
        gsb_result = await gsb_client.check_url_threat(url)
        results["google_safe_browsing"] = gsb_result

        # 3. SSL 인증서 분석
        ssl_client = SSLClient()
        ssl_result = await ssl_client.analyze_ssl_certificate(domain)
        results["ssl_analysis"] = ssl_result

        # 4. 도메인 수명 분석
        domain_client = DomainAnalysisClient()
        domain_result = await domain_client.analyze_domain_age(domain)
        results["domain_analysis"] = domain_result

        # 종합 판정
        threat_levels = []
        if "stats" in vt_result and vt_result["stats"]:
            malicious = vt_result["stats"].get("malicious", 0)
            suspicious = vt_result["stats"].get("suspicious", 0)
            if malicious > 0:
                threat_levels.append("malicious")
            elif suspicious > 0:
                threat_levels.append("suspicious")

        if gsb_result.get("threat_detected"):
            threat_levels.append("malicious")

        if not ssl_result.get("ssl_valid"):
            threat_levels.append("suspicious")

        if domain_result.get("suspicious_indicators"):
            threat_levels.append("suspicious")

        # 최종 판정
        if "malicious" in threat_levels:
            final_threat_level = "malicious"
        elif "suspicious" in threat_levels:
            final_threat_level = "suspicious"
        else:
            final_threat_level = "safe"

        results["comprehensive_analysis"] = {
            "url": url,
            "domain": domain,
            "final_threat_level": final_threat_level,
            "threat_indicators": threat_levels,
            "recommendation": {
                "malicious": "🚨 이 사이트는 악성으로 판정되었습니다. 절대 접근하지 마세요!",
                "suspicious": "⚠️ 이 사이트는 의심스러운 징후가 있습니다. 주의해서 접근하세요.",
                "safe": "✅ 이 사이트는 안전한 것으로 보입니다."
            }.get(final_threat_level, "알 수 없음")
        }

        return json.dumps(results, ensure_ascii=False)

    except Exception as e:
        return json.dumps({"error": f"종합 보안 검사 실패: {str(e)}"}, ensure_ascii=False)

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

# 도구명과 의미 있는 수집 방법 매핑
METHOD_MAPPINGS = {
    "search_username": "사용자명 소셜 미디어 검색",
    "check_domain_reputation": "도메인 보안 평판 확인",
    "check_ip_reputation": "IP 주소 보안 평판 확인",
    "analyze_webpage": "URL 유해성 검증",
    "analyze_url_playwright": "URL 유해성 검증",
    "search_leaks": "유출 정보 검색",
    "search_local_db": "로컬 데이터베이스 검색",
    "crawl_and_analyze_url": "웹사이트 전체 분석",
    "auto_explore_webpage": "자동 웹 탐색",
    "deep_analyze_urls": "재귀 URL 분석",
    "interact_with_webpage": "웹페이지 상호작용 분석",
    "check_virustotal_domain": "VirusTotal 도메인 검사",
    "check_virustotal_ip": "VirusTotal IP 검사",
    "check_google_safe_browsing": "Google 안전 브라우징 검사",
    "analyze_ssl_certificate": "SSL 인증서 분석",
    "analyze_domain_age": "도메인 수명 분석",
    "comprehensive_security_check": "종합 보안 검사"
}

@tool
async def save_to_db(
    target: str,
    summary: str,
    method: str,
    url: str = "",
    pdf_path: str = "",
    emails: list = None,
    phones: list = None,
    social_media: list = None,
    threat_level: str = "unknown",
    additional_metadata: dict = None
) -> str:
    """
    조사 결과(정보)를 데이터베이스에 저장합니다.
    새로운 유의미한 정보를 발견했을 때 반드시 이 도구를 사용하여 기록을 남겨야 합니다.

    Args:
        target: 조사 대상 (예: username, domain, IP)
        summary: 발견된 정보의 상세한 요약 (한글로 작성, 가능한 길고 자세하게)
        method: 사용한 도구 이름 (예: search_username, check_domain_reputation, analyze_webpage)
        url: 관련 URL (있는 경우)
        pdf_path: PDF 스냅샷 경로 (있는 경우)
        emails: 발견된 이메일 주소 리스트
        phones: 발견된 전화번호 리스트
        social_media: 발견된 소셜 미디어 링크 리스트
        threat_level: 위협 수준 (safe, suspicious, malicious, unknown 중 하나)
        additional_metadata: 추가 메타데이터 (dict)

    중요: summary는 발견된 모든 중요 정보를 포함하여 최대한 상세하게 작성해야 합니다.
    """
    try:
        # 도구명을 의미 있는 수집 방법으로 변환
        display_method = METHOD_MAPPINGS.get(method, method)
        print(f"[DEBUG] save_to_db 호출됨 - target: {target}, method: {method} → {display_method}")

        sensitive_info = {}
        if emails:
            sensitive_info["emails"] = emails
        if phones:
            sensitive_info["phones"] = phones
        if social_media:
            sensitive_info["social_media"] = social_media

        metadata = {"source": "AI Chatbot Agent"}
        if additional_metadata:
            metadata.update(additional_metadata)

        print(f"[DEBUG] DB 경로: {db.db_path}")
        print(f"[DEBUG] 저장 시도 - target: {target}, url: {url}, summary 길이: {len(summary)}")

        success = db.add_record(
            target=target,
            url=url,
            pdf_path=pdf_path,
            summary=summary,
            sensitive_info=sensitive_info,
            collection_method=display_method,
            threat_level=threat_level,
            metadata=metadata
        )

        print(f"[DEBUG] 저장 결과: {success}")

        if success:
            return f"✅ 데이터베이스에 성공적으로 저장되었습니다.\n- 타겟: {target}\n- URL: {url or '없음'}\n- PDF: {'생성됨' if pdf_path else '없음'}\n- DB 경로: {db.db_path}"
        else:
            return "❌ 저장에 실패했습니다."
    except Exception as e:
        import traceback
        error_detail = traceback.format_exc()
        print(f"[ERROR] save_to_db 오류: {error_detail}")
        return f"❌ 저장 중 오류 발생: {str(e)}\n상세: {error_detail}"

# 사용 가능한 도구 목록
tools = [search_username, check_domain_reputation, check_ip_reputation, analyze_webpage, search_leaks, search_local_db, check_google_safe_browsing, analyze_ssl_certificate, analyze_domain_age, comprehensive_security_check, save_to_db]



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
    <!-- Marked.js for Markdown rendering -->
    <script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        html, body {
            height: 100vh;
            overflow: auto;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            display: flex;
            flex-direction: column;
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
            width: 100%;
            min-height: 100vh;
            padding: 20px;
            display: flex;
            flex-direction: column;
            gap: 20px;
            overflow: visible;
        }

        .header {
            background: white;
            padding: 20px 30px;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
            flex-shrink: 0;
        }

        .header h1 {
            color: #333;
            margin-bottom: 5px;
            font-size: 2em;
        }

        .header p {
            color: #666;
            font-size: 1em;
        }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            flex-shrink: 0;
        }

        .stat-card {
            background: white;
            padding: 20px;
            border-radius: 15px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
            transition: transform 0.3s ease;
        }

        .stat-card:hover {
            transform: translateY(-5px);
        }

        .stat-card h3 {
            color: #888;
            font-size: 0.85em;
            text-transform: uppercase;
            margin-bottom: 8px;
            font-weight: 600;
        }

        .stat-card .value {
            color: #667eea;
            font-size: 2em;
            font-weight: bold;
        }

        .filters {
            background: white;
            padding: 20px;
            border-radius: 15px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
            flex-shrink: 0;
        }

        .filters h2 {
            margin-bottom: 15px;
            color: #333;
            font-size: 1.3em;
        }

        .filter-group {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 15px;
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
            padding: 20px;
            border-radius: 15px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
            flex: 1;
            display: flex;
            flex-direction: column;
            overflow: visible;
            min-height: 0;
        }

        #records-container {
            flex: 1;
            display: flex;
            flex-direction: column;
            min-height: 0;
            overflow: hidden;
        }

        .records h2 {
            margin-bottom: 15px;
            color: #333;
            font-size: 1.3em;
            flex-shrink: 0;
        }

        .records-table-wrapper {
            width: 100%;
            flex: 1;
            min-height: 0;
            overflow-y: auto;
            overflow-x: auto;
            border: 1px solid #e0e0e0;
            border-radius: 8px;
            scrollbar-width: thin;
            scrollbar-color: #667eea #f0f0f0;
        }

        .records-table-wrapper::-webkit-scrollbar {
            width: 8px;
            height: 8px;
        }

        .records-table-wrapper::-webkit-scrollbar-track {
            background: #f0f0f0;
            border-radius: 4px;
        }

        .records-table-wrapper::-webkit-scrollbar-thumb {
            background: #667eea;
            border-radius: 4px;
        }

        .records-table-wrapper::-webkit-scrollbar-thumb:hover {
            background: #5568d3;
        }

        .records-table {
            width: 100%;
            border-collapse: collapse;
            table-layout: fixed;
        }

        .records-table thead {
            position: sticky;
            top: 0;
            background: #f8f9fa;
            z-index: 10;
        }

        .records-table th {
            padding: 12px 8px;
            text-align: left;
            font-weight: 600;
            color: #555;
            border-bottom: 2px solid #e0e0e0;
            background: #f8f9fa;
        }

        .records-table td {
            padding: 10px 8px;
            border-bottom: 1px solid #f0f0f0;
            vertical-align: middle;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }

        /* 칼럼별 너비 설정 */
        .records-table col:nth-child(1) { width: 11%; } /* 시간 */
        .records-table col:nth-child(2) { width: 10%; } /* 타겟 */
        .records-table col:nth-child(3) { width: 14%; } /* URL */
        .records-table col:nth-child(4) { width: 22%; } /* 요약 */
        .records-table col:nth-child(5) { width: 13%; } /* 수집 방법 */
        .records-table col:nth-child(6) { width: 10%; } /* 위협 수준 */
        .records-table col:nth-child(7) { width: 20%; } /* 액션 */

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

        .records-table td:nth-child(7) {
            white-space: normal;
        }

        .action-btns {
            display: flex;
            gap: 4px;
            justify-content: center;
            align-items: center;
            flex-wrap: wrap;
        }

        .btn-small {
            padding: 5px 8px;
            font-size: 0.7em;
            border-radius: 4px;
            border: none;
            cursor: pointer;
            transition: all 0.2s;
            white-space: nowrap;
            min-width: 40px;
            height: 24px;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            font-weight: 500;
            line-height: 1;
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
            .container {
                padding: 10px;
                gap: 10px;
            }

            .header {
                padding: 15px 20px;
            }

            .header h1 {
                font-size: 1.5em;
            }

            .header p {
                font-size: 0.9em;
            }

            .stats-grid {
                grid-template-columns: 1fr 1fr;
                gap: 10px;
            }

            .stat-card {
                padding: 15px;
            }

            .stat-card .value {
                font-size: 1.5em;
            }

            .filter-group {
                grid-template-columns: 1fr;
            }

            .records {
                padding: 15px;
            }

            .records-table {
                font-size: 0.75em;
            }

            .records-table th,
            .records-table td {
                padding: 8px 4px;
            }

            .btn-small {
                font-size: 0.65em;
                padding: 4px 6px;
                min-width: 35px;
                height: 22px;
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

        /* Markdown styling in messages */
        .message h1, .message h2, .message h3 {
            margin-top: 10px;
            margin-bottom: 5px;
            font-weight: bold;
        }

        .message h1 { font-size: 1.3em; }
        .message h2 { font-size: 1.2em; }
        .message h3 { font-size: 1.1em; }

        .message ul, .message ol {
            margin-left: 20px;
            margin-top: 5px;
            margin-bottom: 5px;
        }

        .message li {
            margin: 3px 0;
        }

        .message code {
            background: #f0f0f0;
            padding: 2px 5px;
            border-radius: 3px;
            font-family: monospace;
            font-size: 0.9em;
        }

        .message pre {
            background: #f0f0f0;
            padding: 10px;
            border-radius: 5px;
            overflow-x: auto;
            margin: 5px 0;
        }

        .message pre code {
            background: none;
            padding: 0;
        }

        .message blockquote {
            border-left: 3px solid #667eea;
            padding-left: 10px;
            margin: 5px 0;
            color: #666;
        }

        .message a {
            color: #667eea;
            text-decoration: underline;
        }

        .message strong {
            font-weight: bold;
        }

        .message em {
            font-style: italic;
        }

        .message p {
            margin: 5px 0;
        }

        .message table {
            border-collapse: collapse;
            margin: 10px 0;
            width: 100%;
        }

        .message th, .message td {
            border: 1px solid #ddd;
            padding: 8px;
            text-align: left;
        }

        .message th {
            background: #f0f0f0;
            font-weight: bold;
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

        .chat-input-area input:disabled {
            background: #f5f5f5;
            cursor: not-allowed;
        }

        .chat-input-area button {
            background: #667eea;
            color: white;
            border: none;
            width: 40px;
            height: 40px;
            border-radius: 50%;
            cursor: pointer;
            transition: all 0.3s;
        }

        .chat-input-area button:disabled {
            background: #ccc;
            cursor: not-allowed;
            opacity: 0.6;
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

        /* Typing indicator animation */
        .typing-indicator {
            display: inline-flex;
            align-items: center;
            gap: 4px;
            padding: 10px 15px;
        }

        .typing-indicator span {
            width: 8px;
            height: 8px;
            background: #999;
            border-radius: 50%;
            animation: typing 1.4s infinite;
        }

        .typing-indicator span:nth-child(2) {
            animation-delay: 0.2s;
        }

        .typing-indicator span:nth-child(3) {
            animation-delay: 0.4s;
        }

        @keyframes typing {
            0%, 60%, 100% {
                transform: translateY(0);
                opacity: 0.4;
            }
            30% {
                transform: translateY(-10px);
                opacity: 1;
            }
        }

        /* Processing badge */
        .processing-badge {
            display: inline-block;
            padding: 3px 10px;
            background: #667eea;
            color: white;
            border-radius: 10px;
            font-size: 0.75em;
            margin-left: 8px;
            animation: pulse 1.5s infinite;
        }

        .completed-badge {
            display: inline-block;
            padding: 3px 10px;
            background: #28a745;
            color: white;
            border-radius: 10px;
            font-size: 0.75em;
            margin-left: 8px;
        }

        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
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
                    <option value="URL 유해성 검증">URL 유해성 검증</option>
                    <option value="웹사이트 전체 분석">웹사이트 전체 분석</option>
                    <option value="VirusTotal 도메인 검사">VirusTotal 도메인 검사</option>
                    <option value="VirusTotal IP 검사">VirusTotal IP 검사</option>
                    <option value="유출 정보 검색">유출 정보 검색</option>
                    <option value="사용자명 소셜 미디어 검색">사용자명 소셜 미디어 검색</option>
                    <option value="도메인 보안 평판 확인">도메인 보안 평판 확인</option>
                    <option value="IP 주소 보안 평판 확인">IP 주소 보안 평판 확인</option>
                    <option value="자동 웹 탐색">자동 웹 탐색</option>
                    <option value="재귀 URL 분석">재귀 URL 분석</option>
                    <option value="웹페이지 상호작용 분석">웹페이지 상호작용 분석</option>
                    <option value="로컬 데이터베이스 검색">로컬 데이터베이스 검색</option>
                    <option value="Google 안전 브라우징 검사">Google 안전 브라우징 검사</option>
                    <option value="SSL 인증서 분석">SSL 인증서 분석</option>
                    <option value="도메인 수명 분석">도메인 수명 분석</option>
                    <option value="종합 보안 검사">종합 보안 검사</option>
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
                console.log('[DEBUG] 레코드 로딩 시작...');
                const response = await fetch('/api/records?_=' + Date.now());
                allRecords = await response.json();
                console.log(`[DEBUG] 로딩된 레코드 수: ${allRecords.length}`);
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
                <div class="records-table-wrapper">
                    <table class="records-table">
                        <colgroup>
                            <col>
                            <col>
                            <col>
                            <col>
                            <col>
                            <col>
                            <col>
                        </colgroup>
                        <thead>
                            <tr>
                                <th>시간</th>
                                <th>타겟</th>
                                <th>URL</th>
                                <th>요약</th>
                                <th>수집 방법</th>
                                <th>위협 수준</th>
                                <th>액션</th>
                            </tr>
                        </thead>
                        <tbody>
            `;

            records.forEach(record => {
                const time = new Date(record.timestamp).toLocaleString('ko-KR', {
                    month: '2-digit',
                    day: '2-digit',
                    hour: '2-digit',
                    minute: '2-digit'
                });
                const threatClass = 'threat-' + record.threat_level;
                const hasPdf = record.pdf_path ? true : false;

                html += `
                    <tr>
                        <td title="${new Date(record.timestamp).toLocaleString('ko-KR')}">${time}</td>
                        <td title="${record.target}">${record.target}</td>
                        <td title="${record.url}">${record.url ? `<a href="${record.url}" target="_blank" style="color: #667eea; text-decoration: none;">${record.url}</a>` : '-'}</td>
                        <td title="${record.summary}">${record.summary}</td>
                        <td title="${record.collection_method}">${record.collection_method}</td>
                        <td><span class="threat-badge ${threatClass}">${record.threat_level}</span></td>
                        <td>
                            <div class="action-btns">
                                <button class="btn-small btn-view" onclick='viewDetail(${JSON.stringify(record).replace(/'/g, "&apos;")})'>상세</button>
                                ${hasPdf ? `<button class="btn-small btn-pdf" onclick="downloadPdf('${record.pdf_path}')">PDF</button>` : ''}
                                <button class="btn-small btn-delete" onclick="deleteRecord('${record.timestamp}')">삭제</button>
                            </div>
                        </td>
                    </tr>
                `;
            });

            html += '</tbody></table></div>';
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

        window.onclick = function(event) {
            const modal = document.getElementById('detail-modal');
            if (event.target === modal) {
                closeModal();
            }
        }

        loadStats();
        loadRecords();

        setInterval(() => {
            loadStats();
            loadRecords();
        }, 30000);

        // 챗봇 관련 스크립트 (WebSocket 적용)
        let ws = null;
        let currentAiMessageId = null;
        let isProcessing = false;

        function toggleChat() {
            const chatWindow = document.getElementById('chat-window');
            if (chatWindow.style.display === 'none' || chatWindow.style.display === '') {
                chatWindow.style.display = 'flex';
                connectWebSocket();
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
                setTimeout(connectWebSocket, 3000);
            };
        }

        function setInputEnabled(enabled) {
            const input = document.getElementById('chat-input');
            const button = document.querySelector('.chat-input-area button');

            if (enabled) {
                input.disabled = false;
                button.disabled = false;
                isProcessing = false;
            } else {
                input.disabled = true;
                button.disabled = true;
                isProcessing = true;
            }
        }

        function handleWsMessage(data) {
            const container = document.getElementById('chat-messages');

            if (data.type === 'start') {
                currentAiMessageId = addTypingIndicator();
                setInputEnabled(false);
            } else if (data.type === 'answer') {
                removeTypingIndicator();
                addMessage(data.content, 'ai', false, true);
                currentAiMessageId = null;
            } else if (data.type === 'tool_start') {
                const div = document.createElement('div');
                div.className = 'tool-status';
                div.id = `tool-status-${Date.now()}`;
                div.innerHTML = `🛠️ <strong>${data.tool}</strong> 실행 중...<span class="processing-badge">처리중</span><br><small>${truncateText(data.args, 100)}</small>`;
                container.appendChild(div);
                container.scrollTop = container.scrollHeight;
            } else if (data.type === 'tool_end') {
                const div = document.createElement('div');
                div.className = 'tool-status';
                div.style.borderLeftColor = '#28a745';
                div.innerHTML = `✅ <strong>${data.tool}</strong> 완료<br><small>${truncateText(data.result, 100)}</small>`;
                container.appendChild(div);
                container.scrollTop = container.scrollHeight;
            } else if (data.type === 'error') {
                removeTypingIndicator();
                addMessage(`❌ 오류: ${data.content}`, 'ai');
                setInputEnabled(true);
            } else if (data.type === 'done') {
                removeTypingIndicator();
                currentAiMessageId = null;
                setInputEnabled(true);
                setTimeout(() => {
                    console.log('[DEBUG] 데이터베이스 새로고침 시작');
                    loadRecords();
                    loadStats();
                }, 500);
            }
        }

        function truncateText(text, maxLength) {
            if (text.length > maxLength) {
                return text.substring(0, maxLength) + '...';
            }
            return text;
        }

        function handleKeyPress(e) {
            if (e.key === 'Enter') sendMessage();
        }

        function sendMessage() {
            const input = document.getElementById('chat-input');
            const message = input.value.trim();
            if (!message) return;

            if (isProcessing) {
                return;
            }

            if (!ws || ws.readyState !== WebSocket.OPEN) {
                alert('서버와 연결되지 않았습니다. 잠시 후 다시 시도해주세요.');
                connectWebSocket();
                return;
            }

            addMessage(message, 'user');
            input.value = '';

            ws.send(JSON.stringify({ message: message }));
        }

        function addMessage(text, type, isLoading = false, useMarkdown = false) {
            const container = document.getElementById('chat-messages');
            const div = document.createElement('div');
            div.className = `message ${type}`;

            if (isLoading) {
                div.id = 'ai-msg-' + Date.now();
                div.textContent = '분석 중...';
            } else {
                if (useMarkdown && type === 'ai' && typeof marked !== 'undefined') {
                    div.innerHTML = marked.parse(text);
                } else {
                    div.textContent = text;
                }
            }

            container.appendChild(div);
            container.scrollTop = container.scrollHeight;
            return div.id;
        }

        function addTypingIndicator() {
            const container = document.getElementById('chat-messages');
            const div = document.createElement('div');
            div.className = 'message ai';
            div.id = 'typing-indicator';
            div.innerHTML = '<div class="typing-indicator"><span></span><span></span><span></span></div>';
            container.appendChild(div);
            container.scrollTop = container.scrollHeight;
            return div.id;
        }

        function removeTypingIndicator() {
            const indicator = document.getElementById('typing-indicator');
            if (indicator) {
                indicator.remove();
            }
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

chat_sessions: Dict[int, List[Any]] = {}

@app.websocket("/ws/chat")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()

    session_id = id(websocket)
    chat_sessions[session_id] = []

    if not HAS_LLM:
        await websocket.send_json({"type": "error", "content": "서버에 LLM 라이브러리가 설치되어 있지 않습니다."})
        await websocket.close()
        return

    try:
        system_prompt = SystemMessage(content="""너는 고급 OSINT(공개출처정보) 분석 및 위협 탐지 전문가 AI Agent입니다.

# 핵심 임무
사용자가 간단한 명령("minseolee 사용자 조사해", "example.com 분석해")만 입력해도 자동으로 포괄적인 OSINT 조사를 수행하고 모든 발견 사항을 데이터베이스에 체계적으로 저장합니다.

# 작업 수행 지침

## 1. 일반 대화 vs 조사 요청 구분
- **일반 대화**: 인사('안녕', 'hi'), 단순 질문('OSINT가 뭐야?'), 감사 인사 등 → 도구 사용 없이 바로 답변
- **조사 요청**: 특정 타겟(사용자명, 도메인, IP, 이메일 등)에 대한 "조사", "분석", "찾아줘", "검색" 등의 키워드 포함 → 자동 조사 워크플로우 실행

## 2. 자동 OSINT 조사 워크플로우

사용자가 조사 요청을 하면 다음 단계를 **자동으로** 순차 실행:

### Step 1: 기존 데이터 확인
```
1. search_local_db(타겟명)로 과거 조사 기록 확인
2. 기존 기록이 있으면 사용자에게 요약 제시
```

### Step 2: 타겟 유형 식별 및 적절한 도구 선택
```
- 사용자명/계정 → search_username(username)
- 도메인 → check_domain_reputation(domain) + analyze_webpage(url)
- IP 주소 → check_ip_reputation(ip)
- URL → analyze_webpage(url)
```

### Step 3: 심화 분석 (자동)
```
- search_username 결과로 SNS 계정 발견 시:
  → 각 계정 URL에 대해 analyze_webpage 실행
  → 프로필 정보, 이메일, 전화번호, 링크 추출

- analyze_webpage로 웹사이트 분석 시:
  → 자동으로 PDF 스냅샷 생성
  → 이메일, 전화번호, 소셜 미디어 링크 추출
  → 메타데이터 수집

- 도메인 발견 시:
  → check_domain_reputation으로 위협 평가
```

### Step 4: 결과 저장 (필수)
```
모든 유의미한 발견 사항은 반드시 save_to_db로 저장:

save_to_db(
    target="조사 대상명",
    summary="상세한 분석 요약 (최소 3-5문장, 발견된 모든 중요 정보 포함)",
    method="사용한 도구명",
    url="관련 URL (있는 경우)",
    pdf_path="PDF 경로 (analyze_webpage에서 반환)",
    emails=[발견된 이메일들],
    phones=[발견된 전화번호들],
    social_media=[소셜 미디어 링크들],
    threat_level="safe/suspicious/malicious/unknown",
    additional_metadata={추가 정보}
)

⚠️ summary는 한 줄이 아니라 다음을 포함한 상세한 내용:
- 발견된 계정/사이트 목록
- 추출된 연락처 정보
- 위협 평가 결과
- 특이 사항 및 주의사항
```

### Step 5: 사용자에게 보고
```
마크다운 형식으로 구조화된 보고서 작성:

## 🔍 [타겟명] OSINT 조사 결과

### 📋 요약
- **조사 대상**: ...
- **발견 계정 수**: ...
- **위협 수준**: ...

### 🎯 발견된 계정
1. **GitHub**: https://github.com/...
2. **Twitter**: https://twitter.com/...

### 📧 수집된 정보
- **이메일**: ...
- **전화번호**: ...

### ⚠️ 위협 분석
...

### 💾 데이터베이스 저장 완료
모든 정보가 데이터베이스에 저장되었습니다.
```

## 3. 예시 시나리오

### 예시 1: "minseolee 조사해"
```
1. search_local_db("minseolee") → 기존 기록 확인
2. search_username("minseolee") → GitHub, Twitter, Instagram 발견
3. analyze_webpage("https://github.com/minseolee") → 프로필 분석, PDF 생성
4. analyze_webpage("https://twitter.com/minseolee") → 프로필 분석, PDF 생성
5. save_to_db(
     target="minseolee",
     summary="GitHub(팔로워 234, 프로젝트 15개), Twitter(팔로워 567), Instagram 계정 발견. GitHub에서 Python 전문가로 활동 중. 이메일 minseo@example.com 발견. 위협 요소 없음.",
     method="search_username",
     url="https://github.com/minseolee",
     pdf_path="./pdfs/20250123_abc123.pdf",
     emails=["minseo@example.com"],
     social_media=[...],
     threat_level="safe"
   )
6. 사용자에게 마크다운 보고서 제시
```

### 예시 2: "example.com 분석해"
```
1. search_local_db("example.com")
2. check_domain_reputation("example.com") → 위협 평가
3. analyze_webpage("https://example.com") → 상세 분석 + PDF
4. save_to_db(...)
5. 보고서 제시
```

## 4. 중요 원칙

✅ **DO (반드시 해야 할 것)**
- 조사 요청 시 자동으로 여러 도구를 연쇄 실행
- 발견된 모든 URL/계정에 대해 analyze_webpage 실행
- 모든 결과를 **상세한 summary**와 함께 save_to_db로 저장
- PDF 스냅샷 항상 생성
- 마크다운으로 구조화된 보고서 작성

❌ **DON'T (하지 말아야 할 것)**
- 도구 하나만 실행하고 끝내기
- summary를 한 줄로 간략하게 작성하기
- PDF 생성 생략하기
- 수집된 이메일/전화번호를 save_to_db에 전달하지 않기
- 일반 대화에 도구 사용하기

## 5. 답변 형식
항상 **친절하고 전문적인 한국어**로 답변하며, 마크다운을 적극 활용하여 가독성을 높입니다.
""")
        chat_sessions[session_id].append(system_prompt)

        while True:
            data = await websocket.receive_json()
            user_message = data.get("message", "")

            if not user_message:
                continue

            llm = ChatOllama(model="qwen3:14b", temperature=0)

            tool_map = {t.name: t for t in tools}
            llm_with_tools = llm.bind_tools(tools)

            chat_sessions[session_id].append(HumanMessage(content=user_message))

            if len(chat_sessions[session_id]) > 20:
                chat_sessions[session_id] = [chat_sessions[session_id][0]] + chat_sessions[session_id][-15:]

            await websocket.send_json({"type": "start", "content": "분석을 시작합니다..."})

            current_messages = chat_sessions[session_id].copy()

            final_response = ""
            for i in range(5):
                ai_msg = await llm_with_tools.ainvoke(current_messages)
                current_messages.append(ai_msg)

                if not ai_msg.tool_calls:
                    final_response = ai_msg.content
                    chat_sessions[session_id].append(ai_msg)
                    await websocket.send_json({"type": "answer", "content": final_response})
                    break

                for tool_call in ai_msg.tool_calls:
                    tool_name = tool_call["name"]
                    tool_args = tool_call["args"]

                    await websocket.send_json({
                        "type": "tool_start",
                        "tool": tool_name,
                        "args": str(tool_args)
                    })

                    if tool_name in tool_map:
                        tool_func = tool_map[tool_name]
                        try:
                            tool_result = await tool_func.ainvoke(tool_args)
                        except Exception as e:
                            tool_result = f"Error executing {tool_name}: {str(e)}"
                    else:
                        tool_result = f"Error: Tool {tool_name} not found"

                    tool_msg = ToolMessage(content=str(tool_result), tool_call_id=tool_call["id"])
                    current_messages.append(tool_msg)

                    preview = str(tool_result)[:200] + "..." if len(str(tool_result)) > 200 else str(tool_result)
                    await websocket.send_json({
                        "type": "tool_end",
                        "tool": tool_name,
                        "result": preview
                    })

            # 5번 반복 후에도 답변이 없으면 최종 답변 생성
            if not final_response:
                final_ai_msg = await llm_with_tools.ainvoke(current_messages)
                final_response = final_ai_msg.content
                current_messages.append(final_ai_msg)
                chat_sessions[session_id].append(final_ai_msg)
                await websocket.send_json({"type": "answer", "content": final_response})

            chat_sessions[session_id] = current_messages

            await websocket.send_json({"type": "done"})

    except WebSocketDisconnect:
        print("WebSocket disconnected")
        if session_id in chat_sessions:
            del chat_sessions[session_id]
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
        llm = ChatOllama(model="qwen3:14b", temperature=0)

        records = db.get_all_records()
        recent_records = records[-5:] if len(records) > 5 else records
        db_context = "최근 수집된 데이터:\n"
        for r in recent_records:
            db_context += f"- [{r['timestamp']}] {r['target']} ({r['collection_method']}): {r['threat_level']}\n"
        if not recent_records:
            db_context = "최근 수집된 데이터가 없습니다."

        tool_map = {t.name: t for t in tools}

        messages = [
            SystemMessage(content=f"""너는 고급 OSINT(공개출처정보) 분석 및 위협 탐지 전문가 AI Agent입니다.

# 핵심 임무
사용자가 간단한 명령만 입력해도 자동으로 포괄적인 OSINT 조사를 수행하고 모든 발견 사항을 데이터베이스에 체계적으로 저장합니다.

# 작업 수행 지침

## 1. 일반 대화 vs 조사 요청 구분
- **일반 대화**: 인사, 단순 질문 등 → 도구 사용 없이 바로 답변
- **조사 요청**: 특정 타겟에 대한 "조사", "분석" 등 → 자동 조사 워크플로우 실행

## 2. 자동 OSINT 조사 워크플로우
1. search_local_db로 과거 기록 확인
2. 타겟 유형에 맞는 도구 실행:
   - **사용자명**: search_username
   - **도메인/URL**: comprehensive_security_check (종합 보안 검사) 실행 후 세부 분석
   - **IP 주소**: check_ip_reputation
3. 의심스러운 사이트 발견 시 추가 분석:
   - comprehensive_security_check: VirusTotal + Google Safe Browsing + SSL + 도메인 분석
   - analyze_ssl_certificate: SSL 인증서 유효성 확인
   - analyze_domain_age: 도메인 등록 정보 분석
4. 발견된 URL들에 대해 analyze_webpage 실행 (PDF 자동 생성)
5. 모든 결과를 **상세한 summary**와 함께 save_to_db로 저장
   - summary는 최소 3-5문장으로 발견된 모든 중요 정보 포함
   - 이메일, 전화번호, 소셜미디어 링크 모두 전달
   - 보안 위협 수준 명확히 표시 (safe/suspicious/malicious)
6. 마크다운 형식으로 구조화된 보고서 제시

## 3. 중요 원칙
✅ DO: 자동으로 여러 도구 연쇄 실행, 상세한 summary 작성, PDF 생성, 마크다운 보고서
❌ DON'T: 도구 하나만 실행하고 끝, summary 한 줄로 작성, 일반 대화에 도구 사용

[수집된 데이터]
{db_context}

항상 **친절하고 전문적인 한국어**로 답변하며, 마크다운을 적극 활용하여 가독성을 높입니다.
"""),
            HumanMessage(content=request.message)
        ]

        llm_with_tools = llm.bind_tools(tools)

        final_response = ""
        for _ in range(5):
            ai_msg = await llm_with_tools.ainvoke(messages)
            messages.append(ai_msg)

            if not ai_msg.tool_calls:
                final_response = ai_msg.content
                break

            for tool_call in ai_msg.tool_calls:
                tool_name = tool_call["name"]
                tool_args = tool_call["args"]

                if tool_name in tool_map:
                    tool_func = tool_map[tool_name]
                    try:
                        tool_result = await tool_func.ainvoke(tool_args)
                    except Exception as e:
                        tool_result = f"Error executing {tool_name}: {str(e)}"
                else:
                    tool_result = f"Error: Tool {tool_name} not found"

                messages.append(ToolMessage(content=str(tool_result), tool_call_id=tool_call["id"]))

        return {"response": final_response}

    except Exception as e:
        print(f"Chat Error: {e}")
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
        port=8080,
        log_level="info"
    )
