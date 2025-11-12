#!/usr/bin/env python3
"""
OSINT Unified MCP Server - fastmcp Architecture
통합 OSINT MCP 서버 - fastmcp 기반

Phase 1 구현: 기존 server.py의 7개 tool을 fastmcp로 마이그레이션
목표: 단일 /mcp 엔드포인트에서 모든 OSINT 도구 제공
"""

import os
import json
import time
import logging
import asyncio
import subprocess
import base64
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone

from dotenv import load_dotenv

try:
    from intelxapi import intelx
except ImportError:
    # Fallback if intelxapi not available
    intelx = None
from playwright.async_api import async_playwright
from bs4 import BeautifulSoup
from fastapi import FastAPI, HTTPException, Request, Query
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

import requests

# ============================================================================
# Phase 0: 초기화 및 환경설정
# ============================================================================

# .env 파일 로드
load_dotenv()

# 로깅 설정
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# API 설정
INTELX_API_KEY = os.getenv("INTELX_API_KEY", "")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "")
HARVESTER_API_KEY = os.getenv("HARVESTER_API_KEY", "")
DEBUG_MODE = os.getenv("DEBUG_MODE", "false").lower() == "true"

# API 키 유효성 확인
if not INTELX_API_KEY and not DEBUG_MODE:
    logger.warning("Intelligence X API KEY가 설정되지 않았습니다")

if not VIRUSTOTAL_API_KEY and not DEBUG_MODE:
    logger.warning(
        "VirusTotal API KEY가 설정되지 않았습니다 (DEBUG_MODE=true인 경우 Mock 데이터 사용)"
    )

if DEBUG_MODE:
    logger.info("🔧 DEBUG_MODE 활성화 - Mock 데이터 사용")

# ============================================================================
# Phase 1: Pydantic 모델
# ============================================================================


class SearchRequest(BaseModel):
    term: str = Field(..., description="검색할 셀렉터 (이메일, 도메인, IP 등)")
    maxresults: int = Field(100, description="최대 결과 수")
    timeout: int = Field(5, description="타임아웃 (초)")
    buckets: Optional[List[str]] = Field(None, description="검색할 버킷 목록")
    datefrom: Optional[str] = Field(None, description="시작 날짜 (YYYY-MM-DD)")
    dateto: Optional[str] = Field(None, description="종료 날짜 (YYYY-MM-DD)")


class SherlockSearchRequest(BaseModel):
    username: str = Field(..., description="검색할 사용자명")
    sites: Optional[List[str]] = Field(
        None, description="검색할 사이트 목록 (예: ['github', 'twitter'])"
    )
    timeout: int = Field(120, description="타임아웃 (초, 기본값: 120초)")


class PlaywrightAnalyzeRequest(BaseModel):
    url: str = Field(..., description="분석할 URL")
    extract_metadata: bool = Field(
        True, description="메타데이터 추출 (제목, 설명, 이미지)"
    )
    extract_text: bool = Field(True, description="페이지 텍스트 추출")
    extract_links: bool = Field(True, description="링크 목록 추출")
    screenshot: bool = Field(False, description="스크린샷 캡처")
    wait_for_selector: Optional[str] = Field(
        None, description="특정 요소가 로드될 때까지 대기"
    )
    timeout: int = Field(30, description="타임아웃 (초)")


class ThreatIntelRequest(BaseModel):
    query: str = Field(..., description="조회할 대상 (도메인 또는 IP)")
    query_type: str = Field("domain", description="조회 타입: domain 또는 ip")
    timeout: int = Field(10, description="타임아웃 (초)")


# ============================================================================
# Phase 2: Client Classes (기존 구현 유지)
# ============================================================================


class IntelligenceXClient:
    """Intelligence X 검색 클라이언트"""

    def __init__(self, api_key: str):
        self.client = None
        self.debug_mode = DEBUG_MODE

        if api_key and intelx is not None:
            self.client = intelx(api_key)
            self.client.API_ROOT = "https://free.intelx.io"

    def search(self, search_request: SearchRequest) -> Dict[str, Any]:
        if self.debug_mode:
            logger.info(f"DEBUG MODE: Mock 데이터 반환 (검색어: {search_request.term})")
            return {
                "records": [
                    {
                        "name": f"Mock Result 1 for {search_request.term}",
                        "description": "This is a mock result for testing purposes",
                        "date": datetime.now().isoformat(),
                        "media": 1,
                        "type": 1,
                        "added": datetime.now().isoformat(),
                        "storageid": "mock-storage-id-1",
                        "bucket": "mock-bucket",
                    },
                    {
                        "name": f"Mock Result 2 for {search_request.term}",
                        "description": "Second mock result for testing",
                        "date": "2025-10-25T12:00:00",
                        "media": 1,
                        "type": 1,
                        "added": "2025-10-25T14:30:00",
                        "storageid": "mock-storage-id-2",
                        "bucket": "mock-bucket",
                    },
                ]
            }

        try:
            if not self.client:
                raise HTTPException(
                    status_code=500, detail="API 키가 설정되지 않았습니다."
                )

            results = self.client.search(
                search_request.term,
                maxresults=search_request.maxresults,
                timeout=search_request.timeout,
            )
            return results
        except Exception as e:
            logger.error(f"검색 요청 실패: {e}")
            raise HTTPException(
                status_code=500, detail=f"Intelligence X API 오류: {str(e)}"
            )


class SherlockClient:
    """Sherlock 사용자명 검색 클라이언트"""

    def __init__(self):
        self.debug_mode = DEBUG_MODE

    def search(self, search_request: SherlockSearchRequest) -> Dict[str, Any]:
        """Sherlock으로 사용자명 검색"""
        if self.debug_mode:
            logger.info(
                f"DEBUG MODE: Sherlock Mock 데이터 반환 (사용자명: {search_request.username})"
            )
            return {
                "found": {
                    "github": {
                        "url": f"https://github.com/{search_request.username}",
                        "status": "found",
                    },
                    "twitter": {
                        "url": f"https://twitter.com/{search_request.username}",
                        "status": "found",
                    },
                },
                "not_found": ["instagram", "reddit"],
                "total_found": 2,
                "total_checked": 4,
            }

        try:
            cmd = ["sherlock", search_request.username, "--no-color", "--no-txt"]

            if search_request.sites:
                for site in search_request.sites:
                    cmd.extend(["--site", site])

            logger.info(f"Sherlock 검색 실행: {' '.join(cmd)}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=search_request.timeout * len(search_request.sites or [100]),
            )

            found_accounts = {}
            lines = result.stdout.split("\n")

            for line in lines:
                if line.strip().startswith("[+]"):
                    parts = line.strip()[4:].split(": ", 1)
                    if len(parts) == 2:
                        site_name = parts[0].strip()
                        url = parts[1].strip()
                        found_accounts[site_name] = {"url": url, "status": "found"}

            total_found = len(found_accounts)

            return {
                "found": found_accounts,
                "total_found": total_found,
                "username": search_request.username,
                "timestamp": datetime.now().isoformat(),
                "status": "completed",
            }
        except subprocess.TimeoutExpired:
            logger.error(f"Sherlock 타임아웃: {search_request.username}")
            raise HTTPException(status_code=408, detail="Sherlock 검색 타임아웃")
        except Exception as e:
            logger.error(f"Sherlock 검색 실패: {e}")
            raise HTTPException(status_code=500, detail=f"Sherlock 검색 오류: {str(e)}")


class PlaywrightClient:
    """Playwright URL 분석 클라이언트"""

    def __init__(self):
        self.debug_mode = DEBUG_MODE

    async def analyze(
        self, analyze_request: PlaywrightAnalyzeRequest
    ) -> Dict[str, Any]:
        """Playwright로 URL 분석"""
        if self.debug_mode:
            logger.info(
                f"DEBUG MODE: Playwright Mock 데이터 반환 (URL: {analyze_request.url})"
            )
            return {
                "url": analyze_request.url,
                "metadata": {
                    "title": "Mock Page Title",
                    "description": "This is a mock page description",
                    "image": "https://example.com/image.jpg",
                },
                "text": "Mock page content...",
                "links": [
                    {"text": "Link 1", "href": "https://example.com/link1"},
                    {"text": "Link 2", "href": "https://example.com/link2"},
                ],
                "screenshot": None,
                "status": "completed",
            }

        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch()
                page = await browser.new_page()

                logger.info(f"Playwright 페이지 로드: {analyze_request.url}")
                await page.goto(
                    analyze_request.url,
                    timeout=analyze_request.timeout * 1000,
                    wait_until="load",
                )

                if analyze_request.wait_for_selector:
                    await page.wait_for_selector(
                        analyze_request.wait_for_selector, timeout=5000
                    )

                result = {"url": analyze_request.url, "status": "completed"}

                if analyze_request.extract_metadata:
                    title = await page.title()

                    try:
                        meta_description = await page.locator(
                            'meta[name="description"]'
                        ).get_attribute("content", timeout=1000)
                    except:
                        meta_description = None

                    try:
                        meta_image = await page.locator(
                            'meta[property="og:image"]'
                        ).get_attribute("content", timeout=1000)
                    except:
                        meta_image = None

                    result["metadata"] = {
                        "title": title,
                        "description": meta_description or "",
                        "image": meta_image or "",
                    }

                if analyze_request.extract_text:
                    html = await page.content()
                    soup = BeautifulSoup(html, "html.parser")
                    for script in soup(["script", "style"]):
                        script.decompose()
                    text = soup.get_text(separator="\n", strip=True)
                    result["text"] = text[:2000] if text else ""

                if analyze_request.extract_links:
                    html = await page.content()
                    soup = BeautifulSoup(html, "html.parser")
                    links = []
                    for link in soup.find_all("a", href=True):
                        links.append(
                            {"text": link.get_text(strip=True), "href": link["href"]}
                        )
                    result["links"] = links[:50]

                if analyze_request.screenshot:
                    screenshot_bytes = await page.screenshot()
                    result["screenshot"] = base64.b64encode(screenshot_bytes).decode(
                        "utf-8"
                    )

                await browser.close()
                return result

        except Exception as e:
            logger.error(f"Playwright 분석 실패: {e}")
            raise HTTPException(status_code=500, detail=f"URL 분석 오류: {str(e)}")


class VTClient:
    """VirusTotal 위협 정보 조회 클래스"""

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.debug_mode = DEBUG_MODE

    def query_domain(self, domain: str) -> Dict[str, Any]:
        """도메인 평판 조회"""
        if self.debug_mode:
            return self._mock_domain_response(domain)

        if not self.api_key:
            return {
                "status": "error",
                "error": {"code": -32001, "message": "VirusTotal API KEY 없음"},
            }

        try:
            headers = {"x-apikey": self.api_key}
            url = f"https://www.virustotal.com/api/v3/domains/{domain}"

            response = requests.get(url, headers=headers, timeout=10)

            if response.status_code == 404:
                return {
                    "status": "error",
                    "error": {
                        "code": -32003,
                        "message": f"도메인 '{domain}'을(를) VirusTotal 데이터베이스에서 찾을 수 없습니다",
                    },
                }
            elif response.status_code == 429:
                return {
                    "status": "error",
                    "error": {
                        "code": -32002,
                        "message": "VirusTotal 요청 제한 초과 - 잠시 후 다시 시도하세요",
                        "data": {"retry_after": 45},
                    },
                }
            elif response.status_code != 200:
                return {
                    "status": "error",
                    "error": {
                        "code": -32000,
                        "message": f"VirusTotal 오류: {response.status_code}",
                    },
                }

            data = response.json()
            attributes = data.get("data", {}).get("attributes", {})

            last_analysis_stats = attributes.get(
                "last_analysis_stats",
                {"malicious": 0, "suspicious": 0, "undetected": 0},
            )

            threat_level = self._calculate_threat_level(last_analysis_stats)

            return {
                "status": "success",
                "data": {
                    "domain": domain,
                    "threat_level": threat_level,
                    "detected_by": last_analysis_stats.get("malicious", 0),
                    "analysis_stats": last_analysis_stats,
                    "last_analysis_date": attributes.get("last_analysis_date"),
                    "categories": attributes.get("categories", {}),
                },
                "metadata": {
                    "source": "virustotal",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "query_time_ms": 0,
                },
            }
        except requests.exceptions.Timeout:
            return {
                "status": "error",
                "error": {"code": -32005, "message": "VirusTotal 요청 타임아웃"},
            }
        except Exception as e:
            return {
                "status": "error",
                "error": {"code": -32000, "message": f"VirusTotal 오류: {str(e)}"},
            }

    def query_ip(self, ip_address: str) -> Dict[str, Any]:
        """IP 주소 평판 조회"""
        if self.debug_mode:
            return self._mock_ip_response(ip_address)

        if not self.api_key:
            return {
                "status": "error",
                "error": {"code": -32001, "message": "VirusTotal API KEY 없음"},
            }

        try:
            headers = {"x-apikey": self.api_key}
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"

            response = requests.get(url, headers=headers, timeout=10)

            if response.status_code == 404:
                return {
                    "status": "error",
                    "error": {
                        "code": -32003,
                        "message": f"IP '{ip_address}'을(를) VirusTotal 데이터베이스에서 찾을 수 없습니다",
                    },
                }
            elif response.status_code == 429:
                return {
                    "status": "error",
                    "error": {
                        "code": -32002,
                        "message": "VirusTotal 요청 제한 초과 - 잠시 후 다시 시도하세요",
                        "data": {"retry_after": 45},
                    },
                }
            elif response.status_code != 200:
                return {
                    "status": "error",
                    "error": {
                        "code": -32000,
                        "message": f"VirusTotal 오류: {response.status_code}",
                    },
                }

            data = response.json()
            attributes = data.get("data", {}).get("attributes", {})

            last_analysis_stats = attributes.get(
                "last_analysis_stats",
                {"malicious": 0, "suspicious": 0, "undetected": 0},
            )

            threat_level = self._calculate_threat_level(last_analysis_stats)

            return {
                "status": "success",
                "data": {
                    "ip_address": ip_address,
                    "country": attributes.get("country", "Unknown"),
                    "asn": attributes.get("asn"),
                    "organization": attributes.get("as_owner", "Unknown"),
                    "threat_level": threat_level,
                    "detected_by": last_analysis_stats.get("malicious", 0),
                    "analysis_stats": last_analysis_stats,
                },
                "metadata": {
                    "source": "virustotal",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "query_time_ms": 0,
                },
            }
        except requests.exceptions.Timeout:
            return {
                "status": "error",
                "error": {"code": -32005, "message": "VirusTotal 요청 타임아웃"},
            }
        except Exception as e:
            logger.error(f"VirusTotal IP 조회 오류: {str(e)}")
            return {
                "status": "error",
                "error": {"code": -32000, "message": f"VirusTotal 오류: {str(e)}"},
            }

    def _calculate_threat_level(self, stats: Dict[str, int]) -> str:
        """위협 수준 계산"""
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)

        if malicious >= 5:
            return "Critical"
        elif malicious >= 2:
            return "High"
        elif malicious + suspicious >= 5:
            return "Medium"
        elif malicious + suspicious > 0:
            return "Low"
        else:
            return "None"

    def _mock_domain_response(self, domain: str) -> Dict[str, Any]:
        """Mock 도메인 응답"""
        return {
            "status": "success",
            "data": {
                "domain": domain,
                "threat_level": "Low",
                "detected_by": 0,
                "analysis_stats": {"malicious": 0, "suspicious": 0, "undetected": 89},
                "last_analysis_date": datetime.now(timezone.utc).isoformat(),
                "categories": {"Sophos": "legitimate", "Kaspersky": "legitimate"},
            },
            "metadata": {
                "source": "virustotal",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "query_time_ms": 245,
                "note": "Mock data in DEBUG_MODE",
            },
        }

    def _mock_ip_response(self, ip: str) -> Dict[str, Any]:
        """Mock IP 응답"""
        return {
            "status": "success",
            "data": {
                "ip_address": ip,
                "country": "US",
                "asn": 15169,
                "organization": "Google LLC",
                "threat_level": "None",
                "detected_by": 0,
                "analysis_stats": {"malicious": 0, "suspicious": 0, "undetected": 89},
            },
            "metadata": {
                "source": "virustotal",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "query_time_ms": 198,
                "note": "Mock data in DEBUG_MODE",
            },
        }


# ============================================================================
# Phase 3: Client 인스턴스 생성
# ============================================================================

intelx_client = IntelligenceXClient(INTELX_API_KEY)
sherlock_client = SherlockClient()
playwright_client = PlaywrightClient()
vt_client = VTClient(VIRUSTOTAL_API_KEY)

# ============================================================================
# Phase 4: FastAPI 앱 초기화
# ============================================================================

app = FastAPI(
    title="OSINT Unified MCP Server",
    description="fastmcp 기반 통합 OSINT 서버 (단일 엔드포인트)",
    version="2.0.0",
)

# CORS 설정
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================================================
# Phase 5: Root & Health Endpoints
# ============================================================================


@app.get("/")
async def root():
    """서버 정보"""
    return {
        "name": "OSINT Unified MCP Server (fastmcp v2.0)",
        "version": "2.0.0",
        "description": "단일 /mcp 엔드포인트를 통한 통합 OSINT 서버",
        "tools_count": 7,
        "debug_mode": DEBUG_MODE,
        "status": "running",
        "api_configured": {
            "intelx": bool(INTELX_API_KEY),
            "virustotal": bool(VIRUSTOTAL_API_KEY),
            "shodan": bool(SHODAN_API_KEY),
        },
    }


@app.get("/health")
async def health():
    """헬스 체크"""
    return {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "debug_mode": DEBUG_MODE,
        "tools_available": 7,
    }


# ============================================================================
# Phase 6: 기존 MCP 엔드포인트 (호환성 유지)
# ============================================================================

# MCP Tool 정의 (기존 구조 유지)
MCP_TOOLS = [
    {
        "name": "search_intelligence_x",
        "description": "Intelligence X에서 다크웹 및 유출 데이터를 검색합니다.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "term": {
                    "type": "string",
                    "description": "검색할 셀렉터 (예: email@example.com)",
                },
                "maxresults": {
                    "type": "integer",
                    "description": "최대 결과 수",
                    "default": 300,
                },
            },
            "required": ["term"],
        },
    },
    {
        "name": "search_username_sherlock",
        "description": "Sherlock을 사용하여 사용자명을 여러 웹사이트에서 검색합니다. 특정 사이트만 검색 가능합니다.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "username": {
                    "type": "string",
                    "description": "검색할 사용자명 (예: john_doe)",
                },
                "sites": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "검색할 사이트 목록 (예: ['github', 'twitter', 'reddit']. 생략하면 모든 사이트 검색)",
                },
                "timeout": {
                    "type": "integer",
                    "description": "검색 타임아웃",
                    "default": 300,
                },
            },
            "required": ["username"],
        },
    },
    {
        "name": "analyze_url_playwright",
        "description": "Playwright를 사용하여 URL을 분석합니다.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "분석할 URL",
                },
            },
            "required": ["url"],
        },
    },
    {
        "name": "check_virustotal_domain",
        "description": "VirusTotal에서 도메인의 위협 정보를 확인합니다. (악성도 점수, 탐지 벤더 등)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {
                    "type": "string",
                    "description": "조회할 도메인",
                },
            },
            "required": ["domain"],
        },
    },
    {
        "name": "check_virustotal_ip",
        "description": "VirusTotal에서 IP 주소의 위협 정보를 확인합니다. (국가, ASN, 악성도 등)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "ip_address": {
                    "type": "string",
                    "description": "조회할 IP 주소",
                },
            },
            "required": ["ip_address"],
        },
    },
]


@app.post("/mcp")
async def mcp_unified_endpoint(request: Request):
    """
    통합 MCP 엔드포인트 (모든 OSINT 도구)
    JSON-RPC 2.0 프로토콜 지원
    """
    try:
        body = await request.json()
        method = body.get("method")
        params = body.get("params", {})
        request_id = body.get("id", 1)

        logger.info(f"MCP 요청: method={method}, id={request_id}")

        # 초기화 메서드
        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {}},
                    "serverInfo": {
                        "name": "OSINT Unified MCP Server (fastmcp v2.0)",
                        "version": "2.0.0",
                    },
                },
            }

        # 알림 메서드
        elif method == "notifications/initialized":
            logger.info("클라이언트 초기화 완료")
            return {"jsonrpc": "2.0", "id": request_id}

        # 도구 목록 반환
        elif method == "tools/list":
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {"tools": MCP_TOOLS},
            }

        # 도구 호출
        elif method == "tools/call":
            tool_name = params.get("name")
            arguments = params.get("arguments", {})

            # Tool 1: search_intelligence_x
            if tool_name == "search_intelligence_x":
                start_time = time.time()
                search_req = SearchRequest(
                    term=arguments.get("term"),
                    maxresults=arguments.get("maxresults", 100),
                    buckets=arguments.get("buckets"),
                    datefrom=arguments.get("datefrom"),
                    dateto=arguments.get("dateto"),
                )

                result = intelx_client.search(search_req)
                execution_time = (time.time() - start_time) * 1000

                return {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": json.dumps(
                                    {
                                        **result,
                                        "execution_time_ms": int(execution_time),
                                    },
                                    indent=2,
                                    ensure_ascii=False,
                                ),
                            }
                        ]
                    },
                }

            # Tool 2: search_username_sherlock
            elif tool_name == "search_username_sherlock":
                start_time = time.time()
                sherlock_req = SherlockSearchRequest(
                    username=arguments.get("username"),
                    sites=arguments.get("sites"),
                    timeout=arguments.get("timeout", 120),
                )

                result = sherlock_client.search(sherlock_req)
                execution_time = (time.time() - start_time) * 1000

                return {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": json.dumps(
                                    {
                                        **result,
                                        "execution_time_ms": int(execution_time),
                                    },
                                    indent=2,
                                    ensure_ascii=False,
                                ),
                            }
                        ]
                    },
                }

            # Tool 3: analyze_url_playwright
            elif tool_name == "analyze_url_playwright":
                start_time = time.time()
                playwright_req = PlaywrightAnalyzeRequest(
                    url=arguments.get("url"),
                    extract_metadata=arguments.get("extract_metadata", True),
                    extract_text=arguments.get("extract_text", True),
                    extract_links=arguments.get("extract_links", True),
                    screenshot=arguments.get("screenshot", False),
                    wait_for_selector=arguments.get("wait_for_selector"),
                    timeout=arguments.get("timeout", 30),
                )

                result = await playwright_client.analyze(playwright_req)
                execution_time = (time.time() - start_time) * 1000

                return {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": json.dumps(
                                    {
                                        **result,
                                        "execution_time_ms": int(execution_time),
                                    },
                                    indent=2,
                                    ensure_ascii=False,
                                ),
                            }
                        ]
                    },
                }

            # Tool 4: check_virustotal_domain
            elif tool_name == "check_virustotal_domain":
                start_time = time.time()
                result = vt_client.query_domain(arguments.get("domain"))
                execution_time = (time.time() - start_time) * 1000

                if result.get("status") == "error":
                    return {
                        "jsonrpc": "2.0",
                        "id": request_id,
                        "error": {
                            "code": result.get("error", {}).get("code", -32000),
                            "message": result.get("error", {}).get(
                                "message", "Unknown error"
                            ),
                        },
                    }

                return {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": json.dumps(
                                    {
                                        **result,
                                        "execution_time_ms": int(execution_time),
                                    },
                                    indent=2,
                                    ensure_ascii=False,
                                ),
                            }
                        ]
                    },
                }

            # Tool 5: check_virustotal_ip
            elif tool_name == "check_virustotal_ip":
                start_time = time.time()
                result = vt_client.query_ip(arguments.get("ip_address"))
                execution_time = (time.time() - start_time) * 1000

                if result.get("status") == "error":
                    return {
                        "jsonrpc": "2.0",
                        "id": request_id,
                        "error": {
                            "code": result.get("error", {}).get("code", -32000),
                            "message": result.get("error", {}).get(
                                "message", "Unknown error"
                            ),
                        },
                    }

                return {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": json.dumps(
                                    {
                                        **result,
                                        "execution_time_ms": int(execution_time),
                                    },
                                    indent=2,
                                    ensure_ascii=False,
                                ),
                            }
                        ]
                    },
                }

            else:
                return {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {
                        "code": -32601,
                        "message": f"알 수 없는 도구: {tool_name}",
                    },
                }

        else:
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32601, "message": f"지원하지 않는 메소드: {method}"},
            }

    except Exception as e:
        logger.error(f"MCP 요청 처리 오류: {e}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={
                "jsonrpc": "2.0",
                "id": body.get("id", 1) if "body" in locals() else 1,
                "error": {"code": -32603, "message": str(e)},
            },
        )


if __name__ == "__main__":
    import uvicorn

    port = int(os.getenv("PORT", "8000"))

    logger.info("=" * 70)
    logger.info("🚀 OSINT Unified MCP Server (fastmcp v2.0)")
    logger.info("=" * 70)
    logger.info(f"포트: {port}")
    logger.info(f"DEBUG 모드: {DEBUG_MODE}")
    logger.info("")
    logger.info("✅ 활성화된 OSINT 도구:")
    logger.info("   1️⃣  search_intelligence_x - 다크웹/유출 데이터 검색")
    logger.info("   2️⃣  search_username_sherlock - 사용자명 검색")
    logger.info("   3️⃣  analyze_url_playwright - URL 분석")
    logger.info("   4️⃣  check_virustotal_domain - VirusTotal 도메인 확인")
    logger.info("   5️⃣  check_virustotal_ip - VirusTotal IP 확인")
    logger.info("")
    logger.info("📍 엔드포인트:")
    logger.info(f"   http://localhost:{port}/ (서버 정보)")
    logger.info(f"   http://localhost:{port}/health (헬스 체크)")
    logger.info(f"   http://localhost:{port}/mcp (MCP JSON-RPC 2.0)")
    logger.info("=" * 70)

    uvicorn.run(app, host="0.0.0.0", port=port)
