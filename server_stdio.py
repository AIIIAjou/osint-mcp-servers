import os
import json
import time
import logging
import asyncio
import subprocess
import shutil
import base64
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone

from dotenv import load_dotenv

try:
    from intelxapi import intelx
except ImportError:
    intelx = None
from playwright.async_api import async_playwright
from bs4 import BeautifulSoup
import requests
from pydantic import BaseModel, Field

from fastmcp import FastMCP

# OSINT 데이터베이스 및 PDF 생성 모듈
from db_manager import OSINTDatabase
from pdf_generator import PDFGenerator

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

# 데이터베이스 및 PDF 생성기 초기화
osint_db = OSINTDatabase("db.csv")
pdf_generator = PDFGenerator("./pdfs")
logger.info("✅ OSINT 데이터베이스 초기화 완료")
logger.info("✅ PDF 생성기 초기화 완료")

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


class PlaywrightCrawlRequest(BaseModel):
    url: str = Field(..., description="시작할 URL")
    max_depth: int = Field(2, description="크롤링 깊이 (기본값: 2)")
    max_pages: int = Field(10, description="최대 방문 페이지 수 (기본값: 10)")
    url_pattern: Optional[str] = Field(
        None, description="크롤링할 URL 패턴 (정규표현식, 예: .*github.com.*)"
    )
    extract_text: bool = Field(True, description="페이지 텍스트 추출")
    extract_links: bool = Field(True, description="링크 추출")
    analyze_content: bool = Field(True, description="지능형 콘텐츠 분석")
    timeout: int = Field(60, description="전체 크롤링 타임아웃 (초)")


class ActionStep(BaseModel):
    """개별 상호작용 액션"""

    action: str = Field(
        ...,
        description="액션 타입: click, type, fill, press, select, scroll, wait, screenshot, navigate",
    )
    selector: Optional[str] = Field(None, description="CSS 셀렉터 (필요한 경우)")
    value: Optional[str] = Field(None, description="입력값 (type, fill, select에 사용)")
    delay: Optional[int] = Field(
        0, description="액션 실행 후 대기 시간 (밀리초)"
    )
    timeout: Optional[int] = Field(5000, description="액션 타임아웃 (밀리초)")
    description: Optional[str] = Field(None, description="액션 설명")


class PlaywrightInteractionRequest(BaseModel):
    """Playwright 동적 상호작용 요청"""

    url: str = Field(..., description="시작 URL")
    actions: List[ActionStep] = Field(..., description="실행할 액션 시퀀스")
    save_session: bool = Field(False, description="세션 저장 (쿠키/스토리지)")
    session_name: Optional[str] = Field(None, description="세션 이름")
    load_session: Optional[str] = Field(None, description="로드할 세션 이름")
    screenshot_final: bool = Field(True, description="최종 스크린샷 캡처")
    extract_data: bool = Field(
        True, description="최종 페이지에서 데이터 추출 (텍스트, 링크 등)"
    )
    headless: bool = Field(True, description="헤드리스 모드 (기본값: True)")
    timeout: int = Field(60, description="전체 작업 타임아웃 (초)")


class PlaywrightAutoExploreRequest(BaseModel):
    """자동 탐색 요청"""

    url: str = Field(..., description="시작 URL")
    goal: str = Field(
        ...,
        description="탐색 목표 (예: '연락처 찾기', 'SNS 링크 찾기', '특정 키워드가 포함된 페이지 찾기')",
    )
    max_interactions: int = Field(
        10, description="최대 상호작용 횟수 (클릭, 폼 제출 등)"
    )
    max_pages: int = Field(5, description="최대 방문 페이지 수")
    timeout: int = Field(120, description="전체 탐색 타임아웃 (초)")


class PlaywrightDeepAnalyzeRequest(BaseModel):
    """재귀적 URL 분석 요청"""

    url: str = Field(..., description="시작 URL")
    max_depth: int = Field(2, description="재귀 깊이 (기본값: 2)")
    max_urls: int = Field(20, description="최대 분석 URL 수 (기본값: 20)")
    include_external: bool = Field(
        True, description="외부 도메인 포함 여부 (기본값: True)"
    )
    check_threats: bool = Field(
        False, description="VirusTotal로 위협 정보 확인 (기본값: False, 시간 소요)"
    )
    extract_emails: bool = Field(True, description="이메일 주소 추출")
    extract_phones: bool = Field(True, description="전화번호 추출")
    extract_social: bool = Field(True, description="소셜 미디어 링크 추출")
    timeout_per_url: int = Field(30, description="URL당 타임아웃 (초)")


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
                raise ValueError("API 키가 설정되지 않았습니다.")

            results = self.client.search(
                search_request.term,
                maxresults=search_request.maxresults,
                timeout=search_request.timeout,
            )
            return results
        except Exception as e:
            logger.error(f"검색 요청 실패: {e}")
            raise ValueError(f"Intelligence X API 오류: {str(e)}")


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
            # Sherlock 절대 경로 찾기
            sherlock_path = shutil.which("sherlock")
            if not sherlock_path:
                raise FileNotFoundError(
                    "Sherlock이 설치되지 않았습니다. 'pip install sherlock-project' 실행하세요."
                )

            cmd = [sherlock_path, search_request.username, "--no-color", "--no-txt"]

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
            raise TimeoutError("Sherlock 검색 타임아웃")
        except Exception as e:
            logger.error(f"Sherlock 검색 실패: {e}")
            raise ValueError(f"Sherlock 검색 오류: {str(e)}")


class PlaywrightClient:
    """Playwright URL 분석 및 자동 크롤링 클라이언트"""

    def __init__(self):
        self.debug_mode = DEBUG_MODE
        self.visited_urls = set()
        self.crawl_results = []
        self.session_storage_dir = "./sessions"
        os.makedirs(self.session_storage_dir, exist_ok=True)

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
            raise ValueError(f"URL 분석 오류: {str(e)}")

    def _analyze_content(self, html: str, text: str, url: str) -> Dict[str, Any]:
        """페이지 콘텐츠의 지능형 분석"""
        import re

        analysis = {
            "page_purpose": self._detect_page_purpose(text, html, url),
            "key_information": self._extract_key_info(text, html),
            "potential_risks": self._detect_risks(text, html, url),
            "entities": self._extract_entities(text),
            "keywords": self._extract_keywords(text),
        }
        return analysis

    def _detect_page_purpose(self, text: str, html: str, url: str) -> str:
        """페이지의 목적 파악"""
        text_lower = text.lower()
        url_lower = url.lower()

        # 프로필 페이지 감지
        if any(
            keyword in text_lower for keyword in ["profile", "about", "bio", "user"]
        ) or any(keyword in url_lower for keyword in ["profile", "user", "about"]):
            return "User/Profile Page"

        # 로그인 페이지
        if any(
            keyword in text_lower
            for keyword in ["login", "password", "username", "sign in"]
        ):
            return "Authentication/Login Page"

        # 상거래 사이트
        if any(
            keyword in text_lower
            for keyword in ["price", "buy", "purchase", "cart", "checkout", "product"]
        ):
            return "E-commerce/Shopping Page"

        # 문서/블로그
        if any(
            keyword in text_lower
            for keyword in ["article", "blog", "post", "author", "published"]
        ):
            return "Blog/Article Page"

        # 검색 결과
        if any(
            keyword in text_lower for keyword in ["search result", "found", "matches"]
        ):
            return "Search Results Page"

        # API 페이지
        if "api" in url_lower or any(
            keyword in text_lower
            for keyword in ["endpoint", "request", "response", "json"]
        ):
            return "API/Technical Documentation"

        return "General Content Page"

    def _extract_key_info(self, text: str, html: str) -> Dict[str, Any]:
        """주요 정보 추출"""
        import re

        info = {}

        # 이메일 추출
        emails = set(
            re.findall(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", text)
        )
        if emails:
            info["emails"] = list(emails)[:5]  # 최대 5개

        # 전화번호 추출 (간단한 패턴)
        phones = set(re.findall(r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b", text))
        if phones:
            info["phone_numbers"] = list(phones)[:5]

        # 소셜 미디어 링크 추출
        social_patterns = {
            "twitter": r"twitter\.com/[\w]+",
            "github": r"github\.com/[\w-]+",
            "linkedin": r"linkedin\.com/in/[\w-]+",
            "instagram": r"instagram\.com/[\w.]+",
            "facebook": r"facebook\.com/[\w.]+",
        }

        social_links = {}
        for platform, pattern in social_patterns.items():
            matches = re.findall(pattern, text)
            if matches:
                social_links[platform] = list(set(matches))[:3]

        if social_links:
            info["social_media"] = social_links

        # HTML 메타데이터에서 추가 정보
        soup = BeautifulSoup(html, "html.parser")

        # Open Graph 정보
        og_title = soup.find("meta", property="og:title")
        og_description = soup.find("meta", property="og:description")

        if og_title:
            info["og_title"] = og_title.get("content")
        if og_description:
            info["og_description"] = og_description.get("content")

        # 조직명 추출 시도
        author = soup.find("meta", {"name": "author"})
        if author:
            info["author"] = author.get("content")

        return info

    def _detect_risks(self, text: str, html: str, url: str) -> List[str]:
        """잠재적 보안 위험 감지"""
        risks = []
        text_lower = text.lower()
        url_lower = url.lower()

        # 피싱 징후
        if any(
            keyword in text_lower
            for keyword in [
                "verify account",
                "confirm identity",
                "update payment",
                "urgent action required",
            ]
        ):
            risks.append("Potential phishing indicators")

        # 인증 요구
        if "password" in text_lower or "login" in text_lower:
            risks.append("Authentication required - verify legitimacy")

        # 의심 활동
        if any(
            keyword in text_lower
            for keyword in [
                "limited time",
                "act now",
                "verify immediately",
                "confirm now",
            ]
        ):
            risks.append("High-pressure/urgency language detected")

        # 외부 스크립트 (XSS 가능성)
        if "<script" in html and "src=" in html:
            script_count = html.count("<script")
            if script_count > 5:
                risks.append(f"Multiple external scripts detected ({script_count})")

        # HTTP vs HTTPS
        if url_lower.startswith("http://") and any(
            keyword in text_lower for keyword in ["password", "payment", "card"]
        ):
            risks.append("Sensitive data handling over insecure HTTP")

        # 숨겨진 폼
        if "<form" in html and "style" in html.lower():
            if "display:none" in html.lower() or "visibility:hidden" in html.lower():
                risks.append("Hidden form elements detected")

        return risks if risks else ["No obvious security risks detected"]

    def _extract_entities(self, text: str) -> Dict[str, List[str]]:
        """텍스트에서 엔티티 추출 (간단한 패턴 기반)"""
        import re

        entities = {}

        # URL 추출
        urls = re.findall(r'https?://[^\s<>"{}|\\^`\[\]]*', text)
        if urls:
            entities["urls"] = list(set(urls))[:10]

        # IP 주소 추출
        ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)
        if ips:
            entities["ip_addresses"] = list(set(ips))[:10]

        # 도메인 추출
        domains = re.findall(
            r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", text.lower()
        )
        if domains:
            entities["domains"] = list(set(domains))[:10]

        return entities

    def _extract_keywords(self, text: str) -> List[str]:
        """중요 키워드 추출 (단순 빈도 기반)"""
        # 불용어 제외
        stopwords = {
            "the",
            "a",
            "an",
            "and",
            "or",
            "but",
            "in",
            "on",
            "at",
            "to",
            "for",
            "of",
            "is",
            "was",
            "are",
            "be",
            "have",
            "has",
            "do",
            "does",
            "did",
            "this",
            "that",
            "these",
            "those",
            "i",
            "you",
            "he",
            "she",
            "it",
            "we",
            "they",
        }

        words = text.lower().split()
        # 길이 4 이상의 단어만 고려
        filtered_words = [
            w for w in words if len(w) > 4 and w not in stopwords and w.isalpha()
        ]

        # 빈도 계산
        from collections import Counter

        word_freq = Counter(filtered_words)

        # 상위 10개 키워드
        keywords = [word for word, _ in word_freq.most_common(10)]
        return keywords

    async def crawl(self, crawl_request: PlaywrightCrawlRequest) -> Dict[str, Any]:
        """자동 크롤링 및 지능형 분석"""
        import re
        from urllib.parse import urljoin, urlparse

        if self.debug_mode:
            logger.info(
                f"DEBUG MODE: Crawler Mock 데이터 반환 (URL: {crawl_request.url})"
            )
            return {
                "start_url": crawl_request.url,
                "pages_crawled": 3,
                "max_depth": crawl_request.max_depth,
                "summary": {
                    "primary_purpose": "Mock User Profile Page",
                    "key_findings": [
                        "4 repositories",
                        "Public profile",
                        "Active developer",
                    ],
                    "social_links": {"github": ["https://github.com/kjmkjmkj"]},
                    "risks": ["No obvious security risks detected"],
                },
                "pages": [
                    {
                        "url": crawl_request.url,
                        "title": "Mock Profile",
                        "purpose": "User/Profile Page",
                        "key_info": {
                            "social_media": {"github": ["https://github.com/kjmkjmkj"]}
                        },
                        "depth": 0,
                    }
                ],
                "status": "completed",
                "note": "Mock data in DEBUG_MODE",
            }

        try:
            self.visited_urls = set()
            self.crawl_results = []

            start_time = time.time()
            async with async_playwright() as p:
                browser = await p.chromium.launch()

                await self._crawl_recursive(
                    crawl_request.url, browser, crawl_request, depth=0
                )

                await browser.close()

            execution_time = time.time() - start_time

            # 분석 결과 종합
            summary = self._generate_summary(self.crawl_results, crawl_request.url)

            return {
                "start_url": crawl_request.url,
                "pages_crawled": len(self.crawl_results),
                "max_depth": crawl_request.max_depth,
                "summary": summary,
                "pages": self.crawl_results,
                "status": "completed",
                "execution_time_ms": int(execution_time * 1000),
            }

        except Exception as e:
            logger.error(f"Playwright 크롤링 실패: {e}")
            raise ValueError(f"크롤링 오류: {str(e)}")

    async def _crawl_recursive(
        self, url: str, browser, crawl_request: PlaywrightCrawlRequest, depth: int
    ) -> None:
        """재귀적 크롤링"""
        import re
        from urllib.parse import urljoin, urlparse

        # 방문 제한 확인
        if url in self.visited_urls:
            return
        if len(self.crawl_results) >= crawl_request.max_pages:
            return
        if depth > crawl_request.max_depth:
            return

        # URL 패턴 확인
        if crawl_request.url_pattern:
            if not re.search(crawl_request.url_pattern, url):
                return

        # 같은 도메인 확인
        start_domain = urlparse(crawl_request.url).netloc
        current_domain = urlparse(url).netloc
        if start_domain != current_domain:
            return

        self.visited_urls.add(url)

        try:
            page = await browser.new_page()
            logger.info(f"크롤링: {url} (깊이: {depth})")

            await page.goto(
                url, timeout=crawl_request.timeout * 1000, wait_until="load"
            )

            # 페이지 분석
            html = await page.content()
            soup = BeautifulSoup(html, "html.parser")

            # 텍스트 추출
            for script in soup(["script", "style"]):
                script.decompose()
            text = soup.get_text(separator="\n", strip=True)

            # 메타데이터
            title = await page.title()

            # 분석
            page_analysis = {}
            if crawl_request.analyze_content:
                page_analysis = self._analyze_content(html, text, url)

            # 링크 추출
            links = []
            if crawl_request.extract_links:
                for link in soup.find_all("a", href=True):
                    href = link["href"]
                    # 상대 URL을 절대 URL로 변환
                    absolute_url = urljoin(url, href)
                    # 프래그먼트 제거
                    absolute_url = absolute_url.split("#")[0]
                    if absolute_url not in self.visited_urls:
                        links.append(absolute_url)

            # 결과 저장
            self.crawl_results.append(
                {
                    "url": url,
                    "depth": depth,
                    "title": title,
                    "text": text[:1500] if crawl_request.extract_text else "",
                    **page_analysis,
                }
            )

            # 다음 레벨 크롤링
            if depth < crawl_request.max_depth:
                for link in links[:5]:  # 각 페이지당 최대 5개 링크만 따라가기
                    if len(self.crawl_results) < crawl_request.max_pages:
                        await self._crawl_recursive(
                            link, browser, crawl_request, depth + 1
                        )

            await page.close()

        except Exception as e:
            logger.error(f"크롤링 중 오류 ({url}): {e}")

    def _generate_summary(self, results: List[Dict], start_url: str) -> Dict[str, Any]:
        """크롤링 결과 종합 분석"""
        if not results:
            return {"status": "no_results"}

        # 첫 번째 페이지를 주요 분석 대상으로
        primary = results[0]

        summary = {
            "primary_purpose": primary.get("page_purpose", "Unknown"),
            "total_pages_analyzed": len(results),
            "key_findings": [],
            "all_entities": {
                "emails": set(),
                "social_media": {},
                "urls": set(),
                "domains": set(),
            },
            "risks": set(),
            "top_keywords": [],
        }

        # 모든 페이지에서 정보 통합
        for result in results:
            # 리스크 통합
            if "potential_risks" in result:
                summary["risks"].update(result["potential_risks"])

            # 엔티티 통합
            if "entities" in result:
                for entity_type, values in result["entities"].items():
                    if entity_type in summary["all_entities"]:
                        if isinstance(values, list):
                            summary["all_entities"][entity_type].update(values)

            # 주요 정보
            if "key_information" in result:
                if "emails" in result["key_information"]:
                    summary["all_entities"]["emails"].update(
                        result["key_information"]["emails"]
                    )
                if "social_media" in result["key_information"]:
                    summary["all_entities"]["social_media"].update(
                        result["key_information"]["social_media"]
                    )

            # 키워드
            if "keywords" in result:
                summary["top_keywords"].extend(result["keywords"][:3])

        # Set을 List로 변환
        summary["all_entities"]["emails"] = list(summary["all_entities"]["emails"])[:10]
        summary["all_entities"]["urls"] = list(summary["all_entities"]["urls"])[:10]
        summary["all_entities"]["domains"] = list(summary["all_entities"]["domains"])[
            :10
        ]
        summary["risks"] = list(summary["risks"])

        # 키워드 중복 제거 및 상위 10개만
        from collections import Counter

        keyword_counts = Counter(summary["top_keywords"])
        summary["top_keywords"] = [word for word, _ in keyword_counts.most_common(10)]

        # 주요 발견사항
        if summary["all_entities"]["social_media"]:
            summary["key_findings"].append(
                f"Found social media links: {list(summary['all_entities']['social_media'].keys())}"
            )
        if summary["all_entities"]["emails"]:
            summary["key_findings"].append(
                f"Found {len(summary['all_entities']['emails'])} email addresses"
            )
        if len(results) > 1:
            summary["key_findings"].append(f"Crawled {len(results)} related pages")
        if summary["all_entities"]["urls"]:
            summary["key_findings"].append(
                f"Found {len(summary['all_entities']['urls'])} external URLs"
            )

        return summary

    async def interact(
        self, interaction_request: PlaywrightInteractionRequest
    ) -> Dict[str, Any]:
        """동적 상호작용 실행"""
        if self.debug_mode:
            logger.info(
                f"DEBUG MODE: Interaction Mock 데이터 반환 (URL: {interaction_request.url})"
            )
            return {
                "url": interaction_request.url,
                "actions_executed": len(interaction_request.actions),
                "actions": [
                    {"action": step.action, "status": "success (mock)"}
                    for step in interaction_request.actions
                ],
                "final_url": interaction_request.url,
                "screenshot": None,
                "status": "completed (mock)",
            }

        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(
                    headless=interaction_request.headless
                )
                context = await browser.new_context()

                # 세션 로드
                if interaction_request.load_session:
                    await self._load_session(context, interaction_request.load_session)

                page = await context.new_page()
                logger.info(f"상호작용 시작: {interaction_request.url}")
                await page.goto(interaction_request.url, wait_until="load")

                action_results = []

                # 액션 시퀀스 실행
                for idx, action_step in enumerate(interaction_request.actions):
                    logger.info(
                        f"액션 {idx + 1}/{len(interaction_request.actions)}: {action_step.action}"
                    )
                    try:
                        result = await self._execute_action(page, action_step)
                        action_results.append(
                            {
                                "step": idx + 1,
                                "action": action_step.action,
                                "selector": action_step.selector,
                                "description": action_step.description,
                                "status": "success",
                                "result": result,
                            }
                        )

                        # 딜레이
                        if action_step.delay and action_step.delay > 0:
                            await page.wait_for_timeout(action_step.delay)

                    except Exception as e:
                        logger.error(f"액션 실행 실패: {action_step.action} - {e}")
                        action_results.append(
                            {
                                "step": idx + 1,
                                "action": action_step.action,
                                "selector": action_step.selector,
                                "status": "failed",
                                "error": str(e),
                            }
                        )

                # 최종 데이터 추출
                final_data = {}
                if interaction_request.extract_data:
                    html = await page.content()
                    soup = BeautifulSoup(html, "html.parser")

                    # 텍스트 추출
                    for script in soup(["script", "style"]):
                        script.decompose()
                    text = soup.get_text(separator="\n", strip=True)
                    final_data["text"] = text[:2000] if text else ""

                    # 링크 추출
                    links = []
                    for link in soup.find_all("a", href=True):
                        links.append(
                            {"text": link.get_text(strip=True), "href": link["href"]}
                        )
                    final_data["links"] = links[:50]

                    # 메타데이터
                    final_data["title"] = await page.title()
                    final_data["url"] = page.url

                # 최종 스크린샷
                screenshot_b64 = None
                if interaction_request.screenshot_final:
                    screenshot_bytes = await page.screenshot(full_page=True)
                    screenshot_b64 = base64.b64encode(screenshot_bytes).decode("utf-8")

                # 세션 저장
                if interaction_request.save_session and interaction_request.session_name:
                    await self._save_session(context, interaction_request.session_name)

                await browser.close()

                return {
                    "url": interaction_request.url,
                    "final_url": page.url,
                    "actions_executed": len(action_results),
                    "actions": action_results,
                    "data": final_data,
                    "screenshot": screenshot_b64,
                    "status": "completed",
                }

        except Exception as e:
            logger.error(f"상호작용 실행 실패: {e}")
            raise ValueError(f"상호작용 오류: {str(e)}")

    async def _execute_action(self, page, action_step: ActionStep) -> Any:
        """개별 액션 실행"""
        action = action_step.action.lower()
        selector = action_step.selector
        value = action_step.value
        timeout = action_step.timeout or 5000

        if action == "click":
            if not selector:
                raise ValueError("click 액션에는 selector가 필요합니다")
            await page.click(selector, timeout=timeout)
            return f"클릭 완료: {selector}"

        elif action == "type":
            if not selector or not value:
                raise ValueError("type 액션에는 selector와 value가 필요합니다")
            await page.type(selector, value, timeout=timeout)
            return f"입력 완료: {selector} = {value}"

        elif action == "fill":
            if not selector or not value:
                raise ValueError("fill 액션에는 selector와 value가 필요합니다")
            await page.fill(selector, value, timeout=timeout)
            return f"채우기 완료: {selector} = {value}"

        elif action == "press":
            if not value:
                raise ValueError("press 액션에는 value(키)가 필요합니다")
            await page.keyboard.press(value)
            return f"키 입력: {value}"

        elif action == "select":
            if not selector or not value:
                raise ValueError("select 액션에는 selector와 value가 필요합니다")
            await page.select_option(selector, value, timeout=timeout)
            return f"선택 완료: {selector} = {value}"

        elif action == "scroll":
            # value에 픽셀 수 또는 "bottom" 지정
            if value == "bottom":
                await page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
                return "페이지 하단까지 스크롤"
            elif value:
                await page.evaluate(f"window.scrollBy(0, {value})")
                return f"{value}px 스크롤"
            else:
                await page.evaluate("window.scrollBy(0, 500)")
                return "500px 스크롤"

        elif action == "wait":
            # value에 밀리초 지정
            wait_time = int(value) if value else 1000
            await page.wait_for_timeout(wait_time)
            return f"{wait_time}ms 대기"

        elif action == "wait_for_selector":
            if not selector:
                raise ValueError("wait_for_selector 액션에는 selector가 필요합니다")
            await page.wait_for_selector(selector, timeout=timeout)
            return f"요소 로드 대기 완료: {selector}"

        elif action == "screenshot":
            # value에 파일명 지정 가능
            filename = value or f"screenshot_{int(time.time())}.png"
            screenshot_bytes = await page.screenshot()
            screenshot_b64 = base64.b64encode(screenshot_bytes).decode("utf-8")
            return {"screenshot": screenshot_b64, "filename": filename}

        elif action == "navigate":
            if not value:
                raise ValueError("navigate 액션에는 value(URL)가 필요합니다")
            await page.goto(value, wait_until="load")
            return f"페이지 이동: {value}"

        elif action == "hover":
            if not selector:
                raise ValueError("hover 액션에는 selector가 필요합니다")
            await page.hover(selector, timeout=timeout)
            return f"마우스 오버: {selector}"

        elif action == "check":
            if not selector:
                raise ValueError("check 액션에는 selector가 필요합니다")
            await page.check(selector, timeout=timeout)
            return f"체크박스 선택: {selector}"

        elif action == "uncheck":
            if not selector:
                raise ValueError("uncheck 액션에는 selector가 필요합니다")
            await page.uncheck(selector, timeout=timeout)
            return f"체크박스 해제: {selector}"

        elif action == "get_text":
            if not selector:
                raise ValueError("get_text 액션에는 selector가 필요합니다")
            text = await page.text_content(selector, timeout=timeout)
            return {"text": text}

        elif action == "get_attribute":
            if not selector or not value:
                raise ValueError(
                    "get_attribute 액션에는 selector와 value(속성명)가 필요합니다"
                )
            attr = await page.get_attribute(selector, value, timeout=timeout)
            return {"attribute": value, "value": attr}

        else:
            raise ValueError(f"지원하지 않는 액션: {action}")

    async def _save_session(self, context, session_name: str) -> None:
        """세션 저장 (쿠키 + 로컬스토리지)"""
        session_path = os.path.join(self.session_storage_dir, f"{session_name}.json")

        # 쿠키 저장
        cookies = await context.cookies()

        # 로컬스토리지는 페이지별로 저장해야 함
        # 간단하게 쿠키만 저장
        session_data = {"cookies": cookies, "timestamp": datetime.now().isoformat()}

        with open(session_path, "w") as f:
            json.dump(session_data, f, indent=2)

        logger.info(f"세션 저장 완료: {session_path}")

    async def _load_session(self, context, session_name: str) -> None:
        """세션 로드"""
        session_path = os.path.join(self.session_storage_dir, f"{session_name}.json")

        if not os.path.exists(session_path):
            logger.warning(f"세션 파일 없음: {session_path}")
            return

        with open(session_path, "r") as f:
            session_data = json.load(f)

        # 쿠키 복원
        if "cookies" in session_data:
            await context.add_cookies(session_data["cookies"])

        logger.info(f"세션 로드 완료: {session_path}")

    async def auto_explore(
        self, explore_request: PlaywrightAutoExploreRequest
    ) -> Dict[str, Any]:
        """자동 탐색 - 목표 기반 지능형 탐색"""
        if self.debug_mode:
            logger.info(
                f"DEBUG MODE: Auto-explore Mock 데이터 반환 (URL: {explore_request.url})"
            )
            return {
                "url": explore_request.url,
                "goal": explore_request.goal,
                "pages_visited": 3,
                "interactions": 5,
                "findings": [
                    "Found contact form",
                    "Found social media links: Twitter, GitHub",
                ],
                "status": "completed (mock)",
            }

        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch()
                page = await browser.new_page()

                logger.info(
                    f"자동 탐색 시작: {explore_request.url} (목표: {explore_request.goal})"
                )
                await page.goto(explore_request.url, wait_until="load")

                interactions = []
                findings = []
                pages_visited = [explore_request.url]

                # 목표 키워드 추출
                goal_keywords = self._extract_goal_keywords(explore_request.goal)

                for i in range(explore_request.max_interactions):
                    if len(pages_visited) >= explore_request.max_pages:
                        break

                    # 페이지 분석
                    html = await page.content()
                    soup = BeautifulSoup(html, "html.parser")

                    # 목표와 관련된 요소 찾기
                    relevant_elements = await self._find_relevant_elements(
                        page, soup, goal_keywords
                    )

                    if not relevant_elements:
                        logger.info("더 이상 관련 요소를 찾을 수 없습니다")
                        break

                    # 가장 관련성 높은 요소 선택
                    element_info = relevant_elements[0]

                    # 상호작용 시도
                    try:
                        interaction_result = await self._interact_with_element(
                            page, element_info
                        )
                        interactions.append(interaction_result)

                        # 새로운 정보 발견
                        new_findings = await self._check_for_findings(
                            page, goal_keywords
                        )
                        findings.extend(new_findings)

                        # URL 변경 확인
                        current_url = page.url
                        if current_url not in pages_visited:
                            pages_visited.append(current_url)
                            logger.info(f"새 페이지 방문: {current_url}")

                    except Exception as e:
                        logger.error(f"상호작용 실패: {e}")
                        continue

                await browser.close()

                return {
                    "url": explore_request.url,
                    "goal": explore_request.goal,
                    "pages_visited": len(pages_visited),
                    "pages": pages_visited,
                    "interactions_count": len(interactions),
                    "interactions": interactions,
                    "findings": list(set(findings)),
                    "status": "completed",
                }

        except Exception as e:
            logger.error(f"자동 탐색 실패: {e}")
            raise ValueError(f"자동 탐색 오류: {str(e)}")

    def _extract_goal_keywords(self, goal: str) -> List[str]:
        """목표에서 키워드 추출"""
        # 간단한 키워드 추출
        keywords = []

        goal_lower = goal.lower()

        # 연락처 관련
        if any(
            word in goal_lower
            for word in ["연락", "contact", "email", "이메일", "phone", "전화"]
        ):
            keywords.extend(["contact", "email", "phone", "tel", "연락"])

        # SNS 관련
        if any(word in goal_lower for word in ["sns", "social", "소셜"]):
            keywords.extend(
                ["twitter", "facebook", "instagram", "linkedin", "github", "social"]
            )

        # 기본적으로 goal의 단어들 추가
        words = goal_lower.split()
        keywords.extend(words)

        return list(set(keywords))

    async def _find_relevant_elements(
        self, page, soup, keywords: List[str]
    ) -> List[Dict[str, Any]]:
        """관련 요소 찾기"""
        relevant = []

        # 링크 찾기
        for link in soup.find_all("a", href=True):
            text = link.get_text(strip=True).lower()
            href = link["href"].lower()

            # 키워드 매칭
            relevance_score = sum(
                1 for keyword in keywords if keyword in text or keyword in href
            )

            if relevance_score > 0:
                # CSS 셀렉터 생성 시도
                selector = None
                if link.get("id"):
                    selector = f"#{link['id']}"
                elif link.get("class"):
                    classes = " ".join(link["class"])
                    selector = f"a.{link['class'][0]}"

                if not selector:
                    # href로 찾기
                    selector = f'a[href="{link["href"]}"]'

                relevant.append(
                    {
                        "type": "link",
                        "text": link.get_text(strip=True),
                        "href": link["href"],
                        "selector": selector,
                        "relevance": relevance_score,
                    }
                )

        # 버튼 찾기
        for button in soup.find_all(["button", "input"]):
            if button.name == "input" and button.get("type") not in [
                "submit",
                "button",
            ]:
                continue

            text = button.get_text(strip=True).lower()
            value = (button.get("value") or "").lower()

            relevance_score = sum(
                1 for keyword in keywords if keyword in text or keyword in value
            )

            if relevance_score > 0:
                selector = None
                if button.get("id"):
                    selector = f"#{button['id']}"
                elif button.get("class"):
                    selector = f"{button.name}.{button['class'][0]}"

                relevant.append(
                    {
                        "type": "button",
                        "text": text or value,
                        "selector": selector,
                        "relevance": relevance_score,
                    }
                )

        # 관련성 순으로 정렬
        relevant.sort(key=lambda x: x["relevance"], reverse=True)

        return relevant[:5]  # 상위 5개만

    async def _interact_with_element(
        self, page, element_info: Dict[str, Any]
    ) -> Dict[str, Any]:
        """요소와 상호작용"""
        element_type = element_info["type"]
        selector = element_info["selector"]

        if element_type == "link":
            await page.click(selector)
            await page.wait_for_load_state("load")
            return {
                "action": "click_link",
                "text": element_info["text"],
                "href": element_info["href"],
            }

        elif element_type == "button":
            await page.click(selector)
            await page.wait_for_timeout(1000)
            return {
                "action": "click_button",
                "text": element_info["text"],
            }

        return {"action": "unknown"}

    async def _check_for_findings(
        self, page, keywords: List[str]
    ) -> List[str]:
        """새로운 발견사항 확인"""
        findings = []
        html = await page.content()
        soup = BeautifulSoup(html, "html.parser")

        # 텍스트에서 키워드 찾기
        text = soup.get_text().lower()

        for keyword in keywords:
            if keyword in text:
                findings.append(f"Found keyword: {keyword}")

        # 이메일 찾기
        import re

        emails = re.findall(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", text)
        if emails:
            findings.append(f"Found {len(set(emails))} email addresses")

        # 전화번호 찾기
        phones = re.findall(r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b", text)
        if phones:
            findings.append(f"Found {len(set(phones))} phone numbers")

        return findings

    async def deep_analyze(
        self, deep_request: PlaywrightDeepAnalyzeRequest
    ) -> Dict[str, Any]:
        """재귀적 URL 분석 - URL을 분석하고 발견된 모든 URL도 재귀적으로 분석"""
        if self.debug_mode:
            logger.info(
                f"DEBUG MODE: Deep analyze Mock 데이터 반환 (URL: {deep_request.url})"
            )
            return {
                "start_url": deep_request.url,
                "total_urls_analyzed": 5,
                "urls": [
                    {
                        "url": deep_request.url,
                        "depth": 0,
                        "status": "success",
                        "title": "Mock Page",
                    }
                ],
                "relationships": [],
                "summary": {"total_emails": 3, "total_threats": 0},
                "status": "completed (mock)",
            }

        try:
            import re
            from urllib.parse import urljoin, urlparse

            async with async_playwright() as p:
                browser = await p.chromium.launch()
                context = await browser.new_context()

                # 분석 데이터 저장
                analyzed_urls = {}  # url -> data
                url_queue = [(deep_request.url, 0, None)]  # (url, depth, parent)
                visited = set()
                relationships = []

                start_domain = urlparse(deep_request.url).netloc

                logger.info(f"재귀적 URL 분석 시작: {deep_request.url}")

                while url_queue and len(analyzed_urls) < deep_request.max_urls:
                    current_url, depth, parent_url = url_queue.pop(0)

                    # 중복 확인
                    if current_url in visited:
                        continue

                    # 깊이 제한
                    if depth > deep_request.max_depth:
                        continue

                    # 외부 도메인 필터링
                    if not deep_request.include_external:
                        current_domain = urlparse(current_url).netloc
                        if current_domain != start_domain:
                            continue

                    visited.add(current_url)

                    # URL 관계 저장
                    if parent_url:
                        relationships.append(
                            {
                                "parent": parent_url,
                                "child": current_url,
                                "depth": depth,
                            }
                        )

                    logger.info(
                        f"분석 중 ({len(analyzed_urls) + 1}/{deep_request.max_urls}): {current_url} (깊이: {depth})"
                    )

                    # URL 분석
                    url_data = await self._analyze_single_url(
                        browser, context, current_url, depth, parent_url, deep_request
                    )

                    analyzed_urls[current_url] = url_data

                    # 성공적으로 분석된 경우에만 하위 URL 추가
                    if url_data["status"] == "success" and "discovered_urls" in url_data:
                        for discovered_url in url_data["discovered_urls"][:10]:  # 최대 10개만
                            if discovered_url not in visited:
                                url_queue.append((discovered_url, depth + 1, current_url))

                await browser.close()

                # 요약 생성
                summary = self._generate_deep_analysis_summary(
                    analyzed_urls, relationships, deep_request
                )

                return {
                    "start_url": deep_request.url,
                    "total_urls_analyzed": len(analyzed_urls),
                    "max_depth_reached": max(
                        (data["depth"] for data in analyzed_urls.values()), default=0
                    ),
                    "urls": list(analyzed_urls.values()),
                    "relationships": relationships,
                    "summary": summary,
                    "status": "completed",
                }

        except Exception as e:
            logger.error(f"재귀적 URL 분석 실패: {e}")
            raise ValueError(f"재귀적 URL 분석 오류: {str(e)}")

    async def _analyze_single_url(
        self,
        browser,
        context,
        url: str,
        depth: int,
        parent_url: Optional[str],
        deep_request: PlaywrightDeepAnalyzeRequest,
    ) -> Dict[str, Any]:
        """단일 URL 분석"""
        import re
        from urllib.parse import urljoin, urlparse

        result = {
            "url": url,
            "depth": depth,
            "parent_url": parent_url,
            "domain": urlparse(url).netloc,
            "status": "pending",
        }

        try:
            page = await context.new_page()
            await page.goto(
                url, timeout=deep_request.timeout_per_url * 1000, wait_until="load"
            )

            # 기본 메타데이터
            result["title"] = await page.title()

            # HTML 가져오기
            html = await page.content()
            soup = BeautifulSoup(html, "html.parser")

            # 텍스트 추출
            for script in soup(["script", "style"]):
                script.decompose()
            text = soup.get_text(separator="\n", strip=True)
            result["text_preview"] = text[:500] if text else ""

            # 메타 설명
            meta_desc = soup.find("meta", {"name": "description"})
            if meta_desc:
                result["description"] = meta_desc.get("content", "")

            # 이메일 추출
            if deep_request.extract_emails:
                emails = set(
                    re.findall(
                        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
                        text,
                    )
                )
                if emails:
                    result["emails"] = list(emails)[:10]

            # 전화번호 추출
            if deep_request.extract_phones:
                phones = set(re.findall(r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b", text))
                if phones:
                    result["phones"] = list(phones)[:10]

            # 소셜 미디어 링크 추출
            if deep_request.extract_social:
                social_patterns = {
                    "twitter": r"(?:twitter\.com|x\.com)/[\w]+",
                    "github": r"github\.com/[\w-]+",
                    "linkedin": r"linkedin\.com/(?:in|company)/[\w-]+",
                    "instagram": r"instagram\.com/[\w.]+",
                    "facebook": r"facebook\.com/[\w.]+",
                    "youtube": r"youtube\.com/(?:@|channel|c)/[\w-]+",
                }

                social_links = {}
                for platform, pattern in social_patterns.items():
                    matches = re.findall(pattern, text.lower())
                    if matches:
                        social_links[platform] = list(set(matches))[:3]

                if social_links:
                    result["social_media"] = social_links

            # URL 추출 (링크 + 텍스트)
            discovered_urls = set()

            # HTML 링크에서 추출
            for link in soup.find_all("a", href=True):
                href = link["href"]
                # 상대 URL을 절대 URL로 변환
                absolute_url = urljoin(url, href)
                # 프래그먼트 제거
                absolute_url = absolute_url.split("#")[0]
                # http/https만
                if absolute_url.startswith(("http://", "https://")):
                    discovered_urls.add(absolute_url)

            # 텍스트에서 URL 추출
            text_urls = re.findall(r'https?://[^\s<>"{}|\\^`\[\]]+', text)
            for text_url in text_urls:
                # 정리
                text_url = text_url.rstrip(".,;:)")
                discovered_urls.add(text_url)

            result["discovered_urls"] = list(discovered_urls)[:50]  # 최대 50개
            result["url_count"] = len(discovered_urls)

            # 위협 정보 확인 (선택적)
            if deep_request.check_threats:
                domain = urlparse(url).netloc
                threat_result = vt_client.query_domain(domain)
                if threat_result.get("status") == "success":
                    threat_data = threat_result.get("data", {})
                    result["threat_info"] = {
                        "threat_level": threat_data.get("threat_level", "Unknown"),
                        "detected_by": threat_data.get("detected_by", 0),
                    }

            result["status"] = "success"
            await page.close()

        except Exception as e:
            logger.error(f"URL 분석 실패 ({url}): {e}")
            result["status"] = "failed"
            result["error"] = str(e)

        return result

    def _generate_deep_analysis_summary(
        self,
        analyzed_urls: Dict[str, Dict],
        relationships: List[Dict],
        deep_request: PlaywrightDeepAnalyzeRequest,
    ) -> Dict[str, Any]:
        """재귀적 분석 요약 생성"""
        summary = {
            "total_urls": len(analyzed_urls),
            "successful": sum(
                1 for data in analyzed_urls.values() if data["status"] == "success"
            ),
            "failed": sum(
                1 for data in analyzed_urls.values() if data["status"] == "failed"
            ),
        }

        # 도메인 분포
        domains = {}
        for data in analyzed_urls.values():
            domain = data.get("domain", "unknown")
            domains[domain] = domains.get(domain, 0) + 1
        summary["domains"] = domains

        # 이메일 수집
        all_emails = set()
        for data in analyzed_urls.values():
            if "emails" in data:
                all_emails.update(data["emails"])
        summary["total_emails_found"] = len(all_emails)
        summary["emails"] = list(all_emails)[:20]  # 최대 20개

        # 전화번호 수집
        all_phones = set()
        for data in analyzed_urls.values():
            if "phones" in data:
                all_phones.update(data["phones"])
        summary["total_phones_found"] = len(all_phones)
        summary["phones"] = list(all_phones)[:20]

        # 소셜 미디어 통합
        all_social = {}
        for data in analyzed_urls.values():
            if "social_media" in data:
                for platform, links in data["social_media"].items():
                    if platform not in all_social:
                        all_social[platform] = set()
                    all_social[platform].update(links)

        summary["social_media"] = {
            platform: list(links)[:5] for platform, links in all_social.items()
        }

        # 위협 정보 (있는 경우)
        if deep_request.check_threats:
            threats = []
            for data in analyzed_urls.values():
                if "threat_info" in data:
                    if data["threat_info"]["threat_level"] not in ["None", "Low"]:
                        threats.append(
                            {
                                "url": data["url"],
                                "threat_level": data["threat_info"]["threat_level"],
                                "detected_by": data["threat_info"]["detected_by"],
                            }
                        )
            summary["threats_found"] = len(threats)
            summary["threats"] = threats

        # URL 관계 통계
        summary["total_relationships"] = len(relationships)

        # 깊이별 분포
        depth_distribution = {}
        for data in analyzed_urls.values():
            depth = data["depth"]
            depth_distribution[depth] = depth_distribution.get(depth, 0) + 1
        summary["depth_distribution"] = depth_distribution

        return summary


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
# Phase 4: MCP 서버 초기화
# ============================================================================

server = FastMCP("osint-mcp-server")


# ============================================================================
# Phase 5: MCP Tools (@server.tool() 데코레이터 사용)
# ============================================================================


@server.tool()
def search_intelligence_x(request: SearchRequest) -> str:
    """
    Intelligence X에서 다크웹 및 유출 데이터를 검색합니다.

    Args:
        request: 검색 요청 정보

    Returns:
        JSON 형식의 검색 결과
    """
    try:
        start_time = time.time()
        result = intelx_client.search(request)
        execution_time = (time.time() - start_time) * 1000

        return json.dumps(
            {
                **result,
                "execution_time_ms": int(execution_time),
            },
            indent=2,
            ensure_ascii=False,
        )
    except Exception as e:
        logger.error(f"Intelligence X 검색 오류: {e}")
        return json.dumps({"error": str(e)}, ensure_ascii=False)


@server.tool()
def search_username_sherlock(request: SherlockSearchRequest) -> str:
    """
    Sherlock을 사용하여 사용자명을 여러 웹사이트에서 검색합니다.

    Args:
        request: Sherlock 검색 요청 정보

    Returns:
        JSON 형식의 검색 결과
    """
    try:
        start_time = time.time()
        result = sherlock_client.search(request)
        execution_time = (time.time() - start_time) * 1000

        return json.dumps(
            {
                **result,
                "execution_time_ms": int(execution_time),
            },
            indent=2,
            ensure_ascii=False,
        )
    except Exception as e:
        logger.error(f"Sherlock 검색 오류: {e}")
        return json.dumps({"error": str(e)}, ensure_ascii=False)


@server.tool()
async def analyze_url_playwright(request: PlaywrightAnalyzeRequest) -> str:
    """
    Playwright를 사용하여 URL을 분석합니다.

    Args:
        request: Playwright 분석 요청 정보

    Returns:
        JSON 형식의 분석 결과
    """
    try:
        start_time = time.time()
        result = await playwright_client.analyze(request)
        execution_time = (time.time() - start_time) * 1000

        # PDF 생성 (비동기)
        pdf_path = ""
        try:
            pdf_path = await pdf_generator.url_to_pdf(request.url)
        except Exception as pdf_error:
            logger.warning(f"PDF 생성 실패: {pdf_error}")

        # 분석 결과 요약 생성
        summary = f"URL: {request.url}"
        if "metadata" in result and "title" in result["metadata"]:
            summary += f" | 제목: {result['metadata']['title']}"

        # 중요 정보 추출
        sensitive_info = {}
        if "entities" in result:
            entities = result["entities"]
            if "emails" in entities:
                sensitive_info["emails"] = entities["emails"]
            if "phones" in entities:
                sensitive_info["phones"] = entities["phones"]
            if "social_media" in entities:
                sensitive_info["social_media"] = entities["social_media"]

        # 데이터베이스에 저장
        try:
            osint_db.add_record(
                target=request.url,
                url=request.url,
                pdf_path=pdf_path,
                summary=summary,
                sensitive_info=sensitive_info,
                collection_method="analyze_url_playwright",
                threat_level="unknown",
                metadata=result
            )
        except Exception as db_error:
            logger.warning(f"DB 저장 실패: {db_error}")

        return json.dumps(
            {
                **result,
                "execution_time_ms": int(execution_time),
                "saved_to_db": True,
                "pdf_path": pdf_path
            },
            indent=2,
            ensure_ascii=False,
        )
    except Exception as e:
        logger.error(f"URL 분석 오류: {e}")
        return json.dumps({"error": str(e)}, ensure_ascii=False)


@server.tool()
def check_virustotal_domain(request: ThreatIntelRequest) -> str:
    """
    VirusTotal에서 도메인의 위협 정보를 확인합니다.

    Args:
        request: 위협 정보 조회 요청 (query_type: 'domain' 사용)

    Returns:
        JSON 형식의 위협 정보
    """
    try:
        start_time = time.time()
        result = vt_client.query_domain(request.query)
        execution_time = (time.time() - start_time) * 1000

        # 위협 수준 결정
        threat_level = "safe"
        if "stats" in result:
            stats = result["stats"]
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)

            if malicious > 0:
                threat_level = "malicious"
            elif suspicious > 0:
                threat_level = "suspicious"

        # 요약 생성
        summary = f"VirusTotal 도메인 조회: {request.query}"
        if "stats" in result:
            summary += f" | 악성: {result['stats'].get('malicious', 0)}, 의심: {result['stats'].get('suspicious', 0)}"

        # 데이터베이스에 저장
        try:
            osint_db.add_record(
                target=request.query,
                url=f"https://{request.query}",
                pdf_path="",
                summary=summary,
                sensitive_info={},
                collection_method="check_virustotal_domain",
                threat_level=threat_level,
                metadata=result
            )
        except Exception as db_error:
            logger.warning(f"DB 저장 실패: {db_error}")

        return json.dumps(
            {
                **result,
                "execution_time_ms": int(execution_time),
                "saved_to_db": True
            },
            indent=2,
            ensure_ascii=False,
        )
    except Exception as e:
        logger.error(f"VirusTotal 도메인 조회 오류: {e}")
        return json.dumps({"error": str(e)}, ensure_ascii=False)


@server.tool()
def check_virustotal_ip(request: ThreatIntelRequest) -> str:
    """
    VirusTotal에서 IP 주소의 위협 정보를 확인합니다.

    Args:
        request: 위협 정보 조회 요청 (query_type: 'ip' 사용)

    Returns:
        JSON 형식의 위협 정보
    """
    try:
        start_time = time.time()
        result = vt_client.query_ip(request.query)
        execution_time = (time.time() - start_time) * 1000

        # 위협 수준 결정
        threat_level = "safe"
        if "stats" in result:
            stats = result["stats"]
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)

            if malicious > 0:
                threat_level = "malicious"
            elif suspicious > 0:
                threat_level = "suspicious"

        # 요약 생성
        summary = f"VirusTotal IP 조회: {request.query}"
        if "stats" in result:
            summary += f" | 악성: {result['stats'].get('malicious', 0)}, 의심: {result['stats'].get('suspicious', 0)}"

        # 데이터베이스에 저장
        try:
            osint_db.add_record(
                target=request.query,
                url=f"http://{request.query}",
                pdf_path="",
                summary=summary,
                sensitive_info={},
                collection_method="check_virustotal_ip",
                threat_level=threat_level,
                metadata=result
            )
        except Exception as db_error:
            logger.warning(f"DB 저장 실패: {db_error}")

        return json.dumps(
            {
                **result,
                "execution_time_ms": int(execution_time),
                "saved_to_db": True
            },
            indent=2,
            ensure_ascii=False,
        )
    except Exception as e:
        logger.error(f"VirusTotal IP 조회 오류: {e}")
        return json.dumps({"error": str(e)}, ensure_ascii=False)


@server.tool()
async def crawl_and_analyze_url(request: PlaywrightCrawlRequest) -> str:
    """
    Playwright를 사용하여 URL을 자동으로 크롤링하고 지능형 분석을 수행합니다.

    Args:
        request: Playwright 크롤링 요청 정보

    Returns:
        JSON 형식의 크롤링 결과
    """
    try:
        start_time = time.time()
        result = await playwright_client.crawl(request)
        execution_time = (time.time() - start_time) * 1000

        # PDF 생성 (첫 번째 페이지만)
        pdf_path = ""
        try:
            pdf_path = await pdf_generator.url_to_pdf(request.url)
        except Exception as pdf_error:
            logger.warning(f"PDF 생성 실패: {pdf_error}")

        # 크롤링 결과 요약
        summary = f"URL 크롤링: {request.url}"
        if "summary" in result:
            crawl_summary = result["summary"]
            summary += f" | 방문 페이지: {crawl_summary.get('total_pages', 0)}개"

        # 모든 페이지에서 중요 정보 수집
        all_emails = []
        all_phones = []
        all_social = []

        if "pages" in result:
            for page in result["pages"]:
                if "entities" in page:
                    entities = page["entities"]
                    all_emails.extend(entities.get("emails", []))
                    all_phones.extend(entities.get("phones", []))
                    all_social.extend(entities.get("social_media", []))

        # 중복 제거
        sensitive_info = {
            "emails": list(set(all_emails)),
            "phones": list(set(all_phones)),
            "social_media": list(set(all_social))
        }

        # 데이터베이스에 저장
        try:
            osint_db.add_record(
                target=request.url,
                url=request.url,
                pdf_path=pdf_path,
                summary=summary,
                sensitive_info=sensitive_info,
                collection_method="crawl_and_analyze_url",
                threat_level="unknown",
                metadata=result
            )
        except Exception as db_error:
            logger.warning(f"DB 저장 실패: {db_error}")

        return json.dumps(
            {
                **result,
                "execution_time_ms": int(execution_time),
                "saved_to_db": True,
                "pdf_path": pdf_path
            },
            indent=2,
            ensure_ascii=False,
        )
    except Exception as e:
        logger.error(f"크롤링 오류: {e}")
        return json.dumps({"error": str(e)}, ensure_ascii=False)


@server.tool()
async def interact_with_webpage(request: PlaywrightInteractionRequest) -> str:
    """
    Playwright를 사용하여 웹페이지와 동적으로 상호작용합니다.

    버튼 클릭, 폼 입력, 스크롤, 네비게이션 등 사용자처럼 웹사이트를 조작할 수 있습니다.
    액션 시퀀스를 정의하여 복잡한 시나리오를 자동화할 수 있습니다.

    지원되는 액션:
    - click: 요소 클릭
    - type/fill: 텍스트 입력
    - press: 키 입력 (Enter, Tab 등)
    - select: 드롭다운 선택
    - scroll: 스크롤
    - wait: 대기
    - wait_for_selector: 요소 로드 대기
    - screenshot: 스크린샷 캡처
    - navigate: 페이지 이동
    - hover: 마우스 오버
    - check/uncheck: 체크박스
    - get_text: 텍스트 가져오기
    - get_attribute: 속성 가져오기

    Args:
        request: Playwright 상호작용 요청 정보

    Returns:
        JSON 형식의 실행 결과 (각 액션의 성공/실패, 최종 데이터, 스크린샷 등)
    """
    try:
        start_time = time.time()
        result = await playwright_client.interact(request)
        execution_time = (time.time() - start_time) * 1000

        return json.dumps(
            {
                **result,
                "execution_time_ms": int(execution_time),
            },
            indent=2,
            ensure_ascii=False,
        )
    except Exception as e:
        logger.error(f"상호작용 오류: {e}")
        return json.dumps({"error": str(e)}, ensure_ascii=False)


@server.tool()
async def auto_explore_webpage(request: PlaywrightAutoExploreRequest) -> str:
    """
    목표 기반 자동 웹 탐색을 수행합니다.

    Agent가 목표를 이해하고 자동으로 관련 링크를 찾아 클릭하며 정보를 수집합니다.
    키워드 기반으로 페이지를 분석하고 가장 관련성 높은 요소와 상호작용합니다.

    예시 목표:
    - "연락처 정보 찾기"
    - "SNS 링크 찾기"
    - "이메일 주소 수집"
    - "특정 키워드가 포함된 페이지 찾기"

    Args:
        request: 자동 탐색 요청 정보 (URL, 목표, 제한사항)

    Returns:
        JSON 형식의 탐색 결과 (방문한 페이지, 상호작용 내역, 발견사항)
    """
    try:
        start_time = time.time()
        result = await playwright_client.auto_explore(request)
        execution_time = (time.time() - start_time) * 1000

        return json.dumps(
            {
                **result,
                "execution_time_ms": int(execution_time),
            },
            indent=2,
            ensure_ascii=False,
        )
    except Exception as e:
        logger.error(f"자동 탐색 오류: {e}")
        return json.dumps({"error": str(e)}, ensure_ascii=False)


@server.tool()
async def deep_analyze_urls(request: PlaywrightDeepAnalyzeRequest) -> str:
    """
    재귀적 URL 분석을 수행합니다.

    제공된 URL을 분석하고, 그 페이지에서 발견된 모든 URL들도 자동으로 분석합니다.
    외부 도메인 포함 여부, 분석 깊이, 최대 URL 수 등을 설정할 수 있습니다.

    각 URL에 대해:
    - 메타데이터 (제목, 설명)
    - 이메일 주소 추출
    - 전화번호 추출
    - 소셜 미디어 링크 추출
    - 위협 정보 (선택적, VirusTotal)
    - URL 간 관계 맵핑

    사용 사례:
    - 특정 웹사이트의 전체 구조 파악
    - 웹사이트에서 모든 연락처 정보 수집
    - 링크된 모든 외부 리소스 확인
    - 웹사이트 보안 분석 (모든 링크된 도메인 위협 검사)

    Args:
        request: 재귀적 분석 요청 정보

    Returns:
        JSON 형식의 분석 결과:
        - urls: 각 URL의 상세 정보
        - relationships: URL 간 부모-자식 관계
        - summary: 통합 요약 (이메일, 전화번호, SNS, 위협 정보 등)
    """
    try:
        start_time = time.time()
        result = await playwright_client.deep_analyze(request)
        execution_time = (time.time() - start_time) * 1000

        return json.dumps(
            {
                **result,
                "execution_time_ms": int(execution_time),
            },
            indent=2,
            ensure_ascii=False,
        )
    except Exception as e:
        logger.error(f"재귀적 URL 분석 오류: {e}")
        return json.dumps({"error": str(e)}, ensure_ascii=False)


if __name__ == "__main__":
    logger.info("=" * 70)
    logger.info("Starting OSINT Unified MCP Server (fastmcp - STDIO mode)")
    logger.info("=" * 70)
    logger.info(f"DEBUG 모드: {DEBUG_MODE}")
    logger.info("Transport: STDIO (Claude Desktop 호환)")
    logger.info("")
    logger.info("✅ 활성화된 OSINT 도구:")
    logger.info("   1. search_intelligence_x - 다크웹/유출 데이터 검색")
    logger.info("   2. search_username_sherlock - 사용자명 검색")
    logger.info("   3. analyze_url_playwright - URL 분석")
    logger.info("   4. check_virustotal_domain - VirusTotal 도메인 확인")
    logger.info("   5. check_virustotal_ip - VirusTotal IP 확인")
    logger.info("   6. crawl_and_analyze_url - URL 자동 크롤링 & 지능형 분석")
    logger.info("")
    logger.info("🚀 동적 상호작용 도구:")
    logger.info("   7. interact_with_webpage - 웹페이지 동적 상호작용")
    logger.info("      (클릭, 입력, 스크롤, 네비게이션 등)")
    logger.info("   8. auto_explore_webpage - 목표 기반 자동 탐색")
    logger.info("      (Agent가 자동으로 관련 정보를 찾아 탐색)")
    logger.info("")
    logger.info("🔍 재귀적 URL 분석:")
    logger.info("   9. deep_analyze_urls - 재귀적 URL 분석 & 관계 매핑")
    logger.info("      (URL을 분석하고 발견된 모든 URL도 자동 분석)")
    logger.info("=" * 70)

    # STDIO 모드로 명시적 실행
    server.run(transport="stdio")
