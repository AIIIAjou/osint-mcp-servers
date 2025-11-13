#!/usr/bin/env python3
"""
OSINT Unified MCP Server - stdio/Claude Desktop App Compatible
통합 OSINT MCP 서버 - Claude Desktop 호환
"""

import os
import json
import time
import logging
import subprocess
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
from pydantic import BaseModel, Field
import requests

# fastmcp 라이브러리 사용
try:
    from fastmcp import mcp
except ImportError:
    print("fastmcp 설치 필요: pip install fastmcp")
    exit(1)

# ============================================================================
# 초기화 및 환경설정
# ============================================================================

load_dotenv()

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
    logger.info("DEBUG_MODE 활성화 - Mock 데이터 사용")

# ============================================================================
# MCP 서버 초기화
# ============================================================================

server = mcp.Server("osint-mcp-server")

# ============================================================================
# Client Classes
# ============================================================================


class IntelligenceXClient:
    """Intelligence X 검색 클라이언트"""

    def __init__(self, api_key: str):
        self.client = None
        self.debug_mode = DEBUG_MODE

        if api_key and intelx is not None:
            self.client = intelx(api_key)
            self.client.API_ROOT = "https://free.intelx.io"

    def search(self, term: str, maxresults: int = 100, timeout: int = 5) -> Dict[str, Any]:
        if self.debug_mode:
            logger.info(f"DEBUG MODE: Mock 데이터 반환 (검색어: {term})")
            return {
                "records": [
                    {
                        "name": f"Mock Result 1 for {term}",
                        "description": "This is a mock result for testing purposes",
                        "date": datetime.now().isoformat(),
                        "media": 1,
                        "type": 1,
                        "added": datetime.now().isoformat(),
                        "storageid": "mock-storage-id-1",
                        "bucket": "mock-bucket",
                    },
                    {
                        "name": f"Mock Result 2 for {term}",
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
                raise Exception("API 키가 설정되지 않았습니다.")

            results = self.client.search(term, maxresults=maxresults, timeout=timeout)
            return results
        except Exception as e:
            logger.error(f"검색 요청 실패: {e}")
            raise


class SherlockClient:
    """Sherlock 사용자명 검색 클라이언트"""

    def __init__(self):
        self.debug_mode = DEBUG_MODE

    def search(self, username: str, sites: Optional[List[str]] = None, timeout: int = 120) -> Dict[str, Any]:
        """Sherlock으로 사용자명 검색"""
        if self.debug_mode:
            logger.info(f"DEBUG MODE: Sherlock Mock 데이터 반환 (사용자명: {username})")
            return {
                "found": {
                    "github": {
                        "url": f"https://github.com/{username}",
                        "status": "found",
                    },
                    "twitter": {
                        "url": f"https://twitter.com/{username}",
                        "status": "found",
                    },
                },
                "not_found": ["instagram", "reddit"],
                "total_found": 2,
                "total_checked": 4,
            }

        try:
            cmd = ["sherlock", username, "--no-color", "--no-txt"]

            if sites:
                for site in sites:
                    cmd.extend(["--site", site])

            logger.info(f"Sherlock 검색 실행: {' '.join(cmd)}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout * len(sites or [100]),
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
                "username": username,
                "timestamp": datetime.now().isoformat(),
                "status": "completed",
            }
        except subprocess.TimeoutExpired:
            logger.error(f"Sherlock 타임아웃: {username}")
            raise Exception(f"Sherlock 타임아웃")
        except Exception as e:
            logger.error(f"Sherlock 검색 실패: {e}")
            raise


class PlaywrightClient:
    """Playwright URL 분석 및 자동 크롤링 클라이언트"""

    def __init__(self):
        self.debug_mode = DEBUG_MODE
        self.visited_urls = set()
        self.crawl_results = []

    async def analyze(
        self,
        url: str,
        extract_metadata: bool = True,
        extract_text: bool = True,
        extract_links: bool = True,
        screenshot: bool = False,
        wait_for_selector: Optional[str] = None,
        timeout: int = 30,
    ) -> Dict[str, Any]:
        """Playwright로 URL 분석"""
        if self.debug_mode:
            logger.info(f"DEBUG MODE: Playwright Mock 데이터 반환 (URL: {url})")
            return {
                "url": url,
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

                logger.info(f"Playwright 페이지 로드: {url}")
                await page.goto(
                    url,
                    timeout=timeout * 1000,
                    wait_until="load",
                )

                if wait_for_selector:
                    await page.wait_for_selector(wait_for_selector, timeout=5000)

                result = {"url": url, "status": "completed"}

                if extract_metadata:
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

                if extract_text:
                    html = await page.content()
                    soup = BeautifulSoup(html, "html.parser")
                    for script in soup(["script", "style"]):
                        script.decompose()
                    text = soup.get_text(separator="\n", strip=True)
                    result["text"] = text[:2000] if text else ""

                if extract_links:
                    html = await page.content()
                    soup = BeautifulSoup(html, "html.parser")
                    links = []
                    for link in soup.find_all("a", href=True):
                        links.append(
                            {"text": link.get_text(strip=True), "href": link["href"]}
                        )
                    result["links"] = links[:50]

                if screenshot:
                    screenshot_bytes = await page.screenshot()
                    result["screenshot"] = base64.b64encode(screenshot_bytes).decode(
                        "utf-8"
                    )

                await browser.close()
                return result

        except Exception as e:
            logger.error(f"Playwright 분석 실패: {e}")
            raise

    async def crawl(
        self,
        url: str,
        max_depth: int = 2,
        max_pages: int = 10,
        url_pattern: Optional[str] = None,
        extract_text: bool = True,
        extract_links: bool = True,
        analyze_content: bool = True,
        timeout: int = 60,
    ) -> Dict[str, Any]:
        """자동 크롤링 및 지능형 분석"""
        import re
        from urllib.parse import urljoin, urlparse

        if self.debug_mode:
            logger.info(f"DEBUG MODE: Crawler Mock 데이터 반환 (URL: {url})")
            return {
                "start_url": url,
                "pages_crawled": 3,
                "max_depth": max_depth,
                "summary": {
                    "primary_purpose": "Mock User Profile Page",
                    "key_findings": ["4 repositories", "Public profile", "Active developer"],
                    "social_links": {"github": ["https://github.com/kjmkjmkj"]},
                    "risks": ["No obvious security risks detected"],
                },
                "pages": [
                    {
                        "url": url,
                        "title": "Mock Profile",
                        "purpose": "User/Profile Page",
                        "key_info": {"social_media": {"github": ["https://github.com/kjmkjmkj"]}},
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
                    url,
                    browser,
                    max_depth,
                    max_pages,
                    url_pattern,
                    extract_text,
                    extract_links,
                    analyze_content,
                    timeout,
                    depth=0
                )

                await browser.close()

            execution_time = time.time() - start_time

            summary = self._generate_summary(self.crawl_results, url)

            return {
                "start_url": url,
                "pages_crawled": len(self.crawl_results),
                "max_depth": max_depth,
                "summary": summary,
                "pages": self.crawl_results,
                "status": "completed",
                "execution_time_ms": int(execution_time * 1000),
            }

        except Exception as e:
            logger.error(f"Playwright 크롤링 실패: {e}")
            raise

    async def _crawl_recursive(
        self,
        url: str,
        browser,
        max_depth: int,
        max_pages: int,
        url_pattern: Optional[str],
        extract_text: bool,
        extract_links: bool,
        analyze_content: bool,
        timeout: int,
        depth: int
    ) -> None:
        """재귀적 크롤링"""
        import re
        from urllib.parse import urljoin, urlparse

        if url in self.visited_urls:
            return
        if len(self.crawl_results) >= max_pages:
            return
        if depth > max_depth:
            return

        if url_pattern:
            if not re.search(url_pattern, url):
                return

        start_domain = urlparse(url).netloc
        current_domain = urlparse(url).netloc
        if start_domain != current_domain:
            return

        self.visited_urls.add(url)

        try:
            page = await browser.new_page()
            logger.info(f"크롤링: {url} (깊이: {depth})")

            await page.goto(
                url,
                timeout=timeout * 1000,
                wait_until="load"
            )

            html = await page.content()
            soup = BeautifulSoup(html, "html.parser")

            for script in soup(["script", "style"]):
                script.decompose()
            text = soup.get_text(separator="\n", strip=True)

            title = await page.title()

            page_analysis = {}
            if analyze_content:
                page_analysis = self._analyze_content(html, text, url)

            links = []
            if extract_links:
                for link in soup.find_all("a", href=True):
                    href = link["href"]
                    absolute_url = urljoin(url, href)
                    absolute_url = absolute_url.split("#")[0]
                    if absolute_url not in self.visited_urls:
                        links.append(absolute_url)

            self.crawl_results.append({
                "url": url,
                "depth": depth,
                "title": title,
                "text": text[:1500] if extract_text else "",
                **page_analysis
            })

            if depth < max_depth:
                for link in links[:5]:
                    if len(self.crawl_results) < max_pages:
                        await self._crawl_recursive(
                            link,
                            browser,
                            max_depth,
                            max_pages,
                            url_pattern,
                            extract_text,
                            extract_links,
                            analyze_content,
                            timeout,
                            depth + 1
                        )

            await page.close()

        except Exception as e:
            logger.error(f"크롤링 중 오류 ({url}): {e}")

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

        if any(keyword in text_lower for keyword in ["profile", "about", "bio", "user"]) or \
           any(keyword in url_lower for keyword in ["profile", "user", "about"]):
            return "User/Profile Page"

        if any(keyword in text_lower for keyword in ["login", "password", "username", "sign in"]):
            return "Authentication/Login Page"

        if any(keyword in text_lower for keyword in ["price", "buy", "purchase", "cart", "checkout", "product"]):
            return "E-commerce/Shopping Page"

        if any(keyword in text_lower for keyword in ["article", "blog", "post", "author", "published"]):
            return "Blog/Article Page"

        if any(keyword in text_lower for keyword in ["search result", "found", "matches"]):
            return "Search Results Page"

        if "api" in url_lower or any(keyword in text_lower for keyword in ["endpoint", "request", "response", "json"]):
            return "API/Technical Documentation"

        return "General Content Page"

    def _extract_key_info(self, text: str, html: str) -> Dict[str, Any]:
        """주요 정보 추출"""
        import re

        info = {}

        emails = set(re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', text))
        if emails:
            info["emails"] = list(emails)[:5]

        phones = set(re.findall(r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b', text))
        if phones:
            info["phone_numbers"] = list(phones)[:5]

        social_patterns = {
            "twitter": r'twitter\.com/[\w]+',
            "github": r'github\.com/[\w-]+',
            "linkedin": r'linkedin\.com/in/[\w-]+',
            "instagram": r'instagram\.com/[\w.]+',
            "facebook": r'facebook\.com/[\w.]+',
        }

        social_links = {}
        for platform, pattern in social_patterns.items():
            matches = re.findall(pattern, text)
            if matches:
                social_links[platform] = list(set(matches))[:3]

        if social_links:
            info["social_media"] = social_links

        soup = BeautifulSoup(html, "html.parser")

        og_title = soup.find("meta", property="og:title")
        og_description = soup.find("meta", property="og:description")

        if og_title:
            info["og_title"] = og_title.get("content")
        if og_description:
            info["og_description"] = og_description.get("content")

        author = soup.find("meta", {"name": "author"})
        if author:
            info["author"] = author.get("content")

        return info

    def _detect_risks(self, text: str, html: str, url: str) -> List[str]:
        """잠재적 보안 위험 감지"""
        risks = []
        text_lower = text.lower()
        url_lower = url.lower()

        if any(keyword in text_lower for keyword in ["verify account", "confirm identity", "update payment", "urgent action required"]):
            risks.append("Potential phishing indicators")

        if "password" in text_lower or "login" in text_lower:
            risks.append("Authentication required - verify legitimacy")

        if any(keyword in text_lower for keyword in ["limited time", "act now", "verify immediately", "confirm now"]):
            risks.append("High-pressure/urgency language detected")

        if "<script" in html and "src=" in html:
            script_count = html.count("<script")
            if script_count > 5:
                risks.append(f"Multiple external scripts detected ({script_count})")

        if url_lower.startswith("http://") and any(keyword in text_lower for keyword in ["password", "payment", "card"]):
            risks.append("Sensitive data handling over insecure HTTP")

        if "<form" in html and "style" in html.lower():
            if "display:none" in html.lower() or "visibility:hidden" in html.lower():
                risks.append("Hidden form elements detected")

        return risks if risks else ["No obvious security risks detected"]

    def _extract_entities(self, text: str) -> Dict[str, List[str]]:
        """텍스트에서 엔티티 추출"""
        import re

        entities = {}

        urls = re.findall(r'https?://[^\s<>"{}|\\^`\[\]]*', text)
        if urls:
            entities["urls"] = list(set(urls))[:10]

        ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)
        if ips:
            entities["ip_addresses"] = list(set(ips))[:10]

        domains = re.findall(r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b', text.lower())
        if domains:
            entities["domains"] = list(set(domains))[:10]

        return entities

    def _extract_keywords(self, text: str) -> List[str]:
        """중요 키워드 추출"""
        stopwords = {'the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for',
                     'of', 'is', 'was', 'are', 'be', 'have', 'has', 'do', 'does', 'did',
                     'this', 'that', 'these', 'those', 'i', 'you', 'he', 'she', 'it', 'we', 'they'}

        words = text.lower().split()
        filtered_words = [w for w in words if len(w) > 4 and w not in stopwords and w.isalpha()]

        from collections import Counter
        word_freq = Counter(filtered_words)

        keywords = [word for word, _ in word_freq.most_common(10)]
        return keywords

    def _generate_summary(self, results: List[Dict], start_url: str) -> Dict[str, Any]:
        """크롤링 결과 종합 분석"""
        if not results:
            return {"status": "no_results"}

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

        for result in results:
            if "potential_risks" in result:
                summary["risks"].update(result["potential_risks"])

            if "entities" in result:
                for entity_type, values in result["entities"].items():
                    if entity_type in summary["all_entities"]:
                        if isinstance(values, list):
                            summary["all_entities"][entity_type].update(values)

            if "key_information" in result:
                if "emails" in result["key_information"]:
                    summary["all_entities"]["emails"].update(result["key_information"]["emails"])
                if "social_media" in result["key_information"]:
                    summary["all_entities"]["social_media"].update(result["key_information"]["social_media"])

            if "keywords" in result:
                summary["top_keywords"].extend(result["keywords"][:3])

        summary["all_entities"]["emails"] = list(summary["all_entities"]["emails"])[:10]
        summary["all_entities"]["urls"] = list(summary["all_entities"]["urls"])[:10]
        summary["all_entities"]["domains"] = list(summary["all_entities"]["domains"])[:10]
        summary["risks"] = list(summary["risks"])

        from collections import Counter
        keyword_counts = Counter(summary["top_keywords"])
        summary["top_keywords"] = [word for word, _ in keyword_counts.most_common(10)]

        if summary["all_entities"]["social_media"]:
            summary["key_findings"].append(f"Found social media links: {list(summary['all_entities']['social_media'].keys())}")
        if summary["all_entities"]["emails"]:
            summary["key_findings"].append(f"Found {len(summary['all_entities']['emails'])} email addresses")
        if len(results) > 1:
            summary["key_findings"].append(f"Crawled {len(results)} related pages")
        if summary["all_entities"]["urls"]:
            summary["key_findings"].append(f"Found {len(summary['all_entities']['urls'])} external URLs")

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
# Client 인스턴스 생성
# ============================================================================

intelx_client = IntelligenceXClient(INTELX_API_KEY)
sherlock_client = SherlockClient()
playwright_client = PlaywrightClient()
vt_client = VTClient(VIRUSTOTAL_API_KEY)

# ============================================================================
# MCP Tools 정의 (@tool 데코레이터 사용)
# ============================================================================


@server.tool()
def search_intelligence_x(term: str, maxresults: int = 100) -> str:
    """
    Intelligence X에서 다크웹 및 유출 데이터를 검색합니다.

    Args:
        term: 검색할 셀렉터 (예: email@example.com)
        maxresults: 최대 결과 수 (기본값: 100)

    Returns:
        JSON 형식의 검색 결과
    """
    try:
        start_time = time.time()
        result = intelx_client.search(term, maxresults=maxresults)
        execution_time = (time.time() - start_time) * 1000

        return json.dumps({
            **result,
            "execution_time_ms": int(execution_time),
        }, indent=2, ensure_ascii=False)
    except Exception as e:
        logger.error(f"Intelligence X 검색 오류: {e}")
        return json.dumps({"error": str(e)}, ensure_ascii=False)


@server.tool()
def search_username_sherlock(username: str, sites: Optional[str] = None, timeout: int = 120) -> str:
    """
    Sherlock을 사용하여 사용자명을 여러 웹사이트에서 검색합니다.

    Args:
        username: 검색할 사용자명 (예: john_doe)
        sites: 검색할 사이트 목록 (쉼표로 구분, 예: 'github,twitter,reddit')
        timeout: 검색 타임아웃 (초, 기본값: 120)

    Returns:
        JSON 형식의 검색 결과
    """
    try:
        start_time = time.time()
        sites_list = None
        if sites:
            sites_list = [s.strip() for s in sites.split(',')]

        result = sherlock_client.search(username, sites=sites_list, timeout=timeout)
        execution_time = (time.time() - start_time) * 1000

        return json.dumps({
            **result,
            "execution_time_ms": int(execution_time),
        }, indent=2, ensure_ascii=False)
    except Exception as e:
        logger.error(f"Sherlock 검색 오류: {e}")
        return json.dumps({"error": str(e)}, ensure_ascii=False)


@server.tool()
async def analyze_url_playwright(
    url: str,
    extract_metadata: bool = True,
    extract_text: bool = True,
    extract_links: bool = True,
    screenshot: bool = False,
    timeout: int = 30
) -> str:
    """
    Playwright를 사용하여 URL을 분석합니다.

    Args:
        url: 분석할 URL
        extract_metadata: 메타데이터 추출 (기본값: true)
        extract_text: 페이지 텍스트 추출 (기본값: true)
        extract_links: 링크 목록 추출 (기본값: true)
        screenshot: 스크린샷 캡처 (기본값: false)
        timeout: 타임아웃 (초, 기본값: 30)

    Returns:
        JSON 형식의 분석 결과
    """
    try:
        start_time = time.time()
        result = await playwright_client.analyze(
            url,
            extract_metadata=extract_metadata,
            extract_text=extract_text,
            extract_links=extract_links,
            screenshot=screenshot,
            timeout=timeout
        )
        execution_time = (time.time() - start_time) * 1000

        return json.dumps({
            **result,
            "execution_time_ms": int(execution_time),
        }, indent=2, ensure_ascii=False)
    except Exception as e:
        logger.error(f"URL 분석 오류: {e}")
        return json.dumps({"error": str(e)}, ensure_ascii=False)


@server.tool()
def check_virustotal_domain(domain: str) -> str:
    """
    VirusTotal에서 도메인의 위협 정보를 확인합니다.

    Args:
        domain: 조회할 도메인

    Returns:
        JSON 형식의 위협 정보
    """
    try:
        start_time = time.time()
        result = vt_client.query_domain(domain)
        execution_time = (time.time() - start_time) * 1000

        return json.dumps({
            **result,
            "execution_time_ms": int(execution_time),
        }, indent=2, ensure_ascii=False)
    except Exception as e:
        logger.error(f"VirusTotal 도메인 조회 오류: {e}")
        return json.dumps({"error": str(e)}, ensure_ascii=False)


@server.tool()
def check_virustotal_ip(ip_address: str) -> str:
    """
    VirusTotal에서 IP 주소의 위협 정보를 확인합니다.

    Args:
        ip_address: 조회할 IP 주소

    Returns:
        JSON 형식의 위협 정보
    """
    try:
        start_time = time.time()
        result = vt_client.query_ip(ip_address)
        execution_time = (time.time() - start_time) * 1000

        return json.dumps({
            **result,
            "execution_time_ms": int(execution_time),
        }, indent=2, ensure_ascii=False)
    except Exception as e:
        logger.error(f"VirusTotal IP 조회 오류: {e}")
        return json.dumps({"error": str(e)}, ensure_ascii=False)


@server.tool()
async def crawl_and_analyze_url(
    url: str,
    max_depth: int = 2,
    max_pages: int = 10,
    url_pattern: Optional[str] = None,
    analyze_content: bool = True,
    timeout: int = 60
) -> str:
    """
    Playwright를 사용하여 URL을 자동으로 크롤링하고 지능형 분석을 수행합니다.

    Args:
        url: 시작할 URL
        max_depth: 크롤링 깊이 (기본값: 2)
        max_pages: 최대 방문 페이지 수 (기본값: 10)
        url_pattern: 크롤링할 URL 패턴 (정규표현식, 선택사항)
        analyze_content: 지능형 콘텐츠 분석 (기본값: true)
        timeout: 전체 크롤링 타임아웃 (초, 기본값: 60)

    Returns:
        JSON 형식의 크롤링 결과
    """
    try:
        start_time = time.time()
        result = await playwright_client.crawl(
            url,
            max_depth=max_depth,
            max_pages=max_pages,
            url_pattern=url_pattern,
            analyze_content=analyze_content,
            timeout=timeout
        )
        execution_time = (time.time() - start_time) * 1000

        return json.dumps({
            **result,
            "execution_time_ms": int(execution_time),
        }, indent=2, ensure_ascii=False)
    except Exception as e:
        logger.error(f"크롤링 오류: {e}")
        return json.dumps({"error": str(e)}, ensure_ascii=False)


# ============================================================================
# 서버 실행
# ============================================================================

if __name__ == "__main__":
    logger.info("=" * 70)
    logger.info("Starting OSINT MCP Server (stdio mode for Claude Desktop)")
    logger.info("=" * 70)
    logger.info(f"DEBUG_MODE: {DEBUG_MODE}")
    logger.info("")
    logger.info("Available Tools:")
    logger.info("  1. search_intelligence_x")
    logger.info("  2. search_username_sherlock")
    logger.info("  3. analyze_url_playwright")
    logger.info("  4. check_virustotal_domain")
    logger.info("  5. check_virustotal_ip")
    logger.info("  6. crawl_and_analyze_url")
    logger.info("=" * 70)

    server.run()
