"""
PDF 생성 모듈
Playwright를 사용하여 웹페이지를 PDF로 저장합니다.
"""

import asyncio
from playwright.async_api import async_playwright, Browser, Page
from pathlib import Path
from datetime import datetime
from typing import Optional
import os
import hashlib


class PDFGenerator:
    """웹페이지를 PDF로 변환하는 클래스"""

    def __init__(self, output_dir: str = "./pdfs"):
        """
        Args:
            output_dir: PDF 파일을 저장할 디렉토리
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.browser: Optional[Browser] = None

    async def _get_browser(self) -> Browser:
        """브라우저 인스턴스 가져오기 (재사용)"""
        if self.browser is None:
            playwright = await async_playwright().start()
            self.browser = await playwright.chromium.launch(headless=True)
        return self.browser

    def _generate_filename(self, url: str, prefix: str = "") -> str:
        """
        URL을 기반으로 고유한 파일명 생성

        Args:
            url: 웹페이지 URL
            prefix: 파일명 접두사

        Returns:
            생성된 파일명
        """
        # URL 해시 생성 (고유성 보장)
        url_hash = hashlib.md5(url.encode()).hexdigest()[:8]

        # 타임스탬프
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # 파일명 조합
        if prefix:
            filename = f"{prefix}_{timestamp}_{url_hash}.pdf"
        else:
            filename = f"{timestamp}_{url_hash}.pdf"

        return filename

    async def url_to_pdf(
        self,
        url: str,
        filename: Optional[str] = None,
        wait_for_selector: Optional[str] = None,
        wait_timeout: int = 30000
    ) -> str:
        """
        URL을 PDF로 변환

        Args:
            url: 변환할 웹페이지 URL
            filename: 저장할 파일명 (None이면 자동 생성)
            wait_for_selector: 대기할 CSS 셀렉터
            wait_timeout: 대기 시간 (밀리초)

        Returns:
            생성된 PDF 파일의 경로
        """
        try:
            browser = await self._get_browser()
            page = await browser.new_page()

            # 페이지 로드
            await page.goto(url, wait_until="networkidle", timeout=wait_timeout)

            # 특정 요소 대기 (선택적)
            if wait_for_selector:
                try:
                    await page.wait_for_selector(wait_for_selector, timeout=wait_timeout)
                except Exception as e:
                    print(f"⚠️  셀렉터 대기 실패: {e}")

            # 파일명 생성
            if filename is None:
                filename = self._generate_filename(url)

            # 전체 경로
            pdf_path = self.output_dir / filename

            # PDF 생성
            await page.pdf(
                path=str(pdf_path),
                format="A4",
                print_background=True,
                margin={
                    "top": "1cm",
                    "right": "1cm",
                    "bottom": "1cm",
                    "left": "1cm"
                }
            )

            await page.close()

            print(f"✅ PDF 생성 완료: {pdf_path}")
            return str(pdf_path)

        except Exception as e:
            print(f"❌ PDF 생성 실패: {e}")
            raise

    async def html_to_pdf(
        self,
        html_content: str,
        filename: Optional[str] = None
    ) -> str:
        """
        HTML 콘텐츠를 PDF로 변환

        Args:
            html_content: HTML 문자열
            filename: 저장할 파일명 (None이면 자동 생성)

        Returns:
            생성된 PDF 파일의 경로
        """
        try:
            browser = await self._get_browser()
            page = await browser.new_page()

            # HTML 콘텐츠 설정
            await page.set_content(html_content)

            # 파일명 생성
            if filename is None:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"html_{timestamp}.pdf"

            # 전체 경로
            pdf_path = self.output_dir / filename

            # PDF 생성
            await page.pdf(
                path=str(pdf_path),
                format="A4",
                print_background=True,
                margin={
                    "top": "1cm",
                    "right": "1cm",
                    "bottom": "1cm",
                    "left": "1cm"
                }
            )

            await page.close()

            print(f"✅ PDF 생성 완료: {pdf_path}")
            return str(pdf_path)

        except Exception as e:
            print(f"❌ PDF 생성 실패: {e}")
            raise

    async def close(self):
        """브라우저 종료"""
        if self.browser:
            await self.browser.close()
            self.browser = None


# 동기 래퍼 함수 (편의를 위한)
def generate_pdf_from_url(
    url: str,
    filename: Optional[str] = None,
    output_dir: str = "./pdfs",
    wait_for_selector: Optional[str] = None
) -> str:
    """
    URL을 PDF로 변환 (동기 함수)

    Args:
        url: 변환할 웹페이지 URL
        filename: 저장할 파일명
        output_dir: 출력 디렉토리
        wait_for_selector: 대기할 CSS 셀렉터

    Returns:
        생성된 PDF 파일의 경로
    """
    async def _generate():
        generator = PDFGenerator(output_dir)
        try:
            pdf_path = await generator.url_to_pdf(url, filename, wait_for_selector)
            return pdf_path
        finally:
            await generator.close()

    return asyncio.run(_generate())


def generate_pdf_from_html(
    html_content: str,
    filename: Optional[str] = None,
    output_dir: str = "./pdfs"
) -> str:
    """
    HTML 콘텐츠를 PDF로 변환 (동기 함수)

    Args:
        html_content: HTML 문자열
        filename: 저장할 파일명
        output_dir: 출력 디렉토리

    Returns:
        생성된 PDF 파일의 경로
    """
    async def _generate():
        generator = PDFGenerator(output_dir)
        try:
            pdf_path = await generator.html_to_pdf(html_content, filename)
            return pdf_path
        finally:
            await generator.close()

    return asyncio.run(_generate())


if __name__ == "__main__":
    # 테스트 코드
    print("=== PDF 생성 테스트 ===\n")

    # URL을 PDF로 변환
    test_url = "https://example.com"
    pdf_path = generate_pdf_from_url(test_url)
    print(f"📄 생성된 PDF: {pdf_path}")

    # HTML을 PDF로 변환
    test_html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>테스트 페이지</title>
        <style>
            body { font-family: Arial; padding: 20px; }
            h1 { color: #333; }
        </style>
    </head>
    <body>
        <h1>OSINT 수집 보고서</h1>
        <p>이것은 테스트 HTML 콘텐츠입니다.</p>
    </body>
    </html>
    """
    html_pdf_path = generate_pdf_from_html(test_html, "test_report.pdf")
    print(f"📄 생성된 HTML PDF: {html_pdf_path}")
