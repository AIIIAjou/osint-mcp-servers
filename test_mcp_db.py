"""
MCP 도구 DB 저장 테스트
실제 MCP 도구가 호출될 때 DB 저장이 제대로 되는지 확인
"""

import asyncio
import sys
import os

# 현재 디렉토리를 Python 경로에 추가
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from db_manager import OSINTDatabase
from pdf_generator import PDFGenerator
from enrichment import InfoEnrichment


async def simulate_mcp_analyze_url():
    """
    analyze_url_playwright MCP 도구를 시뮬레이션
    """
    print("=" * 70)
    print("🧪 MCP 도구 DB 저장 테스트")
    print("=" * 70)
    print()

    # 초기화
    db = OSINTDatabase("db.csv")
    pdf_gen = PDFGenerator("./pdfs")
    enricher = InfoEnrichment()

    test_url = "https://example.com"

    print(f"📊 테스트 URL: {test_url}")
    print("-" * 70)
    print()

    # 1. Playwright 분석 시뮬레이션
    print("1️⃣ Playwright 분석 시뮬레이션...")
    playwright_result = {
        "metadata": {
            "title": "Example Domain",
            "description": "Example Domain for testing"
        },
        "entities": {
            "emails": ["test@example.com", "admin@example.com"],
            "phones": ["+1-555-0100"],
            "social_media": ["https://twitter.com/example"]
        },
        "text": "Example Domain\nThis domain is for use in illustrative examples...",
        "links": ["https://www.iana.org/domains/example"]
    }
    print("✅ Playwright 분석 완료")
    print()

    # 2. PDF 생성
    print("2️⃣ PDF 생성...")
    try:
        pdf_path = await pdf_gen.url_to_pdf(test_url)
        print(f"✅ PDF 생성 성공: {pdf_path}")
    except Exception as e:
        print(f"❌ PDF 생성 실패: {e}")
        pdf_path = ""
    print()

    # 3. Enrichment 정보 수집
    print("3️⃣ Enrichment 정보 수집...")
    try:
        enrichment_data = enricher.enrich_url(test_url)
        print("✅ Enrichment 수집 완료")
    except Exception as e:
        print(f"❌ Enrichment 실패: {e}")
        enrichment_data = {}
    print()

    # 4. 요약 생성 (server_stdio.py와 동일한 로직)
    print("4️⃣ 요약 생성...")
    summary = f"URL: {test_url}"
    if playwright_result.get("metadata", {}).get("title"):
        summary += f" | 제목: {playwright_result['metadata']['title']}"

    # 기술 스택 추가
    if enrichment_data and enrichment_data.get('technologies', {}).get('success'):
        tech_data = enrichment_data['technologies']['data']
        all_techs = []
        for techs in tech_data.values():
            all_techs.extend(techs)
        if all_techs:
            summary += f" | 기술: {', '.join(all_techs[:3])}"

    print(f"  요약: {summary}")
    print()

    # 5. sensitive_info 구성 (server_stdio.py와 동일한 로직)
    print("5️⃣ 중요 정보 추출...")
    sensitive_info = {}

    # 기본 엔티티
    if "entities" in playwright_result:
        entities = playwright_result["entities"]
        if "emails" in entities:
            sensitive_info["emails"] = entities["emails"]
        if "phones" in entities:
            sensitive_info["phones"] = entities["phones"]
        if "social_media" in entities:
            sensitive_info["social_media"] = entities["social_media"]

    # Enrichment 정보 추가
    if enrichment_data:
        # WHOIS
        if enrichment_data.get('whois', {}).get('success'):
            whois_data = enrichment_data['whois']['data']
            sensitive_info["whois"] = {
                "registrar": whois_data.get('registrar'),
                "creation_date": whois_data.get('creation_date'),
                "expiration_date": whois_data.get('expiration_date'),
                "registrant_org": whois_data.get('registrant_org'),
                "registrant_country": whois_data.get('registrant_country'),
                "name_servers": whois_data.get('name_servers', [])
            }

        # DNS
        if enrichment_data.get('dns', {}).get('success'):
            dns_data = enrichment_data['dns']['data']
            sensitive_info["dns"] = {
                "ipv4": dns_data.get('A', []),
                "ipv6": dns_data.get('AAAA', []),
                "mx_records": dns_data.get('MX', []),
                "txt_records": dns_data.get('TXT', [])
            }

        # SSL
        if enrichment_data.get('ssl', {}).get('success'):
            ssl_data = enrichment_data['ssl']['data']
            sensitive_info["ssl"] = {
                "issuer": ssl_data.get('issuer', {}).get('organizationName'),
                "subject": ssl_data.get('subject', {}),
                "not_before": ssl_data.get('not_before'),
                "not_after": ssl_data.get('not_after'),
                "protocol": ssl_data.get('protocol')
            }

        # 기술 스택
        if enrichment_data.get('technologies', {}).get('success'):
            tech_data = enrichment_data['technologies']['data']
            sensitive_info["technologies"] = tech_data

        # 보안 정보
        if enrichment_data.get('headers', {}).get('success'):
            headers_data = enrichment_data['headers']['data']
            sensitive_info["security"] = {
                "server": headers_data.get('server'),
                "powered_by": headers_data.get('powered_by'),
                "security_headers": headers_data.get('security_headers', {})
            }

    print(f"  추출된 키: {list(sensitive_info.keys())}")
    print()

    # 6. 메타데이터 구성
    print("6️⃣ 메타데이터 구성...")
    extended_metadata = {
        **playwright_result,
        "enrichment": enrichment_data
    }
    print(f"  메타데이터 크기: {len(str(extended_metadata))} bytes")
    print()

    # 7. DB에 저장
    print("7️⃣ DB에 저장...")
    try:
        success = db.add_record(
            target=test_url,
            url=test_url,
            pdf_path=pdf_path,
            summary=summary,
            sensitive_info=sensitive_info,
            collection_method="analyze_url_playwright",
            threat_level="unknown",
            metadata=extended_metadata
        )

        if success:
            print("✅ DB 저장 성공!")
        else:
            print("❌ DB 저장 실패!")
    except Exception as e:
        print(f"❌ DB 저장 오류: {e}")
        import traceback
        traceback.print_exc()
    print()

    # 8. 저장 결과 확인
    print("=" * 70)
    print("📊 저장 결과 확인")
    print("=" * 70)

    stats = db.get_statistics()
    print(f"총 레코드 수: {stats['total_records']}")
    print()

    # 방금 저장한 레코드 조회
    records = db.search_records(collection_method="analyze_url_playwright")
    print(f"analyze_url_playwright 레코드: {len(records)}개")
    print()

    if records:
        latest = records[-1]
        print("최신 레코드:")
        print(f"  - 시간: {latest['timestamp']}")
        print(f"  - 타겟: {latest['target']}")
        print(f"  - PDF: {latest['pdf_path'] or 'N/A'}")
        print(f"  - 요약: {latest['summary']}")
        print(f"  - 중요 정보 키: {list(latest['sensitive_info'].keys())}")
        print()

        # sensitive_info 상세
        if latest['sensitive_info']:
            print("중요 정보 상세:")
            for key, value in latest['sensitive_info'].items():
                if isinstance(value, dict):
                    print(f"  - {key}: {len(value)} 항목")
                elif isinstance(value, list):
                    print(f"  - {key}: {len(value)}개")
                else:
                    print(f"  - {key}: {value}")

    print()
    print("=" * 70)
    print("✅ 테스트 완료!")
    print("=" * 70)
    print()
    print("💡 다음 단계:")
    print("1. 웹 대시보드 시작: python web_interface_enhanced.py")
    print("2. Claude Desktop에서 MCP 도구 사용")
    print("3. db.csv 파일 확인")
    print()


if __name__ == "__main__":
    asyncio.run(simulate_mcp_analyze_url())
