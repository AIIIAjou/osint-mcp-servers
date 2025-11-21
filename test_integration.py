"""
통합 테스트 - DB 저장 및 PDF 생성 확인
"""

import asyncio
from db_manager import OSINTDatabase
from pdf_generator import PDFGenerator
from enrichment import InfoEnrichment

async def test_integration():
    print("=" * 70)
    print("🧪 통합 테스트 시작")
    print("=" * 70)
    print()

    # 1. DB 테스트
    print("1️⃣ DB 저장 테스트")
    print("-" * 70)

    db = OSINTDatabase("db.csv")

    test_url = "https://example.com"

    # 기본 정보 추가
    db.add_record(
        target=test_url,
        url=test_url,
        pdf_path="",  # PDF는 나중에 추가
        summary=f"통합 테스트: {test_url}",
        sensitive_info={
            "emails": ["test@example.com"],
            "test": True
        },
        collection_method="test_integration",
        threat_level="safe",
        metadata={"test": True}
    )

    # 확인
    records = db.get_all_records()
    print(f"✅ DB 저장 완료! 총 {len(records)}개 레코드")
    print()

    # 2. PDF 테스트
    print("2️⃣ PDF 생성 테스트")
    print("-" * 70)

    pdf_gen = PDFGenerator("./pdfs")

    try:
        pdf_path = await pdf_gen.url_to_pdf(test_url)
        print(f"✅ PDF 생성 완료: {pdf_path}")

        # DB 업데이트 (PDF 경로 추가)
        # 참고: 실제로는 새 레코드를 추가하는 방식
        db.add_record(
            target=test_url,
            url=test_url,
            pdf_path=pdf_path,
            summary=f"PDF 포함 테스트: {test_url}",
            sensitive_info={"pdf_generated": True},
            collection_method="test_integration_with_pdf",
            threat_level="safe",
            metadata={"pdf_test": True}
        )
        print("✅ PDF 경로가 DB에 저장됨")

    except Exception as e:
        print(f"❌ PDF 생성 실패: {e}")

    print()

    # 3. Enrichment 테스트
    print("3️⃣ Enrichment 테스트")
    print("-" * 70)

    enricher = InfoEnrichment()

    try:
        enrichment_data = enricher.enrich_url(test_url)

        # WHOIS 정보
        if enrichment_data.get('whois', {}).get('success'):
            print("✅ WHOIS 정보 수집 성공")
        else:
            print(f"⚠️  WHOIS 정보 수집 실패: {enrichment_data.get('whois', {}).get('error')}")

        # DNS 정보
        if enrichment_data.get('dns', {}).get('success'):
            dns_data = enrichment_data['dns']['data']
            print(f"✅ DNS 정보 수집 성공 (IPv4: {len(dns_data.get('A', []))}개)")
        else:
            print("⚠️  DNS 정보 수집 실패")

        # SSL 정보
        if enrichment_data.get('ssl', {}).get('success'):
            print("✅ SSL 정보 수집 성공")
        else:
            print("⚠️  SSL 정보 수집 실패")

        # 기술 스택
        if enrichment_data.get('technologies', {}).get('success'):
            print("✅ 기술 스택 탐지 성공")
        else:
            print("⚠️  기술 스택 탐지 실패")

        # DB에 enrichment 정보 포함하여 저장
        sensitive_info = {
            "test": "enrichment_integration"
        }

        if enrichment_data.get('dns', {}).get('success'):
            dns_data = enrichment_data['dns']['data']
            sensitive_info["dns"] = {
                "ipv4": dns_data.get('A', [])
            }

        if enrichment_data.get('ssl', {}).get('success'):
            ssl_data = enrichment_data['ssl']['data']
            sensitive_info["ssl"] = {
                "issuer": ssl_data.get('issuer', {}).get('organizationName'),
                "protocol": ssl_data.get('protocol')
            }

        db.add_record(
            target=test_url,
            url=test_url,
            pdf_path="",
            summary=f"Enrichment 포함 테스트: {test_url}",
            sensitive_info=sensitive_info,
            collection_method="test_enrichment",
            threat_level="safe",
            metadata=enrichment_data
        )
        print("✅ Enrichment 정보가 DB에 저장됨")

    except Exception as e:
        print(f"❌ Enrichment 실패: {e}")

    print()

    # 4. 최종 확인
    print("=" * 70)
    print("📊 최종 결과")
    print("=" * 70)

    stats = db.get_statistics()
    print(f"총 레코드 수: {stats['total_records']}")
    print()

    print("수집 방법별:")
    for method, count in stats['collection_methods'].items():
        print(f"  • {method}: {count}개")
    print()

    # 레코드 상세
    print("레코드 상세:")
    records = db.get_all_records()
    for i, record in enumerate(records[-3:], 1):  # 최근 3개만
        print(f"\n[{i}] {record['timestamp']}")
        print(f"    타겟: {record['target']}")
        print(f"    수집 방법: {record['collection_method']}")
        print(f"    PDF: {record['pdf_path'] or 'N/A'}")
        print(f"    중요 정보: {list(record['sensitive_info'].keys())}")

    print()
    print("=" * 70)
    print("✅ 통합 테스트 완료!")
    print("=" * 70)
    print()
    print("💡 다음 단계:")
    print("1. 웹 대시보드에서 확인: python web_interface_enhanced.py")
    print("2. 브라우저: http://localhost:8000")
    print()

if __name__ == "__main__":
    asyncio.run(test_integration())
