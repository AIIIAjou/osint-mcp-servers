"""
OSINT 데이터베이스 데모
실제 사용 시나리오를 시뮬레이션합니다.
"""

from db_manager import OSINTDatabase
from datetime import datetime
import json

# 데이터베이스 초기화
db = OSINTDatabase("db.csv")

print("=" * 70)
print("🔍 OSINT 데이터베이스 사용 데모")
print("=" * 70)
print()

# 시나리오 1: Sherlock으로 사용자명 검색
print("📝 시나리오 1: 'minseolee' 사용자명 검색")
print("-" * 70)

# Sherlock 검색 결과 시뮬레이션
sherlock_result = db.add_record(
    target="minseolee",
    url="https://github.com/minseolee",
    pdf_path="",
    summary="Sherlock 사용자명 검색: minseolee | 발견된 사이트: GitHub, Twitter, Instagram",
    sensitive_info={
        "found_sites": ["GitHub", "Twitter", "Instagram"],
        "urls": [
            "https://github.com/minseolee",
            "https://twitter.com/minseolee",
            "https://instagram.com/minseolee"
        ]
    },
    collection_method="search_username_sherlock",
    threat_level="unknown",
    metadata={
        "total_sites_checked": 500,
        "found_accounts": 3
    }
)

if sherlock_result:
    print("✅ Sherlock 검색 결과가 DB에 저장되었습니다!")
print()

# 시나리오 2: GitHub 프로필 분석
print("📝 시나리오 2: GitHub 프로필 분석")
print("-" * 70)

github_result = db.add_record(
    target="minseolee",
    url="https://github.com/minseolee",
    pdf_path="./pdfs/github_minseolee_20250121.pdf",
    summary="GitHub 프로필 분석: minseolee | 공개 레포지토리: 15개",
    sensitive_info={
        "emails": ["minseolee@example.com"],
        "social_media": ["https://twitter.com/minseolee"],
        "repositories": ["osint-tools", "web-crawler", "data-analyzer"]
    },
    collection_method="analyze_url_playwright",
    threat_level="safe",
    metadata={
        "profile": {
            "name": "Minseo Lee",
            "bio": "Security Researcher & Developer",
            "location": "Seoul, South Korea",
            "public_repos": 15,
            "followers": 234,
            "following": 89
        },
        "page_title": "minseolee - GitHub"
    }
)

if github_result:
    print("✅ GitHub 프로필 분석 결과가 DB에 저장되었습니다!")
    print("📄 PDF 스냅샷이 생성되었습니다!")
print()

# 시나리오 3: 도메인 위협 정보 확인
print("📝 시나리오 3: minseolee.com 도메인 위협 정보 확인")
print("-" * 70)

vt_result = db.add_record(
    target="minseolee.com",
    url="https://minseolee.com",
    pdf_path="",
    summary="VirusTotal 도메인 조회: minseolee.com | 악성: 0, 의심: 0",
    sensitive_info={},
    collection_method="check_virustotal_domain",
    threat_level="safe",
    metadata={
        "stats": {
            "malicious": 0,
            "suspicious": 0,
            "undetected": 85,
            "harmless": 10
        },
        "reputation": 95,
        "categories": ["personal", "blog"]
    }
)

if vt_result:
    print("✅ VirusTotal 위협 정보가 DB에 저장되었습니다!")
print()

# 시나리오 4: 웹사이트 크롤링
print("📝 시나리오 4: minseolee.com 웹사이트 크롤링")
print("-" * 70)

crawl_result = db.add_record(
    target="minseolee.com",
    url="https://minseolee.com",
    pdf_path="./pdfs/minseolee_com_20250121.pdf",
    summary="URL 크롤링: minseolee.com | 방문 페이지: 5개",
    sensitive_info={
        "emails": ["contact@minseolee.com", "minseolee@gmail.com"],
        "phones": ["+82-10-1234-5678"],
        "social_media": [
            "https://github.com/minseolee",
            "https://twitter.com/minseolee",
            "https://linkedin.com/in/minseolee"
        ]
    },
    collection_method="crawl_and_analyze_url",
    threat_level="safe",
    metadata={
        "summary": {
            "total_pages": 5,
            "total_links": 42,
            "crawl_depth": 2
        },
        "pages": [
            {"url": "https://minseolee.com", "title": "Home"},
            {"url": "https://minseolee.com/about", "title": "About"},
            {"url": "https://minseolee.com/projects", "title": "Projects"},
            {"url": "https://minseolee.com/blog", "title": "Blog"},
            {"url": "https://minseolee.com/contact", "title": "Contact"}
        ]
    }
)

if crawl_result:
    print("✅ 크롤링 결과가 DB에 저장되었습니다!")
    print("📄 PDF 스냅샷이 생성되었습니다!")
print()

# 현재 데이터베이스 통계
print("=" * 70)
print("📊 현재 데이터베이스 통계")
print("=" * 70)

stats = db.get_statistics()
print(f"총 레코드 수: {stats['total_records']}")
print()

print("수집 방법별 통계:")
for method, count in stats['collection_methods'].items():
    print(f"  • {method}: {count}개")
print()

print("위협 수준별 통계:")
for threat, count in stats['threat_levels'].items():
    print(f"  • {threat}: {count}개")
print()

if stats['latest_collection']:
    print(f"최근 수집 시간: {stats['latest_collection']}")
print()

# minseolee 관련 모든 레코드 검색
print("=" * 70)
print("🔎 'minseolee' 관련 모든 레코드 검색")
print("=" * 70)

minseolee_records = db.search_records(target="minseolee")
print(f"발견된 레코드: {len(minseolee_records)}개")
print()

for i, record in enumerate(minseolee_records, 1):
    print(f"[{i}] {record['timestamp']}")
    print(f"    타겟: {record['target']}")
    print(f"    URL: {record['url']}")
    print(f"    수집 방법: {record['collection_method']}")
    print(f"    위협 수준: {record['threat_level']}")
    print(f"    요약: {record['summary']}")

    # 중요 정보 출력
    if record['sensitive_info']:
        print(f"    중요 정보:")
        for key, value in record['sensitive_info'].items():
            if value:
                print(f"      - {key}: {value}")
    print()

# JSON 내보내기
print("=" * 70)
print("📤 JSON 내보내기")
print("=" * 70)

export_success = db.export_to_json("minseolee_report.json")
if export_success:
    print("✅ minseolee_report.json 파일로 내보내기 완료!")
print()

# 사용 방법 안내
print("=" * 70)
print("🌐 웹 대시보드에서 확인하기")
print("=" * 70)
print()
print("1. 웹 대시보드 시작:")
print("   $ python web_interface.py")
print()
print("2. 브라우저에서 접속:")
print("   http://localhost:8000")
print()
print("3. 대시보드에서 할 수 있는 것:")
print("   • 실시간 통계 확인")
print("   • 'minseolee'로 검색")
print("   • 각 레코드의 상세 정보 조회")
print("   • PDF 다운로드")
print("   • 중요 정보 확인 (이메일, 전화번호, SNS)")
print("   • JSON 내보내기")
print()
print("=" * 70)
print("✅ 데모 완료!")
print("=" * 70)
