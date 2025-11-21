"""
OSINT 데이터베이스 관리 모듈
CSV 파일을 사용하여 수집된 OSINT 정보를 저장하고 관리합니다.
"""

import csv
import os
from datetime import datetime
from typing import List, Dict, Optional, Any
import json
from pathlib import Path


class OSINTDatabase:
    """OSINT 데이터를 CSV 파일로 관리하는 클래스"""

    def __init__(self, db_path: str = "db.csv"):
        """
        Args:
            db_path: CSV 데이터베이스 파일 경로
        """
        self.db_path = db_path
        self.fieldnames = [
            'timestamp',          # 수집 시간
            'target',             # 수집 타겟 (이메일, 도메인, 사용자명 등)
            'url',                # 수집된 곳의 URL
            'pdf_path',           # 저장된 PDF 파일 경로
            'summary',            # 정보 요약
            'sensitive_info',     # 중요 정보 (이메일, 전화번호 등 JSON 형식)
            'collection_method',  # 수집 방법 (사용한 MCP 도구)
            'threat_level',       # 위협 수준 (VirusTotal 결과)
            'metadata'            # 추가 메타데이터 (JSON 형식)
        ]
        self._initialize_db()

    def _initialize_db(self):
        """데이터베이스 파일 초기화 (없으면 생성)"""
        if not os.path.exists(self.db_path):
            with open(self.db_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=self.fieldnames)
                writer.writeheader()
            print(f"✅ 데이터베이스 파일 생성: {self.db_path}")

    def add_record(
        self,
        target: str,
        url: str = "",
        pdf_path: str = "",
        summary: str = "",
        sensitive_info: Optional[Dict[str, Any]] = None,
        collection_method: str = "",
        threat_level: str = "unknown",
        metadata: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        새로운 레코드를 데이터베이스에 추가

        Args:
            target: 수집 타겟
            url: 수집된 URL
            pdf_path: PDF 파일 경로
            summary: 정보 요약
            sensitive_info: 중요 정보 딕셔너리
            collection_method: 수집 방법
            threat_level: 위협 수준
            metadata: 추가 메타데이터

        Returns:
            성공 여부
        """
        try:
            record = {
                'timestamp': datetime.now().isoformat(),
                'target': target,
                'url': url,
                'pdf_path': pdf_path,
                'summary': summary,
                'sensitive_info': json.dumps(sensitive_info or {}, ensure_ascii=False),
                'collection_method': collection_method,
                'threat_level': threat_level,
                'metadata': json.dumps(metadata or {}, ensure_ascii=False)
            }

            with open(self.db_path, 'a', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=self.fieldnames)
                writer.writerow(record)

            print(f"✅ 레코드 추가: {target} ({collection_method})")
            return True

        except Exception as e:
            print(f"❌ 레코드 추가 실패: {e}")
            return False

    def get_all_records(self) -> List[Dict[str, Any]]:
        """모든 레코드 조회"""
        records = []

        if not os.path.exists(self.db_path):
            return records

        try:
            with open(self.db_path, 'r', newline='', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    # JSON 필드 파싱
                    row['sensitive_info'] = json.loads(row.get('sensitive_info', '{}'))
                    row['metadata'] = json.loads(row.get('metadata', '{}'))
                    records.append(row)
        except Exception as e:
            print(f"❌ 레코드 조회 실패: {e}")

        return records

    def search_records(
        self,
        target: Optional[str] = None,
        collection_method: Optional[str] = None,
        threat_level: Optional[str] = None,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        조건에 맞는 레코드 검색

        Args:
            target: 타겟 검색어 (부분 일치)
            collection_method: 수집 방법
            threat_level: 위협 수준
            start_date: 시작 날짜 (ISO format)
            end_date: 종료 날짜 (ISO format)

        Returns:
            검색된 레코드 리스트
        """
        all_records = self.get_all_records()
        filtered = []

        for record in all_records:
            # 타겟 필터
            if target and target.lower() not in record['target'].lower():
                continue

            # 수집 방법 필터
            if collection_method and collection_method != record['collection_method']:
                continue

            # 위협 수준 필터
            if threat_level and threat_level != record['threat_level']:
                continue

            # 날짜 필터
            record_date = record['timestamp']
            if start_date and record_date < start_date:
                continue
            if end_date and record_date > end_date:
                continue

            filtered.append(record)

        return filtered

    def get_statistics(self) -> Dict[str, Any]:
        """데이터베이스 통계 정보 반환"""
        records = self.get_all_records()

        if not records:
            return {
                'total_records': 0,
                'collection_methods': {},
                'threat_levels': {},
                'latest_collection': None
            }

        # 수집 방법별 통계
        methods = {}
        for record in records:
            method = record['collection_method']
            methods[method] = methods.get(method, 0) + 1

        # 위협 수준별 통계
        threats = {}
        for record in records:
            threat = record['threat_level']
            threats[threat] = threats.get(threat, 0) + 1

        # 최근 수집 시간
        latest = max(records, key=lambda x: x['timestamp'])['timestamp']

        return {
            'total_records': len(records),
            'collection_methods': methods,
            'threat_levels': threats,
            'latest_collection': latest
        }

    def delete_record(self, timestamp: str) -> bool:
        """
        특정 레코드 삭제 (timestamp 기준)

        Args:
            timestamp: 삭제할 레코드의 timestamp

        Returns:
            성공 여부
        """
        try:
            records = self.get_all_records()
            filtered = [r for r in records if r['timestamp'] != timestamp]

            if len(records) == len(filtered):
                print(f"❌ 해당 timestamp의 레코드를 찾을 수 없습니다: {timestamp}")
                return False

            # 파일 다시 쓰기
            with open(self.db_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=self.fieldnames)
                writer.writeheader()
                for record in filtered:
                    # JSON 필드 다시 문자열로 변환
                    record['sensitive_info'] = json.dumps(record['sensitive_info'], ensure_ascii=False)
                    record['metadata'] = json.dumps(record['metadata'], ensure_ascii=False)
                    writer.writerow(record)

            print(f"✅ 레코드 삭제 완료: {timestamp}")
            return True

        except Exception as e:
            print(f"❌ 레코드 삭제 실패: {e}")
            return False

    def export_to_json(self, output_path: str = "db_export.json") -> bool:
        """
        데이터베이스를 JSON 파일로 내보내기

        Args:
            output_path: 출력 JSON 파일 경로

        Returns:
            성공 여부
        """
        try:
            records = self.get_all_records()
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(records, f, ensure_ascii=False, indent=2)

            print(f"✅ JSON 내보내기 완료: {output_path}")
            return True

        except Exception as e:
            print(f"❌ JSON 내보내기 실패: {e}")
            return False


# 편의를 위한 전역 인스턴스
db = OSINTDatabase()


if __name__ == "__main__":
    # 테스트 코드
    print("=== OSINT 데이터베이스 테스트 ===\n")

    # 샘플 데이터 추가
    db.add_record(
        target="test@example.com",
        url="https://example.com",
        pdf_path="./pdfs/example_com.pdf",
        summary="테스트 웹사이트 분석",
        sensitive_info={
            "emails": ["test@example.com", "contact@example.com"],
            "phones": ["+82-10-1234-5678"]
        },
        collection_method="analyze_url_playwright",
        threat_level="safe",
        metadata={"page_title": "Example Domain"}
    )

    # 통계 출력
    stats = db.get_statistics()
    print(f"\n📊 통계:")
    print(f"  - 총 레코드 수: {stats['total_records']}")
    print(f"  - 수집 방법별: {stats['collection_methods']}")
    print(f"  - 위협 수준별: {stats['threat_levels']}")
    print(f"  - 최근 수집: {stats['latest_collection']}")

    # 모든 레코드 출력
    print(f"\n📋 모든 레코드:")
    for record in db.get_all_records():
        print(f"  - {record['timestamp']} | {record['target']} | {record['collection_method']}")
