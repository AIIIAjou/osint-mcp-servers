"""
OSINT 데이터베이스 웹 인터페이스
FastAPI를 사용하여 수집된 OSINT 정보를 시각화하고 관리합니다.
"""

import os
from typing import Optional, List
from datetime import datetime
from fastapi import FastAPI, Query, HTTPException
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

from db_manager import OSINTDatabase


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
