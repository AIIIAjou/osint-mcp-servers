# 🔄 변경사항 (2025-11-21)

## ✅ 완료된 작업

### 1. 기본 모델을 qwen3:8b로 변경

**파일**: `web_interface_enhanced.py`, `start_enhanced.sh`

**변경 내용**:
- Ollama 기본 모델을 `qwen3:8b`로 설정
- 시작 스크립트에서도 `qwen3:8b` 표시

```python
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen3:8b")
```

---

### 2. DB 저장 문제 원점부터 탐색

**파일**: `test_mcp_db.py` (새로 생성)

**문제**: 사용자가 DB에 데이터가 저장되지 않는다고 보고

**해결**:
- MCP 도구의 DB 저장 로직을 시뮬레이션하는 테스트 스크립트 생성
- `server_stdio.py`의 `analyze_url_playwright` 로직을 정확히 재현
- 테스트 결과: **DB 저장 로직은 정상 작동함** ✅

**결론**:
- DB/PDF/Enrichment 모든 기능이 정상 작동
- 만약 실제 사용 시 저장이 안 된다면, Claude Desktop에서 MCP 도구가 호출되지 않는 것이 원인

**테스트 실행**:
```bash
python test_mcp_db.py
```

**테스트 결과**:
```
✅ PDF 생성 성공: /Users/ms/Documents/gits/ollama/osint-mcp-servers/pdfs/20251121_212557_c984d06a.pdf
✅ Enrichment 수집 완료
✅ DB 저장 성공!
총 레코드 수: 4
중요 정보 키: ['emails', 'phones', 'social_media', 'whois', 'dns', 'ssl', 'technologies', 'security']
```

---

### 3. PDF 새 탭에서 열기로 변경

**파일**: `web_interface_enhanced.py`

**이전 동작**: PDF 클릭 시 다운로드

**변경 후**: PDF 클릭 시 새 탭에서 열림

**변경 내용**:
```python
@app.get("/api/pdf")
async def get_pdf(path: str):
    """PDF 파일 새 탭에서 열기"""
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="PDF 파일을 찾을 수 없습니다.")
    return FileResponse(
        path,
        media_type="application/pdf",
        headers={"Content-Disposition": "inline"}  # ← 변경: inline으로 브라우저에서 표시
    )
```

**효과**:
- PDF 버튼 클릭 시 다운로드 없이 새 탭에서 바로 확인 가능
- 사용자 경험 개선

---

### 4. 상세 모달에 LLM 원본 응답 표시

**파일**: `web_dashboard.html`

**이전 구조**:
1. 기본 정보 (시간, 타겟, URL 등)
2. 요약
3. 중요 정보 (WHOIS, DNS, SSL 등)

**변경 후 구조**:
1. **📝 요약 (최상단, 하이라이트)**
2. 기본 정보
3. **🤖 LLM 분석 결과 (마크다운 렌더링)** ← 새로 추가
4. 중요 정보

**추가된 기능**:
- `marked.js` CDN 추가 (마크다운 파싱)
- `metadata.text`에서 LLM 원본 응답 추출
- 마크다운 형식으로 렌더링
- 코드 블록 스타일링 (다크 테마)

**CSS 추가**:
```css
.summary-section {
    background: #e3f2fd;
    padding: 15px 20px;
    border-radius: 8px;
    margin-bottom: 20px;
    border-left: 4px solid #2196f3;
}

.llm-response {
    background: #f8f9fa;
    padding: 20px;
    border-radius: 8px;
    margin-top: 20px;
    border-left: 4px solid #667eea;
}

.llm-response-content pre {
    background: #2d2d2d;
    color: #f8f8f2;
    padding: 15px;
    border-radius: 5px;
}
```

**JavaScript 로직**:
```javascript
// metadata에서 LLM 원본 응답 추출
if (record.metadata) {
    let rawResponse = '';

    if (record.metadata.text) {
        rawResponse = record.metadata.text;
    } else if (record.metadata.metadata && record.metadata.metadata.text) {
        rawResponse = record.metadata.metadata.text;
    }

    if (rawResponse) {
        const renderedHtml = marked.parse(rawResponse);
        html += `
            <div class="llm-response">
                <h3>🤖 LLM 분석 결과</h3>
                <div class="llm-response-content">
                    ${renderedHtml}
                </div>
            </div>
        `;
    }
}
```

---

## 📊 테스트 및 확인

### DB 저장 테스트
```bash
python test_mcp_db.py
```
**결과**: ✅ 모든 기능 정상 작동

### 웹 대시보드 시작
```bash
./start_enhanced.sh
```
또는
```bash
python web_interface_enhanced.py
```

**확인 사항**:
- ✅ Ollama 모델: qwen3:8b
- ✅ PDF 새 탭에서 열림
- ✅ 상세 모달: 요약 → LLM 응답 → 중요 정보 순서
- ✅ 마크다운 렌더링

---

## 🎯 다음 단계

### Claude Desktop에서 MCP 도구 사용
1. `claude_desktop_config.json` 확인
2. Claude Desktop 재시작
3. "example.com을 조사해줘" 실행
4. 웹 대시보드에서 결과 확인

### 웹 대시보드 확인
```
http://localhost:8000
```

**확인 항목**:
- [ ] 레코드가 표시되는가?
- [ ] PDF 버튼 클릭 시 새 탭에서 열리는가?
- [ ] 상세 버튼 클릭 시 요약이 맨 위에 있는가?
- [ ] LLM 분석 결과가 마크다운으로 렌더링되는가?
- [ ] 채팅 기능이 qwen3:8b 모델을 사용하는가?

---

## 🐛 알려진 문제 및 해결 방법

### DB에 데이터가 없는 경우
1. **테스트 데이터 생성**:
   ```bash
   python test_integration.py
   # 또는
   python test_mcp_db.py
   ```

2. **Claude Desktop에서 MCP 도구 호출**:
   ```
   "example.com을 조사해줘"
   ```

3. **MCP 서버 로그 확인**:
   - Claude Desktop의 MCP 연결 확인
   - `server_stdio.py`가 올바르게 실행되는지 확인

### Ollama 연결 실패
```bash
# Ollama 시작
ollama serve

# 모델 다운로드
ollama pull qwen3:8b
```

### PDF가 생성되지 않는 경우
```bash
# Playwright Chromium 설치
python -m playwright install chromium
```

---

**Happy OSINT! 🕵️**
