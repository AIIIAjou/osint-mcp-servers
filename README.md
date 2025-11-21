# 🔍 Enhanced OSINT Dashboard

AI를 활용한 인텔리전스 위협 탐지 자동화 프로젝트

LLM이 MCP(Model Context Protocol)를 통해 OSINT(Open Source Intelligence) 작업을 수행하고, 수집된 정보를 자동으로 데이터베이스화하여 웹 대시보드로 시각화합니다.

## ✨ 새로운 기능

- ✅ **풍부한 데이터 수집**: WHOIS, DNS, SSL, 기술 스택, 보안 헤더 등
- ✅ **웹 LLM 채팅**: Ollama 통합으로 웹에서 바로 질문 가능
- ✅ **향상된 UI**: 깔끔한 디자인, 스크롤 없는 레이아웃
- ✅ **PDF 스냅샷**: 모든 웹페이지를 PDF로 저장 (증거 보존)
- ✅ **자동 DB 저장**: 모든 수집 정보가 자동으로 저장됨

## 🚀 주요 기능

### 1. OSINT 수집 도구 (MCP 서버)

- **Intelligence X**: 다크웹 및 유출 데이터 검색
- **Sherlock**: 500+ 웹사이트에서 사용자명 검색
- **Playwright**: 웹페이지 분석 및 크롤링
  - 단일 URL 분석
  - 재귀적 크롤링 및 분석
  - 동적 웹페이지 상호작용
  - 자동 탐색 (AI 기반)
- **VirusTotal**: 도메인 및 IP 위협 정보 확인

### 2. 데이터베이스 자동화

수집된 모든 정보가 자동으로 CSV 데이터베이스에 저장됩니다:

- **필드**:
  - `timestamp`: 수집 시간
  - `target`: 수집 타겟
  - `url`: 수집된 URL
  - `pdf_path`: 웹페이지 PDF 스냅샷 경로
  - `summary`: 정보 요약
  - `sensitive_info`: 중요 정보 (이메일, 전화번호, SNS 링크 등)
  - `collection_method`: 사용된 수집 방법
  - `threat_level`: 위협 수준 (safe/suspicious/malicious/unknown)
  - `metadata`: 추가 메타데이터

### 3. 웹 대시보드

FastAPI 기반 웹 인터페이스로 수집된 데이터를 시각화:

- 📊 실시간 통계 대시보드
- 🔍 검색 및 필터링 기능
- 📄 상세 정보 조회
- 📥 PDF 다운로드
- 🗑️ 레코드 삭제
- 📤 JSON 내보내기

## 📦 설치

### 요구사항

- Python 3.12+
- Node.js (선택사항)

### 패키지 설치

```bash
pip install -r requirements.txt
playwright install chromium
```

### 환경 설정

`.env` 파일을 생성하고 API 키를 설정:

```env
INTELX_API_KEY=your_intelligence_x_api_key
VIRUSTOTAL_API_KEY=your_virustotal_api_key
SHODAN_API_KEY=your_shodan_api_key
HARVESTER_API_KEY=your_harvester_api_key
DEBUG_MODE=false
```

## ⚡ 빠른 시작

### 1. Ollama 설치 및 실행

```bash
# macOS
brew install ollama

# 모델 다운로드
ollama pull llama3.2

# Ollama 서버 시작
ollama serve
```

### 2. 프로젝트 설정

```bash
# 패키지 설치
pip install -r requirements.txt
python -m playwright install chromium

# 테스트 데이터 생성 (선택사항)
python test_integration.py
```

### 3. 웹 대시보드 시작

```bash
./start_enhanced.sh
```

### 4. 브라우저 열기

```
http://localhost:8000
```

## 🎯 사용 방법

### 방법 1: Enhanced 웹 대시보드 (권장)

```bash
./start_enhanced.sh
```

- 📊 실시간 대시보드
- 💬 LLM 채팅 (Ollama)
- 🔍 데이터 검색 및 필터링
- 📄 PDF 다운로드

### 방법 2: Claude Desktop (MCP)

**Claude Desktop 설정 (`claude_desktop_config.json`)**:

```json
{
  "mcpServers": {
    "osint": {
      "command": "python",
      "args": ["/절대경로/osint-mcp-servers/server_stdio.py"]
    }
  }
}
```

Claude Desktop에서:
```
"example.com을 조사해줘"
```

→ 자동으로 DB에 저장됨!

### 3. Claude에게 OSINT 작업 요청

예시:

```
example.com 도메인을 분석하고 VirusTotal로 위협 정보도 확인해줘
```

```
github.com에서 "johndoe" 사용자명을 검색해줘
```

```
https://target-website.com를 크롤링하고 연락처 정보를 수집해줘
```

모든 결과는 자동으로 `db.csv`에 저장되고, 웹페이지는 `./pdfs/` 디렉토리에 PDF로 저장됩니다.

## 📂 프로젝트 구조

```
osint-mcp-servers/
├── server_stdio.py          # MCP 서버 (OSINT 도구)
├── db_manager.py            # CSV 데이터베이스 관리
├── pdf_generator.py         # PDF 생성 모듈
├── web_interface.py         # 웹 대시보드
├── db.csv                   # 데이터베이스 파일
├── pdfs/                    # PDF 스냅샷 저장 폴더
├── sessions/                # Playwright 세션 저장 폴더
├── requirements.txt         # Python 의존성
└── README.md
```

## 🛠️ 모듈별 설명

### `db_manager.py`

CSV 데이터베이스를 관리하는 모듈:

- `OSINTDatabase`: 데이터베이스 클래스
  - `add_record()`: 레코드 추가
  - `get_all_records()`: 모든 레코드 조회
  - `search_records()`: 조건부 검색
  - `delete_record()`: 레코드 삭제
  - `get_statistics()`: 통계 정보
  - `export_to_json()`: JSON 내보내기

### `pdf_generator.py`

Playwright를 사용한 PDF 생성:

- `PDFGenerator`: PDF 생성 클래스
  - `url_to_pdf()`: URL을 PDF로 변환
  - `html_to_pdf()`: HTML을 PDF로 변환

동기 래퍼 함수도 제공:
- `generate_pdf_from_url()`
- `generate_pdf_from_html()`

### `web_interface.py`

FastAPI 기반 웹 대시보드:

**API 엔드포인트**:
- `GET /`: 메인 대시보드 페이지
- `GET /api/statistics`: 통계 정보
- `GET /api/records`: 모든 레코드 조회
- `DELETE /api/records/{timestamp}`: 레코드 삭제
- `GET /api/pdf`: PDF 다운로드
- `GET /api/export`: JSON 내보내기

## 📊 웹 대시보드 기능

### 통계 대시보드
- 총 레코드 수
- 위협 수준별 집계 (안전/의심/악성)
- 최근 수집 시간

### 검색 및 필터링
- 타겟 검색 (텍스트 검색)
- 수집 방법별 필터
- 위협 수준별 필터

### 레코드 관리
- 상세 정보 조회 (모달)
- PDF 다운로드
- 레코드 삭제
- 자동 새로고침 (30초)

## 🔒 보안 고려사항

1. **API 키 보안**: `.env` 파일을 사용하여 API 키를 안전하게 관리
2. **중요 정보 저장**: 수집된 이메일, 전화번호 등은 별도 필드에 저장
3. **위협 정보**: VirusTotal 결과를 기반으로 위협 수준 자동 분류
4. **PDF 스냅샷**: 웹페이지의 시점 증거 보존

## 🧪 테스트

### 데이터베이스 모듈 테스트

```bash
python db_manager.py
```

샘플 데이터가 추가되고 통계가 출력됩니다.

### PDF 생성 테스트

```bash
python pdf_generator.py
```

example.com의 PDF가 생성됩니다.

## 📝 개발 로그

### 최근 업데이트
- ✅ CSV 데이터베이스 자동화
- ✅ PDF 스냅샷 생성
- ✅ MCP 서버 통합
- ✅ 웹 대시보드 구현
- ✅ 실시간 통계 및 필터링

### 향후 계획
- [ ] 엑셀 내보내기
- [ ] 이메일 알림
- [ ] 스케줄링 기능
- [ ] 고급 검색 (정규표현식)
- [ ] 데이터 시각화 차트

## 🤝 기여

이슈와 PR을 환영합니다!

## 📄 라이센스

MIT License

## 📧 문의

프로젝트 관련 문의사항이 있으시면 이슈를 등록해주세요.

---

**Made with ❤️ for OSINT automation**
