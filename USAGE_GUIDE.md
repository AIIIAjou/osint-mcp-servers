# 🚀 Enhanced OSINT Dashboard 사용 가이드

## 📋 목차
1. [시스템 요구사항](#시스템-요구사항)
2. [설치 및 설정](#설치-및-설정)
3. [사용 방법](#사용-방법)
4. [웹 채팅으로 질답하기](#웹-채팅으로-질답하기)
5. [수집되는 정보](#수집되는-정보)
6. [문제 해결](#문제-해결)

---

## 시스템 요구사항

### 필수
- **Python 3.12+**
- **Ollama** (LLM 채팅 기능용)
- **Git**

### 선택사항
- **Claude Desktop** (MCP 통합용)

---

## 설치 및 설정

### 1️⃣ 기본 설치

```bash
# 1. 저장소 클론
cd /path/to/your/workspace
git clone https://github.com/your-repo/osint-mcp-servers.git
cd osint-mcp-servers

# 2. 가상환경 생성 및 활성화
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# 3. 패키지 설치
pip install -r requirements.txt

# 4. Playwright 브라우저 드라이버 설치
python -m playwright install chromium
```

### 2️⃣ Ollama 설치 (LLM 채팅용)

#### macOS
```bash
# Homebrew로 설치
brew install ollama

# 또는 공식 사이트에서 다운로드
# https://ollama.com/download
```

#### Linux
```bash
curl -fsSL https://ollama.com/install.sh | sh
```

#### Windows
https://ollama.com/download 에서 다운로드

### 3️⃣ Ollama 모델 설치

```bash
# Ollama 서버 시작
ollama serve

# 다른 터미널에서 모델 다운로드
ollama pull llama3.2        # 추천: 빠르고 가벼움
ollama pull llama3.1:70b    # 선택: 더 강력함 (큰 용량)
ollama pull qwen2.5:14b     # 선택: 한국어 성능 우수
```

### 4️⃣ 환경 변수 설정

`.env` 파일 생성:

```bash
# OSINT API 키 (선택사항)
INTELX_API_KEY=your_intelligence_x_api_key
VIRUSTOTAL_API_KEY=your_virustotal_api_key

# Ollama 설정
OLLAMA_API_URL=http://localhost:11434
OLLAMA_MODEL=llama3.2

# 디버그 모드
DEBUG_MODE=false
```

---

## 사용 방법

### 방법 1: Enhanced 웹 대시보드 (권장)

#### 시작하기

```bash
# 간단한 시작
./start_enhanced.sh

# 또는 직접 실행
source venv/bin/activate
python web_interface_enhanced.py
```

#### 웹 브라우저에서 접속

```
http://localhost:8000
```

#### 기능

1. **실시간 대시보드**
   - 총 레코드 수
   - 위협 수준별 통계
   - Ollama 연결 상태

2. **OSINT 데이터 조회**
   - 모든 수집된 정보 테이블 형식
   - 상세 정보 모달 (WHOIS, DNS, SSL, 기술 스택 등)
   - PDF 다운로드
   - 레코드 삭제

3. **LLM 채팅 (우측 패널)**
   - Ollama와 실시간 대화
   - OSINT 분석 질문
   - 자동 응답

### 방법 2: Claude Desktop에서 MCP 사용

#### Claude Desktop 설정

`claude_desktop_config.json` 파일 수정:

**macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
**Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "osint": {
      "command": "python",
      "args": ["/절대/경로/osint-mcp-servers/server_stdio.py"],
      "env": {
        "PYTHONPATH": "/절대/경로/osint-mcp-servers/venv/lib/python3.12/site-packages"
      }
    }
  }
}
```

#### Claude Desktop 재시작

설정 후 Claude Desktop을 재시작하세요.

#### 사용 예시

Claude Desktop에서:

```
"minseolee"라는 사용자명을 조사해줘.
Sherlock으로 어떤 사이트에 계정이 있는지 찾고,
발견된 사이트들을 분석하고,
관련 도메인의 위협 정보도 확인해줘.
```

Claude가 자동으로:
1. `search_username_sherlock` 실행
2. 발견된 URL들을 `analyze_url_playwright`로 분석
3. `check_virustotal_domain`으로 위협 정보 확인
4. **자동으로 DB에 저장**
5. **자동으로 PDF 생성**
6. 결과를 종합하여 보고

---

## 웹 채팅으로 질답하기

### 🎯 3번 요구사항: 웹으로 LLM과 대화하기

#### 준비사항

1. **Ollama가 실행 중이어야 합니다**

```bash
# Ollama 실행 확인
curl http://localhost:11434/api/tags

# 실행되지 않았다면
ollama serve
```

2. **Enhanced 웹 대시보드 시작**

```bash
./start_enhanced.sh
```

3. **브라우저 접속**

```
http://localhost:8000
```

#### 사용법

웹 대시보드 우측에 **💬 LLM 채팅** 패널이 있습니다.

##### 예시 대화

**질문 1: 기본 질문**
```
사용자: OSINT가 무엇인가요?
LLM: OSINT는 Open Source Intelligence의 약자로, 공개적으로
     이용 가능한 정보원을 통해 정보를 수집하고 분석하는
     인텔리전스 활동입니다...
```

**질문 2: 데이터 분석**
```
사용자: 데이터베이스에 저장된 정보를 요약해줘
LLM: (데이터베이스 정보는 직접 조회하지 못하지만,
     OSINT 분석 방법을 설명할 수 있습니다...)
```

**질문 3: OSINT 도구 사용법**
```
사용자: Sherlock으로 사용자명을 검색하는 방법을 알려줘
LLM: Sherlock은 여러 소셜 미디어 플랫폼에서 사용자명을
     검색하는 도구입니다...
```

#### 제한사항

현재 웹 채팅은 **일반적인 LLM 대화**만 가능합니다.
MCP 도구를 직접 호출하지는 않습니다.

**MCP 도구를 사용하려면 Claude Desktop을 사용하세요!**

---

## 수집되는 정보

### 📊 자동으로 수집되는 정보

#### 1. 기본 정보
- 페이지 제목, 설명, 메타데이터
- 텍스트 콘텐츠
- 링크 목록

#### 2. 연락처 정보
- ✉️ 이메일 주소
- 📱 전화번호
- 🔗 소셜 미디어 링크 (9개 플랫폼)

#### 3. WHOIS 정보 (NEW!)
- 등록기관
- 생성일 / 만료일
- 등록자 정보
- 네임서버 목록

#### 4. DNS 레코드 (NEW!)
- A 레코드 (IPv4)
- AAAA 레코드 (IPv6)
- MX 레코드 (메일 서버)
- TXT 레코드

#### 5. SSL/TLS 인증서 (NEW!)
- 발급자 정보
- 유효 기간
- 프로토콜 버전 (TLS 1.3 등)

#### 6. HTTP 헤더 (NEW!)
- 서버 정보
- Powered-By
- 보안 헤더 6종 체크
  - Strict-Transport-Security
  - Content-Security-Policy
  - X-Frame-Options
  - X-Content-Type-Options
  - X-XSS-Protection
  - Referrer-Policy

#### 7. 기술 스택 탐지 (NEW!)
- **프레임워크**: React, Vue.js, Angular, Next.js 등
- **CMS**: WordPress, Drupal, Joomla, Ghost 등
- **분석 도구**: Google Analytics, GTM, Mixpanel 등
- **CDN**: Cloudflare, AWS CloudFront, Fastly 등
- **JavaScript 라이브러리**: jQuery, Bootstrap, D3.js 등

#### 8. PDF 스냅샷 (NEW!)
- 웹페이지 전체를 PDF로 저장
- 절대 경로로 저장되어 웹에서 다운로드 가능

### 📁 저장 위치

```
osint-mcp-servers/
├── db.csv                    # 모든 정보가 여기 저장됨
├── pdfs/                     # PDF 스냅샷
│   ├── 20251121_203253_c984d06a.pdf
│   └── ...
└── sessions/                 # Playwright 세션
```

### 🔍 DB 조회 방법

#### 방법 1: 웹 대시보드 (권장)

```
http://localhost:8000
```

- 실시간 통계
- 테이블 형식 조회
- 상세 정보 모달

#### 방법 2: Python 스크립트

```python
from db_manager import OSINTDatabase

db = OSINTDatabase("db.csv")

# 모든 레코드
records = db.get_all_records()

# 검색
results = db.search_records(target="minseolee")

# 통계
stats = db.get_statistics()
print(stats)
```

#### 방법 3: CSV 직접 열기

Excel, Google Sheets, 또는 텍스트 에디터로 `db.csv` 파일 열기

---

## 문제 해결

### 🐛 PDF가 저장되지 않아요

**증상**: `pdfs/` 폴더가 비어있음

**해결책**:

```bash
# Playwright 드라이버 재설치
python -m playwright install chromium

# 권한 확인
chmod -R 755 pdfs/

# 테스트
python pdf_generator.py
```

### 🐛 DB가 빈약해요 (정보가 적음)

**증상**: DB에 기본 정보만 있고 WHOIS, DNS, SSL 등이 없음

**해결책**:

1. **최신 버전 확인**
   ```bash
   git pull
   ```

2. **enrichment 모듈 테스트**
   ```bash
   python enrichment.py
   ```

3. **server_stdio.py가 최신인지 확인**
   - `enricher.enrich_url()` 호출하는지 확인
   - `sensitive_info`에 enrichment 데이터 포함되는지 확인

### 🐛 Ollama가 연결되지 않아요

**증상**: 웹 채팅에서 "Ollama: Offline" 표시

**해결책**:

```bash
# 1. Ollama 실행 확인
curl http://localhost:11434/api/tags

# 2. 실행되지 않았다면
ollama serve

# 3. 다른 포트 사용 중이라면 .env 수정
# OLLAMA_API_URL=http://localhost:다른포트
```

### 🐛 웹 대시보드가 열리지 않아요

**증상**: `http://localhost:8000` 접속 안됨

**해결책**:

```bash
# 1. 포트 사용 중인 프로세스 확인
lsof -i :8000

# 2. 프로세스 종료
kill -9 PID번호

# 3. 다시 시작
./start_enhanced.sh
```

### 🐛 모듈을 찾을 수 없어요 (ImportError)

**증상**: `ModuleNotFoundError: No module named 'xxx'`

**해결책**:

```bash
# 가상환경 활성화 확인
source venv/bin/activate

# 패키지 재설치
pip install -r requirements.txt

# Playwright 재설치
python -m playwright install chromium
```

---

## 🎓 완전한 사용 시나리오

### 시나리오: "johndoe" 사용자 조사

#### 1단계: Ollama + 웹 대시보드 시작

```bash
# 터미널 1: Ollama 시작
ollama serve

# 터미널 2: 웹 대시보드 시작
./start_enhanced.sh
```

#### 2단계: Claude Desktop에서 조사 요청

```
"johndoe"라는 사용자명을 조사해줘.
1. Sherlock으로 소셜 미디어 계정 찾기
2. 발견된 GitHub 프로필 분석
3. johndoe.com 도메인 위협 정보 확인
4. 웹사이트 크롤링해서 연락처 정보 수집
```

#### 3단계: Claude가 자동으로 작업

- `search_username_sherlock` → GitHub, Twitter, Instagram 발견
- `analyze_url_playwright` → GitHub 프로필 분석 + PDF 생성
- `check_virustotal_domain` → 도메인 안전성 확인
- `crawl_and_analyze_url` → 웹사이트 크롤링 + 연락처 추출

**모든 결과가 자동으로 `db.csv`에 저장됨!**

#### 4단계: 웹 대시보드에서 확인

```
http://localhost:8000
```

- 📊 통계: 4개 레코드 추가됨
- 🔍 검색: "johndoe" 입력
- 📄 상세: 각 레코드 클릭하여 모든 정보 확인
  - WHOIS 정보
  - DNS 레코드
  - SSL 인증서
  - 기술 스택
  - 연락처 정보
- 📥 PDF: 다운로드하여 증거 보존

#### 5단계: 웹 채팅으로 분석 질문

웹 대시보드 우측 채팅 패널에서:

```
사용자: johndoe의 온라인 활동을 분석해서 어떤 특징이 있는지 알려줘
LLM: [분석 제공...]

사용자: GitHub 프로필에서 보안 취약점을 찾는 방법은?
LLM: [보안 분석 방법 설명...]
```

---

## ⚡ 빠른 참조

### 주요 명령어

```bash
# 웹 대시보드 시작
./start_enhanced.sh

# Ollama 시작
ollama serve

# PDF 테스트
python pdf_generator.py

# Enrichment 테스트
python enrichment.py

# 데모 실행
python demo.py
```

### 주요 URL

- 웹 대시보드: `http://localhost:8000`
- API 문서: `http://localhost:8000/docs`
- Ollama API: `http://localhost:11434`

### 주요 파일

- DB: `db.csv`
- PDF: `pdfs/`
- 설정: `.env`
- 로그: 터미널 출력

---

## 📚 추가 리소스

- [Ollama 공식 문서](https://github.com/ollama/ollama)
- [FastAPI 문서](https://fastapi.tiangolo.com/)
- [Playwright 문서](https://playwright.dev/python/)

---

## 💡 팁

1. **정기적인 백업**: `db.csv`와 `pdfs/` 폴더를 정기적으로 백업하세요
2. **모델 선택**: 더 빠른 응답을 원하면 `llama3.2`, 더 정확한 답변을 원하면 `llama3.1:70b`
3. **보안**: API 키는 절대 공개 저장소에 커밋하지 마세요
4. **성능**: 대량의 URL을 크롤링할 때는 `max_pages`를 제한하세요

---

**Made with ❤️ for OSINT automation**
