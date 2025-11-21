# 🔧 문제 해결 가이드

## 3가지 주요 문제 해결 완료! ✅

### 1️⃣ DB 저장이 안돼요 (db.csv가 비어있음)

**원인**: MCP 도구를 실제로 호출하지 않았거나, 테스트 데이터를 생성하지 않음

**해결책**:

#### A. 테스트 데이터 생성

```bash
python test_integration.py
```

이 스크립트는:
- ✅ DB에 샘플 데이터 저장
- ✅ PDF 생성 테스트
- ✅ Enrichment 정보 수집 테스트

실행 후 `db.csv`와 `pdfs/` 폴더에 데이터가 생성됩니다!

#### B. Claude Desktop에서 MCP 도구 호출

```
"example.com을 조사해줘"
```

Claude가 자동으로:
1. `analyze_url_playwright` 실행
2. DB에 저장
3. PDF 생성

#### C. 웹 대시보드에서 확인

```bash
python web_interface_enhanced.py
# 브라우저: http://localhost:8000
```

---

### 2️⃣ Ollama API 404 에러

**원인**: 잘못된 API 엔드포인트 사용 (`/api/generate` → `/api/chat`)

**해결책**: ✅ 이미 수정 완료!

현재 버전은 올바른 엔드포인트를 사용합니다:
- 채팅: `/api/chat`
- 응답 구조: `message.content`

#### Ollama가 실행되지 않았다면:

```bash
# Ollama 시작
ollama serve

# 모델이 없다면
ollama pull llama3.2
```

#### 연결 확인:

```bash
curl http://localhost:11434/api/tags
```

정상이면:
```json
{"models":[{"name":"llama3.2",...}]}
```

---

### 3️⃣ 웹 UI가 못생겼어요 (높이 초과, 스크롤 발생)

**원인**: 고정 높이 없이 `min-height: 100vh` 사용

**해결책**: ✅ 이미 수정 완료!

현재 버전:
- ✅ `height: 100vh` (고정 높이)
- ✅ `overflow: hidden` (스크롤 제거)
- ✅ Flex 레이아웃 (컨텐츠 자동 조정)
- ✅ 반응형 디자인 (모바일/태블릿)

#### 최신 버전 사용 확인:

```bash
git pull origin main
```

#### 캐시 삭제 후 재시작:

```bash
# 브라우저에서 Ctrl+Shift+R (강제 새로고침)
# 또는 시크릿 모드로 열기
```

---

## 기타 문제 해결

### PDF가 생성되지 않아요

**증상**: `pdfs/` 폴더가 비어있음

**해결책**:

```bash
# Playwright 드라이버 설치
python -m playwright install chromium

# 테스트
python pdf_generator.py

# 성공하면:
# ✅ PDF 생성 완료: /path/to/pdfs/...pdf
```

### Enrichment 정보가 없어요

**증상**: DB에 WHOIS, DNS, SSL 정보가 없음

**원인**: 최신 `server_stdio.py`를 사용하지 않음

**해결책**:

```bash
# 최신 버전 확인
git pull

# enrichment 모듈 테스트
python enrichment.py

# server_stdio.py에 enricher가 통합되었는지 확인
grep "enricher.enrich_url" server_stdio.py
```

### 웹 대시보드가 열리지 않아요

**증상**: `http://localhost:8000` 접속 안됨

**해결책**:

```bash
# 포트 사용 중인 프로세스 확인
lsof -i :8000

# 프로세스 종료
kill -9 <PID>

# 다시 시작
./start_enhanced.sh
```

### 모듈을 찾을 수 없어요 (ImportError)

**증상**: `ModuleNotFoundError: No module named 'xxx'`

**해결책**:

```bash
# 가상환경 활성화 확인
source venv/bin/activate

# 패키지 재설치
pip install -r requirements.txt
```

### Ollama가 너무 느려요

**해결책**:

```bash
# 더 작은 모델 사용
ollama pull llama3.2  # 빠름

# 대신:
# ollama pull llama3.1:70b  # 느림
```

### LLM 채팅이 작동하지 않아요

**체크리스트**:

1. ✅ Ollama가 실행 중인가?
   ```bash
   curl http://localhost:11434/api/tags
   ```

2. ✅ 모델이 설치되었는가?
   ```bash
   ollama list
   ```

3. ✅ 웹 대시보드에서 "Ollama: Connected" 표시되는가?

4. ✅ 브라우저 콘솔에 에러가 없는가?
   (F12 → Console 탭)

---

## 완전한 재설치

모든 것을 처음부터 다시 시작하려면:

```bash
# 1. 가상환경 삭제
rm -rf venv

# 2. 가상환경 재생성
python3 -m venv venv
source venv/bin/activate

# 3. 패키지 재설치
pip install --upgrade pip
pip install -r requirements.txt
python -m playwright install chromium

# 4. Ollama 재설치 (필요시)
brew reinstall ollama
ollama pull llama3.2

# 5. 테스트
python test_integration.py
./start_enhanced.sh
```

---

## 도움이 필요하신가요?

- 📖 [USAGE_GUIDE.md](USAGE_GUIDE.md) - 완전한 사용 가이드
- ⚡ [QUICKSTART.md](QUICKSTART.md) - 빠른 시작 가이드
- 🐛 [GitHub Issues](https://github.com/your-repo/issues) - 버그 보고

---

**Happy OSINT! 🕵️**
