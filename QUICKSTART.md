# ⚡ 빠른 시작 가이드

## 5분 안에 시작하기

### 1️⃣ Ollama 설치 및 실행

```bash
# macOS
brew install ollama

# 모델 다운로드
ollama pull llama3.2

# Ollama 서버 시작
ollama serve
```

### 2️⃣ 프로젝트 설정

```bash
# 패키지 설치
pip install -r requirements.txt
python -m playwright install chromium
```

### 3️⃣ 웹 대시보드 시작

```bash
./start_enhanced.sh
```

### 4️⃣ 브라우저 열기

```
http://localhost:8000
```

---

## 🎯 세 가지 요구사항 완료!

### ✅ 1. PDF 버그 수정

**문제**: PDF가 저장되지 않거나 경로가 잘못됨

**해결**:
- Playwright context manager 수정
- 절대 경로로 저장
- `pdfs/` 폴더에 제대로 저장됨

**확인**:
```bash
python pdf_generator.py
ls -lh pdfs/
```

### ✅ 2. DB 데이터 풍부화

**문제**: DB에 정보가 너무 적음

**해결**:
- **WHOIS 정보** 추가 (등록기관, 만료일 등)
- **DNS 레코드** 추가 (IP, MX, TXT)
- **SSL 인증서** 추가 (발급자, 유효기간)
- **기술 스택** 추가 (React, WordPress 등)
- **보안 헤더** 추가 (6종 체크)
- 모두 `sensitive_info`에 저장됨!

**확인**:
```python
from db_manager import OSINTDatabase
db = OSINTDatabase("db.csv")
records = db.get_all_records()
print(records[0]['sensitive_info'])  # 풍부한 정보!
```

### ✅ 3. 웹으로 LLM 질답

**문제**: 웹에서 LLM과 대화하는 방법?

**해결**:
- Ollama API 통합
- 웹 대시보드에 채팅 패널 추가
- 실시간 대화 가능

**사용법**:
1. Ollama 실행: `ollama serve`
2. 웹 열기: `http://localhost:8000`
3. 우측 채팅 패널에서 대화!

---

## 📊 수집되는 정보 (요약)

| 카테고리 | 정보 |
|---------|------|
| **기본** | 제목, 설명, 텍스트, 링크 |
| **연락처** | 이메일, 전화번호, SNS (9개 플랫폼) |
| **WHOIS** | 등록기관, 생성일, 만료일, 등록자 |
| **DNS** | IPv4/IPv6, MX, TXT |
| **SSL** | 발급자, 유효기간, 프로토콜 |
| **보안** | 서버 정보, 보안 헤더 6종 |
| **기술** | 프레임워크, CMS, 분석 도구, CDN |
| **PDF** | 웹페이지 전체 스냅샷 |

---

## 🚀 사용 예시

### Claude Desktop에서

```
"example.com을 조사해줘"
```

**자동으로**:
1. URL 분석 (Playwright)
2. WHOIS 조회
3. DNS 조회
4. SSL 인증서 확인
5. 기술 스택 탐지
6. PDF 생성
7. DB 저장

### 웹 대시보드에서

1. **통계 확인**: 실시간 대시보드
2. **데이터 조회**: 모든 수집 정보 테이블
3. **상세 보기**: WHOIS, DNS, SSL, 기술 스택 등
4. **LLM 채팅**: 우측 패널에서 질문
5. **PDF 다운로드**: 클릭 한 번

---

## 🔧 쉘 코드 예시

### 웹 대시보드 + Ollama 한 번에 시작

```bash
#!/bin/bash
# start_all.sh

# Ollama 시작 (백그라운드)
ollama serve &
OLLAMA_PID=$!

# 5초 대기
sleep 5

# 웹 대시보드 시작
./start_enhanced.sh

# 종료 시 Ollama도 종료
trap "kill $OLLAMA_PID" EXIT
```

### 특정 타겟 조사 자동화

```bash
#!/bin/bash
# investigate.sh <target>

TARGET=$1

if [ -z "$TARGET" ]; then
    echo "사용법: ./investigate.sh <타겟>"
    exit 1
fi

echo "🔍 $TARGET 조사 중..."

# Claude CLI가 있다면
echo "$TARGET을 조사해줘. Sherlock으로 계정 찾고, URL 분석하고, 위협 정보 확인해줘." | claude

# 결과 확인
python -c "
from db_manager import OSINTDatabase
db = OSINTDatabase('db.csv')
results = db.search_records(target='$TARGET')
print(f'발견된 레코드: {len(results)}개')
for r in results:
    print(f'- {r[\"collection_method\"]}: {r[\"summary\"]}')
"
```

### PDF 일괄 생성

```bash
#!/bin/bash
# batch_pdf.sh

URLS=(
    "https://example.com"
    "https://github.com"
    "https://twitter.com"
)

for URL in "${URLS[@]}"; do
    echo "📄 PDF 생성: $URL"
    python -c "
from pdf_generator import generate_pdf_from_url
pdf_path = generate_pdf_from_url('$URL')
print(f'✅ 생성 완료: {pdf_path}')
"
done
```

---

## 💡 자주 묻는 질문 (FAQ)

### Q: Ollama 없이도 사용할 수 있나요?
**A**: 네! Ollama는 웹 채팅 기능에만 필요합니다. Claude Desktop + MCP는 별도로 작동합니다.

### Q: PDF가 저장되지 않아요
**A**: `python -m playwright install chromium` 실행하세요.

### Q: DB에 정보가 적어요
**A**: 최신 `server_stdio.py`를 사용하고 있는지 확인하세요. `enricher.enrich_url()`이 호출되어야 합니다.

### Q: 웹 채팅이 작동하지 않아요
**A**: `ollama serve`가 실행 중인지 확인하세요.

### Q: 어떤 모델을 사용해야 하나요?
**A**:
- 빠른 응답: `llama3.2` (추천)
- 정확한 답변: `llama3.1:70b`
- 한국어: `qwen2.5:14b`

---

## 📞 도움이 필요하신가요?

자세한 가이드는 [USAGE_GUIDE.md](USAGE_GUIDE.md)를 참조하세요!

**Happy OSINT! 🕵️**
