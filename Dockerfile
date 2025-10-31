# 멀티스테이지 빌드 - 빌드 스테이지
FROM python:3.11-slim AS builder

WORKDIR /build

# 시스템 의존성 설치
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Python 의존성 설치
COPY requirements.txt .
RUN pip install --user --no-cache-dir -r requirements.txt

# 최종 스테이지
FROM python:3.11-slim

WORKDIR /app

# 빌드 스테이지에서 설치된 패키지 복사
COPY --from=builder /root/.local /root/.local

# PATH 설정
ENV PATH=/root/.local/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# 헬스체크를 위한 curl 설치
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# 애플리케이션 코드 복사
COPY server.py .

# 포트 노출
EXPOSE 8000

# 헬스체크
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# 비루트 사용자 생성 (보안)
RUN useradd -m -u 1000 appuser && chown -R appuser:appuser /app
USER appuser

# 서버 실행
CMD ["python", "server.py"]