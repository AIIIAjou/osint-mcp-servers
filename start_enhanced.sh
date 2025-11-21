#!/bin/bash

# Enhanced OSINT Dashboard 시작 스크립트

echo "=========================================="
echo "🚀 Enhanced OSINT Dashboard 시작"
echo "=========================================="
echo ""

# Ollama 실행 여부 확인
echo "🔍 Ollama 서버 확인 중..."
if curl -s http://localhost:11434/api/tags > /dev/null 2>&1; then
    echo "✅ Ollama 서버가 실행 중입니다."
else
    echo "⚠️  Ollama 서버가 실행되지 않았습니다."
    echo ""
    echo "Ollama를 시작하시겠습니까? (y/n)"
    read -p "> " start_ollama

    if [ "$start_ollama" = "y" ]; then
        echo "📦 Ollama 시작 중..."
        # macOS의 경우
        if [ "$(uname)" = "Darwin" ]; then
            open -a Ollama 2>/dev/null || echo "Ollama 앱을 찾을 수 없습니다. 수동으로 시작해주세요."
        else
            # Linux의 경우
            ollama serve &
        fi
        echo "⏳ Ollama 서버 시작 대기 중 (5초)..."
        sleep 5
    else
        echo "⚠️  Ollama 없이 계속합니다. (채팅 기능이 비활성화됩니다)"
    fi
fi

echo ""

# 필요한 디렉토리 생성
echo "📁 디렉토리 확인..."
mkdir -p pdfs
mkdir -p sessions

# Python 가상환경 확인
if [ ! -d "venv" ]; then
    echo "⚠️  가상환경이 없습니다. 생성 중..."
    python3 -m venv venv
    source venv/bin/activate
    echo "📦 패키지 설치 중..."
    pip install -r requirements.txt
    playwright install chromium
else
    source venv/bin/activate
fi

# Playwright 드라이버 확인
if [ ! -d "$HOME/Library/Caches/ms-playwright/chromium-1187" ] && [ ! -d "$HOME/.cache/ms-playwright/chromium-1187" ]; then
    echo "📦 Playwright Chromium 설치 중..."
    python -m playwright install chromium
fi

# 웹 대시보드 시작
echo ""
echo "=========================================="
echo "🌐 Enhanced OSINT Dashboard 시작 중..."
echo "=========================================="
echo ""
echo "📊 웹 대시보드: http://localhost:8000"
echo "📖 API 문서: http://localhost:8000/docs"
echo "💬 LLM 채팅: 웹 인터페이스에서 사용 가능"
echo ""
echo "⚙️  설정:"
echo "  - Ollama URL: http://localhost:11434"
echo "  - 기본 모델: qwen3:8b"
echo ""
echo "종료하려면 Ctrl+C를 누르세요."
echo "=========================================="
echo ""

python web_interface_enhanced.py
