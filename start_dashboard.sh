#!/bin/bash

# OSINT Dashboard 시작 스크립트

echo "=========================================="
echo "🚀 OSINT Dashboard 시작"
echo "=========================================="
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

# 웹 대시보드 시작
echo ""
echo "🌐 웹 대시보드 시작 중..."
echo "📊 대시보드: http://localhost:8000"
echo "📖 API 문서: http://localhost:8000/docs"
echo ""
echo "종료하려면 Ctrl+C를 누르세요."
echo "=========================================="
echo ""

python web_interface.py
