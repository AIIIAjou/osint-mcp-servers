"""
향상된 OSINT 웹 인터페이스
- 풍부한 데이터 시각화
- Ollama LLM 채팅 통합
"""

import os
import json
from typing import Optional, List, Dict, Any
from datetime import datetime
from fastapi import FastAPI, Query, HTTPException, Request
from fastapi.responses import HTMLResponse, FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn
import requests
import asyncio

from db_manager import OSINTDatabase


# FastAPI 앱 생성
app = FastAPI(
    title="Enhanced OSINT Dashboard",
    description="OSINT 수집 정보 대시보드 + LLM 채팅",
    version="2.0.0"
)

# CORS 설정
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 데이터베이스 인스턴스
db = OSINTDatabase("db.csv")

# Ollama 설정
OLLAMA_API_URL = os.getenv("OLLAMA_API_URL", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen3:8b")


class ChatMessage(BaseModel):
    message: str
    model: Optional[str] = None


@app.get("/", response_class=HTMLResponse)
async def root():
    """메인 대시보드 페이지"""
    with open("web_dashboard.html", "r", encoding="utf-8") as f:
        return f.read()


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
    """PDF 파일 새 탭에서 열기"""
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="PDF 파일을 찾을 수 없습니다.")
    return FileResponse(
        path,
        media_type="application/pdf",
        headers={"Content-Disposition": "inline"}
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


@app.post("/api/chat")
async def chat_with_llm(message: ChatMessage):
    """
    Ollama LLM과 채팅

    Args:
        message: 사용자 메시지

    Returns:
        LLM 응답
    """
    try:
        # Ollama API 호출 (올바른 엔드포인트)
        response = requests.post(
            f"{OLLAMA_API_URL}/api/chat",
            json={
                "model": message.model or OLLAMA_MODEL,
                "messages": [
                    {
                        "role": "user",
                        "content": message.message
                    }
                ],
                "stream": False
            },
            timeout=60
        )

        if response.status_code == 200:
            result = response.json()
            # Ollama API 응답 구조에 맞게 수정
            assistant_message = result.get("message", {})
            return {
                "success": True,
                "response": assistant_message.get("content", ""),
                "model": message.model or OLLAMA_MODEL
            }
        else:
            # 상세한 에러 메시지
            error_detail = f"Ollama API 오류 (HTTP {response.status_code})"
            try:
                error_json = response.json()
                error_detail += f": {error_json.get('error', response.text)}"
            except:
                error_detail += f": {response.text[:200]}"

            return {
                "success": False,
                "error": error_detail
            }

    except requests.exceptions.ConnectionError:
        return {
            "success": False,
            "error": "Ollama 서버에 연결할 수 없습니다. 'ollama serve' 명령으로 Ollama를 시작하세요."
        }
    except requests.exceptions.Timeout:
        return {
            "success": False,
            "error": "Ollama 응답 시간 초과. 모델이 너무 크거나 서버가 느릴 수 있습니다."
        }
    except Exception as e:
        return {
            "success": False,
            "error": f"예상치 못한 오류: {str(e)}"
        }


@app.post("/api/chat/stream")
async def chat_with_llm_stream(message: ChatMessage):
    """
    Ollama LLM과 스트리밍 채팅

    Args:
        message: 사용자 메시지

    Returns:
        스트리밍 응답
    """
    async def generate():
        try:
            response = requests.post(
                f"{OLLAMA_API_URL}/api/chat",
                json={
                    "model": message.model or OLLAMA_MODEL,
                    "messages": [
                        {
                            "role": "user",
                            "content": message.message
                        }
                    ],
                    "stream": True
                },
                stream=True,
                timeout=120
            )

            for line in response.iter_lines():
                if line:
                    data = json.loads(line)
                    if "message" in data:
                        content = data["message"].get("content", "")
                        if content:
                            yield f"data: {json.dumps({'text': content})}\n\n"
                    if data.get("done"):
                        yield f"data: {json.dumps({'done': True})}\n\n"
                        break

        except Exception as e:
            yield f"data: {json.dumps({'error': str(e)})}\n\n"

    return StreamingResponse(generate(), media_type="text/event-stream")


@app.get("/api/ollama/models")
async def get_ollama_models():
    """사용 가능한 Ollama 모델 목록 조회"""
    try:
        response = requests.get(f"{OLLAMA_API_URL}/api/tags", timeout=5)
        if response.status_code == 200:
            models = response.json().get("models", [])
            return {
                "success": True,
                "models": [m["name"] for m in models]
            }
        else:
            return {
                "success": False,
                "error": "모델 목록을 가져올 수 없습니다."
            }
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }


@app.get("/api/health")
async def health_check():
    """서버 상태 체크"""
    # Ollama 연결 확인
    ollama_status = "disconnected"
    try:
        response = requests.get(f"{OLLAMA_API_URL}/api/tags", timeout=2)
        if response.status_code == 200:
            ollama_status = "connected"
    except:
        pass

    return {
        "status": "healthy",
        "ollama": ollama_status,
        "database": "connected",
        "records": db.get_statistics()["total_records"]
    }


if __name__ == "__main__":
    print("=" * 70)
    print("🌐 Enhanced OSINT Dashboard 시작")
    print("=" * 70)
    print("📊 대시보드: http://localhost:8000")
    print("📖 API 문서: http://localhost:8000/docs")
    print("💬 LLM 채팅: 웹 인터페이스에서 사용 가능")
    print()
    print("⚙️  설정:")
    print(f"  - Ollama URL: {OLLAMA_API_URL}")
    print(f"  - 기본 모델: {OLLAMA_MODEL}")
    print("=" * 70)

    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        log_level="info"
    )
