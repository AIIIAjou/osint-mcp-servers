import os
import json
import time
import logging
import asyncio
from typing import Any, Dict, List, Optional
from datetime import datetime

from dotenv import load_dotenv
from intelxapi import intelx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# .env 파일 로드
load_dotenv()

# 로깅 설정
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# FastAPI 앱 초기화
app = FastAPI(
    title="Intelligence X MCP Server",
    description="다크웹 및 DB 유출 데이터 분석을 위한 MCP 서버",
    version="1.0.0",
)

# CORS 설정
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Intelligence X API 설정
INTELX_API_KEY = os.getenv("INTELX_API_KEY", "")
DEBUG_MODE = os.getenv("DEBUG_MODE", "false").lower() == "true"

if not INTELX_API_KEY:
    logger.warning("API KEY 없음")

if DEBUG_MODE:
    logger.warning("DEBUG")


# MCP 요청/응답 모델
class MCPRequest(BaseModel):
    method: str
    params: Optional[Dict[str, Any]] = None


class MCPResponse(BaseModel):
    result: Optional[Any] = None
    error: Optional[Dict[str, Any]] = None


class SearchRequest(BaseModel):
    term: str = Field(..., description="검색할 셀렉터 (이메일, 도메인, IP 등)")
    maxresults: int = Field(100, description="최대 결과 수")
    timeout: int = Field(5, description="타임아웃 (초)")
    buckets: Optional[List[str]] = Field(None, description="검색할 버킷 목록")
    datefrom: Optional[str] = Field(None, description="시작 날짜 (YYYY-MM-DD)")
    dateto: Optional[str] = Field(None, description="종료 날짜 (YYYY-MM-DD)")


class IntelligenceXClient:
    def __init__(self, api_key: str):
        self.client = None
        self.debug_mode = DEBUG_MODE

        if api_key:
            self.client = intelx(api_key)
            self.client.API_ROOT = "https://free.intelx.io"

    def search(self, search_request: SearchRequest) -> Dict[str, Any]:
        if self.debug_mode:
            logger.info(f"DEBUG MODE: Mock 데이터 반환 (검색어: {search_request.term})")
            return {
                "records": [
                    {
                        "name": f"Mock Result 1 for {search_request.term}",
                        "description": "This is a mock result for testing purposes",
                        "date": datetime.now().isoformat(),
                        "media": 1,
                        "type": 1,
                        "added": datetime.now().isoformat(),
                        "storageid": "mock-storage-id-1",
                        "bucket": "mock-bucket",
                    },
                    {
                        "name": f"Mock Result 2 for {search_request.term}",
                        "description": "Second mock result for testing",
                        "date": "2025-10-25T12:00:00",
                        "media": 1,
                        "type": 1,
                        "added": "2025-10-25T14:30:00",
                        "storageid": "mock-storage-id-2",
                        "bucket": "mock-bucket",
                    },
                ]
            }

        # 실제 API 호출
        try:
            if not self.client:
                raise HTTPException(
                    status_code=500, detail="API 키가 설정되지 않았습니다."
                )

            results = self.client.search(
                search_request.term,
                maxresults=search_request.maxresults,
                timeout=search_request.timeout,
            )
            return results
        except Exception as e:
            logger.error(f"검색 요청 실패: {e}")
            raise HTTPException(
                status_code=500, detail=f"Intelligence X API 오류: {str(e)}"
            )


# Intelligence X 클라이언트 인스턴스
intelx_client = IntelligenceXClient(INTELX_API_KEY)

# MCP 도구 정의
MCP_TOOLS = [
    {
        "name": "search_intelligence_x",
        "description": "Intelligence X에서 다크웹 및 유출 데이터를 검색합니다. 이메일, 도메인, IP, URL, Bitcoin 주소 등의 셀렉터를 지원합니다.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "term": {
                    "type": "string",
                    "description": "검색할 셀렉터 (예: email@example.com, example.com, 192.168.1.1)",
                },
                "maxresults": {
                    "type": "integer",
                    "description": "최대 결과 수 (기본값: 100)",
                    "default": 100,
                },
                "buckets": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "검색할 데이터 카테고리 (예: ['darknet.tor', 'pastes'])",
                },
                "datefrom": {
                    "type": "string",
                    "description": "시작 날짜 (YYYY-MM-DD 형식)",
                },
                "dateto": {
                    "type": "string",
                    "description": "종료 날짜 (YYYY-MM-DD 형식)",
                },
            },
            "required": ["term"],
        },
    },
    {
        "name": "read_intelligence_x_file",
        "description": "Intelligence X 검색 결과에서 특정 파일의 내용을 읽습니다.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "system_id": {"type": "string", "description": "파일의 시스템 ID"},
                "bucket": {"type": "string", "description": "파일이 속한 버킷"},
            },
            "required": ["system_id", "bucket"],
        },
    },
    {
        "name": "get_search_results",
        "description": "이전 검색의 결과를 검색 ID로 조회합니다.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "search_id": {"type": "string", "description": "검색 ID"},
                "limit": {
                    "type": "integer",
                    "description": "가져올 결과 수 (기본값: 100)",
                    "default": 100,
                },
            },
            "required": ["search_id"],
        },
    },
]


@app.get("/")
async def root():
    """서버 정보"""
    return {
        "name": "Intelligence X MCP Server",
        "version": "1.0.0",
        "description": "다크웹 및 DB 유출 데이터 분석을 위한 MCP 서버",
        "api_configured": bool(INTELX_API_KEY),
    }


@app.get("/health")
async def health():
    """헬스 체크"""
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}


@app.post("/mcp")
async def mcp_endpoint(request: Request):
    """MCP 프로토콜 엔드포인트 (JSON-RPC 2.0)"""
    try:
        body = await request.json()
        method = body.get("method")
        params = body.get("params", {})
        request_id = body.get("id", 1)

        logger.info(f"MCP 요청: method={method}, id={request_id}")

        # 초기화 메서드
        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {}},
                    "serverInfo": {
                        "name": "Intelligence X MCP Server",
                        "version": "1.0.0",
                    },
                },
            }

        # 알림 메서드 (응답 없음 - 단순히 로그만)
        elif method == "notifications/initialized":
            logger.info("클라이언트 초기화 완료")
            return {"jsonrpc": "2.0", "id": request_id}

        # 도구 목록 반환 (JSON-RPC 2.0 형식)
        elif method == "tools/list":
            return {"jsonrpc": "2.0", "id": request_id, "result": {"tools": MCP_TOOLS}}

        # 도구 호출 (JSON-RPC 2.0 형식)
        elif method == "tools/call":
            tool_name = params.get("name")
            arguments = params.get("arguments", {})

            if tool_name == "search_intelligence_x":
                search_req = SearchRequest(
                    term=arguments.get("term"),
                    maxresults=arguments.get("maxresults", 100),
                    buckets=arguments.get("buckets"),
                    datefrom=arguments.get("datefrom"),
                    dateto=arguments.get("dateto"),
                )

                result = intelx_client.search(search_req)

                return {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": json.dumps(
                                    result, indent=2, ensure_ascii=False
                                ),
                            }
                        ]
                    },
                }

            else:
                return {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {
                        "code": -32601,
                        "message": f"알 수 없는 도구: {tool_name}",
                    },
                }

        else:
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32601, "message": f"지원하지 않는 메소드: {method}"},
            }

    except Exception as e:
        logger.error(f"MCP 요청 처리 오류: {e}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={
                "jsonrpc": "2.0",
                "id": body.get("id", 1) if "body" in locals() else 1,
                "error": {"code": -32603, "message": str(e)},
            },
        )


if __name__ == "__main__":
    import uvicorn

    port = int(os.getenv("PORT", "8000"))

    logger.info(f"Intelligence X MCP Server 시작 (포트: {port})")
    logger.info(f"API 키 설정됨: {bool(INTELX_API_KEY)}")

    uvicorn.run(app, host="0.0.0.0", port=port)
