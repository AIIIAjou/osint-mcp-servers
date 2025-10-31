

set -e

MCP_SERVER_URL="${MCP_SERVER_URL:-http://localhost:8000}"

echo "test"

# 색상 정의
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 헬스 체크
echo -e "${YELLOW}1. 헬스 체크${NC}"
response=$(curl -s "${MCP_SERVER_URL}/health")
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ 서버가 정상 작동 중입니다${NC}"
    echo "$response" | jq .
else
    echo -e "${RED}✗ 서버 연결 실패${NC}"
    exit 1
fi

echo ""
echo "========================================"
echo ""

# 서버 정보
echo -e "${YELLOW}2. 서버 정보${NC}"
curl -s "${MCP_SERVER_URL}/" | jq .

echo ""
echo "========================================"
echo ""

# 도구 목록
echo -e "${YELLOW}3. 사용 가능한 도구 목록${NC}"
curl -s "${MCP_SERVER_URL}/mcp" \
  -H "Content-Type: application/json" \
  -d '{
    "method": "tools/list"
  }' | jq '.tools[] | {name: .name, description: .description}'

echo ""
echo "========================================"
echo ""

# 검색 테스트 (예제)
echo -e "${YELLOW}4. 검색 테스트 (example.com)${NC}"
echo -e "${YELLOW}   주의: 유효한 API 키가 필요합니다${NC}"
echo ""

result=$(curl -s "${MCP_SERVER_URL}/mcp" \
  -H "Content-Type: application/json" \
  -d '{
    "method": "tools/call",
    "params": {
      "name": "search_intelligence_x",
      "arguments": {
        "term": "example.com",
        "maxresults": 5
      }
    }
  }')

if echo "$result" | jq -e '.error' > /dev/null 2>&1; then
    echo -e "${RED}✗ 오류 발생:${NC}"
    echo "$result" | jq '.error'
else
    echo -e "${GREEN}✓ 검색 성공${NC}"
    echo "$result" | jq '.content[0].text' -r | jq '.search_id, .total'
fi

echo ""
echo "========================================"
echo -e "${GREEN}테스트 완료!${NC}"
echo "========================================"