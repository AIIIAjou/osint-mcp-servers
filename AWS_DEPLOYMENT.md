# AWS 배포 가이드

## 0. 준비 사항

- AWS 계정
- AWS CLI 설치 및 설정 (`aws configure`)
- Docker 설치
- GitHub 계정 (선택사항, 하지만 권장)

---

## 1. 로컬에서 Docker 테스트

먼저 로컬에서 제대로 동작하는지 확인합니다:

```bash
# .env 파일에 API 키 설정
export INTELX_API_KEY="your-api-key-here"
export DEBUG_MODE=false

# Docker Compose로 실행
docker-compose up --build

# 다른 터미널에서 테스트
curl http://localhost:8000/
curl http://localhost:8000/health
```

---

## 2. Docker 이미지를 AWS ECR에 푸시

### 2-1. ECR 저장소 생성

```bash
# AWS 리전 설정 (예: us-east-1)
export AWS_REGION=us-east-1
export AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
export ECR_REPO_NAME=intelligence-x-mcp-server

# ECR 저장소 생성
aws ecr create-repository \
  --repository-name $ECR_REPO_NAME \
  --region $AWS_REGION
```

### 2-2. Docker 이미지 빌드 및 푸시

```bash
# Docker 로그인
aws ecr get-login-password --region $AWS_REGION | \
  docker login --username AWS --password-stdin \
  $AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com

# 이미지 빌드
docker build -t $ECR_REPO_NAME:latest .

# 이미지에 태그 추가
docker tag $ECR_REPO_NAME:latest \
  $AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/$ECR_REPO_NAME:latest

# ECR에 푸시
docker push $AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/$ECR_REPO_NAME:latest
```

---

## 3. AWS ECS에서 실행 (권장)

### 3-1. ECS 클러스터 생성

```bash
export CLUSTER_NAME=intelligence-x-cluster

aws ecs create-cluster --cluster-name $CLUSTER_NAME --region $AWS_REGION
```

### 3-2. CloudWatch 로그 그룹 생성

```bash
export LOG_GROUP=/ecs/intelligence-x-mcp-server

aws logs create-log-group \
  --log-group-name $LOG_GROUP \
  --region $AWS_REGION
```

### 3-3. ECS 작업 정의 생성

`task-definition.json` 파일을 생성합니다:

```json
{
  "family": "intelligence-x-mcp-server",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "256",
  "memory": "512",
  "containerDefinitions": [
    {
      "name": "mcp-server",
      "image": "YOUR_AWS_ACCOUNT_ID.dkr.ecr.AWS_REGION.amazonaws.com/intelligence-x-mcp-server:latest",
      "portMappings": [
        {
          "containerPort": 8000,
          "hostPort": 8000,
          "protocol": "tcp"
        }
      ],
      "environment": [
        {
          "name": "DEBUG_MODE",
          "value": "false"
        },
        {
          "name": "PORT",
          "value": "8000"
        }
      ],
      "secrets": [
        {
          "name": "INTELX_API_KEY",
          "valueFrom": "arn:aws:secretsmanager:AWS_REGION:AWS_ACCOUNT_ID:secret:intelx-api-key::"
        }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/intelligence-x-mcp-server",
          "awslogs-region": "AWS_REGION",
          "awslogs-stream-prefix": "ecs"
        }
      },
      "healthCheck": {
        "command": ["CMD-SHELL", "curl -f http://localhost:8000/health || exit 1"],
        "interval": 30,
        "timeout": 10,
        "retries": 3,
        "startPeriod": 5
      }
    }
  ]
}
```

실제 값으로 대체:

```bash
sed -i "s/YOUR_AWS_ACCOUNT_ID/$AWS_ACCOUNT_ID/g" task-definition.json
sed -i "s/AWS_REGION/$AWS_REGION/g" task-definition.json
```

### 3-4. API 키를 AWS Secrets Manager에 저장

```bash
aws secretsmanager create-secret \
  --name intelx-api-key \
  --secret-string "your-intelx-api-key" \
  --region $AWS_REGION
```

### 3-5. IAM 역할 생성

```bash
# 신뢰 정책 파일 생성
cat > trust-policy.json << 'TRUST'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "ecs-tasks.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
TRUST

# IAM 역할 생성
aws iam create-role \
  --role-name ecsTaskExecutionRole \
  --assume-role-policy-document file://trust-policy.json

# 정책 연결
aws iam attach-role-policy \
  --role-name ecsTaskExecutionRole \
  --policy-arn arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy

# Secrets Manager 접근 권한 추가
cat > secrets-policy.json << 'POLICY'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "secretsmanager:GetSecretValue"
      ],
      "Resource": "arn:aws:secretsmanager:*:*:secret:intelx-api-key*"
    }
  ]
}
POLICY

aws iam put-role-policy \
  --role-name ecsTaskExecutionRole \
  --policy-name SecretsManagerAccess \
  --policy-document file://secrets-policy.json
```

### 3-6. ECS 작업 정의 등록

```bash
aws ecs register-task-definition \
  --cli-input-json file://task-definition.json \
  --region $AWS_REGION
```

### 3-7. ECS 서비스 생성

```bash
# VPC와 서브넷 정보 조회
export VPC_ID=$(aws ec2 describe-vpcs --filters "Name=isDefault,Values=true" \
  --query "Vpcs[0].VpcId" --output text --region $AWS_REGION)

export SUBNET_ID=$(aws ec2 describe-subnets --filters "Name=vpc-id,Values=$VPC_ID" \
  --query "Subnets[0].SubnetId" --output text --region $AWS_REGION)

# 보안 그룹 생성
export SG_ID=$(aws ec2 create-security-group \
  --group-name intelligence-x-sg \
  --description "Security group for Intelligence X MCP Server" \
  --vpc-id $VPC_ID \
  --query 'GroupId' --output text --region $AWS_REGION)

# 포트 8000 열기
aws ec2 authorize-security-group-ingress \
  --group-id $SG_ID \
  --protocol tcp --port 8000 --cidr 0.0.0.0/0 \
  --region $AWS_REGION

# ECS 서비스 생성
aws ecs create-service \
  --cluster $CLUSTER_NAME \
  --service-name intelligence-x-mcp-server \
  --task-definition intelligence-x-mcp-server:1 \
  --desired-count 1 \
  --launch-type FARGATE \
  --network-configuration "awsvpcConfiguration={subnets=[$SUBNET_ID],securityGroups=[$SG_ID],assignPublicIp=ENABLED}" \
  --region $AWS_REGION
```

---

## 4. 서비스 확인

### 4-1. ECS 작업 상태 확인

```bash
aws ecs list-tasks \
  --cluster $CLUSTER_NAME \
  --region $AWS_REGION

# 작업 세부사항 확인
aws ecs describe-tasks \
  --cluster $CLUSTER_NAME \
  --tasks <TASK_ARN> \
  --region $AWS_REGION
```

### 4-2. 퍼블릭 IP 확인

```bash
# ENI ID 확인
ENI_ID=$(aws ecs describe-tasks \
  --cluster $CLUSTER_NAME \
  --tasks <TASK_ARN> \
  --region $AWS_REGION \
  --query 'tasks[0].attachments[0].details[?name==`networkInterfaceId`].value[0]' \
  --output text)

# 퍼블릭 IP 조회
aws ec2 describe-network-interfaces \
  --network-interface-ids $ENI_ID \
  --region $AWS_REGION \
  --query 'NetworkInterfaces[0].Association.PublicIp' \
  --output text
```

### 4-3. 서버 테스트

```bash
export PUBLIC_IP="<위에서 조회한 IP>"

curl http://$PUBLIC_IP:8000/
curl http://$PUBLIC_IP:8000/health
```

---

## 5. AWS ALB (Application Load Balancer)로 배포 (선택)

더 프로덕션스러운 환경을 원한다면:

```bash
# ALB 생성
export LB_NAME=intelligence-x-alb

aws elbv2 create-load-balancer \
  --name $LB_NAME \
  --subnets $SUBNET_ID \
  --security-groups $SG_ID \
  --scheme internet-facing \
  --type application \
  --region $AWS_REGION

# 대상 그룹 생성
export TG_ARN=$(aws elbv2 create-target-group \
  --name intelligence-x-tg \
  --protocol HTTP \
  --port 8000 \
  --vpc-id $VPC_ID \
  --region $AWS_REGION \
  --query 'TargetGroups[0].TargetGroupArn' \
  --output text)

# 리스너 생성
aws elbv2 create-listener \
  --load-balancer-arn <LB_ARN> \
  --protocol HTTP \
  --port 80 \
  --default-actions Type=forward,TargetGroupArn=$TG_ARN \
  --region $AWS_REGION
```

---

## 6. OpenAI Agent Builder와 연결

### 6-1. 공개 URL 설정

OpenAI Agent Builder에서 다음 URL을 사용:

```
http://<PUBLIC_IP>:8000/mcp
```

또는 ALB를 사용하는 경우:

```
http://<ALB_DNS_NAME>/mcp
```

### 6-2. HTTPS 설정 (권장)

AWS Certificate Manager에서 SSL 인증서를 받고 ALB에 연결:

```bash
# ACM 인증서 요청 (console에서 또는)
aws acm request-certificate \
  --domain-name your-domain.com \
  --validation-method DNS
```

---

## 7. 비용 최적화

- **Fargate**: 시간당 약 $0.01 USD (1GB 메모리, 256 CPU)
- **Data Transfer**: 첫 100GB/month 무료
- **CloudWatch Logs**: 1GB $0.50/month

비용을 줄이려면:
- 사용하지 않을 때 작업 중단
- 한 번에 여러 API 요청 배치 처리
- 캐싱 구현

---

## 8. 모니터링 및 로깅

```bash
# CloudWatch 로그 조회
aws logs tail $LOG_GROUP --follow --region $AWS_REGION

# 로그 필터링
aws logs tail $LOG_GROUP --follow --filter-pattern "ERROR" --region $AWS_REGION
```

---

## 9. 체크리스트

- [ ] .env 파일에 INTELX_API_KEY 설정
- [ ] Docker로 로컬 테스트 성공
- [ ] ECR 이미지 푸시 완료
- [ ] ECS 클러스터 생성
- [ ] Secrets Manager에 API 키 저장
- [ ] IAM 역할 설정
- [ ] ECS 서비스 생성 및 실행
- [ ] 퍼블릭 IP에서 서버 접근 확인
- [ ] OpenAI Agent Builder에 URL 연결
- [ ] CloudWatch 로그 모니터링 설정

---

## 10. 문제 해결

### 이미지 푸시 실패

```bash
# ECR 로그인 다시 시도
aws ecr get-login-password --region $AWS_REGION | \
  docker login --username AWS --password-stdin \
  $AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com
```

### ECS 작업이 실패함

```bash
# CloudWatch 로그 확인
aws logs tail /ecs/intelligence-x-mcp-server --follow --region $AWS_REGION

# 작업 상태 확인
aws ecs describe-tasks --cluster $CLUSTER_NAME --tasks <TASK_ARN> --region $AWS_REGION
```

### 서버에 접근 불가

```bash
# 보안 그룹 확인
aws ec2 describe-security-groups --group-ids $SG_ID --region $AWS_REGION

# 인바운드 규칙 추가
aws ec2 authorize-security-group-ingress \
  --group-id $SG_ID \
  --protocol tcp --port 8000 --cidr 0.0.0.0/0 \
  --region $AWS_REGION
```

