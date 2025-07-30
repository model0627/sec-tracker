# Security Tracker Agent

리눅스 시스템을 위한 경량 보안 모니터링 에이전트입니다. 시스템 정보를 수집하고 보안 이벤트를 실시간으로 감시하여 관리 서버로 전송하거나 터미널에 직접 출력할 수 있습니다.

## 🚀 주요 기능

### 시스템 모니터링
- **시스템 정보 수집**: CPU, 메모리, 디스크, 네트워크 정보
- **리소스 사용량 추적**: 실시간 사용률 모니터링
- **시스템 업타임 및 로드 평균**: 시스템 상태 추적

### 보안 이벤트 감시
- **프로세스 모니터링**: 프로세스 생성/종료 감지
- **파일 시스템 감시**: 중요 디렉토리 변경 사항 추적
- **인증 이벤트**: 로그인/로그아웃, sudo 사용 감지
- **네트워크 활동**: 연결 상태 모니터링

### 출력 모드
- **서버 모드**: 관리 서버로 데이터 전송 (데몬 모드)
- **로컬 모드**: 터미널에 실시간 출력
  - 사람이 읽기 쉬운 형태 또는 JSON 형태
  - 원샷 스캔 또는 지속적 모니터링
  - 컬러 출력 및 타임스탬프 지원

### 통신 및 안정성
- **배치 전송**: 효율적인 데이터 전송
- **재시도 로직**: 네트워크 장애 대응
- **큐잉 시스템**: 오프라인 상황 대응
- **TLS 암호화**: 안전한 데이터 전송

## 📋 시스템 요구사항

- **운영체제**: Ubuntu 18.04+ / Debian 9+
- **아키텍처**: x86_64, ARM64
- **권한**: root 권한 (설치 시)
- **네트워크**: HTTPS 아웃바운드 연결 (서버 모드만)
- **메모리**: 최소 64MB RAM
- **디스크**: 최소 100MB 여유 공간

## 🛠️ 설치 방법

### 1. 빌드

```bash
# 저장소 클론
git clone https://github.com/your-org/sec-tracker.git
cd sec-tracker

# 의존성 설치
go mod download

# 빌드
go build -o sec-tracker
```

### 2. 설치

```bash
# 설치 스크립트 실행 (root 권한 필요)
sudo chmod +x scripts/install.sh
sudo ./scripts/install.sh
```

### 3. 설정

```bash
# 설정 파일 편집
sudo nano /etc/sec-tracker/config.json
```

**필수 설정 항목 (서버 모드):**
- `server.url`: 관리 서버 URL
- `server.api_key`: API 키
- `agent.id`: 고유한 에이전트 ID

### 4. 서비스 시작

```bash
# 서비스 시작
sudo systemctl start sec-tracker

# 서비스 상태 확인
sudo systemctl status sec-tracker

# 로그 확인
sudo journalctl -u sec-tracker -f
```

## 🖥️ 로컬 모드 사용법

### 기본 사용법

```bash
# 도움말 보기
./sec-tracker -help

# 버전 정보
./sec-tracker -version

# 터미널에서 연속 모니터링 (컬러 출력)
./sec-tracker -local

# 시스템 정보 한 번만 출력하고 종료
./sec-tracker -local -oneshot

# JSON 형태로 출력
./sec-tracker -local -json

# 한 번만 스캔하여 JSON으로 출력
./sec-tracker -local -oneshot -json

# 사용자 설정 파일로 실행
./sec-tracker -local -config my-config.json
```

### 출력 예시

**사람이 읽기 쉬운 형태:**
```
Starting Security Tracker Agent in LOCAL mode...
Agent ID: agent-001
Output Format: Human-readable
Mode: Continuous

=== CONTINUOUS MONITORING ===
Press Ctrl+C to stop...

== SYSTEM INFORMATION ==
Timestamp: 2024-01-15 10:30:45
Hostname: my-server
OS: linux
Kernel: 5.4.0-74-generic
Architecture: amd64

--- CPU ---
Cores: 4
Model: Intel(R) Core(TM) i7-8550U CPU @ 1.80GHz
Usage: 15.2%

--- MEMORY ---
Total: 16.0 GB
Available: 12.8 GB
Used: 3.2 GB
Usage: 20.0%

--- STATUS ---
Uptime: 2.5d
Load Average: 0.15 0.18 0.22
--------------------------------------------------

>>> EVENT <<<
Time: 2024-01-15 10:31:02
Type: process
Severity: INFO
Source: process_monitor
Message: Process started: vim (PID: 12345)
Details: PID=12345, PPID=1234, User=john, Command=vim
----------------------------------------
```

**JSON 형태:**
```json
{
  "hostname": "my-server",
  "os": "linux",
  "kernel": "5.4.0-74-generic",
  "architecture": "amd64",
  "cpu_info": {
    "cores": 4,
    "model_name": "Intel(R) Core(TM) i7-8550U CPU @ 1.80GHz",
    "usage_percent": 15.2
  },
  "memory_info": {
    "total": 17179869184,
    "available": 13743895552,
    "used": 3435973632,
    "usage_percent": 20.0
  },
  "timestamp": "2024-01-15T10:30:45Z"
}
```

## ⚙️ 설정 옵션

### Server 설정
```json
{
  "server": {
    "url": "https://your-server.com",
    "api_key": "your-api-key",
    "timeout": "30s",
    "retry_max": 3,
    "batch_size": 100
  }
}
```

### Agent 설정
```json
{
  "agent": {
    "id": "unique-agent-id",
    "name": "server-name",
    "report_interval": "60s",
    "buffer_size": 1000,
    "max_queue_size": 10000,
    "enable_tls": true
  }
}
```

### Monitoring 설정
```json
{
  "monitoring": {
    "system_info": true,
    "process_monitor": true,
    "file_monitor": true,
    "network_monitor": true,
    "auth_monitor": true,
    "watch_paths": ["/etc", "/usr/bin", "/var/log"],
    "scan_interval": "5s"
  }
}
```

### Local Output 설정
```json
{
  "local_output": {
    "json_format": false,
    "one_shot": false,
    "show_timestamp": true,
    "show_colors": true,
    "compact_output": false
  }
}
```

## 📊 API 엔드포인트

에이전트가 관리 서버와 통신하는 API 엔드포인트:

### 데이터 전송
```
POST /api/v1/agent/data
Content-Type: application/json
Authorization: Bearer {api_key}

{
  "agent_id": "agent-001",
  "timestamp": "2024-01-01T00:00:00Z",
  "payloads": [...]
}
```

### 헬스 체크
```
POST /api/v1/agent/health
Content-Type: application/json
Authorization: Bearer {api_key}

{
  "agent_id": "agent-001",
  "timestamp": "2024-01-01T00:00:00Z",
  "status": "healthy",
  "metrics": {...}
}
```

## 🔧 관리 명령어

### 서비스 관리
```bash
# 시작
sudo systemctl start sec-tracker

# 중지
sudo systemctl stop sec-tracker

# 재시작
sudo systemctl restart sec-tracker

# 상태 확인
sudo systemctl status sec-tracker

# 자동 시작 설정
sudo systemctl enable sec-tracker
```

### 로컬 모드 명령어
```bash
# 실시간 모니터링
./sec-tracker -local

# 시스템 스캔 (JSON)
./sec-tracker -local -oneshot -json > system-info.json

# 컴팩트 형태로 모니터링
./sec-tracker -local -config <(echo '{"local_output": {"compact_output": true}}')

# 색상 없이 출력
./sec-tracker -local -config <(echo '{"local_output": {"show_colors": false}}')
```

### 로그 확인
```bash
# 실시간 로그
sudo journalctl -u sec-tracker -f

# 최근 로그
sudo journalctl -u sec-tracker --since "1 hour ago"

# 로그 파일 직접 확인
sudo tail -f /var/log/sec-tracker/agent.log
```

### 설정 유효성 검사
```bash
# 설정 파일 문법 검사
sudo /usr/local/bin/sec-tracker -config-check

# 연결 테스트
sudo /usr/local/bin/sec-tracker -test-connection
```

## 🛡️ 보안 고려사항

### 권한 설정
- 에이전트는 전용 사용자(`sec-tracker`)로 실행
- 최소 권한 원칙 적용
- AppArmor/SELinux 프로파일 제공

### 네트워크 보안
- TLS 1.2+ 강제 사용
- 인증서 검증
- API 키 기반 인증

### 데이터 보호
- 메모리 내 민감 정보 보호
- 로그 순환 및 압축
- 설정 파일 권한 제한

## 🔍 문제 해결

### 일반적인 문제들

**1. 서비스가 시작되지 않음**
```bash
# 설정 파일 확인
sudo journalctl -u sec-tracker

# 권한 확인
ls -la /etc/sec-tracker/config.json

# 네트워크 연결 확인
curl -I https://your-server.com
```

**2. 높은 CPU 사용률**
```bash
# 모니터링 간격 조정
sudo nano /etc/sec-tracker/config.json
# scan_interval을 늘림 (예: "10s")
```

**3. 연결 오류**
```bash
# 방화벽 확인
sudo ufw status

# DNS 확인
nslookup your-server.com

# API 키 확인
grep api_key /etc/sec-tracker/config.json
```

**4. 로컬 모드에서 색상이 나오지 않음**
```bash
# 터미널 지원 확인
echo $TERM

# 강제로 색상 활성화
./sec-tracker -local -config <(echo '{"local_output": {"show_colors": true}}')
```

### 디버그 모드
```bash
# 디버그 로그 레벨로 실행
sudo systemctl edit sec-tracker
# Environment="LOG_LEVEL=debug" 추가

# 로컬 모드에서 상세 출력
./sec-tracker -local -config <(echo '{"local_output": {"compact_output": false}}')
```

## 📈 성능 최적화

### 메모리 사용량 줄이기
- `buffer_size` 값 조정
- `scan_interval` 증가
- 불필요한 모니터링 비활성화

### 네트워크 대역폭 최적화
- `batch_size` 증가
- `report_interval` 증가
- 압축 활성화

### CPU 사용량 최적화
- 모니터링 간격 조정
- watch_paths 범위 제한
- 프로세스 스캔 주기 조정

## 💡 사용 시나리오

### 🔍 시스템 진단
```bash
# 빠른 시스템 상태 확인
./sec-tracker -local -oneshot

# 상세한 시스템 정보 수집
./sec-tracker -local -oneshot -json > system-report.json
```

### 📱 실시간 모니터링
```bash
# 보안 이벤트 실시간 감시
./sec-tracker -local

# 컴팩트한 형태로 이벤트 모니터링
./sec-tracker -local -config <(echo '{"local_output": {"compact_output": true}}')
```

### 📊 데이터 수집
```bash
# 시스템 정보를 JSON으로 수집
./sec-tracker -local -oneshot -json | jq .

# 특정 시간 동안 이벤트 수집
timeout 60 ./sec-tracker -local -json > events.jsonl
```

### 🖥️ 스크립트 연동
```bash
#!/bin/bash
# 시스템 상태 체크 스크립트

# 시스템 정보 수집
SYSTEM_INFO=$(./sec-tracker -local -oneshot -json)
CPU_USAGE=$(echo $SYSTEM_INFO | jq '.cpu_info.usage_percent')

if (( $(echo "$CPU_USAGE > 80" | bc -l) )); then
    echo "Warning: High CPU usage detected: $CPU_USAGE%"
fi
```

## 🏗️ 아키텍처

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   System Info   │    │   Event Monitor  │    │  Communication │
│   Collector     │    │                  │    │     Client      │
├─────────────────┤    ├──────────────────┤    ├─────────────────┤
│ • CPU/Memory    │    │ • Process Events │    │ • Batch Sending │
│ • Disk Usage    │    │ • File Changes   │    │ • Retry Logic   │
│ • Network       │    │ • Auth Events    │    │ • Queue Mgmt    │
│ • Load Average  │    │ • Network Conn   │    │ • TLS Security  │
└─────────────────┘    └──────────────────┘    └─────────────────┘
        │                       │                       │
        └───────────────────────┼───────────────────────┘
                                │
                    ┌─────────────────┐
                    │   Main Agent    │
                    │                 │
                    │ • Coordination  │
                    │ • Buffering     │
                    │ • Health Checks │
                    │ • Metrics       │
                    └─────────────────┘
                                │
                    ┌─────────────────┐
                    │Terminal Output  │
                    │                 │
                    │ • Human Format  │
                    │ • JSON Format   │
                    │ • Color Support │
                    │ • One-shot Mode │
                    └─────────────────┘
```

## 🤝 기여하기

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## 📄 라이선스

MIT License - 자세한 내용은 LICENSE 파일을 참조하세요.

## 📞 지원

- **문서**: [Wiki](https://github.com/your-org/sec-tracker/wiki)
- **이슈**: [GitHub Issues](https://github.com/your-org/sec-tracker/issues)
- **이메일**: support@your-org.com

---

**⚠️ 주의사항**: 이 에이전트는 시스템 레벨 권한이 필요하므로 신뢰할 수 있는 환경에서만 사용하세요. 