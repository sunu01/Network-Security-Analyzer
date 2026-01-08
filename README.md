# Network Security Analyzer (C++ / Linux)

## 프로젝트 개요
본 프로젝트는 Linux 환경에서 **libpcap**을 활용하여 네트워크 Raw 패킷을 실시간으로 캡처하고,  
C++ 멀티스레드 기반의 고성능 구조로 패킷을 분석하여 **IP별 트래픽 통계 및 이상 트래픽(PPS 기반) 탐지**를 수행하는 서버 소프트웨어입니다.

실제 방화벽 제어 대신, iptables 차단 명령을 로그로 출력하는 방식으로  
네트워크 보안 제어 로직 설계 역량을 입증하는 것을 목표로 합니다.

---

## 개발 환경
- OS: Ubuntu (WSL2)
- Language: C++17
- Library: libpcap
- Build Tool: CMake
- Threading: std::thread, mutex, condition_variable

---

## 시스템 아키텍처
[ Network Interface ]
|
libpcap
|
(Producer Thread)
|
Thread-safe Queue
|
(Consumer Thread)
|
[ Packet Parsing / Statistics / PPS Detection ]


### 구조 설명
- **Producer Thread**
  - libpcap 콜백을 통해 네트워크 패킷을 수집
  - 패킷 메모리 수명 문제를 방지하기 위해 패킷을 복사하여 큐에 저장

- **Consumer Thread**
  - 큐에서 패킷을 가져와 L3/L4 파싱
  - IP별 통계 집계 및 이상 트래픽 탐지 수행

- Producer–Consumer 패턴을 적용하여 실시간 처리 성능을 확보

---

## 주요 기능

### 1. 패킷 캡처 및 파싱
- Ethernet / Linux SLL / Linux SLL2 링크 계층 지원
- IPv4 패킷만 분석
- TCP / UDP 헤더 직접 파싱

---

### 2. IP별 트래픽 통계
- 출발지 IP 기준 패킷 수 집계
- 누적 바이트 수 계산
- 실행 종료 시 IP별 통계 출력

---

### 3. PPS 기반 이상 트래픽 탐지
- 초당 패킷 수(PPS) 윈도우 기반 탐지 로직
- 일정 임계값 초과 시 이상 트래픽으로 판단
- 실시간 탐지 로그 출력

---

### 4. 트래픽 차단 로직 설계 (시뮬레이션)
- 이상 트래픽 탐지 시 차단 대상 IP 식별
- 실제 차단 대신 iptables 차단 명령을 로그로 출력
- 네트워크 보안 제어 설계 역량을 강조

## 실행 방법

### 의존성 설치
```bash
sudo apt update
sudo apt install -y libpcap-dev cmake g++
