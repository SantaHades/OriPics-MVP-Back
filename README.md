---
title: OriPics-MVP-Back
emoji: 🖼️
colorFrom: indigo
colorTo: blue
sdk: docker
app_port: 7860
pinned: false
---

# OriPics MVP Backend

FastAPI 기반의 OriPics 원본 인증 백엔드 서버입니다.

## 주요 기능
- 이미지 스테가노그래피(Steganography)를 이용한 타임스탬프 및 메타데이터 삽입
- 원본 이미지 검증 및 인증 정보 추출
- 7일간 유효한 공유 링크 생성 및 관리

## 배포 환경
- **Hugging Face Spaces (Docker SDK)**
- **Python 3.11-slim**
- **Port:** 7860

## API Endpoints
- `POST /api/process`: 이미지 업로드 및 인증 정보 삽입/검증
- `POST /api/links/create`: 공유 링크 생성
- `GET /api/links/{link_id}`: 인증된 이미지 및 메타데이터 조회
