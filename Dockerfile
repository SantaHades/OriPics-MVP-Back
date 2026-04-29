FROM python:3.11-slim

# Hugging Face Spaces 환경을 위한 UID 1000 유저 생성
RUN useradd -m -u 1000 user

WORKDIR /code
RUN chown -R user:user /code

# 의존성 설치
COPY --chown=user requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 코드 복사 및 소유권 변경
COPY --chown=user . .

# 권한이 제한된 user로 스위칭
USER user

# Hugging Face Spaces가 앱 라우팅을 위해 바라보는 기본 포트
EXPOSE 7860

CMD uvicorn main:app --host 0.0.0.0 --port ${PORT:-7860}
