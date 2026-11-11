FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY bridge.py .

RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin appuser
USER 10001

CMD ["python", "bridge.py"]
