FROM python:3.11-slim-bookworm

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    dnsutils \
    iputils-ping \
    netcat-openbsd \
    procps \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd -g 13370 appgroup && useradd -u 13370 -g appgroup -s /bin/bash -m appuser

WORKDIR /home/appuser/app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

RUN chown -R appuser:appgroup /home/appuser/app

USER 13370:13370

EXPOSE 8080

CMD ["gunicorn", "--bind", "0.0.0.0:8080", "--workers", "2", "--access-logfile", "-", "app:app"]
