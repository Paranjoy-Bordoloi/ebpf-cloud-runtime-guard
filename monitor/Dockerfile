FROM python:3.11-slim-bookworm

ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY dns_entropy_detector.py .

RUN mkdir -p /var/log/tetragon

EXPOSE 53/udp

CMD ["python", "dns_entropy_detector.py"]
