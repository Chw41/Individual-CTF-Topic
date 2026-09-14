FROM python:3.11-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends clamav && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py /app/app.py
COPY assets /app/assets/
COPY sigs /opt/sigs/
COPY flag /flag

RUN useradd -m -u 10001 appuser && \
    mkdir -p /app/uploads && \
    chown -R appuser:appuser /app && \
    chmod 644 /flag

USER appuser

EXPOSE 8080
CMD ["python3", "app.py"]
