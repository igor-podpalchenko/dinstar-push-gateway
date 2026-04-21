FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DUMP_DIR=/dumps

WORKDIR /app

COPY requirements.txt .
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential libcurl4-gnutls-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && PYCURL_SSL_LIBRARY=gnutls pip install --no-cache-dir --no-binary pycurl -r requirements.txt

COPY app ./app

RUN mkdir -p /dumps

VOLUME ["/dumps"]

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
