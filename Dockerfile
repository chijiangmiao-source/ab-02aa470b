FROM python:3.11-slim

WORKDIR /srv

# 零三方依赖：仅使用 Python 标准库。
COPY app ./app

ENV APP_HOST=0.0.0.0 \
    APP_PORT=8000 \
    APP_DB=/data/directory.db \
    PYTHONUNBUFFERED=1

EXPOSE 8000
VOLUME ["/data"]

HEALTHCHECK --interval=5s --timeout=3s --retries=10 --start-period=3s \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=5).status == 200 else 1)"

CMD ["python", "-m", "app.server"]
