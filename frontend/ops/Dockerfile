FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    STREAMLIT_BROWSER_GATHER_USAGE_STATS=false \
    STREAMLIT_SERVER_HEADLESS=true \
    STREAMLIT_SERVER_ENABLE_XSRF_PROTECTION=true \
    STREAMLIT_SERVER_MAX_UPLOAD_SIZE=1 \
    STREAMLIT_CLIENT_TOOLBAR_MODE=minimal \
    STREAMLIT_CLIENT_SHOW_ERROR_DETAILS=false
WORKDIR /srv
RUN useradd --system --uid 10002 --home-dir /srv app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py ops_client.py ./
USER app
EXPOSE 8501
HEALTHCHECK --interval=15s --timeout=5s --retries=4 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8501/_stcore/health', timeout=3)"
CMD ["streamlit", "run", "app.py", "--server.address=0.0.0.0", "--server.port=8501"]
