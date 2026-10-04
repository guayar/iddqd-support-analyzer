FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libxml2-dev \
    libxslt1-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements-core.txt .
RUN pip install --no-cache-dir -r requirements-core.txt

COPY app.py actions.py config.py modules.py reporting.py uploads.py kb_ui.py kb_rendering.py ./
COPY VERSION ./
COPY analyzers/*.py ./analyzers/

ENV PYTHONUNBUFFERED=1
ENV IDDQD_EDITION=light
ENV APP_HOST=0.0.0.0

EXPOSE 7860

CMD ["python", "app.py"]
