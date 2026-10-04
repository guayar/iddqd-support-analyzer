FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libxml2-dev \
    libxslt1-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements-core.txt .
RUN pip install --no-cache-dir -r requirements-core.txt

COPY app.py actions.py config.py modules.py reporting.py uploads.py ./
COPY analyzers/*.py ./analyzers/
COPY templates/ ./templates/

ENV PYTHONUNBUFFERED=1
EXPOSE 7860

CMD ["python", "app.py"]
