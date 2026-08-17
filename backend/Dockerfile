FROM python:3.12-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt-get/lists/*

COPY pyproject.toml .

RUN pip install --no-cache-dir pip setuptools wheel && \
    pip install --no-cache-dir "fastapi>=0.110.0" "uvicorn[standard]>=0.28.0" "pydantic>=2.6.0" "pydantic-settings>=2.2.0" "sqlalchemy>=2.0.28" "alembic>=1.13.1" "pandas>=2.2.1" "python-multipart>=0.0.9"

COPY app ./app
COPY alembic ./alembic
COPY alembic.ini .

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
