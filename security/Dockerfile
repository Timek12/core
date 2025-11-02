FROM python:3.11-slim

WORKDIR /app

# Install system dependencies including PostgreSQL dev headers
RUN apt-get update && apt-get install -y \
    postgresql-client \
    libpq-dev \
    gcc \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY . /app

RUN mkdir -p /app/api /app/services /app/repositories /app/dto

EXPOSE 8001

CMD ["python", "main.py"]