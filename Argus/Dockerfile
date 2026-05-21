FROM python:3.11-slim

WORKDIR /app

# Системни зависимости
RUN apt-get update && apt-get install -y \
    nmap \
    gobuster \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN python manage.py migrate --no-input
