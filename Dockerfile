# Python 3.12 use karo kyunki mitmproxy 12.x ko yahi chahiye
FROM python:3.12-slim

# System dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Requirements install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Pura code copy
COPY . .

# Ports expose
EXPOSE 10000
EXPOSE 9944

# Script run
CMD ["python", "axcanmol.py"]
