FROM python:3.12-slim

RUN apt-get update && apt-get install -y \
    build-essential libffi-dev libssl-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

# Hugging Face Spaces ke liye port 7860 zaroori hai
EXPOSE 7860

CMD ["python", "axcanmol.py"]
