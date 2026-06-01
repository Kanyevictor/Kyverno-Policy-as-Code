FROM python:3.11-slim

RUN apt-get update && apt-get install -y curl && \
    curl -LO "https://dl.k8s.io/release/v1.29.0/bin/linux/amd64/kubectl" && \
    chmod +x kubectl && mv kubectl /usr/local/bin/ && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN chown -R 1000:1000 /app

EXPOSE 5000
CMD ["python", "app.py"]
