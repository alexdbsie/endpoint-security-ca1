FROM python:3.11-slim
WORKDIR /app
RUN apt-get update && apt-get install -y iptables && rm -rf /var/lib/apt/lists/*
RUN pip install flask
COPY app.py .
COPY allowlist.json .
CMD ["python", "app.py"]
