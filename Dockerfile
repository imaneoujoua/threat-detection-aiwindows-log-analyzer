FROM python:3.9-slim

LABEL maintainer="Imane Oujoua <imanoujoua@gmail.com>"
LABEL description="CyberShield AI - Threat Detection System"

WORKDIR /app

RUN apt-get update && apt-get install -y gcc && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p data/raw data/processed data/models logs database reports

EXPOSE 5000 8050

CMD ["python", "app/routes.py"]
