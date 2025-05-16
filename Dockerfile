# Stufe 1: Installation von uv und Abhängigkeiten
FROM ghcr.io/astral-sh/uv:python3.9-bookworm AS builder

WORKDIR /app

# System-Abhängigkeiten für Build-Zwecke installieren
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Kopiere requirements.txt in das Image
COPY requirements.txt .

# Verwende uv, um die Abhängigkeiten in einen Zielordner zu installieren
RUN uv pip install --system \
    --target=/python-packages \
    -r requirements.txt

# Stufe 2: Endgültiges Anwendungsimage
FROM ghcr.io/astral-sh/uv:python3.9-bookworm

WORKDIR /app

# Systemabhängigkeiten installieren
RUN apt-get update && apt-get install -y \
    openssl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Python-Packages aus der Builder-Stage kopieren
COPY --from=builder /python-packages /usr/local/lib/python3.9/site-packages/

# Anwendungsverzeichnisse erstellen
RUN mkdir -p /app/static/css /app/static/js /app/views

# Anwendungscode kopieren
COPY app.py ssl_checker.py /app/
COPY static/ /app/static/
COPY views/ /app/views/

# Port freigeben
EXPOSE 8080

# Server starten
CMD ["python", "app.py"]

