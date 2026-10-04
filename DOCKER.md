# IDDQD Support Analyzer - Docker (Light Edition)

Run **IDDQD Light Edition** in a container on Windows, Mac, or Linux.

## Requirements

- **Docker Desktop** (https://www.docker.com/products/docker-desktop)
- **Port 7860** available
- ~500MB disk for Light image + Knowledge Base

## Quick Start

### 1. Build image (first time only)

```bash
docker compose build
```

### 2. Run application

```bash
docker compose up -d
```

Open: **http://localhost:7860**

### 3. Analyze logs and SAML

Upload files directly in the **Analyze** tab. Knowledge Base persists in `./data/iddqd_kb.db`.

## Usage

Upload any log file or SAML trace via the web UI. Results and Knowledge Base entries are stored locally.

## Advanced Commands

### Stop container
```bash
docker compose down
```

### Rebuild from scratch
```bash
docker compose down
docker compose build --no-cache
docker compose up -d
```

### View live logs
```bash
docker compose logs -f iddqd-light
```

### Access container shell
```bash
docker compose exec iddqd-light bash
```

### Check container status
```bash
docker compose ps
```

## Persistence

The Knowledge Base is stored in `./data/iddqd_kb.db` and persists between restarts:

```bash
# Start container
docker compose up -d

# Verify Knowledge Base is created
ls -la ./data/iddqd_kb.db

# Stop container (data remains)
docker compose down

# Start again (Knowledge Base is loaded)
docker compose up -d
```

## What's included (Light Edition)

✅ **Analyze** - Log and SAML analysis  
✅ **Knowledge Base** - SQLite local database with full-text search  
✅ **Anonymize** - Structure-aware pseudonymization  
✅ **Export** - JSON, Markdown, CSV formats  

❌ **Assistant** - Not included (requires local Ollama)  
❌ **General Chat** - Not included (requires local Ollama)  

## Troubleshooting

**Port 7860 already in use?**

Edit `docker-compose.yml` and change:
```yaml
ports:
  - "8080:7860"
```

Then open: http://localhost:8080

**Container won't start?**

Check logs:
```bash
docker compose logs iddqd-light
```

**Knowledge Base not persisting?**

Verify `./data` folder exists:
```bash
mkdir -p ./data
docker compose restart
```

## Updates

Each `git pull` gets the latest Light Edition code. Rebuild the container:

```bash
docker compose build --no-cache
docker compose up -d
```

---

**Light Edition in Docker** — Analyze logs and SAML, manage a local Knowledge Base, all offline. 🐳
