# IDDQD Support Analyzer - Docker (Light Edition)

Uruchamiaj IDDQD Light Edition na Windows/Mac/Linux za pomocą Docker'a.

## Wymagania

- **Docker Desktop** (https://www.docker.com/products/docker-desktop)
- **Port 7860** dostępny

## Quick Start

### 1. Build image
```bash
docker-compose build
```

### 2. Uruchomić aplikację
```bash
docker-compose up
```

Otwórz: http://localhost:7860

### 3. Dodaj logi do analizy

Umieść pliki logów w folderze `inputs/`:
```
./inputs/
  ├── app.log
  ├── error.log
  └── system.log
```

Wyniki analiz będą dostępne w `outputs/`

## Zaawansowane

### Stop
```bash
docker-compose down
```

### Rebuild
```bash
docker-compose build --no-cache
docker-compose up
```

### Logi
```bash
docker-compose logs -f
```

### Shell w container'e
```bash
docker-compose exec iddqd-light bash
```

## Co jest w Light Edition

✅ Log Analysis (Syslog, Windows Event Log, itp.)
✅ SAML Metadata Analysis
✅ Incident Detection
✅ Export (JSON, Markdown, CSV)

❌ LLM Features (Full Edition only)
❌ Vision Analysis (Full Edition only)

## Volumes

- `./inputs/` → Twoje pliki logów
- `./outputs/` → Wyniki analiz

## Troubleshooting

**Port 7860 już zajęty?**
```yaml
# docker-compose.yml - zmień:
ports:
  - "8080:7860"  # Potem otwórz http://localhost:8080
```

**Out of memory?**
```bash
docker-compose up --memory 2g
```

## Updates

Każdy `git pull` pobrze nową wersję Light Edition.
Rebuild image:
```bash
docker-compose build --no-cache
docker-compose up
```

---

**Light Edition** - all-in-one SAML/Log analyzer w jednym container'e. 🐳
