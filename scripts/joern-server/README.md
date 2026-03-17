# Joern Server Setup

## Requirements
- docker
- docker compose

## Setup
1. Copy `.env.example` to `.env`
2. Edit `.env` for your local paths
3. Build and run:

```bash
docker compose up --build -d
```

## Default container paths

Source code: /app/source

Workspace: /app/workspace

## Default port

Joern server: 9000

## Notes

`php-cli` is installed for PHP CPG generation.

The mounted source directory can point to any supported project.