# Deployment Guide

## Local Development
1. Create a virtual environment.
2. Install dependencies from requirements.txt.
3. Start the backend with uvicorn.
4. Start the frontend with npm run dev.

## Docker
Run:
```bash
docker-compose up --build
```

## Production Notes
- Replace SQLite with PostgreSQL.
- Configure environment variables in .env.
- Set a strong SECRET_KEY.
