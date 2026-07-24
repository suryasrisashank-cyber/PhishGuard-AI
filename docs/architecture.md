# Architecture Overview

## Components
- Backend: FastAPI service handling authentication, scanning, dashboard, and ML endpoints.
- Frontend: React + Tailwind dashboard for scan submission and visualization.
- ML: Scikit-learn, XGBoost, and LightGBM training pipeline stored in ml/models.
- Database: SQLite for local development, extendable to PostgreSQL.
- Deployment: Docker Compose for local orchestration.

## Data Flow
1. User sends a scan request from the React dashboard.
2. FastAPI routes forward the request to scanner and intelligence services.
3. Results are persisted in the SQLite database.
4. Dashboard queries the database for stats and recent results.
