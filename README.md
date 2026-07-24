 # PhishGuard AI Pro

 PhishGuard AI Pro — FastAPI backend + React/Tailwind frontend for phishing detection.

 ## Overview
 - Backend: FastAPI, SQLAlchemy (SQLite), Pydantic v2
 - Frontend: React + Vite + Tailwind CSS (recharts for charts)

 ## Local development (recommended)
 1. Ensure Python 3.14 virtualenv is active and dependencies installed:

 ```powershell
 cd "C:\Users\MAHADEV\Desktop\sashank pj"
 .venv\Scripts\python.exe -m pip install -r requirements.txt
 ```

 2. Install Node.js (required for full React dev workflow).

 ### Install Node.js on Windows (recommended):
 - Download and run the LTS installer from https://nodejs.org/en/
 - Or use nvm-windows: https://github.com/coreybutler/nvm-windows

 Verify installation in PowerShell/Terminal:
 ```powershell
 node -v
 npm -v
 ```

 3. Frontend setup and run (from project root):
 ```powershell
 cd frontend
 npm install
 npm run dev
 ```

 4. Start backend (from project root):
 ```powershell
 .venv\Scripts\python.exe -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
 ```

 5. Open the frontend (Vite) URL shown by `npm run dev` (usually http://localhost:5173) or open the static fallback at http://127.0.0.1:5173 if serving `frontend/static`.

 ## How the frontend connects to backend
 - The React app calls the backend API at `http://127.0.0.1:8000/api` by default.
 - CORS is configured on the backend to allow local development.
 - The UI auto-prepends `https://` when the user enters a domain without a scheme.

 ## Tests
 Run the backend tests (pytest):
 ```powershell
 .venv\Scripts\python.exe -m pytest -q
 ```

 ## Project layout
 - `backend/` — FastAPI backend
   - `backend/app/api/routers/` — API routes
   - `backend/app/services/` — scanning, ML, screenshot services
   - `backend/app/schemas/` — Pydantic v2 schemas
 - `frontend/` — React + Vite frontend
   - `frontend/src` — React components (new dashboard UI)
   - `frontend/static` — static fallback UI (served without Node)

 ## Screenshots
 Add screenshots to `/docs/screenshots` and reference them here.

 ## Notes & Troubleshooting
 - If the frontend fails to build, ensure Node/npm are installed and the correct Node version (LTS) is used.
 - Pydantic is v2: schemas use `model_config = {"from_attributes": True}` for ORM conversions.

 ---
 If you'd like, I can:
 - Run `npm install` and `npm run dev` here after you install Node, or
 - Add screenshot images and a short demo GIF to `README.md`.
