# ScamDefender.ai IPQS API Starter

Production ready Node API that powers your browser extension with real URL and email risk checks via IPQualityScore.

## Features
- Endpoints: POST /v1/check and POST /v1/check_email
- Health endpoint: GET /healthz
- CORS, Helmet, and rate limiting enabled
- Maps IPQS fields to verdict, confidence, and human readable evidence

## Setup
1. Copy .env.example to .env and set IPQS_KEY.
2. Install dependencies.
```bash
npm install
```
3. Run locally.
```bash
npm run dev
```

## Docker
```bash
docker build -t scamdefender-ipqs .
docker run -e IPQS_KEY=your_key -p 8080:8080 scamdefender-ipqs
```

Compose:
```bash
IPQS_KEY=your_key docker compose up --build
```

## Deploy on Render
- New Web Service
- Build command: npm install
- Start command: npm start
- Env vars: IPQS_KEY, PORT, CORS_ORIGIN

## API
See server.js for request and response examples.
