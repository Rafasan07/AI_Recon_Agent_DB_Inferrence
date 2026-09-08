# FastAPI Target + Recon Agent

This repository is a small local security-research environment designed to test SQL-injection reconnaissance workflows against a deliberately vulnerable API. It contains two main parts:

- `fastapi-target/`: a deliberately insecure FastAPI application with SQLite-backed endpoints that leak query errors and schema hints
- `recon-agent/`: a lightweight agent that probes the target, reads responses, and tries to infer the database schema using a local LLM

This project is intended for authorized security research, training, and controlled experimentation in isolated environments only.

## Project overview

The target app is intentionally noisy and vulnerable. It exposes a set of endpoints that directly interpolate untrusted input into SQL queries without sanitization. The responses are verbose, including raw SQL errors, the original query text, and database-level hints. That makes it useful for testing an AI or automated recon agent that is learning to infer schema and exploit injection surfaces from API behavior.

The recon agent complements this by acting as a probing system:

1. It generates likely API endpoints.
2. It sends crafted probes to the target.
3. It reads HTTP responses and SQL errors.
4. It updates a schema hypothesis.
5. It chooses the next injection probe based on the hints it receives.

## Repository structure

```text
fastapi-target/
├── app/
│   └── main.py              # Vulnerable FastAPI server
├── Dockerfile               # Container build for the target app
├── docker-compose.yml       # Local container orchestration
├── requirements.txt         # Runtime dependencies for the target app
├── README.md                # Quick notes for the vulnerable API
└── research.db              # SQLite database created at runtime

recon-agent/
├── agent.py                 # Local LLM-driven reconnaissance agent
├── requirements.txt         # Agent dependencies
├── results/                 # Output artifacts from probe runs
└── README.md                # Short notes on the recon workflow
```

## Target application details

The target service lives in `fastapi-target/app/main.py` and is a SQLite-backed e-commerce-style API with the following tables:

- `users`
- `products`
- `orders`
- `order_items`
- `reviews`

Each table is seeded with realistic sample data. The API intentionally exposes many endpoints that build raw SQL using string interpolation. For example:

- `GET /users?id=<value>`
- `GET /users/search?username=<value>`
- `GET /products?id=<value>`
- `GET /products/search?name=<value>`
- `GET /orders?user_id=<value>`
- `GET /order-items?order_id=<value>`
- `GET /reviews?product_id=<value>`
- `GET /browse?table=<name>`
- `GET /health`

The most relevant challenge endpoint is `/browse`, which allows direct table selection and is designed to reveal table names and schema-related errors. The app returns verbose JSON responses including:

- full SQL query text
- database error messages
- type hints such as `OperationalError` or `DatabaseError`
- a narrow but useful schema leak when the query fails

This is intentionally high-verbosity behavior and is the core of the challenge.

## How the target app behaves

The app creates the SQLite database on startup and seeds the tables with demo records. It is built around a helper function named `run_query()` that executes raw SQL input directly and catches SQLite errors. If an error occurs, the response includes:

- the original SQL query
- the exact SQLite error message
- a hint describing the likely issue

This makes it easy for a reconnaissance agent to infer:

- whether the endpoint is injectable
- which tables exist
- which columns are exposed
- how to adjust a payload for UNION-based or error-based probing

## Local setup

### Prerequisites

- Python 3.11+
- pip
- Docker and Docker Compose (optional, for containerized runs)
- Ollama (if you intend to run the LLM-based recon agent locally)

### 1) Create and activate a virtual environment

From the workspace root:

```bash
python -m venv .venv
. .venv/bin/activate
```

On Windows PowerShell:

```powershell
python -m venv .venv
. .\.venv\Scripts\Activate.ps1
```

### 2) Install target app dependencies

```bash
cd fastapi-target
pip install -r requirements.txt
```

### 3) Run the target API locally

```bash
cd fastapi-target
uvicorn app.main:app --host 0.0.0.0 --port 8081 --reload
```

The app will be available at:

- `http://localhost:8081/health`
- `http://localhost:8081/users?id=1`

### 4) Run with Docker (optional)

```bash
cd fastapi-target
docker compose up --build
```

This exposes the app on port `8081` and persists SQLite data in a Docker volume.

## Example probes

The project is designed around payloads like these:

```bash
curl "http://localhost:8081/health"
curl "http://localhost:8081/users?id=1"
curl "http://localhost:8081/users?id=1'"
curl "http://localhost:8081/browse?table=nonexistent"
```

The intentionally invalid payloads trigger SQLite errors that reveal the underlying query structure and table names.

## Recon agent setup

The recon agent is located in `recon-agent/` and is designed to interact with the vulnerable target using a local LLM. It uses an OpenAI-compatible client pointed at Ollama by default.

### Install agent dependencies

```bash
cd recon-agent
pip install -r requirements.txt
```

### Configure Ollama

Make sure you have Ollama running locally and a compatible model available. The default configuration in `agent.py` points to:

- base URL: `http://localhost:11434/v1`
- model: `llama3.1:8b`

If needed, pull the model first:

```bash
ollama pull llama3.1:8b
```

### Run the agent

```bash
cd recon-agent
python agent.py
```

The agent attempts to:

- generate realistic endpoint candidates
- issue HTTP probes against the target
- capture responses and SQL errors
- infer schema and table relationships
- decide the next payload to test based on prior results

## Agent behavior in brief

The agent logic is built around the idea that SQL errors are rich hints. When a response indicates a missing table, missing column, or syntax issue, the agent interprets the message and chooses the next endpoint or injection pattern accordingly. This simulates an automated recon workflow that depends heavily on error semantics rather than arbitrary fuzzing.

It stores output in `recon-agent/results/`, which contains JSON artifacts and local SQLMap output for review.

## Security and usage notes

This project intentionally exposes vulnerable patterns and should not be deployed outside a strictly controlled environment.

Use it only when:

- you are working in a local or isolated testing environment
- you have explicit authorization to test the target
- you understand that the app is intentionally insecure

Do not expose the API publicly or run it on a shared network. The purpose is research and controlled demonstration, not production deployment.

## Why this project exists

The repository is useful for studying:

- SQL-injection recon workflows
- how LLM agents interpret error-based hints
- schema inference from API responses
- local experimentation with AI-driven offensive security tooling

It is a compact example of a target application paired with an autonomous probing agent, designed to demonstrate how a model can infer database structure from noisy but informative error messages.

## Quick start summary

```bash
# Terminal 1: start target app
cd fastapi-target
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8081 --reload

# Terminal 2: start recon agent
cd ../recon-agent
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
python agent.py
```

## License and intent

This project is intentionally built for educational and research-oriented security exploration in a secure local environment. It is not intended for production use or public exposure.
