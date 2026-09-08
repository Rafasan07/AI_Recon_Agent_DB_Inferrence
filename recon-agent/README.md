1. Send HTTP probes to the target API
2. Feed the response to GPT-4o
3. Parse GPT-4o's output (next probe + updated schema)
4. Repeat until schema is fully inferred

to run sqlmap
sqlmap -u "http://localhost:8081/users?id=1" --batch --level=3 --risk=2 --schema --output-dir=results/sqlmap 2>&1 | tee results/sqlmap_run.txt
