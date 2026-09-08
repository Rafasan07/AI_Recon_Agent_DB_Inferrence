Endpoint Injection Point
GET /users?id=  Numeric lookup
GET /users/search?username= String LIKE query
GET /products?id=   Numeric lookup
GET /products/search?name=String LIKE query
GET /orders?user_id=    FK lookup
GET /order-items?order_id=  FK lookup
GET /reviews?product_id=    FK lookup
GET /browse?table=  Direct table name injection 
GET /health Health check

# Test it
curl "http://localhost:8081/health"
curl "http://localhost:8081/users?id=1"

# Break it intentionally — this is what your LLM agent will see
curl "http://localhost:8081/users?id=1'"
curl "http://localhost:8081/browse?table=nonexistent"

to run locally
uvicorn app.main:app --host 0.0.0.0 --port 8081 --reload  