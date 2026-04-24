.PHONY: up up-demo down logs backend agent clean

up:
	docker compose up --build

up-demo:
	docker compose --profile demo-agent up --build

down:
	docker compose down

logs:
	docker compose logs -f

backend:
	cd backend && pip install -r requirements.txt && \
	  DATABASE_URL=sqlite:///./cyberassetiq.db uvicorn app:app --host 0.0.0.0 --port 8000 --reload

agent:
	cd agent && pip install -r requirements.txt && \
	  uvicorn service.main:app --host 0.0.0.0 --port 8099 --reload

clean:
	docker compose down -v
	find . -name "*.pyc" -delete
	find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
