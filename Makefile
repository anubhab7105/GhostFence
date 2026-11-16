.PHONY: up down test reliability bench verify

up:
	docker compose up -d --build

down:
	docker compose down -v

test:
	cd backend && pytest -q

reliability:
	cd backend && python -m app.reliability.run --runs 20

bench:
	cd backend && python -m app.bench.run

verify:
	cd backend && python -m app.audit.verify_cli