.PHONY: check test run up down logs smoke

check:
	cargo fmt --all -- --check
	cargo clippy --all-targets --all-features -- -D warnings

test:
	cargo test --all-targets

run:
	cargo run --bin jfr-server

up:
	docker compose up --build -d

down:
	docker compose down

logs:
	docker compose logs -f runtime

smoke:
	./scripts/e2e-smoke.sh

ui-smoke:
	node --experimental-websocket ./scripts/ui-smoke.mjs
