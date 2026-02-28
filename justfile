# justfile for proof-carrying-monitor

default: build

build:
    cargo build --workspace

test:
    cargo test --workspace

bench:
    cargo bench --workspace -- --output-format=bencher 2>&1 | tee bench-results.txt

bench-check:
    cargo bench --workspace -- --test

bench-report:
    bash scripts/bench-report.sh

fmt:
    cargo fmt --all

lint:
    cargo clippy --workspace -- -D warnings

lean-build:
    cd lean && lake build PCM

lean-proofs:
    cd lean && lake build PCMProofs

docker-up:
    docker compose up --build -d

docker-down:
    docker compose down

docker-clean:
    docker compose down -v

smoke-test:
    bash scripts/smoke-test.sh

demo: docker-up
    @echo "Waiting for services to start..."
    sleep 15
    just smoke-test

e2e-test:
    docker compose -f docker-compose.test.yml up --build --abort-on-container-exit --exit-code-from test-runner

e2e-clean:
    docker compose -f docker-compose.test.yml down -v

all: build test lint
