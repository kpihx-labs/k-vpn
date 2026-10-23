SHELL := /bin/zsh
.DEFAULT_GOAL := help
.PHONY: help sync check uv-link build publish push
help:
	@printf '%s\n' 'sync: synchronize the project environment' 'check: lint, types and offline regression tests' 'uv-link: install this checkout in editable mode' 'build: validate and build sdist/wheel in dist/' 'publish: build and publish to PyPI (with-env make publish)' 'push: push the current branch to every remote in parallel using xargs'
sync:
	uv sync
check: sync
	ruff check src tests
	ruff format --check src tests
	uv run python -m compileall -q src
	pyright --pythonpath .venv/bin/python src
	uv run python -m unittest discover -s tests -v
uv-link:
	uv tool install --editable . --force
build: check
	rm -rf dist
	uv build --out-dir dist
publish: build
	@test -n "$$UV_PUBLISH_TOKEN" || { printf '%s\n' 'UV_PUBLISH_TOKEN is missing. Run with-env make publish in an interactive tmux pane.' >&2; exit 1; }
	uv publish dist/*
push:
	@branch="$$(git symbolic-ref --quiet --short HEAD)" || { printf '%s\n' 'Cannot push a detached HEAD.' >&2; exit 1; }; \
	remotes="$$(git remote)"; \
	test -n "$$remotes" || { printf '%s\n' 'No Git remotes configured.' >&2; exit 1; }; \
	printf '%s\n' "$$remotes" | tr '\n' '\0' | xargs -0 -r -P 0 -I '{}' git push -- '{}' "$$branch"
