# Contributing to ADFIR Platform

Thank you for your interest in contributing to the **Automated Digital Forensics & Incident Response Platform**! This guide will help you get started.

---

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Branching Strategy](#branching-strategy)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Pull Request Process](#pull-request-process)
- [Reporting Issues](#reporting-issues)

---

## Code of Conduct

This project adheres to the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code. Please report unacceptable behaviour to the project maintainers.

---

## Getting Started

1. **Fork** the repository on GitHub
2. **Clone** your fork locally:
   ```bash
   git clone https://github.com/<your-username>/Automated-Digital-Forensics-Incident-Response-Platform.git
   cd Automated-Digital-Forensics-Incident-Response-Platform
   ```
3. **Add the upstream** remote:
   ```bash
   git remote add upstream https://github.com/Meera1010/Automated-Digital-Forensics-Incident-Response-Platform.git
   ```

---

## Development Setup

```bash
# Create and activate a virtual environment
python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS/Linux:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Copy environment template and configure
cp .env.example .env
# Edit .env with your local settings

# Start the application
python run.py
```

Or use **Docker Compose** for a one-command setup:
```bash
docker compose up --build
```

---

## Branching Strategy

We use a simple feature-branch workflow:

| Branch | Purpose |
|--------|---------|
| `main` | Stable, production-ready code |
| `feature/<name>` | New features |
| `bugfix/<name>` | Bug fixes |
| `hotfix/<name>` | Urgent production fixes |

**Always branch from `main`** and keep your branch up to date:
```bash
git checkout main
git pull upstream main
git checkout -b feature/your-feature-name
```

---

## Coding Standards

### Python

- **Formatter**: [Black](https://github.com/psf/black) (line length: 100)
- **Linter**: [flake8](https://flake8.pycqa.org/) (line length: 100)
- **Type Hints**: Use type annotations for all function signatures
- **Docstrings**: Google-style docstrings for all public functions and classes
- **Imports**: Group imports in order: stdlib → third-party → local

```bash
# Format code
black backend/ tests/ --line-length 100

# Lint code
flake8 backend/ --max-line-length=100
```

### JavaScript / CSS

- Vanilla JS — no frameworks or build tools
- Use `const` / `let` — never `var`
- Descriptive function and variable names

### Security

- **Never** hardcode secrets — always use environment variables
- All SQL through SQLAlchemy ORM (parameterised queries)
- Input validation on every API endpoint via Marshmallow schemas

---

## Testing

All contributions **must include tests** for new functionality:

```bash
# Run all tests
pytest tests/ -v --tb=short

# Run unit tests only
pytest tests/unit/ -v

# Run integration tests only
pytest tests/integration/ -v

# Run with coverage
pytest tests/ --cov=backend
```

### Test Guidelines

- Place unit tests in `tests/unit/`
- Place integration tests in `tests/integration/`
- Place API tests in `tests/api/`
- Use fixtures from `tests/conftest.py`
- Test names should follow: `test_<function>_<scenario>_<expected_result>`

---

## Pull Request Process

1. **Ensure all tests pass** locally before submitting
2. **Run the linter** and fix any issues
3. **Update documentation** if your changes affect the API or configuration
4. **Write a clear PR description** explaining:
   - What the change does
   - Why it's needed
   - How to test it
5. **Keep PRs focused** — one feature or fix per PR
6. **Request a review** from at least one maintainer

### PR Title Format

Use conventional commit style:
- `feat: Add new detection rule for DNS tunneling`
- `fix: Correct severity scoring edge case`
- `docs: Update API reference for events endpoint`
- `test: Add integration tests for playbook execution`
- `chore: Update dependencies to latest versions`

---

## Reporting Issues

When reporting a bug, please include:

1. **Environment**: OS, Python version, PostgreSQL version
2. **Steps to reproduce**: Minimal steps to trigger the issue
3. **Expected behaviour**: What should happen
4. **Actual behaviour**: What actually happens
5. **Logs/Screenshots**: Any relevant error output

For **feature requests**, describe the use case and how it aligns with the platform's goals.

---

## Questions?

If you have questions about contributing, open a [GitHub Discussion](https://github.com/Meera1010/Automated-Digital-Forensics-Incident-Response-Platform/discussions) or reach out to the maintainers.

Thank you for helping make ADFIR better! 🛡️
