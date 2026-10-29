# Contributing to LinkArmor

Thank you for your interest in contributing to LinkArmor, an open-source machine learning and heuristic threat intelligence engine for malicious URL detection.

---

## Code of Conduct

We are committed to maintaining a welcoming, inclusive, and professional environment for all contributors and security researchers.

---

## Development Setup

### 1. Clone & Virtual Environment
```bash
git clone https://github.com/fenilsojitra242-code/linkarmor.git
cd linkarmor

python -m venv .venv
# Linux / macOS:
source .venv/bin/activate
# Windows:
.venv\Scripts\activate
```

### 2. Install Dependencies
```bash
pip install --upgrade pip
pip install -r requirements.txt
pip install pytest flake8
```

---

## Testing & Quality Assurance

Before submitting any Pull Request:
1. Ensure all unit and heuristic benchmark tests pass:
   ```bash
   pytest -v tests/
   ```
2. Ensure code follows PEP 8 standards:
   ```bash
   flake8 . --count --max-line-length=127 --statistics
   ```

---

## Pull Request Guidelines

1. Fork the repo and create a focused topic branch from `main` (e.g., `feature/entropy-heuristic` or `fix/ip-parser`).
2. Adhere to conventional commit messages (`feat:`, `fix:`, `docs:`, `test:`, `ci:`).
3. Include relevant unit tests for new heuristic extraction features.
4. Ensure CI tests pass cleanly on your fork prior to requesting review.
