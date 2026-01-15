# Contributing to NetGraph

Thank you for your interest in contributing to NetGraph! This document provides guidelines and instructions for contributing.

## Code of Conduct

Please be respectful and constructive in all interactions. We want to maintain a welcoming community for everyone.

## Getting Started

### Prerequisites

- Python 3.10 or higher
- Git
- An AWS account (for testing against real infrastructure)

### Development Setup

1. **Fork and clone the repository**

   ```bash
   git clone https://github.com/ayushgoel24/mcp-netgraph.git
   cd mcp-netgraph
   ```

2. **Create a virtual environment**

   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

3. **Install dependencies**

   ```bash
   pip install -e ".[dev]"
   ```

4. **Verify your setup**

   ```bash
   pytest                 # Run tests
   mypy src/              # Type checking
   ruff check src/ tests/ # Linting
   ```

## How to Contribute

### Reporting Bugs

Before submitting a bug report:

1. Search existing issues to avoid duplicates
2. Use the latest version of NetGraph
3. Collect relevant information:
   - Python version (`python --version`)
   - Package version (`pip show aws-vpc-analyzer`)
   - Full error message and stack trace
   - Minimal reproduction steps

When submitting, include:

- Clear, descriptive title
- Steps to reproduce the issue
- Expected vs actual behavior
- Relevant logs (sanitize any AWS resource IDs or sensitive info)

### Suggesting Features

We welcome feature suggestions! Please open an issue describing:

- The problem you're trying to solve
- Your proposed solution
- Alternative approaches you've considered
- Any relevant examples or use cases

### Submitting Pull Requests

1. **Create a branch**

   ```bash
   git checkout -b feat/your-feature-name
   # or
   git checkout -b fix/your-bug-fix
   ```

2. **Make your changes**

   - Write clear, well-documented code
   - Follow existing code style (enforced by ruff)
   - Add tests for new functionality
   - Update documentation if needed

3. **Run quality checks**

   ```bash
   # Run all checks
   pytest                      # Tests pass
   mypy src/                   # No type errors
   ruff check src/ tests/      # No lint errors
   ruff format src/ tests/     # Code formatted
   ```

4. **Write a good commit message**

   ```
   feat(core): add support for Transit Gateway traversal

   - Add TGW node type to graph model
   - Implement TGW route handling in PathAnalyzer
   - Add unit tests for TGW scenarios

   Closes #123
   ```

   Use conventional commit prefixes:
   - `feat:` - New feature
   - `fix:` - Bug fix
   - `docs:` - Documentation only
   - `test:` - Adding/updating tests
   - `refactor:` - Code refactoring
   - `style:` - Formatting changes
   - `ci:` - CI/CD changes

5. **Submit the PR**

   - Reference any related issues
   - Describe what changed and why
   - Include test plan or verification steps

## Development Guidelines

### Code Style

- Follow PEP 8 (enforced by ruff)
- Use type hints for all function signatures
- Maximum line length: 100 characters
- Use double quotes for strings

### Testing

- Write unit tests for all new functionality
- Use `pytest` and `pytest-asyncio` for async tests
- Mock AWS calls using `moto` library
- Aim for 80%+ code coverage

```bash
# Run tests with coverage
pytest --cov=src/netgraph --cov-report=term-missing
```

### Architecture

The codebase follows a layered architecture:

```
MCP Layer (server.py)
    ↓
Core Engine (core/)
    ↓
Rule Evaluators (evaluators/)
    ↓
AWS Client (aws/)
    ↓
Data Models (models/)
```

Key principles:

- **Lazy loading**: Fetch AWS resources JIT, not upfront
- **Deterministic traversal**: Use LPM routing, not BFS/DFS
- **Graceful degradation**: Return `UNKNOWN` (not `BLOCKED`) on permission errors
- **Stateless evaluation**: NACLs require return path verification

### Documentation

- Update README.md for user-facing changes
- Add docstrings for public APIs
- Update CHANGELOG.md for notable changes
- Add examples to `docs/examples.md` for new features

## Questions?

If you have questions about contributing, please open an issue with the "question" label.

Thank you for contributing to NetGraph!
