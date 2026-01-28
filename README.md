# AI Bug Bounty Agent

An intelligent agent for automating bug bounty reconnaissance and vulnerability scanning using OWASP ZAP and AI-driven validation.

## Structure

- `config/`: Configuration for targets and attack rules.
- `core/`: Main orchestration logic.
- `zap/`: ZAP API client and scanning logic.
- `ai/`: AI planning and validation modules.
- `attacks/`: Implementation of specific attack vectors.
- `reporting/`: Report generation logic.
- `utils/`: Helper utilities.

## Setup

1. Install dependencies: `pip install -r requirements.txt`
2. Configure `.env` with API keys.
3. Update `config/target.yaml` with your target details.
4. Run: `python main.py`
