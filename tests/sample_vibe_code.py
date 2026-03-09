"""
Sample vibe code for testing the VibeSafe analyzer and deploy pipeline.

This script intentionally uses:
- requests (network egress)
- os (high risk - OS module)

to trigger the analyzer's security profiling.
"""

import os
import requests


def fetch_data(url: str) -> str:
    """Fetch data from a remote URL."""
    response = requests.get(url)
    return response.text


def get_env_var(name: str) -> str:
    """Read an environment variable (high risk: os access)."""
    return os.environ.get(name, "")


def main() -> None:
    api_url = get_env_var("API_URL") or "https://httpbin.org/get"
    data = fetch_data(api_url)
    print(f"Fetched {len(data)} bytes")


if __name__ == "__main__":
    main()
