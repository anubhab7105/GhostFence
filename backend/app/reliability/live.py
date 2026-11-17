"""Live LLM reliability runner (requires gateway provider key)."""

import os
import sys

def main():
    if not os.getenv("ANTHROPIC_API_KEY") and not os.getenv("GHOSTFENCE_ANTHROPIC_API_KEY"):
        print("missing provider key in gateway environment")
        raise SystemExit(2)
    print("not implemented: live LLM runner")
    raise SystemExit(0)

if __name__ == "__main__":
    main()