from .service import verify_chain

if __name__ == "__main__":
    import json
    print(json.dumps(verify_chain(), indent=2))