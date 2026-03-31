import os

import uvicorn


def main() -> None:
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "8000"))
    uvicorn.run(
        "api_keys_service.app:app",
        host=host,
        port=port,
        factory=False,
    )


if __name__ == "__main__":
    main()
