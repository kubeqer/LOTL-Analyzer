from __future__ import annotations

import uvicorn

from lotl_backend.app import app


def main() -> None:
    uvicorn.run(app, host="0.0.0.0", port=8080)


if __name__ == "__main__":
    main()
