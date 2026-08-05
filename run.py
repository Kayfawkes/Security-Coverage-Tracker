import os
import threading

import uvicorn

from app.main import app, launch_browser

HOST = os.getenv("SCT_HOST", "0.0.0.0")
PORT = int(os.getenv("SCT_PORT", "7777"))

if __name__ == "__main__":
    threading.Timer(1.2, lambda: launch_browser(PORT)).start()
    print(f"Security Coverage Tracker is listening on http://{HOST}:{PORT}")
    print(f"Local access: http://127.0.0.1:{PORT}")
    print(f"LAN access: http://<THIS-PC-IP>:{PORT}")
    uvicorn.run(app, host=HOST, port=PORT, log_level="warning")
