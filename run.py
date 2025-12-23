# run.py
import os
import sys
import threading
import time
import webbrowser
from dotenv import load_dotenv

# --------------------------------------------------
# Resource path helper (works for Nuitka & source)
# --------------------------------------------------
def get_resource_path(relative_path: str) -> str:
    if getattr(sys, "frozen", False):  # Nuitka compiled
        base_path = os.path.dirname(sys.executable)
    else:
        base_path = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base_path, relative_path)

# --------------------------------------------------
# Load .env automatically
# --------------------------------------------------
dotenv_path = get_resource_path(".env")
if os.path.exists(dotenv_path):
    load_dotenv(dotenv_path)

# --------------------------------------------------
# Ensure runtime directories
# --------------------------------------------------
for folder in ("logs", "cache"):
    os.makedirs(get_resource_path(folder), exist_ok=True)

# --------------------------------------------------
# Open browser after Streamlit boots
# --------------------------------------------------
def open_browser():
    time.sleep(3)
    webbrowser.open("http://localhost:8501")

# --------------------------------------------------
# Run Streamlit internally (Streamlit 1.37 compatible)
# --------------------------------------------------
def run_streamlit():
    from streamlit.web import bootstrap

    app_path = get_resource_path("app.py")

    # These replace CLI flags
    args = []
    flag_options = {
        "server.address": "127.0.0.1",
        "server.port": 8501,
        "server.headless": True,
        "browser.gatherUsageStats": False,
    }

    bootstrap.run(
        main_script_path=app_path,
        is_hello=False,
        args=args,
        flag_options=flag_options,
    )

# --------------------------------------------------
# Entry point
# --------------------------------------------------
if __name__ == "__main__":
    threading.Thread(target=open_browser, daemon=True).start()
    run_streamlit()
