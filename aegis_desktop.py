"""Aegis as a desktop app: runs the server in the background and shows the dashboard in its own window."""
import logging, threading, time, webbrowser
import app as A
logging.getLogger("werkzeug").setLevel(logging.ERROR)
url = f"http://127.0.0.1:{A.CFG['port']}/_aegis/"
if __name__ == "__main__":
    A.start_background()
    threading.Thread(target=lambda: A.app.run(host=A.CFG["host"], port=A.CFG["port"], threaded=True), daemon=True).start()
    time.sleep(1.5)
    try:
        import webview
        webview.settings['ALLOW_DOWNLOADS'] = True
        webview.create_window("Aegis", url, width=1250, height=820); webview.start()
    except ImportError:
        webbrowser.open(url)
        while True: time.sleep(3600)
