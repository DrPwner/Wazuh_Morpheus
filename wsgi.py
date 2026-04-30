"""
WSGI entry point — run with waitress (Windows-compatible production server):

    pip install waitress
    python wsgi.py

Or directly:
    waitress-serve --call "wsgi:create_app"
"""
import os
import json
from app import create_app

app = create_app()

if __name__ == '__main__':
    from waitress import serve

    config_path = os.path.join(os.path.dirname(__file__), 'config.json')
    with open(config_path) as f:
        cfg = json.load(f)

    host = cfg['app'].get('host', '0.0.0.0')
    port = cfg['app'].get('port', 5000)
    threads = cfg['app'].get('wsgi_threads', 8)

    print(f'Starting waitress on {host}:{port} ({threads} threads)')
    serve(app, host=host, port=port, threads=threads)
