import os
import json
from app import create_app

app = create_app()

if __name__ == '__main__':
    config_path = os.path.join(os.path.dirname(__file__), 'config.json')
    with open(config_path) as f:
        cfg = json.load(f)
    app.run(
        host=cfg['app'].get('host', '0.0.0.0'),
        port=cfg['app'].get('port', 5000),
        debug=cfg['app'].get('debug', False)
    )
