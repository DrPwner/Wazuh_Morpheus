"""
Background monitor for Wazuh indexer (OpenSearch/Elasticsearch) health.

Two monitor types:
  - cluster_health: periodically checks /_cluster/health for status (green/yellow/red),
    node count, shard health. Alerts based on alert_on threshold.
  - log_activity: periodically checks latest document freshness via timestamp comparison.
    Alerts when no new data arrives within the configured threshold.

Each monitor entry has its own check_interval_seconds.
"""
import threading
import time
import copy
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

_running = False
_thread = None
_last_results = {}
# Track the previous latest timestamp per indexer for staleness comparison
_prev_timestamps = {}
# Track when each host was last checked (for per-host intervals)
_last_checked = {}


def start_indexer_monitor(app):
    global _running, _thread
    if _thread and _thread.is_alive():
        return
    _running = True
    _thread = threading.Thread(
        target=_indexer_monitor_worker, args=(app,), daemon=True,
        name='indexer-monitor'
    )
    _thread.start()
    logger.info('Indexer monitor started')


def get_indexer_status():
    """Return a copy of the latest results (called by health API)."""
    return copy.deepcopy(_last_results)


def _check_cluster_health(indexer):
    """GET /_cluster/health — returns cluster status dict."""
    import requests
    url = indexer['url'].rstrip('/')
    try:
        resp = requests.get(
            url + '/_cluster/health',
            auth=(indexer.get('username', ''), indexer.get('password', '')),
            verify=indexer.get('verify_ssl', False),
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json()
        return {
            'status': data.get('status', 'unknown'),
            'number_of_nodes': data.get('number_of_nodes', 0),
            'active_primary_shards': data.get('active_primary_shards', 0),
            'unassigned_shards': data.get('unassigned_shards', 0),
            'error': None,
        }
    except Exception as e:
        return {
            'status': 'unreachable',
            'number_of_nodes': 0,
            'active_primary_shards': 0,
            'unassigned_shards': 0,
            'error': str(e),
        }


def _check_latest_document(indexer):
    """Query for the most recent document and check freshness."""
    import requests
    url = indexer['url'].rstrip('/')
    try:
        pattern = indexer.get('index_pattern', 'wazuh-alerts-*')
        resp = requests.get(
            url + '/' + pattern + '/_search',
            json={
                'size': 1,
                'sort': [{'@timestamp': {'order': 'desc'}}],
                '_source': ['@timestamp'],
            },
            auth=(indexer.get('username', ''), indexer.get('password', '')),
            verify=indexer.get('verify_ssl', False),
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json()
        hits = data.get('hits', {}).get('hits', [])
        if not hits:
            return {
                'latest_timestamp': None,
                'is_current': False,
                'age_minutes': None,
                'age_hours': None,
                'timestamp_changed': False,
                'error': 'No documents found in ' + pattern + ' indices',
            }

        ts_str = hits[0].get('_source', {}).get('@timestamp', '')
        try:
            raw_ts = ts_str
            if ts_str.endswith('Z'):
                ts_str = ts_str[:-1] + '+00:00'
            ts = datetime.fromisoformat(ts_str)
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            age_seconds = (now - ts).total_seconds()
            age_minutes = round(age_seconds / 60, 1)
            age_hours = round(age_seconds / 3600, 1)
        except Exception:
            raw_ts = ts_str
            age_minutes = None
            age_hours = None

        threshold = int(indexer.get('no_new_data_minutes', 10))
        return {
            'latest_timestamp': raw_ts,
            'is_current': age_minutes is not None and (threshold <= 0 or age_minutes < threshold),
            'age_minutes': age_minutes,
            'age_hours': age_hours,
            'timestamp_changed': True,  # Updated by caller after comparison
            'error': None,
        }
    except Exception as e:
        return {
            'latest_timestamp': None,
            'is_current': False,
            'age_minutes': None,
            'age_hours': None,
            'timestamp_changed': False,
            'error': str(e),
        }


def _should_alert(indexer, cluster, doc):
    """Determine if an alert should fire for this indexer check."""
    monitor_type = indexer.get('type', 'cluster_health')

    if monitor_type == 'cluster_health':
        # Connection error
        if cluster.get('error'):
            return True
        # Cluster status check
        status = cluster.get('status', 'unknown')
        alert_on = indexer.get('alert_on', 'red')
        if alert_on == 'any' and status != 'green':
            return True
        if alert_on == 'yellow' and status in ('yellow', 'red'):
            return True
        if alert_on == 'red' and status == 'red':
            return True

    elif monitor_type == 'log_activity':
        # Connection/query error — always alert regardless of quiet hours
        if doc.get('error'):
            return True
        # During quiet hours, suppress stale-data and age-threshold alerts
        try:
            from ..notifications.email_service import is_quiet_hours
            from flask import current_app
            if is_quiet_hours(current_app.config['CONFIG']):
                return False
        except Exception:
            pass
        # Timestamp unchanged between consecutive checks (stale data)
        if not doc.get('timestamp_changed', True):
            return True
        # No-data threshold: alert if latest doc is older than configured minutes
        threshold_min = int(indexer.get('no_new_data_minutes', 10))
        age_min = doc.get('age_minutes')
        if age_min is not None and threshold_min > 0 and age_min >= threshold_min:
            return True

    return False


def _send_indexer_alert(indexer, cluster, doc):
    """Send notification email for an indexer issue."""
    try:
        from ..notifications.email_service import send_notification
        monitor_type = indexer.get('type', 'cluster_health')
        age = doc.get('age_hours') if doc else None
        age_str = (str(age) + ' hours') if age is not None else 'unknown'

        reasons = []
        if monitor_type == 'cluster_health':
            if cluster.get('error'):
                reasons.append('Connection error: ' + cluster['error'])
            elif cluster.get('status') in ('red', 'yellow', 'unreachable'):
                reasons.append('Cluster status: ' + cluster.get('status'))
        elif monitor_type == 'log_activity':
            if doc.get('error'):
                reasons.append(doc['error'])
            if not doc.get('timestamp_changed', True):
                reasons.append('Latest document unchanged between checks (stale)')
            age_min = doc.get('age_minutes')
            threshold = int(indexer.get('no_new_data_minutes', 10))
            if age_min is not None and threshold > 0 and age_min >= threshold:
                reasons.append('No new data for %.0f minutes (threshold: %d min)' % (age_min, threshold))

        send_notification('indexer_issue', {
            'indexer_name': indexer.get('name', 'Unknown'),
            'indexer_url': indexer.get('url', ''),
            'monitor_type': monitor_type,
            'cluster_status': cluster.get('status', 'n/a') if cluster else 'n/a',
            'nodes': cluster.get('number_of_nodes', 0) if cluster else 0,
            'unassigned_shards': cluster.get('unassigned_shards', 0) if cluster else 0,
            'latest_document': doc.get('latest_timestamp') or 'none' if doc else 'none',
            'document_age': age_str,
            'index_pattern': indexer.get('index_pattern', 'n/a'),
            'error': '; '.join(reasons) if reasons else '',
        })
    except Exception as e:
        logger.error('Failed to send indexer alert: %s', e)


def _indexer_monitor_worker(app):
    global _running, _last_results, _prev_timestamps, _last_checked
    with app.app_context():
        config = app.config['CONFIG']
        tick = 10  # check every 10s if any host is due

        while _running:
            hosts = config.get('indexers', {}).get('hosts', [])
            now = time.time()

            for indexer in hosts:
                if not indexer.get('enabled', True):
                    continue

                name = indexer.get('name', indexer.get('url', 'unknown'))
                interval = max(30, int(indexer.get('check_interval_seconds', 120)))

                # Skip if not yet due
                if name in _last_checked and (now - _last_checked[name]) < interval:
                    continue
                _last_checked[name] = now

                monitor_type = indexer.get('type', 'cluster_health')
                cluster = None
                doc = None

                if monitor_type == 'cluster_health':
                    cluster = _check_cluster_health(indexer)
                elif monitor_type == 'log_activity':
                    doc = _check_latest_document(indexer)
                    # Compare latest timestamp with previous check
                    current_ts = doc.get('latest_timestamp')
                    prev_ts = _prev_timestamps.get(name)
                    if prev_ts is not None and current_ts is not None:
                        doc['timestamp_changed'] = (current_ts != prev_ts)
                    else:
                        doc['timestamp_changed'] = True
                    _prev_timestamps[name] = current_ts

                _last_results[name] = {
                    'name': name,
                    'url': indexer.get('url', ''),
                    'type': monitor_type,
                    'cluster': cluster,
                    'latest_doc': doc,
                    'index_pattern': indexer.get('index_pattern', ''),
                    'no_new_data_minutes': int(indexer.get('no_new_data_minutes', 10)),
                    'check_interval_seconds': interval,
                    'checked_at': datetime.now(timezone.utc).isoformat(),
                }

                should = _should_alert(indexer, cluster, doc)
                if should:
                    _send_indexer_alert(indexer, cluster, doc)

            time.sleep(tick)
