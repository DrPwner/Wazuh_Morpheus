"""
Backup service: compresses Wazuh rule files on a schedule.
Uses APScheduler for scheduling.
"""
import os
import gzip
import shutil
import json
import logging
from datetime import datetime

logger = logging.getLogger(__name__)
_scheduler = None


def init_backup_scheduler(app):
    global _scheduler
    cfg = app.config['CONFIG'].get('backup', {})
    if not cfg.get('enabled', False):
        return

    try:
        from apscheduler.schedulers.background import BackgroundScheduler
        from apscheduler.triggers.cron import CronTrigger
        from apscheduler.triggers.interval import IntervalTrigger

        _scheduler = BackgroundScheduler(daemon=True)

        schedule_type = cfg.get('schedule_type', 'daily')
        H = int(cfg.get('schedule_hour', 23))
        M = int(cfg.get('schedule_minute', 59))

        if schedule_type == 'daily':
            trigger = CronTrigger(hour=H, minute=M)
        elif schedule_type in ('interval', 'hourly'):
            trigger = IntervalTrigger(hours=int(cfg.get('interval_hours', 24)))
        elif schedule_type == 'every_n_days':
            from datetime import datetime, timedelta
            days = max(1, int(cfg.get('interval_days', 2)))
            now = datetime.now()
            next_run = now.replace(hour=H, minute=M, second=0, microsecond=0)
            if next_run <= now:
                next_run += timedelta(days=1)
            trigger = IntervalTrigger(days=days, start_date=next_run)
        elif schedule_type == 'weekly':
            days_list = cfg.get('schedule_days_of_week') or ['mon']
            trigger = CronTrigger(day_of_week=','.join(days_list), hour=H, minute=M)
        else:
            trigger = CronTrigger(hour=H, minute=M)

        _scheduler.add_job(
            func=run_backup,
            args=[app],
            trigger=trigger,
            id='wazuh_backup',
            replace_existing=True
        )
        _scheduler.start()
        logger.info('Backup scheduler started')
    except ImportError:
        logger.warning('APScheduler not available; scheduled backups disabled')
    except Exception as e:
        logger.error(f'Failed to start backup scheduler: {e}')


def reload_scheduler(app):
    global _scheduler
    if _scheduler and _scheduler.running:
        _scheduler.shutdown(wait=False)
    _scheduler = None
    init_backup_scheduler(app)


def run_backup(app):
    """Execute a backup run immediately."""
    with app.app_context():
        from ..database import get_db
        cfg = app.config['CONFIG'].get('backup', {})
        db = get_db()

        files_to_backup = cfg.get('files_to_backup', [])
        backup_dir = os.path.join(
            app.config['BASE_DIR'],
            cfg.get('backup_dir', 'data/backups')
        )
        compress = cfg.get('compress', True)
        keep_last_n = cfg.get('keep_last_n', 30)

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        run_dir = os.path.join(backup_dir, timestamp)
        os.makedirs(run_dir, exist_ok=True)

        cur = db.execute(
            "INSERT INTO backup_runs (started_at, status) VALUES (datetime('now'), 'in_progress')"
        )
        run_id = cur.lastrowid
        db.commit()

        backed_up = []
        total_size = 0
        errors = []

        for src_path in files_to_backup:
            if not os.path.exists(src_path):
                errors.append(f'File not found: {src_path}')
                continue
            try:
                fname = os.path.basename(src_path)
                dest = os.path.join(run_dir, fname)
                shutil.copy2(src_path, dest)

                if compress:
                    gz_path = dest + '.gz'
                    with open(dest, 'rb') as f_in:
                        with gzip.open(gz_path, 'wb') as f_out:
                            shutil.copyfileobj(f_in, f_out)
                    os.remove(dest)
                    dest = gz_path

                size = os.path.getsize(dest)
                total_size += size
                backed_up.append({'src': src_path, 'dest': dest, 'size': size})
            except Exception as e:
                errors.append(f'Failed to backup {src_path}: {e}')

        # Cleanup old backups
        try:
            all_runs = sorted(
                [d for d in os.listdir(backup_dir)
                 if os.path.isdir(os.path.join(backup_dir, d))],
                reverse=True
            )
            for old_run in all_runs[keep_last_n:]:
                shutil.rmtree(os.path.join(backup_dir, old_run), ignore_errors=True)
        except Exception as e:
            errors.append(f'Cleanup failed: {e}')

        status = 'success' if not errors else ('partial' if backed_up else 'failed')
        db.execute(
            '''UPDATE backup_runs SET status = ?, files_backed_up = ?, backup_path = ?,
               size_bytes = ?, completed_at = datetime('now'),
               error_message = ? WHERE id = ?''',
            (status, json.dumps(backed_up), run_dir, total_size,
             '\n'.join(errors) if errors else None, run_id)
        )
        db.commit()

        logger.info(f'Backup {run_id}: {status} - {len(backed_up)} files, {total_size} bytes')

        return {
            'run_id': run_id,
            'status': status,
            'files_backed_up': len(backed_up),
            'total_size': total_size,
            'backup_path': run_dir,
            'errors': errors,
        }
