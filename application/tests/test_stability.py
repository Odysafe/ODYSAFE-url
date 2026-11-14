"""Release regressions: navigation, invalid input, recovery and retained backups."""
from contextlib import closing
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import re
import sqlite3
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import uuid

from fastapi.testclient import TestClient
from app.database import reconcile_scans
from app.orchestration import ControllerUnavailable
from app.web.main import create_app


class Controller:
    def start(self, payload):
        raise ControllerUnavailable('Temporarily unavailable')


class WebStability(unittest.TestCase):
    def setUp(self):
        self.directory = TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.app = create_app(database_path=self.root/'catalog.db', scans_root=self.root/'scans',
                              testing=True, controller_client=Controller())
        self.client = self.enterContext(TestClient(self.app, base_url='http://127.0.0.1:8080'))
        self.csrf = re.search(r'name="csrf" value="([^"]+)"', self.client.get('/').text)[1]

    def post(self, path, **data):
        return self.client.post(path, data={'csrf': self.csrf, **data},
                                headers={'Origin': 'http://127.0.0.1:8080', 'Accept': 'text/html'},
                                follow_redirects=False)

    def test_engine_views_and_editors_in_both_languages(self):
        for language in ('en', 'fr'):
            self.client.cookies.set('odysafe_language', language)
            for engine in ('yara', 'ioc', 'dns'):
                for view in ('library', 'analyze', 'results', 'providers', 'settings', 'checks'):
                    with self.subTest(language=language, engine=engine, view=view):
                        self.assertEqual(self.client.get(f'/engines/{engine}?view={view}').status_code, 200)
            for path in ('/engines/ioc?new=1', '/engines/yara?new=1',
                         '/engines/ioc?edit=missing', '/engines/yara?edit=missing'):
                self.assertLess(self.client.get(path).status_code, 500)

    def test_invalid_ioc_and_yara_forms_render_useful_errors(self):
        response = self.post('/iocs/save', ioc_type='domain', value='https://invalid/path')
        self.assertEqual(response.status_code, 400)
        self.assertIn('text/html', response.headers['content-type'])
        for name, source in [('invalid name!', 'rule x { condition: true }'), ('ValidName', 'not a rule')]:
            self.assertLess(self.post('/rules/save', name=name, source=source).status_code, 500)

    def test_library_save_edit_move_and_archive(self):
        from app.rules.library import EngineLibrary
        for engine, path, data in [('ioc', '/iocs/save', dict(ioc_type='domain', value='example.org')),
                                   ('yara', '/rules/save', dict(name='RegressionRule', source='rule RegressionRule { condition: true }'))]:
            with self.subTest(engine=engine):
                response = self.post(path, **data)
                self.assertEqual(response.status_code, 303, response.text)
                self.assertEqual(self.client.get(response.headers['location']).status_code, 200)
                registry = self.app.state.iocs if engine == 'ioc' else self.app.state.rules
                identifier = next(item['id'] for item in registry.list() if item.get('name') == 'RegressionRule' or item.get('original_value') == 'example.org')
                folder = EngineLibrary(self.app.state.database, engine).save_folder('Regression folder')
                self.assertEqual(self.post(f'/engines/{engine}/move', selected=[identifier], folder_id=folder).status_code, 303)
                self.assertEqual(registry.get(identifier)['folder_id'], folder)
                prefix = 'iocs' if engine == 'ioc' else 'rules'
                self.assertEqual(self.post(f'/{prefix}/{identifier}/state/archive').status_code, 303)
                self.assertEqual(self.client.get(f'/engines/{engine}?folder=archive').status_code, 200)

    def test_csrf_and_unknown_resources_return_errors_without_server_failure(self):
        self.assertEqual(self.post('/settings', csrf='expired', page_size=25).status_code, 403)
        for path in ('/scans/not-a-uuid', '/scans/'+str(uuid.uuid4()), '/sessions/not-a-uuid/connect'):
            self.assertEqual(self.client.get(path, headers={'Accept': 'text/html'}).status_code, 404)
        self.assertEqual(self.client.get('/scans/export.xlsx').status_code, 409)
        self.assertEqual(self.post('/engines/ioc/analyze').status_code, 400)
        self.assertEqual(self.post('/engines/unknown/prepare').status_code, 404)

    def test_dns_settings_and_custom_resolver_validation(self):
        self.assertEqual(self.post('/settings/dns', concurrency=0).status_code, 400)
        self.assertEqual(self.post('/settings/dns/custom', name='Invalid', address='127.0.0.1').status_code, 400)
        self.assertEqual(self.post('/settings/dns/custom', name='Test resolver', address='8.8.8.8').status_code, 303)
        self.assertEqual(self.post('/settings/dns/custom', name='Duplicate', address='8.8.8.8').status_code, 409)
        self.assertEqual(self.client.get('/engines/dns?view=settings').status_code, 200)

    def test_controller_failure_does_not_leave_capture_capacity_locked(self):
        for _ in range(3):
            response = self.post('/sessions/start', mode='automatic', url='http://fixture-server:8000/simple.html')
            self.assertEqual(response.status_code, 303)
            self.assertNotIn('Controller+busy', response.headers['location'])
        with self.app.state.database.connect() as connection:
            states = [row[0] for row in connection.execute('SELECT status FROM capture_sessions')]
        self.assertEqual(states, ['failed']*3)
        self.assertEqual(self.client.get('/sessions').status_code, 200)

    def test_partial_investigation_remains_browsable(self):
        identifier = str(uuid.uuid4())
        directory = self.root/'scans'/identifier
        directory.mkdir()
        (directory/'meta.json').write_text(json.dumps({'submitted_url': 'http://fixture-server:8000/simple.html', 'status':'interrupted'}))
        # A crash may leave missing or incomplete artifacts; the UI must still open.
        (directory/'report.json').write_text('{')
        reconcile_scans(self.app.state.database, self.root/'scans')
        for section in ('overview', 'hosts', 'network', 'navigation', 'behavior', 'detections', 'artifacts', 'indicators', 'threat_intelligence'):
            with self.subTest(section=section):
                self.assertEqual(self.client.get(f'/scans/{identifier}?section={section}').status_code, 200)


class MaintenanceStability(unittest.TestCase):
    def test_repeated_snapshots_are_closed_rotated_and_verifiable(self):
        from app import maintenance
        with TemporaryDirectory() as directory:
            root = Path(directory)
            database = root/'catalog.db'
            with closing(sqlite3.connect(database)) as connection:
                connection.execute('CREATE TABLE evidence (id INTEGER)')
                connection.commit()
            baseline = len(list(Path('/proc/self/fd').iterdir()))
            start = datetime(2026, 1, 1, tzinfo=timezone.utc)
            with patch.object(maintenance, 'DATABASE', database), patch.object(maintenance, 'BACKUPS', root/'backups'):
                for day in range(20):
                    clock = SimpleNamespace(now=lambda *_, day=day: start+timedelta(days=day))
                    with patch.object(maintenance, 'datetime', clock):
                        maintenance.backup_database()
                snapshots = maintenance.snapshots()
                self.assertEqual(len(snapshots), 14)
                for snapshot in snapshots:
                    self.assertEqual(json.loads(snapshot.with_suffix('.json').read_text())['sha256'], hashlib.sha256(snapshot.read_bytes()).hexdigest())
                    with closing(sqlite3.connect(snapshot)) as connection:
                        self.assertEqual(connection.execute('PRAGMA quick_check').fetchone()[0], 'ok')
                self.assertEqual(list((root/'backups').glob('*.tmp')), [])
            self.assertLessEqual(len(list(Path('/proc/self/fd').iterdir())), baseline+1)

    def test_session_cache_and_controller_history_remain_bounded(self):
        from app.web.security import SessionStore
        from app.orchestration import controller
        sessions = SessionStore(max_sessions=8)
        for _ in range(1000):
            sessions.create()
        self.assertEqual(len(sessions.values), 8)
        with patch.object(controller, 'SESSIONS', {str(i):{'status':'completed'} for i in range(1000)}):
            controller.reap_dead_sessions()
            self.assertEqual(len(controller.SESSIONS), 128)

    def test_dns_worker_rejects_malformed_payloads(self):
        from app.dns.worker import execute
        for payload in (None, [], 'invalid', {}, {'job_id':'x','domains':[], 'providers':['quad9'], 'custom_providers':None}):
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                execute(payload)


@unittest.skipUnless(__import__('os').environ.get('ODYSAFE_TEST_BROWSER') == '1', 'requires Chromium and fixture network')
class BrowserWorkflows(unittest.TestCase):
    def test_capture_investigation_engines_and_exports(self):
        import asyncio
        import io
        import zipfile
        from app.capture import capture
        from app.config import load_profiles, select_profile
        from app.reporting import build_report
        with TemporaryDirectory() as directory:
            root = Path(directory)
            identifier = str(uuid.uuid4())
            evidence = root/'scans'/identifier
            _, profile = select_profile(load_profiles(), 'desktop')
            profile = dict(profile, timeout_ms=9000, _scan_id=identifier,
                           _allowed_origins=['http://fixture-server:8000'])
            metadata = asyncio.run(capture('http://fixture-server:8000/stage9.html', evidence, profile))
            self.assertEqual(metadata['status'], 'completed', metadata)
            build_report(evidence)
            app = create_app(database_path=root/'catalog.db', scans_root=root/'scans', testing=True)
            with TestClient(app, base_url='http://127.0.0.1:8080') as client:
                csrf = re.search(r'name="csrf" value="([^"]+)"', client.get('/').text)[1]
                def post(path, **data):
                    return client.post(path, data={'csrf':csrf, **data},
                                       headers={'Origin':'http://127.0.0.1:8080'}, follow_redirects=False)
                for language in ('en', 'fr'):
                    client.cookies.set('odysafe_language', language)
                    for section in ('overview', 'hosts', 'network', 'navigation', 'behavior', 'detections', 'artifacts', 'indicators', 'threat_intelligence'):
                        with self.subTest(language=language, section=section):
                            self.assertEqual(client.get(f'/scans/{identifier}?section={section}').status_code, 200)
                rule = app.state.rules.save('WorkflowRule', 'rule WorkflowRule { strings: $a="Stage 9 fixture" condition: $a }')
                ioc = app.state.iocs.save('url', 'http://fixture-server:8000/stage9.html')
                for engine, registry, item in [('yara', app.state.rules, rule), ('ioc', app.state.iocs, ioc)]:
                    registry.set_state(item, 'activate')
                    self.assertEqual(post(f'/engines/{engine}/analyze', selected=[item], scan_ids=[identifier]).status_code, 200)
                    self.assertEqual(post(f'/engines/{engine}/analyze', selected=[item], scan_ids=[identifier], stage='run').status_code, 303)
                    self.assertEqual(client.get(f'/engines/{engine}?view=results').status_code, 200)
                before = set(Path('/tmp').glob('odysafe-report-*.xlsx'))
                for path in (f'/scans/{identifier}/export.xlsx', '/scans/export.xlsx'):
                    response = client.get(path)
                    self.assertEqual(response.status_code, 200)
                    with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
                        self.assertIsNone(archive.testzip())
                        self.assertIn('xl/workbook.xml', archive.namelist())
                self.assertEqual(set(Path('/tmp').glob('odysafe-report-*.xlsx')), before)
                (evidence/'downloads').mkdir(exist_ok=True)
                (evidence/'downloads'/'evidence.txt').write_text('local evidence')
                self.assertEqual(post(f'/scans/{identifier}/downloads.zip').status_code, 404)
                report = json.loads((evidence/'report.json').read_text())
                report['downloaded_files'] = [{'path':'downloads/evidence.txt', 'status':'collected'}]
                (evidence/'report.json').write_text(json.dumps(report))
                response = post(f'/scans/{identifier}/downloads.zip')
                self.assertEqual(response.status_code, 200)
                with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
                    self.assertIsNone(archive.testzip())
                    self.assertTrue(any(name.endswith('evidence.txt') for name in archive.namelist()))

    def test_demo_scripts_execute_without_syntax_errors(self):
        from playwright.sync_api import sync_playwright
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(channel="chromium")
            try:
                page = browser.new_page()
                errors = []
                page.on('pageerror', lambda error: errors.append(str(error)))
                page.goto('http://fixture-server:8000/js_redirect.html')
                page.wait_for_url('**/target.html')
                page.goto('http://fixture-server:8000/stage9.html')
                with page.expect_popup() as opened:
                    page.locator('#popup').click()
                opened.value.wait_for_url('**/target.html')
                with page.expect_download() as downloaded:
                    page.locator('#download').click()
                self.assertIsNotNone(downloaded.value.path())
                self.assertEqual(errors, [])
            finally:
                browser.close()

    def test_controller_recovers_after_malformed_requests(self):
        import os
        import subprocess
        import sys
        import time
        import urllib.error
        import urllib.request
        with TemporaryDirectory() as directory:
            process = subprocess.Popen([sys.executable, '-B', '-m', 'app.orchestration.controller'],
                         env=dict(os.environ, ODYSAFE_DATA_DIR=directory, ODYSAFE_CONTROLLER_TOKEN='protocol-regression-test'),
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                deadline = time.monotonic()+10
                while True:
                    try:
                        with urllib.request.urlopen('http://127.0.0.1:8765/healthz', timeout=1) as response:
                            self.assertEqual(response.status, 200)
                        break
                    except OSError:
                        if time.monotonic()>deadline:
                            self.fail('Controller did not start')
                        time.sleep(0.1)
                invalid_timeout = dict(url='http://fixture-server:8000/simple.html', mode='automatic',
                     profile='desktop', session_id=str(uuid.uuid4()), scan_id=str(uuid.uuid4()), timeout_seconds=None)
                for payload in (None, [], 'invalid', invalid_timeout):
                    request = urllib.request.Request('http://127.0.0.1:8765/v1/sessions',
                                data=json.dumps(payload).encode(), headers={'X-ODYSAFE-Token':'protocol-regression-test'})
                    with self.subTest(payload=payload), self.assertRaises(urllib.error.HTTPError) as error:
                        urllib.request.urlopen(request, timeout=2)
                    self.assertEqual(error.exception.code, 400)
                with urllib.request.urlopen('http://127.0.0.1:8765/healthz', timeout=2) as response:
                    self.assertEqual(json.load(response)['active'], 0)
            finally:
                process.terminate()
                try:
                    self.assertEqual(process.wait(timeout=5), 0)
                finally:
                    if process.poll() is None:
                        process.kill()
                        process.wait()
