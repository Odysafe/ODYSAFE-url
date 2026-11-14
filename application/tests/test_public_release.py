"""Regressions for public pages, capture defaults and idle service shutdown.

Run from application/: python -B -m unittest discover -s tests -p test_public_release.py
Set ODYSAFE_TEST_BROWSER=1 in the browser image, on the fixture network, for Chromium.
"""
import asyncio
from contextlib import closing
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import sys
from tempfile import TemporaryDirectory
import time
import unittest

from fastapi.testclient import TestClient
from jinja2 import Environment, FileSystemLoader

from app.web.main import WEB_ROOT, create_app


class Controller:
    def __init__(self):
        self.started = []

    def start(self, payload):
        self.started.append(payload)
        return {"status": "running"}

    def status(self, identifier):
        return {"status": "running"}


class PublicPages(unittest.TestCase):
    def setUp(self):
        self.directory = TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        root = Path(self.directory.name)
        self.controller = Controller()
        self.app = create_app(database_path=root / 'catalog.db', scans_root=root / 'scans',
                              testing=True, controller_client=self.controller,
                              allowed_origins=frozenset({'http://127.0.0.1:8080'}))
        self.client = self.enterContext(TestClient(self.app, base_url="http://127.0.0.1:8080"))
        self.home = self.client.get('/').text
        self.csrf = re.search(r'name="csrf" value="([^"]+)"', self.home)[1]

    def launch(self, mode, **values):
        return self.client.post('/sessions/start', data={
            'csrf': self.csrf, 'url': 'http://fixture-server:8000/simple.html',
            'mode': mode, 'network_policy': 'fixture', **values,
        }, headers={'Origin': 'http://127.0.0.1:8080'}, follow_redirects=False)

    def test_all_templates_compile_and_public_pages_render_in_both_languages(self):
        env = Environment(loader=FileSystemLoader(WEB_ROOT / 'templates'))
        for name in env.list_templates():
            with self.subTest(template=name):
                env.get_template(name)
        for language in ('fr', 'en'):
            self.client.cookies.set('odysafe_language', language)
            for path in ('/', '/engines', '/engines/yara', '/engines/ioc',
                         '/engines/dns', '/sessions', '/scans', '/settings', '/system'):
                with self.subTest(language=language, path=path):
                    self.assertEqual(self.client.get(path).status_code, 200)
            error = self.client.get('/missing', headers={'Accept': 'text/html'})
            self.assertEqual(error.status_code, 404)
            self.assertIn('text/html', error.headers['content-type'])

    def test_application_reports_its_release_version(self):
        from app import __version__
        self.assertEqual(self.app.version, __version__)

    def test_interactive_is_selected(self):
        self.assertRegex(self.home, r'name="mode" value="interactive" checked')
        self.assertNotRegex(self.home, r'name="mode" value="automatic" checked')

    def test_automatic_defaults_to_nine_seconds(self):
        response = self.launch('automatic')
        self.assertEqual(response.status_code, 303)
        self.assertEqual(self.controller.started[0]['timeout_seconds'], 9)
        with self.app.state.database.connect() as connection:
            row = connection.execute('SELECT mode,timeout_seconds FROM capture_sessions').fetchone()
        self.assertEqual(tuple(row), ('automatic', 9))

    def test_interactive_keeps_its_own_default_duration(self):
        self.launch('interactive')
        self.assertEqual(self.controller.started[0]['timeout_seconds'], 90)

    def test_short_invalid_durations_never_reach_controller(self):
        for mode, seconds in [('automatic', 8), ('interactive', 9)]:
            with self.subTest(mode=mode):
                response = self.launch(mode, timeout_seconds=seconds)
                self.assertIn('Invalid+capture+parameters', response.headers['location'])
        self.assertEqual(self.controller.started, [])

    def test_custom_nine_second_automatic_duration(self):
        self.launch('automatic', duration_mode='custom', custom_duration=9, duration_unit='seconds')
        self.assertEqual(self.controller.started[0]['timeout_seconds'], 9)


class IdleShutdown(unittest.TestCase):
    def test_backup_exits_on_term_without_waiting_for_hourly_sleep(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            with closing(sqlite3.connect(root / 'catalog.db')) as connection:
                connection.execute('CREATE TABLE evidence (id INTEGER)')
            env = dict(os.environ, ODYSAFE_DB_PATH=str(root / 'catalog.db'),
                       ODYSAFE_BACKUP_DIR=str(root / 'backups'))
            subprocess.run([sys.executable, '-B', '-m', 'app.maintenance', '--once'], env=env, check=True,
                           stdout=subprocess.DEVNULL)
            process = subprocess.Popen([sys.executable, '-B', '-m', 'app.maintenance'], env=env)
            try:
                time.sleep(0.5)
                process.terminate()
                self.assertEqual(process.wait(timeout=3), 0)
                with closing(sqlite3.connect(root / 'catalog.db')) as connection:
                    self.assertEqual(connection.execute('PRAGMA quick_check').fetchone()[0], 'ok')
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()


@unittest.skipUnless(os.environ.get('ODYSAFE_TEST_BROWSER') == '1', 'requires Chromium and fixture network')
class BrowserCapture(unittest.TestCase):
    def test_automatic_preserves_evidence_and_finishes_without_a_stop_request(self):
        from app.capture import capture
        from app.config import load_profiles, select_profile
        _, profile = select_profile(load_profiles(), 'desktop')
        profile = dict(profile, timeout_ms=9000, _allowed_origins=['http://fixture-server:8000'])
        with TemporaryDirectory() as directory:
            root = Path(directory)
            started = time.monotonic()
            result = asyncio.run(capture('http://fixture-server:8000/stage9.html', root, profile))
            self.assertEqual(result['status'], 'completed', result)
            self.assertEqual(result['errors'], [])
            self.assertGreaterEqual(time.monotonic() - started, 9)
            for name in ('network.har', 'dom.html', 'screenshot.png', 'cookies.json', 'browser_events.json'):
                self.assertTrue((root / name).is_file(), name)
            self.assertTrue(json.loads((root / 'network.har').read_text())['log']['entries'])

    def test_duration_switches_in_real_browser(self):
        from playwright.sync_api import sync_playwright
        with TemporaryDirectory() as directory:
            root = Path(directory)
            app = create_app(database_path=root / 'db', scans_root=root / 'scans',
                             testing=True, controller_client=Controller())
            with TestClient(app) as client:
                html = client.get('/').text
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(headless=True, channel="chromium")
                try:
                    page = browser.new_page()
                    # Keep all application assets local; only the scripts under test execute.
                    page.route('**/*', lambda route: route.abort())
                    page.set_content(html)
                    page.evaluate("window.ODYSAFE_I18N={setText:(n,s)=>n.textContent=s}; crypto.randomUUID=()=>String(Math.random())")
                    page.add_script_tag(content=(WEB_ROOT / 'static/app.js').read_text())
                    self.assertTrue(page.locator('[name=mode][value=interactive]').is_checked())
                    self.assertEqual(page.locator('[name=timeout_seconds]').input_value(), '90')
                    page.locator('[name=mode][value=automatic]').check()
                    self.assertEqual(page.locator('[name=timeout_seconds]').input_value(), '9')
                    self.assertEqual(page.locator('[name=timeout_seconds]').evaluate('(n)=>n.nextElementSibling.textContent'), '9 s')
                    page.locator('[name=mode][value=interactive]').check()
                    self.assertEqual(page.locator('[name=timeout_seconds]').input_value(), '90')
                    self.assertTrue(page.locator('[name=timeout_seconds] option[value="9"]').evaluate('(n)=>n.disabled'))
                finally:
                    browser.close()

    def test_controller_shutdown_finalizes_active_automatic_and_interactive_captures(self):
        import urllib.request
        import uuid
        for mode in ('automatic', 'interactive'):
            with self.subTest(mode=mode), TemporaryDirectory() as directory:
                root = Path(directory)
                env = dict(os.environ, ODYSAFE_CONTROLLER_TOKEN='local-regression-test',
                           ODYSAFE_DATA_DIR=str(root), ODYSAFE_ALLOWED_ORIGINS='http://fixture-server:8000')
                process = subprocess.Popen([sys.executable, '-B', '-m', 'app.orchestration.controller'],
                                           env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                def request(path, payload=None):
                    raw = json.dumps(payload).encode() if payload is not None else None
                    req = urllib.request.Request('http://127.0.0.1:8765' + path, data=raw,
                                                 headers={'X-ODYSAFE-Token': 'local-regression-test',
                                                          'Content-Type': 'application/json'})
                    with urllib.request.urlopen(req, timeout=2) as response:
                        return json.load(response)
                try:
                    deadline = time.monotonic() + 10
                    while True:
                        try:
                            request('/healthz')
                            break
                        except OSError:
                            if time.monotonic() > deadline:
                                self.fail('Controller did not become ready')
                            time.sleep(0.1)
                    session_id, scan_id = str(uuid.uuid4()), str(uuid.uuid4())
                    request('/v1/sessions', dict(session_id=session_id, scan_id=scan_id,
                            url='http://fixture-server:8000/stage9.html', mode=mode,
                            profile='desktop', timeout_seconds=60, network_policy='fixture'))
                    deadline = time.monotonic() + 20
                    while request('/v1/sessions/' + session_id)['status'] != 'running':
                        if time.monotonic() > deadline:
                            self.fail('Capture did not start')
                        time.sleep(0.1)
                    time.sleep(2)
                    process.terminate()
                    self.assertEqual(process.wait(timeout=42), 0)
                    evidence = root / 'scans' / scan_id
                    metadata = json.loads((evidence / 'meta.json').read_text())
                    self.assertEqual(metadata['status'], 'completed', metadata)
                    self.assertTrue((evidence / 'network.har').is_file())
                    self.assertTrue((evidence / 'report.json').is_file())
                finally:
                    if process.poll() is None:
                        process.kill()
                        process.wait()
