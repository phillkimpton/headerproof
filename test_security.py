"""Regression tests for untrusted input and safe report output, using synthetic data."""
import contextlib
import csv
import datetime
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import Mock, patch
from html.parser import HTMLParser

import headerproof as hp


class Security(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.generated = datetime.datetime.now(datetime.timezone.utc)

    def error_record(self, text):
        return {'target': 'example.com', 'error': text,
                '_meta': {'http_code': '200'}, '_scanerror': True, '_problems': 0}

    def test_csv_formula_prefixes_are_literal(self):
        targets = ['=1+1', '+1', '-1', '@value', '  =1+1', '＝1+1']
        hp.render_csv([], [{'target': t, 'dns': 'NODNS', 'http_code': '000'} for t in targets], self.root / 'r.csv')
        with (self.root / 'r.csv').open() as stream:
            rows = list(csv.DictReader(stream))
        self.assertEqual([r['target'] for r in rows], ["'" + t for t in targets])
        self.assertEqual(hp.csv_value('example.com'), 'example.com')

    def test_controls_are_escaped_in_text_and_xlsx_but_preserved_in_json(self):
        from openpyxl import load_workbook
        raw = 'bad\x1b[31m\x00response\n\u202e\ud800'
        records = [self.error_record(raw)]
        hp.render_txt(records, [], self.root / 'r.txt')
        hp.render_xlsx(records, [], self.root / 'r.xlsx')
        hp.render_json(records, [], self.root / 'r.json')
        self.assertNotIn('\x1b', (self.root / 'r.txt').read_text())
        self.assertIn('\\u001b', (self.root / 'r.txt').read_text())
        wb = load_workbook(self.root / 'r.xlsx')
        self.assertEqual(wb['Not assessed']['C2'].value, hp.display_text(raw))
        wb.close()
        self.assertEqual(json.loads((self.root / 'r.json').read_text())['live'][0]['error'], raw)

    def test_html_untrusted_values_cannot_add_markup(self):
        class Tags(HTMLParser):
            def __init__(self):
                super().__init__()
                self.tags = []
                self.attrs = []
            def handle_starttag(self, tag, attrs):
                self.tags.append(tag)
                self.attrs.extend(attrs)
        payload = '\"><img src=x onerror=alert(1)><script>alert(1)</script>\ud800'
        record = self.error_record(payload)
        record['target'] = payload
        hp.render_html([record], [{'target': payload, 'dns': 'NODNS', 'http_code': '000'}], self.root / 'r.html')
        parser = Tags()
        parser.feed((self.root / 'r.html').read_text())
        self.assertEqual(parser.tags.count('script'), 1)
        self.assertNotIn('img', parser.tags)
        self.assertFalse(any(name.startswith('on') for name, value in parser.attrs))

    def test_invalid_hostnames_and_argument_options_rejected(self):
        for target in ('=1+1', '--file', 'a' * 64 + '.example.com', 'example..com', 'https://example.com/\x1b'):
            with self.subTest(target=target), self.assertRaises(ValueError):
                hp.target_parts(target)
        self.assertEqual(hp.target_parts('https://example.com:443/path'), ('example.com', 443))

    def test_https_flag_schema_rejected(self):
        record = {'headers': {}, 'https': {'supported': '=1+1'}}
        with patch.object(hp.subprocess, 'run', return_value=Mock(returncode=0, stdout=json.dumps(record), stderr='')):
            self.assertEqual(hp.scan_one('example.com')['error'], 'unparseable scanner output')

    def test_failed_render_preserves_existing_file_and_removes_temporary(self):
        path = self.root / 'r.json'
        path.write_text('original')
        def fail(records, dead, destination, generated):
            Path(destination).write_text('partial')
            raise OSError('disk error')
        with self.assertRaises(OSError):
            hp.write_report(fail, [], [], str(path), self.generated)
        self.assertEqual(path.read_text(), 'original')
        self.assertEqual(list(self.root.iterdir()), [path])

    @unittest.skipUnless(os.name == 'posix', 'POSIX permission and symlink semantics')
    def test_atomic_write_does_not_follow_file_symlink_and_is_private(self):
        original = self.root / 'original'
        original.write_text('preserve')
        destination = self.root / 'r.json'
        destination.symlink_to(original)
        hp.write_report(hp.render_json, [], [], str(destination), self.generated)
        self.assertEqual(original.read_text(), 'preserve')
        self.assertFalse(destination.is_symlink())
        self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o600)
        self.assertEqual(json.loads(destination.read_text())['live_count'], 0)

    def test_missing_scanner_fails_before_probe(self):
        with patch.object(hp.shutil, 'which', return_value=None), \
             patch.object(hp.importlib.util, 'find_spec', return_value=None), \
             patch.object(hp, 'check_live') as probe:
            with self.assertRaisesRegex(RuntimeError, 'pipx install secheaders'):
                hp.main(['example.com', '--outdir', str(self.root)])
            probe.assert_not_called()

    def test_cli_expected_failures_have_no_traceback(self):
        for error, code in ((OSError('cannot write'), 1), (RuntimeError('missing'), 1), (KeyboardInterrupt(), 130)):
            stderr = io.StringIO()
            with patch.object(hp, 'main', side_effect=error), contextlib.redirect_stderr(stderr):
                self.assertEqual(hp.cli(), code)
            self.assertNotIn('Traceback', stderr.getvalue())

    def test_controls_in_output_name_rejected_before_work(self):
        with patch.object(hp, 'check_live') as probe, contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as error:
                hp.main(['example.com', '--name', 'report\x00'])
            self.assertEqual(error.exception.code, 2)
            probe.assert_not_called()


if __name__ == '__main__':
    unittest.main()
