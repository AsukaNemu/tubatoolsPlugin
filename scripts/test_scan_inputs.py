import contextlib
import importlib.util
import io
import json
import os
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch


def load_script(filename):
    spec = importlib.util.spec_from_file_location(filename, Path(__file__).parent / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


collect = load_script('collect-pr-files.py')
vt = load_script('virustotal-check.py')


class CollectFilesTests(unittest.TestCase):
    def test_pagination_preserves_same_basename_files_and_keeps_token_off_raw_urls(self):
        seen_pages = []

        def urlopen(request, timeout):
            url = request.full_url
            if '/files?' in url:
                page = int(url.rsplit('page=', 1)[1])
                seen_pages.append(page)
                if page == 1:
                    data = [{'filename': f'docs/{i}.md'} for i in range(99)] + [
                        {'filename': 'plugins/a/plugin.json', 'raw_url': 'https://raw.githubusercontent.com/test/a'}]
                else:
                    data = [{'filename': 'plugins/b/plugin.json', 'raw_url': 'https://raw.githubusercontent.com/test/b'}]
            elif '/pulls/1' in url:
                data = {'head': {'sha': 'fixed-head'}}
            else:
                self.assertNotIn('Authorization', request.headers)
                return io.BytesIO(url.rsplit('/', 1)[-1].encode())
            return io.BytesIO(json.dumps(data).encode())

        with tempfile.TemporaryDirectory() as directory:
            with patch.dict(os.environ, {'GITHUB_REPOSITORY': 'test/repo', 'GITHUB_TOKEN': 'dummy-token'}):
                with patch.object(collect.urllib.request, 'urlopen', side_effect=urlopen):
                    with contextlib.redirect_stdout(io.StringIO()):
                        files = collect.collect_pr_files('1', directory)
            self.assertEqual(seen_pages, [1, 2])
            self.assertEqual(len(files), 2)
            self.assertEqual((Path(directory) / 'plugins/a/plugin.json').read_bytes(), b'a')
            self.assertEqual((Path(directory) / 'plugins/b/plugin.json').read_bytes(), b'b')

    def test_empty_collection_fails(self):
        def urlopen(request, timeout):
            return io.BytesIO(json.dumps([] if '/files?' in request.full_url else {'head': {'sha': 'x'}}).encode())
        with tempfile.TemporaryDirectory() as directory:
            with patch.dict(os.environ, {'GITHUB_REPOSITORY': 'test/repo'}):
                with patch.object(collect.urllib.request, 'urlopen', side_effect=urlopen):
                    with contextlib.redirect_stdout(io.StringIO()), self.assertRaisesRegex(RuntimeError, 'No scannable'):
                        collect.collect_pr_files('1', directory)

    def test_download_failure_fails_collection(self):
        def urlopen(request, timeout):
            if 'raw.githubusercontent' in request.full_url:
                raise urllib.error.URLError('offline')
            data = [{'filename': 'a.zip', 'raw_url': 'https://raw.githubusercontent.com/test/a'}] if '/files?' in request.full_url else {'head': {'sha': 'x'}}
            return io.BytesIO(json.dumps(data).encode())
        with tempfile.TemporaryDirectory() as directory:
            with patch.dict(os.environ, {'GITHUB_REPOSITORY': 'test/repo'}):
                with patch.object(collect.urllib.request, 'urlopen', side_effect=urlopen):
                    with self.assertRaisesRegex(RuntimeError, 'Failed to download'):
                        collect.collect_pr_files('1', directory)


class VirusTotalTests(unittest.TestCase):
    def test_unknown_hash_is_not_a_clean_result(self):
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / 'tool.exe').write_bytes(b'synthetic fixture')
            with patch.dict(os.environ, {'VT_API_KEY': 'dummy-key'}):
                with patch.object(vt, 'query_virustotal', return_value={'response_code': 0}):
                    with patch.object(vt.time, 'sleep'), contextlib.redirect_stdout(io.StringIO()):
                        self.assertEqual(vt.scan_directory(directory)['status'], 'unknown')

    def test_logs_do_not_corrupt_stdout_json(self):
        output = io.StringIO()
        def scan(_):
            print('progress')
            return {'status': 'pass'}
        with patch.object(vt, 'scan_directory', side_effect=scan), patch.object(vt.sys, 'argv', ['vt', 'input']):
            with contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as result:
                    vt.main()
        self.assertEqual(result.exception.code, 0)
        self.assertEqual(json.loads(output.getvalue())['status'], 'pass')

    def test_failure_does_not_serialize_a_credential_url(self):
        output = io.StringIO()
        error = urllib.error.URLError('https://example.invalid/?apikey=fixture-secret')
        with patch.object(vt, 'scan_directory', side_effect=error), patch.object(vt.sys, 'argv', ['vt', 'input']):
            with contextlib.redirect_stdout(output), self.assertRaises(SystemExit) as result:
                vt.main()
        self.assertEqual(result.exception.code, 1)
        self.assertEqual(json.loads(output.getvalue())['status'], 'error')
        self.assertNotIn('fixture-secret', output.getvalue())


if __name__ == '__main__':
    unittest.main()
