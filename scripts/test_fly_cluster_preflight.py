"""Pure/temp-file controls; no Fly, subprocess, container or native execution."""
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock


PROFILE = Path(__file__).resolve().parents[1] / 'deploy/fly/cluster'
SPEC = importlib.util.spec_from_file_location('fly_preflight_renderer', PROFILE / 'render.py')
renderer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(renderer)


class CapabilityControls(unittest.TestCase):
    def test_unsupported_verification_refuses_before_render_or_output_access(self):
        with mock.patch.object(renderer, 'safe_verification_available', return_value=False), \
                mock.patch.object(renderer, 'render') as render, \
                mock.patch.object(renderer, 'open_output_directory') as opened:
            with self.assertRaisesRegex(renderer.ProfileError, 'safe-output-verification-unavailable'):
                renderer.verify_output({}, '/never-opened')
            render.assert_not_called()
            opened.assert_not_called()

    def test_existing_rendering_remains_available_without_verification_capability(self):
        data = renderer.load_inventory(PROFILE / 'inventory.example.json')
        with tempfile.TemporaryDirectory(prefix='fly-render-portable-') as temporary, \
                mock.patch.object(renderer, 'safe_verification_available', return_value=False):
            manifest = renderer.render_to(data, Path(temporary) / 'out', example=True)
            self.assertTrue(manifest['example_only'])
            self.assertFalse(manifest['live_deployment_authorized'])


@unittest.skipUnless(renderer.safe_verification_available(), 'POSIX no-follow descriptor traversal required')
class OutputVerificationControls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='fly-preflight-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.output = self.root / 'output'
        self.data = renderer.load_inventory(PROFILE / 'inventory.example.json')
        renderer.render_to(self.data, self.output, example=True)
        self.inventory = self.root / 'inventory.json'
        self.inventory.write_bytes(renderer.json_bytes(self.data))

    def verify(self, output=None, data=None):
        return renderer.verify_output(self.data if data is None else data,
                                      self.output if output is None else output, example=True)

    def snapshot(self):
        return {str(p.relative_to(self.output)): (p.read_bytes(), p.stat().st_mode,
                p.stat().st_mtime_ns) for p in self.output.rglob('*') if p.is_file()}

    def cli(self, output=None, extra=()):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            result = renderer.main(['--inventory', str(self.inventory), '--verify-output',
                                    str(self.output if output is None else output), '--example', *extra])
        return result, stdout.getvalue(), stderr.getvalue()

    def test_exact_output_passes_without_writes_or_render_to(self):
        original = self.snapshot()
        with mock.patch.object(renderer, 'render_to', side_effect=AssertionError('verification wrote output')):
            result, stdout, stderr = self.cli()
        self.assertEqual(result, 0)
        self.assertEqual(stderr, '')
        self.assertIn('Verified rendered bytes for five example profiles', stdout)
        self.assertIn('no deployment or readiness verified', stdout)
        self.assertEqual(self.snapshot(), original)

    def test_same_length_content_and_self_rehashed_manifest_are_refused(self):
        target = self.output / 'relay-a/fly.toml'
        before = target.read_bytes()
        after = before.replace(b'soft_limit = 900', b'soft_limit = 800')
        self.assertNotEqual(before, after)
        self.assertEqual(len(before), len(after))
        target.write_bytes(after)
        manifest = json.loads((self.output / 'manifest.json').read_bytes())
        manifest['files']['relay-a/fly.toml'] = hashlib.sha256(after).hexdigest()
        (self.output / 'manifest.json').write_bytes(renderer.json_bytes(manifest))
        with self.assertRaisesRegex(renderer.ProfileError, 'rendered-file-mismatch'):
            self.verify()

    def test_tls_verification_change_is_refused(self):
        target = self.output / 'relay-a/fly.toml'
        original = target.read_bytes()
        changed = original.replace(b'tls_skip_verify = false', b'tls_skip_verify = true ')
        self.assertNotEqual(original, changed)
        self.assertEqual(len(original), len(changed))
        target.write_bytes(changed)
        with self.assertRaisesRegex(renderer.ProfileError, 'rendered-file-mismatch'):
            self.verify()

    def test_changed_authoritative_inventory_is_refused(self):
        data = copy.deepcopy(self.data)
        data['relays'][0]['memory_mb'] += 256
        with self.assertRaises(renderer.ProfileError):
            self.verify(data=data)

    def test_changed_authoritative_template_is_refused(self):
        profile = self.root / 'profile'
        shutil.copytree(PROFILE / 'templates', profile / 'templates')
        template = profile / 'templates/relay-fly.toml.in'
        template.write_bytes(template.read_bytes().replace(b'soft_limit = 900', b'soft_limit = 800'))
        with mock.patch.object(renderer, 'ROOT', profile), self.assertRaises(renderer.ProfileError):
            self.verify()

    def test_missing_manifest_file_and_role_are_refused(self):
        for relative in ('manifest.json', 'relay-a/relay.toml', 'redis'):
            with self.subTest(relative=relative):
                target = self.output / relative
                retained = self.root / 'retained'
                target.rename(retained)
                try:
                    with self.assertRaisesRegex(renderer.ProfileError, 'rendered-tree-mismatch'):
                        self.verify()
                finally:
                    retained.rename(target)

    def test_unknown_root_and_nested_paths_are_refused_before_read(self):
        for parent in (self.output, self.output / 'authority'):
            extra = parent / 'credential-SENTINEL'
            extra.write_bytes(b'PRIVATE-SENTINEL')
            try:
                status, stdout, stderr = self.cli()
                self.assertEqual(status, 1)
                self.assertEqual(stdout, '')
                self.assertEqual(stderr, 'fly-cluster: rendered-tree-mismatch\n')
            finally:
                extra.unlink()

    def test_exact_names_still_refuse_directory_in_file_slot(self):
        target = self.output / 'manifest.json'
        target.unlink()
        target.mkdir()
        with self.assertRaisesRegex(renderer.ProfileError, 'rendered-file-refused'):
            self.verify()

    def test_fifo_is_refused_before_any_read(self):
        target = self.output / 'manifest.json'
        target.unlink()
        os.mkfifo(target)
        with mock.patch.object(renderer.os, 'read', side_effect=AssertionError('read a FIFO')):
            with self.assertRaisesRegex(renderer.ProfileError, 'rendered-file-refused'):
                self.verify()

    def test_hardlinked_file_is_refused(self):
        os.link(self.output / 'manifest.json', self.root / 'linked-manifest')
        with self.assertRaisesRegex(renderer.ProfileError, 'rendered-file-refused'):
            self.verify()

    def test_root_and_ancestor_symlinks_are_not_followed(self):
        root_link = self.root / 'output-link'
        root_link.symlink_to(self.output, target_is_directory=True)
        ancestor_link = self.root / 'ancestor-link'
        ancestor_link.symlink_to(self.root, target_is_directory=True)
        for path in (root_link, ancestor_link / 'output'):
            with self.subTest(path=path), self.assertRaises(OSError):
                self.verify(output=path)

    def test_role_and_file_symlinks_are_not_followed(self):
        for relative in ('manifest.json', 'redis'):
            with self.subTest(relative=relative):
                target = self.output / relative
                retained = self.root / 'retained'
                target.rename(retained)
                target.symlink_to(retained, target_is_directory=retained.is_dir())
                try:
                    with self.assertRaises(OSError):
                        self.verify()
                finally:
                    target.unlink()
                    retained.rename(target)

    def test_file_replaced_with_symlink_after_inventory_is_not_followed(self):
        actual_open = os.open
        target = self.output / 'manifest.json'
        outside = self.root / 'outside'
        outside.write_bytes(b'SENTINEL')

        def replace_then_open(name, flags, *args, **kwargs):
            if name == 'manifest.json':
                target.unlink()
                target.symlink_to(outside)
            return actual_open(name, flags, *args, **kwargs)

        with mock.patch.object(renderer, 'safe_verification_available', return_value=True), \
                mock.patch.object(renderer.os, 'open', side_effect=replace_then_open), \
                mock.patch.object(renderer.os, 'read', side_effect=AssertionError('followed replacement')):
            with self.assertRaises(OSError):
                self.verify()

    def test_size_mismatch_refuses_before_read_and_expected_bounds_refuse_before_open(self):
        target = self.output / 'manifest.json'
        target.write_bytes(target.read_bytes() + b' ')
        with mock.patch.object(renderer.os, 'read', side_effect=AssertionError('read oversized file')):
            with self.assertRaisesRegex(renderer.ProfileError, 'rendered-file-refused'):
                self.verify()
        expected = renderer.render(self.data, example=True)
        expected['manifest.json'] = b'x' * (renderer.MAX_RENDERED_FILE + 1)
        with mock.patch.object(renderer, 'render', return_value=expected), \
                mock.patch.object(renderer, 'open_output_directory') as opened:
            with self.assertRaisesRegex(renderer.ProfileError, 'rendered-output-bound'):
                self.verify()
            opened.assert_not_called()

    def test_directory_walk_stops_at_first_unexpected_entry(self):
        consumed = []

        class Entry:
            name = 'unexpected'

        def entries():
            consumed.append(1)
            yield Entry()
            raise AssertionError('enumerated beyond first mismatch')

        with mock.patch.object(renderer.os, 'scandir', return_value=contextlib.nullcontext(entries())):
            with self.assertRaisesRegex(renderer.ProfileError, 'rendered-tree-mismatch'):
                renderer.exact_directory_entries(-1, {'manifest.json'})
        self.assertEqual(consumed, [1])

    def test_content_read_remains_bounded_and_detects_growth(self):
        actual_read = os.read
        requests = []

        def growing_read(descriptor, count):
            requests.append(count)
            if len(requests) == 1:
                return b'x' * count
            raise AssertionError('read beyond expected size plus one')

        with renderer.open_output_directory(self.output) as directory, \
                mock.patch.object(renderer.os, 'read', side_effect=growing_read):
            with self.assertRaisesRegex(renderer.ProfileError, 'rendered-file-mismatch'):
                renderer.verify_rendered_file(directory, 'manifest.json',
                                              (self.output / 'manifest.json').read_bytes())
        self.assertEqual(len(requests), 1)
        self.assertLessEqual(requests[0], renderer.MAX_RENDERED_FILE + 1)
        self.assertIs(renderer.os.read, actual_read)

    def test_file_metadata_change_during_read_is_refused(self):
        actual_fstat = os.fstat
        calls = []
        with renderer.open_output_directory(self.output) as directory:
            def changed_fstat(descriptor):
                info = actual_fstat(descriptor)
                calls.append(descriptor)
                if len(calls) == 2:
                    changed = mock.Mock(wraps=info)
                    for attr in ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns'):
                        setattr(changed, attr, getattr(info, attr))
                    changed.st_ctime_ns += 1
                    return changed
                return info
            with mock.patch.object(renderer.os, 'fstat', side_effect=changed_fstat):
                with self.assertRaisesRegex(renderer.ProfileError, 'rendered-file-changed-during-verification'):
                    renderer.verify_rendered_file(directory, 'manifest.json',
                                                  (self.output / 'manifest.json').read_bytes())

    def test_root_directory_change_after_enumeration_is_refused(self):
        actual_verify = renderer.verify_rendered_file

        def change_after_manifest(directory, name, expected):
            observed = actual_verify(directory, name, expected)
            if name == 'manifest.json':
                (self.output / 'unexpected').write_bytes(b'not read')
            return observed

        with mock.patch.object(renderer, 'verify_rendered_file', side_effect=change_after_manifest):
            with self.assertRaisesRegex(renderer.ProfileError, 'rendered-directory-changed-during-verification'):
                self.verify()

    def test_output_path_replacement_is_refused(self):
        actual_verify = renderer.verify_rendered_file

        def replace_after_manifest(directory, name, expected):
            observed = actual_verify(directory, name, expected)
            if name == 'manifest.json':
                retained = self.root / 'retained-output'
                self.output.rename(retained)
                shutil.copytree(retained, self.output)
            return observed

        with mock.patch.object(renderer, 'verify_rendered_file', side_effect=replace_after_manifest):
            with self.assertRaisesRegex(renderer.ProfileError, 'rendered-(?:directory-changed-during-verification|output-path-changed)'):
                self.verify()

    def test_earlier_file_mutated_while_later_files_are_read_is_refused(self):
        actual_verify = renderer.verify_rendered_file
        changed = []

        def change_earlier_file(directory, name, expected):
            observed = actual_verify(directory, name, expected)
            if name != 'manifest.json' and not changed:
                target = self.output / 'manifest.json'
                content = bytearray(target.read_bytes())
                content[0] = ord('[')
                target.write_bytes(content)
                changed.append(True)
            return observed

        with mock.patch.object(renderer, 'verify_rendered_file', side_effect=change_earlier_file):
            with self.assertRaisesRegex(renderer.ProfileError, 'rendered-file-changed-before-completion'):
                self.verify()
        self.assertEqual(changed, [True])

    def test_nonexistent_output_is_not_created_and_errors_are_closed(self):
        missing = self.root / 'SECRET-SENTINEL' / 'out'
        status, stdout, stderr = self.cli(output=missing)
        self.assertEqual(status, 1)
        self.assertEqual(stdout, '')
        self.assertEqual(stderr, 'fly-cluster: profile-input-or-output-refused\n')
        self.assertFalse(missing.parent.exists())

    def test_example_selection_and_mutually_exclusive_actions_remain_required(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as caught:
            renderer.main(['--inventory', str(self.inventory), '--output', str(self.root / 'new'),
                           '--verify-output', str(self.output), '--example'])
        self.assertEqual(caught.exception.code, 2)
        self.assertFalse((self.root / 'new').exists())
        with self.assertRaisesRegex(renderer.ProfileError, 'purpose-requires-explicit-example-selection'):
            renderer.verify_output(self.data, self.output)


if __name__ == '__main__':
    unittest.main()
