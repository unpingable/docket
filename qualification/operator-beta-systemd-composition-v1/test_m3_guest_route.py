import tempfile
import copy
from pathlib import Path
import unittest
from unittest.mock import patch
import m3_guest_route as route


class EnrolledRouteTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.text = 'ExecStart=/usr/bin/python3.11 -m labelwatch.maintenance_step --step /var/lib/constellation-m3/run/step.json --expected-sha256 ' + 'a' * 64 + '\nRestart=no\n'
        self.root = root
        self.candidate = {'step': str(root / 'step.json'), 'step_sha256': 'a' * 64, 'action': 'stage', 'qualification_interruption': None, 'qualification_restore_substitution': False, 'unit_sha256': route.digest(self.text.encode())}
        self.candidate['unit'] = route.unit_name(self.candidate)
        (root / self.candidate['unit']).write_text(self.text)

    def test_positive_unit_is_not_instrumented(self):
        self.assertEqual(route.enrolled_unit(self.candidate), self.text.encode())

    def test_each_closed_cut_preserves_producer_seal(self):
        for cut in route.CUTS:
            with self.subTest(cut=cut):
                self.candidate['qualification_interruption'] = cut
                self.candidate['unit'] = route.unit_name(self.candidate)
                (self.root / self.candidate['unit']).write_text(self.text)
                self.assertEqual(route.enrolled_unit(self.candidate), self.text.encode())

    def test_changed_unit_or_unknown_cut_refuses(self):
        with self.assertRaises(ValueError):
            self.candidate['qualification_interruption'] = 'other'
            route.enrolled_unit(self.candidate)
        self.candidate['qualification_interruption'] = None
        self.candidate['unit_sha256'] = '0' * 64
        with self.assertRaises(ValueError):
            route.enrolled_unit(self.candidate)

    def test_conflicting_or_relabelled_modes_refuse(self):
        self.candidate['qualification_interruption'] = 'before_started'
        with self.assertRaises(ValueError):
            route.enrolled_unit(self.candidate)
        self.candidate['qualification_restore_substitution'] = True
        with self.assertRaises(ValueError):
            route.unit_name(self.candidate)

    def test_restore_is_sealed_and_stage_only(self):
        self.candidate['qualification_restore_substitution'] = True
        self.candidate['unit'] = route.unit_name(self.candidate)
        (self.root / self.candidate['unit']).write_text(self.text)
        self.assertEqual(route.enrolled_unit(self.candidate), self.text.encode())
        self.candidate['action'] = 'cleanup'
        with self.assertRaises(ValueError):
            route.unit_name(self.candidate)

    def test_cleanup_action_cannot_be_relabelled_as_fixture_admission(self):
        step = {'schema': 'labelwatch.sqlite-relief-step/v1', 'action': 'cleanup', 'revision': 'b' * 40}
        raw = route.canonical(step)
        candidate = dict(self.candidate, schema='labelwatch.m3-enrollment-candidate/v1',
                         source_revision='b' * 40, status='NOT_ENROLLED_NOT_AUTHORIZED',
                         step_sha256=route.digest(raw), action='stage')
        candidate['unit'] = route.unit_name(candidate)
        with patch.object(route, 'enrolled_unit') as fragment:
            with self.assertRaisesRegex(ValueError, 'metadata differs'):
                route.validate_candidate(candidate, raw)
            fragment.assert_not_called()

    def test_malformed_digest_rejected_before_unit_path_construction(self):
        for sha in ('../other', 'A' * 64, 'g' * 64, 'a' * 63):
            with self.assertRaises(ValueError):
                route.unit_name(dict(self.candidate, step_sha256=sha))

    def test_reconnect_cannot_adopt_or_restart_existing_route_output(self):
        with patch.object(route.os, 'geteuid', return_value=0), patch.object(route.subprocess, 'run') as run:
            with self.assertRaisesRegex(RuntimeError, 'absent evidence destination'):
                route.execute(self.root / 'missing-candidate.json', self.root, None)
            run.assert_not_called()

    def test_native_request_is_bound_to_real_predecessor_chain_and_operation(self):
        journal = self.root / 'journal'
        journal.mkdir()
        ready = {}
        for number, role in enumerate(('main', 'discovery'), start=10):
            path = self.root / (role + '.json')
            path.write_bytes(route.canonical({'pid': number, 'start_ticks': number * 100}))
            ready[role] = str(path)
        base = {'schema': 'labelwatch.sqlite-relief-step/v1', 'operation': 'same-operation',
                'source': str(self.root / 'source.sqlite'), 'original': str(self.root / 'original.sqlite'),
                'backup': str(self.root / 'backup.sqlite'), 'restore': str(self.root / 'restore.sqlite'),
                'revision': 'b' * 40, 'expected': {'table': 'é😀\u007f'}, 'source_identity': {'inode': 1},
                'journal': str(journal), 'action': 'stage', 'predecessor': None, 'predecessor_sha256': None, 'ready_records': ready}
        binding = route.digest(route.canonical({key: value for key, value in base.items() if key not in {'action', 'predecessor', 'predecessor_sha256', 'ready_records'}}).rstrip(b'\n'))
        previous = None
        identities = {'backup': {'inode': 2}, 'restored': {'inode': 3}}
        replacement = {'device': 4, 'inode': 5}
        for action in ('stage', 'replace', 'verify-service'):
            step = dict(base, action=action, predecessor=str(previous) if previous else None,
                        predecessor_sha256=route.digest(previous.read_bytes()) if previous else None)
            raw = route.canonical(step)
            sha = route.digest(raw)
            directory = self.root / 'enrollment-candidates' / sha
            directory.mkdir(parents=True)
            (directory / 'step.json').write_bytes(raw)
            detail = {'backup': {name: {'identity': identity} for name, identity in identities.items()}} if action == 'stage' else {'replacement': {'identity': replacement}}
            previous = journal / (sha + '.completed.json')
            previous.write_bytes(route.canonical({'operation': base['operation'], 'binding_sha256': binding, 'action': action, 'step_sha256': sha, 'detail': detail}))
        cleanup = dict(base, action='cleanup', predecessor=str(previous), predecessor_sha256=route.digest(previous.read_bytes()))
        cut = route.digest(route.canonical(base['expected']).rstrip(b'\n'))
        hold = {'schema': 'labelwatch.maintenance-hold/v1', 'operation': base['operation'], 'database': base['source'], 'manifest_sha256': cut, 'application_revision': base['revision']}
        held = {'operation': base['operation'], 'source': base['source'], 'original': base['original'], 'application_revision': base['revision'],
                'original_identity': base['source_identity'], 'expected_cut_sha256': cut, 'phase': 'pre_ingest',
                'replacement_device': 4, 'replacement_inode': 5,
                'writer_identities': {'main': {'pid': 10, 'start_ticks': 1000}, 'discovery': {'pid': 11, 'start_ticks': 1100}}}
        request = {'held_request': held, 'backup': base['backup'], 'restore': base['restore'],
                   'backup_identity': identities['backup'], 'restore_identity': identities['restored'],
                   'expected_hold_sha256': route.digest(route.canonical(hold).rstrip(b'\n'))}
        for number, role in enumerate(('main', 'discovery'), start=10):
            Path(ready[role]).write_bytes(route.canonical({'schema': 'labelwatch.held-writer-ready/v1', 'operation': base['operation'], 'role': role,
                'pid': number, 'start_ticks': number * 100, 'hold_sha256': request['expected_hold_sha256'], 'verification_sha256': cut}))
        route.bind_cleanup_request(cleanup, request)
        for field, value in [('operation', 'other-otherwise-valid-operation'), ('replacement_inode', 99), ('expected_cut_sha256', '0' * 64)]:
            substituted = copy.deepcopy(request)
            substituted['held_request'][field] = value
            with self.assertRaises(ValueError):
                route.bind_cleanup_request(cleanup, substituted)
        substituted = copy.deepcopy(request)
        substituted['backup_identity']['inode'] = 999
        with self.assertRaises(ValueError):
            route.bind_cleanup_request(cleanup, substituted)
        record_path = Path(ready['main'])
        original = record_path.read_bytes()
        import json
        for key in ('operation', 'hold_sha256', 'verification_sha256'):
            record = json.loads(original)
            record[key] = 'otherwise-valid-foreign-binding'
            record_path.write_bytes(route.canonical(record))
            with self.assertRaisesRegex(ValueError, 'readiness record'):
                route.bind_cleanup_request(cleanup, request)
        record_path.write_bytes(original)

    def test_app_canonical_bytes_include_ascii_del_and_surrogate_escapes_without_newline(self):
        value = {'z': 'é😀\u007f\n\t\b\f\r\0\\"', 'a': [1, True, None]}
        expected = br'{"a":[1,true,null],"z":"\u00e9\ud83d\ude00\u007f\n\t\b\f\r\u0000\\\""}'
        self.assertEqual(route.canonical(value).rstrip(b'\n'), expected)


if __name__ == '__main__':
    unittest.main()
