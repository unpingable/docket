#!/usr/bin/env python3
"""Fixture exercise of existing owner archive, fresh init and restore commands.

This does not migrate historical authority, schedule recovery or authorize a cut.
The old/new stores are stopped, campaign-owned copies with no active writers.
"""
import argparse
import hashlib
import json
import pathlib
import subprocess
import tempfile
from day_two_restore import logical_manifest


def exercise(current, archive, artifact, output):
    output.mkdir(mode=0o700, exist_ok=False)
    previous = archive / 'bin/nq'
    metadata = json.loads((archive / 'ARCHIVE.json').read_text())
    assert hashlib.sha256(previous.read_bytes()).hexdigest() == metadata['tool_binary_digest'].removeprefix('sha256:')
    config = output / 'nq.toml'
    database = output / 'fresh.sqlite'
    # A fresh private parent under root-owned sticky /tmp satisfies the existing
    # owner's ancestor policy; do not chmod shared campaign artifact ancestors.
    runtime = pathlib.Path(tempfile.mkdtemp(prefix='m4-cold-cut-runtime-'))
    (output / 'runtime-path.txt').write_text(str(runtime) + '\n')
    config.write_text('schema="nq.config.v1"\ndatabase_path=' + json.dumps(str(database)) + '\nsocket_path=' + json.dumps(str(output / 'unused.sock')) + '\nadmissions_dir=' + json.dumps(str(output / 'admissions')) + '\nhelper_runtime_dir=' + json.dumps(str(runtime / 'helpers')) + '\nwatchers=[]\n')

    def run(label, binary, args):
        result = subprocess.run([str(binary), '--config', str(config), '--json', *args], capture_output=True, timeout=60)
        (output / (label + '.stdout')).write_bytes(result.stdout)
        (output / (label + '.stderr')).write_bytes(result.stderr)
        (output / (label + '.exit')).write_text(str(result.returncode) + '\n')
        assert result.returncode == 0, label
        return json.loads(result.stdout)

    run('old-archive-verify', previous, ['admin', 'archive-verify', str(archive)])
    run('fresh-init', current, ['init', '--legacy-manifest-digest', metadata['manifest_sha256']])
    before = logical_manifest(database)
    # A pre-activation rollback reopens the old cohort with its own binary into
    # an absent destination. It never rewinds or overwrites either current store.
    restored = output / 'old-cohort-restored.sqlite'
    run('pre-activation-old-restore', previous, ['restore', str(archive / 'db/nq.db'), str(restored)])
    assert logical_manifest(restored) == logical_manifest(archive / 'db/nq.db')
    assert logical_manifest(database) == before
    run('post-cut-custody-import', current, ['diagnostics', 'import', str(artifact), '--import-id', 'm4-cold-cut-custody-001'])
    after = logical_manifest(database)
    assert after != before
    # This is the runbook's observed refusal condition, not a new authority API.
    # No restore is issued after the new cohort contains post-cut records.
    (output / 'RESULT.json').write_text(json.dumps({
        'disposition': 'COLD_COHORT_FIXTURE_DEMONSTRATED',
        'old_binary_sha256': metadata['tool_binary_digest'],
        'new_binary_sha256': 'sha256:' + hashlib.sha256(current.read_bytes()).hexdigest(),
        'legacy_manifest_reference': metadata['manifest_sha256'],
        'old_history_current_authority': False,
        'fresh_watcher_admissions': 'NOT_RUN',
        'pre_activation_old_restore_exact_rows': True,
        'post_cut_record_present': True,
        'rollback_after_post_cut': 'NOT_EXECUTED_FORWARD_RECOVERY_REQUIRED',
        'scope': 'stopped local fixture copies; no package installation or service activation',
    }, sort_keys=True) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    for name in ('current', 'archive', 'artifact', 'output'):
        parser.add_argument('--' + name, type=pathlib.Path, required=True)
    args = parser.parse_args()
    exercise(args.current.resolve(strict=True), args.archive.resolve(strict=True), args.artifact.resolve(strict=True), args.output.resolve())
