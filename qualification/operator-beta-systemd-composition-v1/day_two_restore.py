#!/usr/bin/env python3
"""Qualification-only use of NQ's existing backup/restore/export boundary.

Never operates on the admitted source store: all CLI work uses a private copy.
The table digest compares every typed row value, not merely counts/integrity.
This is fixture evidence, not authority to restore a running deployment.
"""
import argparse
import hashlib
import json
import pathlib
import shutil
import sqlite3
import subprocess


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def encoded(value):
    if isinstance(value, bytes):
        return ["blob", value.hex()]
    if value is None:
        return ["null"]
    if isinstance(value, float):
        return ["real", value.hex()]
    return [type(value).__name__, value]


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def logical_manifest(path):
    connection = sqlite3.connect(path.resolve().as_uri() + "?mode=ro&immutable=1", uri=True)
    try:
        assert connection.execute("PRAGMA integrity_check").fetchall() == [("ok",)]
        schema = connection.execute(
            "SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY type,name"
        ).fetchall()
        tables = {}
        for name, in connection.execute("SELECT name FROM sqlite_schema WHERE type='table' ORDER BY name"):
            quoted = '"' + name.replace('"', '""') + '"'
            rows = sorted(canonical([encoded(v) for v in row]) for row in connection.execute("SELECT * FROM " + quoted))
            tables[name] = {"rows": len(rows), "sha256": hashlib.sha256(canonical([row.hex() for row in rows])).hexdigest()}
        return {"schema_sha256": hashlib.sha256(canonical(schema)).hexdigest(), "tables": tables}
    finally:
        connection.close()


def run(binary, source, output):
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    original_digest = digest(source)
    copied = output / "source.sqlite"
    shutil.copyfile(source, copied)
    copied.chmod(0o600)
    config = output / "nq.toml"
    config.write_text('schema = "nq.config.v1"\ndatabase_path = ' + json.dumps(str(copied)) + '\nsocket_path = ' + json.dumps(str(output / 'unused.sock')) + '\nadmissions_dir = ' + json.dumps(str(output / 'admissions')) + '\nhelper_runtime_dir = ' + json.dumps(str(output / 'helpers')) + '\nwatchers = []\n')
    records = []

    def invoke(name, arguments, expected=0):
        result = subprocess.run([str(binary), '--config', str(config), '--json', *arguments], capture_output=True, timeout=60)
        (output / (name + '.stdout')).write_bytes(result.stdout)
        (output / (name + '.stderr')).write_bytes(result.stderr)
        records.append({"case": name, "exit": result.returncode, "stdout_sha256": hashlib.sha256(result.stdout).hexdigest(), "stderr_sha256": hashlib.sha256(result.stderr).hexdigest()})
        if (expected == 0) != (result.returncode == 0):
            raise RuntimeError(f'{name}: unexpected exit {result.returncode}')
        return result.stdout

    before = logical_manifest(copied)
    backup, restored = output / 'backup.sqlite', output / 'restored.sqlite'
    invoke('backup', ['backup', str(backup)])
    assert logical_manifest(backup) == before
    invoke('restore', ['restore', str(backup), str(restored)])
    assert logical_manifest(restored) == before
    preserved = digest(restored)
    invoke('restore-existing-refused', ['restore', str(backup), str(restored)], 1)
    assert digest(restored) == preserved
    corrupt = output / 'invalid.sqlite'
    corrupt.write_bytes(b'not a SQLite database\n')
    rejected = output / 'invalid-restored.sqlite'
    invoke('restore-invalid-refused', ['restore', str(corrupt), str(rejected)], 1)
    assert not rejected.exists()
    bad_config = output / 'invalid.toml'
    bad_config.write_text('schema = [invalid\n')
    config_before = config.read_bytes()
    invoke('config-invalid-refused', ['config', 'apply', str(bad_config)], 1)
    assert config.read_bytes() == config_before
    # Exact public export equivalence is additional to whole-row preservation.
    source_status = invoke('status-source', ['status', 'export'])
    config.write_text(config_before.decode().replace(str(copied), str(restored)))
    restored_status = invoke('status-restored', ['status', 'export'])
    assert source_status == restored_status
    assert digest(source) == original_digest
    result = {"scope": "copied accepted two-VM NQ stores; no service or authority activation", "source_sha256": original_digest, "binary_sha256": digest(binary), "logical_manifest": before, "cases": records, "disposition": "RESTORE_AND_EXACT_LOGICAL_DATA_PRESERVATION_DEMONSTRATED", "daemon_restart": "NOT_RUN", "application_restore": "NOT_RUN", "historical_restore_grants_new_authority": False}
    (output / 'RESULT.json').write_bytes(canonical(result) + b'\n')
    print(result['disposition'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', type=pathlib.Path, required=True)
    parser.add_argument('--source', type=pathlib.Path, required=True)
    parser.add_argument('--output', type=pathlib.Path, required=True)
    arguments = parser.parse_args()
    run(arguments.binary.resolve(strict=True), arguments.source.resolve(strict=True), arguments.output)
