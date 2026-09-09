#!/usr/bin/env python3
"""Closed, data-minimized public projection of the fixed M4 fixture result.

Reads only the explicitly supplied result, never a directory, DB, journal,
configuration, admission or key. Unknown fields are not copied. This exports
scripted qualification metadata, not evidence contents or a release verdict.
"""
import argparse
import hashlib
import json
import pathlib


def project(raw):
    if len(raw) > 1024 * 1024:
        raise ValueError('result exceeds bound')
    result = json.loads(raw)
    fixed = {'schema': 'constellation.m4.day_two_fixture.v1',
             'disposition': 'DAY_TWO_PROCEDURE_DEMONSTRATED',
             'service': 'nqd.service', 'scheduled_watchers': 0,
             'upgrade': 'ALREADY_CURRENT_ONLY', 'binary_upgrade': 'NOT_RUN',
             'restored_history_authorizes_effects': False,
             'human_operator_trial': 'NOT_RUN'}
    for key, value in fixed.items():
        if type(result.get(key)) is not type(value) or result[key] != value:
            raise ValueError('not the bounded fixed day-two result')
    return {'schema': 'constellation.m4.public_fixture_summary.v1',
            'source_owner': 'scripted day-two fixture; not release authority',
            'source_bytes_sha256': hashlib.sha256(raw).hexdigest(),
            'facts': fixed,
            'private_material': 'NOT_EXPORTED',
            'independent_acceptance': 'NOT_ASSERTED'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('result', type=pathlib.Path)
    parser.add_argument('output', type=pathlib.Path)
    args = parser.parse_args()
    with args.result.open('rb') as source:
        summary = project(source.read(1024 * 1024 + 1))
    with args.output.open('xb') as destination:
        destination.write(json.dumps(summary, sort_keys=True, separators=(',', ':')).encode() + b'\n')
