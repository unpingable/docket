#!/usr/bin/env python3
"""Executable closure for the composed operator-beta M1 qualification receipt."""

from __future__ import annotations

import copy
import hashlib
import json
import pathlib
import sqlite3
import unittest

import jsonschema


ROOT = pathlib.Path(__file__).resolve().parent
RECEIPT_PATH = ROOT / "qualification-receipt.v1.json"
SCHEMA_PATH = ROOT / "qualification-receipt-v1.schema.json"


def sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


class QualificationReceiptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.receipt = json.loads(RECEIPT_PATH.read_bytes())
        cls.schema = json.loads(SCHEMA_PATH.read_bytes())
        cls.authoritative = pathlib.Path(cls.receipt["archive"]["authoritative_path"])
        cls.copy = pathlib.Path(cls.receipt["archive"]["preservation_copy_path"])

    def test_closed_receipt_validates(self) -> None:
        jsonschema.Draft202012Validator.check_schema(self.schema)
        jsonschema.Draft202012Validator(self.schema).validate(self.receipt)
        self.assertEqual(self.schema["const"], self.receipt)

    def test_manifest_reopens_exact_authoritative_run(self) -> None:
        archive = self.receipt["archive"]
        manifest_path = self.authoritative / "ARTIFACTS.sha256"
        result_path = self.authoritative / "RESULT.json"
        self.assertEqual(manifest_path.stat().st_size, archive["manifest_bytes"])
        self.assertEqual(result_path.stat().st_size, archive["result_bytes"])
        self.assertEqual(sha256(manifest_path), archive["manifest_sha256"])
        self.assertEqual(sha256(result_path), archive["result_sha256"])
        manifest = json.loads(manifest_path.read_bytes())
        result = json.loads(result_path.read_bytes())
        self.assertEqual(result["manifest_sha256"], archive["manifest_sha256"])
        self.assertEqual(result["disposition"], self.receipt["disposition"])
        expected = {entry["path"] for entry in manifest["files"]}
        actual = {
            path.relative_to(self.authoritative).as_posix()
            for path in self.authoritative.rglob("*")
            if path.is_file()
            and path.name not in {"ARTIFACTS.sha256", "RESULT.json"}
        }
        self.assertEqual(len(expected), archive["manifest_entries"])
        self.assertEqual(actual, expected)
        for entry in manifest["files"]:
            path = self.authoritative / entry["path"]
            self.assertFalse(path.is_symlink())
            self.assertEqual(path.stat().st_size, entry["bytes"])
            self.assertEqual(sha256(path), entry["sha256"])

    def test_preservation_copy_is_byte_identical_but_not_authoritative(self) -> None:
        self.assertEqual(
            self.receipt["archive"]["preservation_copy_role"],
            "BYTE_IDENTICAL_NON_AUTHORITATIVE_COPY",
        )
        original = {
            path.relative_to(self.authoritative).as_posix(): path
            for path in self.authoritative.rglob("*")
            if path.is_file()
        }
        preserved = {
            path.relative_to(self.copy).as_posix(): path
            for path in self.copy.rglob("*")
            if path.is_file()
        }
        self.assertEqual(set(original), set(preserved))
        for relative, path in original.items():
            self.assertEqual(sha256(path), sha256(preserved[relative]))

    def test_historical_decision_and_composition_reopen(self) -> None:
        first = self.authoritative / "evidence/composition-occurrence"
        authorization = json.loads((first / "authorization-state.json").read_bytes())
        decision = authorization["state"]["authorization_consumed"]["admitted"]["decision"]
        issuance = authorization["state"]["authorization_consumed"]["issuance"]
        retained = self.receipt["historical_decision"]
        for field in (
            "decision",
            "disposition",
            "proposal",
            "observation",
            "standing_resolution",
            "policy_basis",
        ):
            self.assertEqual(decision[field], retained[field])
        for field in ("spend", "issuance", "subject", "scope", "work"):
            self.assertEqual(issuance[field], retained[field])

        composed = json.loads((first / "composition-result.json").read_bytes())
        custody = self.receipt["composition"]
        for field in ("ag_spends", "docket_attempts", "settlements", "attempt", "marker", "receipt"):
            self.assertEqual(composed[field], custody[field])
        self.assertTrue(custody["owner_query_replay_equal"])
        self.assertTrue(custody["docket_query_replay_equal"])

    def test_store_observation_and_limits_reopen(self) -> None:
        composition = self.receipt["composition"]
        store = self.authoritative / "evidence/composition-ag-attempt-store-cut.sqlite"
        self.assertEqual(store.stat().st_size, composition["store_cut_bytes"])
        self.assertEqual(sha256(store), composition["store_cut_sha256"])
        connection = sqlite3.connect(f"file:{store}?mode=ro&immutable=1", uri=True)
        self.assertEqual(connection.execute("PRAGMA integrity_check").fetchone(), ("ok",))
        self.assertEqual(
            connection.execute("SELECT count(*) FROM docket_effect_attempt").fetchone()[0],
            composition["store_attempt_rows"],
        )
        self.assertEqual(
            connection.execute("SELECT count(*) FROM systemd_dbus_evidence").fetchone()[0],
            composition["store_evidence_rows"],
        )
        connection.close()
        support = json.loads(
            (self.authoritative / "evidence/current-support-after-restart.json").read_bytes()
        )
        self.assertEqual(
            support["historical_effect"],
            self.receipt["observation_history"]["historical_effect"],
        )
        self.assertEqual(
            support["aggregate_postcondition"],
            self.receipt["limitations"]["aggregate_postcondition"],
        )

    def test_teardown_and_revocations_reopen(self) -> None:
        teardown = self.receipt["teardown"]
        total = 0
        for role in ("control", "target"):
            backup = self.authoritative / f"evidence/{role}-nq-backup.sqlite"
            connection = sqlite3.connect(f"file:{backup}?mode=ro&immutable=1", uri=True)
            self.assertEqual(
                connection.execute("PRAGMA integrity_check").fetchone()[0],
                teardown["backup_sqlite_integrity"],
            )
            connection.close()
            self.assertEqual(sha256(backup), teardown[f"{role}_backup_sha256"])
            revocations = json.loads(
                (self.authoritative / f"evidence/{role}-revocations.json").read_bytes()
            )
            total += len(revocations["instances"])
        self.assertEqual(total, teardown["revoked_instances"])
        final = self.authoritative / "evidence/host-final-observation.json"
        self.assertEqual(sha256(final), teardown["host_final_observation_sha256"])
        self.assertFalse(teardown["general_restore_qualified"])

    def test_substitutions_refuse(self) -> None:
        validator = jsonschema.Draft202012Validator(self.schema)
        substitutions = []
        changed = copy.deepcopy(self.receipt)
        changed["disposition"] = "QUALIFIED"
        substitutions.append(changed)
        changed = copy.deepcopy(self.receipt)
        changed["historical_decision"]["exact_policy_catalog_content"] = "RECORDED"
        substitutions.append(changed)
        changed = copy.deepcopy(self.receipt)
        changed["archive"]["authoritative_path"] = changed["archive"]["preservation_copy_path"]
        substitutions.append(changed)
        changed = copy.deepcopy(self.receipt)
        changed["aggregate_result"] = "healthy"
        substitutions.append(changed)
        for candidate in substitutions:
            with self.subTest(candidate=candidate):
                self.assertFalse(validator.is_valid(candidate))


if __name__ == "__main__":
    unittest.main()
