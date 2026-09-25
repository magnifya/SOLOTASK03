"""Tests for checkpoint-history verification with signer rotation and
revocation (``ledger.light_client.verify_history_trust``).

The pages themselves follow the exact :func:`export_history` /
:func:`verify_history` rules, but each page may be signed by a different
key: authorization comes from a signer log ``trust`` with the exact key
order ``root, records, head`` whose records
(``at, key, status, prev, signature``) are root-signed certificates.

Covers:

* success with one signer and with rotation across pages; re-activation of
  a previously revoked key; the boundary semantics of ``at``;
* ``input`` for missing/extra/reordered keys, wrong types (booleans and
  floats for ``at``) and malformed hex in the trust log, the pinned root or
  the pages;
* ``auth`` for a root mismatch, a bad record certificate signature, a bad
  page signature, an unknown key and a revoked key;
* ``integrity`` for non-ascending ``at``, a bad ``prev``/``head`` link and
  a page straddling an authorization boundary, plus the inherited
  record/pagination/checkpoint-replay defects;
* failures are always ``{"ok": False, "error": ...}`` and never raise.

Run: python3 tests/checkpoint_history_trust_test.py
"""
from __future__ import annotations

import copy
import hashlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from checkpoint_history_export_test import ExportFixture, PAGE_KEYS  # noqa: E402

from ledger import crypto  # noqa: E402
from ledger.light_client import (  # noqa: E402
    ERR_AUTH,
    ERR_INPUT,
    ERR_INTEGRITY,
    _canonical_json_bytes,
    verify_history,
    verify_history_trust,
)

RECORD_KEYS = ["at", "key", "status", "prev", "signature"]
ZERO = "0" * 64


class TrustFixture(ExportFixture):
    def setUp(self) -> None:
        super().setUp()
        self.root_seed = crypto.generate_private_key()
        self.root_pub = crypto.derive_public_key(self.root_seed)
        self.key_a_seed = crypto.generate_private_key()
        self.key_a = crypto.derive_public_key(self.key_a_seed)
        self.key_b_seed = crypto.generate_private_key()
        self.key_b = crypto.derive_public_key(self.key_b_seed)
        self.key_c_seed = crypto.generate_private_key()
        self.key_c = crypto.derive_public_key(self.key_c_seed)

    def advance_times(self, times: list[int]) -> None:
        """Advance one generation per entry, recording it at ``verified_at``."""
        anchor = self.anchor
        for index, now in enumerate(times):
            result = self.advance(
                [self.continuation_page(index)], anchor, now=now
            )
            self.assertTrue(result["ok"], result)
            anchor = None

    def signer_log(
        self,
        items: list[tuple[int, str, str]],
        *,
        root_seed: str | None = None,
        head_override: str | None = None,
    ) -> dict:
        """Build a root-signed ``{root, records, head}`` signer log.

        ``items`` is a list of ``(at, key, status)`` triples; each record's
        ``prev`` is chained from the previous full record's canonical hash
        (the first from 64 zeros) and its ``signature`` is the root signature
        over the SHA-256 of its canonical JSON with ``signature`` removed.
        """
        seed = self.root_seed if root_seed is None else root_seed
        records = []
        prev = ZERO
        for at_value, key, status in items:
            unsigned = {"at": at_value, "key": key, "status": status,
                       "prev": prev}
            digest = hashlib.sha256(_canonical_json_bytes(unsigned)).digest()
            signature = crypto.sign_message(seed, digest)
            record = dict(unsigned)
            record["signature"] = signature
            self.assertEqual(list(record.keys()), RECORD_KEYS)
            records.append(record)
            prev = hashlib.sha256(
                _canonical_json_bytes(record)
            ).hexdigest()
        return {"root": self.root_pub, "records": records,
                "head": prev if head_override is None else head_override}

    def sign_pages(self, pages: list[dict], seeds: list[str]) -> list[dict]:
        """Re-sign each page with the matching seed, key order preserved."""
        self.assertEqual(len(pages), len(seeds))
        return [self.resign(copy.deepcopy(page), seed)
                for page, seed in zip(pages, seeds)]

    def relink(self, log: dict) -> dict:
        """Recompute every ``prev`` and ``head`` over the records as given.

        Lets a test keep a forged certificate ``signature`` while making the
        hash chain self-consistent, so certificate-auth failures are not
        masked by a broken link.
        """
        prev = ZERO
        for record in log["records"]:
            record["prev"] = prev
            prev = hashlib.sha256(
                _canonical_json_bytes(record)
            ).hexdigest()
        log["head"] = prev
        return log

    def unsigned_certificate(self, record: dict) -> dict:
        return {name: record[name] for name in RECORD_KEYS
                if name != "signature"}


class VerifyHistoryTrustSuccessTests(TrustFixture):
    def test_single_signer_single_and_multiple_pages(self) -> None:
        self.advance_n(6)
        trust = self.signer_log([(1, self.key_a, "active")])
        for limit in (1, 2, 6):
            pages = self.export_all(limit)
            pages = self.sign_pages(pages, [self.key_a_seed] * len(pages))
            self.assertEqual(
                verify_history_trust(pages, trust, self.root_pub),
                {"ok": True},
            )

    def test_rotation_across_pages(self) -> None:
        # Two checkpoints per page, one verification time per page window.
        self.advance_times([100, 100, 200, 200, 300, 300])
        trust = self.signer_log([
            (50, self.key_a, "active"),
            (150, self.key_b, "active"),
            (250, self.key_c, "active"),
        ])
        pages = self.export_all(2)
        pages = self.sign_pages(
            pages, [self.key_a_seed, self.key_b_seed, self.key_c_seed]
        )
        self.assertEqual(
            verify_history_trust(pages, trust, self.root_pub), {"ok": True}
        )

    def test_revoked_then_reactivated_key(self) -> None:
        # Key A authorizes, is revoked, then re-authorized; pages only ever
        # sit in A-active windows.
        self.advance_times([100, 100, 260, 260, 260, 260])
        trust = self.signer_log([
            (50, self.key_a, "active"),
            (150, self.key_a, "revoked"),
            (250, self.key_a, "active"),
        ])
        pages = self.export_all(2)
        pages = self.sign_pages(pages, [self.key_a_seed] * len(pages))
        self.assertEqual(
            verify_history_trust(pages, trust, self.root_pub), {"ok": True}
        )

    def test_activation_is_effective_exactly_at_at(self) -> None:
        # ``active`` authorizes from ``at`` itself (at <= verified_at).
        self.advance_times([100, 100])
        trust = self.signer_log([(100, self.key_a, "active")])
        pages = self.export_all(2)
        pages = self.sign_pages(pages, [self.key_a_seed])
        self.assertEqual(
            verify_history_trust(pages, trust, self.root_pub), {"ok": True}
        )

    def test_plain_verify_history_still_requires_one_pinned_key(self) -> None:
        # The rotation-aware verifier is additive: verify_history must still
        # reject pages signed under different keys even when each key is
        # individually legitimate.
        self.advance_times([100, 100, 200, 200])
        pages = self.export_all(2)
        pages = self.sign_pages(pages, [self.key_a_seed, self.key_b_seed])
        self.assertEqual(
            verify_history(pages, self.key_a)["error"], ERR_AUTH
        )


class VerifyHistoryTrustInputTests(TrustFixture):
    def setUp(self) -> None:
        super().setUp()
        self.advance_n(2)
        self.trust = self.signer_log([(1, self.key_a, "active")])
        self.pages = self.sign_pages(
            self.export_all(2), [self.key_a_seed]
        )

    def check_input(self, *, pages=None, trust=None, root=None) -> None:
        result = verify_history_trust(
            self.pages if pages is None else pages,
            self.trust if trust is None else trust,
            self.root_pub if root is None else root,
        )
        self.assertEqual(result, {"ok": False, "error": ERR_INPUT})

    def test_bad_root_argument(self) -> None:
        for bad in (None, 123, "Z" * 64, "0" * 63, "0" * 65, b"0" * 64):
            result = verify_history_trust(
                self.pages, self.trust, bad
            )
            self.assertEqual(result, {"ok": False, "error": ERR_INPUT}, bad)

    def test_trust_shape(self) -> None:
        for bad in (None, 1, [], "x", {"x": 1}):
            result = verify_history_trust(
                self.pages, bad, self.root_pub
            )
            self.assertEqual(result, {"ok": False, "error": ERR_INPUT}, bad)
        # Wrong order, missing key, extra key.
        reordered = {"head": self.trust["head"],
                     "records": self.trust["records"],
                     "root": self.trust["root"]}
        self.check_input(trust=reordered)
        self.check_input(trust={"root": self.trust["root"],
                                "records": self.trust["records"]})
        self.check_input(trust=dict(self.trust, extra=1))
        # Malformed root field.
        self.check_input(trust=dict(self.trust, root="Z" * 64))
        # Empty / non-list records, malformed head.
        self.check_input(trust=dict(self.trust, records=[]))
        self.check_input(trust=dict(self.trust, records="x"))
        self.check_input(trust=dict(self.trust, head="Z" * 64))

    def test_record_shape(self) -> None:
        def with_record(record) -> dict:
            # Shape defects are judged before any chaining, so the original
            # record's valid prev/head are left in place.
            log = copy.deepcopy(self.trust)
            log["records"] = [record]
            return log

        base = self.trust["records"][0]
        # Wrong order, missing key, extra key.
        self.check_input(trust=with_record(
            {name: base[name] for name in reversed(RECORD_KEYS)}
        ))
        self.check_input(trust=with_record(
            {name: base[name] for name in RECORD_KEYS if name != "prev"}
        ))
        extra = dict(base, extra=1)
        bad = copy.deepcopy(self.trust)
        bad["records"] = [extra]
        self.check_input(trust=bad)
        # Bad ``at``: zero, negative, bool, float, string.
        for bad_at in (0, -1, True, False, 1.5, "1", [1]):
            record = dict(base, at=bad_at)
            self.check_input(trust=with_record(record))
        # Bad key / prev hex.
        for field in ("key", "prev"):
            for bad_value in ("Z" * 64, "0" * 63, 123, None):
                record = dict(base, **{field: bad_value})
                self.check_input(trust=with_record(record))
        # Bad status.
        for bad_status in ("ACTIVE", "revoked ", "", None, 1):
            record = dict(base, status=bad_status)
            self.check_input(trust=with_record(record))
        # Bad signature hex.
        for bad_sig in ("z" * 128, "0" * 127, 123, None):
            record = dict(base, signature=bad_sig)
            self.check_input(trust=with_record(record))

    def test_pages_still_follow_verify_history_input_rules(self) -> None:
        self.check_input(pages=[])
        self.check_input(pages="x")
        page = self.pages[0]
        missing = {name: page[name] for name in PAGE_KEYS if name != "head"}
        self.check_input(pages=[missing])
        bad_auth = copy.deepcopy(page)
        bad_auth["auth"] = {"public_key": "Z" * 64,
                            "signature": page["auth"]["signature"]}
        self.check_input(pages=[bad_auth])


class VerifyHistoryTrustAuthTests(TrustFixture):
    def setUp(self) -> None:
        super().setUp()
        self.advance_times([100, 100, 200, 200])
        self.trust = self.signer_log([
            (50, self.key_a, "active"),
            (150, self.key_b, "active"),
        ])
        self.pages = self.sign_pages(
            self.export_all(2), [self.key_a_seed, self.key_b_seed]
        )

    def assert_auth(self, *, pages=None, trust=None, root=None) -> None:
        result = verify_history_trust(
            self.pages if pages is None else pages,
            self.trust if trust is None else trust,
            self.root_pub if root is None else root,
        )
        self.assertEqual(result, {"ok": False, "error": ERR_AUTH})

    def test_root_mismatch(self) -> None:
        other_pub = crypto.derive_public_key(crypto.generate_private_key())
        # A well-formed but different pinned root is an auth failure.
        self.assert_auth(root=other_pub)
        # A trust document carrying another well-formed root is too.
        other_log = copy.deepcopy(self.trust)
        other_log["root"] = other_pub
        self.assert_auth(trust=other_log)

    def test_bad_certificate_signature(self) -> None:
        # Forge one signature but keep the hash links self-consistent so the
        # certificate auth check is what fails (the chain covers the whole
        # record including its signature).
        log = copy.deepcopy(self.trust)
        log["records"][0]["signature"] = "0" * 128
        log = self.relink(log)
        self.assert_auth(trust=log)
        # A certificate signed by a different root.
        self.assert_auth(trust=self.signer_log(
            [(50, self.key_a, "active"), (150, self.key_b, "active")],
            root_seed=crypto.generate_private_key(),
        ))

    def test_bad_page_signature(self) -> None:
        pages = copy.deepcopy(self.pages)
        pages[0]["auth"] = {
            "public_key": self.key_a,
            "signature": "0" * 128,
        }
        self.assert_auth(pages=pages)

    def test_page_naming_unknown_key_is_auth(self) -> None:
        pages = self.sign_pages(
            copy.deepcopy(self.export_all(2)), [self.key_c_seed,
                                                self.key_b_seed]
        )
        self.assert_auth(pages=pages)

    def test_revoked_key_is_auth(self) -> None:
        # Every checkpoint of the second window falls in a revocation gap:
        # B is revoked at 150 and nothing follows it.
        trust = self.signer_log([
            (50, self.key_a, "active"),
            (150, self.key_b, "revoked"),
        ])
        pages = self.sign_pages(
            self.export_all(2), [self.key_a_seed, self.key_a_seed]
        )
        result = verify_history_trust(pages, trust, self.root_pub)
        self.assertEqual(result, {"ok": False, "error": ERR_AUTH})
        # Naming the revoked key itself is no better.
        pages = self.sign_pages(
            self.export_all(2), [self.key_a_seed, self.key_b_seed]
        )
        result = verify_history_trust(pages, trust, self.root_pub)
        self.assertEqual(result, {"ok": False, "error": ERR_AUTH})

    def test_checkpoint_before_first_activation_is_auth(self) -> None:
        trust = self.signer_log([(150, self.key_a, "active")])
        pages = self.sign_pages(
            self.export_all(2), [self.key_a_seed, self.key_a_seed]
        )
        result = verify_history_trust(pages, trust, self.root_pub)
        self.assertEqual(result, {"ok": False, "error": ERR_AUTH})


class VerifyHistoryTrustIntegrityTests(TrustFixture):
    def setUp(self) -> None:
        super().setUp()
        self.advance_times([100, 100, 200, 200])
        self.trust = self.signer_log([
            (50, self.key_a, "active"),
            (150, self.key_b, "active"),
        ])
        self.pages = self.sign_pages(
            self.export_all(2), [self.key_a_seed, self.key_b_seed]
        )

    def assert_integrity(self, *, pages=None, trust=None) -> None:
        result = verify_history_trust(
            self.pages if pages is None else pages,
            self.trust if trust is None else trust,
            self.root_pub,
        )
        self.assertEqual(result, {"ok": False, "error": ERR_INTEGRITY})

    def test_at_must_strictly_ascend(self) -> None:
        for bad_at in (50, 40):
            log = self.signer_log([
                (50, self.key_a, "active"),
                (bad_at, self.key_b, "active"),
            ])
            self.assert_integrity(trust=log)

    def test_bad_prev_link(self) -> None:
        log = copy.deepcopy(self.trust)
        # First record must start at 64 zeros.
        log["records"][0]["prev"] = "1" * 64
        self.assert_integrity(trust=log)
        # A later prev must equal the previous full record's canonical hash.
        log = copy.deepcopy(self.trust)
        log["records"][1]["prev"] = "1" * 64
        self.assert_integrity(trust=log)

    def test_bad_head(self) -> None:
        log = copy.deepcopy(self.trust)
        log["head"] = "f" * 64
        self.assert_integrity(trust=log)

    def test_page_straddling_rotation_boundary_is_integrity(self) -> None:
        # With page size 3, the first page covers gens 1..3, i.e. times
        # 100, 100, 200: no single envelope key can authenticate all of them.
        pages = self.export_all(3)
        pages = self.sign_pages(pages, [self.key_a_seed, self.key_b_seed])
        self.assert_integrity(pages=pages)

    def test_page_straddling_revocation_boundary_is_integrity(self) -> None:
        # The size-3 first page holds a checkpoint before and one after A is
        # revoked at 150: active key changes A -> none within one envelope.
        trust = self.signer_log([
            (50, self.key_a, "active"),
            (150, self.key_a, "revoked"),
        ])
        pages = self.export_all(3)
        pages = self.sign_pages(pages, [self.key_a_seed, self.key_a_seed])
        self.assert_integrity(pages=pages, trust=trust)

    def test_boundary_exactly_between_checkpoints_is_fine(self) -> None:
        # The rotation at 150 sits strictly between the two page windows.
        self.assertEqual(
            verify_history_trust(self.pages, self.trust, self.root_pub),
            {"ok": True},
        )

    def test_inherited_pagination_and_chain_defects(self) -> None:
        # A dropped middle page breaks generation order.
        pages = self.sign_pages(
            self.export_all(1),
            [self.key_a_seed, self.key_a_seed, self.key_b_seed,
             self.key_b_seed],
        )
        self.assert_integrity(pages=[pages[0], pages[2], pages[3]])
        # Tampered record content, honestly re-signed, fails the hash/replay.
        edited = self.resign(copy.deepcopy(self.pages[1]), self.key_b_seed)
        edited["records"][0]["prev"] = "1" * 64
        edited = self.resign(edited, self.key_b_seed)
        self.assert_integrity(
            pages=[self.pages[0], edited]
        )

    def test_never_raises_on_garbage(self) -> None:
        for garbage in (None, 1, "x", {"x": 1}, [None], [1, 2], [[]],
                        [{"records": []}]):
            result = verify_history_trust(garbage, self.trust, self.root_pub)
            self.assertFalse(result["ok"], garbage)
            self.assertIn(result["error"],
                          (ERR_INPUT, ERR_AUTH, ERR_INTEGRITY))
        for garbage in (None, 1, [], "x", {"root": self.root_pub}):
            result = verify_history_trust(self.pages, garbage, self.root_pub)
            self.assertFalse(result["ok"], garbage)
            self.assertIn(result["error"],
                          (ERR_INPUT, ERR_AUTH, ERR_INTEGRITY))


if __name__ == "__main__":
    import unittest

    unittest.main()
