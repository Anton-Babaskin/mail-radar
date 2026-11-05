"""MVP export acceptance: references, schema and identifiers survive redaction."""
import json
import unittest

from mailradar.model import finding, finish_report, redact_report


class MVPExportTests(unittest.TestCase):
    def test_redaction_preserves_trace_links_conclusions_and_finding_ids(self):
        first = "box.private.test/postfix/ABCDE#1"
        second = "box.private.test/postfix/BCDEF#1"
        report = finish_report(dict(findings=[finding("DNS.MX", "OK", "host box.private.test")],
                                    traces=[dict(id=first, host="box.private.test", links=[dict(target=second)]),
                                            dict(id=second, host="box.private.test", links=[dict(target=first)])],
                                    conclusions=[dict(status="OK", trace_id=second)], completeness=dict(complete=True)))
        redacted = redact_report(report)
        ids = {trace["id"] for trace in redacted["traces"]}
        for trace in redacted["traces"]:
            self.assertIn(trace["links"][0]["target"], ids)
        self.assertIn(redacted["conclusions"][0]["trace_id"], ids)
        self.assertNotIn("private.test", json.dumps(redacted))
        self.assertEqual(redacted["findings"][0]["id"], "DNS.MX")

    def test_metadata_epoch_keys_are_schema_not_domains(self):
        row = {"date.received.unixtime": 1793700000, "date.saved.unixtime": 1793700010,
               "hdr.message-id": "<one@private.test>", "hdr.received": "from box.private.test"}
        report = redact_report({"evidence": [row]})
        self.assertEqual(set(report["evidence"][0]), set(row))
        self.assertEqual(report["evidence"][0]["date.received.unixtime"], 1793700000)
        self.assertNotIn("private.test", json.dumps(report))

    def test_quoted_addresses_are_whole_aliases_and_dynamic_keys_stay_correlated(self):
        address = '"Private Person"@private.test'
        result = redact_report(dict(recipient=address, statistics=dict(recipients={address: 1})))
        self.assertNotIn("Private Person", json.dumps(result))
        self.assertEqual(result["recipient"], next(iter(result["statistics"]["recipients"])))
