"""End-to-end TruffleHog multi-source integration: job file -> scan -> graph.

Walks the whole pipeline with only the TruffleHog binary faked:

    orchestrator writes job.json
        -> TrufflehogRunner builds argv, parses JSONL, writes out.json
            -> the clean ingest step writes out.json into the graph

The unit suites pin each stage in isolation; this one pins the SEAMS between
them, which is where a multi-source feature actually breaks: an output file two
sources share, a field the scanner writes and the graph never reads, a source id
that changes spelling as it crosses a boundary.
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "scanners"))

from graph_db.mixins.secret_mixin import SecretMixin  # noqa: E402
from trufflehog_scan import sources as reg  # noqa: E402
from trufflehog_scan.job_config import load_job  # noqa: E402
from trufflehog_scan.trufflehog_runner import TrufflehogRunner  # noqa: E402

from trufflehog_graph_fake import FakeClient  # noqa: E402


class FakeProcess:
    def __init__(self, lines, returncode=0):
        self.stdout = iter(lines)
        self.stderr = _Empty()
        self.returncode = returncode

    def wait(self):
        return self.returncode


class _Empty:
    def read(self):
        return ""


def github_result(repo, path, detector="AWS", verified=False):
    return json.dumps({
        "DetectorName": detector,
        "DetectorDescription": "d",
        "Verified": verified,
        "Redacted": "AKIA****",
        "SourceMetadata": {"Data": {"Github": {
            "repository": repo, "file": path, "line": 7, "commit": "c0ffee",
        }}},
    })


def docker_result(image, tag, path, detector="AWS", verified=True):
    return json.dumps({
        "DetectorName": detector,
        "DetectorDescription": "d",
        "Verified": verified,
        "Redacted": "AKIA****",
        "SourceMetadata": {"Data": {"Docker": {
            "Image": image, "Tag": tag, "Layer": "sha256:abcd", "File": path,
        }}},
    })


class PipelineTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.graph = FakeClient()

    def tearDown(self):
        self._tmp.cleanup()

    def write_job(self, source, config, common=None, secrets_env=None):
        """What the orchestrator writes into the per-run directory."""
        run_dir = self.tmp / f"run_{source}"
        run_dir.mkdir(parents=True, exist_ok=True)
        job = {
            "project_id": "p1", "user_id": "u1", "source": source, "run_id": source,
            "config": config, "common": common or {},
            "run_dir": str(run_dir), "output_file": str(run_dir / "out.json"),
        }
        (run_dir / "job.json").write_text(json.dumps(job))
        return load_job({"TRUFFLEHOG_JOB": str(run_dir / "job.json")})

    def scan(self, job, lines, env=None):
        runner = TrufflehogRunner(job, env=env or {})
        with patch("subprocess.Popen", return_value=FakeProcess(lines)):
            runner.run()
        return json.loads(Path(runner.output_file).read_text())

    def ingest(self, out):
        return self.graph.update_graph_from_trufflehog(out, "u1", "p1")


class TestSingleSourceRoundTrip(PipelineTestCase):
    def test_github_run_reaches_the_graph_intact(self):
        job = self.write_job("github", {"orgs": ["acme"]})
        out = self.scan(job, [github_result("acme/api", "src/app.py", verified=True)])
        self.ingest(out)

        scans = self.graph.nodes_of("TrufflehogScan")
        self.assertEqual(len(scans), 1)
        self.assertEqual(scans[0]["source"], "github")
        self.assertEqual(scans[0]["target"], "acme")

        repos = self.graph.nodes_of("TrufflehogRepository")
        self.assertEqual([r["name"] for r in repos], ["acme/api"])

        findings = self.graph.findings()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["validation_status"], "validated")
        self.assertEqual(findings[0]["location"], "src/app.py")
        self.assertEqual(findings[0]["commit"], "c0ffee")

    def test_docker_run_produces_an_image_asset_with_the_tag(self):
        job = self.write_job("docker", {"images": ["acme/app:1.0"]})
        out = self.scan(job, [docker_result("acme/app", "1.0", "/app/.env")])
        self.ingest(out)

        images = self.graph.nodes_of("TrufflehogImage")
        self.assertEqual([i["name"] for i in images], ["acme/app:1.0"])
        extra = json.loads(self.graph.findings()[0]["extra_data"])
        self.assertEqual(extra["Tag"], "1.0")
        self.assertEqual(extra["Layer"], "sha256:abcd")

    def test_scanner_statistics_land_on_the_scan_node(self):
        job = self.write_job("github", {"orgs": ["acme"]})
        out = self.scan(job, [
            github_result("acme/api", "a.py", verified=True),
            github_result("acme/api", "b.py"),
            github_result("acme/web", "c.py"),
        ])
        self.ingest(out)
        scan = self.graph.nodes_of("TrufflehogScan")[0]
        self.assertEqual(scan["total_findings"], 3)
        self.assertEqual(scan["validated_findings"], 1)
        self.assertEqual(scan["assets_scanned"], 2)


class TestParallelSources(PipelineTestCase):
    """The feature's whole point, exercised through the real seams."""

    def test_two_sources_coexist_end_to_end(self):
        gh_job = self.write_job("github", {"orgs": ["acme"]})
        dk_job = self.write_job("docker", {"images": ["acme/app:1.0"]})

        gh_out = self.scan(gh_job, [github_result("acme/api", "src/app.py")])
        dk_out = self.scan(dk_job, [docker_result("acme/app", "1.0", "/app/.env")])

        # Interleaved the way parallel runs actually finish.
        self.ingest(gh_out)
        self.ingest(dk_out)

        self.assertEqual(len(self.graph.findings("github")), 1)
        self.assertEqual(len(self.graph.findings("docker")), 1)
        self.assertEqual(len(self.graph.nodes_of("TrufflehogScan")), 2)
        self.assertEqual(len(self.graph.nodes_of("TrufflehogRepository")), 1)
        self.assertEqual(len(self.graph.nodes_of("TrufflehogImage")), 1)

    def test_the_two_runs_never_share_an_output_file(self):
        gh_job = self.write_job("github", {"orgs": ["acme"]})
        dk_job = self.write_job("docker", {"images": ["acme/app:1.0"]})
        self.assertNotEqual(gh_job.output_file, dk_job.output_file)

    def test_re_scanning_one_source_leaves_the_other_alone(self):
        self.ingest(self.scan(self.write_job("github", {"orgs": ["acme"]}),
                              [github_result("acme/api", "old.py")]))
        self.ingest(self.scan(self.write_job("docker", {"images": ["acme/app:1.0"]}),
                              [docker_result("acme/app", "1.0", "/app/.env")]))
        self.ingest(self.scan(self.write_job("github", {"orgs": ["acme"]}),
                              [github_result("acme/api", "new.py")]))

        self.assertEqual([f["location"] for f in self.graph.findings("github")], ["new.py"])
        self.assertEqual(len(self.graph.findings("docker")), 1)

    def test_node_ids_are_stable_across_a_re_scan(self):
        """Unstable ids used to be masked by the blanket clear. With scoped
        clearing they would show up as orphans; with stable ids the same asset
        keeps the same node across runs."""
        job = self.write_job("github", {"orgs": ["acme"]})
        self.ingest(self.scan(job, [github_result("acme/api", "a.py")]))
        first = self.graph.nodes_of("TrufflehogRepository")[0]["id"]
        self.ingest(self.scan(job, [github_result("acme/api", "a.py")]))
        self.assertEqual(self.graph.nodes_of("TrufflehogRepository")[0]["id"], first)


class TestCrossBoundaryContract(PipelineTestCase):
    """Fields the scanner writes and the graph must not drop."""

    def test_every_field_the_graph_reads_is_written_by_the_scanner(self):
        job = self.write_job("docker", {"images": ["acme/app:1.0"]})
        out = self.scan(job, [docker_result("acme/app", "1.0", "/app/.env")])
        finding = out["findings"][0]
        for key in ("source", "asset", "location", "line", "detector_name",
                    "validation_status", "finding_kind", "extra_data", "redacted"):
            self.assertIn(key, finding, f"the graph reads {key} but the scanner drops it")

    def test_asset_kind_crosses_the_boundary_and_picks_the_label(self):
        for source, config, kind, label in (
            ("huggingface", {"models": ["acme/m"]}, "model", "TrufflehogModel"),
            ("s3", {"buckets": ["b"]}, "bucket", "TrufflehogBucket"),
            ("jenkins", {"url": "https://ci.example.com"}, "endpoint", "TrufflehogEndpoint"),
        ):
            graph = FakeClient()
            job = self.write_job(source, config)
            out = self.scan(job, [])
            self.assertEqual(out["asset_kind"], kind)
            out["findings"] = [{
                "source": source, "asset": "a", "location": "l",
                "detector_name": "AWS", "line": 1, "validation_status": "unvalidated",
            }]
            graph.update_graph_from_trufflehog(out, "u1", "p1")
            self.assertEqual(len(graph.nodes_of(label)), 1)

    def test_verification_off_survives_to_the_graph(self):
        job = self.write_job("github", {"orgs": ["acme"]}, common={"skipVerification": True})
        out = self.scan(job, [github_result("acme/api", "a.py", verified=True)])
        self.assertFalse(out["verification_enabled"])
        self.ingest(out)
        self.assertEqual(self.graph.findings()[0]["validation_status"], "unverified")
        self.assertFalse(self.graph.nodes_of("TrufflehogScan")[0]["verification_enabled"])

    def test_source_spelling_is_normalised_once_and_stays_normalised(self):
        run_dir = self.tmp / "run_dashed"
        run_dir.mkdir()
        (run_dir / "job.json").write_text(json.dumps({
            "project_id": "p1", "user_id": "u1", "source": "github-experimental",
            "config": {"repo": "acme/api"}, "run_dir": str(run_dir),
            "output_file": str(run_dir / "out.json"),
        }))
        job = load_job({"TRUFFLEHOG_JOB": str(run_dir / "job.json")})
        self.assertEqual(job.source, "github_experimental")
        out = self.scan(job, [])
        self.assertEqual(out["source"], "github_experimental")
        self.ingest(out)
        self.assertEqual(self.graph.nodes_of("TrufflehogScan")[0]["source"],
                         "github_experimental")

    def test_the_command_matches_the_registry_for_the_job_config(self):
        job = self.write_job("github", {"orgs": ["acme"], "includeForks": True},
                             common={"concurrency": 4})
        runner = TrufflehogRunner(job, env={"GITHUB_TOKEN": "ghp_x"})
        argv = runner.build_commands()[0]
        self.assertEqual(argv[:2], ["trufflehog", "github"])
        self.assertIn("--org=acme", argv)
        self.assertIn("--include-forks", argv)
        self.assertIn("--concurrency=4", argv)
        self.assertNotIn("ghp_x", " ".join(argv))


class TestFailureModes(PipelineTestCase):
    def test_an_errored_run_still_produces_an_ingestible_artifact(self):
        job = self.write_job("github", {"orgs": ["acme"]})
        runner = TrufflehogRunner(job, env={})
        with patch("subprocess.Popen", return_value=FakeProcess([], returncode=1)):
            runner.run()
        out = json.loads(Path(runner.output_file).read_text())
        self.assertEqual(out["status"], "error")
        stats = self.ingest(out)
        self.assertEqual(stats["scan_created"], 1)
        self.assertEqual(self.graph.nodes_of("TrufflehogScan")[0]["status"], "error")

    def test_an_unknown_metadata_key_still_yields_distinct_graph_nodes(self):
        # The silent-failure case: empty assets collapse every finding into one.
        job = self.write_job("github", {"orgs": ["acme"]})
        lines = [json.dumps({
            "DetectorName": "AWS",
            "SourceMetadata": {"Data": {"Slack": {"channel": "#ops", "file": f}}},
        }) for f in ("a.txt", "b.txt")]
        out = self.scan(job, lines)
        self.ingest(out)
        findings = self.graph.findings()
        self.assertEqual(len(findings), 2)
        self.assertTrue(all(f["asset"] for f in findings))

    def test_a_source_with_no_findings_still_records_the_scan(self):
        job = self.write_job("s3", {"buckets": ["acme-prod"]})
        out = self.scan(job, [])
        self.ingest(out)
        self.assertEqual(len(self.graph.nodes_of("TrufflehogScan")), 1)
        self.assertEqual(self.graph.findings(), [])


if __name__ == "__main__":
    unittest.main()
