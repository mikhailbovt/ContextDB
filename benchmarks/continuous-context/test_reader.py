"""Measurement integrity checks; model quality is measured only by live replay."""

import unittest
from types import SimpleNamespace

from local_reader import Client
from run_reader import aggregate, baseline, finish_task


class StubClient(Client):
    def __init__(self, replies):
        super().__init__("http://127.0.0.1:18765")
        self.replies = iter(replies)

    def post(self, path, value=None, wire=None):
        result = next(self.replies)
        if isinstance(result, Exception):
            raise result
        return result

    def count(self, text, special=False):
        return 10


def response(**changes):
    return {
        "content": '{"answer":"observed"}',
        "tokens_evaluated": 10,
        "tokens_predicted": 4,
        "tokens_cached": 999,  # post-completion size is not a cache-read count
        "timings": {"cache_n": 8, "prompt_n": 2, "prompt_ms": 1.5},
        "stop_type": "eos",
        "truncated": False,
    } | changes


class MeasurementTests(unittest.TestCase):
    def test_measured_cache_and_visible_output_survive_missing_usage(self):
        client = StubClient(
            [response(), response(tokens_evaluated=11), response(truncated=True)]
        )
        valid = client.complete_wire(b"{}", 10)
        self.assertEqual(valid["usage"]["cache_read_tokens"], 8)
        invalid = client.complete_wire(b"{}", 10)
        self.assertEqual(invalid["text"], valid["text"])
        self.assertIsNone(invalid["usage"])
        self.assertTrue(invalid["completed"])
        partial = client.complete_wire(b"{}", 10)
        self.assertEqual(partial["text"], valid["text"])
        self.assertFalse(partial["completed"])

    def test_transport_failure_preserves_previous_tasks_and_attempt_cost(self):
        client = StubClient([response(), OSError("connection lost")])
        history = {
            "events": [
                {"id": "e0", "scope": "main", "role": "user", "text": "Original."}
            ],
            "targets": [
                {"id": "q0", "text": "First?"},
                {"id": "q1", "text": "Second?"},
            ],
        }
        run = {"tasks": [], "preprocessing": []}
        args = SimpleNamespace(hot_events=1, input_tokens=100, output_tokens=20)
        with self.assertRaises(OSError):
            baseline("rolling", history, args, client, None, 17, run)
        self.assertEqual(len(run["tasks"]), 2)
        self.assertTrue(run["tasks"][0]["completed"])
        self.assertFalse(run["tasks"][1]["completed"])
        finish_task(run["tasks"][1])
        self.assertGreaterEqual(run["tasks"][1]["elapsed_micros"], 0)
        self.assertEqual(len(client.calls), 2)
        self.assertIsNone(client.calls[1]["usage"])
        self.assertIsNotNone(client.calls[1]["elapsed_micros"])

    def test_whole_run_failures_and_unstarted_tasks_are_distinct(self):
        report = aggregate(
            [
                {
                    "method": "rolling",
                    "elapsed_micros": 10_000_000,
                    "tasks": [
                        {
                            "attempted": True,
                            "answer_correct": True,
                            "elapsed_micros": 1_000_000,
                        },
                        {
                            "attempted": True,
                            "answer_correct": False,
                            "elapsed_micros": 2_000_000,
                            "error": "lost",
                        },
                        {
                            "attempted": False,
                            "answer_correct": False,
                            "elapsed_micros": None,
                            "error": "not started",
                        },
                    ],
                    "calls": [{"usage": {"input_tokens": 10}}, {"usage": None}],
                    "embedding_calls": [{"elapsed_micros": 100}],
                }
            ]
        )["rolling"]
        self.assertEqual(report["requested_tasks"], 3)
        self.assertEqual(report["attempted_tasks"], 2)
        self.assertEqual(report["not_started_tasks"], 1)
        self.assertEqual(report["success_rate"], 1 / 3)
        self.assertEqual(report["wall_seconds_per_attempt"], 5)
        self.assertEqual(report["wall_seconds_per_success"], 10)
        self.assertIsNone(report["usage"]["input_tokens"])
        self.assertIsNone(report["total_monetary_cost"])


if __name__ == "__main__":
    unittest.main()
