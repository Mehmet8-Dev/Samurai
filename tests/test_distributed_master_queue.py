from argparse import Namespace

from ddos_samurai.control.master import _chunk_counts, _parse_job_queue


def _base_args(**kw):
    d = {
        "count": 100,
        "job_timeout_s": 0,
        "control_insecure": True,
    }
    d.update(kw)
    return Namespace(**d)


def test_chunk_counts_basic():
    assert _chunk_counts(0, 10) == []
    assert _chunk_counts(5, 10) == [5]
    assert _chunk_counts(25, 10) == [10, 10, 5]


def test_parse_job_queue_default_single_job():
    args = _base_args()
    jobs = _parse_job_queue(args)
    assert isinstance(jobs, list)
    assert len(jobs) == 1
    assert int(jobs[0]["count"]) == 100


def test_parse_job_queue_list_overrides():
    args = _base_args(job_queue_json='[{"count": 10}, {"count": 20, "job_timeout_s": 3}]')
    jobs = _parse_job_queue(args)
    assert len(jobs) == 2
    assert int(jobs[0]["count"]) == 10
    assert int(jobs[1]["count"]) == 20
    assert int(jobs[1]["job_timeout_s"]) == 3
