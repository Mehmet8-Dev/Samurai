import time

from ddos_samurai.control.autoscale import K8sAutoscaleController


def test_autoscale_scales_up_with_step_and_respects_cooldown():
    c = K8sAutoscaleController(
        enabled=False,
        target_name="samurai-slave",
        min_replicas=1,
        max_replicas=10,
        step=2,
        cooldown_s=10.0,
        shards_per_worker=2,
    )
    c.enabled = True
    c._init_err = ""
    c._current_replicas = 1

    r1 = c.maybe_scale(pending_shards=10, inflight_shards=0, workers_count=1)
    assert bool(r1.get("changed")) is True
    assert int(r1.get("applied", 0)) == 3
    assert int(r1.get("desired", 0)) == 5

    r2 = c.maybe_scale(pending_shards=10, inflight_shards=0, workers_count=1)
    assert bool(r2.get("changed")) is False
    assert str(r2.get("reason", "")) == "cooldown"


def test_autoscale_scales_down_when_idle():
    c = K8sAutoscaleController(
        enabled=False,
        target_name="samurai-slave",
        min_replicas=1,
        max_replicas=10,
        step=2,
        cooldown_s=1.0,
        idle_scale_down_s=5.0,
    )
    c.enabled = True
    c._init_err = ""
    c._current_replicas = 6
    c._last_scale_ts = time.time() - 100.0
    c._last_busy_ts = time.time() - 100.0

    r = c.maybe_scale(pending_shards=0, inflight_shards=0, workers_count=6)
    assert bool(r.get("changed")) is True
    assert int(r.get("desired", 0)) == 1
    assert int(r.get("applied", 0)) == 4

