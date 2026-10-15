"""The calibration that the CI time check divides every scan time by.

It needs no rule base, so unlike test_scan_performance.py it always runs.
"""

from pathlib import Path

import pytest

from gangmu.eval import perf


def _clock(durations):
    """A perf_counter that advances by each duration in turn: one round reads it twice."""
    ticks, now = [], 0.0
    for d in durations:
        ticks += [now, now + d]
        now += d + 1.0
    it = iter(ticks)
    return lambda: next(it)


def test_calibration_is_the_median_round_not_the_fastest(monkeypatch):
    # On CI one run's calibration came out 25% below its neighbours (0.045 s against 0.06 s)
    # because the fastest of three rounds was a lucky one, and every scan in that run read 20%
    # dearer than it was. One fast round must not set the unit.
    monkeypatch.setattr("gangmu.analysis.analyse_bytes", lambda *a, **k: None)
    monkeypatch.setattr(perf.time, "perf_counter", _clock([0.06] * 8 + [0.03]))
    assert perf.calibrate(rounds=9) == pytest.approx(0.06)


def test_calibration_ignores_a_slow_round_too(monkeypatch):
    monkeypatch.setattr("gangmu.analysis.analyse_bytes", lambda *a, **k: None)
    monkeypatch.setattr(perf.time, "perf_counter", _clock([0.06] * 8 + [0.5]))
    assert perf.calibrate(rounds=9) == pytest.approx(0.06)


def test_a_suite_calibrates_before_and_after_and_reports_the_drift(monkeypatch):
    values = iter([0.05, 0.07])
    monkeypatch.setattr(perf, "calibrate", lambda *a, **k: next(values))
    monkeypatch.setattr(perf, "measure_in_child", lambda *a, **k: {"scan_s": 3.0})
    out = perf.run_suite(Path("."), [], scales=(1,), warm=False)
    assert out["calibration_s"] == 0.06 and out["calibration_drift"] == 1.4
    assert out["runs"][0]["scan_units"] == 50.0
