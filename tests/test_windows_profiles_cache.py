"""Short-lived cache for safety._windows_profiles() (perf follow-up to I1)."""

from __future__ import annotations

import os

import pytest

from cleanix.core import safety


@pytest.fixture
def scandir_calls(monkeypatch):
    calls = []
    real = os.scandir

    def counting(path="."):
        calls.append(str(path))
        return real(path)

    monkeypatch.setattr(safety.os, "scandir", counting)
    return calls


@pytest.fixture
def clock(monkeypatch):
    now = {"t": 1000.0}
    monkeypatch.setattr(safety.time, "monotonic", lambda: now["t"])
    return now


def _users_listings(calls):
    return [c for c in calls if c.lower().endswith("users")]


def test_second_call_within_ttl_does_not_relist(scandir_calls, clock):
    safety._windows_profiles_cache_clear()
    safety._windows_profiles()
    first = len(_users_listings(scandir_calls))
    assert first >= 1
    clock["t"] += safety._WINDOWS_PROFILES_TTL - 0.5
    safety._windows_profiles()
    safety._windows_profiles()
    assert len(_users_listings(scandir_calls)) == first


def test_expired_ttl_relists(scandir_calls, clock):
    safety._windows_profiles_cache_clear()
    safety._windows_profiles()
    first = len(_users_listings(scandir_calls))
    clock["t"] += safety._WINDOWS_PROFILES_TTL + 0.1
    safety._windows_profiles()
    assert len(_users_listings(scandir_calls)) == 2 * first


def test_clear_forces_relist(scandir_calls, clock):
    safety._windows_profiles_cache_clear()
    safety._windows_profiles()
    first = len(_users_listings(scandir_calls))
    safety._windows_profiles_cache_clear()
    safety._windows_profiles()
    assert len(_users_listings(scandir_calls)) == 2 * first


def test_ttl_is_five_seconds():
    assert safety._WINDOWS_PROFILES_TTL == 5.0


def test_cache_is_keyed_on_the_directory(scandir_calls, clock, monkeypatch):
    safety._windows_profiles_cache_clear()
    monkeypatch.setenv("SystemDrive", "Q:")
    safety._windows_profiles()
    n = len(_users_listings(scandir_calls))
    monkeypatch.setenv("SystemDrive", "R:")
    safety._windows_profiles()
    assert len(_users_listings(scandir_calls)) > n
