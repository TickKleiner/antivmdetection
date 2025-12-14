from __future__ import annotations

from antivmdetection.util.random import ENV_SEED_KEY, build_rng


def test_seeded_rng_reproducible() -> None:
    rng = build_rng(42)
    numbers = [rng.randint(0, 1000) for _ in range(5)]

    assert numbers == [654, 114, 25, 759, 281]


def test_env_seed_used_when_explicit_seed_missing(monkeypatch) -> None:
    monkeypatch.setenv(ENV_SEED_KEY, "99")

    rng_one = build_rng()
    rng_two = build_rng()

    expected = [413, 389, 204, 613]
    assert [rng_one.randint(0, 1000) for _ in range(4)] == expected
    assert [rng_two.randint(0, 1000) for _ in range(4)] == expected
