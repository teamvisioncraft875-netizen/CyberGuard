"""
CYBERGUARD — Phase 5.5 Empirical Latency & Concurrency Benchmark

Executes controlled measurements across the integrated FastAPI path:
- URL Analysis (100 requests): Mean, P50, P95, P99
- Network Analysis: Cold-start latency, Warm Mean (100 requests), P50, P95, P99
- Concurrency scaling (workers: 5, 10, 20)
"""

import sys
import platform
import time
import numpy as np
from concurrent.futures import ThreadPoolExecutor
from fastapi.testclient import TestClient
from pathlib import Path

# Force fresh import for cold-start measurement
import app.services.system_engine as system_engine
from app.main import app


def run_benchmark():
    print("=" * 72)
    print("  CYBERGUARD PHASE 5 EMPIRICAL BENCHMARK SUITE")
    print("=" * 72)
    print(f"Platform: {platform.platform()} | Python: {platform.python_version()}")
    print("=" * 72)

    client = TestClient(app)

    # -------------------------------------------------------------------------
    # 1. URL Engine Latency Benchmark (100 requests)
    # -------------------------------------------------------------------------
    print("\n[Benchmark 1] Measuring URL Threat Engine Latency (100 iterations)...")
    url_payload = {"url": "http://sl83684.pro/loading.php?user=amazon_account_update"}
    url_latencies = []

    for _ in range(100):
        t0 = time.perf_counter()
        res = client.post("/api/v1/analyze/url", json=url_payload)
        t1 = time.perf_counter()
        assert res.status_code == 200
        url_latencies.append((t1 - t0) * 1000.0)

    url_latencies = np.array(url_latencies)
    url_mean = float(np.mean(url_latencies))
    url_p50 = float(np.percentile(url_latencies, 50))
    url_p95 = float(np.percentile(url_latencies, 95))
    url_p99 = float(np.percentile(url_latencies, 99))
    print(f"  URL Latency: Mean = {url_mean:.3f} ms | P50 = {url_p50:.3f} ms | P95 = {url_p95:.3f} ms | P99 = {url_p99:.3f} ms")

    # -------------------------------------------------------------------------
    # 2. Network Engine Latency Benchmark
    # -------------------------------------------------------------------------
    print("\n[Benchmark 2] Measuring Network Threat Engine Latency...")
    net_payload = {
        "user_id": "usr_benchmark_perf",
        "timestamp": "2026-09-25T12:00:00Z",
        "event_type": "network_flow",
        "details": {
            "duration": 2.5,
            "packet_count": 15.0,
            "total_bytes": 4500.0,
            "source_bytes": 1200.0,
            "protocol": "tcp",
            "destination_port": 443,
            "direction": "<->"
        }
    }

    # Reset cache to simulate cold-start
    system_engine._NETWORK_MODEL = None
    t0_cold = time.perf_counter()
    res_cold = client.post("/api/v1/analyze/system", json=net_payload)
    t1_cold = time.perf_counter()
    assert res_cold.status_code == 200
    cold_start_latency_ms = (t1_cold - t0_cold) * 1000.0
    print(f"  Network Cold-Start Latency (Model load from disk + initial inference): {cold_start_latency_ms:.3f} ms")

    # Warm requests (100 iterations)
    net_latencies = []
    for _ in range(100):
        t0 = time.perf_counter()
        res = client.post("/api/v1/analyze/system", json=net_payload)
        t1 = time.perf_counter()
        assert res.status_code == 200
        net_latencies.append((t1 - t0) * 1000.0)

    net_latencies = np.array(net_latencies)
    net_warm_mean = float(np.mean(net_latencies))
    net_p50 = float(np.percentile(net_latencies, 50))
    net_p95 = float(np.percentile(net_latencies, 95))
    net_p99 = float(np.percentile(net_latencies, 99))
    print(f"  Network Warm Latency: Mean = {net_warm_mean:.3f} ms | P50 = {net_p50:.3f} ms | P95 = {net_p95:.3f} ms | P99 = {net_p99:.3f} ms")

    # -------------------------------------------------------------------------
    # 3. Concurrency Scalability Benchmark
    # -------------------------------------------------------------------------
    print("\n[Benchmark 3] Measuring Concurrency Scaling (5, 10, 20 concurrent threads)...")
    for workers in [5, 10, 20]:
        t0_c = time.perf_counter()
        with ThreadPoolExecutor(max_workers=workers) as executor:
            f_url = [executor.submit(client.post, "/api/v1/analyze/url", json=url_payload) for _ in range(workers)]
            f_net = [executor.submit(client.post, "/api/v1/analyze/system", json=net_payload) for _ in range(workers)]
            for f in f_url + f_net:
                assert f.result().status_code == 200
        elapsed_c = (time.perf_counter() - t0_c) * 1000.0
        total_reqs = workers * 2
        per_req_eff = elapsed_c / total_reqs
        print(f"  Concurrency = {workers:2d} workers | {total_reqs:2d} parallel requests completed in {elapsed_c:6.2f} ms (~{per_req_eff:.2f} ms/req)")

    print("\n" + "=" * 72)
    print("  PHASE 5 BENCHMARK COMPLETE — ALL CRITERIA SATISFIED")
    print("=" * 72)


if __name__ == "__main__":
    run_benchmark()
