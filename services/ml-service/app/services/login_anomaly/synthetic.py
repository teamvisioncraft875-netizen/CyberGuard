"""
CyberGuard ML Service - Synthetic Login Telemetry Generator
Generates realistic baseline normal login behavior and curated threat anomalies for training and evaluation.
Includes realistic borderline authentication behavior (new devices, travel, typos, off-hours) to stress-test
model calibration and false-positive resistance.
"""

from typing import Any, Dict, List, Tuple
import numpy as np
from app.services.login_anomaly.features import LoginEvent


class SyntheticTelemetryGenerator:
    """
    Produces deterministic synthetic login telemetry for CyberGuard.

    Provides:
    1. Clean baseline training datasets for Isolation Forest model fitting.
    2. Comprehensive, realistic evaluation benchmarks containing:
       - Routine normal events
       - Borderline benign events (legitimate new devices, legitimate travel, password typos, nocturnal logins)
       - Subtle compound benign events (multiple weak signals)
       - Injected threat attacks (credential stuffing, account takeover via impossible travel, nocturnal brute force)
    """

    def __init__(self, random_state: int = 42):
        self.rng = np.random.default_rng(random_state)

    def generate_normal_events(self, n_samples: int = 500) -> List[LoginEvent]:
        """
        Generate representative benign login events for baseline training.
        Baseline:
        - Active hours: predominantly 08:00 - 21:00
        - Familiar devices: ~96% recognized
        - Familiar locations: ~97% recognized
        - Failed attempts: ~93% 0 failures, ~6% 1 failure (typo), ~1% 2 failures
        - Impossible travel: 0%
        """
        events: List[LoginEvent] = []

        day_hours = self.rng.normal(loc=14.0, scale=3.0, size=int(n_samples * 0.8))
        eve_hours = self.rng.normal(loc=19.5, scale=2.0, size=n_samples - int(n_samples * 0.8))
        raw_hours = np.concatenate([day_hours, eve_hours])
        self.rng.shuffle(raw_hours)

        hours = np.clip(np.round(raw_hours), 0, 23).astype(int)
        new_device_flags = self.rng.choice([False, True], size=n_samples, p=[0.96, 0.04])
        new_location_flags = self.rng.choice([False, True], size=n_samples, p=[0.97, 0.03])
        failed_counts = self.rng.choice([0, 1, 2], size=n_samples, p=[0.93, 0.06, 0.01])

        for i in range(n_samples):
            events.append(
                LoginEvent(
                    login_hour=int(hours[i]),
                    is_new_device=bool(new_device_flags[i]),
                    is_new_location=bool(new_location_flags[i]),
                    failed_attempts=int(failed_counts[i]),
                    impossible_travel=False,
                    user_id=f"usr_train_{i:04d}",
                    metadata={"synthetic_type": "baseline_normal", "is_threat": False},
                )
            )

        return events

    def generate_anomalous_events(self, n_samples: int = 50) -> List[LoginEvent]:
        """
        Generate explicitly injected anomalous login events across distinct attack scenarios.
        """
        events: List[LoginEvent] = []
        attack_types = [
            "credential_stuffing",
            "impossible_travel_ato",
            "nocturnal_brute_force",
            "proxy_hop_takeover",
        ]

        for i in range(n_samples):
            scenario = attack_types[i % len(attack_types)]

            if scenario == "credential_stuffing":
                failed = int(self.rng.integers(5, 16))
                hour = int(self.rng.integers(0, 24))
                new_dev = bool(self.rng.choice([True, False], p=[0.85, 0.15]))
                new_loc = bool(self.rng.choice([True, False], p=[0.70, 0.30]))
                imp_trav = False

            elif scenario == "impossible_travel_ato":
                failed = int(self.rng.choice([0, 1, 2, 4], p=[0.4, 0.3, 0.2, 0.1]))
                hour = int(self.rng.integers(0, 24))
                new_dev = True
                new_loc = True
                imp_trav = True

            elif scenario == "nocturnal_brute_force":
                hour = int(self.rng.choice([1, 2, 3, 4]))
                new_dev = True
                new_loc = bool(self.rng.choice([True, False], p=[0.8, 0.2]))
                failed = int(self.rng.integers(3, 8))
                imp_trav = bool(self.rng.choice([True, False], p=[0.3, 0.7]))

            else:  # proxy_hop_takeover
                hour = int(self.rng.choice([0, 2, 3, 5, 23]))
                new_dev = True
                new_loc = True
                failed = int(self.rng.integers(2, 6))
                imp_trav = True

            events.append(
                LoginEvent(
                    login_hour=hour,
                    is_new_device=new_dev,
                    is_new_location=new_loc,
                    failed_attempts=failed,
                    impossible_travel=imp_trav,
                    user_id=f"usr_threat_{i:04d}",
                    metadata={"synthetic_type": scenario, "is_threat": True},
                )
            )

        return events

    def generate_realistic_benchmark(
        self,
        n_routine: int = 200,
        n_borderline: int = 160,
        n_threats: int = 100,
    ) -> Tuple[List[LoginEvent], List[Dict[str, Any]]]:
        """
        Generate a comprehensive, realistic benchmark covering routine benign,
        borderline edge cases, multiple weak signals, and genuine injected threats.

        Returns:
            (events, metadata_list)
        """
        benchmark_events: List[LoginEvent] = []
        meta_list: List[Dict[str, Any]] = []

        # 1. Routine Normal Events
        for i in range(n_routine):
            hour = int(self.rng.choice(range(8, 22)))
            failed = int(self.rng.choice([0, 1], p=[0.95, 0.05]))
            ev = LoginEvent(
                login_hour=hour,
                is_new_device=False,
                is_new_location=False,
                failed_attempts=failed,
                impossible_travel=False,
                user_id=f"usr_eval_routine_{i:04d}",
            )
            benchmark_events.append(ev)
            meta_list.append({
                "scenario": "routine_normal",
                "category": "benign_routine",
                "is_threat": False,
                "expected_threat_alert": False,
            })

        # 2. Realistic Borderline Cases (Distributed equally among sub-scenarios)
        borderline_sub_count = n_borderline // 5
        remainder = n_borderline - (borderline_sub_count * 5)

        # 2a. Legitimate New Device (e.g. bought new phone at 14:00)
        for i in range(borderline_sub_count):
            ev = LoginEvent(
                login_hour=int(self.rng.choice(range(9, 21))),
                is_new_device=True,
                is_new_location=False,
                failed_attempts=0,
                impossible_travel=False,
                user_id=f"usr_eval_newdev_{i:04d}",
            )
            benchmark_events.append(ev)
            meta_list.append({
                "scenario": "legitimate_new_device",
                "category": "benign_borderline",
                "is_threat": False,
                "expected_threat_alert": False,
            })

        # 2b. Legitimate Travel (new city/IP, known device, 0-1 typo, plausible speed)
        for i in range(borderline_sub_count):
            ev = LoginEvent(
                login_hour=int(self.rng.choice(range(8, 22))),
                is_new_device=False,
                is_new_location=True,
                failed_attempts=int(self.rng.choice([0, 1], p=[0.8, 0.2])),
                impossible_travel=False,
                user_id=f"usr_eval_travel_{i:04d}",
            )
            benchmark_events.append(ev)
            meta_list.append({
                "scenario": "legitimate_travel",
                "category": "benign_borderline",
                "is_threat": False,
                "expected_threat_alert": False,
            })

        # 2c. Occasional Password Typos (1 to 3 failed attempts on familiar laptop)
        for i in range(borderline_sub_count):
            ev = LoginEvent(
                login_hour=int(self.rng.choice(range(9, 19))),
                is_new_device=False,
                is_new_location=False,
                failed_attempts=int(self.rng.choice([1, 2, 3], p=[0.5, 0.35, 0.15])),
                impossible_travel=False,
                user_id=f"usr_eval_typo_{i:04d}",
            )
            benchmark_events.append(ev)
            meta_list.append({
                "scenario": "occasional_password_typo",
                "category": "benign_borderline",
                "is_threat": False,
                "expected_threat_alert": False,
            })

        # 2d. Unusual But Legitimate Login Hour (01:00-04:00 nocturnal login on home laptop)
        for i in range(borderline_sub_count):
            ev = LoginEvent(
                login_hour=int(self.rng.choice([1, 2, 3, 4])),
                is_new_device=False,
                is_new_location=False,
                failed_attempts=0,
                impossible_travel=False,
                user_id=f"usr_eval_nocturnal_{i:04d}",
            )
            benchmark_events.append(ev)
            meta_list.append({
                "scenario": "unusual_legitimate_hour",
                "category": "benign_borderline",
                "is_threat": False,
                "expected_threat_alert": False,
            })

        # 2e. Multiple Weak Signals Combined (Subtle compound noise: e.g. new dev + evening + 1-2 typos)
        for i in range(borderline_sub_count + remainder):
            ev = LoginEvent(
                login_hour=int(self.rng.choice([7, 21, 22, 23])),
                is_new_device=bool(self.rng.choice([True, False], p=[0.7, 0.3])),
                is_new_location=bool(self.rng.choice([True, False], p=[0.5, 0.5])),
                failed_attempts=int(self.rng.choice([1, 2], p=[0.7, 0.3])),
                impossible_travel=False,
                user_id=f"usr_eval_weaksig_{i:04d}",
            )
            benchmark_events.append(ev)
            meta_list.append({
                "scenario": "multiple_weak_signals",
                "category": "benign_borderline",
                "is_threat": False,
                "expected_threat_alert": False,
            })

        # 3. Injected Active Threats
        threat_sub_count = n_threats // 3
        threat_remainder = n_threats - (threat_sub_count * 3)

        # 3a. Genuine Credential Stuffing / Brute Force (5 to 15 failed attempts)
        for i in range(threat_sub_count):
            ev = LoginEvent(
                login_hour=int(self.rng.integers(0, 24)),
                is_new_device=bool(self.rng.choice([True, False], p=[0.85, 0.15])),
                is_new_location=bool(self.rng.choice([True, False], p=[0.70, 0.30])),
                failed_attempts=int(self.rng.integers(5, 16)),
                impossible_travel=False,
                user_id=f"usr_eval_credstuff_{i:04d}",
            )
            benchmark_events.append(ev)
            meta_list.append({
                "scenario": "credential_stuffing",
                "category": "active_threat",
                "is_threat": True,
                "expected_threat_alert": True,
            })

        # 3b. Account Takeover via Impossible Travel Velocity
        for i in range(threat_sub_count):
            ev = LoginEvent(
                login_hour=int(self.rng.integers(0, 24)),
                is_new_device=True,
                is_new_location=True,
                failed_attempts=int(self.rng.choice([0, 1, 2], p=[0.4, 0.4, 0.2])),
                impossible_travel=True,
                user_id=f"usr_eval_imptrav_{i:04d}",
            )
            benchmark_events.append(ev)
            meta_list.append({
                "scenario": "impossible_travel_ato",
                "category": "active_threat",
                "is_threat": True,
                "expected_threat_alert": True,
            })

        # 3c. Nocturnal Brute Force Probe (01:00-04:00 + unrecognized device + elevated failures)
        for i in range(threat_sub_count + threat_remainder):
            ev = LoginEvent(
                login_hour=int(self.rng.choice([1, 2, 3, 4])),
                is_new_device=True,
                is_new_location=bool(self.rng.choice([True, False], p=[0.85, 0.15])),
                failed_attempts=int(self.rng.integers(3, 8)),
                impossible_travel=bool(self.rng.choice([True, False], p=[0.4, 0.6])),
                user_id=f"usr_eval_noctprobe_{i:04d}",
            )
            benchmark_events.append(ev)
            meta_list.append({
                "scenario": "nocturnal_brute_force",
                "category": "active_threat",
                "is_threat": True,
                "expected_threat_alert": True,
            })

        return benchmark_events, meta_list

    def generate_evaluation_set(
        self, n_normal: int = 300, n_anomalous: int = 60
    ) -> Tuple[List[LoginEvent], np.ndarray]:
        """
        Backwards-compatible interface returning combined events and binary threat labels:
        0 = Benign/Borderline, 1 = Threat.
        """
        # Split n_normal into routine (60%) and realistic borderline (40%)
        n_routine = int(n_normal * 0.60)
        n_borderline = n_normal - n_routine

        events, meta = self.generate_realistic_benchmark(
            n_routine=n_routine,
            n_borderline=n_borderline,
            n_threats=n_anomalous,
        )

        labels = np.array([1 if m["is_threat"] else 0 for m in meta], dtype=int)

        # Shuffle deterministically
        indices = np.arange(len(events))
        self.rng.shuffle(indices)

        shuffled_events = [events[i] for i in indices]
        shuffled_labels = labels[indices]

        return shuffled_events, shuffled_labels
