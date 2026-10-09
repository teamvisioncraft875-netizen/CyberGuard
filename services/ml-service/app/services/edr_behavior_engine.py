"""
CYBERGUARD EDR Behavior Detection & Process-Tree Engine V1.
Evaluates endpoint execution chains, process-tree relationships, and syscall behavior
using a trained, calibrated Random Forest pipeline on real BETH host telemetry.

Outputs advisory behavioral risk scores, malicious probabilities, reconstructed execution chains,
and MITRE ATT&CK tactical context for SOC analysts.
Guaranteed non-destructive: strictly advisory-only (never kills, blocks, deletes, or remediates).
"""

import time
import json
import hashlib
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional
from collections import deque
import pandas as pd
import numpy as np
import joblib

from app.schemas.edr_behavior import (
    EDRBehaviorAnalysisRequest,
    EDRBehaviorAnalysisResponse,
)

logger = logging.getLogger(__name__)

MODELS_DIR = Path(__file__).resolve().parent.parent / "models"
REGISTRY_PATH = MODELS_DIR / "model_registry.json"
MODEL_PATH = MODELS_DIR / "edr_behavior" / "edr_behavior_classifier_v1.0.0.joblib"
METADATA_PATH = MODELS_DIR / "edr_behavior" / "edr_behavior_metadata.json"

SHELLS = {'bash', 'sh', 'zsh', 'dash', 'csh', 'tcsh', 'ksh'}
ADMIN_TOOLS = {'systemctl', '(ystemctl)', 'service', 'iptables', 'passwd', 'useradd', 'userdel', 'sudo', 'su', 'chmod', 'chown', 'crontab'}
DAEMONS = {'systemd', '(systemd)', 'systemd-journal', 'systemd-resolved', 'sshd', 'cron', 'snapd', 'amazon-ssm-agent', 'rs:main Q:Reg', '(sd-pam)', '(sd-executor)', '30-systemd-envi', '(direxec)'}
NET_TOOLS = {'wget', 'curl', 'nc', 'ncat', 'netcat', 'ssh', 'scp', 'rsync'}
COMPILERS = {'python', 'python3', 'perl', 'ruby', 'gcc', 'make', 'php'}
USER_UTILS = {'ps', 'cat', 'grep', 'egrep', 'awk', 'sed', 'cut', 'tr', 'head', 'tail', 'sort', 'who', 'w', 'uname', 'lscpu', 'free', 'top', 'ls', 'rm', 'mv', 'cp', 'tar', 'gzip', 'find', 'stat', 'mktemp', 'dirname', 'bc', 'date', 'id'}

FILE_SYSCALLS = {'open', 'openat', 'close', 'read', 'write', 'stat', 'fstat', 'lstat', 'security_file_open', 'access', 'getdents64', 'unlink', 'rename', 'dup', 'dup2'}
NET_SYSCALLS = {'socket', 'connect', 'bind', 'listen', 'accept', 'sendto', 'recvfrom', 'security_socket_connect', 'security_socket_sendmsg', 'getsockname', 'getpeername'}
PROC_SYSCALLS = {'execve', 'fork', 'clone', 'prctl', 'kill', 'sched_process_exit', 'wait4', 'exit_group'}
PRIV_SYSCALLS = {'cap_capable', 'setuid', 'setgid', 'setreuid', 'setresuid', 'security_bprm_check'}
INFO_SYSCALLS = {'uname', 'sysinfo', 'getuid', 'geteuid', 'getgid', 'getegid', 'getpid', 'getppid'}


def categorize_process(name: str) -> str:
    name = str(name).lower()
    if name in SHELLS: return 'shell'
    if name in ADMIN_TOOLS: return 'admin_tool'
    if name in DAEMONS: return 'daemon'
    if name in NET_TOOLS: return 'net_tool'
    if name in COMPILERS: return 'compiler'
    if name in USER_UTILS: return 'user_util'
    return 'other'


def categorize_event(name: str) -> str:
    name = str(name).lower()
    if name in FILE_SYSCALLS: return 'file_io'
    if name in NET_SYSCALLS: return 'net_socket'
    if name in PROC_SYSCALLS: return 'proc_ctrl'
    if name in PRIV_SYSCALLS: return 'priv_cap'
    if name in INFO_SYSCALLS: return 'info_query'
    return 'other'


class EDRBehaviorEngine:
    _instance: Optional["EDRBehaviorEngine"] = None

    def __init__(self):
        self._model = None
        self._threshold = 0.0300
        self._model_version = "1.0.0"
        self._expected_sha256 = None
        
        # Stateful causal tracking for running processes
        self._pid_table: Dict[int, Dict[str, Any]] = {
            0: {"processName": "swapper", "userId": 0, "parentProcessId": 0},
            1: {"processName": "systemd", "userId": 0, "parentProcessId": 0}
        }
        self._proc_cum_count: Dict[int, int] = {}
        self._proc_failed_count: Dict[int, int] = {}
        self._proc_seen_syscalls: Dict[int, set] = {}
        self._time_window: deque = deque()
        
        self._load_registry_metadata()
        self._load_model()

    @classmethod
    def get_instance(cls) -> "EDRBehaviorEngine":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def _load_registry_metadata(self):
        try:
            if REGISTRY_PATH.exists():
                with open(REGISTRY_PATH, "r", encoding="utf-8") as f:
                    reg = json.load(f)
                    edr_entry = reg.get("models", {}).get("edr_behavior", {})
                    self._expected_sha256 = edr_entry.get("artifact_sha256")
                    self._threshold = float(edr_entry.get("operating_threshold", 0.0300))
                    v = edr_entry.get("model_version", "1.0.0")
                    self._model_version = v.lstrip("v") if v else "1.0.0"
        except Exception as e:
            logger.warning(f"Could not parse registry metadata: {e}. Using defaults.")

    def _verify_artifact_sha(self, path: Path) -> bool:
        if not path.exists():
            return False
        hasher = hashlib.sha256()
        with open(path, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        current_sha = hasher.hexdigest()
        if self._expected_sha256 and current_sha != self._expected_sha256:
            logger.error(f"SHA-256 mismatch for {path}: expected {self._expected_sha256}, got {current_sha}")
            return False
        return True

    def _load_model(self):
        if not MODEL_PATH.exists():
            logger.error(f"EDR behavior model artifact not found at {MODEL_PATH}")
            self._model = None
            return

        if not self._verify_artifact_sha(MODEL_PATH):
            logger.error(f"Security validation failed: artifact SHA-256 integrity check failed for {MODEL_PATH}")
            self._model = None
            return

        try:
            self._model = joblib.load(MODEL_PATH)
            logger.info(f"Loaded EDR Behavior model v{self._model_version} from {MODEL_PATH}")
        except Exception as e:
            logger.error(f"Failed to deserialize model artifact {MODEL_PATH}: {e}")
            self._model = None

    def _extract_single_features(self, req: EDRBehaviorAnalysisRequest) -> pd.DataFrame:
        pid = req.process_id if req.process_id is not None and req.process_id > 0 else 9999
        ppid = req.parent_process_id if req.parent_process_id is not None and req.parent_process_id >= 0 else 1
        pname = req.process_name
        ename = req.event_name
        uid = req.user_id
        retval = req.return_value if req.return_value is not None else 0
        argsnum = req.args_num if req.args_num is not None else 0
        t = req.timestamp if req.timestamp is not None else time.time()

        # Update causal lineage state
        if pid not in self._pid_table:
            if len(self._pid_table) > 50000:
                excess_keys = [k for k in self._pid_table.keys() if k not in (0, 1)][:5000]
                for k in excess_keys:
                    self._pid_table.pop(k, None)
                    self._proc_cum_count.pop(k, None)
                    self._proc_failed_count.pop(k, None)
                    self._proc_seen_syscalls.pop(k, None)

            self._pid_table[pid] = {
                "processName": pname,
                "userId": uid,
                "parentProcessId": ppid
            }

        # Parent process name resolution
        if req.parent_process_name and req.parent_process_name not in ("UNKNOWN_PARENT", "unknown", ""):
            parent_name = req.parent_process_name
        else:
            parent_info = self._pid_table.get(ppid, {})
            parent_name = parent_info.get("processName", "UNKNOWN_PARENT")
        
        parent_uid = self._pid_table.get(ppid, {}).get("userId", -1)

        # 1. Categories
        p_cat = categorize_process(pname)
        parent_cat = categorize_process(parent_name)

        # 2. Ancestry
        is_p_init = 1 if ppid == 1 else 0
        is_p_kernel = 1 if ppid == 0 else 0
        is_p_known = 1 if (ppid in self._pid_table or parent_name != "UNKNOWN_PARENT") else 0

        # Check sshd or shell in lineage
        grandparent_ppid = self._pid_table.get(ppid, {}).get("parentProcessId", -1)
        grandparent_name = self._pid_table.get(grandparent_ppid, {}).get("processName", "")
        is_ssh = 1 if (parent_name == "sshd" or grandparent_name == "sshd") else 0
        is_sh = 1 if (parent_name in SHELLS or grandparent_name in SHELLS) else 0
        depth = 1 if ppid in (0, 1) else 2

        # 3. Privilege
        is_root = 1 if uid == 0 else 0
        is_system = 1 if (1 <= uid < 1000) else 0
        is_interactive = 1 if uid >= 1000 else 0
        priv_trans = 1 if (parent_uid != -1 and uid != parent_uid) else 0

        # 4. Execution
        ev_cat = categorize_event(ename)
        is_file = 1 if ev_cat == "file_io" else 0
        is_net = 1 if ev_cat == "net_socket" else 0
        is_proc = 1 if ev_cat == "proc_ctrl" else 0
        is_priv = 1 if ev_cat == "priv_cap" else 0
        is_failed = 1 if retval < 0 else 0
        args_num = min(5, max(0, int(argsnum)))
        ret_sign = -1 if retval < 0 else (1 if retval > 0 else 0)

        # 5. Causal process state accumulation
        c = self._proc_cum_count.get(pid, 0) + 1
        self._proc_cum_count[pid] = c
        f = self._proc_failed_count.get(pid, 0) + is_failed
        self._proc_failed_count[pid] = f
        if pid not in self._proc_seen_syscalls:
            self._proc_seen_syscalls[pid] = set()
        self._proc_seen_syscalls[pid].add(ename)
        u_syscalls = len(self._proc_seen_syscalls[pid])

        cum_event_count = float(np.log1p(c))
        failed_syscall_ratio = float(f / c)
        syscall_diversity = float(u_syscalls / c)

        # Recent frequency
        self._time_window.append(t)
        while self._time_window and (t - self._time_window[0] > 5.0):
            self._time_window.popleft()
        recent_freq = float(len(self._time_window))

        return pd.DataFrame([{
            'process_category': p_cat,
            'parent_process_category': parent_cat,
            'is_parent_init': is_p_init,
            'is_parent_kernel': is_p_kernel,
            'is_parent_known': is_p_known,
            'is_spawned_by_sshd': is_ssh,
            'is_spawned_by_shell': is_sh,
            'ancestry_depth': depth,
            'is_root': is_root,
            'is_system_user': is_system,
            'is_interactive_user': is_interactive,
            'privilege_transition': priv_trans,
            'event_category': ev_cat,
            'is_file_syscall': is_file,
            'is_network_syscall': is_net,
            'is_proc_ctrl_syscall': is_proc,
            'is_priv_cap_syscall': is_priv,
            'is_failed_syscall': is_failed,
            'args_num': args_num,
            'return_val_sign': ret_sign,
            'cum_event_count': cum_event_count,
            'unique_syscall_count': u_syscalls,
            'failed_syscall_count': f,
            'failed_syscall_ratio': failed_syscall_ratio,
            'syscall_diversity': syscall_diversity,
            'recent_event_freq': recent_freq
        }])

    def _determine_mitre_context(self, pname: str, ename: str, parent_name: str, uid: int) -> Optional[Dict[str, Any]]:
        pname_lower = pname.lower()
        if parent_name == "sshd" or pname_lower in SHELLS:
            return {
                "tactic": "Initial Access / Execution",
                "technique_id": "T1078.003",
                "technique_name": "Valid Accounts: Local Accounts",
                "subtechnique": "Interactive SSH session execution"
            }
        elif pname_lower in ("passwd", "crontab", "tar", "chmod", "modprobe"):
            return {
                "tactic": "Privilege Escalation / Persistence",
                "technique_id": "T1068",
                "technique_name": "Exploitation for Privilege Escalation",
                "subtechnique": "Credential alteration / persistence mechanism"
            }
        elif pname_lower in ("who", "w", "lscpu", "free", "top", "ls", "grep", "cat", "uname"):
            return {
                "tactic": "Discovery",
                "technique_id": "T1082",
                "technique_name": "System Information Discovery",
                "subtechnique": "Host reconnaissance via utility binary"
            }
        elif pname_lower in ("tsm", "wget", "krane", "curl", "nc"):
            return {
                "tactic": "Command and Control / Execution",
                "technique_id": "T1105",
                "technique_name": "Ingress Tool Transfer / Malicious Payload Execution",
                "subtechnique": "Backdoor payload execution"
            }
        return None

    def analyze(self, req: EDRBehaviorAnalysisRequest) -> EDRBehaviorAnalysisResponse:
        parent_name = req.parent_process_name if req.parent_process_name and req.parent_process_name != "unknown" else "UNKNOWN_PARENT"
        chain_str = f"{parent_name} -> {req.process_name}"

        if self._model is None:
            # Fallback heuristic if model artifact missing
            is_suspicious_lineage = (parent_name == "sshd" or parent_name in SHELLS) and req.user_id >= 1000
            score = 0.85 if is_suspicious_lineage else 0.01
            prob = score
            cls_name = "malicious_behavior" if score >= self._threshold else "benign_behavior"
            summary = f"[HEURISTIC FALLBACK] Process '{req.process_name}' in lineage '{chain_str}' evaluated via heuristic rule."
            return EDRBehaviorAnalysisResponse(
                behavior_score=round(score, 4),
                malicious_probability=round(prob, 4),
                classification=cls_name,
                confidence=0.70,
                behavior_summary=summary,
                observed_process_chain=chain_str,
                operating_threshold=self._threshold,
                is_advisory_only=True,
                mitre_context=self._determine_mitre_context(req.process_name, req.event_name, parent_name, req.user_id)
            )

        # Feature extraction
        feats = self._extract_single_features(req)
        
        # Inference
        probs = self._model.predict_proba(feats)[0]
        malicious_prob = float(probs[1]) if len(probs) > 1 else float(probs[0])
        score = malicious_prob

        is_malicious = score >= self._threshold
        classification = "malicious_behavior" if is_malicious else "benign_behavior"

        # Statistical confidence: distance from decision threshold
        if is_malicious:
            conf = min(0.99, max(0.60, 0.60 + (score - self._threshold) * 0.40 / max(0.001, (1.0 - self._threshold))))
        else:
            conf = min(0.99, max(0.60, 0.60 + (self._threshold - score) * 0.40 / max(0.001, self._threshold)))

        mitre = self._determine_mitre_context(req.process_name, req.event_name, parent_name, req.user_id)

        if is_malicious:
            summary = (
                f"Malicious behavioral execution pattern detected for process '{req.process_name}' "
                f"within execution chain '{chain_str}' (score: {score:.4f} >= threshold: {self._threshold:.4f}). "
                f"Syscall action: {req.event_name}. User privilege: {'root' if req.user_id == 0 else f'UID {req.user_id}'}."
            )
        else:
            summary = (
                f"Benign host execution pattern verified for process '{req.process_name}' "
                f"within execution chain '{chain_str}' (score: {score:.4f} < threshold: {self._threshold:.4f}). "
                f"Syscall action: {req.event_name} matches typical operating baseline."
            )

        return EDRBehaviorAnalysisResponse(
            behavior_score=round(score, 4),
            malicious_probability=round(malicious_prob, 4),
            classification=classification,
            confidence=round(conf, 4),
            behavior_summary=summary,
            observed_process_chain=chain_str,
            operating_threshold=self._threshold,
            is_advisory_only=True,
            mitre_context=mitre
        )
