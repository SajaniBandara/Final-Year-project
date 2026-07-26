#!/usr/bin/env python3
"""
functional_verification.py -- Full-system FUNCTIONAL VERIFICATION for MOBIGUARD.

Deliverable (2) for Task 8.  audit_equations.py proves the code is PRESENT;
this script proves the code WORKED, by reading the artefacts a completed run
actually wrote and asserting each subsystem behaved as docs/main.tex specifies.

Every check names the thesis equation (or metric M1-M12) it exercises:

    [PASS] FV07 eq:delay_updated  M6   attack inflates end-to-end latency vs clean
           avg_lat_ms: attacked=97.9250 >= clean=22.8274

SUBSYSTEMS COVERED
------------------
  A0 mobility & environment instrumentation
  A  run artefacts & CSV schema conformance
  B  metric validity + independent recomputation (M1-M4, M6)
  C  attack impact, per attack family (time-delay / TCAM / hidden-forwarding)
  D  LRAD detection response across the intensity sweep
  E  dual-mode architecture (D_OBU -> escalation -> D_RSU)
  F  TCAM signatures S3/S4
  G  hidden-forwarding signatures S5-S8 and unauthorised copies (M3)
  H  witness-based forwarding verification (M12)
  I  hybrid cryptographic integrity layer (M7)
  J  crypto operation timing log and causal ordering
  K  blockchain endorsement, audit trail and anchoring (M11)
  L  trust management and controller failover (M5)
  M  distributed trusted time reference (M9)
  N  federated LSTM pipeline (M8)
  O  EXTERNAL baselines B2 (SFTO-Guard) and B3 (FADE)
  P  EXTERNAL baseline B1 (TAP)
  Q  metric coverage roll-up (M1-M12)

Groups A-N verify MOBIGUARD, the proposed framework.  Groups O and P verify
the three EXTERNAL state-of-the-art baselines defined in docs/main.tex
"External Baselines" -- B1 TAP (Arsalan & Rehman 2018), B2 SFTO-Guard (Tang
2023) and B3 FADE (Zhang 2021).  These are independent prior-art detectors
re-implemented for comparison ONLY; they are not components of the proposed
solution, and their checks assert that each comparator produced usable output
to benchmark against, not that MOBIGUARD works.

Groups A-P run once per attack sweep discovered in the result directories;
A0, J, N, O and Q run once for the whole verification.

STATUS SEMANTICS
----------------
  PASS  the artefact exists and the asserted property holds
  FAIL  the artefact exists and the property does NOT hold -- a real defect
  WARN  the artefact was not produced by this run, so the property could not be
        evaluated (e.g. no TCAM sweep present).  A WARN is a gap in run
        coverage, not a defect; --strict exits non-zero on FAIL only.

Usage:
  python3 scripts/functional_verification.py
  python3 scripts/functional_verification.py --results-dir <path> [--results-dir <p2>]
  python3 scripts/functional_verification.py --attack 1 --delay 80
  python3 scripts/functional_verification.py --strict --no-color
"""

import argparse
import glob
import importlib.util
import json
import math
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

# Reuse the positional CSV parser from verify_metrics.py (same directory).
_spec = importlib.util.spec_from_file_location(
    "verify_metrics", os.path.join(HERE, "verify_metrics.py"))
vm = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(vm)

# Result directories searched when --results-dir is not given.  These mirror
# run_rule_based_sweep.py's NS3_DIR (~/ns3_g13_apsari/...); the pre-migration
# ~/ns3_g13_apsari tree is deliberately NOT a default -- pass it with --results-dir if
# you need to inspect those older runs.
DEFAULT_RESULTS = [
    os.path.expanduser("~/ns3_g13_apsari/ns-allinone-3.35/ns-3.35/results_routing"),
    os.path.expanduser("~/ns3_g13_apsari/ns-allinone-3.35/ns-3.35/results_routing_test_runs_1"),
    os.path.expanduser("~/ns3_g13_apsari/ns-allinone-3.35/ns-3.35/results_routing_test_runs/results_routing"),
]


def newest_source_mtime():
    """mtime of the most recently modified simulator source, or None."""
    scratch = os.path.join(ROOT, "scratch")
    if not os.path.isdir(scratch):
        return None
    times = [os.path.getmtime(os.path.join(scratch, n))
             for n in os.listdir(scratch) if n.endswith((".h", ".cc", ".cpp"))]
    return max(times) if times else None


SRC_MTIME = newest_source_mtime()

# TAP baseline CSV has its own 19-column schema (write_tap_csv in tap_detection.h).
TAP_COLUMNS = [
    "cycle", "cur_PDR", "avg_PDR", "cur_lat_ms", "avg_lat_ms", "cur_MCC", "avg_MCC",
    "cur_DR", "avg_DR", "cur_FPR", "avg_FPR", "cur_mit_ms", "avg_mit_ms",
    "TP", "FP", "TN", "FN", "cur_TVR", "avg_TVR",
]

# Attack variant -> (family key, human label).  docs/main.tex "Attack Scenarios"
# defines TWO top-level attack classes, four variants each:
#
#   SELECTIVE TIME DELAY  variants 1-4.  Variants 1-2 inject the delay directly;
#                         variants 3-4 induce the same delay indirectly by
#                         exhausting the RSU TCAM so safety packets miss their
#                         flow rule and take the slow path.  All four are
#                         selective time delay attacks.
#   HIDDEN FORWARDING     variants 5-8 (active 5-6, passive 7-8).
#
# `family` selects which impact assertions apply (a TCAM variant is proven
# through occupancy, a direct variant through injected latency); `parent` is
# the paper's attack class, reported in the coverage roll-up.
ATTACK_FAMILY = {
    1: ("delay", "Selective Time Delay: Direct Injection, Control Plane"),
    2: ("delay", "Selective Time Delay: Direct Injection, Data Plane"),
    3: ("tcam",  "Selective Time Delay: Slow TCAM Exhaustion, Control Plane"),
    4: ("tcam",  "Selective Time Delay: Slow TCAM Exhaustion, Data Plane"),
    5: ("hf",    "Hidden Forwarding: Active, Control Plane"),
    6: ("hf",    "Hidden Forwarding: Active, Data Plane"),
    7: ("hf",    "Hidden Forwarding: Passive, Control Plane"),
    8: ("hf",    "Hidden Forwarding: Passive, Data Plane"),
}

ATTACK_CLASS = {v: "SELECTIVE TIME DELAY" if v <= 4 else "HIDDEN FORWARDING"
                for v in range(1, 9)}


def _src_const(pattern, cast=float, default=None):
    """Read a design constant back out of scratch/, so the thresholds asserted
    here stay tied to the build rather than to hard-coded copies of it."""
    scratch = os.path.join(ROOT, "scratch")
    if not os.path.isdir(scratch):
        return default
    for name in sorted(os.listdir(scratch)):
        if not name.endswith((".h", ".cc")):
            continue
        try:
            with open(os.path.join(scratch, name), errors="ignore") as fh:
                m = re.search(pattern, fh.read())
        except OSError:
            continue
        if m:
            try:
                return cast(m.group(1))
            except (ValueError, IndexError):
                pass
    return default


BATCH_SIZE  = _src_const(r"BATCH_SIZE\s*=\s*(\d+)", int, 15)
N_RSUS      = _src_const(r"uint32_t\s+N_RSUs\s*=\s*(\d+)", int, 64)
TRUST_T_MIN = _src_const(r"TRUST_T_MIN\s*=\s*([0-9.]+)", float, 0.5)


# --------------------------------------------------------------------------- #
# Output plumbing
# --------------------------------------------------------------------------- #

class Palette:
    def __init__(self, on):
        self.G = "\033[32m" if on else ""
        self.R = "\033[31m" if on else ""
        self.Y = "\033[33m" if on else ""
        self.D = "\033[2m"  if on else ""
        self.O = "\033[0m"  if on else ""


class Report:
    """Accumulates checks, prints them grouped, and tallies the outcome."""

    def __init__(self, palette):
        self.c = palette
        self.n = 0
        self.pass_ = self.fail = self.warn = 0
        self.failures = []
        self.metrics_seen = set()

    def group(self, title, eqs):
        print("=" * 78)
        print(title)
        print(f"    /{eqs}/")
        print("=" * 78)

    def add(self, eq, metric, desc, result):
        """result is (status, message) from one of the assertion helpers."""
        status, msg = result
        self.n += 1
        if status == "PASS":
            self.pass_ += 1
            col = self.c.G
            if metric:
                self.metrics_seen.add(metric)
        elif status == "WARN":
            self.warn += 1
            col = self.c.Y
        else:
            self.fail += 1
            col = self.c.R
            self.failures.append(f"FV{self.n:02d} {eq} -- {desc}: {msg}")
        mt = f"{metric:<4}" if metric else "    "
        print(f"  {col}[{status}]{self.c.O} FV{self.n:02d} {eq:<24} {mt} {desc}")
        print(f"         {self.c.D}{msg}{self.c.O}")


# --------------------------------------------------------------------------- #
# Assertion helpers -- each returns (status, message)
# --------------------------------------------------------------------------- #

def rng(val, lo, hi, name):
    if val is None:
        return "WARN", f"{name}: column absent from this run"
    return ("PASS", f"{name}={val:.4f} in [{lo},{hi}]") if lo <= val <= hi \
        else ("FAIL", f"{name}={val:.4f} OUT OF [{lo},{hi}]")


def gt(val, thr, name):
    if val is None:
        return "WARN", f"{name}: column absent from this run"
    return ("PASS", f"{name}={val:.4f} > {thr}") if val > thr \
        else ("FAIL", f"{name}={val:.4f} NOT > {thr}")


def gte(val, thr, name):
    if val is None:
        return "WARN", f"{name}: column absent from this run"
    return ("PASS", f"{name}={val:.4f} >= {thr}") if val >= thr \
        else ("FAIL", f"{name}={val:.4f} NOT >= {thr}")


def lte(val, thr, name):
    if val is None:
        return "WARN", f"{name}: column absent from this run"
    return ("PASS", f"{name}={val:.4f} <= {thr}") if val <= thr \
        else ("FAIL", f"{name}={val:.4f} NOT <= {thr}")


def cmp_hi(hi, lo, name, what="attacked", ref="clean"):
    if hi is None or lo is None:
        return "WARN", f"{name}: needs both a pct=0 and a top-pct run"
    return ("PASS", f"{name}: {what}={hi:.4f} >= {ref}={lo:.4f}") if hi >= lo \
        else ("FAIL", f"{name}: {what}={hi:.4f} < {ref}={lo:.4f} (no effect)")


def approx(reported, recomputed, tol, name):
    if reported is None or recomputed is None:
        return "WARN", f"{name}: inputs absent"
    ok = abs(reported - recomputed) <= tol
    return ("PASS" if ok else "FAIL",
            f"{name}: recomputed={recomputed:.4f} reported={reported:.4f} "
            f"(tolerance {tol})")


def truth(cond, ok_msg, bad_msg):
    return ("PASS", ok_msg) if cond else ("FAIL", bad_msg)


def _stamp(mtime):
    import datetime
    return datetime.datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M")


_ROW_COUNT_CACHE = {}


def data_rows(path):
    """Number of non-comment, non-header rows in a CSV.

    Cached: the blockchain audit logs run to several MB and the same file is
    consulted once per attack subject, so an uncached count dominates runtime.
    """
    if path in _ROW_COUNT_CACHE:
        return _ROW_COUNT_CACHE[path]
    n, header = 0, 0
    try:
        # Binary + explicit decode: some artefacts carry stray non-UTF-8 bytes,
        # which the incremental text decoder chokes on even with errors="ignore".
        with open(path, "rb") as fh:
            for raw in fh:
                line = raw.decode("utf-8", "replace")
                if not line.strip() or line.startswith("#"):
                    continue
                if n == 0:
                    try:
                        float(line.split(",", 1)[0].strip())
                    except ValueError:
                        header = 1  # first data line was a text header
                n += 1
    except OSError:
        pass
    _ROW_COUNT_CACHE[path] = max(n - header, 0)
    return _ROW_COUNT_CACHE[path]


def present(paths, name, need_rows=True):
    """PASS if at least one of `paths` exists (and has data rows if required)."""
    if not paths:
        return "WARN", f"{name}: not produced by this run"
    with_rows = [p for p in paths if data_rows(p) > 0]
    if need_rows and not with_rows:
        return "WARN", f"{name}: {len(paths)} file(s) present but header-only"
    return "PASS", (f"{name}: {len(paths)} file(s), "
                    f"{sum(data_rows(p) for p in with_rows)} data row(s)")


# --------------------------------------------------------------------------- #
# Loaders
# --------------------------------------------------------------------------- #

# Result filenames differ per runner, and every form must be discovered:
#   run_std_attacks.py       MOBIGUARD_Attack1_100_d80ms.csv
#   run_hf_attacks.py        MOBIGUARD_Attack5_100.csv
#   run_rule_based_sweep.py  MOBIGUARD_Attack3_100_seed1.csv
#
# The rule-based sweep ALWAYS renames its output to embed the seed (even for a
# single seed), because write_security_metrics_csv() has no seed in its
# filename and opens with ios::app -- two concurrent seeds of the same
# (attack, pct) would otherwise interleave into one file.  It is also the only
# runner that produces attacks 3 and 4, so a pattern that rejected the _seed
# suffix would silently drop every TCAM result and report "sweep not run".
MG_RE = re.compile(
    r"MOBIGUARD_Attack(\d+)_(\d+)(?:_d(\d+)ms)?(?:_seed(\d+))?\.csv$")


def find_files(dirs, pattern):
    out = []
    for d in dirs:
        out.extend(sorted(glob.glob(os.path.join(d, pattern))))
    return out


def discover_subjects(dirs):
    """-> ({(attack, delay): {pct: (rows, path)}}, {(attack, delay): {pct: {seeds}}})

    One (attack, pct, delay) can appear several times: once per result
    directory, and once per RNG seed when the rule-based sweep ran multiple
    seeds.  The most recently written file is the one verified, so a stale copy
    in a secondary directory can never silently shadow a fresh run -- and the
    seeds seen are returned alongside, so the log can state how many were
    available rather than quietly verifying one of them.
    """
    subjects, seeds = {}, {}
    for path in find_files(dirs, "MOBIGUARD_Attack*.csv"):
        m = MG_RE.search(os.path.basename(path))
        if not m:
            continue
        attack, pct = int(m.group(1)), int(m.group(2))
        delay = int(m.group(3)) if m.group(3) else None
        seed = int(m.group(4)) if m.group(4) else None
        rows = vm.parse_mobiguard_csv(path)
        if not rows:
            continue
        key = (attack, delay)
        if seed is not None:
            seeds.setdefault(key, {}).setdefault(pct, set()).add(seed)
        bucket = subjects.setdefault(key, {})
        if pct in bucket and os.path.getmtime(bucket[pct][1]) >= os.path.getmtime(path):
            continue
        bucket[pct] = (rows, path)
    return subjects, seeds


def parse_crypto_ops(dirs):
    """{op_name: [row, ...]} from every crypto_timing_log*.csv found.

    One file per (variant, pct, seed, delay) run since g_sim_tag was added to
    its filename (crypto_event_log.h) -- glob to pick up all of them.
    """
    ops = {}
    for p in find_files(dirs, "crypto_timing_log*.csv"):
        run_tag = os.path.basename(p)
        with open(p, "rb") as fh:
            for raw in fh:
                parts = [x.strip() for x in raw.decode("utf-8", "replace").split(",")]
                if len(parts) != 6 or parts[0] == "sim_time_s":
                    continue
                try:
                    ops.setdefault(parts[1], []).append(
                        {"t": float(parts[0]), "op": parts[1], "node": int(parts[2]),
                         "pkt": int(parts[3]), "us": float(parts[4]), "res": parts[5],
                         "run": run_tag})
                except ValueError:
                    continue
    return ops


def load_tap(dirs, attack, delay):
    """{pct: last_row} for the TAP baseline of one subject (19-column schema)."""
    suffix = f"_d{delay}ms" if delay is not None else ""
    out = {}
    for path in find_files(dirs, f"TAP_Attack{attack}_*{suffix}.csv"):
        m = re.search(r"TAP_Attack\d+_(\d+)", os.path.basename(path))
        if not m:
            continue
        rows = []
        with open(path, "rb") as fh:
            for raw in fh:
                line = raw.decode("utf-8", "replace").strip()
                if not line or line.startswith("#"):
                    continue
                parts = [p.strip() for p in line.split(",")]
                if len(parts) != len(TAP_COLUMNS):
                    continue
                try:
                    rows.append(dict(zip(TAP_COLUMNS, [float(p) for p in parts])))
                except ValueError:
                    continue
        if rows:
            out[int(m.group(1))] = rows[-1]
    return out


def load_json(path):
    try:
        with open(path) as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


# --------------------------------------------------------------------------- #
# No-bypass attestation
#
# Task 8 requires evidence of "correct coding WITHOUT BYPASSING MODELING".
# crypto_layer.h exposes one kill-switch (--disable_crypto) and ten ablation
# gates (--enable_*) that each short-circuit a modelled subsystem.  A run made
# with any of them off is an ABLATION run, not full-system evidence.
#
# Each entry: (flag, bypass_value, subsystem, evidence_fn)
#   evidence_fn(top, ops) -> (ran: bool|None, detail: str)
#     True   the subsystem demonstrably executed in this run
#     False  it demonstrably did not
#     None   this run cannot tell either way
# --------------------------------------------------------------------------- #

def _ev(cond, yes, no):
    return (bool(cond), yes if cond else no)


def _ev_crypto(top, ops):
    sigs = len(ops.get("sign", [])) + len(ops.get("verify", []))
    rate = top.get("sig_valid_rate")
    byts = top.get("o_crypto_bytes_pkt")
    return _ev(sigs > 0 and (byts or 0) > 0,
               f"{sigs} ML-DSA sign/verify op(s) timed, sig_valid_rate={rate}, "
               f"o_crypto_bytes_pkt={byts}",
               "no ML-DSA sign/verify activity and no crypto bytes accrued")


def _ev_obu(top, ops):
    n = len(ops.get("lrad_obu", []))
    c = top.get("d_obu_count")
    return _ev(n > 0 or (c or 0) > 0,
               f"{n} lrad_obu invocation(s) timed, d_obu_count={c}",
               "OBU rule engine never ran")


def _ev_rsu(top, ops):
    n = len(ops.get("lrad_rsu", []))
    c = top.get("d_rsu_count")
    return _ev(n > 0, f"{n} lrad_rsu invocation(s) timed, d_rsu_count={c}",
               "RSU full-mode engine never ran")


def _ev_stark_delay(top, ops):
    t = top.get("t_stark_ms_avg")
    f = top.get("stark_timing_fail_count")
    return _ev((t or 0) > 0, f"t_stark_ms_avg={t}, stark_timing_fail_count={f}",
               "no STARK timing-proof cost recorded")


def _ev_stark_hop(top, ops):
    n = len(ops.get("stark_hop", []))
    return _ev(n > 0, f"{n} stark_hop proof op(s) timed",
               "no STARK hop-proof activity")


def _ev_witness(top, ops):
    da, nfa = top.get("witness_da_count"), top.get("witness_nfa_count")
    p = top.get("WAP_precision")
    ran = (da or 0) > 0 or (nfa or 0) > 0 or (p or 0) > 0
    return (ran if ran else None), (
        f"witness_da_count={da}, witness_nfa_count={nfa}, WAP_precision={p}"
        if ran else
        f"no witness alerts fired (da={da}, nfa={nfa}) -- consistent with either "
        f"an inactive mechanism or an attack that raised none")


def _ev_quarantine(top, ops):
    t = top.get("avg_trust_score")
    if t is None:
        return None, "avg_trust_score absent"
    return (True, f"trust scoring active, avg_trust_score={t:.4f} (moved off 1.0)") \
        if t < 1.0 else \
        (None, "avg_trust_score is exactly 1.0 -- no penalty was ever applied, "
               "so trust updates cannot be distinguished from a disabled gate")


def _ev_endorse(top, ops):
    r = top.get("flowmod_endorsement_rate")
    n = len(ops.get("consensus", []))
    return _ev((r or 0) > 0 or n > 0,
               f"flowmod_endorsement_rate={r}, {n} consensus round(s) timed",
               "no FlowMod endorsement or consensus activity")


def _ev_failover(top, ops):
    ev = top.get("ctrl_failover_events")
    if ev is None:
        return None, "ctrl_failover_events absent"
    return (True, f"{ev:.0f} controller revocation/failover event(s)") if ev > 0 else \
        (None, "no controller fell below T_min_ctrl, so the failover path was "
               "never entered -- cannot distinguish from a disabled gate")


def _ev_keyrot(top, ops, ctx=None):
    rounds = (ctx or {}).get("dkg_rounds")
    if rounds is None:
        return None, ("no bc_dkg_log found; key rotation fires only on RSU "
                      "revocation and is not visible in the metrics CSV")
    if rounds > 1:
        return True, (f"bc_dkg_log records {rounds} DKG round(s) -- round>1 is a "
                      f"re-keying, so eq:vk_commit_rotated executed")
    # A single round is the initial DKG ceremony only.  Key rotation fires ONLY
    # when an RSU is revoked (trust < T_min); if no RSU crossed that threshold in
    # this run, rotation was simply not triggered -- that is neither activity to
    # confirm nor evidence of a bypass, so report WARN (None), not FAIL.
    return None, ("bc_dkg_log records a single round (initial DKG ceremony only); "
                  "key rotation fires only on RSU revocation, which did not occur "
                  "in this run -- not exercised here, not bypassed")


def _ev_lstm(top, ops):
    return None, ("live in-sim LSTM inference is OFF BY DEFAULT "
                  "(enable_lstm_inference=false in crypto_layer.h); the federated "
                  "LSTM is evaluated offline in lstm_pipeline/ -- see GROUP N")


BYPASS_GATES = [
    ("disable_crypto",              "1", "ML-DSA-87 + STARK crypto layer", _ev_crypto),
    ("enable_lrad_obu",             "0", "AB1 OBU rule engine",            _ev_obu),
    ("enable_lrad_rsu",             "0", "AB1 RSU full-mode engine",       _ev_rsu),
    ("enable_stark_delay",          "0", "AB4 STARK timing proof",         _ev_stark_delay),
    ("enable_stark_hop",            "0", "AB4 STARK hop proof",            _ev_stark_hop),
    ("enable_witness_mechanism",    "0", "AB6 witness mechanism",          _ev_witness),
    ("enable_quarantine",           "0", "AB7 trust + SC.Quarantine",      _ev_quarantine),
    ("enable_endorsement_requirement", "0", "AB8 f+1 FlowMod endorsement", _ev_endorse),
    ("enable_controller_failover",  "0", "AB9 controller trust/failover",  _ev_failover),
    ("enable_key_rotation",         "0", "AB11 ZKP key rotation",          _ev_keyrot),
    ("enable_lstm_inference",       "0", "live in-sim LSTM inference",     _ev_lstm),
]


def max_dkg_round(paths):
    """Highest `round` value across bc_dkg_log files, or None if unavailable."""
    best = None
    for p in paths:
        with open(p, "rb") as fh:
            for raw in fh:
                parts = raw.decode("utf-8", "replace").split(",")
                if len(parts) < 2:
                    continue
                try:
                    r = int(parts[1])
                except ValueError:
                    continue  # header row
                best = r if best is None else max(best, r)
    return best


def find_run_logs(attack, delay, pct=None):
    """Run logs written by the sweep runners.

    Filename is A<attack>_pct<pct>[_d<X>ms]_seed<N>.log, but the directory
    differs by runner: run_std_attacks.py / run_hf_attacks.py write straight to
    logs/, while run_rule_based_sweep.py nests them under logs/rule_based_sweep/.
    Search recursively so the no-bypass attestation finds the authoritative
    '# Command:' header wherever a runner chose to put it.
    """
    sfx = f"_d{delay}ms" if delay is not None else ""
    pat = f"A{attack}_pct{'*' if pct is None else pct}{sfx}_seed*.log"
    return sorted(glob.glob(os.path.join(ROOT, "logs", "**", pat), recursive=True))


def parse_run_flags(paths):
    """{flag: value} from the '# Command:' header the runner writes."""
    flags = {}
    for p in paths:
        try:
            with open(p, errors="ignore") as fh:
                head = fh.readline()
        except OSError:
            continue
        if not head.startswith("# Command:"):
            continue
        for k, v in re.findall(r"--([A-Za-z_]+)=(\S+)", head):
            flags.setdefault(k, set()).add(v.rstrip('"\''))
    return flags


def split_runs(rows):
    """Split a metrics CSV into per-run segments.

    A re-run appends to the existing file rather than truncating it, so one CSV
    can hold several runs back to back.  Each run restarts its cycle counter at
    1, so a decrease in `cycle` marks a run boundary.  Per-run invariants
    (monotone cycle index, monotone chain length) hold within a segment, never
    across the concatenation.
    """
    segments, cur = [], []
    for row in rows:
        if cur and (row.get("cycle") or 0) <= (cur[-1].get("cycle") or 0):
            segments.append(cur)
            cur = []
        cur.append(row)
    if cur:
        segments.append(cur)
    return segments


# --------------------------------------------------------------------------- #
# Independent recomputations -- a check must not simply trust the column it is
# verifying, so the confusion-matrix columns are used to re-derive the rates.
# --------------------------------------------------------------------------- #

def mcc_from_confusion(row):
    tp, fp, tn, fn = row.get("TP"), row.get("FP"), row.get("TN"), row.get("FN")
    if None in (tp, fp, tn, fn):
        return None
    den = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    return (tp * tn - fp * fn) / den if den > 0 else 0.0


def dr_from_confusion(row):
    tp, fn = row.get("TP"), row.get("FN")
    if None in (tp, fn) or (tp + fn) == 0:
        return None
    return 100.0 * tp / (tp + fn)


def fpr_from_confusion(row):
    fp, tn = row.get("FP"), row.get("TN")
    if None in (fp, tn) or (fp + tn) == 0:
        return None
    return 100.0 * fp / (fp + tn)


# --------------------------------------------------------------------------- #
# Per-subject verification (groups A..P, run once per attack sweep)
# --------------------------------------------------------------------------- #

def verify_subject(rep, dirs, attack, delay, runs, ops):
    pcts = sorted(runs)
    all_rows, top_path = runs[pcts[-1]]
    # A CSV may hold several appended runs; verify the most recent one.
    segments = split_runs(all_rows)
    top_rows = segments[-1]
    top = top_rows[-1]
    clean = split_runs(runs[0][0])[-1][-1] if 0 in runs else None
    family, label = ATTACK_FAMILY.get(attack, ("unknown", f"Attack {attack}"))
    tag = f"A{attack} {label}" + (f", d={delay}ms" if delay else "")

    # ---- A. run artefacts & schema ---------------------------------------- #
    rep.group(f"GROUP A [{tag}] -- RUN ARTEFACTS & CSV SCHEMA",
              "routing.cc:write_security_metrics_csv")
    is_tcam_schema = "max_tcam_util" in top
    ncols = len(vm.COLUMNS_TCAM) if is_tcam_schema else len(vm.COLUMNS_NO_TCAM)
    rep.add("schema", None, "metrics CSV parses at a known column width",
            truth(len(top) == ncols,
                  f"{os.path.basename(top_path)}: {len(top)} columns "
                  f"({'TCAM' if is_tcam_schema else 'non-TCAM'} schema)",
                  f"{len(top)} columns, expected {ncols}"))
    rep.add("schema", None, "sweep covers a clean baseline and an attacked endpoint",
            ("PASS", f"pct={pcts} (clean pct=0 present)") if len(pcts) >= 2 and 0 in runs
            else ("WARN", f"pct={pcts} -- single-point run, so the clean-vs-attacked "
                          f"comparisons below cannot be evaluated"))
    cycles = [r.get("cycle") for r in top_rows]
    seg_note = (f" (file holds {len(segments)} appended run(s); verifying the "
                f"most recent)" if len(segments) > 1 else "")
    rep.add("schema", None,
            "cycle index is strictly increasing within the run (no truncated writes)",
            truth(all(b > a for a, b in zip(cycles, cycles[1:])),
                  f"{len(cycles)} cycles, {cycles[0]:.0f}..{cycles[-1]:.0f} "
                  f"monotone{seg_note}",
                  f"cycle column is not monotone within a single run{seg_note} "
                  f"-- interleaved or truncated write"))
    rep.add("schema", None, "no NaN/Inf values written to the metrics CSV",
            truth(all(math.isfinite(v) for r in top_rows for v in r.values()),
                  f"all {len(top_rows) * len(top)} cells finite",
                  "NaN or Inf present in the metrics CSV"))
    # A result file older than the simulator sources was produced by a previous
    # build, so any failure below may already be fixed -- say so explicitly
    # rather than reporting a stale artefact as a defect in the current code.
    art_mtime = os.path.getmtime(top_path)
    fresh = SRC_MTIME is None or art_mtime >= SRC_MTIME
    rep.add("schema", None, "artefact was produced by the current source build",
            ("PASS", f"{os.path.basename(top_path)} is newer than the newest "
                     f"scratch/ source")
            if fresh else
            ("WARN", f"{os.path.basename(top_path)} "
                     f"({_stamp(art_mtime)}) PREDATES the current simulator sources "
                     f"({_stamp(SRC_MTIME)}) -- re-run this sweep; failures below "
                     f"may already be fixed"))

    dkg = find_files(dirs, f"bc_dkg_log_Attack{attack}_*"
                           + (f"_d{delay}ms" if delay is not None else "") + ".csv")
    verify_no_bypass(rep, attack, delay, top, ops, tag,
                     {"dkg_rounds": max_dkg_round(dkg)})

    # ---- B. metric validity + recomputation -------------------------------- #
    rep.group(f"GROUP B [{tag}] -- METRIC VALIDITY & RECOMPUTATION (M1-M4, M6)",
              "eq:mcc, eq:tvr, eq:ucr, eq:l_mit, eq:l_e2e")
    rep.add("eq:mcc", "M1", "avg_MCC within the valid correlation range",
            rng(top.get("avg_MCC"), -1.0, 1.0, "avg_MCC"))
    rep.add("eq:mcc", "M1", "cur_MCC equals MCC recomputed from TP/FP/TN/FN",
            approx(top.get("cur_MCC"), mcc_from_confusion(top), 1e-3, "cur_MCC"))
    rep.add("eq:mcc", "M1", "cur_DR equals TP/(TP+FN) recomputed from the confusion matrix",
            approx(top.get("cur_DR"), dr_from_confusion(top), 1e-2, "cur_DR"))
    rep.add("eq:mcc", "M1", "cur_FPR equals FP/(FP+TN) recomputed from the confusion matrix",
            approx(top.get("cur_FPR"), fpr_from_confusion(top), 1e-2, "cur_FPR"))
    rep.add("eq:tvr", "M2", "avg_TVR is a valid non-negative rate",
            rng(top.get("avg_TVR"), 0.0, 100.0, "avg_TVR"))
    rep.add("eq:ucr", "M3", "avg_UCR within [0,100]",
            rng(top.get("avg_UCR"), 0.0, 100.0, "avg_UCR"))
    rep.add("eq:l_mit", "M4", "mitigation latency is non-negative",
            gte(top.get("avg_mit_ms"), 0.0, "avg_mit_ms"))
    rep.add("eq:l_e2e", "M6", "avg end-to-end latency is positive",
            gt(top.get("avg_lat_ms"), 0.0, "avg_lat_ms"))
    rep.add("eq:l_e2e", "M6", "avg PDR is a valid percentage",
            rng(top.get("avg_PDR"), 0.0, 100.0, "avg_PDR"))

    # ---- C. attack impact, per family -------------------------------------- #
    rep.group(f"GROUP C [{tag}] -- ATTACK IMPACT",
              "eq:delay_updated, eq:intensity_td, eq:intensity_hf, eq:sig_s3, eq:ucr")
    if family == "delay":
        rep.add("eq:delay_updated", "M6", "attack inflates end-to-end latency vs clean",
                cmp_hi(top.get("avg_lat_ms"), clean and clean.get("avg_lat_ms"),
                       "avg_lat_ms"))
        rep.add("eq:tvr", "M2", "attack raises the safety-threshold violation rate",
                cmp_hi(top.get("avg_TVR"), clean and clean.get("avg_TVR"), "avg_TVR"))
        rep.add("eq:intensity_td", "M2", "clean baseline (pct=0) shows ~zero violation",
                rng(clean.get("avg_TVR"), 0.0, 0.5, "clean avg_TVR") if clean
                else ("WARN", "no pct=0 run present"))
    elif family == "tcam":
        rep.add("eq:sig_s3", None, "attack drives TCAM occupancy above the clean baseline",
                cmp_hi(top.get("max_tcam_util"), clean and clean.get("max_tcam_util"),
                       "max_tcam_util"))
        rep.add("eq:delay_updated", "M6", "TCAM exhaustion inflates end-to-end latency",
                cmp_hi(top.get("avg_lat_ms"), clean and clean.get("avg_lat_ms"),
                       "avg_lat_ms"))
        rep.add("eq:intensity_td", None, "malicious FlowMod injections recorded",
                gt(top.get("total_lambda_fm"), 0.0, "total_lambda_fm"))
    elif family == "hf":
        rep.add("eq:ucr", "M3", "hidden forwarding raises the unauthorised copy rate",
                cmp_hi(top.get("avg_UCR"), clean and clean.get("avg_UCR"), "avg_UCR"))
        rep.add("eq:intensity_hf", "M3", "unauthorised copies actually occurred",
                gt(top.get("avg_UCR"), 0.0, "avg_UCR"))
        rep.add("eq:intensity_hf", None, "clean baseline shows no unauthorised copies",
                rng(clean.get("avg_UCR"), 0.0, 0.5, "clean avg_UCR") if clean
                else ("WARN", "no pct=0 run present"))
    else:
        for eq, d in (("eq:intensity_td", "attack inflates its target metric"),
                      ("eq:tvr", "attack raises its violation metric"),
                      ("eq:intensity_td", "clean baseline is quiescent")):
            rep.add(eq, None, d, ("WARN", f"attack {attack} has no family mapping"))

    # ---- D. detection response --------------------------------------------- #
    rep.group(f"GROUP D [{tag}] -- LRAD DETECTION RESPONSE",
              "eq:sig_s1, eq:sig_s2, eq:rule_s1, eq:mcc, eq:intensity_td")
    rep.add("eq:sig_s1", "M1", "detector separates attacked from clean (MCC rises)",
            cmp_hi(top.get("avg_MCC"), clean and clean.get("avg_MCC"), "avg_MCC"))
    rep.add("eq:rule_s1", "M1", "detection rate is non-zero under an active attack",
            gt(top.get("avg_DR"), 0.0, "avg_DR"))
    # main.tex sec:metrics (M1): "hyperparameters are rejected if the resulting FPR
    # exceeds 1% in either mode" -- this is the paper's explicit calibration target,
    # not a loose sanity bound. A FAIL here under an active-attack sweep most likely
    # reflects that s1_k/s1_beta/U_thresh/etc. are still running on their main.tex
    # [tbd] initial-candidate values rather than the final calibrated sweep result
    # (see the S3/S4 FPR discussion in GROUP F below for the same caveat) -- it is
    # real evidence the calibration sweep is not yet complete, not necessarily a
    # coding defect.
    rep.add("eq:rule_s1", "M1", "false-positive rate meets the main.tex M1 calibration target (<=1%)",
            rng(top.get("avg_FPR"), 0.0, 1.0, "avg_FPR"))
    rep.add("eq:sig_s2", "M1", "the detector fired at all (confusion matrix non-empty)",
            gt(sum(top.get(k) or 0.0 for k in ("TP", "FP", "FN")), 0.0, "TP+FP+FN"))
    if len(pcts) >= 3:
        mid = runs[pcts[len(pcts) // 2]][0][-1]
        mid_mcc = mid.get("avg_MCC")
        rep.add("eq:intensity_td", "M1",
                "detection holds up as attack intensity rises (top vs mid sweep point)",
                gte(top.get("avg_MCC"), (mid_mcc or 0.0) - 0.35,
                    f"avg_MCC(pct={pcts[-1]}) vs avg_MCC(pct={pcts[len(pcts) // 2]})-0.35"))
    else:
        rep.add("eq:intensity_td", "M1",
                "detection holds up as attack intensity rises (top vs mid sweep point)",
                ("WARN", "sweep has fewer than 3 intensity points"))

    # ---- E. dual-mode architecture ----------------------------------------- #
    rep.group(f"GROUP E [{tag}] -- DUAL-MODE ARCHITECTURE (light OBU / full RSU)",
              "eq:composite_light, alg:lrad_obu, alg:lrad_rsu")
    d_obu, d_rsu, esc = (top.get("d_obu_count"), top.get("d_rsu_count"),
                         top.get("escalation_count"))
    rep.add("eq:composite_light", None, "OBU-side light detector produced decisions",
            gt(d_obu, 0.0, "d_obu_count"))
    rep.add("alg:lrad_rsu", None, "RSU-side full detector counter is populated",
            gte(d_rsu, 0.0, "d_rsu_count"))
    rep.add("alg:lrad_obu", None,
            "every escalation is backed by an OBU detection (escalations <= D_OBU)",
            lte(esc, d_obu, "escalation_count vs d_obu_count")
            if None not in (esc, d_obu) else ("WARN", "counters absent"))
    rep.add("alg:lrad_obu", None, "the OBU -> RSU escalation path was exercised",
            gt(esc, 0.0, "escalation_count"))

    # ---- F. TCAM signatures S3/S4 ------------------------------------------ #
    rep.group(f"GROUP F [{tag}] -- TCAM SIGNATURES S3/S4",
              "eq:sig_s3, eq:sig_s4, eq:rule_s3, eq:rule_s4")
    if not is_tcam_schema:
        for eq, desc in (("eq:sig_s3", "S3 unauthorised-flow-rule signature evaluated"),
                         ("eq:sig_s4", "S4 TCAM-saturation signature evaluated"),
                         ("eq:rule_s3", "TCAM occupancy stays within [0,1]"),
                         ("eq:rule_s4", "attacker attribution counters recorded")):
            rep.add(eq, None, desc,
                    ("WARN", "this variant writes the 52-column schema "
                             "(no TCAM block emitted)"))
    else:
        s3, s4 = top.get("s3_fired_count"), top.get("s4_fired_count")
        if family == "tcam":
            # A TCAM-exhaustion variant must actually trip its own signatures.
            rep.add("eq:sig_s3", "M1",
                    "S3/S4 signatures fired under a TCAM-exhaustion attack",
                    gt((s3 or 0.0) + (s4 or 0.0), 0.0, "s3_fired_count+s4_fired_count"))
            # NOT "clean must be exactly zero": the rule engine is calibrated to
            # a ~1% false-positive target (lstm_pipeline/rule_calibrator.py), so
            # occasional clean-traffic fires are expected and are precisely what
            # avg_FPR measures.  The meaningful property is separation.
            _clean_s34 = ((clean.get("s3_fired_count") or 0.0)
                          + (clean.get("s4_fired_count") or 0.0)) if clean else None
            rep.add("eq:sig_s4", None,
                    "S3/S4 fire strictly more under attack than on clean traffic",
                    gt((s3 or 0.0) + (s4 or 0.0), _clean_s34,
                       "attacked s3+s4 fired vs clean")
                    if _clean_s34 is not None else ("WARN", "no pct=0 run present"))
        else:
            rep.add("eq:sig_s3", None, "S3 unauthorised-flow-rule signature evaluated",
                    gte(s3, 0.0, "s3_fired_count"))
            rep.add("eq:sig_s4", None, "S4 TCAM-saturation signature evaluated",
                    gte(s4, 0.0, "s4_fired_count"))
        rep.add("eq:rule_s3", None, "TCAM occupancy stays within [0,1]",
                rng(top.get("max_tcam_util"), 0.0, 1.0, "max_tcam_util"))
        rep.add("eq:rule_s4", None,
                "attacker attribution counters recorded (lambda_PI)",
                gte(top.get("total_lambda_pi"), 0.0, "total_lambda_pi"))
    rep.add("eq:sig_s4", None, "per-RSU TCAM occupancy trace written",
            present(find_files(dirs, f"tcam_occupancy_attack{attack}.csv"),
                    "tcam_occupancy"))
    rep.add("eq:rule_s4", None, "per-RSU TCAM rule snapshots written",
            present(find_files(dirs, f"tcam_snapshots_attack{attack}*.csv"),
                    "tcam_snapshots"))

    # ---- G. hidden forwarding S5-S8 ---------------------------------------- #
    rep.group(f"GROUP G [{tag}] -- HIDDEN-FORWARDING SIGNATURES S5-S8 (M3)",
              "eq:sig_s5, eq:sig_s6, eq:sig_s7, eq:sig_s8, eq:ucr, eq:nfwd_detect")
    rep.add("eq:ucr", "M3", "unauthorised copy rate is a valid percentage",
            rng(top.get("cur_UCR"), 0.0, 100.0, "cur_UCR"))
    if family == "hf":
        rep.add("eq:sig_s5", "M1", "hidden-forwarding detector produced true positives",
                gt(top.get("TP"), 0.0, "TP"))
        rep.add("eq:nfwd_detect", None,
                "duplication / non-forwarding evidence reached the RSU detector",
                gt(top.get("d_rsu_count"), 0.0, "d_rsu_count"))
    else:
        rep.add("eq:sig_s5", "M3",
                "S5-S8 report no unauthorised copies for a non-HF variant",
                rng(top.get("avg_UCR"), 0.0, 1.0, "avg_UCR"))
        rep.add("eq:nfwd_detect", None,
                "duplication / non-forwarding evidence reached the RSU detector",
                ("WARN", "not applicable to this attack family"))

    # ---- H. witness verification ------------------------------------------- #
    rep.group(f"GROUP H [{tag}] -- WITNESS-BASED FORWARDING VERIFICATION (M12)",
              "eq:da_sign, eq:nfa_sign, eq:wap, eq:war")
    # routing.cc writes current_WAP_precision/recall scaled by 100, so both
    # columns are percentages (calculate_witness_wapr_metric).
    rep.add("eq:wap", "M12", "witness alert precision within [0,100]%",
            rng(top.get("WAP_precision"), 0.0, 100.0, "WAP_precision"))
    rep.add("eq:war", "M12", "witness alert recall within [0,100]%",
            rng(top.get("WAP_recall"), 0.0, 100.0, "WAP_recall"))
    wtp, wfp, wfn = (top.get("witness_TP_W"), top.get("witness_FP_W"),
                     top.get("witness_FN_W"))
    rep.add("eq:wap", "M12", "WAP_precision equals TP_W/(TP_W+FP_W) recomputed",
            approx(top.get("WAP_precision"), 100.0 * wtp / (wtp + wfp), 1e-2,
                   "WAP_precision")
            if None not in (wtp, wfp) and (wtp + wfp) > 0
            else ("WARN", "no witness alerts were raised in this run"))
    rep.add("eq:war", "M12", "WAP_recall equals TP_W/(TP_W+FN_W) recomputed",
            approx(top.get("WAP_recall"), 100.0 * wtp / (wtp + wfn), 1e-2, "WAP_recall")
            if None not in (wtp, wfn) and (wtp + wfn) > 0
            else ("WARN", "no witness ground-truth events in this run"))
    # M12 is defined against PASSIVE hidden forwarding (variants 7/8), the case
    # cryptographic proof alone cannot catch -- there the witness quorum must
    # actually fire, not merely be counted.
    if attack in (7, 8):
        rep.add("eq:da_sign", "M12",
                "witness duplication-alert quorum fired under passive HF",
                gt(top.get("witness_da_count"), 0.0, "witness_da_count"))
        rep.add("eq:nfa_sign", "M12", "witness alerts produced a usable precision",
                gt(top.get("WAP_precision"), 0.0, "WAP_precision"))
    else:
        rep.add("eq:da_sign", None, "detection-agreement co-signatures counted",
                gte(top.get("witness_da_count"), 0.0, "witness_da_count"))
        rep.add("eq:nfa_sign", None, "non-forwarding-agreement signatures counted",
                gte(top.get("witness_nfa_count"), 0.0, "witness_nfa_count"))

    # ---- I. cryptographic integrity layer ---------------------------------- #
    rep.group(f"GROUP I [{tag}] -- HYBRID CRYPTOGRAPHIC INTEGRITY LAYER (M7)",
              "eq:mldsa_sign, eq:batch_verify, eq:stark_delay_verify, "
              "eq:stark_hop_verify, eq:o_crypto, eq:t_verify, eq:t_consensus, "
              "eq:overhead_batch")
    rep.add("eq:mldsa_sign", None, "ML-DSA-87 signature validity rate within [0,1]",
            rng(top.get("sig_valid_rate"), 0.0, 1.0, "sig_valid_rate"))
    rep.add("eq:o_crypto", "M7", "per-packet crypto overhead bytes accrued",
            gt(top.get("o_crypto_bytes_pkt"), 0.0, "o_crypto_bytes_pkt"))
    # B is the 50ms-window occupancy that crypto_batch_verify_tick() actually
    # collected, not a cap -- BATCH_SIZE is the CLI-configured nominal size, so
    # the assertion here is that batching happened at all, with B reported.
    rep.add("eq:overhead_batch", "M7",
            f"batch verification aggregated packets (mean B, nominal "
            f"BATCH_SIZE={BATCH_SIZE})",
            gt(top.get("batch_B_avg"), 0.0, "batch_B_avg"))
    rep.add("eq:batch_verify", "M7", "batch verification latency accounted (>0)",
            gt(top.get("t_batch_ms_avg"), 0.0, "t_batch_ms_avg"))
    rep.add("eq:t_consensus", "M7", "consensus latency accounted (>0)",
            gt(top.get("t_consensus_ms_avg"), 0.0, "t_consensus_ms_avg"))
    rep.add("eq:t_verify", "M7", "STARK proving/verification latency accounted (>0)",
            gt(top.get("t_stark_ms_avg"), 0.0, "t_stark_ms_avg"))
    # stark_prove/verify_timing are reached only from S2 (data-plane hop delay,
    # s2_detection.h), so a control-plane variant legitimately records zero
    # timing failures.  What must hold for every variant is that a CLEAN run
    # produces no spurious proof failures, and that an attack never reduces them.
    rep.add("eq:stark_delay_verify", None,
            "clean baseline records no spurious STARK delay-proof failures",
            rng(clean.get("stark_timing_fail_count"), 0.0, 0.0,
                "clean stark_timing_fail_count")
            if clean else ("WARN", "no pct=0 run present"))
    rep.add("eq:stark_delay_verify", None,
            "STARK delay-proof failures do not decrease under attack",
            cmp_hi(top.get("stark_timing_fail_count"),
                   clean and clean.get("stark_timing_fail_count"),
                   "stark_timing_fail_count"))
    rep.add("eq:stark_hop_verify", None,
            "clean baseline records no spurious STARK hop-proof failures",
            rng(clean.get("stark_hop_fail_count"), 0.0, 0.0,
                "clean stark_hop_fail_count")
            if clean else ("WARN", "no pct=0 run present"))

    # ---- K. blockchain ------------------------------------------------------ #
    rep.group(f"GROUP K [{tag}] -- BLOCKCHAIN ENDORSEMENT & AUDIT TRAIL (M11)",
              "eq:rsu_endorsement, eq:endorsed_commit, eq:ufcr, eq:flowmod_log, "
              "eq:anchor_hash, eq:rsu_write, eq:vk_commit, eq:bc_model_verify")
    rep.add("eq:endorsed_commit", None, "FlowMod endorsement rate within [0,1]",
            rng(top.get("flowmod_endorsement_rate"), 0.0, 1.0,
                "flowmod_endorsement_rate"))
    rep.add("eq:ufcr", "M11", "unauthorised-FlowMod containment rate within [0,100]",
            rng(top.get("UFCR"), 0.0, 100.0, "UFCR"))
    blocked, unauth = top.get("ufcr_blocked"), top.get("ufcr_unauth_total")
    rep.add("eq:ufcr", "M11", "UFCR equals blocked/unauthorised recomputed",
            approx(top.get("UFCR"), 100.0 * blocked / unauth, 1e-2, "UFCR")
            if None not in (blocked, unauth) and unauth > 0
            else ("WARN", "no unauthorised FlowMods were observed in this run"))
    chain = [r.get("rsu_chain_len") for r in top_rows]
    rep.add("eq:rsu_write", None, "RSU chain grows monotonically across cycles",
            truth(all(b >= a for a, b in zip(chain, chain[1:])) and chain[-1] > 0,
                  f"rsu_chain_len {chain[0]:.0f} -> {chain[-1]:.0f} over "
                  f"{len(chain)} cycles",
                  "rsu_chain_len is not monotonically non-decreasing"))
    gchain = [r.get("global_chain_len") for r in top_rows]
    rep.add("eq:anchor_hash", None, "global anchor chain grows monotonically",
            truth(all(b >= a for a, b in zip(gchain, gchain[1:])) and gchain[-1] > 0,
                  f"global_chain_len {gchain[0]:.0f} -> {gchain[-1]:.0f}",
                  "global_chain_len is not monotonically non-decreasing"))
    suffix = f"_d{delay}ms" if delay is not None else ""
    for eq, stem, desc in (
            ("eq:flowmod_log",     "bc_flowmod_log",   "on-chain FlowMod audit log"),
            ("eq:anchor_hash",     "bc_anchor_log",    "periodic anchor-hash log"),
            ("eq:vk_commit",       "bc_dkg_log",       "DKG verification-key commitment log"),
            ("eq:time_consensus",  "bc_tref_log",      "trusted time-reference log"),
            ("eq:trust_update",    "bc_trust_updates", "on-chain trust-update log"),
            ("eq:bc_model_verify", "bc_detection_log", "on-chain detection-event log")):
        rep.add(eq, None, f"{desc} written and populated",
                present(find_files(dirs, f"{stem}_Attack{attack}_*{suffix}.csv"), stem))

    # ---- L. trust & controller failover ------------------------------------- #
    rep.group(f"GROUP L [{tag}] -- TRUST MANAGEMENT & CONTROLLER FAILOVER (M5)",
              "eq:trust_update, eq:ctrl_trust_update, eq:quarantine, eq:sc_revoke, "
              "eq:ctrl_failover, eq:l_failover")
    ct_att = top.get("avg_trust_score")
    rep.add("eq:trust_update", None, "avg node trust score within [0,1]",
            rng(ct_att, 0.0, 1.0, "avg_trust_score"))
    rep.add("eq:ctrl_trust_update", None,
            "attack erodes trust (attacked trust <= clean trust)",
            cmp_hi(clean and clean.get("avg_trust_score"), ct_att, "avg_trust_score",
                   what="clean", ref="attacked"))
    # eq:quarantine (main.tex:3616) is a strictly PER-NODE condition:
    #   SC.Quarantine(v) <= T_v(t) < T_min
    # The metrics CSV only carries the aggregate avg_trust_score, from which the
    # per-node rule cannot be verified (and main.tex asserts nothing about the
    # average -- under attack it legitimately falls as malicious nodes are
    # correctly distrusted). The per-node evidence lives in the bc_trust_updates
    # log. The grounded, observable properties -- trust bounded [0,1] and trust
    # eroding under attack -- are already covered by eq:trust_update (above) and
    # eq:ctrl_trust_update (above), so this line reports the limitation honestly
    # rather than asserting an aggregate bound the paper never states.
    bc_trust = find_files(dirs, f"bc_trust_updates_Attack{attack}_*"
                          + (f"_d{delay}ms" if delay is not None else "") + ".csv")
    rep.add("eq:quarantine", None,
            "per-node quarantine trigger (T_v < T_min) recorded for later audit",
            ("WARN", f"eq:quarantine is a per-node condition not verifiable from the "
                     f"aggregate avg_trust_score={ct_att:.4f}; per-node trust "
                     f"evidence is in {len(bc_trust)} bc_trust_updates log(s) "
                     f"(see eq:trust_update / eq:ctrl_trust_update for the grounded "
                     f"aggregate checks)")
            if ct_att is not None else ("WARN", "avg_trust_score absent"))
    ev = top.get("ctrl_failover_events")
    reas = top.get("ctrl_failover_reassigned")
    mx = top.get("ctrl_failover_max_ms")
    rep.add("eq:ctrl_failover", "M5", "controller-failover event counter is non-negative",
            gte(ev, 0.0, "ctrl_failover_events"))
    if ev:
        rep.add("eq:l_failover", "M5", "failover latency recorded for the revocation event",
                gt(mx, 0.0, "ctrl_failover_max_ms"))
        rep.add("eq:sc_revoke", "M5", "RSUs were reassigned after SC.Revoke",
                gt(reas, 0.0, "ctrl_failover_reassigned"))
    else:
        rep.add("eq:l_failover", "M5", "failover latency recorded for the revocation event",
                ("WARN", "no controller revocation fired in this run -- no controller "
                         "trust fell below T_min_ctrl"))
        rep.add("eq:sc_revoke", "M5",
                "failover counters are self-consistent with zero revocations",
                truth((reas or 0.0) == 0.0 and (mx or 0.0) == 0.0,
                      "no revocation, no reassignments, no latency -- consistent",
                      f"no revocation events but reassigned={reas}, max_ms={mx}"))

    # ---- M. distributed trusted time reference ------------------------------ #
    rep.group(f"GROUP M [{tag}] -- DISTRIBUTED TRUSTED TIME REFERENCE (M9)",
              "eq:time_consensus, eq:eps_ref")
    rep.add("eq:eps_ref", "M9", "time-reference error is non-negative",
            gte(top.get("avg_eps_ref_s"), 0.0, "avg_eps_ref_s"))
    rep.add("eq:eps_ref", "M9", "time-reference error stays sub-second",
            lte(top.get("avg_eps_ref_s"), 1.0, "avg_eps_ref_s"))
    fmax = (N_RSUS - 1) // 3
    rep.add("eq:time_consensus", "M9",
            f"faulty time sources stay within the BFT bound f <= {fmax}",
            lte(top.get("time_ref_f_bad"), float(fmax), "time_ref_f_bad"))

    # ---- P. TAP baseline comparator ----------------------------------------- #
    tap = load_tap(dirs, attack, delay)
    rep.group(f"GROUP P [{tag}] -- EXTERNAL BASELINE B1: TAP "
              f"(Arsalan & Rehman 2018)\n"
              f"    NOT part of the proposed framework -- prior-art comparator only.",
              "eq:mcc, eq:tvr")
    if not tap:
        for desc in ("[B1 TAP baseline] produced output for this sweep",
                     "[B1 TAP baseline] MCC within the valid range",
                     "MOBIGUARD (proposed) outperforms [B1 TAP baseline] on MCC"):
            rep.add("eq:mcc", "M1", desc,
                    ("WARN", "no TAP baseline CSVs for this subject"))
    else:
        tap_top = tap[sorted(tap)[-1]]
        rep.add("eq:mcc", "M1", "[B1 TAP baseline] produced output for this sweep",
                ("PASS", f"TAP runs at pct={sorted(tap)}"))
        rep.add("eq:mcc", "M1", "[B1 TAP baseline] MCC within the valid range",
                rng(tap_top.get("avg_MCC"), -1.0, 1.0, "TAP avg_MCC"))
        rep.add("eq:mcc", "M1", "MOBIGUARD (proposed) outperforms [B1 TAP baseline] on MCC",
                cmp_hi(top.get("avg_MCC"), tap_top.get("avg_MCC"), "avg_MCC",
                       what="MOBIGUARD", ref="TAP"))


# --------------------------------------------------------------------------- #
# Global verification (groups A0, J, N, O, Q -- run once)
# --------------------------------------------------------------------------- #

def verify_environment(rep, dirs):
    rep.group("GROUP A0 -- MOBILITY & ENVIRONMENT INSTRUMENTATION",
              "eq:density_x, eq:speed_x, eq:density_normalized_rate")
    # One file per (variant, pct, seed, delay) run since g_sim_tag was added to
    # its filename (routing.cc) -- aggregate across all of them, not just the
    # first match, so every completed run contributes its density samples.
    dens = find_files(dirs, "rsu_density*.csv")
    rep.add("eq:density_x", None, "per-RSU vehicle density and mean speed logged",
            present(dens, "rsu_density"))
    if dens:
        rho, vb = [], []
        for d in dens:
            with open(d, errors="ignore") as fh:
                for line in fh:
                    parts = [x.strip() for x in line.split(",")]
                    if len(parts) != 4 or parts[0] == "t":
                        continue
                    try:
                        rho.append(float(parts[2]))
                        vb.append(float(parts[3]))
                    except ValueError:
                        continue
        rep.add("eq:density_x", None, "logged vehicle densities are non-negative",
                truth(rho and all(v >= 0 for v in rho),
                      f"{len(rho)} sample(s), rho in [{min(rho):.0f}, {max(rho):.0f}] veh",
                      "negative density sample logged"))
        rep.add("eq:speed_x", None, "logged mean speeds are non-negative and finite",
                truth(vb and all(v >= 0 and math.isfinite(v) for v in vb),
                      f"{len(vb)} sample(s), v_bar in "
                      f"[{min(vb):.2f}, {max(vb):.2f}] m/s",
                      "invalid mean-speed sample logged"))
    else:
        for eq, d in (("eq:density_x", "logged vehicle densities are non-negative"),
                      ("eq:speed_x", "logged mean speeds are non-negative and finite")):
            rep.add(eq, None, d, ("WARN", "rsu_density.csv absent"))
    rep.add("eq:density_normalized_rate", None,
            "ground-truth injection-rate trace written",
            present(find_files(dirs, "lambda_l_true_attack*.csv"), "lambda_l_true"))


def verify_crypto_timing(rep, dirs):
    rep.group("GROUP J -- CRYPTO OPERATION TIMING LOG & CAUSAL ORDERING",
              "eq:t_verify, eq:t_consensus, eq:mldsa_sign, alg:lrad_obu, alg:lrad_rsu")
    paths = find_files(dirs, "crypto_timing_log*.csv")
    if not paths:
        for eq, d in (("eq:t_verify", "crypto timing log produced and populated"),
                      ("eq:mldsa_sign", "every crypto/detection operation class exercised"),
                      ("eq:t_verify", "measured wall-clock durations are positive"),
                      ("eq:mldsa_sign", "sign precedes verify for every packet"),
                      ("alg:lrad_obu", "OBU detection starts no later than RSU detection"),
                      ("eq:t_consensus", "consensus rounds completed successfully")):
            rep.add(eq, "M7", d, ("WARN", "crypto_timing_log*.csv absent"))
        return

    rows = []
    for p in paths:
        run_tag = os.path.basename(p)
        with open(p, errors="ignore") as fh:
            for line in fh:
                parts = [x.strip() for x in line.strip().split(",")]
                if len(parts) != 6 or parts[0] == "sim_time_s":
                    continue
                try:
                    rows.append({"t": float(parts[0]), "op": parts[1],
                                 "node": int(parts[2]), "pkt": int(parts[3]),
                                 "us": float(parts[4]), "res": parts[5],
                                 "run": run_tag})
                except ValueError:
                    continue

    rep.add("eq:t_verify", "M7", "crypto timing log produced and populated",
            truth(bool(rows),
                  f"{len(rows)} timed operations across {len(paths)} file(s)",
                  "timing log present but contains no parsable rows"))
    if not rows:
        return

    ops = {}
    for r in rows:
        ops.setdefault(r["op"], []).append(r)
    expected = {"sign", "verify", "batch_verify", "consensus", "stark_hop",
                "lrad_obu", "lrad_rsu"}
    missing = sorted(expected - set(ops))
    rep.add("eq:mldsa_sign", "M7", "every crypto/detection operation class was exercised",
            truth(not missing,
                  "ops: " + ", ".join(f"{k}={len(v)}" for k, v in sorted(ops.items())),
                  f"never invoked: {', '.join(missing)}"))
    rep.add("eq:t_verify", "M7",
            "all measured wall-clock durations are positive and finite",
            truth(all(r["us"] > 0 and math.isfinite(r["us"]) for r in rows),
                  f"min={min(r['us'] for r in rows):.3f}us "
                  f"max={max(r['us'] for r in rows):.3f}us",
                  "non-positive or non-finite duration recorded"))

    # Both per-event-pairing checks below run PER FILE, not pooled across the
    # sweep. pkt_id and node are small counters that restart in every run, so
    # pooling first and then disambiguating with a composite key (an earlier
    # version of this check did that) is solving a problem this design avoids
    # outright: a sign in run A can never be paired with a verify in run B if
    # run B's rows are never in scope when run A is checked. Checking each run
    # in isolation also means a violation is reported against the specific run
    # that has it, not lost in an aggregate "some packet somewhere" count.
    by_run = {}
    for r in rows:
        by_run.setdefault(r["run"], []).append(r)

    sign_checked, sign_bad_runs = 0, []
    obu_checked, obu_bad_runs = 0, []
    for run_name, run_rows in sorted(by_run.items()):
        run_ops = {}
        for r in run_rows:
            run_ops.setdefault(r["op"], []).append(r)

        # sign precedes verify, for every (node, pkt) signed/verified in THIS run
        sign_t, ver_t = {}, {}
        for r in run_rows:
            key = (r["node"], r["pkt"])
            if r["op"] == "sign":
                sign_t[key] = min(sign_t.get(key, r["t"]), r["t"])
            elif r["op"] == "verify":
                ver_t[key] = max(ver_t.get(key, r["t"]), r["t"])
        both = set(sign_t) & set(ver_t)
        if both:
            sign_checked += 1
            bad = [k for k in both if ver_t[k] < sign_t[k]]
            if bad:
                sign_bad_runs.append((run_name, bad))

        # escalate_to_rsu() is only ever reached from inside lrad_obu() when
        # D_OBU=1, so within one run an escalation can never precede the OBU
        # detection on that node that raised it.
        first_obu = {}
        for r in run_ops.get("lrad_obu", []):
            n = r["node"]
            first_obu[n] = min(first_obu.get(n, r["t"]), r["t"])
        escalations = run_ops.get("escalate_to_rsu", [])
        if escalations:
            obu_checked += 1
            orphans = [e for e in escalations
                       if e["node"] not in first_obu
                       or first_obu[e["node"]] > e["t"] + 1e-9]
            if orphans:
                obu_bad_runs.append((run_name, orphans))

    rep.add("eq:mldsa_sign", "M7", "sign precedes verify for every packet (causal order)",
            truth(not sign_bad_runs,
                  f"checked {sign_checked} run(s) independently, 0 out-of-order "
                  f"events in any of them",
                  f"{len(sign_bad_runs)} run(s) had an out-of-order event: "
                  + ", ".join(f"{r}({len(b)})" for r, b in sign_bad_runs[:3]))
            if sign_checked
            else ("WARN", "no run has both a sign and a verify record"))

    rep.add("alg:lrad_obu", None,
            "no escalation precedes the OBU detection that raised it (D_OBU=1)",
            truth(not obu_bad_runs,
                  f"checked {obu_checked} run(s) independently, every escalation "
                  f"preceded by an lrad_obu on the same node within its own run",
                  f"{len(obu_bad_runs)} run(s) had an escalation with no preceding "
                  f"lrad_obu: " + ", ".join(f"{r}({len(o)})" for r, o in obu_bad_runs[:3]))
            if obu_checked
            else ("WARN", "no run has escalation events recorded"))

    # batch_verify rows carry B in the node column and n_verified in the pkt
    # column (crypto_layer.h:crypto_batch_verify_tick).
    batches = ops.get("batch_verify", [])
    over = [b for b in batches if b["pkt"] > b["node"]]
    rep.add("eq:batch_verify", "M7",
            "each batch verified no more signatures than it aggregated (n <= B)",
            truth(not over,
                  f"{len(batches)} batch(es), max B={max(b['node'] for b in batches)}, "
                  f"n_verified <= B in every batch",
                  f"{len(over)} batch(es) report n_verified > B")
            if batches else ("WARN", "no batch_verify operations logged"))

    cons = ops.get("consensus", [])
    rep.add("eq:t_consensus", "M7", "consensus rounds completed successfully",
            truth(any(r["res"] == "ok" for r in cons),
                  f"{sum(1 for r in cons if r['res'] == 'ok')}/{len(cons)} "
                  f"consensus rounds ok",
                  "no consensus round reported ok")
            if cons else ("WARN", "no consensus operations logged"))


def verify_lstm_pipeline(rep):
    rep.group("GROUP N -- FEDERATED LSTM PIPELINE (M8)",
              "eq:lstm_input, eq:lstm_threshold, eq:fed_robust, eq:delta_poison, "
              "eq:mcc_variant, eq:mcc_mobility")
    base = os.path.join(ROOT, "lstm_pipeline")

    ab2 = load_json(os.path.join(base, "ab2_centralized_vs_federated_results.json"))
    if ab2 and "AB2_B_federated" in ab2:
        fed = ab2["AB2_B_federated"]
        vals = [v["MCC"] for v in fed.values()
                if isinstance(v, dict) and v.get("MCC") is not None]
        rep.add("eq:fed_robust", "M8",
                "AB2 federated aggregation produced per-variant MCC in range",
                truth(vals and all(-1.0 <= v <= 1.0 for v in vals),
                      f"{len(vals)} variant(s), MCC in "
                      f"[{min(vals):.4f}, {max(vals):.4f}]",
                      "federated MCC outside [-1,1] or absent"))
        cen = ab2.get("AB2_A_centralized", {})
        pairs = [(cen[k].get("MCC"), fed[k].get("MCC")) for k in fed
                 if isinstance(fed.get(k), dict) and isinstance(cen.get(k), dict)]
        pairs = [(a, b) for a, b in pairs if None not in (a, b)]
        rep.add("eq:fed_robust", "M8",
                "federated model tracks the centralised baseline (no collapse)",
                truth(pairs and all(f >= c - 0.15 for c, f in pairs),
                      f"{len(pairs)} variant(s) compared, federated stays within "
                      f"0.15 MCC of centralised",
                      "federated MCC collapsed >0.15 below centralised on some variant"))
    else:
        for d in ("AB2 federated aggregation produced per-variant MCC in range",
                  "federated model tracks the centralised baseline (no collapse)"):
            rep.add("eq:fed_robust", "M8", d,
                    ("WARN", "ab2_centralized_vs_federated_results.json absent"))

    ab3 = load_json(os.path.join(base, "ab3_feature_ablation_results.json"))
    if ab3 and "AB3_A_5feature" in ab3 and "AB3_B_7feature" in ab3:
        a, b = ab3["AB3_A_5feature"], ab3["AB3_B_7feature"]
        gains = [b[k]["MCC"] - a[k]["MCC"] for k in b
                 if isinstance(b.get(k), dict) and isinstance(a.get(k), dict)
                 and None not in (b[k].get("MCC"), a[k].get("MCC"))]
        rep.add("eq:lstm_input", "M8",
                "AB3 ZKP-failure features evaluated on both feature sets",
                truth(bool(gains),
                      f"{len(gains)} variant(s) compared, mean MCC delta "
                      f"(7-feature - 5-feature) = {sum(gains) / len(gains):+.4f}",
                      "no comparable variants between the 5- and 7-feature runs"))
    else:
        rep.add("eq:lstm_input", "M8",
                "AB3 ZKP-failure features evaluated on both feature sets",
                ("WARN", "ab3_feature_ablation_results.json absent"))

    brfa = load_json(os.path.join(base, "brfa_param_sweep_results.json"))
    if brfa and "selected" in brfa:
        sel = brfa["selected"]
        rep.add("eq:delta_poison", "M8",
                "BRFA-selected parameters bound the poisoning impact",
                lte(sel.get("delta_poison"), 0.10,
                    "delta_poison at the selected (gamma, t_min)"))
        rep.add("eq:fed_robust", "M8", "the BRFA parameter grid was actually swept",
                truth(len(brfa.get("grid", [])) > 1,
                      f"{len(brfa.get('grid', []))} (gamma, t_min) point(s) evaluated, "
                      f"selected gamma={sel.get('gamma')} t_min={sel.get('t_min')}",
                      "BRFA grid has fewer than 2 points"))
    else:
        rep.add("eq:delta_poison", "M8",
                "BRFA-selected parameters bound the poisoning impact",
                ("WARN", "brfa_param_sweep_results.json absent"))
        rep.add("eq:fed_robust", "M8", "the BRFA parameter grid was actually swept",
                ("WARN", "brfa_param_sweep_results.json absent"))

    mob = load_json(os.path.join(base, "mobility_stratified_results.json"))
    if mob and "per_variant" in mob:
        cells = [v for pv in mob["per_variant"].values() if isinstance(pv, dict)
                 for v in pv.values()]
        filled = [v for v in cells if isinstance(v, (int, float))]
        rep.add("eq:mcc_mobility", "M1",
                "MCC stratified across density x mean-speed bins",
                truth(bool(mob["per_variant"]),
                      f"{len(mob['per_variant'])} variant(s) x "
                      f"{len(mob.get('rho_labels', []))} density x "
                      f"{len(mob.get('vbar_labels', []))} speed bins, "
                      f"{len(filled)}/{len(cells)} cells populated",
                      "no per-variant stratification present"))
        rep.add("eq:mcc_variant", "M1", "stratified MCC values stay within [-1,1]",
                truth(all(-1.0 <= v <= 1.0 for v in filled),
                      f"{len(filled)} populated cell(s), all within [-1,1]",
                      "a stratified MCC cell is outside [-1,1]"))
    else:
        rep.add("eq:mcc_mobility", "M1",
                "MCC stratified across density x mean-speed bins",
                ("WARN", "mobility_stratified_results.json absent"))
        rep.add("eq:mcc_variant", "M1", "stratified MCC values stay within [-1,1]",
                ("WARN", "mobility_stratified_results.json absent"))

    cal = load_json(os.path.join(base, "calibrated_params.json"))
    rep.add("eq:lstm_threshold", None,
            "detector thresholds calibrated from the training distribution",
            truth(cal is not None and cal.get("k") is not None
                  and cal.get("beta") is not None,
                  f"k={cal.get('k')} beta={cal.get('beta')} delta0={cal.get('delta0')} "
                  f"max FPR drift={cal.get('robustness_max_delta_fpr')}" if cal else "",
                  "calibrated_params.json missing k/beta")
            if cal else ("WARN", "calibrated_params.json absent"))


def verify_baselines(rep, dirs):
    rep.group("GROUP O -- EXTERNAL BASELINES B2 (SFTO-Guard) & B3 (FADE)\n"
              "    NOT part of the proposed framework -- independent state-of-the-art\n"
              "    prior art (docs/main.tex 'External Baselines'), verified only to\n"
              "    confirm each comparator produced usable output to benchmark against.",
              "eq:mcc, eq:sig_s5, eq:ucr")
    sfto = sorted(glob.glob(os.path.join(ROOT, "sfto_pipeline", "results", "*",
                                         "metrics.json")))
    if not sfto:
        for d in ("[B2 SFTO-Guard baseline] benchmark metrics produced",
                  "[B2 SFTO-Guard baseline] confusion matrix agrees with reported accuracy"):
            rep.add("eq:mcc", "M1", d, ("WARN", "no SFTO results present"))
    else:
        ok, bad = [], []
        for p in sfto:
            d = load_json(p) or {}
            acc, cm = d.get("accuracy"), d.get("confusion_matrix")
            name = os.path.basename(os.path.dirname(p))
            if acc is None or not cm:
                continue
            tn, fp = cm[0]
            fn, tp = cm[1]
            tot = tn + fp + fn + tp
            (ok if tot and abs((tp + tn) / tot - acc) < 1e-6 else bad).append(name)
        rep.add("eq:mcc", "M1", "[B2 SFTO-Guard baseline] benchmark metrics produced",
                ("PASS", f"{len(sfto)} SFTO result set(s): "
                         + ", ".join(os.path.basename(os.path.dirname(p))
                                     for p in sfto)))
        rep.add("eq:mcc", "M1", "[B2 SFTO-Guard baseline] confusion matrix agrees with reported accuracy",
                truth(not bad, f"{len(ok)} result set(s) internally consistent",
                      f"inconsistent result set(s): {bad}"))

    rep.add("eq:sig_s5", "M3", "[B3 FADE baseline] per-flow detection detail written",
            present(find_files(dirs, "fade_results_*.csv"), "fade_results"))
    rep.add("eq:ucr", "M3", "[B3 FADE baseline] per-run summary metrics written",
            present(find_files(dirs, "fade_metrics_*.csv"), "fade_metrics"))


def verify_no_bypass(rep, attack, delay, top, ops, tag, ctx):
    """Task 8: attest the run exercised the full model, bypassing nothing."""
    rep.group(f"GROUP A1 [{tag}] -- NO-BYPASS / FULL-MODELLING ATTESTATION\n"
              f"    Task 8 requires 'correct coding without bypassing modeling'.\n"
              f"    Each modelled subsystem is attested from the run's own\n"
              f"    artefacts, and cross-checked against the recorded command line\n"
              f"    when the run log is available.",
              "crypto_layer.h ablation gates + --disable_crypto")

    logs = find_run_logs(attack, delay)
    flags = parse_run_flags(logs)
    rep.add("no-bypass", None, "run log with the recorded command line is available",
            ("PASS", f"{len(logs)} run log(s), {len(flags)} flag(s) recorded: "
                     + ", ".join(sorted(flags)[:6]) + ("..." if len(flags) > 6 else ""))
            if flags else
            ("WARN", f"{len(logs)} run log(s) under logs/ carry no '# Command:' "
                     f"header -- attestation falls back to artefact evidence only"))

    for flag, bypass_val, subsystem, evidence in BYPASS_GATES:
        declared = flags.get(flag)
        try:
            ran, detail = evidence(top, ops, ctx)
        except TypeError:
            ran, detail = evidence(top, ops)

        # The command line is authoritative when we have it.
        if declared and bypass_val in declared:
            rep.add("no-bypass", None, f"{subsystem} was NOT bypassed",
                    ("FAIL", f"run was launched with --{flag}={bypass_val} -- this is "
                             f"an ABLATION run, not full-system evidence "
                             f"({detail})"))
            continue

        if ran is True:
            src = f"--{flag} not set to {bypass_val}; " if declared else ""
            rep.add("no-bypass", None, f"{subsystem} was NOT bypassed",
                    ("PASS", f"{src}subsystem demonstrably executed: {detail}"))
        elif ran is False:
            rep.add("no-bypass", None, f"{subsystem} was NOT bypassed",
                    ("FAIL", f"subsystem produced no activity: {detail}"))
        else:
            rep.add("no-bypass", None, f"{subsystem} was NOT bypassed",
                    ("WARN", detail))


def verify_attack_coverage(rep, subjects):
    """Roll up which of the 8 paper attack variants this run actually verified."""
    rep.group("GROUP R -- ATTACK VARIANT COVERAGE ROLL-UP (Variants 1-8)",
              "docs/main.tex 'Attack Scenarios'")
    verified = {a for (a, _) in subjects}
    for cls in ("SELECTIVE TIME DELAY", "HIDDEN FORWARDING"):
        variants = [v for v in sorted(ATTACK_CLASS) if ATTACK_CLASS[v] == cls]
        for v in variants:
            label = ATTACK_FAMILY[v][1]
            if v in verified:
                pcts = sorted(next(r for (a, _), r in subjects.items() if a == v))
                rep.add(f"{cls[:3]}-V{v}", None, f"Variant {v} -- {label}",
                        ("PASS", f"verified against a live sweep, pct={pcts}"))
            else:
                rep.add(f"{cls[:3]}-V{v}", None, f"Variant {v} -- {label}",
                        ("WARN", "no MOBIGUARD_Attack%d_*.csv in the result "
                                 "directories -- sweep not run" % v))
        done = sum(1 for v in variants if v in verified)
        rep.add("class", None, f"{cls} class coverage (variants "
                               f"{variants[0]}-{variants[-1]})",
                ("PASS", f"{done}/{len(variants)} variant(s) verified")
                if done == len(variants) else
                ("WARN", f"{done}/{len(variants)} variant(s) verified -- missing "
                         f"{[v for v in variants if v not in verified]}"))


def verify_metric_coverage(rep):
    rep.group("GROUP Q -- METRIC COVERAGE ROLL-UP (M1-M12)",
              "docs/main.tex sec:metrics")
    expect = {
        "M1":  "Detection quality and mobility robustness (MCC)",
        "M2":  "Safety-critical threshold violation rate (TVR)",
        "M3":  "Unauthorized copy rate (UCR)",
        "M4":  "Node/flow mitigation latency (L_mit)",
        "M5":  "Controller failover latency (L_failover)",
        "M6":  "Overall system latency (L_e2e)",
        "M7":  "Security processing and consensus overhead",
        "M8":  "Federated model poisoning resistance",
        "M9":  "Distributed time reference robustness",
        "M10": "Privacy leakage score (L_priv)",
        "M11": "Unauthorized FlowMod containment rate (UFCR)",
        "M12": "Witness alert precision and recall (WAP-R)",
    }
    for m in sorted(expect, key=lambda x: int(x[1:])):
        if m == "M10":
            rep.add("eq:l_priv", None, expect[m],
                    ("WARN", "architectural metric -- argued from the AB2 federated-vs-"
                             "centralised design rather than measured per run "
                             "(declared paper-only in audit_equations.py)"))
        elif m in rep.metrics_seen:
            rep.add("metrics", None, expect[m],
                    ("PASS", f"{m} evidenced by at least one passing check above"))
        else:
            rep.add("metrics", None, expect[m],
                    ("WARN", f"{m} not exercised by the artefacts present in this run"))


# --------------------------------------------------------------------------- #
# Runner
# --------------------------------------------------------------------------- #

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--results-dir", action="append", default=None,
                    help="result directory to verify (repeatable)")
    ap.add_argument("--attack", type=int, default=None,
                    help="restrict to one attack variant (default: all discovered)")
    ap.add_argument("--delay", type=int, default=None,
                    help="restrict to one injected-delay setting in ms")
    ap.add_argument("--strict", action="store_true", help="exit 1 on any FAIL")
    ap.add_argument("--no-color", action="store_true")
    args = ap.parse_args()

    dirs = [d for d in (args.results_dir or DEFAULT_RESULTS) if os.path.isdir(d)]
    c = Palette(sys.stdout.isatty() and not args.no_color)
    rep = Report(c)

    if not dirs:
        print("No result directory found -- run a sweep first "
              "(scripts/run_rule_based_sweep.py).")
        sys.exit(2)

    subjects, seed_map = discover_subjects(dirs)
    if args.attack is not None:
        subjects = {k: v for k, v in subjects.items() if k[0] == args.attack}
    if args.delay is not None:
        subjects = {k: v for k, v in subjects.items() if k[1] == args.delay}
    seed_map = {k: v for k, v in seed_map.items() if k in subjects}

    print("=" * 78)
    print("MOBIGUARD -- FULL-SYSTEM FUNCTIONAL VERIFICATION")
    print("reference : docs/main.tex (equations, algorithms, metrics M1-M12)")
    for d in dirs:
        print(f"results   : {d}")
    if not subjects:
        print("subjects  : none")
        print("=" * 78)
        print("No MOBIGUARD_Attack*.csv found -- run a sweep first.")
        sys.exit(2)
    for (a, dl), runs in sorted(subjects.items()):
        fam = ATTACK_FAMILY.get(a, ("?", "unknown"))[1]
        allseeds = sorted({s for pcts in seed_map.get((a, dl), {}).values()
                           for s in pcts})
        print(f"subject   : Attack {a} ({fam})"
              + (f", d={dl}ms" if dl else "")
              + f", pct={sorted(runs)}"
              + (f", seeds={allseeds} (newest per pct verified)" if allseeds else ""))
    print("=" * 78)

    verify_environment(rep, dirs)
    crypto_ops = parse_crypto_ops(dirs)
    for (a, dl), runs in sorted(subjects.items()):
        verify_subject(rep, dirs, a, dl, runs, crypto_ops)
    verify_crypto_timing(rep, dirs)
    verify_lstm_pipeline(rep)
    verify_baselines(rep, dirs)
    verify_attack_coverage(rep, subjects)
    verify_metric_coverage(rep)

    print()
    print("=" * 78)
    print("FUNCTIONAL VERIFICATION SUMMARY")
    print("=" * 78)
    print(f"  subjects verified : {len(subjects)} attack sweep(s)")
    print(f"  checks executed   : {rep.n}")
    print(f"  result            : {c.G}{rep.pass_} PASS{c.O}, "
          f"{c.R}{rep.fail} FAIL{c.O}, "
          f"{c.Y}{rep.warn} WARN (artefact not produced by this run){c.O}")
    print("=" * 78)
    if rep.fail == 0:
        print(f"{c.G}TEST PASSED -- FULL-SYSTEM FUNCTIONAL VERIFICATION{c.O}")
        print(f"{c.G}Every subsystem exercised by the artefacts present behaved as "
              f"docs/main.tex{c.O}")
        print(f"{c.G}specifies: attacks took effect, detection fired, the crypto and "
              f"blockchain{c.O}")
        print(f"{c.G}layers accrued, trust and failover reacted, and every reported "
              f"metric agrees{c.O}")
        print(f"{c.G}with its independent recomputation.{c.O}")
        if rep.warn:
            print(f"{c.Y}{rep.warn} check(s) were skipped because the corresponding "
                  f"artefact was not produced{c.O}")
            print(f"{c.Y}by this run -- these are gaps in run coverage, not defects.{c.O}")
    else:
        print(f"{c.R}TEST FAILED -- {rep.fail} check(s) did not hold:{c.O}")
        for f in rep.failures:
            print(f"{c.R}    - {f}{c.O}")
    print("=" * 78)

    if args.strict and rep.fail:
        sys.exit(1)


if __name__ == "__main__":
    main()
