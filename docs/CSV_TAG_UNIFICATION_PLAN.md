# CSV Tag Unification & Bug Fix Plan

Status: not started. Nothing in this document has been applied yet.

Source of truth for editing: this repo's `scratch/routing.cc` and
`scratch/*.h`. Sync to `ns-allinone-3.35/ns-3.35/scratch/routing/` (or run
each script's `sync_files()`) after each step, and rebuild before testing.

## Target format

```
_Attack{N}_{pct}[_d{X}ms]_seed{S}
```

- `N` — 1-indexed attack number, `0` for baseline/clean runs. Convert via
  `bc_run_suffix()`'s existing formula: `id = (active_attack_variant >= 0) ? active_attack_variant + 1 : 0`.
- `pct` — `attack_percentage`, unchanged.
- `_d{X}ms` — present only when `g_delay_suffix` is currently set (attacks 1/2 only;
  gated by `attack_number_explicitly_set` — see routing.cc:142004-142007). Preserve
  this condition as-is.
- `seed` — `sim_seed`, native to the filename from the moment the file is opened.

Prefix-specific filenames:
- `MOBIGUARD_Attack{N}_{pct}[_d{X}ms]_seed{S}.csv`
- `TAP__Attack{N}_{pct}[_d{X}ms]_seed{S}.csv` (double underscore: prefix `TAP_` + suffix `_Attack...`)
- `FADE__Attack{N}_{pct}[_d{X}ms]_seed{S}.csv` (double underscore: prefix `FADE_` + suffix `_Attack...`)
- Baseline uniformly represented as `Attack0` — no more separate `MOBIGUARD_baseline.csv` /
  `FADE_baseline.csv` / `tcam_*_baseline.csv` files, no more raw negative index (`V-1`).
- `lstm_training/RSU_{r}/Attack{N}_{pct}[_d{X}ms]_seed{S}.csv` — replaces the current
  `A{v}_pct{p}_seed{s}.csv` (see Phase 2 #7b for why this rename's downstream impact is
  bigger than it looks).

## Fix order

### Phase 1 — Live corruption bugs (fix first, independent of naming unification)

1. **DONE — `AnimationInterface` hardcoded path.** routing.cc:144219 wrote `routing.xml`
   to one fixed global path with no tag, so every concurrent process overwrote the same
   file. Fixed by tagging the path with `g_sim_tag` (`routing<tag>.xml`).

   While implementing this, testing surfaced a second problem the original writeup
   didn't anticipate: NetAnim traces grow ~1.46 MB per simulated second (measured), so a
   real `simTime=300` training run produces ~440 MB, and `run_training_attacks.py`'s
   240-run sweep alone would produce ~105 GB — a large fraction of the 233 GB free on
   this disk — once every run started keeping its own permanent tagged file instead of
   all runs overwriting one shared (corrupted) file. Fixed by also gating construction
   behind a new `--enable_netanim` CLI flag, default off — sweeps no longer produce any
   trace file unless explicitly asked to.

   Verified: build succeeds; a default run produces no `.xml`; `--enable_netanim=1`
   produces a correctly-tagged trace; two concurrent runs with different attack/pct/seed
   (`--enable_netanim=1` on both) produced two distinct, independently-growing files
   with no collision.

2. **DONE — `bc_run_suffix()` missing `_FADE` disambiguator.** bc_blockchain_helper.h:90-94
   had `enable_tap ? "_TAP" : ""` but no equivalent for FADE runs. `run_hf_attacks.py`
   submits the normal MOBIGUARD run and the FADE run for the same (attack, pct) to the
   same `ThreadPoolExecutor` concurrently (confirmed in `main()`, lines 325-358), and
   `FADE_PARAMS` never set any flag this function checked — so both processes computed
   the identical suffix and collided on `bc_anchor_log`, `bc_dkg_log`, `bc_detection_log`,
   `bc_model_log`, `bc_flowmod_log`, `bc_trust_updates`, `bc_tref_log`.

   Fixed by checking `fade_detection_active` alongside `enable_tap` — no new CLI flag
   needed. `fade_detection_active` (routing.cc:144339,
   `active_attack_variant in [4,7] && !enable_lrad_obu && !enable_lrad_rsu`) is already a
   reliable, auto-computed signal that's true precisely during an isolated FADE run, and
   it's resolved during one-time setup in `main()` before `Simulator::Run()` starts —
   i.e. before any bc_* file could possibly be opened from a scheduled event — so it's
   safe to read from `bc_run_suffix()` without reordering anything. Zero changes needed
   to `run_hf_attacks.py` or `FADE_PARAMS`.

   Verified: build succeeds; ran the normal MOBIGUARD process and an isolated FADE
   process (`--enable_lrad_obu=0 --enable_lrad_rsu=0`) concurrently for the same
   Attack5/pct40/seed1, and got two fully disjoint file sets —
   `bc_dkg_log_Attack5_40.csv` / `bc_dkg_log_Attack5_40_FADE.csv`, and the same clean
   split for `bc_flowmod_log`, `bc_tref_log`, `bc_trust_updates` — no collision.

3. **DONE — `tcam_snapshots_*` / `tcam_occupancy_*` / `lambda_l_true_*` missing seed (and
   mostly missing pct).** tcam_attack_helper.h's `tcam_snapshot_dump()` built `mode` as
   just `"attack{N}"` / `"baseline"`, with pct-like info only for Attack 3/4 (and even
   then it was `cp_attack_intensity`/`num_attackers`, not the report's
   `attack_percentage`). Every other attack got zero differentiation by percentage or
   seed — two different percentage sweeps of the same attack collided on the identical
   filename, not just two seeds.

   Fixed by appending `_ap{attack_percentage}_seed{sim_seed}` to `mode` unconditionally,
   after the existing `_nN`/`_pctN` logic. Used `_ap` rather than `_pct` deliberately so
   it can never be confused with Attack 3's `cp_attack_intensity`-derived `_pctN` — see
   the "watch" note at the bottom of this doc. Since `tcam_occupancy_*` and
   `lambda_l_true_*` reuse the same local `mode` variable in the same function, fixing
   it once fixed all three files together.

   Verified: build succeeds; ran two concurrent Attack 1 runs at pct=40 and pct=80
   (same seed) — previously both would collide on `tcam_snapshots_attack1.csv`; now
   produced `tcam_snapshots_attack1_ap40_seed1.csv` / `_ap80_seed1.csv`, with the same
   clean split for `tcam_occupancy_*` and `lambda_l_true_*`.

4. **DONE — `hf_events_{mode}_{pct}.csv` missing seed.** hf_attack_helper.h's
   `export_hf_event_log()` had `pct` but no seed. Appended `_seed{sim_seed}`, same
   pattern as #3.

   Verified build-only, not runtime — while implementing this, found that
   `export_hf_event_log()` is never actually called anywhere in the codebase (grepped
   all of `scratch/`), and the `g_hf_event_log` vector it reads from is never pushed to
   either. `hf_events_*.csv` is dead code as it stands today: correctly tagged now, but
   not produced by any current run regardless. This is a pre-existing gap unrelated to
   the tagging bug — separate from what this plan scopes, flagging here rather than
   fixing it silently. If HF per-event duplicate logging is actually wanted, wiring up
   the call site and the `g_hf_event_log.push_back(...)` is a distinct piece of work.

4b. **DONE — `routing_fade_per_cycle.csv` completely untagged.** `fade_write_per_cycle_csv()`
   (routing.cc) wrote `dir + "routing_fade_per_cycle.csv"` with no attack/pct/seed/delay
   at all — every concurrent FADE-adjacent run of any attack/pct/seed appended to the
   identical shared file. This wasn't a hypothetical: `scripts/plot_fade_results.py`
   (lines 192-197) already had a docstring explicitly warning about this exact file
   being "cross-contaminated by concurrent runs" and instructing callers to use
   `fade_metrics_V<variant>_pct<pct>_s<seed>.csv` instead for anything that needs
   per-run isolation — i.e. the collision was already known and worked around in one
   consumer, never fixed at the source.

   Fixed by tagging with `g_sim_tag`, same approach as the `AnimationInterface` fix
   (#1) — the function only fires from a scheduled per-cycle callback, always well
   after `g_sim_tag` is resolved during setup.

   Note for whoever picks up Phase 2 #6 (converting `g_sim_tag` to the canonical
   `Attack{N}` shape): `fade_write_per_cycle_csv()` is gated by
   `if (!fade_detection_active) return;` at its top, so it only ever fires for HF
   attacks (5-8) run in isolated-FADE mode — this matters when re-testing after that
   conversion (a normal, non-FADE run will never produce this file, by design, not by
   bug).

   Verified: build succeeds (explicitly re-confirmed compile+link after deleting the
   stale object/binary — see the caveat added to "Coverage & caveats" below); ran two
   concurrent Attack 5 runs at pct=40/seed=1 and pct=80/seed=2 (both with
   `--enable_lrad_obu=0 --enable_lrad_rsu=0`, matching real FADE-isolation runs) and got
   two distinct files, `routing_fade_per_cycle_V4_pct40_s1.csv` and
   `routing_fade_per_cycle_V4_pct80_s2.csv`, instead of one shared file.

4c. **DONE — `tcam_snapshots_{mode}_final.csv` missing seed.** tcam_attack_helper.h's
   `export_tcam_snapshot_baseline()` (end-of-sim backup dump) built `mode` via the exact
   same logic as #3's per-second writer, with the same gap. Fixed identically —
   appended the same `_ap{attack_percentage}_seed{sim_seed}` after its `_nN`/`_pctN`
   logic. Build verified; not separately runtime-tested beyond the build (same fix as
   #3, applied to a function that only fires once at end-of-sim).

### Phase 2 — Naming/indexing unification (do after Phase 1 fixes are verified)

5. **DONE — Add seed to MOBIGUARD/TAP/FADE/bc_*.** None of these five file families
   carried `sim_seed`. Added `_seed{S}` per the target format, and applied the
   `TAP_`/`FADE_` double-underscore prefix convention (`TAP__Attack...`,
   `FADE__Attack...`) at the same time since it was part of the same target-format
   change:
   - MOBIGUARD: routing.cc `write_security_metrics_csv()`
   - TAP: tap_detection.h `write_tap_csv()`
   - FADE: routing.cc `fade_write_per_cycle_csv()`
   - bc_*: bc_blockchain_helper.h `bc_run_suffix()` — seed placed before the
     `_TAP`/`_FADE` disambiguators (`..._seed{S}_TAP`, not `..._TAP_seed{S}`)

   Went slightly beyond the item's literal wording: also added seed to the *baseline*
   branch of MOBIGUARD (`MOBIGUARD_baseline.csv` → `MOBIGUARD_baseline_seed{S}.csv`)
   and FADE (`FADE_baseline.csv` → `FADE_baseline_seed{S}.csv`), which weren't
   separately called out as their own Phase 1 item but had the identical missing-seed
   collision — two seeds of a baseline run would otherwise still collide after this
   item. Baseline is intentionally NOT given the double-underscore treatment
   (`FADE_baseline`, not `FADE__baseline`) since it isn't using the
   `_Attack{N}_{pct}...` canonical suffix that motivated the double underscore in the
   first place — that gets resolved when baseline is unified to `Attack0` in #7.

   FADE's percentage bucketing (rounds `attack_percentage` to the nearest of
   `{0,20,40,60,80,100}` before embedding it) was left untouched — out of scope for a
   seed-only change, noted here so it isn't mistaken for something this item was
   supposed to fix.

   Verified: build succeeds (force-rebuilt per the gotcha above); ran four concurrent
   processes — normal Attack1, TAP-enabled Attack2, FADE-isolated Attack5, and a
   baseline run, all `--sim_seed=1` — and got correctly-tagged output from all four
   writer families in one pass: `MOBIGUARD_Attack1_40_d100ms_seed1.csv`,
   `MOBIGUARD_baseline_seed1.csv`, `TAP__Attack2_40_d100ms_seed1.csv`,
   `FADE__Attack5_40_seed1.csv`, `bc_dkg_log_Attack1_40_d100ms_seed1.csv`, and
   `bc_dkg_log_Attack5_40_seed1_FADE.csv`. `FADE_baseline_seed{S}.csv`'s branch wasn't
   live-fired (the baseline test run has `active_attack_variant == -1`, so
   `fade_detection_active` never gates true and `fade_write_per_cycle_csv()` returns
   before reaching it) — code-reviewed only for that specific branch, same conditional
   structure as the verified MOBIGUARD baseline branch.

6. **DONE — Convert `g_sim_tag` from 0-indexed to 1-indexed, and to the canonical
   shape.** routing.cc used to build `_V{active_attack_variant}_pct{...}_s{seed}{delay}`
   from the raw 0-indexed variant. Replaced outright with the canonical
   `_Attack{N}_{pct}[_d{X}ms]_seed{S}` shape — same `id = variant>=0 ? variant+1 : 0`
   conversion `bc_run_suffix()` already used, `Attack` instead of `V`, `seed{S}` instead
   of `s{seed}`, and the delay segment (when present) now ordered before seed instead
   of after. No `V`-prefixed form is kept anywhere.

   Consumers automatically inherited the new shape with no code changes needed, since
   they just interpolate `g_sim_tag` as-is: `optimization_link_lifetime_data_*`,
   `link_lifetime_solution_*`, `fade_results`, `fade_metrics`, `crypto_timing_log`,
   plus the two Phase 1 fixes that also use `g_sim_tag` directly (`routing.xml`,
   `routing_fade_per_cycle.csv`) — all verified producing `..._Attack5_40_seed1...`
   filenames in the runtime test below.

   `plot_fade_results.py` and `plot_hf_results.py`, which parsed the old
   `_V{variant}_pct{...}` shape directly, were NOT left broken — updated in this same
   change (see below) rather than deferred to #8, since leaving them stale would mean
   the g_sim_tag conversion ships broken for its two actual consumers.

   **Downstream fixes made in this same pass, beyond the item's literal scope:**
   - `plot_fade_results.py`: `load_method_data()`'s FADE branch (exact match, assumed
     an unsuffixed `FADE_Attack<N>_<pct>.csv`) is now glob+seed based like its
     MOBIGUARD branch always was, with a `"FADE_"` prefix (double underscore result:
     `"FADE_" + "_Attack..." = "FADE__Attack..."`) — call site updated accordingly.
     `load_fade_summary_mcc()`'s exact-match path rewritten from
     `fade_metrics_V<variant>_pct<pct>_s<seed>.csv` to
     `fade_metrics_Attack<N>_<pct>_seed<S>.csv`; the now-unused `variant = attack_number
     - 1` line removed. `load_mobiguard_final_mcc()` needed no change — it was already
     glob+seed based and tolerates the new shape as-is. Docstrings/comments referencing
     the old filename shapes updated throughout the file for accuracy.
   - `plot_hf_results.py`: had **zero seed awareness at all** (not just the V-tag
     issue) — `load_fade(variant, pct)` and `load_mobiguard(number, pct)` both did
     bare exact-match lookups with no seed segment, which Phase 2 #5's seed addition
     had already silently broken before this item even started. Rewrote both:
     `load_fade` now takes `(number, pct, seed=1)` and reads
     `fade_metrics_Attack{number}_{pct}_seed{seed}.csv`; `load_mobiguard` now takes
     `(number, pct, seed=1)` and globs `MOBIGUARD_Attack{number}_{pct}*_seed{seed}.csv`
     (tolerating a possible delay segment, mirroring `plot_fade_results.py`'s pattern
     even though delay never actually applies to the Attacks 5-8 this script targets).
     Added the missing `import glob`. Updated the `load_all()` call site to pass the
     1-indexed attack `number` instead of the internal 0-indexed `variant` (the
     filenames are keyed by attack number now, not variant).
   - `run_hf_attacks.py`: `check_results()` did exact-match checks for
     `MOBIGUARD_Attack{a}_{p}.csv` / `FADE_Attack{a}_{p}.csv` with no seed and the old
     single underscore — also silently broken by #5 before this item started (every
     check would report MISSING regardless of real output). Added a `seed` parameter,
     fixed to `MOBIGUARD_Attack{a}_{p}_seed{seed}.csv` /
     `FADE__Attack{a}_{p}_seed{seed}.csv`, and passed `args.seed` through at the call
     site. Also corrected a stale module-docstring block describing the old filename
     shapes.

   Deliberately NOT touched in this pass (left for #8 as originally scoped):
   `run_std_attacks.py`, `run_ablation_sweep.py`, `run_tcam_sweep.py`,
   `functional_verification.py`, `verify_metrics.py`, `plot_tcam_detection.py` — these
   weren't newly broken by g_sim_tag specifically (or weren't verified either way), so
   fixing them here would be scope creep beyond what this item's testing covered.

   Verified: build succeeds (force-rebuilt, confirmed `Compiling`/`Linking` lines);
   `python3 -m py_compile` clean on all three edited Python files; ran a FADE-isolated
   Attack5/pct40/seed1 sim and got `fade_results_Attack5_40_seed1.csv`,
   `routing_fade_per_cycle_Attack5_40_seed1.csv`, and `routing_Attack5_40_seed1.xml`
   (all three now inheriting the canonical shape automatically); ran a normal
   Attack5/pct40/seed1 sim and functionally tested the real Python loaders against the
   real output files — `plot_hf_results.py`'s `load_mobiguard()` correctly parsed 4 real
   data rows into PDR/MCC/DR/FPR arrays, and `plot_fade_results.py`'s
   `load_method_data()` correctly found 4 rows for both the MOBIGUARD and FADE_ prefixes
   against the same files.

7. **DONE — Unify baseline representation to `Attack0` everywhere.** Replaced the
   competing conventions (separate filename in MOBIGUARD/FADE/tcam) with the `Attack0`
   convention `bc_run_suffix()`/`g_sim_tag`/lstm_logger.h already used. Removed
   `MOBIGUARD_baseline_*.csv`, `FADE_baseline_*.csv`, and tcam's `"baseline"` mode
   string as distinct forms:
   - `write_security_metrics_csv()` (MOBIGUARD): the whole `switch` that special-cased
     `active_attack_variant == -1` into a separate filename was replaced with the same
     one-line `id = variant>=0 ? variant+1 : 0` formula everywhere else already uses —
     baseline now falls out of the general path naturally as `Attack0`.
   - `fade_write_per_cycle_csv()` (FADE): same restructuring. Its baseline branch was
     actually unreachable dead code before this change too — `fade_detection_active`
     (the function's own top-of-function guard) requires `active_attack_variant` in
     `[4,7]`, which a true baseline run (`variant == -1`) never satisfies — but fixed
     for consistency and in case that guard is ever relaxed.
   - `tcam_snapshot_dump()` / `export_tcam_snapshot_baseline()`: `mode` folded to
     `"attack0"` for baseline, staying within tcam's own existing lowercase
     `"attack{N}"` convention rather than jumping ahead to the capitalized `Attack{N}`
     canonical shape — that full rename is #7c's job, not this item's; doing it here
     too would be churn undone again one item later.

   **Fixed three scripts that hardcoded the literal `"MOBIGUARD_baseline.csv"`** (exact
   string, not a wildcard) in the same change, per the risk flagged when this item was
   still pending:
   - `run_tcam_sweep.py` — `out_csv` for baseline updated to
     `MOBIGUARD_Attack0_0_seed1.csv` (no `--sim_seed` is ever passed by this script, so
     seed is always the C++ default of 1 — exact match is accurate here, not just
     convenient). Also fixed its Attack3/Attack4 `out_csv` entries the same way — they
     had the identical missing-seed gap, not just the baseline one.
   - `plot_tcam_detection.py` — same fix, plus discovered its `Attack{ATTACK_ID}_{pct}`
     lookup had the identical missing-seed bug independent of baseline (already broken
     by #5, not just this item). Added a `SEED = 1` config constant and fixed both
     lookups.
   - `verify_metrics.py` — its `pattern_map`'s baseline entry was the one exact-match
     holdout while its three sibling entries (`Attack1`, `Attack5`, `Attack7`) already
     used a `*` wildcard via `find_one()` (confirmed glob-based). Changed baseline to
     `MOBIGUARD_Attack0_*.csv` to match that existing glob convention instead of
     hardcoding a seed. Left `MOBIGUARD_baseline_fbad*.csv` (a different, unrelated
     M9-specific naming convention — not produced by `write_security_metrics_csv()`)
     untouched.

   Also corrected a stale doc-comment above `fade_write_per_cycle_csv()` describing the
   old `FADE_baseline.csv` shape.

   Verified: build succeeds (force-rebuilt, confirmed `Compiling`/`Linking`);
   `python3 -m py_compile` clean on all three edited scripts; ran a true baseline sim
   (no `--attack_number` at all) and got `MOBIGUARD_Attack0_0_seed1.csv` and
   `tcam_snapshots_attack0_ap0_seed1.csv` — no `_baseline`-named file produced at all.

7b. **DONE — Convert lstm_logger.h to the canonical shape.** Was
   `lstm_training/RSU_{r}/A{v}_pct{p}_seed{s}.csv`: no `_d{X}ms`, no leading `Attack`
   literal, used `A` instead of `Attack`. Converted to
   `Attack{v}_{pct}[_d{X}ms]_seed{s}.csv` (`attack_v` was already the correct
   1-indexed-with-0-benign value — pure rename, not an indexing fix). Confirmed live:
   attacks 1/2 DO now carry a real `_d{X}ms` segment in lstm files (e.g.
   `Attack1_40_d100ms_seed1.csv`) since `run_training_sweep.py`/`run_training_attacks.py`
   never override `--attack_delay_ms`, so `g_delay_suffix` fires at its default anchor
   value — this is a genuinely new segment these files didn't carry before, not a
   theoretical edge case.

   **Full audit of all 12 originally-flagged consumers, done before touching the C++
   writer as planned:**

   Real fixes required (all applied):
   - `lstm_pipeline/src/preprocessor.py` — the positional parse (`parts[0][1:]` etc.)
     rewritten to a named-group regex
     (`^Attack(?P<attack_v>\d+)_(?P<pct>\d+)(?:_d\d+ms)?_seed(?P<seed>\d+)$`) tolerant
     of the optional delay segment; glob updated to `Attack*_seed*.csv`.
   - `lstm_pipeline/src/rule_calibrator.py` — glob updated
     (`A0_pct0_seed*.csv` → `Attack0_0_seed*.csv`); its `p.stem.split("seed")[1]`
     seed-extraction needed no change (splits on the literal substring "seed",
     agnostic to whatever prefix precedes it).
   - `lstm_pipeline/src/plot_mobility_stratified_mcc.py` — same positional-parse bug
     as preprocessor.py (`parts[0][1:]` etc.), fixed with the same regex approach; glob
     updated to `Attack[5-8]_*_seed5.csv`.
   - `lstm_pipeline/src/q30_holdout_eval.py` — exact-match path updated
     (`A0_pct0_seed{seed}.csv` → `Attack0_0_seed{seed}.csv`).
   - `scripts/run_training_sweep.py` — `csv_is_complete()` and `check_outputs()` both
     did exact-match lookups with no delay tolerance; both now share a new
     `lstm_csv_path()` helper that globs `Attack{attack}_{pct}*_seed{seed}.csv`,
     correctly tolerating the delay segment for attacks 1/2.

   Confirmed NOT broken (docstring-only staleness fixed, no functional bug):
   `scripts/run_training_attacks.py` (only ever logs to its own `.log` files, never
   reads the CSV back to check it).

   Confirmed genuinely out of scope (grepped in originally only because of a
   coincidental `A{n}_pct{p}` substring match, not a real lstm_training reference):
   - `lstm_pipeline/src/evaluator.py`, `mobility_stratified_eval.py`,
     `a2_warmup_adaptation_eval.py` — the matches were `f"A{av}"` human-readable
     fallback labels (`ATTACK_NAMES.get(av, f"A{av}")`), not file paths. These three
     plus `local_trainer.py`/`fed_aggregator.py` only ever consume already-preprocessed
     `.npy`/`.pt`/`.json` artifacts, never the raw `lstm_training/*.csv` files directly.
   - `scripts/run_std_attacks.py`, `functional_verification.py` — their matches were
     this script's own `.log` filenames or console-only labels; neither references
     `lstm_training` at all (confirmed via direct grep).
   - `scripts/run_hf_attacks.py` — already fully handled in Phase 2 #6 (MOBIGUARD/FADE
     files); doesn't touch lstm_training either.

   **`scripts/run_rule_based_sweep.py` — confirmed out of #7b's scope, but surfaced a
   new, currently-live bug, not just staleness.** This script has nothing to do with
   lstm_training (it exclusively renames `MOBIGUARD_Attack*.csv`, matched by the same
   `A{n}_pct{p}` substring coincidence as the other false positives above) — its
   in-scope home is Phase 2 #8, where the plan already says to "drop the sequential-lane
   rename workaround." But its docstring's premise
   ("`write_security_metrics_csv()` has no seed in its output filename") was falsified
   by Phase 2 #5 several commits before this one, and the script wasn't updated at the
   time. Concretely, today: it runs the sim (now producing an *already*
   seed-tagged `MOBIGUARD_Attack1_40_d80ms_seed3.csv`), then unconditionally does
   `src.name.replace(".csv", f"_seed{seed}.csv")` — appending a **second** seed suffix
   on top of the one the C++ side already wrote, e.g.
   `MOBIGUARD_Attack1_40_d80ms_seed3_seed3.csv`. Not fixed here (deliberately —
   staying inside this item's scope), but flagged prominently since it's an active
   double-suffix bug right now, not a "becomes unnecessary" cleanup — should be the
   first thing addressed when #8 starts.

   Also corrected two stale filename-shape references in `CLAUDE.md` (lstm_training
   line and the adjacent MOBIGUARD line, which was separately missing seed/baseline
   accuracy from Phase 2 #5/#7).

   Verified: build succeeds; `python3 -m py_compile` clean on all six edited Python
   files; ran a real Attack1/pct40/seed1 training-data-collection sim
   (`--training=1`) and got `Attack1_40_d100ms_seed1.csv` (confirming the delay
   segment really does appear); ran `preprocessor.py`'s actual `load_all_csvs()`
   against the real output — correctly parsed 256 rows across all 64 RSU directories
   with `attack_v=1, pct=40, seed=1` extracted correctly from the delay-bearing
   filename; separately confirmed via direct glob calls that `rule_calibrator.py`'s and
   `run_training_sweep.py`'s new patterns match/reject correctly against the same real
   file.

7c. **Convert tcam/lambda and hf_events to the canonical shape** — Phase 1 #3/#4 only
   patch the live collision (add seed, add pct where missing) while keeping each
   file's own ad hoc `mode` string. This item replaces that scheme outright with the
   canonical `Attack{N}_{pct}[_d{X}ms]_seed{S}` shape, same as everything else in
   Phase 2. (`_d{X}ms` will in practice never appear here — the delay suffix is only
   gated on for attack_number 1/2, and tcam is 3/4, hf is 5-8 — but keep the same
   conditional logic rather than special-casing its absence.)

   - `tcam_snapshots_*` / `tcam_occupancy_*` / `lambda_l_true_*` (tcam_attack_helper.h):
     `mode` is currently `"attack" + (variant+1)` / `"baseline"`, with two *extra*,
     attack-specific axes bolted on that are **not** part of the canonical format and
     must be preserved as additional suffixes rather than folded into `{pct}`:
     - Attack 3's `_pctN` is derived from `cp_attack_intensity`, not
       `attack_percentage` (explicit code comment warns about this — see the "watch"
       note at the bottom of this doc). The canonical `{pct}` field must be
       `attack_percentage` per the target-format definition; `cp_attack_intensity`
       needs its own distinct suffix segment (e.g. keep it as an explicit
       `_cpintN` or similar) so it isn't misread as the report's attack percentage.
     - Attack 4's `_nN` (attacker count) has no equivalent slot in the canonical
       format either — keep it as its own trailing suffix.
     So the realistic end shape here is `Attack{N}_{pct}_seed{S}[_cpintN|_nN].csv`,
     not a bare drop-in of the canonical format — decide the exact extra-suffix
     spelling at implementation time, but don't lose either axis in the conversion.

   - `hf_events_{mode}_{pct}.csv` (hf_attack_helper.h): `mode` comes from a
     hardcoded `{4:"attack5", 5:"attack6", 6:"attack7", 7:"attack8"}` map (default
     `"baseline"`). Replace with `Attack{N}_{pct}_seed{S}.csv` using the same
     `variant + 1` conversion as everywhere else, rather than the hardcoded map.

   Confirmed consumer: `scripts/functional_verification.py` reads these by
   constructed name — `tcam_occupancy_attack{attack}.csv` (line 864),
   `tcam_snapshots_attack{attack}*.csv` (line 867), `lambda_l_true_attack*.csv`
   (line 1136) — all lowercase `attack{N}`, no seed in the lookup pattern today.
   Must be updated in lockstep with the writer change, same as its two `bc_*`
   patterns already noted in item 8.

8. **Update downstream Python consumers** — once the C++ side changes:
   - `run_rule_based_sweep.py` — drop the sequential-lane "run then rename" workaround
     (its own docstring says this exists only to fix the contamination bug from before
     seed was native to the filename); can move to running seeds concurrently once seed
     is baked in from the moment the file is opened.
   - `run_std_attacks.py`, `run_hf_attacks.py` (also carries the Phase 1 #2 fix),
     `run_ablation_sweep.py`, `run_tcam_sweep.py` — update any hardcoded filename
     patterns to match the new scheme.
   - `plot_fade_results.py` — also update/remove the docstring at lines 192-197 once
     `routing_fade_per_cycle.csv` (Phase 1 #4b) is tagged; the warning about it being
     untagged and cross-contaminated becomes stale once fixed, and the file becomes
     safe to use directly instead of routing everyone to `fade_metrics_*` as a workaround.
   - `plot_fade_results.py`, `plot_hf_results.py` — currently do manual
     `variant = attack_number - 1` conversion to bridge `g_sim_tag`'s 0-indexing against
     MOBIGUARD's 1-indexing (plot_fade_results.py:200, plot_hf_results.py:51-54). This
     conversion becomes unnecessary once `g_sim_tag` is 1-indexed (Phase 2 #6) — remove it,
     don't just leave it as a no-op.
   - `plot_tcam_detection.py` — check against new tcam filenames.
   - `verify_metrics.py` — check against new filenames generally.
   - `functional_verification.py` — two hardcoded patterns to update:
     `bc_dkg_log_Attack{attack}_*` (line 713), `bc_trust_updates_Attack{attack}_*`
     (line 1021). Its main MOBIGUARD-parsing regex (line 330) may already tolerate the
     new shape — verify rather than assume.

### Not in scope for this plan

- **`main.tex` RSU coverage-radius inconsistency** (300–500 m at line 1499 vs. 270 m at
  lines 5742/6134, matching `d_max_dsrc = 270.0` in code) — documentation fix, unrelated
  to CSV tagging, track separately.
- **Fully untagged global scratch files** (`optimization_data.csv`,
  `optimization_results.csv`, `delay_solution.csv`, `delay_training_data.csv`,
  `delay_data_for_prediction.csv`) — intentionally global/shared per run; leave as-is
  unless a specific need to tag them surfaces.

### Watch during implementation, not a bug by itself

- `tcam_attack_helper.h`'s Attack-3 `_pctN` filename suffix is derived from
  `cp_attack_intensity`, **not** `attack_percentage` (explicit warning already in the
  code). Don't let the unified suffix logic silently conflate the two.

## Coverage & caveats

**Verification method**: every item above was found by grepping every `.csv` string
literal across all 24 files in `scratch/` (`*.cc` + `*.h`) — not just the subset
originally suspected. Two items (Phase 1 #4b, #4c) were only caught on this final
exhaustive pass; earlier passes had missed them. Confirmed separately that no Python
script under `scripts/` or `lstm_pipeline/src/` independently writes CSVs
(`grep -rlE ".to_csv\(|csv\.writer\(" → 0 matches`) — every CSV originates on the C++
side, so this file-by-file sweep is the complete set of *writers*. This plan is
therefore structurally complete: every CSV-writing call site in the codebase is
accounted for with a specific fix.

**Build verification gotcha found while implementing #4b**: `./waf build` reported
`'build' finished successfully` in ~0.2s without a `Compiling`/`Linking` line, on a
change that was definitely a real header-content edit — the object file was stale
relative to the edit and the binary didn't reflect the change, despite waf reporting
success. Deleting `build/scratch/routing/routing.cc.*.o` and
`build/scratch/routing/routing` outright and rebuilding fixed it, with `Compiling
scratch/routing/routing.cc` / `Linking build/scratch/routing/routing` then appearing
as expected. Don't trust a fast/quiet `./waf build` after a header-only edit — grep the
output for an explicit `Compiling scratch/routing/routing.cc` line, and if it's
missing, force it by deleting the object/binary before concluding the build is
actually current.

That said, applying this plan does not make every inconsistency instantly and
silently disappear. Three caveats:

1. **Existing CSVs on disk are not touched.** This plan fixes the code that generates
   *future* files. Anything already sitting in `results_routing/` from past runs keeps
   its old filename shape — there is no migration/rename step for historical data in
   this plan. If old and new-format runs need to coexist for analysis, that's separate
   work not currently scoped here.

2. **Downstream Python fixes are scoped, not all pre-verified line-by-line.** For
   `bc_*`, `hf_events`, `tcam_*`, and `functional_verification.py`'s three lookup
   patterns, the exact lines needing change are identified. For the 8
   `lstm_pipeline/src/*.py` files and several `scripts/*.py` files (Phase 2 #7b, #8),
   the plan lists them as "confirmed via grep to reference this filename shape" —
   someone still needs to open each one and determine exactly what breaks (glob
   pattern vs. positional parse vs. plain path string) before the C++ writer changes,
   as those sections already say. Treat that enumeration as part of the implementation
   work, not something already done.

3. **A few fields don't map cleanly onto the canonical shape and need a judgment call
   at implementation time**, not a mechanical find-replace: Attack 3's
   `cp_attack_intensity`-derived suffix and Attack 4's `_nN` attacker-count suffix
   (Phase 2 #7c) must survive as extra segments alongside `Attack{N}_{pct}_seed{S}`,
   and the exact spelling of those extra segments isn't locked in yet.
