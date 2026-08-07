# CSV Tag Unification & Bug Fix Plan

Status: DONE. All Phase 1 and Phase 2 items applied, verified, and committed
(see individual item entries below for what each verification actually covered).
Existing CSVs on disk from prior runs were not migrated — see "Coverage &
caveats" below.

**Amendment (post-completion):** the `TAP__Attack.../FADE__Attack...` double-underscore
form documented throughout this doc and originally shipped was later reversed to single
underscore (`TAP_Attack...`, `FADE_Attack...`, matching MOBIGUARD's plain form) at
explicit request. Every `Verified`/`Confirmed live` note below that shows a
double-underscore filename is an accurate record of what was tested *at the time* —
left as-is rather than rewritten, since revising history here would make the doc lie
about what was actually run and when. The "Target format" section immediately below
reflects the current, final state; everything past that point in the doc is historical.

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
- `TAP_Attack{N}_{pct}[_d{X}ms]_seed{S}.csv` (single underscore, same form as MOBIGUARD —
  reversed from an earlier double-underscore version; see the amendment note at the top)
- `FADE_Attack{N}_{pct}[_d{X}ms]_seed{S}.csv` (single underscore, same reversal as TAP)
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
   `Attack{N}_{pct}[_d{X}ms]_seed{S}.csv` (the local C++ variable is named
   `attack_v`, but it already held the correct 1-indexed-with-0-benign value that
   the rest of this doc calls `N` — pure rename, not an indexing fix). Confirmed live:
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

7c. **DONE — Convert tcam/lambda and hf_events to the canonical shape.** Phase 1
   #3/#4 only patched the live collision (add seed, add pct where missing) while
   keeping each file's own ad hoc `mode` string. This item replaced that scheme
   outright with the canonical `Attack{N}_{pct}_seed{S}` shape:

   - `tcam_snapshots_*` / `tcam_occupancy_*` / `lambda_l_true_*` (tcam_attack_helper.h,
     both `tcam_snapshot_dump()` and `export_tcam_snapshot_baseline()`): `mode` was
     `"attack" + (variant+1)` / `"baseline"` lowercase, plus two extra axes that don't
     fit the canonical format — preserved as trailing suffixes rather than lost or
     folded into `{pct}`:
     - Attack 3's suffix renamed from `_pctN` to `_cpintN` (still derived from
       `cp_attack_intensity`, not `attack_percentage` — the rename makes that
       explicit in the filename itself instead of relying on a code comment nobody
       reads at 2am). The canonical `{pct}` field is always `attack_percentage` now.
     - Attack 4's `_nN` (attacker count) kept as-is, still has no canonical slot.
     Final shape: `Attack{N}_{pct}_seed{S}[_cpintN|_nN].csv`. Confirmed live:
     `Attack3_40_seed1_cpint40.csv`, `Attack4_40_seed1_n80.csv` (the `_n80` isn't a
     bug — `--num_attackers` is explicitly documented as a no-op CLI flag; the real
     value is always recomputed from `attack_percentage`, and 40% of 200 vehicles is
     genuinely 80).

   - `hf_events_{mode}_{pct}.csv` (hf_attack_helper.h): `mode` came from a hardcoded
     `{4:"attack5", 5:"attack6", 6:"attack7", 7:"attack8"}` map (default `"baseline"`,
     covering only Attacks 5-8 and never baseline/Attacks-1-4 correctly). Replaced
     with `Attack{N}_{pct}_seed{S}.csv` using the same `variant + 1` conversion as
     everywhere else. Still dead code per Phase 1 #4's finding (never called, build
     verified only — same caveat as before, unchanged by this item).

   `scripts/functional_verification.py`'s three lookups fixed in the same change:
   `tcam_occupancy_attack{attack}.csv` → `tcam_occupancy_Attack{attack}_*.csv`,
   `tcam_snapshots_attack{attack}*.csv` → `tcam_snapshots_Attack{attack}_*.csv`,
   `lambda_l_true_attack*.csv` → `lambda_l_true_Attack*.csv` (all via `find_files()`,
   already glob-based internally — only the literal pattern strings needed updating).
   Its two separate `bc_dkg_log`/`bc_trust_updates` patterns are a different family
   entirely (not touched by this item) and remain item 8's job, as originally scoped.

   Verified: build succeeds; `python3 -m py_compile` clean on
   `functional_verification.py`; ran a real Attack3/pct40/seed1 sim and got
   `tcam_snapshots_Attack3_40_seed1_cpint40.csv` (and matching
   `tcam_occupancy_*`/`lambda_l_true_*`); ran a real Attack4 sim and confirmed the
   `_nN` suffix path produces `tcam_snapshots_Attack4_40_seed1_n80.csv`.

8. **DONE — Update downstream Python consumers.**

   - **`run_rule_based_sweep.py`** — dropped the sequential-lane "run then rename"
     workaround entirely, as planned. Its premise was already false: `result_filename()`
     built the pre-Phase-2-#5 no-seed name, so `src.exists()` in the rename step was
     always `False` (the seed-tagged file the C++ side actually wrote never matched),
     meaning every run silently logged "(NO OUTPUT FILE)" and `passed` was always 0 —
     even though the final "sample check" loop happened to construct the *correct*
     seed-tagged name independently and would have reported files present. Restructured
     to submit one job per `(attack, pct, seed)` directly (no lanes, no rename) and
     check for the native output path.
     **Verified live**, not just build/syntax: ran a real 2-job sweep
     (`--attack 1 --percentage 40 --seeds 1 2`) — `Passed: 2/2`, both
     `MOBIGUARD_Attack1_40_d80ms_seed{1,2}.csv` found directly with no rename step.

   - **`run_ablation_sweep.py`** — confirmed this one is *not* like
     `run_rule_based_sweep.py`: its sequential-lane rename exists for a genuinely
     different, still-real collision (multiple ablation configs — AB4-A/B/C, AB1-A/B —
     sharing the identical `(attack, pct, seed=1)`, since ablation flags like
     `enable_stark_delay`/`enable_lrad_rsu` have no slot in the filename at all). Kept
     the rename mechanism; the actual bug was that `result_filename()` was missing
     `_seed{S}` (same "can't find the file to rename" failure pattern), fixed by adding
     it. Docstring corrected to explain why this workaround stays necessary while
     `run_rule_based_sweep.py`'s did not.

   - **`run_std_attacks.py`** — `clean_results()` and `check_results()` both did
     exact-match lookups with no seed and the old single-underscore `TAP_Attack`; both
     switched to glob-based (`clean_results`) / seed-parameterized exact match
     (`check_results`, threaded through from `args.seed`) with the `TAP__Attack` double
     underscore. Docstring and two inline comments referencing the old filename shapes
     corrected.

   - **`run_hf_attacks.py`** — found a second bug beyond the `check_results()` one
     already fixed in Phase 2 #6: `clean_results()` had the identical no-seed,
     single-underscore-TAP problem (missed in the earlier pass since that function
     wasn't touched then). Fixed the same way — glob-based cleanup tolerating any seed.

   - **`plot_tap_results.py`** — **not on the original 12-file list at all**, discovered
     while reading `run_std_attacks.py`'s comments (which reference it directly). Its
     `load_method_data()` was byte-for-byte the same exact-match-no-seed bug as
     `plot_fade_results.py`'s had before Phase 2 #6 — fixed identically: glob-based,
     `seed` parameter (new `--seed` CLI flag, default 1) threaded through, `"TAP_"`
     prefix (→ `"TAP__Attack..."`) at the call site. This is exactly the kind of gap
     the plan's "enumerate exactly what each one assumes... before changing the writer"
     caution was for — the original file audit was scoped to lstm consumers and never
     looked at this one, since it doesn't touch `lstm_training` at all.

   - **`plot_fade_results.py`** — updated the docstring at `load_fade_summary_mcc()`
     that used to justify avoiding `routing_fade_per_cycle.csv` partly by citing its
     (now-fixed) cross-contamination risk. Kept the function's actual behavior
     unchanged — the small-sample MCC artifact reason alone still justifies preferring
     `fade_metrics_*` — just corrected the now-false half of the stated reasoning.

   - **`plot_hf_results.py`** — the `variant = attack_number - 1` conversion this item
     originally flagged was already removed as part of Phase 2 #6's rewrite (confirmed
     via grep — zero remaining references). No further action needed here.

   - **`plot_tcam_detection.py`** — already fully handled in Phase 2 #7 (fixed
     alongside the baseline-unification work, since it shared the same missing-seed bug
     independent of baseline).

   - **`verify_metrics.py`** — the `MOBIGUARD_baseline.csv` exact match was already
     fixed in Phase 2 #7. Broader audit here found nothing else needing a change: every
     other lookup was already glob-based (`find_one()`), and there's no regex-based
     filename parsing in this file to re-verify (unlike `functional_verification.py`'s
     `MG_RE`). `MOBIGUARD_baseline_fbad*.csv` (a separate, unrelated M9-specific
     convention, not produced by `write_security_metrics_csv()`) correctly left alone,
     as already noted in Phase 2 #7.

   - **`functional_verification.py`** — the two flagged patterns
     (`bc_dkg_log_Attack{attack}_*`, `bc_trust_updates_Attack{attack}_*`) needed a
     trailing `*` added before `.csv`: with `bc_run_suffix()` now appending
     `_seed{S}[_TAP][_FADE]` *after* the delay segment, the old glob (ending exactly at
     `_d{delay}ms.csv`) stopped matching whenever a delay was present — the no-delay
     case worked by coincidence (its trailing `*` already covered the seed segment).
     Also found `load_tap()` doing the same single-underscore `TAP_Attack` bug found
     independently in `run_std_attacks.py`/`plot_tap_results.py` — fixed to
     `TAP__Attack` in both the glob and its accompanying regex, with the same trailing
     `*` fix. The main `MG_RE` regex was confirmed (not assumed) already correct — it
     already had an optional seed group before this plan even started. Also corrected a
     stale block comment above `MG_RE` that was actively misleading about *why* seeds
     appear in filenames (attributing it to `run_rule_based_sweep.py`'s now-removed
     rename step rather than the C++ side being fixed at the source).

   Verified throughout: `python3 -m py_compile` clean on all eight touched files
   (`run_rule_based_sweep.py`, `run_ablation_sweep.py`, `run_std_attacks.py`,
   `run_hf_attacks.py`, `plot_tap_results.py`, `plot_fade_results.py`,
   `functional_verification.py`, `verify_metrics.py`); `run_rule_based_sweep.py` also
   verified with a real live sweep as described above.

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

The three caveats below were written before implementation started, to flag what
this plan would *not* automatically solve. Now that every item is DONE, #2 and #3
are resolved (recorded here for history, not as open work) — #1 remains genuinely
true and is the one thing left if you need it:

1. **Existing CSVs on disk were not touched — still true.** Every fix changed the
   code that generates *future* files. Anything already sitting in `results_routing/`
   from before this work kept its old filename shape — no migration/rename step was
   run over historical data. If old and new-format runs need to coexist for analysis,
   or old files need bulk-renaming to the new shape, that's separate work, not done
   as part of this plan.

2. **Downstream Python fixes — resolved.** Every file originally flagged as
   "confirmed via grep, needs opening to determine what breaks" was individually
   opened, classified (glob / positional-parse / plain path / genuinely unaffected),
   and fixed where needed — see each item's "Verified" note for specifics. Two
   consumers not on the original list at all (`plot_tap_results.py`, and a second bug
   in `run_hf_attacks.py`'s `clean_results()`) were found and fixed during that
   process rather than being missed.

3. **The extra-suffix spelling — resolved.** Attack 3's `cp_attack_intensity`-derived
   suffix is `_cpintN`; Attack 4's attacker-count suffix stayed `_nN`. Both ship as
   trailing segments after `Attack{N}_{pct}_seed{S}`, confirmed live
   (`Attack3_40_seed1_cpint40.csv`, `Attack4_40_seed1_n80.csv`).
