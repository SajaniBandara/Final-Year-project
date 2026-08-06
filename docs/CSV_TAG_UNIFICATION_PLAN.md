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

5. **Add seed to MOBIGUARD/TAP/FADE/bc_*** — none of these five file families carry
   `sim_seed` today. Add `_seed{S}` per the target format above.
   - MOBIGUARD: routing.cc:117736 (`write_security_metrics_csv`)
   - TAP: tap_detection.h:183 (`write_tap_csv`)
   - FADE: routing.cc:117942
   - bc_*: bc_blockchain_helper.h `bc_run_suffix()`

6. **Convert `g_sim_tag` from 0-indexed to 1-indexed, and to the canonical shape** —
   routing.cc:143846-143850 currently builds
   `_V{active_attack_variant}_pct{...}_s{seed}{delay}` using the raw 0-indexed variant.
   Decided: replace this outright with the canonical
   `_Attack{N}_{pct}[_d{X}ms]_seed{S}` shape — same `id = variant>=0 ? variant+1 : 0`
   conversion `bc_run_suffix()` already uses, `Attack` instead of `V`, and `seed{S}`
   instead of `s{seed}`. No `V`-prefixed form is kept anywhere, internal or otherwise.

   `N` must be derived from `active_attack_variant + 1`, never from the `attack_number`
   variable — confirmed `attack_number` (routing.cc:141912) is only populated on the
   new `--attack_number` CLI path (routing.cc:141991, gated by
   `attack_number_cli != -1`); a run launched via the legacy `--active_attack_variant`
   path never touches it, leaving it stale/default, and it isn't `extern`'d into any
   header anyway. `active_attack_variant` is the only state both CLI paths reliably
   resolve into (routing.cc:141996), which is why every existing tag-writer
   (`bc_run_suffix()`, MOBIGUARD's switch, TAP, tcam) already derives `N` from it via
   `variant + 1` rather than from `attack_number` — keep that pattern.

   Consumers to re-check after this change: `optimization_link_lifetime_data_*`,
   `link_lifetime_solution_*`, `fade_results`, `fade_metrics` (efade_detection.h:401),
   `crypto_timing_log` (crypto_event_log.h:69) — and `plot_fade_results.py` /
   `plot_hf_results.py`, which currently parse the `_V{variant}_pct{...}` shape directly
   (see Phase 2 #8) and must be updated to parse `_Attack{N}_{pct}...` instead, not just
   drop their `variant = attack_number - 1` conversion.

7. **Unify baseline representation to `Attack0` everywhere** — replace the three
   competing conventions (separate filename in MOBIGUARD/FADE/tcam; raw negative index
   in `g_sim_tag`) with the `Attack0` convention `bc_run_suffix()` and lstm_logger.h
   already use. Removes `MOBIGUARD_baseline.csv`, `FADE_baseline.csv`,
   `tcam_*_baseline.csv` as distinct filenames.

   **Will silently break three scripts if not updated in the same change** — confirmed
   via grep, these hardcode the literal filename `"MOBIGUARD_baseline.csv"` (exact
   string, not a wildcard/glob), so once that file stops being produced they'll fail
   to find it (missing-file error, or silently-empty baseline series depending on how
   each handles a missing path):
   - `scripts/run_tcam_sweep.py:151`
   - `scripts/verify_metrics.py:325`
   - `scripts/plot_tcam_detection.py:87`

7b. **Convert lstm_logger.h to the canonical shape** — currently writes
   `lstm_training/RSU_{r}/A{v}_pct{p}_seed{s}.csv` (lstm_logger.h, near the
   `attack_v = (active_attack_variant < 0) ? 0 : (active_attack_variant + 1)` line):
   no `_d{X}ms`, no leading `_Attack` literal, uses `A` instead of `Attack`. Needs
   converting to `Attack{N}_{pct}[_d{X}ms]_seed{S}.csv` per the canonical shape
   (`attack_v` is already the correct 1-indexed-with-0-benign value — this is a pure
   rename, not an indexing fix).

   **This one has a much wider and more fragile blast radius than MOBIGUARD/TAP/FADE/bc_*:**
   `lstm_pipeline/src/preprocessor.py:60-70` globs `RSU_*/A*_pct*_seed*.csv` and then
   parses the filename **positionally** — `p.stem.split("_")`, then
   `parts[0][1:]` / `parts[1][3:]` / `parts[2][4:]` for `attack_v`/`pct`/`seed`. This
   is not "may need updating" like other consumers — it **will** break the moment the
   prefix changes from `A` to `Attack` or a `_d{X}ms` segment is inserted, since the
   fixed-offset slicing (`[1:]`, `[3:]`, `[4:]`) and fixed part index (`parts[2]` for
   seed) both assume the current exact shape. Must be rewritten (e.g. to a proper
   regex extracting each field by name, not position) in the same change that renames
   the C++ writer — not after.

   Also confirmed via grep to reference this filename shape and need checking:
   `lstm_pipeline/src/evaluator.py`, `local_trainer.py`, `fed_aggregator.py`,
   `rule_calibrator.py`, `mobility_stratified_eval.py`, `plot_mobility_stratified_mcc.py`,
   `a2_warmup_adaptation_eval.py`, `q30_holdout_eval.py`; and on the writer/launcher
   side, `scripts/run_training_sweep.py`, `run_training_attacks.py`,
   `run_rule_based_sweep.py`, `run_std_attacks.py`, `run_hf_attacks.py`,
   `functional_verification.py`. This list was found by grepping for the filename
   shape, not by reading each file — enumerate exactly what each one assumes (glob
   pattern vs. positional parse vs. just a path string) before changing the writer.

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
