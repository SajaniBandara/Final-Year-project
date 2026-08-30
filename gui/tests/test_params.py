"""Tests for the simulation parameter registry.

The important ones here are the drift tests: they re-read the declarations in
``scratch/*.h`` and ``scratch/routing.cc`` and fail when a default in
:mod:`gui.backend.params` no longer matches the C++. Without them the form can
silently pre-fill a value the binary does not use, and the operator has no way
to notice -- the run simply behaves differently from what the screen said.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

from gui.backend import params as P
from gui.backend.catalog import REPO_ROOT

SCRATCH = REPO_ROOT / "scratch"


def _declared_default(name: str) -> str | None:
    """Find ``<type> <name> = <value>;`` across the simulator sources.

    Deliberately textual: the point is to read what a human reads when they
    open the file, so a mismatch is visible at the declaration site rather than
    inferred from behaviour.
    """
    pattern = re.compile(
        rf"^\s*(?:const\s+)?(?:bool|int|uint32_t|double|float|std::string)\s+"
        rf"{re.escape(name)}\s*=\s*([^;]+);",
        re.MULTILINE,
    )
    for path in sorted(SCRATCH.glob("*.h")) + [SCRATCH / "routing.cc"]:
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        m = pattern.search(text)
        if m:
            return m.group(1).strip()
    return None


class TestRegistryIntegrity(unittest.TestCase):
    def test_names_are_unique(self):
        names = [p.name for p in P.PARAMS]
        self.assertEqual(len(names), len(set(names)))

    def test_every_param_has_a_known_group(self):
        for param in P.PARAMS:
            self.assertIn(param.group, P.GROUP_ORDER, param.name)

    def test_every_param_has_help_text(self):
        for param in P.PARAMS:
            self.assertTrue(param.help.strip(), param.name)

    def test_every_registered_flag_exists_in_the_simulator(self):
        """A flag the binary does not accept would be silently ignored by ns-3."""
        registered = set()
        for path in [SCRATCH / "routing.cc"] + sorted(SCRATCH.glob("*.h")):
            if not path.is_file():
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            registered.update(re.findall(r'cmd\.AddValue\s*\(\s*"([^"]+)"', text))
        self.assertTrue(registered, "found no AddValue calls -- test is broken")
        for param in P.PARAMS:
            self.assertIn(param.name, registered, f"{param.name} is not a real flag")

    def test_defaults_match_the_cpp_declarations(self):
        """The drift guard. Values are compared loosely, by rendered form."""
        checks = {
            "N_Vehicles": "200", "N_RSUs": "64", "N_Controllers": "4",
            "simTime": "300", "sim_seed": "1", "maxspeed": "150",
            "flow_size": "55", "attack_percentage": "0",
            "attack_start_time": "10.0", "attack_rate_pps": "20.0",
            "s1_k": "3.0", "s1_beta": "0.95",
        }
        for name, expected in checks.items():
            with self.subTest(param=name):
                declared = _declared_default(name)
                self.assertIsNotNone(declared, f"{name} not found in the sources")
                self.assertEqual(
                    float(re.sub(r"[^\d.eE+-]", "", declared)), float(expected),
                    f"{name}: C++ says {declared!r}, registry says {expected!r}",
                )
                self.assertEqual(float(P.PARAMS_BY_NAME[name].default), float(expected))

    def test_attack_delay_default_tracks_the_named_anchor(self):
        """The one that already bit: the default is an anchor constant, not 80."""
        text = (SCRATCH / "attack_variables.h").read_text(
            encoding="utf-8", errors="replace"
        )
        m = re.search(r"ATTACK_DELAY_ANCHOR_MED_MS\s*=\s*([\d.]+)", text)
        self.assertIsNotNone(m)
        self.assertEqual(
            float(m.group(1)), P.PARAMS_BY_NAME["attack_delay_ms"].default
        )

    def test_boolean_defaults_match(self):
        for name in ("enable_lrad_obu", "enable_lrad_rsu", "enable_stark_delay",
                     "enable_stark_hop", "enable_witness_mechanism",
                     "enable_quarantine", "enable_endorsement_requirement",
                     "enable_controller_failover", "enable_key_rotation",
                     "enable_lstm_inference"):
            with self.subTest(param=name):
                declared = _declared_default(name)
                self.assertIsNotNone(declared, name)
                expected = declared.strip().lower().startswith("true")
                self.assertEqual(P.PARAMS_BY_NAME[name].default, expected)


class TestCoercion(unittest.TestCase):
    def test_int_rejects_bool(self):
        """A checkbox posted to an int field must fail, not become 0/1."""
        with self.assertRaises(P.ParamError):
            P.PARAMS_BY_NAME["N_Vehicles"].coerce(True)

    def test_bounds_are_enforced(self):
        with self.assertRaises(P.ParamError):
            P.PARAMS_BY_NAME["attack_percentage"].coerce(101)
        with self.assertRaises(P.ParamError):
            P.PARAMS_BY_NAME["attack_percentage"].coerce(-1)
        self.assertEqual(P.PARAMS_BY_NAME["attack_percentage"].coerce("60"), 60)

    def test_choice_rejects_unlisted_values(self):
        with self.assertRaises(P.ParamError):
            P.PARAMS_BY_NAME["attack_number"].coerce(9)
        self.assertEqual(P.PARAMS_BY_NAME["attack_number"].coerce("4"), 4)

    def test_bool_accepts_the_usual_spellings(self):
        param = P.PARAMS_BY_NAME["enable_tap"]
        for truthy in (True, 1, "1", "true", "on", "yes"):
            self.assertIs(param.coerce(truthy), True, truthy)
        for falsy in (False, 0, "0", "false", "off", "no"):
            self.assertIs(param.coerce(falsy), False, falsy)

    def test_run_tag_cannot_traverse_a_path(self):
        """run_tag is concatenated into an output filename by the C++."""
        param = P.PARAMS_BY_NAME["run_tag"]
        for bad in ("../etc", "a/b", "x y", "tag;rm -rf /", "$(id)"):
            with self.subTest(tag=bad), self.assertRaises(P.ParamError):
                param.coerce(bad)
        self.assertEqual(param.coerce("GUI_01-x"), "GUI_01-x")

    def test_unknown_parameters_are_rejected_not_ignored(self):
        with self.assertRaises(P.ParamError):
            P.validate({"simTme": 40})


class TestCommandBuilding(unittest.TestCase):
    def test_only_non_default_values_appear(self):
        argv = P.build_command("routing", {"simTime": 40.0, "N_Vehicles": 200})
        self.assertIn("--simTime=40.0", argv)
        self.assertNotIn("--N_Vehicles=200", argv)  # equals the C++ default

    def test_include_defaults_emits_everything_given(self):
        argv = P.build_command(
            "routing", {"N_Vehicles": 200}, include_defaults=True
        )
        self.assertIn("--N_Vehicles=200", argv)

    def test_benign_omits_attack_number_entirely(self):
        """attack_number=0 is the flag being absent, not --attack_number=0.

        Passing 0 explicitly does not produce the benign baseline: the baseline
        is active_attack_variant staying at -1, which only happens when the flag
        is not given. run_training_attacks.py relies on the same rule.
        """
        argv = P.build_command("routing", {"attack_number": 0, "simTime": 40.0})
        self.assertFalse(any("attack_number" in a for a in argv))

    def test_booleans_render_as_one_and_zero(self):
        argv = P.build_command("routing", {"enable_tap": True})
        self.assertIn("--enable_tap=1", argv)
        argv = P.build_command("routing", {"enable_quarantine": False})
        self.assertIn("--enable_quarantine=0", argv)

    def test_binary_is_always_first(self):
        argv = P.build_command("/path/to/routing", {"simTime": 40.0})
        self.assertEqual(argv[0], "/path/to/routing")

    def test_no_argument_contains_a_shell_metacharacter(self):
        """Belt and braces: the process is spawned without a shell anyway."""
        argv = P.build_command("routing", P.defaults(), include_defaults=True)
        for arg in argv[1:]:
            self.assertNotRegex(arg, r"[;&|`$<>\n]", arg)


class TestDefenceLayers(unittest.TestCase):
    def test_every_layer_flag_is_registered(self):
        for layer in P.DEFENCE_LAYERS:
            for name in list(layer.on) + list(layer.off):
                self.assertIn(name, P.PARAMS_BY_NAME, f"{layer.key} -> {name}")

    def test_on_and_off_touch_the_same_flags(self):
        """Otherwise toggling a layer off then on would not restore it."""
        for layer in P.DEFENCE_LAYERS:
            self.assertEqual(set(layer.on), set(layer.off), layer.key)

    def test_disable_flags_are_inverted_consistently(self):
        """`disable_crypto` is a disable switch, so ON must mean False."""
        crypto = P.DEFENCE_BY_KEY["crypto"]
        self.assertIs(crypto.on["disable_crypto"], False)
        self.assertIs(crypto.off["disable_crypto"], True)

    def test_layer_defaults_reflect_the_registry(self):
        described = {d["key"]: d["default"] for d in P.describe()["defences"]}
        self.assertTrue(described["lrad"])
        self.assertTrue(described["crypto"])
        self.assertFalse(described["lstm"])   # off in the C++

    def test_applying_a_layer_sets_its_flags(self):
        values = P.apply_defences({"simTime": 40.0}, {"crypto": False})
        self.assertIs(values["disable_crypto"], True)
        values = P.apply_defences({"simTime": 40.0}, {"crypto": True})
        self.assertIs(values["disable_crypto"], False)

    def test_unknown_layer_is_rejected(self):
        with self.assertRaises(P.ParamError):
            P.apply_defences({}, {"nonexistent": True})

    def test_layers_win_over_explicit_values(self):
        """The toggle board is what the panel is looking at, so it wins."""
        values = P.apply_defences({"enable_quarantine": True}, {"quarantine": False})
        self.assertIs(values["enable_quarantine"], False)


class TestPresets(unittest.TestCase):
    def test_presets_validate(self):
        for preset in P.PRESETS:
            with self.subTest(preset=preset.key):
                P.validate(preset.values)

    def test_presets_have_wall_time_estimates(self):
        for preset in P.PRESETS:
            self.assertGreater(preset.est_wall_s, 0, preset.key)

    def test_a_benign_preset_exists(self):
        """The false-positive floor is the reference every claim needs."""
        benign = P.PRESETS_BY_KEY["benign"]
        self.assertEqual(benign.values["attack_number"], 0)


class TestDescribe(unittest.TestCase):
    def test_describe_is_json_serialisable(self):
        import json
        json.dumps(P.describe())

    def test_all_eight_variants_plus_baseline_are_described(self):
        described = P.describe()["attacks"]
        self.assertEqual([a["number"] for a in described], list(range(9)))

    def test_each_attack_names_its_signatures(self):
        for attack in P.describe()["attacks"]:
            if attack["number"] == 0:
                self.assertEqual(attack["signatures"], [])
            else:
                self.assertTrue(attack["signatures"], attack["number"])


if __name__ == "__main__":
    unittest.main()
